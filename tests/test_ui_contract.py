import json
import unittest
from datetime import datetime
from pathlib import Path

from besecured.models import SCAN_RESULT_SCHEMA_VERSION, Finding, ScanResult


TOP_LEVEL_KEYS = {
    "schema_version",
    "scan_source",
    "generated_at",
    "system_info",
    "status_counts",
    "category_scores",
    "overall_score",
    "grade",
    "score_details",
    "scoring_note",
    "findings",
}
REQUIRED_FINDING_KEYS = {
    "category",
    "name",
    "status",
    "severity",
    "severity_label",
    "what_we_found",
    "why_it_matters",
    "how_to_fix",
    "fix_steps",
    "supported_os",
    "requires_admin",
}
LEGACY_TOP_LEVEL_KEYS = {"data_source", "os_name", "risk_level", "scan_time", "score", "summary"}
VALID_STATUSES = {"CRIT", "WARN", "INFO", "OK", "SKIP"}


class UiContractTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.ui_root = root / "besecured" / "ui" / "static"
        self.data = json.loads((self.ui_root / "scan-results.json").read_text(encoding="utf-8"))

    def test_sample_scan_results_match_scan_result_contract(self):
        self.assertEqual(set(self.data), TOP_LEVEL_KEYS)
        self.assertEqual(self.data["schema_version"], SCAN_RESULT_SCHEMA_VERSION)
        self.assertTrue(LEGACY_TOP_LEVEL_KEYS.isdisjoint(self.data))
        self.assertIsInstance(self.data["findings"], list)
        self.assertGreater(len(self.data["findings"]), 0)

        for finding in self.data["findings"]:
            with self.subTest(finding=finding.get("name")):
                self.assertTrue(REQUIRED_FINDING_KEYS.issubset(finding))
                self.assertIn(finding["status"], VALID_STATUSES)
                self.assertEqual(finding["severity"], finding["status"])
                self.assertIsInstance(finding["supported_os"], list)
                self.assertIsInstance(finding["fix_steps"], list)
                self.assertGreater(len(finding["fix_steps"]), 0)
                self.assertIsInstance(finding["requires_admin"], bool)

    def test_scan_result_to_dict_uses_same_contract_shape(self):
        result = ScanResult(
            generated_at=datetime(2026, 6, 5, 12, 0, 0),
            system_info={"Hostname": "test-host", "OS": "TestOS"},
            findings=[Finding("Firewall", "Firewall", "CRIT", "Disabled", "Enable the firewall.")],
            status_counts={"CRIT": 1, "WARN": 0, "INFO": 0, "OK": 0, "SKIP": 0},
            category_scores={"Firewall": 0},
            overall_score=0,
            grade="F",
            score_details={"score": 0},
            scoring_note="Test scoring note.",
        ).to_dict()

        self.assertEqual(set(result), set(self.data))
        self.assertTrue(REQUIRED_FINDING_KEYS.issubset(result["findings"][0]))

    def test_status_counts_match_findings(self):
        for status in ["CRIT", "WARN", "INFO", "OK", "SKIP"]:
            expected = sum(1 for finding in self.data["findings"] if finding["status"] == status)
            self.assertEqual(self.data["status_counts"][status], expected)

    def test_sample_score_details_are_defensible(self):
        details = self.data["score_details"]

        self.assertEqual(details["score"], self.data["overall_score"])
        self.assertEqual(details["formula"], "100 - round(lost_points / max_points * 100)")
        self.assertEqual(details["severity_weights"], {"OK": 0, "WARN": 2, "CRIT": 5})
        self.assertEqual(details["lost_points"], 13)
        self.assertEqual(details["max_points"], 50)
        self.assertEqual(details["status_impact"]["CRIT"]["lost_points"], 5)
        self.assertEqual(details["status_impact"]["WARN"]["lost_points"], 8)
        self.assertEqual(details["category_details"]["Protection"]["lost_points"], 7)
        self.assertTrue(details["finding_impacts"])

    def test_ui_assets_do_not_reference_remote_services(self):
        forbidden = ("https://", "http://", "<script src=\"//", "@import url(")
        for path in sorted(self.ui_root.glob("*")):
            if path.suffix not in {".html", ".css", ".js", ".json"}:
                continue
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                with self.subTest(path=path.name, marker=marker):
                    self.assertNotIn(marker, text)

    def test_start_scan_uses_local_scan_api(self):
        app_js = (self.ui_root / "app.js").read_text(encoding="utf-8")

        self.assertIn('fetch("/api/scan"', app_js)
        self.assertNotIn('fetch("scan-results.json"', app_js)


if __name__ == "__main__":
    unittest.main()

import json
import unittest
from pathlib import Path


class UiContractTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.ui_root = root / "besecured" / "ui" / "static"
        self.data = json.loads((self.ui_root / "scan-results.json").read_text(encoding="utf-8"))

    def test_mock_scan_results_match_ui_contract(self):
        required_top_level = {"os_name", "scan_time", "score", "risk_level", "summary", "findings"}
        self.assertTrue(required_top_level.issubset(self.data))
        self.assertIsInstance(self.data["findings"], list)
        self.assertGreater(len(self.data["findings"]), 0)

        required_finding_keys = {
            "id",
            "category",
            "title",
            "severity",
            "status",
            "detail",
            "why_it_matters",
            "fix_steps",
            "supported",
            "requires_admin",
        }
        for finding in self.data["findings"]:
            with self.subTest(finding=finding.get("id")):
                self.assertTrue(required_finding_keys.issubset(finding))
                self.assertIsInstance(finding["fix_steps"], list)
                self.assertGreater(len(finding["fix_steps"]), 0)

    def test_summary_counts_match_findings(self):
        summary = self.data["summary"]
        severity_map = {
            "critical": "critical",
            "warning": "warning",
            "passed": "passed",
            "info": "info",
            "skipped": "skipped",
        }

        for summary_key, severity in severity_map.items():
            expected = sum(1 for finding in self.data["findings"] if finding["severity"] == severity)
            self.assertEqual(summary[summary_key], expected)

    def test_ui_assets_do_not_reference_remote_services(self):
        forbidden = ("https://", "http://", "<script src=\"//", "@import url(")
        for path in sorted(self.ui_root.glob("*")):
            if path.suffix not in {".html", ".css", ".js", ".json"}:
                continue
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                with self.subTest(path=path.name, marker=marker):
                    self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()

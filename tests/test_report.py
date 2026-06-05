import unittest
from datetime import datetime
from pathlib import Path

from besecured.models import Finding, ScanResult
from besecured.report import render_html
from besecured.scoring import category_scores, count_statuses, grade_for_score, score_breakdown


class ReportTests(unittest.TestCase):
    def test_html_is_self_contained_and_contains_simple_recommendations(self):
        findings = [
            Finding("Firewall", "Firewall", "CRIT", "Disabled", "Enable the firewall."),
            Finding("Open Ports", "RDP", "OK", "Closed", "Keep it closed."),
        ]
        breakdown = score_breakdown(findings)
        result = ScanResult(
            generated_at=datetime(2026, 6, 5, 12, 0, 0),
            system_info={"Hostname": "test-host", "OS": "TestOS"},
            findings=findings,
            status_counts=count_statuses(findings),
            category_scores=category_scores(findings),
            overall_score=breakdown.score,
            grade=grade_for_score(breakdown.score),
            score_details=breakdown.to_dict(),
            scoring_note=breakdown.summary,
        )

        html = render_html(result)

        self.assertIn("What we found", html)
        self.assertIn("Why it matters", html)
        self.assertIn("How to fix it", html)
        self.assertIn("A disabled firewall can expose local services to other machines.", html)
        self.assertIn("Enable the firewall.", html)
        self.assertIn("does not upload scan data", html)
        self.assertIn("No account, cloud API or remote backend is used.", html)
        self.assertIn("Formula:", html)
        self.assertIn("Calculation", html)
        self.assertIn("Weight Model", html)
        self.assertIn("Category Impact", html)
        self.assertIn("Finding Impact", html)
        self.assertIn("Severity points lost: 5", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)

    def test_finding_dict_contains_explanation_and_action(self):
        finding = Finding("User Accounts", "Guest Account", "CRIT", "Guest account is enabled.")
        data = finding.to_dict()

        self.assertEqual(data["explanation"], "Guest access can let someone use the machine without a named account.")
        self.assertEqual(data["recommended_action"], "Disable guest account.")
        self.assertEqual(data["fix_steps"], ["Disable guest account."])
        self.assertNotIn("remediation", data)
        self.assertNotIn("why_it_matters", data)

    def test_findings_are_sorted_by_severity(self):
        findings = [
            Finding("System", "ok-check", "OK", "ok"),
            Finding("System", "info-check", "INFO", "info"),
            Finding("System", "warn-check", "WARN", "warn"),
            Finding("System", "crit-check", "CRIT", "crit"),
            Finding("System", "skip-check", "SKIP", "skip"),
        ]
        breakdown = score_breakdown(findings)
        result = ScanResult(
            generated_at=datetime(2026, 6, 5, 12, 0, 0),
            system_info={"Hostname": "test-host", "OS": "TestOS"},
            findings=findings,
            status_counts=count_statuses(findings),
            category_scores=category_scores(findings),
            overall_score=breakdown.score,
            grade=grade_for_score(breakdown.score),
            score_details=breakdown.to_dict(),
            scoring_note=breakdown.summary,
        )

        html = render_html(result)
        json_findings = [finding["name"] for finding in result.to_dict()["findings"]]

        self.assertEqual(json_findings, ["crit-check", "warn-check", "info-check", "ok-check", "skip-check"])
        findings_table = html[html.index("<tbody>") :]
        self.assertLess(findings_table.index("crit-check"), findings_table.index("warn-check"))
        self.assertLess(findings_table.index("warn-check"), findings_table.index("info-check"))
        self.assertLess(findings_table.index("info-check"), findings_table.index("ok-check"))

    def test_scanner_sources_do_not_reference_remote_assets_or_clients(self):
        root = Path(__file__).resolve().parents[1]
        source_paths = [
            *sorted((root / "besecured").rglob("*.py")),
            root / "README.md",
            root / "pyproject.toml",
            root / "WindowsSecurityCheck.ps1",
            root / "WindowsSecurityCheckv2.ps1",
        ]
        forbidden = (
            "https://",
            "http://",
            "<script src=",
            "@import url(",
            "Invoke-WebRequest",
            "Invoke-RestMethod",
            "Start-BitsTransfer",
            "System.Net.WebClient",
            "HttpClient",
            "Microsoft.Update.Session",
            "CreateUpdateSearcher",
        )

        for path in source_paths:
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                with self.subTest(path=path.name, marker=marker):
                    self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main()

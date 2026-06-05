import unittest
from datetime import datetime
from pathlib import Path

from besecured.models import Finding, ScanResult
from besecured.report import render_html
from besecured.scoring import category_scores, count_statuses, grade_for_score, score_breakdown


class ReportTests(unittest.TestCase):
    def test_html_is_self_contained_and_contains_remediation(self):
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

        self.assertIn("Enable the firewall.", html)
        self.assertIn("does not upload scan data", html)
        self.assertIn("No account, cloud API or remote backend is used.", html)
        self.assertIn("Formula:", html)
        self.assertIn("Weight Model", html)
        self.assertIn("Severity points lost: 5", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)

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

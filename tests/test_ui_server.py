import json
import threading
import unittest
import urllib.request
from datetime import datetime
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from besecured.models import Finding, ScanResult
from besecured.scoring import category_scores, count_statuses, grade_for_score, score_breakdown
from besecured.ui.__main__ import BeSecuredUIHandler


def fake_scan_result() -> ScanResult:
    findings = [
        Finding("Network", "RDP", "WARN", "Port 3389 is listening.", "Disable RDP."),
        Finding("Protection", "Firewall", "OK", "Firewall is enabled.", "Keep it enabled."),
    ]
    breakdown = score_breakdown(findings)
    return ScanResult(
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


class UiServerTests(unittest.TestCase):
    def test_scan_endpoint_runs_local_scanner(self):
        root = Path(__file__).resolve().parents[1]
        static_dir = root / "besecured" / "ui" / "static"
        handler = partial(BeSecuredUIHandler, directory=str(static_dir))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            port = server.server_address[1]
            request = urllib.request.Request(f"http://127.0.0.1:{port}/api/scan", method="POST")
            with patch("besecured.ui.__main__.run_scan", return_value=fake_scan_result()) as scanner:
                with urllib.request.urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))

            scanner.assert_called_once_with()
            self.assertEqual(payload["scan_source"], "scanner")
            self.assertEqual(payload["system_info"]["Hostname"], "test-host")
            self.assertEqual(payload["findings"][0]["status"], "WARN")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

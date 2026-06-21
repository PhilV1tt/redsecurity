import unittest
from unittest.mock import patch

from besecured.models import Finding, ScanResult
from besecured import scanner


class ScannerOrchestrationTests(unittest.TestCase):
    def test_run_scan_returns_scored_result(self):
        result = scanner.run_scan()
        self.assertIsInstance(result, ScanResult)
        self.assertIsInstance(result.overall_score, int)
        self.assertIn(result.grade, {"A", "B", "C", "D", "F"})
        self.assertTrue(result.findings)

    def test_run_scan_records_scan_duration_in_system_info(self):
        result = scanner.run_scan()
        self.assertIn("Scan Duration", result.system_info)
        self.assertTrue(result.system_info["Scan Duration"].endswith("s"))

    def test_a_failing_platform_module_does_not_abort_the_scan(self):
        def boom() -> list[Finding]:
            raise RuntimeError("platform module exploded")

        # Force the platform dispatch to raise; the scan must still produce a score.
        with patch.object(scanner, "_run_platform_checks", side_effect=boom):
            result = scanner.run_scan()

        self.assertIsInstance(result, ScanResult)
        self.assertIn(result.grade, {"A", "B", "C", "D", "F"})
        # Common checks still ran, so we still have findings.
        self.assertTrue(result.findings)

    def test_scan_result_serializes_to_the_frozen_contract(self):
        from besecured.models import SCAN_RESULT_SCHEMA_VERSION

        data = scanner.run_scan().to_dict()
        expected_keys = {
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
        self.assertEqual(set(data), expected_keys)
        self.assertEqual(data["schema_version"], SCAN_RESULT_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()

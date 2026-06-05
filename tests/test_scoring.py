import unittest

from besecured.models import Finding
from besecured.scoring import category_scores, count_statuses, grade_for_score, score_breakdown, score_findings


class ScoringTests(unittest.TestCase):
    def test_info_and_skip_do_not_change_score(self):
        findings = [
            Finding("A", "pass", "OK", "ok"),
            Finding("A", "warn", "WARN", "warn"),
            Finding("B", "info", "INFO", "info"),
            Finding("B", "skip", "SKIP", "skip"),
        ]

        self.assertEqual(score_findings(findings), 80)
        self.assertEqual(count_statuses(findings)["INFO"], 1)
        self.assertIsNone(category_scores(findings)["B"])

    def test_critical_findings_have_maximum_weight(self):
        findings = [
            Finding("A", "pass", "OK", "ok"),
            Finding("A", "crit", "CRIT", "crit"),
        ]

        self.assertEqual(score_findings(findings), 50)
        self.assertEqual(grade_for_score(50), "D")

    def test_breakdown_explains_points_lost(self):
        findings = [
            Finding("Firewall", "enabled", "WARN", "warn"),
            Finding("Accounts", "guest", "CRIT", "crit"),
            Finding("Updates", "hotfix", "OK", "ok"),
        ]

        breakdown = score_breakdown(findings)

        self.assertEqual(breakdown.scored_findings, 3)
        self.assertEqual(breakdown.lost_points, 7)
        self.assertEqual(breakdown.max_points, 15)
        self.assertEqual(breakdown.score, 53)
        self.assertIn("Formula:", breakdown.summary)
        self.assertIn("Accounts", breakdown.category_lost_points)


if __name__ == "__main__":
    unittest.main()

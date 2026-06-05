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

    def test_status_counts_keep_display_order(self):
        findings = [
            Finding("A", "pass", "OK", "ok"),
            Finding("A", "warn", "WARN", "warn"),
            Finding("A", "crit", "CRIT", "crit"),
            Finding("B", "info", "INFO", "info"),
            Finding("B", "skip", "SKIP", "skip"),
        ]

        self.assertEqual(list(count_statuses(findings)), ["CRIT", "WARN", "INFO", "OK", "SKIP"])

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
        self.assertEqual(breakdown.formula, "100 - round(lost_points / max_points * 100)")
        self.assertEqual(breakdown.status_impact["CRIT"]["lost_points"], 5)
        self.assertEqual(breakdown.status_impact["WARN"]["lost_points"], 2)
        self.assertEqual(breakdown.category_details["Accounts"]["lost_points"], 5)
        self.assertEqual(breakdown.category_details["Accounts"]["max_points"], 5)
        self.assertEqual(breakdown.category_details["Accounts"]["impacted_findings"][0]["name"], "guest")
        self.assertEqual(breakdown.finding_impacts[0]["status"], "CRIT")
        self.assertIn("INFO", breakdown.to_dict()["ignored_statuses"])
        self.assertIn("Lost severity points: 7 out of 15.", breakdown.calculation_steps)


if __name__ == "__main__":
    unittest.main()

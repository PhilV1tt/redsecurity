from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .models import ACTIONABLE_STATUSES, Finding

SEVERITY_WEIGHTS = {"OK": 0, "WARN": 2, "CRIT": 5}
MAX_SEVERITY_WEIGHT = SEVERITY_WEIGHTS["CRIT"]


@dataclass(frozen=True)
class ScoreBreakdown:
    score: int
    scored_findings: int
    lost_points: int
    max_points: int
    severity_weights: dict[str, int]
    category_lost_points: dict[str, int]
    summary: str
    factors: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "scored_findings": self.scored_findings,
            "lost_points": self.lost_points,
            "max_points": self.max_points,
            "severity_weights": self.severity_weights,
            "category_lost_points": self.category_lost_points,
            "summary": self.summary,
            "factors": self.factors,
        }


def count_statuses(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.status for finding in findings)
    return {status: counts.get(status, 0) for status in ["OK", "WARN", "CRIT", "INFO", "SKIP"]}


def score_findings(findings: list[Finding]) -> int:
    return score_breakdown(findings).score


def score_breakdown(findings: list[Finding]) -> ScoreBreakdown:
    actionable = [finding for finding in findings if finding.status in ACTIONABLE_STATUSES]
    if not actionable:
        return ScoreBreakdown(
            score=0,
            scored_findings=0,
            lost_points=0,
            max_points=0,
            severity_weights=SEVERITY_WEIGHTS.copy(),
            category_lost_points={},
            summary="No scored checks ran, so BeSecured cannot rate this machine yet.",
            factors=["INFO and SKIP findings are shown in the report but do not change the score."],
        )

    counts = Counter(finding.status for finding in actionable)
    max_points = len(actionable) * MAX_SEVERITY_WEIGHT
    lost_points = sum(SEVERITY_WEIGHTS[finding.status] for finding in actionable)
    raw_score = 100 - round((lost_points / max_points) * 100)
    score = max(0, min(100, raw_score))
    category_lost_points: dict[str, int] = defaultdict(int)
    for finding in actionable:
        category_lost_points[finding.category] += SEVERITY_WEIGHTS[finding.status]

    return ScoreBreakdown(
        score=score,
        scored_findings=len(actionable),
        lost_points=lost_points,
        max_points=max_points,
        severity_weights=SEVERITY_WEIGHTS.copy(),
        category_lost_points=dict(sorted(category_lost_points.items())),
        summary=_score_summary(score, counts, lost_points, max_points, len(actionable)),
        factors=_score_factors(counts, category_lost_points),
    )


def category_scores(findings: list[Finding]) -> dict[str, int | None]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.category].append(finding)

    scores: dict[str, int | None] = {}
    for category, category_findings in sorted(grouped.items()):
        if any(finding.status in ACTIONABLE_STATUSES for finding in category_findings):
            scores[category] = score_findings(category_findings)
        else:
            scores[category] = None
    return scores


def _score_summary(score: int, counts: Counter[str], lost_points: int, max_points: int, total: int) -> str:
    ok = counts.get("OK", 0)
    warn = counts.get("WARN", 0)
    crit = counts.get("CRIT", 0)
    if score >= 90:
        quality = "Strong score"
    elif score >= 75:
        quality = "Good score"
    elif score >= 60:
        quality = "Medium score"
    elif score >= 40:
        quality = "Weak score"
    else:
        quality = "Bad score"

    if crit:
        reason = f"{crit} critical finding(s) have the highest weight."
    elif warn:
        reason = f"{warn} warning finding(s) reduce the score."
    else:
        reason = "all scored checks passed."

    return (
        f"{quality}: {reason} "
        f"{ok}/{total} scored checks passed. "
        f"Formula: 100 - round({lost_points}/{max_points} * 100) = {score}."
    )


def _score_factors(counts: Counter[str], category_lost_points: dict[str, int]) -> list[str]:
    factors: list[str] = []
    if counts.get("CRIT", 0):
        factors.append(
            f"Critical findings: {counts['CRIT']} x {SEVERITY_WEIGHTS['CRIT']} severity points."
        )
    if counts.get("WARN", 0):
        factors.append(
            f"Warnings: {counts['WARN']} x {SEVERITY_WEIGHTS['WARN']} severity points."
        )
    if counts.get("OK", 0):
        factors.append(f"Passed checks: {counts['OK']} x 0 severity points.")

    impacted = [
        (category, points)
        for category, points in sorted(category_lost_points.items(), key=lambda item: (-item[1], item[0]))
        if points > 0
    ]
    if impacted:
        top_categories = ", ".join(f"{category} ({points})" for category, points in impacted[:3])
        factors.append(f"Main score impact: {top_categories}.")
    else:
        factors.append("No warning or critical finding removed points.")
    factors.append("INFO and SKIP findings are listed for context but are not scored.")
    return factors


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"

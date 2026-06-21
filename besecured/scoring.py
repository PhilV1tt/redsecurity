from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .models import ACTIONABLE_STATUSES, Finding

STATUS_DISPLAY_ORDER = ("CRIT", "WARN", "INFO", "OK", "SKIP")
SCORED_STATUSES = ("CRIT", "WARN", "OK")
IGNORED_STATUSES = ("INFO", "SKIP")
SEVERITY_WEIGHTS = {"OK": 0, "WARN": 2, "CRIT": 5}
MAX_SEVERITY_WEIGHT = SEVERITY_WEIGHTS["CRIT"]
SCORE_FORMULA = "100 - round(lost_points / max_points * 100)"


@dataclass(frozen=True)
class ScoreBreakdown:
    score: int
    scored_findings: int
    lost_points: int
    max_points: int
    formula: str
    severity_weights: dict[str, int]
    status_impact: dict[str, dict[str, int]]
    category_lost_points: dict[str, int]
    category_details: dict[str, dict[str, object]]
    finding_impacts: list[dict[str, object]]
    calculation_steps: list[str]
    summary: str
    factors: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "scored_findings": self.scored_findings,
            "lost_points": self.lost_points,
            "max_points": self.max_points,
            "formula": self.formula,
            "severity_weights": self.severity_weights,
            "scored_statuses": list(SCORED_STATUSES),
            "ignored_statuses": list(IGNORED_STATUSES),
            "status_impact": self.status_impact,
            "category_lost_points": self.category_lost_points,
            "category_details": self.category_details,
            "finding_impacts": self.finding_impacts,
            "calculation_steps": self.calculation_steps,
            "summary": self.summary,
            "factors": self.factors,
        }


def count_statuses(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.status for finding in findings)
    return {status: counts.get(status, 0) for status in STATUS_DISPLAY_ORDER}


def score_findings(findings: list[Finding]) -> int:
    return score_breakdown(findings).score


def score_breakdown(findings: list[Finding]) -> ScoreBreakdown:
    actionable = [finding for finding in findings if finding.status in ACTIONABLE_STATUSES]
    if not actionable:
        # No OK/WARN/CRIT check could run (e.g. unsupported OS, or every check
        # was SKIP/INFO). No weakness was detected, so no points are lost: report
        # the formula's natural limit (100) rather than 0, which would wrongly
        # grade an unscannable machine as the most insecure one possible. The
        # summary makes clear the machine is effectively unscored.
        return ScoreBreakdown(
            score=100,
            scored_findings=0,
            lost_points=0,
            max_points=0,
            formula=SCORE_FORMULA,
            severity_weights=SEVERITY_WEIGHTS.copy(),
            status_impact=_status_impact(Counter()),
            category_lost_points={},
            category_details={},
            finding_impacts=[],
            calculation_steps=[
                "No OK, WARN or CRIT checks ran.",
                "INFO and SKIP findings are visible but ignored by the score.",
            ],
            summary="No scored checks ran, so BeSecured could not rate this machine. No weakness was detected.",
            factors=["INFO and SKIP findings are shown in the report but do not change the score."],
        )

    counts = Counter(finding.status for finding in actionable)
    max_points = len(actionable) * MAX_SEVERITY_WEIGHT
    lost_points = sum(SEVERITY_WEIGHTS[finding.status] for finding in actionable)
    score = _score_from_points(lost_points, max_points)
    category_lost_points: dict[str, int] = defaultdict(int)
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in actionable:
        category_lost_points[finding.category] += SEVERITY_WEIGHTS[finding.status]
        grouped[finding.category].append(finding)

    sorted_category_lost_points = dict(sorted(category_lost_points.items()))
    category_details = {
        category: _category_detail(category, category_findings)
        for category, category_findings in sorted(grouped.items())
    }
    finding_impacts = _finding_impacts(actionable, max_points)

    return ScoreBreakdown(
        score=score,
        scored_findings=len(actionable),
        lost_points=lost_points,
        max_points=max_points,
        formula=SCORE_FORMULA,
        severity_weights=SEVERITY_WEIGHTS.copy(),
        status_impact=_status_impact(counts),
        category_lost_points=sorted_category_lost_points,
        category_details=category_details,
        finding_impacts=finding_impacts,
        calculation_steps=_calculation_steps(len(actionable), lost_points, max_points, score),
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


def _score_from_points(lost_points: int, max_points: int) -> int:
    if max_points <= 0:
        return 0
    raw_score = 100 - round((lost_points / max_points) * 100)
    return max(0, min(100, raw_score))


def _status_impact(counts: Counter[str]) -> dict[str, dict[str, int]]:
    return {
        status: {
            "count": counts.get(status, 0),
            "severity_points_each": SEVERITY_WEIGHTS[status],
            "lost_points": counts.get(status, 0) * SEVERITY_WEIGHTS[status],
        }
        for status in SCORED_STATUSES
    }


def _category_detail(category: str, findings: list[Finding]) -> dict[str, object]:
    lost_points = sum(SEVERITY_WEIGHTS[finding.status] for finding in findings)
    max_points = len(findings) * MAX_SEVERITY_WEIGHT
    impacted = [
        {
            "name": finding.name,
            "status": finding.status,
            "severity_points": SEVERITY_WEIGHTS[finding.status],
        }
        for finding in findings
        if SEVERITY_WEIGHTS[finding.status] > 0
    ]
    return {
        "category": category,
        "score": _score_from_points(lost_points, max_points),
        "scored_findings": len(findings),
        "lost_points": lost_points,
        "max_points": max_points,
        "impacted_findings": impacted,
    }


def _finding_impacts(findings: list[Finding], max_points: int) -> list[dict[str, object]]:
    impacts = []
    for finding in sorted(findings, key=lambda item: item.sort_key()):
        severity_points = SEVERITY_WEIGHTS[finding.status]
        impacts.append(
            {
                "category": finding.category,
                "name": finding.name,
                "status": finding.status,
                "severity_points": severity_points,
                "max_severity_points": MAX_SEVERITY_WEIGHT,
                "score_impact_percent": round((severity_points / max_points) * 100, 1),
            }
        )
    return impacts


def _calculation_steps(total: int, lost_points: int, max_points: int, score: int) -> list[str]:
    return [
        f"{total} scored check(s): only OK, WARN and CRIT affect the score.",
        f"Each scored check can lose up to {MAX_SEVERITY_WEIGHT} severity points.",
        f"Lost severity points: {lost_points} out of {max_points}.",
        f"Final score: {SCORE_FORMULA} = {score}.",
    ]


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

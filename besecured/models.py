from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


ACTIONABLE_STATUSES = {"OK", "WARN", "CRIT"}
VALID_STATUSES = ACTIONABLE_STATUSES | {"INFO", "SKIP"}
STATUS_SORT = {"CRIT": 0, "WARN": 1, "OK": 2, "INFO": 3, "SKIP": 4}


@dataclass(frozen=True)
class Finding:
    category: str
    name: str
    status: str
    detail: str
    remediation: str = ""

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f"Invalid finding status: {self.status}")

    @property
    def is_actionable(self) -> bool:
        return self.status in ACTIONABLE_STATUSES

    def sort_key(self) -> tuple[int, str, str]:
        return (STATUS_SORT[self.status], self.category.lower(), self.name.lower())

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class ScanResult:
    generated_at: datetime
    system_info: dict[str, str]
    findings: list[Finding]
    status_counts: dict[str, int]
    category_scores: dict[str, int | None]
    overall_score: int
    grade: str
    score_details: dict[str, Any] = field(default_factory=dict)
    scoring_note: str = field(
        default=(
            "OK, WARN and CRIT checks are scored with severity weights. INFO and "
            "SKIP findings are shown for transparency but do not change the score."
        )
    )

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda item: item.sort_key())

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "system_info": self.system_info,
            "status_counts": self.status_counts,
            "category_scores": self.category_scores,
            "overall_score": self.overall_score,
            "grade": self.grade,
            "score_details": self.score_details,
            "scoring_note": self.scoring_note,
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
        }

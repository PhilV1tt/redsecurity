from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Iterable


ACTIONABLE_STATUSES = {"OK", "WARN", "CRIT"}
VALID_STATUSES = ACTIONABLE_STATUSES | {"INFO", "SKIP"}
STATUS_SORT = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3, "SKIP": 4}
STATUS_LABELS = {
    "CRIT": "Critical",
    "WARN": "Warning",
    "INFO": "Info",
    "OK": "OK",
    "SKIP": "Skipped",
}
SCAN_RESULT_SCHEMA_VERSION = "besecured.scan_result.v1"
SUPPORTED_OS_ALL = ("Windows", "Linux", "macOS")


@dataclass(frozen=True)
class Finding:
    category: str
    name: str
    status: str
    detail: str
    remediation: str = ""
    explanation: str = ""
    recommended_action: str = ""
    supported_os: tuple[str, ...] = SUPPORTED_OS_ALL
    requires_admin: bool = False

    def __post_init__(self) -> None:
        status = self.status.upper()
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid finding status: {self.status}")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "supported_os", _normalise_supported_os(self.supported_os))
        object.__setattr__(self, "requires_admin", bool(self.requires_admin))

    @property
    def is_actionable(self) -> bool:
        return self.status in ACTIONABLE_STATUSES

    @property
    def explanation_text(self) -> str:
        return self.explanation or _default_explanation(self)

    @property
    def action_text(self) -> str:
        return self.recommended_action or self.remediation or _default_action(self) or "No action needed."

    @property
    def what_we_found(self) -> str:
        return self.detail

    @property
    def why_it_matters(self) -> str:
        return self.explanation_text

    @property
    def how_to_fix(self) -> str:
        return self.action_text

    @property
    def severity_label(self) -> str:
        return STATUS_LABELS[self.status]

    def with_context(
        self,
        *,
        supported_os: Iterable[str] | None = None,
        requires_admin: bool | None = None,
    ) -> "Finding":
        return replace(
            self,
            supported_os=tuple(supported_os) if supported_os is not None else self.supported_os,
            requires_admin=self.requires_admin if requires_admin is None else requires_admin,
        )

    def sort_key(self) -> tuple[int, str, str]:
        return (STATUS_SORT[self.status], self.category.lower(), self.name.lower())

    def to_dict(self) -> dict[str, Any]:
        why = self.why_it_matters
        fix = self.how_to_fix
        return {
            "category": self.category,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "explanation": why,
            "recommended_action": fix,
            "fix_steps": [fix],
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
    scan_source: str = "scanner"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda item: item.sort_key())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCAN_RESULT_SCHEMA_VERSION,
            "scan_source": self.scan_source,
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


def _default_explanation(finding: Finding) -> str:
    key = _finding_key(finding)
    if finding.status == "OK":
        return "This check passed."
    if finding.status == "SKIP":
        return "BeSecured could not run this check safely on this machine."
    if "firewall" in key:
        return "A disabled firewall can expose local services to other machines."
    if "update" in key or "hotfix" in key or "xprotect" in key or "signature" in key:
        return "Missing updates leave known security issues open."
    if "guest" in key:
        return "Guest access can let someone use the machine without a named account."
    if "password" in key:
        return "Weak account rules make unauthorized access easier."
    if "admin" in key or "uid 0" in key:
        return "Too many admin accounts increase the impact of a compromised account."
    if "share" in key or "samba" in key or "nfs" in key:
        return "Shared folders can expose files to other users or devices."
    if "startup" in key or "launch" in key:
        return "Unexpected startup entries can keep unwanted software running."
    if "antivirus" in key or "defender" in key or "gatekeeper" in key or "protection" in key:
        return "Security protection helps block common malware and unsafe apps."
    if "encrypt" in key or "bitlocker" in key or "filevault" in key or "luks" in key:
        return "Disk encryption helps protect data if the device is lost or stolen."
    if "rdp" in key or "port" in key:
        return "Open network services can be reached by other machines."
    if "uac" in key:
        return "UAC helps stop unexpected changes from getting administrator rights."
    if finding.status == "INFO":
        return "This item is shown for context."
    return "This issue can weaken the local security posture."


def _default_action(finding: Finding) -> str:
    key = _finding_key(finding)
    if finding.status == "OK":
        return finding.remediation or "No action needed."
    if finding.status == "SKIP":
        return finding.remediation or "Check manually."
    if finding.status == "INFO":
        return finding.remediation or "Review if needed."
    if "firewall" in key:
        return "Enable firewall."
    if "update" in key or "hotfix" in key or "xprotect" in key or "signature" in key:
        return "Update system."
    if "guest" in key:
        return "Disable guest account."
    if "no-password" in key or "passwordless" in key:
        return "Require account passwords."
    if "password" in key:
        return "Strengthen password policy."
    if "admin" in key or "uid 0" in key:
        return "Limit administrator access."
    if "share" in key or "samba" in key or "nfs" in key:
        return "Restrict shared folders."
    if "startup" in key or "launch" in key:
        return "Review startup entries."
    if "gatekeeper" in key:
        return "Enable Gatekeeper."
    if "system integrity protection" in key:
        return "Enable SIP."
    if "real-time protection" in key:
        return "Enable real-time protection."
    if "defender" in key:
        return "Enable Microsoft Defender."
    if "antivirus" in key or "protection" in key:
        return "Enable antivirus protection."
    if "encrypt" in key or "bitlocker" in key or "filevault" in key or "luks" in key:
        return "Enable disk encryption."
    if "rdp" in key:
        return "Disable RDP."
    if "port" in key:
        return "Restrict exposed ports."
    if "uac" in key:
        return "Enable UAC."
    return finding.remediation or "Fix this issue."


def _finding_key(finding: Finding) -> str:
    return f"{finding.category} {finding.name}".lower()


def _normalise_supported_os(value: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    supported: list[str] = []
    for item in value:
        clean = str(item).strip()
        if not clean or clean.lower() in seen:
            continue
        seen.add(clean.lower())
        supported.append(clean)
    return tuple(supported)

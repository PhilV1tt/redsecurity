from __future__ import annotations
import platform
from datetime import datetime
from .checks import collect_system_info, is_admin
from .checks.common import run_common_checks
from .models import Finding, ScanResult
from .scoring import category_scores, count_statuses, grade_for_score, score_breakdown

def run_scan() -> ScanResult:
    admin = is_admin()
    findings: list[Finding] = []
    findings.extend(run_common_checks(admin))
    system = platform.system()
    if system == "Windows":
        from .checks.windows import run_windows_checks
        findings.extend(run_windows_checks())
    elif system == "Linux":
        from .checks.linux import run_linux_checks
        findings.extend(run_linux_checks())
    elif system == "Darwin":
        from .checks.macos import run_macos_checks
        findings.extend(run_macos_checks())
    else:
        findings.append(
            Finding(
                "Platform",
                "OS Support",
                "SKIP",
                f"{system or 'Unknown'} is not supported yet. Only common checks were run.",
                "Run BeSecured on Windows, Linux or macOS for the full scanner.",
                supported_os=("Windows", "Linux", "macOS"),
            )
        )
    breakdown = score_breakdown(findings)
    return ScanResult(
        generated_at=datetime.now().astimezone(),
        system_info=collect_system_info(admin),
        findings=findings,
        status_counts=count_statuses(findings),
        category_scores=category_scores(findings),
        overall_score=breakdown.score,
        grade=grade_for_score(breakdown.score),
        score_details=breakdown.to_dict(),
        scoring_note=breakdown.summary,
    )

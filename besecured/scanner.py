from __future__ import annotations
import platform
import time
from datetime import datetime
from .checks import collect_system_info, is_admin
from .checks.common import run_common_checks, run_checks
from .models import Finding, ScanResult
from .scoring import category_scores, count_statuses, grade_for_score, score_breakdown

def run_scan() -> ScanResult:
    started = time.perf_counter()
    admin = is_admin()
    system_info = collect_system_info(admin)
    findings: list[Finding] = run_common_checks(admin)
    findings.extend(run_checks([("Platform", _run_platform_checks)]))
    breakdown = score_breakdown(findings)
    system_info["Scan Duration"] = f"{time.perf_counter() - started:.2f} s"
    return ScanResult(
        generated_at=datetime.now().astimezone(),
        system_info=system_info,
        findings=findings,
        status_counts=count_statuses(findings),
        category_scores=category_scores(findings),
        overall_score=breakdown.score,
        grade=grade_for_score(breakdown.score),
        score_details=breakdown.to_dict(),
        scoring_note=breakdown.summary,
    )


def _run_platform_checks() -> list[Finding]:
    system = platform.system()
    if system == "Windows":
        from .checks.windows import run_windows_checks
        return run_windows_checks()
    if system == "Linux":
        from .checks.linux import run_linux_checks
        return run_linux_checks()
    if system == "Darwin":
        from .checks.macos import run_macos_checks
        return run_macos_checks()
    return [
        Finding(
            "Platform",
            "OS Support",
            "SKIP",
            f"{system or 'Unknown'} is not supported yet. Only common checks were run.",
            "Run BeSecured on Windows, Linux or macOS for the full scanner.",
            supported_os=("Windows", "Linux", "macOS"),
        )
    ]

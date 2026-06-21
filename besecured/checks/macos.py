from __future__ import annotations

import datetime as dt
import grp
import os
import re
from pathlib import Path

from besecured.checks.common import command_exists, file_mentions_temp, readable_files, run_checks, run_command, unavailable_finding
from besecured.models import Finding


def run_macos_checks() -> list[Finding]:
    checks = [
        ("Firewall", check_firewall),
        ("Updates", check_updates),
        ("Disk Encryption", check_disk_encryption),
        ("User Accounts", check_users),
        ("Password Policy", check_password_policy),
        ("Shared Folders", check_shared_folders),
        ("Startup Programs", check_startup_programs),
        ("Antivirus", check_antimalware),
        ("Privilege Elevation", check_privilege_model),
    ]
    return _macos_findings(run_checks(checks))


def _macos_findings(findings: list[Finding]) -> list[Finding]:
    return [finding.with_context(supported_os=("macOS",)) for finding in findings]


def check_firewall() -> list[Finding]:
    category = "Firewall"
    command = Path("/usr/libexec/ApplicationFirewall/socketfilterfw")
    if not command.exists():
        return [
            unavailable_finding(
                category,
                "Application Firewall",
                "socketfilterfw is not available",
                "Open System Settings and verify that Firewall is enabled.",
            )
        ]
    result = run_command([str(command), "--getglobalstate"], timeout=6)
    text = (result.stdout + " " + result.stderr).lower()
    if "enabled" in text:
        return [Finding(category, "Application Firewall", "OK", "macOS Application Firewall is enabled.", "Keep the firewall enabled unless a managed policy replaces it.")]
    if "disabled" in text:
        return [Finding(category, "Application Firewall", "CRIT", "macOS Application Firewall is disabled.", "Enable the firewall in System Settings > Network > Firewall.")]
    return [
        unavailable_finding(
            category,
            "Application Firewall",
            "macOS firewall status could not be parsed",
            "Open System Settings and verify that Firewall is enabled.",
        )
    ]


def check_updates() -> list[Finding]:
    category = "Updates"
    if not command_exists("softwareupdate"):
        return [
            unavailable_finding(
                category,
                "Software Update",
                "softwareupdate is not available",
                "Open System Settings and install pending macOS updates.",
            )
        ]
    result = run_command(["softwareupdate", "--history"], timeout=10)
    dates = _extract_dates(result.stdout)
    if not dates:
        return [
            unavailable_finding(
                category,
                "Software Update",
                "macOS update history returned no usable date",
                "Open System Settings and install pending macOS updates.",
            )
        ]
    age = (dt.datetime.now().date() - max(dates)).days
    if age < 30:
        status = "OK"
    elif age < 90:
        status = "WARN"
    else:
        status = "CRIT"
    return [Finding(category, "Software Update", status, f"Most recent software update entry is {age} day(s) old.", "Install pending macOS security updates.")]


def check_disk_encryption() -> list[Finding]:
    category = "Disk Encryption"
    if not command_exists("fdesetup"):
        return [
            unavailable_finding(
                category,
                "FileVault",
                "fdesetup is not available",
                "Check FileVault manually in System Settings > Privacy & Security.",
            )
        ]
    result = run_command(["fdesetup", "status"], timeout=8)
    return [_filevault_finding_from_text(result.stdout + " " + result.stderr)]


def check_users() -> list[Finding]:
    category = "User Accounts"
    findings: list[Finding] = []
    try:
        admin_group = grp.getgrnam("admin")
        admins = _human_account_names(admin_group.gr_mem)
    except KeyError:
        admins = []

    findings.append(
        Finding(
            category,
            "Admin Accounts",
            "OK" if len(admins) <= 2 else "WARN",
            f"Admin group member(s): {', '.join(admins) if admins else 'none detected'}",
            "Keep admin rights limited to users who need them.",
        )
    )

    guest_result = run_command(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], timeout=5)
    guest_enabled = guest_result.stdout.strip() == "1"
    findings.append(
        Finding(
            category,
            "Guest Account",
            "CRIT" if guest_enabled else "OK",
            "Guest account is enabled." if guest_enabled else "Guest account is disabled or not configured.",
            "Disable Guest User in System Settings unless it is truly needed.",
        )
    )
    findings.append(
        Finding(
            category,
            "No-Password Accounts",
            "SKIP",
            "macOS does not expose passwordless account status through a safe unprivileged check.",
            "Review users in System Settings and ensure every account has a password.",
        )
    )
    return findings


def check_password_policy() -> list[Finding]:
    result = run_command(["pwpolicy", "-getaccountpolicies"], timeout=8)
    if result.stdout:
        return [Finding("Password Policy", "Account Policies", "INFO", "macOS account password policy is configured.", "Review policy strength if this is a shared or managed machine.")]
    return [Finding("Password Policy", "Account Policies", "SKIP", "No macOS account password policy was returned.", "Review password requirements in System Settings or MDM if applicable.")]


def check_shared_folders() -> list[Finding]:
    category = "Shared Folders"
    command = Path("/usr/sbin/sharing")
    if not command.exists():
        return [
            unavailable_finding(
                category,
                "Shared Folders",
                "macOS sharing tool is not available",
                "Open System Settings and review File Sharing manually.",
            )
        ]
    result = run_command([str(command), "-l"], timeout=8)
    return _shared_folder_findings_from_text(category, result.stdout, result.ok)


def _shared_folder_findings_from_text(category: str, text: str, command_ok: bool) -> list[Finding]:
    clean_text = text.strip()
    if not command_ok:
        return [
            unavailable_finding(
                category,
                "Shared Folders",
                "macOS sharing command could not query shared folders",
                "Open System Settings and verify File Sharing manually.",
            )
        ]
    if "No shares" in clean_text or "There are no shared folders" in clean_text:
        return [Finding(category, "Shared Folders", "OK", "No shared folders detected by macOS sharing tool.", "Keep file sharing disabled unless it is needed.")]
    if not clean_text:
        return [
            unavailable_finding(
                category,
                "Shared Folders",
                "macOS sharing tool returned no output",
                "Open System Settings and verify File Sharing manually.",
            )
        ]
    share_names = _dedupe(re.findall(r"(?im)^\s*name:\s*(.+)$", text))
    if not share_names and text:
        share_names = ["sharing output detected"]
    return [
        Finding(
            category,
            f"Share: {name}",
            "WARN",
            "macOS sharing is configured.",
            "Remove unnecessary shared folders or restrict access to trusted users.",
        )
        for name in share_names
    ]


def check_startup_programs() -> list[Finding]:
    category = "Startup Programs"
    paths = [
        Path.home() / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    files = readable_files(paths, suffix=".plist")
    suspicious = [path for path in files if file_mentions_temp(path)]
    findings = [
        Finding(
            category,
            "Launch Items",
            "INFO" if len(files) <= 30 else "WARN",
            f"{len(files)} LaunchAgent or LaunchDaemon plist file(s) found.",
            "Review login and launch items and remove entries that are not needed.",
        )
    ]
    if suspicious:
        findings.append(
            Finding(
                category,
                "Suspicious Startup",
                "CRIT",
                f"Launch item(s) mention temporary paths: {', '.join(str(path) for path in suspicious[:5])}",
                "Investigate these launch items before deleting evidence.",
            )
        )
    return findings


def check_antimalware() -> list[Finding]:
    category = "Antivirus"
    findings: list[Finding] = []
    if command_exists("spctl"):
        gatekeeper = run_command(["spctl", "--status"], timeout=6)
        findings.append(_gatekeeper_finding_from_text(gatekeeper.stdout + " " + gatekeeper.stderr))
    else:
        findings.append(
            unavailable_finding(
                category,
                "Gatekeeper",
                "spctl is not available",
                "Review Gatekeeper status manually in System Settings.",
            )
        )

    if command_exists("csrutil"):
        sip = run_command(["csrutil", "status"], timeout=6)
        findings.append(_sip_finding_from_text(sip.stdout + " " + sip.stderr))
    else:
        findings.append(
            unavailable_finding(
                category,
                "System Integrity Protection",
                "csrutil is not available",
                "Review SIP status manually if this is a managed Mac.",
            )
        )

    if command_exists("pkgutil"):
        install_time = _latest_xprotect_install_date()
        if install_time:
            age = (dt.datetime.now().date() - install_time).days
            status = "OK" if age <= 14 else "WARN" if age <= 45 else "CRIT"
            findings.append(Finding(category, "XProtect Data", status, f"XProtect package install time is {age} day(s) old.", "Install pending macOS security updates."))
        else:
            findings.append(
                unavailable_finding(
                    category,
                    "XProtect Data",
                    "XProtect package install time could not be determined",
                    "Install pending macOS security updates and review XProtect status manually.",
                )
            )
    else:
        findings.append(
            unavailable_finding(
                category,
                "XProtect Data",
                "pkgutil is not available",
                "Install pending macOS security updates and review XProtect status manually.",
            )
        )
    return findings


def check_privilege_model() -> list[Finding]:
    return [
        Finding(
            "Privilege Elevation",
            "UAC Equivalent",
            "INFO",
            "macOS uses admin authorization prompts, SIP and TCC instead of Windows UAC.",
            "Use a standard account for daily work and approve elevation prompts only when expected.",
        )
    ]


def _extract_dates(text: str) -> list[dt.date]:
    dates: list[dt.date] = []
    today = dt.datetime.now().date()
    for match in re.findall(r"\b(\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{1,2}-\d{1,2})\b", text):
        parsed = _parse_history_date(match, today)
        if parsed:
            dates.append(parsed)
    return dates


def _parse_history_date(value: str, today: dt.date | None = None) -> dt.date | None:
    today = today or dt.datetime.now().date()
    if "-" in value:
        try:
            parsed = dt.datetime.strptime(value, "%Y-%m-%d").date()
            return parsed if parsed <= today else None
        except ValueError:
            return None

    candidates: list[dt.date] = []
    for fmt in ("%m/%d/%Y", "%d/%m/%Y"):
        try:
            parsed = dt.datetime.strptime(value, fmt).date()
        except ValueError:
            continue
        if parsed <= today:
            candidates.append(parsed)
    return max(candidates) if candidates else None


def _human_account_names(names: list[str]) -> list[str]:
    ignored = {"root", "daemon", "nobody"}
    return sorted({name for name in names if name and not name.startswith("_") and name.lower() not in ignored})


def _filevault_finding_from_text(text: str) -> Finding:
    clean = text.lower()
    if "filevault is on" in clean:
        return Finding(
            "Disk Encryption",
            "FileVault",
            "OK",
            "FileVault is enabled.",
            "Keep the recovery key stored safely and separate from the Mac.",
        )
    if "filevault is off" in clean:
        return Finding(
            "Disk Encryption",
            "FileVault",
            "WARN",
            "FileVault is disabled.",
            "Enable FileVault on portable Macs or machines that may leave a trusted location.",
        )
    return unavailable_finding(
        "Disk Encryption",
        "FileVault",
        "FileVault status could not be parsed",
        "Check FileVault manually in System Settings > Privacy & Security.",
    )


def _gatekeeper_finding_from_text(text: str) -> Finding:
    clean = text.lower()
    if "assessments enabled" in clean:
        return Finding(
            "Antivirus",
            "Gatekeeper",
            "OK",
            "Gatekeeper assessments are enabled.",
            "Keep Gatekeeper enabled to block untrusted applications.",
        )
    if "assessments disabled" in clean:
        return Finding(
            "Antivirus",
            "Gatekeeper",
            "CRIT",
            "Gatekeeper assessments are disabled.",
            "Re-enable Gatekeeper unless there is a documented operational reason.",
        )
    return unavailable_finding(
        "Antivirus",
        "Gatekeeper",
        "Gatekeeper status could not be parsed",
        "Review Gatekeeper status manually in System Settings.",
    )


def _sip_finding_from_text(text: str) -> Finding:
    clean = text.lower()
    if "enabled" in clean:
        return Finding(
            "Antivirus",
            "System Integrity Protection",
            "OK",
            "System Integrity Protection is enabled.",
            "Keep SIP enabled unless there is a documented operational reason.",
        )
    if "disabled" in clean:
        return Finding(
            "Antivirus",
            "System Integrity Protection",
            "WARN",
            "System Integrity Protection is disabled.",
            "Re-enable SIP unless there is a documented operational reason.",
        )
    return unavailable_finding(
        "Antivirus",
        "System Integrity Protection",
        "SIP status could not be parsed",
        "Review SIP status manually if this is a managed Mac.",
    )


def _latest_xprotect_install_date() -> dt.date | None:
    pkgs = run_command(["pkgutil", "--pkgs"], timeout=6)
    receipts = _xprotect_receipts(pkgs.stdout)
    dates: list[dt.date] = []
    for receipt in receipts:
        info = run_command(["pkgutil", "--pkg-info", receipt], timeout=6)
        install_time = _pkg_install_time(info.stdout)
        if install_time:
            dates.append(install_time)
    return max(dates) if dates else None


def _xprotect_receipts(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("com.apple.pkg.XProtect")
    ]


def _pkg_install_time(text: str) -> dt.date | None:
    match = re.search(r"install-time:\s*(\d+)", text)
    if not match:
        return None
    return dt.datetime.fromtimestamp(int(match.group(1))).date()


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        clean = value.strip()
        key = clean.lower()
        if not clean or key in seen:
            continue
        seen.add(key)
        deduped.append(clean)
    return deduped

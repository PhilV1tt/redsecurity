from __future__ import annotations

import grp
import os
import pwd
import re
from pathlib import Path

from besecured.checks.common import command_exists, file_age_days, file_mentions_temp, readable_files, run_checks, run_command, unavailable_finding
from besecured.models import Finding


def run_linux_checks() -> list[Finding]:
    checks = [
        ("Firewall", check_firewall),
        ("Updates", check_updates),
        ("Disk Encryption", check_disk_encryption),
        ("User Accounts", check_users),
        ("Password Policy", check_password_policy),
        ("Shared Folders", check_shared_folders),
        ("Startup Programs", check_startup_programs),
        ("Antivirus", check_antivirus),
        ("Privilege Elevation", check_privilege_model),
    ]
    return _linux_findings(run_checks(checks))


def _linux_findings(findings: list[Finding]) -> list[Finding]:
    return [finding.with_context(supported_os=("Linux",)) for finding in findings]


def check_firewall() -> list[Finding]:
    category = "Firewall"
    checked_tools: list[str] = []
    blocked_tools: list[str] = []
    if command_exists("ufw"):
        checked_tools.append("ufw")
        result = run_command(["ufw", "status"], timeout=6)
        if "Status: active" in result.stdout:
            return [Finding(category, "UFW", "OK", "UFW firewall is active.", "Keep UFW enabled and allow only required services.")]
        if "Status: inactive" in result.stdout:
            return [Finding(category, "UFW", "CRIT", "UFW firewall is inactive.", "Enable UFW or another local firewall.")]
        if _command_blocked(result):
            blocked_tools.append("ufw")

    if command_exists("firewall-cmd"):
        checked_tools.append("firewall-cmd")
        result = run_command(["firewall-cmd", "--state"], timeout=6)
        if "running" in result.stdout:
            return [Finding(category, "firewalld", "OK", "firewalld is running.", "Keep firewalld enabled and restrict exposed services.")]
        if _command_blocked(result):
            blocked_tools.append("firewall-cmd")

    if command_exists("nft"):
        checked_tools.append("nft")
        result = run_command(["nft", "list", "ruleset"], timeout=6)
        if "table " in result.stdout:
            return [Finding(category, "nftables", "OK", "nftables has an active ruleset.", "Review firewall rules periodically.")]
        if _command_blocked(result):
            blocked_tools.append("nft")

    if command_exists("iptables"):
        checked_tools.append("iptables")
        result = run_command(["iptables", "-S"], timeout=6)
        if _iptables_has_rules(result.stdout):
            return [Finding(category, "iptables", "OK", "iptables has non-default filtering rules.", "Review firewall rules periodically.")]
        if _command_blocked(result):
            blocked_tools.append("iptables")

    if not checked_tools:
        return [
            unavailable_finding(
                category,
                "Firewall Check",
                "no supported Linux firewall command was found",
                "Install or enable UFW, firewalld, nftables or iptables if this machine needs a local firewall.",
            )
        ]

    if blocked_tools and len(blocked_tools) == len(checked_tools):
        return [
            unavailable_finding(
                category,
                "Firewall Check",
                f"{', '.join(blocked_tools)} could not be queried with current privileges",
                "Run with appropriate privileges or review firewall status manually.",
            )
        ]

    return [Finding(category, "Firewall Check", "WARN", "No active Linux firewall was detected with common tools.", "Enable UFW, firewalld or nftables and allow only required services.")]


def check_updates() -> list[Finding]:
    category = "Updates"
    candidates = [
        Path("/var/lib/apt/periodic/update-success-stamp"),
        Path("/var/log/dpkg.log"),
        Path("/var/log/apt/history.log"),
        Path("/var/log/dnf.log"),
        Path("/var/log/yum.log"),
        Path("/var/log/pacman.log"),
    ]
    existing = [path for path in candidates if path.exists()]
    ages = [age for age in (file_age_days(path) for path in existing) if age is not None]
    if not existing:
        return [
            unavailable_finding(
                category,
                "Package Updates",
                "no common package manager log or update stamp was found",
                "Run the system package updater and verify security updates through the distribution tools.",
            )
        ]
    if not ages:
        return [Finding(category, "Package Updates", "WARN", "Could not determine package update freshness.", "Run the system package updater and install security updates.")]
    age = min(ages)
    if age < 30:
        status = "OK"
    elif age < 90:
        status = "WARN"
    else:
        status = "CRIT"
    return [Finding(category, "Package Updates", status, f"Most recent package activity was {age} day(s) ago.", "Run the system package updater and install security updates.")]


def check_disk_encryption() -> list[Finding]:
    category = "Disk Encryption"
    if not command_exists("lsblk"):
        return [
            unavailable_finding(
                category,
                "LUKS/dm-crypt",
                "lsblk is not available",
                "Check disk encryption through the distribution installer, Disks app or storage management tools.",
            )
        ]

    result = run_command(["lsblk", "-P", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT,PKNAME"], timeout=8)
    if not result.stdout:
        return [Finding(category, "LUKS/dm-crypt", "WARN", "Could not inspect block devices with lsblk.", "Check whether the root disk uses LUKS or another full-disk encryption setup.")]
    return [_linux_disk_encryption_finding(result.stdout)]


def check_users() -> list[Finding]:
    category = "User Accounts"
    findings: list[Finding] = []
    users = list(pwd.getpwall())
    uid0_users = [user.pw_name for user in users if user.pw_uid == 0]
    findings.append(
        Finding(
            category,
            "UID 0 Accounts",
            "OK" if uid0_users == ["root"] else "CRIT",
            f"UID 0 account(s): {', '.join(uid0_users)}",
            "Only root should have UID 0.",
        )
    )

    admin_groups = _group_members(["sudo", "wheel", "admin"])
    findings.append(
        Finding(
            category,
            "Admin Groups",
            "INFO" if len(admin_groups) <= 3 else "WARN",
            f"Privileged group member(s): {', '.join(admin_groups) if admin_groups else 'none detected'}",
            "Keep sudo or wheel membership limited to users who need admin rights.",
        )
    )

    findings.append(
        unavailable_finding(
            category,
            "Guest Account",
            "Linux has no single built-in Guest account model",
            "Check distribution-specific guest sessions manually if this machine exposes a shared desktop login.",
        )
    )

    if os.access("/etc/shadow", os.R_OK):
        passwordless = _passwordless_shadow_users(Path("/etc/shadow"))
        findings.append(
            Finding(
                category,
                "No-Password Accounts",
                "CRIT" if passwordless else "OK",
                f"Accounts with empty password field: {', '.join(passwordless)}" if passwordless else "No empty password fields detected in /etc/shadow.",
                "Lock or set passwords for accounts with empty password fields.",
                requires_admin=True,
            )
        )
    else:
        findings.append(
            Finding(
                category,
                "No-Password Accounts",
                "SKIP",
                "Cannot read /etc/shadow without elevated privileges.",
                "Run with appropriate privileges or ask an administrator to verify passwordless accounts.",
                requires_admin=True,
            )
        )
    return findings


def check_password_policy() -> list[Finding]:
    category = "Password Policy"
    login_defs = Path("/etc/login.defs")
    if not login_defs.exists():
        return [
            unavailable_finding(
                category,
                "Password Policy",
                "/etc/login.defs was not found",
                "Review password policy through the distribution security settings.",
            )
        ]

    values = _parse_login_defs(login_defs)
    min_len = _to_int(values.get("PASS_MIN_LEN"))
    max_days = _to_int(values.get("PASS_MAX_DAYS"))
    findings = [
        Finding(
            category,
            "Min Password Length",
            "OK" if min_len is not None and min_len >= 8 else "WARN",
            f"PASS_MIN_LEN is {min_len if min_len is not None else 'not configured'}.",
            "Set a minimum password length of at least 8 characters, preferably more.",
        ),
        Finding(
            category,
            "Password Expiry",
            "WARN" if max_days is None or max_days == 99999 or max_days > 365 else "OK",
            f"PASS_MAX_DAYS is {max_days if max_days is not None else 'not configured'}.",
            "Use a reasonable password aging policy where it fits the environment.",
        ),
    ]
    findings.append(_pam_password_quality_finding())
    return findings


def check_shared_folders() -> list[Finding]:
    category = "Shared Folders"
    findings: list[Finding] = []
    smb_conf = Path("/etc/samba/smb.conf")
    if smb_conf.exists():
        shares = _samba_shares(smb_conf)
        for share in shares:
            findings.append(Finding(category, f"Samba Share: {share}", "WARN", "Custom Samba share configured.", "Remove unnecessary shares or restrict them to trusted users."))

    exports = Path("/etc/exports")
    if exports.exists():
        exported = [line.strip() for line in exports.read_text(errors="ignore").splitlines() if line.strip() and not line.lstrip().startswith("#")]
        for line in exported:
            findings.append(Finding(category, "NFS Export", "WARN", f"NFS export configured: {line}", "Remove unnecessary exports or restrict them to trusted hosts."))

    return findings or [Finding(category, "Custom Shares", "OK", "No Samba shares or NFS exports detected in common config files.", "Keep sharing disabled unless it is needed.")]


def check_startup_programs() -> list[Finding]:
    category = "Startup Programs"
    paths = [
        Path.home() / ".config/autostart",
        Path("/etc/xdg/autostart"),
        Path.home() / ".config/systemd/user",
        Path("/etc/systemd/system"),
    ]
    files = readable_files(paths)
    suspicious = [path for path in files if file_mentions_temp(path)]
    findings = [
        Finding(
            category,
            "Startup Entries",
            "INFO" if len(files) <= 25 else "WARN",
            f"{len(files)} startup or service file(s) found in common locations.",
            "Review startup entries and disable services that are not needed.",
        )
    ]
    if suspicious:
        findings.append(
            Finding(
                category,
                "Suspicious Startup",
                "CRIT",
                f"Startup file(s) mention temporary paths: {', '.join(str(path) for path in suspicious[:5])}",
                "Investigate the referenced startup files before deleting evidence.",
            )
        )
    return findings


def check_antivirus() -> list[Finding]:
    category = "Antivirus"
    service_names = ["clamav-daemon", "clamd"]
    if command_exists("systemctl"):
        for service in service_names:
            result = run_command(["systemctl", "is-active", service], timeout=5)
            if result.stdout.strip() == "active":
                return [Finding(category, "ClamAV", "OK", f"{service} is active.", "Keep antivirus signatures updated.")]
    return [Finding(category, "Linux AV", "INFO", "No common Linux antivirus daemon detected. This is not always required on desktop Linux.", "Use the security tooling required by your organization and keep packages updated.")]


def check_privilege_model() -> list[Finding]:
    return [
        Finding(
            "Privilege Elevation",
            "UAC Equivalent",
            "INFO",
            "Linux uses sudo, polkit and file permissions instead of Windows UAC.",
            "Use a standard user account for daily work and elevate only when needed.",
        )
    ]


def _iptables_has_rules(text: str) -> bool:
    for line in text.splitlines():
        clean = line.strip()
        if clean.startswith("-A "):
            return True
        if clean.startswith("-P ") and not clean.endswith(" ACCEPT"):
            return True
    return False


def _command_blocked(result) -> bool:
    text = f"{result.stdout} {result.stderr}".lower()
    blocked = [
        "permission denied",
        "operation not permitted",
        "not permitted",
        "must be root",
        "you need to be root",
        "access denied",
    ]
    return result.returncode not in (0, None) and any(marker in text for marker in blocked)


def _linux_disk_encryption_finding(text: str) -> Finding:
    rows = [_lsblk_row(line) for line in text.splitlines()]
    rows = [row for row in rows if row]
    root_rows = [row for row in rows if row.get("mountpoint") == "/"]
    if any(_root_row_mentions_crypto(row) for row in root_rows):
        return Finding(
            "Disk Encryption",
            "LUKS/dm-crypt",
            "OK",
            "The root filesystem appears to be backed by LUKS or dm-crypt.",
            "Keep the recovery key stored safely and separate from the device.",
        )
    if root_rows:
        detail = "No LUKS or dm-crypt device was visible for the root filesystem."
        if any(_row_mentions_crypto(row) for row in rows):
            detail = "An encrypted device is visible, but the root filesystem is not clearly on it."
        return Finding(
            "Disk Encryption",
            "LUKS/dm-crypt",
            "WARN",
            detail,
            "Enable full-disk encryption on laptops and machines that may leave a trusted location.",
        )
    return unavailable_finding(
        "Disk Encryption",
        "LUKS/dm-crypt",
        "the root filesystem could not be identified from lsblk output",
        "Check disk encryption manually with the distribution storage tools.",
    )


def _lsblk_row(line: str) -> dict[str, str]:
    values = {key.lower(): value for key, value in re.findall(r'(\w+)="([^"]*)"', line)}
    if "name" not in values or "type" not in values:
        return {}
    return values


def _row_mentions_crypto(row: dict[str, str]) -> bool:
    return any("crypt" in row.get(key, "").lower() for key in ["name", "type", "fstype"])


def _root_row_mentions_crypto(row: dict[str, str]) -> bool:
    return _row_mentions_crypto(row) or "crypt" in row.get("pkname", "").lower()


def _group_members(group_names: list[str]) -> list[str]:
    members: set[str] = set()
    for group_name in group_names:
        try:
            group = grp.getgrnam(group_name)
        except KeyError:
            continue
        members.update(group.gr_mem)
        for user in pwd.getpwall():
            if user.pw_gid == group.gr_gid:
                members.add(user.pw_name)
    return sorted(members)


def _passwordless_shadow_users(path: Path) -> list[str]:
    users: list[str] = []
    for line in path.read_text(errors="ignore").splitlines():
        fields = line.split(":")
        if len(fields) > 1 and fields[1] == "":
            users.append(fields[0])
    return users


def _parse_login_defs(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(errors="ignore").splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean:
            continue
        parts = clean.split()
        if len(parts) >= 2:
            values[parts[0]] = parts[1]
    return values


def _pam_password_quality_finding() -> Finding:
    paths = [
        Path("/etc/pam.d/common-password"),
        Path("/etc/pam.d/system-auth"),
        Path("/etc/pam.d/password-auth"),
    ]
    files = [path for path in paths if path.exists()]
    if not files:
        return unavailable_finding(
            "Password Policy",
            "Password Complexity",
            "no common PAM password policy file was found",
            "Review password complexity through PAM or the distribution security tools.",
        )

    modules: set[str] = set()
    for path in files:
        try:
            modules.update(_pam_quality_modules_from_text(path.read_text(errors="ignore")))
        except OSError:
            continue

    if modules:
        return Finding(
            "Password Policy",
            "Password Complexity",
            "OK",
            f"Common PAM password quality module(s) detected: {', '.join(sorted(modules))}.",
            "Keep password quality settings aligned with the machine context.",
        )
    return Finding(
        "Password Policy",
        "Password Complexity",
        "WARN",
        "No pam_pwquality or pam_cracklib rule was found in common PAM password files.",
        "Add PAM password quality rules if this machine relies on local passwords.",
    )


def _pam_quality_modules_from_text(text: str) -> set[str]:
    modules: set[str] = set()
    for line in text.splitlines():
        clean = line.split("#", 1)[0]
        if "pam_pwquality.so" in clean:
            modules.add("pam_pwquality")
        if "pam_cracklib.so" in clean:
            modules.add("pam_cracklib")
    return modules


def _to_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _samba_shares(path: Path) -> list[str]:
    ignored = {"global", "printers", "print$"}
    shares: list[str] = []
    for match in re.finditer(r"^\s*\[([^\]]+)\]", path.read_text(errors="ignore"), flags=re.MULTILINE):
        share = match.group(1).strip()
        if share.lower() not in ignored:
            shares.append(share)
    return shares

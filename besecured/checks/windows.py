from __future__ import annotations

import json
import re
import shutil
import unicodedata

from besecured.checks.common import run_command, unavailable_finding
from besecured.models import Finding


def run_windows_checks() -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_firewall())
    findings.extend(check_updates())
    findings.extend(check_disk_encryption())
    findings.extend(check_users())
    findings.extend(check_password_policy())
    findings.extend(check_shared_folders())
    findings.extend(check_startup_programs())
    findings.extend(check_antivirus())
    findings.extend(check_uac())
    return findings


def check_firewall() -> list[Finding]:
    category = "Firewall"
    skip = _powershell_skip(category, "Firewall Check", "Open Windows Security and verify that all firewall profiles are enabled.")
    if skip:
        return skip
    data = _powershell_json("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
    if data is None:
        return [Finding(category, "Firewall Check", "WARN", "Could not query Windows Firewall.", "Open Windows Security and verify that all firewall profiles are enabled.")]

    profiles = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    for profile in profiles:
        name = str(profile.get("Name", "Unknown"))
        enabled = bool(profile.get("Enabled"))
        findings.append(
            Finding(
                category,
                f"Firewall ({name})",
                "OK" if enabled else "CRIT",
                f"Profile {name} is {'enabled' if enabled else 'disabled'}.",
                "Keep Windows Firewall enabled on Domain, Private and Public profiles.",
            )
        )
    return findings


def check_updates() -> list[Finding]:
    category = "Updates"
    skip = _powershell_skip(category, "Last Hotfix", "Run Windows Update and install pending security updates.")
    if skip:
        return skip
    script = """
    $h = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($h -and $h.InstalledOn) { [int](((Get-Date) - [datetime]$h.InstalledOn).TotalDays) } else { "UNKNOWN" }
    """
    result = _powershell(script)
    if not result.stdout or "UNKNOWN" in result.stdout:
        return [Finding(category, "Last Hotfix", "WARN", "Could not determine last Windows update date.", "Run Windows Update and install pending security updates.")]

    days = _first_int(result.stdout)
    if days is None:
        return [Finding(category, "Last Hotfix", "WARN", "Could not parse Windows update age.", "Run Windows Update and install pending security updates.")]
    return [_age_finding(category, "Last Hotfix", days, "Windows hotfix")]


def check_disk_encryption() -> list[Finding]:
    category = "Disk Encryption"
    skip = _powershell_skip(category, "BitLocker", "Review BitLocker or Device Encryption status in Windows Security.")
    if skip:
        return skip
    script = """
    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue |
      Select-Object MountPoint,VolumeStatus,ProtectionStatus
    [pscustomobject]@{ Volumes = @($volumes) } | ConvertTo-Json -Depth 4 -Compress
    """
    data = _powershell_json(script)
    if data is None:
        return [
            unavailable_finding(
                category,
                "BitLocker",
                "BitLocker cmdlets returned no usable data",
                "Review BitLocker or Device Encryption status in Windows Security.",
            )
        ]
    return _bitlocker_findings_from_payload(data)


def check_users() -> list[Finding]:
    category = "User Accounts"
    skip = _powershell_skip(category, "User Audit", "Run the scanner as Administrator or review local users manually.")
    if skip:
        return skip
    script = """
    $userProbeOk = $false
    $adminProbeOk = $false
    $users = @()
    $admins = @()
    try {
      $users = @(Get-LocalUser -ErrorAction Stop | Select-Object Name,Enabled,PasswordRequired,@{Name="SID";Expression={$_.SID.Value}})
      $userProbeOk = $true
    } catch {}
    try {
      $adminGroup = Get-LocalGroup -ErrorAction Stop | Where-Object { $_.SID.Value -eq "S-1-5-32-544" } | Select-Object -First 1
      if ($adminGroup) {
        $admins = @(Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction Stop | Select-Object Name,SID,ObjectClass)
        $adminProbeOk = $true
      }
    } catch {}
    [pscustomobject]@{
      UserProbeOk = $userProbeOk
      AdminProbeOk = $adminProbeOk
      Users = $users
      Admins = $admins
    } | ConvertTo-Json -Depth 4 -Compress
    """
    data = _powershell_json(script)
    if data is None:
        return [Finding(category, "User Audit", "WARN", "Could not audit Windows local users.", "Run the scanner as Administrator or review local users manually.")]
    return _windows_user_findings_from_payload(data)


def check_password_policy() -> list[Finding]:
    category = "Password Policy"
    result = run_command(["net", "accounts"], timeout=8)
    if not result.stdout:
        return [Finding(category, "Password Policy", "WARN", "Could not retrieve Windows password policy.", "Review local security policy and require strong passwords.")]

    min_length = _value_after_labels(result.stdout, ["Minimum password length", "Longueur minimale du mot de passe"])
    max_age = _value_after_labels(
        result.stdout,
        [
            "Maximum password age",
            "Durée maximale du mot de passe",
            "Duree maximale du mot de passe",
            "Durée de vie maximale du mot de passe",
            "Duree de vie maximale du mot de passe",
        ],
    )
    findings = [
        Finding(
            category,
            "Min Password Length",
            "OK" if min_length is not None and min_length >= 8 else "WARN",
            f"Minimum password length is {min_length if min_length is not None else 'unknown'} characters.",
            "Set the minimum password length to at least 8 characters, preferably more.",
        )
    ]
    findings.append(
        Finding(
            category,
            "Password Expiry",
            "WARN" if max_age is None or max_age == 0 or max_age > 365 else "OK",
            "Passwords never expire or expire after a very long time." if max_age is None or max_age == 0 or max_age > 365 else f"Passwords expire every {max_age} days.",
            "Use a reasonable password policy and focus on strong unique passwords plus MFA where available.",
        )
    )
    return findings


def check_shared_folders() -> list[Finding]:
    category = "Shared Folders"
    skip = _powershell_skip(category, "Shares Check", "Review Windows shared folders manually.")
    if skip:
        return skip
    script = """
    $probeOk = $false
    $shares = @()
    try {
      $shares = @(Get-SmbShare -ErrorAction Stop |
        Where-Object { $_.Name -notmatch "^(ADMIN\\$|C\\$|IPC\\$|print\\$|[A-Z]\\$)$" } |
        Select-Object Name,Path)
      $probeOk = $true
    } catch {}
    [pscustomobject]@{ ProbeOk = $probeOk; Shares = $shares } | ConvertTo-Json -Depth 4 -Compress
    """
    data = _powershell_json(script)
    if data is None:
        return [Finding(category, "Shares Check", "WARN", "Could not audit SMB shared folders.", "Review Windows shared folders manually.")]
    return _share_findings_from_payload(data)


def _share_findings_from_payload(data) -> list[Finding]:
    category = "Shared Folders"
    if not isinstance(data, dict) or data.get("ProbeOk") is not True:
        return [
            unavailable_finding(
                category,
                "Shares Check",
                "Windows SMB share cmdlet returned incomplete data",
                "Review Windows shared folders manually.",
            )
        ]

    shares = _as_list(data.get("Shares", []))
    if not shares:
        return [Finding(category, "Custom Shares", "OK", "No custom SMB shared folders detected.", "Keep file sharing disabled unless it is needed.")]

    return [
        Finding(
            category,
            f"Share: {share.get('Name', 'Unknown')}",
            "WARN",
            f"Shared folder path: {share.get('Path', 'Unknown')}",
            "Remove unnecessary shares or restrict them to trusted users.",
        )
        for share in shares
        if isinstance(share, dict)
    ]


def check_startup_programs() -> list[Finding]:
    category = "Startup Programs"
    skip = _powershell_skip(category, "Startup Audit", "Review Startup Apps and registry Run keys manually.")
    if skip:
        return skip
    script = """
    $paths = @(
      "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    $rows = @()
    foreach ($path in $paths) {
      $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
      if ($items) {
        $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
          $rows += [pscustomobject]@{ Name = $_.Name; Command = [string]$_.Value; Path = $path }
        }
      }
    }
    [pscustomobject]@{ Entries = @($rows) } | ConvertTo-Json -Depth 4 -Compress
    """
    data = _powershell_json(script)
    if data is None:
        return [Finding(category, "Startup Audit", "WARN", "Could not audit Windows startup entries.", "Review Startup Apps and registry Run keys manually.")]
    startup = _as_list(data.get("Entries", []))
    findings = [
        Finding(
            category,
            "Startup Entries",
            "INFO" if len(startup) <= 10 else "WARN",
            f"{len(startup)} startup entrie(s) found.",
            "Review startup entries and remove software that does not need to launch automatically.",
        )
    ]
    suspicious = [item for item in startup if isinstance(item, dict) and re.search(r"\\(temp|tmp)\\", str(item.get("Command", "")), re.IGNORECASE)]
    if suspicious:
        names = ", ".join(str(item.get("Name", "Unknown")) for item in suspicious)
        findings.append(
            Finding(
                category,
                "Suspicious Startup",
                "CRIT",
                f"Startup command from TEMP path: {names}",
                "Disable the startup entry and investigate the referenced file before deleting evidence.",
            )
        )
    return findings


def check_antivirus() -> list[Finding]:
    category = "Antivirus"
    skip = _powershell_skip(category, "AV Check", "Open Windows Security and verify antivirus protection manually.")
    if skip:
        return skip
    script = """
    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($status) {
      [pscustomobject]@{
        DefenderAvailable = $true
        AntivirusEnabled = $status.AntivirusEnabled
        RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
        SignatureAgeDays = [int](((Get-Date) - $status.AntivirusSignatureLastUpdated).TotalDays)
      } | ConvertTo-Json -Compress
    } else {
      $av = Get-CimInstance -Namespace "root\\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
      [pscustomobject]@{
        DefenderAvailable = $false
        Products = @($av | Select-Object -ExpandProperty displayName)
      } | ConvertTo-Json -Compress
    }
    """
    data = _powershell_json(script)
    if data is None:
        return [Finding(category, "AV Check", "WARN", "Could not determine antivirus status.", "Open Windows Security and verify antivirus protection manually.")]

    if data.get("DefenderAvailable"):
        age = data.get("SignatureAgeDays")
        findings = [
            Finding(
                category,
                "Windows Defender",
                "OK" if data.get("AntivirusEnabled") else "CRIT",
                "Defender antivirus is enabled." if data.get("AntivirusEnabled") else "Defender antivirus is disabled.",
                "Enable Microsoft Defender or another trusted antivirus product.",
            ),
            Finding(
                category,
                "Real-Time Protection",
                "OK" if data.get("RealTimeProtectionEnabled") else "CRIT",
                "Real-time protection is active." if data.get("RealTimeProtectionEnabled") else "Real-time protection is off.",
                "Enable real-time protection in Windows Security.",
            ),
        ]
        if isinstance(age, int):
            findings.append(_age_finding(category, "Signature Age", age, "Defender signatures", warn_days=3, crit_days=7))
        return findings

    products = data.get("Products") or []
    if isinstance(products, str):
        products = [products]
    return [
        Finding(
            category,
            "Antivirus Product",
            "OK" if products else "CRIT",
            f"Detected antivirus product(s): {', '.join(products)}" if products else "No antivirus product detected.",
            "Install or enable a trusted antivirus product.",
        )
    ]


def check_uac() -> list[Finding]:
    category = "UAC"
    skip = _powershell_skip(category, "UAC Enabled", "Open Windows security settings and verify that UAC is enabled.")
    if skip:
        return skip
    script = '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -ErrorAction SilentlyContinue).EnableLUA'
    result = _powershell(script)
    value = result.stdout.strip()
    if value not in {"0", "1"}:
        return [
            Finding(
                category,
                "UAC Enabled",
                "WARN",
                "Could not determine User Account Control status.",
                "Open Windows security settings and verify that UAC is enabled.",
            )
        ]
    enabled = value == "1"
    return [
        Finding(
            category,
            "UAC Enabled",
            "OK" if enabled else "CRIT",
            "User Account Control is enabled." if enabled else "User Account Control is disabled.",
            "Keep UAC enabled so privilege elevation requires confirmation.",
        )
    ]


def _powershell_available() -> bool:
    return _powershell_executable() is not None


def _powershell_executable() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")


def _powershell_skip(category: str, name: str, remediation: str) -> list[Finding]:
    if _powershell_available():
        return []
    return [
        unavailable_finding(
            category,
            name,
            "PowerShell is not available",
            remediation,
        )
    ]


def _powershell(script: str):
    executable = _powershell_executable()
    if not executable:
        return run_command(["powershell.exe", "-Command", script], timeout=1)
    return run_command([executable, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=15)


def _powershell_json(script: str):
    result = _powershell(script)
    if not result.stdout:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _admin_names_from_payload(data) -> list[str]:
    admins = _as_list(data.get("Admins", [])) if isinstance(data, dict) else []
    return [str(item.get("Name", "")) for item in admins if isinstance(item, dict) and item.get("Name")]


def _windows_user_findings_from_payload(data) -> list[Finding]:
    category = "User Accounts"
    if not isinstance(data, dict) or data.get("UserProbeOk") is not True or data.get("AdminProbeOk") is not True:
        return [
            unavailable_finding(
                category,
                "User Audit",
                "Windows local user cmdlets returned incomplete data",
                "Run the scanner as Administrator or review local users manually.",
            )
        ]

    users = _as_list(data.get("Users", []))
    if not users:
        return [
            unavailable_finding(
                category,
                "User Audit",
                "Windows local user list was empty",
                "Run the scanner as Administrator or review local users manually.",
            )
        ]

    admin_names = _admin_names_from_payload(data)
    if admin_names:
        findings = [
            Finding(
                category,
                "Admin Accounts",
                "OK" if len(admin_names) <= 2 else "WARN",
                f"{len(admin_names)} administrator principal(s): {', '.join(admin_names)}",
                "Keep only the accounts and groups that truly need administrator rights.",
            )
        ]
    else:
        findings = [
            unavailable_finding(
                category,
                "Admin Accounts",
                "Windows administrator group returned no members",
                "Review the local Administrators group manually.",
            )
        ]

    guest_enabled = _guest_enabled_from_users(users)
    findings.append(
        Finding(
            category,
            "Guest Account",
            "CRIT" if guest_enabled else "OK",
            "Guest account is enabled." if guest_enabled else "Guest account is disabled.",
            "Disable the Guest account unless there is a documented need.",
        )
    )

    no_password = _no_password_users(users)
    findings.append(
        Finding(
            category,
            "No-Password Accounts",
            "CRIT" if no_password else "OK",
            f"Accounts without required password: {', '.join(no_password)}" if no_password else "All enabled accounts require a password.",
            "Require passwords for every enabled local account.",
        )
    )
    return findings


def _bitlocker_findings_from_payload(data) -> list[Finding]:
    volumes = _as_list(data.get("Volumes", [])) if isinstance(data, dict) else []
    volumes = [volume for volume in volumes if isinstance(volume, dict)]
    if not volumes:
        return [
            unavailable_finding(
                "Disk Encryption",
                "BitLocker",
                "no BitLocker volume data was returned",
                "Review BitLocker or Device Encryption status in Windows Security.",
            )
        ]

    findings: list[Finding] = []
    for volume in volumes:
        mount = str(volume.get("MountPoint") or "Unknown volume")
        protection = _bitlocker_protection_text(volume.get("ProtectionStatus"))
        protected = protection == "on"
        findings.append(
            Finding(
                "Disk Encryption",
                f"BitLocker ({mount})",
                "OK" if protected else "WARN",
                f"BitLocker protection is {protection} for {mount}.",
                "Enable BitLocker or Device Encryption on portable machines and sensitive disks.",
            )
        )
    return findings


def _bitlocker_protection_text(value) -> str:
    clean = str(value).strip().lower()
    if clean in {"1", "on", "true"}:
        return "on"
    if clean in {"0", "off", "false"}:
        return "off"
    return clean or "unknown"


def _guest_enabled_from_users(users) -> bool:
    for user in users:
        if not isinstance(user, dict):
            continue
        sid = str(user.get("SID", ""))
        name = str(user.get("Name", "")).lower()
        if user.get("Enabled") and (sid.endswith("-501") or name in {"guest", "invité", "invite"}):
            return True
    return False


def _no_password_users(users) -> list[str]:
    return [
        str(user.get("Name"))
        for user in users
        if isinstance(user, dict) and user.get("Enabled") and user.get("PasswordRequired") is False
    ]


def _first_int(text: str) -> int | None:
    match = re.search(r"\d+", text)
    return int(match.group(0)) if match else None


def _value_after_labels(text: str, labels: list[str]) -> int | None:
    normalized_labels = [_normalize_text(label) for label in labels]
    for line in text.splitlines():
        normalized_line = _normalize_text(line)
        if any(label in normalized_line for label in normalized_labels):
            return _first_int(line)
    return None


def _normalize_text(value: str) -> str:
    without_accents = "".join(
        char for char in unicodedata.normalize("NFKD", value) if not unicodedata.combining(char)
    )
    return without_accents.casefold()


def _age_finding(category: str, name: str, days: int, label: str, warn_days: int = 30, crit_days: int = 90) -> Finding:
    if days < warn_days:
        status = "OK"
    elif days < crit_days:
        status = "WARN"
    else:
        status = "CRIT"
    return Finding(
        category,
        name,
        status,
        f"{label} last updated {days} day(s) ago.",
        "Install pending security updates as soon as possible.",
    )

# BeSecured

BeSecured is a local cybersecurity awareness scanner for Windows, Linux and macOS.

It runs passive checks on the current machine, calculates a simple 0 to 100 risk score, then exports a clear local report with findings and remediation steps. It is designed for non technical users and small organizations. It is not a penetration testing tool.

## Run

Requirements:

- Python 3.10 or newer
- No external Python packages

From the project folder:

```bash
python -m besecured
```

Write the report to a specific path:

```bash
python -m besecured --output SecurityReport.html --no-open
```

Generate JSON instead of HTML:

```bash
python -m besecured --format json --output SecurityReport.json
```

Generate both HTML and JSON:

```bash
python -m besecured --output SecurityReport.html --json-output SecurityReport.json --no-open
```

## What It Checks

Common checks:

- Listening TCP ports and risky exposed services
- Scanner privilege context
- Basic system information
- Risk score and findings ranked by severity
- Local HTML or JSON report export

Windows checks:

- Windows Firewall profiles
- Last installed hotfix
- BitLocker or Device Encryption status when PowerShell exposes it
- Local users, administrator accounts, Guest account and accounts without password requirement
- Password policy through `net accounts`
- SMB shares
- Startup registry entries
- Microsoft Defender or registered antivirus status
- Real-time protection, signature age and UAC

Linux checks:

- Firewall status through common tools such as UFW, firewalld, nftables or iptables
- Package update freshness from common package logs
- LUKS or dm-crypt visibility through `lsblk`
- UID 0 accounts, privileged groups and passwordless accounts when `/etc/shadow` is readable
- Password policy from `/etc/login.defs` and common PAM password quality files
- Samba shares, NFS exports and common startup/service files
- ClamAV detection when present

macOS checks:

- Application Firewall
- Software update history
- FileVault status
- Admin group, Guest account and safe account checks
- Shared folders
- LaunchAgents and LaunchDaemons
- Gatekeeper, System Integrity Protection and XProtect package freshness

Unsupported checks, missing local tools and checks limited by permissions are marked as `SKIP` or `INFO` and do not reduce the score.

## Scoring

Only `OK`, `WARN` and `CRIT` findings affect the score. `INFO` and `SKIP` findings are shown for transparency but are not scored.

Each scored finding has a severity weight:

```text
OK   = 0 severity points lost
WARN = 2 severity points lost
CRIT = 5 severity points lost
```

The final score is:

```text
score = 100 - round(lost severity points / maximum possible severity points * 100)
```

The final score is clamped between 0 and 100. The HTML and JSON reports include the number of scored checks, the points lost, the maximum possible points, and the main categories that reduced the score.

Grades:

- A: 90 to 100
- B: 75 to 89
- C: 60 to 74
- D: 40 to 59
- F: 0 to 39

## Privacy

BeSecured runs locally. It does not upload scan data, credentials, files or system details to an external service.

No account, API key, cloud service or remote backend is required.

The HTML report is self contained and does not load Chart.js, fonts or assets from a CDN.

Default reports are written to a local BeSecured app data folder, not to Desktop. URL paths, UNC paths, common cloud sync folders and common mounted network locations are rejected for report export.

## Legacy PowerShell MVP

`WindowsSecurityCheckv2.ps1` remains in the repository as the previous Windows only MVP baseline.

The Python CLI is now the main scanner path because it supports Windows, Linux and macOS.

## Validate

Run the unit tests:

```bash
python -m unittest discover -s tests
```

Run a local smoke test:

```bash
python -m besecured --output /tmp/BeSecured_Report.html --json-output /tmp/BeSecured_Report.json --no-open
```

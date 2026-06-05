#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Security Personality Checker
    Scans your system and generates a visual HTML security report.

.NOTES
    Run as Administrator for full results:
    Right-click PowerShell > Run as Administrator
    Then: .\WindowsSecurityCheck.ps1
#>

param(
    [string]$OutputPath = ""
)

# ─── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step($msg) {
    Write-Host "  >> $msg" -ForegroundColor Cyan
}
function Write-OK($msg)   { Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-WARN($msg) { Write-Host "  [!!]  $msg" -ForegroundColor Yellow }
function Write-CRIT($msg) { Write-Host "  [XX]  $msg" -ForegroundColor Red }

function Get-DefaultOutputPath {
    $base = [Environment]::GetFolderPath("LocalApplicationData")
    if ([string]::IsNullOrWhiteSpace($base)) { $base = Join-Path $env:USERPROFILE "AppData\Local" }
    return (Join-Path $base "BeSecured\Reports\SecurityReport.html")
}

function Test-LocalOutputPath($path) {
    if (($path -match "^[A-Za-z][A-Za-z0-9+.-]*:/") -and ($path -notmatch "^[A-Za-z]:[\\/]")) { return $false }
    if ($path.StartsWith("\\")) { return ($path -match "^\\\\\?\\[A-Za-z]:\\") }
    try {
        $full = [System.IO.Path]::GetFullPath($path)
        $normalized = $full.Replace("/", "\").ToLowerInvariant()
        $blockedPrefixes = @("\onedrive", "\dropbox", "\google drive", "\box sync", "\nextcloud", "\owncloud", "\creative cloud files", "\iclouddrive", "\icloud drive", "\mobile documents")
        foreach ($marker in $blockedPrefixes) {
            if ($normalized.Contains($marker)) { return $false }
        }
        $blockedExact = @("\box\")
        foreach ($marker in $blockedExact) {
            if ($normalized.Contains($marker)) { return $false }
        }
        $root = [System.IO.Path]::GetPathRoot($full)
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $drive = [System.IO.DriveInfo]::new($root)
            if ($drive.DriveType -eq [System.IO.DriveType]::Network) { return $false }
        }
    } catch {}
    return $true
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Get-DefaultOutputPath }

if (-not (Test-LocalOutputPath $OutputPath)) {
    Write-Host "  [XX] Refusing to write a report to a remote path. Use a local disk path." -ForegroundColor Red
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║   Windows Security Personality Checker   ║" -ForegroundColor Magenta
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""
if (-not $isAdmin) {
    Write-Host "  [NOTE] Not running as Administrator. Some checks may be limited." -ForegroundColor Yellow
    Write-Host ""
}

$findings = @()   # each: [category, name, status, detail]   status: OK / WARN / CRIT / INFO
$scores   = @{}   # category -> [good, total]

function Add-Finding($category, $name, $status, $detail) {
    $script:findings += [PSCustomObject]@{
        Category = $category
        Name     = $name
        Status   = $status
        Detail   = $detail
    }
    if (-not $script:scores.ContainsKey($category)) {
        $script:scores[$category] = @{Good=0; Total=0}
    }
    $script:scores[$category].Total++
    if ($status -eq "OK") { $script:scores[$category].Good++ }
}

# ─── 1. OPEN PORTS ─────────────────────────────────────────────────────────────
Write-Step "Scanning open ports..."
$cat = "Open Ports"
try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                 Select-Object LocalAddress, LocalPort, OwningProcess
    $riskyPorts = @{
        21="FTP"; 23="Telnet"; 25="SMTP"; 53="DNS"; 135="RPC";
        137="NetBIOS"; 139="NetBIOS"; 445="SMB"; 1433="MSSQL";
        3306="MySQL"; 3389="RDP"; 5900="VNC"; 8080="HTTP-Alt"
    }
    $openCount = ($listeners | Select-Object -ExpandProperty LocalPort -Unique).Count
    Add-Finding $cat "Total Listening Ports" "INFO" "$openCount ports listening"

    foreach ($l in ($listeners | Sort-Object LocalPort -Unique)) {
        $port = $l.LocalPort
        if ($riskyPorts.ContainsKey([int]$port)) {
            $svcName = $riskyPorts[[int]$port]
            # Try to get process name
            $proc = ""
            try { $proc = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).Name } catch {}
            Add-Finding $cat "Port $port ($svcName)" "WARN" "Exposed service: $svcName$(if($proc){" (Process: $proc)"})"
            Write-WARN "Risky port open: $port ($svcName)"
        }
    }
    # RDP specifically
    if ($listeners | Where-Object { $_.LocalPort -eq 3389 }) {
        Add-Finding $cat "RDP (3389)" "CRIT" "Remote Desktop is enabled and listening"
        Write-CRIT "RDP is open on port 3389"
    } else {
        Add-Finding $cat "RDP (3389)" "OK" "RDP not listening"
        Write-OK "RDP not exposed"
    }
} catch {
    Add-Finding $cat "Port Scan" "WARN" "Could not complete port scan: $_"
}

# ─── 2. FIREWALL ───────────────────────────────────────────────────────────────
Write-Step "Checking Windows Firewall..."
$cat = "Firewall"
try {
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($p in $profiles) {
        if ($p.Enabled) {
            Add-Finding $cat "Firewall ($($p.Name))" "OK" "Profile '$($p.Name)' is enabled"
            Write-OK "Firewall profile '$($p.Name)' enabled"
        } else {
            Add-Finding $cat "Firewall ($($p.Name))" "CRIT" "Profile '$($p.Name)' is DISABLED"
            Write-CRIT "Firewall profile '$($p.Name)' is disabled!"
        }
    }
} catch {
    Add-Finding $cat "Firewall Check" "WARN" "Could not query firewall profiles"
}

# ─── 3. WINDOWS UPDATE ─────────────────────────────────────────────────────────
Write-Step "Checking Windows Update status..."
$cat = "Updates"
try {
    $lastUpdate = (Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
    if ($lastUpdate) {
        $daysSince = ((Get-Date) - $lastUpdate).Days
        if ($daysSince -lt 30) {
            Add-Finding $cat "Last Hotfix" "OK" "Last hotfix installed $daysSince days ago ($lastUpdate)"
            Write-OK "Last hotfix: $daysSince days ago"
        } elseif ($daysSince -lt 90) {
            Add-Finding $cat "Last Hotfix" "WARN" "Last hotfix was $daysSince days ago - consider updating"
            Write-WARN "Last hotfix was $daysSince days ago"
        } else {
            Add-Finding $cat "Last Hotfix" "CRIT" "Last hotfix was $daysSince days ago - system likely unpatched"
            Write-CRIT "Last hotfix was $daysSince days ago!"
        }
    } else {
        Add-Finding $cat "Last Hotfix" "WARN" "Could not determine last update date"
    }
} catch {
    Add-Finding $cat "Update Check" "WARN" "Could not determine update status"
}

# ─── 4. LOCAL USERS & ADMINS ───────────────────────────────────────────────────
Write-Step "Auditing local users..."
$cat = "User Accounts"
try {
    $users = Get-LocalUser -ErrorAction SilentlyContinue
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

    $enabledAdmins = $admins | Where-Object { $_.ObjectClass -eq "User" }
    Add-Finding $cat "Admin Accounts" $(if($enabledAdmins.Count -le 2){"OK"}else{"WARN"}) "$($enabledAdmins.Count) admin account(s): $(($enabledAdmins.Name -join ', '))"

    $guestUser = $users | Where-Object { $_.Name -eq "Guest" -and $_.Enabled }
    if ($guestUser) {
        Add-Finding $cat "Guest Account" "CRIT" "Guest account is enabled — disable it"
        Write-CRIT "Guest account is enabled!"
    } else {
        Add-Finding $cat "Guest Account" "OK" "Guest account is disabled"
        Write-OK "Guest account disabled"
    }

    $noPasswordUsers = $users | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled }
    if ($noPasswordUsers) {
        Add-Finding $cat "Accounts Without Password" "CRIT" "$(($noPasswordUsers.Name -join ', ')) have no password required"
        Write-CRIT "Users without password: $(($noPasswordUsers.Name -join ', '))"
    } else {
        Add-Finding $cat "Password Required" "OK" "All enabled accounts require a password"
        Write-OK "All accounts require passwords"
    }
} catch {
    Add-Finding $cat "User Audit" "WARN" "Could not fully audit local users"
}

# ─── 5. PASSWORD POLICY ────────────────────────────────────────────────────────
Write-Step "Checking password policy..."
$cat = "Password Policy"
try {
    $netAccounts = net accounts 2>$null
    $minLen = ($netAccounts | Select-String "Minimum password length").ToString() -replace "\D", ""
    $maxAge  = ($netAccounts | Select-String "Maximum password age").ToString() -replace "[^0-9]", ""

    if ([int]$minLen -ge 8) {
        Add-Finding $cat "Min Password Length" "OK" "Minimum length is $minLen characters"
        Write-OK "Min password length: $minLen"
    } else {
        Add-Finding $cat "Min Password Length" "WARN" "Minimum length is only $minLen — recommend at least 8"
        Write-WARN "Weak min password length: $minLen"
    }

    if ($maxAge -eq "0" -or [int]$maxAge -gt 365) {
        Add-Finding $cat "Password Expiry" "WARN" "Passwords never expire or expire after a very long time ($maxAge days)"
    } else {
        Add-Finding $cat "Password Expiry" "OK" "Passwords expire every $maxAge days"
        Write-OK "Password expiry: $maxAge days"
    }
} catch {
    Add-Finding $cat "Password Policy" "WARN" "Could not retrieve password policy"
}

# ─── 6. SHARED FOLDERS ─────────────────────────────────────────────────────────
Write-Step "Checking shared folders..."
$cat = "Shared Folders"
try {
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -notmatch "^(ADMIN\$|C\$|IPC\$|print\$|[A-Z]\$)$"
    }
    if ($shares.Count -eq 0) {
        Add-Finding $cat "Custom Shares" "OK" "No custom shared folders detected"
        Write-OK "No custom shares"
    } else {
        foreach ($s in $shares) {
            Add-Finding $cat "Share: $($s.Name)" "WARN" "Shared folder '$($s.Name)' at path '$($s.Path)'"
            Write-WARN "Share found: $($s.Name) -> $($s.Path)"
        }
    }
    # Check for Everyone-accessible shares
    $everyoneShares = Get-SmbShareAccess -ErrorAction SilentlyContinue |
                      Where-Object { $_.AccountName -eq "Everyone" -and $_.AccessRight -ne "None" }
    if ($everyoneShares) {
        Add-Finding $cat "Everyone Access" "CRIT" "Some shares are accessible by Everyone: $(($everyoneShares.Name -join ', '))"
        Write-CRIT "Shares open to Everyone!"
    }
} catch {
    Add-Finding $cat "Shares Check" "WARN" "Could not fully audit shared folders"
}

# ─── 7. STARTUP PROGRAMS ───────────────────────────────────────────────────────
Write-Step "Auditing startup programs..."
$cat = "Startup Programs"
try {
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $allStartup = @()
    foreach ($path in $startupPaths) {
        try {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
            if ($items) {
                $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    $allStartup += [PSCustomObject]@{ Name=$_.Name; Command=$_.Value }
                }
            }
        } catch {}
    }
    Add-Finding $cat "Startup Entries" $(if($allStartup.Count -le 10){"INFO"}else{"WARN"}) "$($allStartup.Count) startup entries found"
    if ($allStartup.Count -gt 15) {
        Add-Finding $cat "Excessive Startup" "WARN" "More than 15 startup entries — review for unwanted programs"
        Write-WARN "Many startup entries: $($allStartup.Count)"
    } else {
        Write-OK "Startup entries: $($allStartup.Count)"
    }
    # Check for entries in temp/appdata locations
    $suspiciousPaths = $allStartup | Where-Object { $_.Command -match "(?i)(temp|appdata\\local\\temp|\\tmp\\)" }
    if ($suspiciousPaths) {
        Add-Finding $cat "Suspicious Startup Path" "CRIT" "Startup entries launching from TEMP: $(($suspiciousPaths.Name -join ', '))"
        Write-CRIT "Startup entries in TEMP folder!"
    }
} catch {
    Add-Finding $cat "Startup Audit" "WARN" "Could not audit startup programs"
}

# ─── 8. ANTIVIRUS / DEFENDER ───────────────────────────────────────────────────
Write-Step "Checking antivirus status..."
$cat = "Antivirus"
try {
    $av = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($av) {
        if ($av.AntivirusEnabled) {
            Add-Finding $cat "Windows Defender" "OK" "Defender is enabled and running"
            Write-OK "Windows Defender enabled"
        } else {
            Add-Finding $cat "Windows Defender" "CRIT" "Windows Defender is DISABLED"
            Write-CRIT "Defender is disabled!"
        }
        if ($av.RealTimeProtectionEnabled) {
            Add-Finding $cat "Real-Time Protection" "OK" "Real-time protection is active"
        } else {
            Add-Finding $cat "Real-Time Protection" "CRIT" "Real-time protection is OFF"
            Write-CRIT "Real-time protection is off!"
        }
        $defAge = ((Get-Date) - $av.AntivirusSignatureLastUpdated).Days
        if ($defAge -le 3) {
            Add-Finding $cat "Signature Age" "OK" "Virus definitions updated $defAge day(s) ago"
            Write-OK "Definitions: $defAge days old"
        } elseif ($defAge -le 7) {
            Add-Finding $cat "Signature Age" "WARN" "Virus definitions are $defAge days old"
            Write-WARN "Definitions: $defAge days old"
        } else {
            Add-Finding $cat "Signature Age" "CRIT" "Virus definitions are $defAge days old — update immediately"
            Write-CRIT "Definitions: $defAge days old!"
        }
    } else {
        # Try WMI fallback
        $wmiAV = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($wmiAV) {
            Add-Finding $cat "Antivirus (WMI)" "OK" "AV product detected: $(($wmiAV.displayName -join ', '))"
            Write-OK "AV: $(($wmiAV.displayName -join ', '))"
        } else {
            Add-Finding $cat "Antivirus" "CRIT" "No antivirus product detected"
            Write-CRIT "No antivirus found!"
        }
    }
} catch {
    Add-Finding $cat "AV Check" "WARN" "Could not determine antivirus status"
}

# ─── 9. UAC ────────────────────────────────────────────────────────────────────
Write-Step "Checking UAC settings..."
$cat = "UAC"
try {
    $uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
    if ($uacVal -eq 1) {
        Add-Finding $cat "UAC Enabled" "OK" "User Account Control is enabled"
        Write-OK "UAC is enabled"
    } else {
        Add-Finding $cat "UAC Enabled" "CRIT" "UAC is DISABLED — elevation prompts won't appear"
        Write-CRIT "UAC is disabled!"
    }
} catch {
    Add-Finding $cat "UAC Check" "WARN" "Could not determine UAC status"
}

# ─── 10. SYSTEM INFO ───────────────────────────────────────────────────────────
Write-Step "Gathering system info..."
$sysInfo = @{}
try {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $sysInfo["OS"]         = "$($os.Caption) (Build $($os.BuildNumber))"
    $sysInfo["Arch"]       = $os.OSArchitecture
    $sysInfo["Hostname"]   = $env:COMPUTERNAME
    $sysInfo["Username"]   = $env:USERNAME
    $sysInfo["Uptime"]     = "$([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)) hours"
    $sysInfo["RAM"]        = "$([math]::Round($os.TotalVisibleMemorySize / 1MB, 1)) GB"
    $sysInfo["CPU"]        = $cpu.Name.Trim()
    $sysInfo["IsAdmin"]    = $isAdmin.ToString()
    $sysInfo["ScanTime"]   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
} catch {
    $sysInfo["Error"] = "Could not fully retrieve system info"
}

# ─── CALCULATE SCORES ──────────────────────────────────────────────────────────
$totalGood  = ($findings | Where-Object { $_.Status -eq "OK" }).Count
$totalWarn  = ($findings | Where-Object { $_.Status -eq "WARN" }).Count
$totalCrit  = ($findings | Where-Object { $_.Status -eq "CRIT" }).Count
$totalInfo  = ($findings | Where-Object { $_.Status -eq "INFO" }).Count
$totalChecks = $totalGood + $totalWarn + $totalCrit

$overallScore = if ($totalChecks -gt 0) {
    [math]::Round((($totalGood / $totalChecks) * 100) - ($totalCrit * 5), 0)
} else { 0 }
$overallScore = [math]::Max(0, [math]::Min(100, $overallScore))

$grade = switch ($true) {
    { $overallScore -ge 90 } { "A"; break }
    { $overallScore -ge 75 } { "B"; break }
    { $overallScore -ge 60 } { "C"; break }
    { $overallScore -ge 40 } { "D"; break }
    default                  { "F" }
}

# ─── BUILD HTML ────────────────────────────────────────────────────────────────
Write-Step "Generating HTML report..."

# Build local chart rows
$categoryBars = ($scores.Keys | Sort-Object | ForEach-Object {
    $s = $scores[$_]
    $pct = if ($s.Total -gt 0) { [math]::Round(($s.Good / $s.Total) * 100) } else { 0 }
    "<div class='bar-row'><div class='bar-label'>$_</div><div class='bar-track'><span style='width:$pct%'></span></div><div class='bar-value'>$pct%</div></div>"
}) -join "`n"

$distTotal = [math]::Max(1, $totalGood + $totalWarn + $totalCrit + $totalInfo)
$okPct = [math]::Round(($totalGood / $distTotal) * 100)
$warnPct = [math]::Round(($totalWarn / $distTotal) * 100)
$critPct = [math]::Round(($totalCrit / $distTotal) * 100)
$infoPct = [math]::Round(($totalInfo / $distTotal) * 100)
$distributionBars = @"
<div class='bar-row'><div class='bar-label'>Passed</div><div class='bar-track'><span class='bar-ok' style='width:$okPct%'></span></div><div class='bar-value'>$totalGood</div></div>
<div class='bar-row'><div class='bar-label'>Warnings</div><div class='bar-track'><span class='bar-warn' style='width:$warnPct%'></span></div><div class='bar-value'>$totalWarn</div></div>
<div class='bar-row'><div class='bar-label'>Critical</div><div class='bar-track'><span class='bar-crit' style='width:$critPct%'></span></div><div class='bar-value'>$totalCrit</div></div>
<div class='bar-row'><div class='bar-label'>Info</div><div class='bar-track'><span class='bar-info' style='width:$infoPct%'></span></div><div class='bar-value'>$totalInfo</div></div>
"@

# Build findings table rows
$tableRows = ($findings | ForEach-Object {
    $color = switch ($_.Status) {
        "OK"   { "#22c55e" }
        "WARN" { "#f59e0b" }
        "CRIT" { "#ef4444" }
        "INFO" { "#60a5fa" }
        default { "#94a3b8" }
    }
    $icon = switch ($_.Status) {
        "OK"   { "✓" }
        "WARN" { "⚠" }
        "CRIT" { "✗" }
        "INFO" { "ℹ" }
        default { "?" }
    }
    $detail = [System.Web.HttpUtility]::HtmlEncode($_.Detail)
    "<tr><td class='cat'>$($_.Category)</td><td>$($_.Name)</td><td style='color:$color;font-weight:700;text-align:center'>$icon $($_.Status)</td><td class='detail'>$detail</td></tr>"
}) -join "`n"

# Build sysinfo rows
$sysRows = ($sysInfo.GetEnumerator() | ForEach-Object {
    "<tr><td class='si-key'>$($_.Key)</td><td class='si-val'>$($_.Value)</td></tr>"
}) -join "`n"

$gradeColor = switch ($grade) {
    "A" { "#22c55e" } "B" { "#84cc16" } "C" { "#f59e0b" } "D" { "#f97316" } default { "#ef4444" }
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report - $($sysInfo['Hostname'])</title>
<style>
  :root {
    --bg: #0a0e1a; --surface: #111827; --surface2: #1a2235;
    --border: #1e3a5f; --accent: #00d4ff; --accent2: #7c3aed;
    --ok: #22c55e; --warn: #f59e0b; --crit: #ef4444; --info: #60a5fa;
    --text: #e2e8f0; --muted: #64748b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         min-height: 100vh; padding: 2rem; }
  body::before {
    content: ''; position: fixed; inset: 0; z-index: -1;
    background: radial-gradient(ellipse at 20% 20%, rgba(0,212,255,0.07) 0%, transparent 60%),
                radial-gradient(ellipse at 80% 80%, rgba(124,58,237,0.07) 0%, transparent 60%);
  }

  /* ── Header ── */
  .header { text-align: center; margin-bottom: 2.5rem; position: relative; }
  .header::after {
    content: ''; display: block; height: 1px; margin-top: 1.5rem;
    background: linear-gradient(90deg, transparent, var(--accent), var(--accent2), transparent);
  }
  .logo { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.75rem;
          color: var(--accent); letter-spacing: 4px; text-transform: uppercase; margin-bottom: 0.5rem; }
  h1 { font-size: 2.2rem; font-weight: 900; letter-spacing: 0;
       background: linear-gradient(135deg, var(--accent), var(--accent2));
       -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .subtitle { color: var(--muted); font-size: 0.9rem; margin-top: 0.3rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }

  /* ── Grid ── */
  .grid-top { display: grid; grid-template-columns: 200px 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
  .grid-charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }

  /* ── Cards ── */
  .card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 1.25rem; position: relative; overflow: hidden;
  }
  .card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
  }
  .card-title {
    font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 3px;
    color: var(--muted); margin-bottom: 1rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  .privacy { margin-bottom: 1.5rem; color: var(--text); }
  .privacy p { color: var(--muted); font-size: 0.9rem; }

  /* ── Grade ── */
  .grade-card { display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .grade-letter { font-size: 5rem; font-weight: 900; line-height: 1; color: $gradeColor;
                  text-shadow: 0 0 30px ${gradeColor}88; }
  .grade-score  { font-size: 1.1rem; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }

  /* ── Stat pills ── */
  .stats { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; justify-content: center; }
  .stat { padding: 0.5rem 1rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700;
          display: flex; align-items: center; gap: 0.4rem; }
  .stat-ok   { background: rgba(34,197,94,0.15);  color: var(--ok);   border: 1px solid rgba(34,197,94,0.3); }
  .stat-warn { background: rgba(245,158,11,0.15); color: var(--warn); border: 1px solid rgba(245,158,11,0.3); }
  .stat-crit { background: rgba(239,68,68,0.15);  color: var(--crit); border: 1px solid rgba(239,68,68,0.3); }
  .stat-info { background: rgba(96,165,250,0.15); color: var(--info); border: 1px solid rgba(96,165,250,0.3); }
  .stat-num  { font-size: 1.6rem; }

  /* ── Sys info ── */
  .si-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  .si-table tr { border-bottom: 1px solid var(--border); }
  .si-table tr:last-child { border-bottom: none; }
  .si-key { color: var(--muted); padding: 0.35rem 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; width: 40%; }
  .si-val { color: var(--text); font-weight: 600; }

  /* ── Charts ── */
  .chart-wrap { display: grid; gap: 0.8rem; min-height: 260px; align-content: center; }
  .bar-row { display: grid; grid-template-columns: 140px 1fr 48px; gap: 0.75rem; align-items: center; }
  .bar-label { color: var(--text); font-size: 0.8rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bar-track { height: 12px; background: var(--surface2); border: 1px solid var(--border); border-radius: 999px; overflow: hidden; }
  .bar-track span { display: block; height: 100%; background: var(--accent); }
  .bar-track .bar-ok { background: var(--ok); }
  .bar-track .bar-warn { background: var(--warn); }
  .bar-track .bar-crit { background: var(--crit); }
  .bar-track .bar-info { background: var(--info); }
  .bar-value { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8rem; text-align: right; }

  /* ── Findings Table ── */
  .findings-card { margin-top: 0; }
  .findings-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
  .findings-table thead th {
    background: var(--surface2); color: var(--muted); text-transform: uppercase;
    letter-spacing: 2px; font-size: 0.68rem; padding: 0.7rem 0.8rem; text-align: left;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; border-bottom: 1px solid var(--border);
  }
  .findings-table tbody tr { border-bottom: 1px solid rgba(30,58,95,0.5); transition: background 0.15s; }
  .findings-table tbody tr:hover { background: var(--surface2); }
  .findings-table td { padding: 0.6rem 0.8rem; vertical-align: middle; }
  .cat { color: var(--accent); font-weight: 600; font-size: 0.78rem;
         white-space: nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .detail { color: var(--muted); font-size: 0.8rem; }

  /* ── Footer ── */
  .footer { text-align: center; margin-top: 2rem; color: var(--muted);
            font-size: 0.75rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
</style>
</head>
<body>

<div class="header">
  <div class="logo">// Windows Security Personality Checker //</div>
  <h1>Security Report</h1>
  <div class="subtitle">HOST: $($sysInfo['Hostname']) &nbsp;|&nbsp; SCAN: $($sysInfo['ScanTime'])</div>
</div>

<div class="card privacy">
  <div class="card-title">Privacy</div>
  <p>BeSecured runs 100% locally. No scan data is sent to a server. No account, cloud API or remote backend is used.</p>
</div>

<div class="grid-top">

  <!-- Grade -->
  <div class="card grade-card">
    <div class="card-title">Security Grade</div>
    <div class="grade-letter">$grade</div>
    <div class="grade-score">$overallScore / 100</div>
  </div>

  <!-- Summary stats -->
  <div class="card" style="display:flex;flex-direction:column;justify-content:center;">
    <div class="card-title">Summary</div>
    <div class="stats">
      <div class="stat stat-ok">  <span class="stat-num">$totalGood</span>  Passed</div>
      <div class="stat stat-warn"><span class="stat-num">$totalWarn</span> Warnings</div>
      <div class="stat stat-crit"><span class="stat-num">$totalCrit</span>  Critical</div>
      <div class="stat stat-info"><span class="stat-num">$totalInfo</span>  Info</div>
    </div>
  </div>

  <!-- System info -->
  <div class="card">
    <div class="card-title">System Info</div>
    <table class="si-table">
      $sysRows
    </table>
  </div>

</div>

<div class="grid-charts">
  <div class="card">
    <div class="card-title">Score by Category</div>
    <div class="chart-wrap">$categoryBars</div>
  </div>
  <div class="card">
    <div class="card-title">Finding Distribution</div>
    <div class="chart-wrap">$distributionBars</div>
  </div>
</div>

<div class="card findings-card">
  <div class="card-title">Detailed Findings</div>
  <table class="findings-table">
    <thead>
      <tr><th>Category</th><th>Check</th><th style="text-align:center">Status</th><th>Detail</th></tr>
    </thead>
    <tbody>
      $tableRows
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by WindowsSecurityCheck.ps1 &nbsp;·&nbsp; $($sysInfo['ScanTime'])
</div>

</body>
</html>
"@

# Write file
$outputDir = [System.IO.Path]::GetDirectoryName($OutputPath)
if ($outputDir -and -not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║           Scan Complete!                 ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Grade    : $grade ($overallScore/100)" -ForegroundColor $(if($overallScore -ge 75){"Green"}elseif($overallScore -ge 50){"Yellow"}else{"Red"})
Write-Host "  OK       : $totalGood" -ForegroundColor Green
Write-Host "  Warnings : $totalWarn" -ForegroundColor Yellow
Write-Host "  Critical : $totalCrit" -ForegroundColor Red
Write-Host ""
Write-Host "  Report saved to:" -ForegroundColor White
Write-Host "  $OutputPath" -ForegroundColor Cyan
Write-Host ""

# Open report automatically
try { Start-Process $OutputPath } catch {}

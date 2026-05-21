#Requires -Version 5.1
param([string]$OutputPath = "$env:USERPROFILE\Desktop\SecurityReport.html")

function Write-Step($msg) { Write-Host "  >> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-WARN($msg) { Write-Host "  [!!]  $msg" -ForegroundColor Yellow }
function Write-CRIT($msg) { Write-Host "  [XX]  $msg" -ForegroundColor Red }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
Write-Host ""
Write-Host "  Windows Security Checker" -ForegroundColor Magenta
Write-Host ""
if (-not $isAdmin) { Write-Host "  [NOTE] Not Administrator - some checks limited." -ForegroundColor Yellow; Write-Host "" }

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$scores   = @{}

function Add-Finding {
    param($category, $name, $status, $detail)
    $script:findings.Add([PSCustomObject]@{ Category=$category; Name=$name; Status=$status; Detail=$detail })
    if (-not $script:scores.ContainsKey($category)) { $script:scores[$category] = @{Good=0;Total=0} }
    $script:scores[$category].Total++
    if ($status -eq "OK") { $script:scores[$category].Good++ }
}

# 1. OPEN PORTS
Write-Step "Scanning open ports..."
$cat = "Open Ports"
try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess
    $riskyPorts = @{21="FTP";23="Telnet";25="SMTP";53="DNS";135="RPC";137="NetBIOS";139="NetBIOS";445="SMB";1433="MSSQL";3306="MySQL";3389="RDP";5900="VNC";8080="HTTP-Alt"}
    $openCount = ($listeners | Select-Object -ExpandProperty LocalPort -Unique).Count
    Add-Finding $cat "Total Listening Ports" "INFO" "$openCount ports listening"
    foreach ($l in ($listeners | Sort-Object LocalPort -Unique)) {
        $port = [int]$l.LocalPort
        if ($riskyPorts.ContainsKey($port)) {
            $svcName = $riskyPorts[$port]
            $proc = ""
            try { $proc = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).Name } catch {}
            $procStr = if ($proc) { " (Process: $proc)" } else { "" }
            Add-Finding $cat "Port $port ($svcName)" "WARN" "Exposed service: $svcName$procStr"
            Write-WARN "Risky port open: $port ($svcName)"
        }
    }
    if ($listeners | Where-Object { $_.LocalPort -eq 3389 }) {
        Add-Finding $cat "RDP (3389)" "CRIT" "Remote Desktop is enabled and listening"
        Write-CRIT "RDP is open on port 3389"
    } else {
        Add-Finding $cat "RDP (3389)" "OK" "RDP not listening"
        Write-OK "RDP not exposed"
    }
} catch { Add-Finding $cat "Port Scan" "WARN" "Could not complete port scan" }

# 2. FIREWALL
Write-Step "Checking Windows Firewall..."
$cat = "Firewall"
try {
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($p in $profiles) {
        if ($p.Enabled) {
            Add-Finding $cat "Firewall ($($p.Name))" "OK" "Profile $($p.Name) is enabled"
            Write-OK "Firewall '$($p.Name)' enabled"
        } else {
            Add-Finding $cat "Firewall ($($p.Name))" "CRIT" "Profile $($p.Name) is DISABLED"
            Write-CRIT "Firewall '$($p.Name)' disabled!"
        }
    }
} catch { Add-Finding $cat "Firewall Check" "WARN" "Could not query firewall" }

# 3. WINDOWS UPDATE
Write-Step "Checking Windows Update..."
$cat = "Updates"
try {
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
    $lastUpdate = $hotfixes | Select-Object -First 1
    if ($lastUpdate -and $lastUpdate.InstalledOn) {
        $daysSince = [math]::Round(((Get-Date) - [datetime]$lastUpdate.InstalledOn).TotalDays)
        if ($daysSince -lt 30) {
            Add-Finding $cat "Last Hotfix" "OK" "Last hotfix $daysSince days ago"
            Write-OK "Last hotfix: $daysSince days ago"
        } elseif ($daysSince -lt 90) {
            Add-Finding $cat "Last Hotfix" "WARN" "Last hotfix was $daysSince days ago"
            Write-WARN "Last hotfix: $daysSince days ago"
        } else {
            Add-Finding $cat "Last Hotfix" "CRIT" "Last hotfix was $daysSince days ago - may be unpatched"
            Write-CRIT "Last hotfix: $daysSince days ago!"
        }
    } else {
        Add-Finding $cat "Last Hotfix" "WARN" "Could not determine last update date"
    }
} catch { Add-Finding $cat "Update Check" "WARN" "Could not determine update status" }

# 4. LOCAL USERS
Write-Step "Auditing local users..."
$cat = "User Accounts"
try {
    $users  = Get-LocalUser -ErrorAction SilentlyContinue
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $adminUsers = $admins | Where-Object { $_.ObjectClass -eq "User" }
    $adminCount = if ($adminUsers) { @($adminUsers).Count } else { 0 }
    $adminNames = if ($adminUsers) { ($adminUsers.Name -join ", ") } else { "none" }
    $adminStatus = if ($adminCount -le 2) { "OK" } else { "WARN" }
    Add-Finding $cat "Admin Accounts" $adminStatus "$adminCount admin(s): $adminNames"

    $guestUser = $users | Where-Object { $_.Name -eq "Guest" -and $_.Enabled }
    if ($guestUser) {
        Add-Finding $cat "Guest Account" "CRIT" "Guest account is enabled - disable it"
        Write-CRIT "Guest account is enabled!"
    } else {
        Add-Finding $cat "Guest Account" "OK" "Guest account is disabled"
        Write-OK "Guest account disabled"
    }

    $noPass = $users | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled }
    if ($noPass) {
        $noPassNames = ($noPass.Name -join ", ")
        Add-Finding $cat "No-Password Accounts" "CRIT" "Accounts without password: $noPassNames"
        Write-CRIT "Users without password: $noPassNames"
    } else {
        Add-Finding $cat "Password Required" "OK" "All enabled accounts require a password"
        Write-OK "All accounts require passwords"
    }
} catch { Add-Finding $cat "User Audit" "WARN" "Could not fully audit local users" }

# 5. PASSWORD POLICY
Write-Step "Checking password policy..."
$cat = "Password Policy"
try {
    $netAcc = net accounts 2>$null
    $minLenLine = $netAcc | Select-String "Minimum password length"
    $maxAgeLine = $netAcc | Select-String "Maximum password age"
    $minLen = if ($minLenLine) { [int]($minLenLine -replace "\D","") } else { 0 }
    $maxAge = if ($maxAgeLine) { ($maxAgeLine -replace "[^0-9]","").Trim() } else { "0" }

    if ($minLen -ge 8) {
        Add-Finding $cat "Min Password Length" "OK" "Minimum length is $minLen characters"
        Write-OK "Min password length: $minLen"
    } else {
        Add-Finding $cat "Min Password Length" "WARN" "Minimum length is $minLen - recommend at least 8"
        Write-WARN "Weak min password length: $minLen"
    }

    $maxAgeInt = [int]$maxAge
    if ($maxAgeInt -eq 0 -or $maxAgeInt -gt 365) {
        Add-Finding $cat "Password Expiry" "WARN" "Passwords never expire or expire after very long time"
    } else {
        Add-Finding $cat "Password Expiry" "OK" "Passwords expire every $maxAge days"
        Write-OK "Password expiry: $maxAge days"
    }
} catch { Add-Finding $cat "Password Policy" "WARN" "Could not retrieve password policy" }

# 6. SHARED FOLDERS
Write-Step "Checking shared folders..."
$cat = "Shared Folders"
try {
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "^(ADMIN\$|C\$|IPC\$|print\$|[A-Z]\$)$" }
    if ($shares -and @($shares).Count -gt 0) {
        foreach ($s in $shares) {
            Add-Finding $cat "Share: $($s.Name)" "WARN" "Shared folder '$($s.Name)' at '$($s.Path)'"
            Write-WARN "Share found: $($s.Name) -> $($s.Path)"
        }
    } else {
        Add-Finding $cat "Custom Shares" "OK" "No custom shared folders detected"
        Write-OK "No custom shares"
    }
} catch { Add-Finding $cat "Shares Check" "WARN" "Could not audit shared folders" }

# 7. STARTUP PROGRAMS
Write-Step "Auditing startup programs..."
$cat = "Startup Programs"
try {
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    $allStartup = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($regPath in $startupPaths) {
        try {
            $items = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if ($items) {
                $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    $allStartup.Add([PSCustomObject]@{ Name=$_.Name; Command=$_.Value })
                }
            }
        } catch {}
    }
    $startupCount = $allStartup.Count
    $startupStatus = if ($startupCount -le 10) { "INFO" } else { "WARN" }
    Add-Finding $cat "Startup Entries" $startupStatus "$startupCount startup entries found"
    Write-OK "Startup entries: $startupCount"

    $suspicious = $allStartup | Where-Object { $_.Command -match "(?i)(\\temp\\|\\tmp\\)" }
    if ($suspicious) {
        $suspNames = ($suspicious.Name -join ", ")
        Add-Finding $cat "Suspicious Startup" "CRIT" "Startup from TEMP folder: $suspNames"
        Write-CRIT "Startup entries in TEMP!"
    }
} catch { Add-Finding $cat "Startup Audit" "WARN" "Could not audit startup programs" }

# 8. ANTIVIRUS
Write-Step "Checking antivirus..."
$cat = "Antivirus"
try {
    $av = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($av) {
        if ($av.AntivirusEnabled) {
            Add-Finding $cat "Windows Defender" "OK" "Defender is enabled and running"
            Write-OK "Windows Defender enabled"
        } else {
            Add-Finding $cat "Windows Defender" "CRIT" "Windows Defender is DISABLED"
            Write-CRIT "Defender disabled!"
        }
        if ($av.RealTimeProtectionEnabled) {
            Add-Finding $cat "Real-Time Protection" "OK" "Real-time protection is active"
            Write-OK "Real-time protection active"
        } else {
            Add-Finding $cat "Real-Time Protection" "CRIT" "Real-time protection is OFF"
            Write-CRIT "Real-time protection off!"
        }
        $defAge = [math]::Round(((Get-Date) - $av.AntivirusSignatureLastUpdated).TotalDays)
        if ($defAge -le 3) {
            Add-Finding $cat "Signature Age" "OK" "Virus definitions updated $defAge day(s) ago"
            Write-OK "Definitions: $defAge days old"
        } elseif ($defAge -le 7) {
            Add-Finding $cat "Signature Age" "WARN" "Virus definitions are $defAge days old"
            Write-WARN "Definitions: $defAge days old"
        } else {
            Add-Finding $cat "Signature Age" "CRIT" "Virus definitions are $defAge days old - update now"
            Write-CRIT "Definitions: $defAge days old!"
        }
    } else {
        $wmiAV = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($wmiAV) {
            $avNames = ($wmiAV.displayName -join ", ")
            Add-Finding $cat "Antivirus (WMI)" "OK" "AV detected: $avNames"
            Write-OK "AV: $avNames"
        } else {
            Add-Finding $cat "Antivirus" "CRIT" "No antivirus product detected"
            Write-CRIT "No antivirus found!"
        }
    }
} catch { Add-Finding $cat "AV Check" "WARN" "Could not determine antivirus status" }

# 9. UAC
Write-Step "Checking UAC..."
$cat = "UAC"
try {
    $uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
    if ($uacVal -eq 1) {
        Add-Finding $cat "UAC Enabled" "OK" "User Account Control is enabled"
        Write-OK "UAC is enabled"
    } else {
        Add-Finding $cat "UAC Enabled" "CRIT" "UAC is DISABLED - elevation prompts wont appear"
        Write-CRIT "UAC is disabled!"
    }
} catch { Add-Finding $cat "UAC Check" "WARN" "Could not determine UAC status" }

# SYSTEM INFO
Write-Step "Gathering system info..."
$sysInfo = [ordered]@{}
try {
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $sysInfo["Hostname"]  = $env:COMPUTERNAME
    $sysInfo["Username"]  = $env:USERNAME
    $sysInfo["OS"]        = if ($os) { "$($os.Caption) (Build $($os.BuildNumber))" } else { "Unknown" }
    $sysInfo["Arch"]      = if ($os) { $os.OSArchitecture } else { "Unknown" }
    $sysInfo["CPU"]       = if ($cpu) { $cpu.Name.Trim() } else { "Unknown" }
    $sysInfo["RAM"]       = if ($os) { "$([math]::Round($os.TotalVisibleMemorySize / 1MB, 1)) GB" } else { "Unknown" }
    $sysInfo["Uptime"]    = if ($os) { "$([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)) hrs" } else { "Unknown" }
    $sysInfo["Admin Run"] = $isAdmin.ToString()
    $sysInfo["Scan Time"] = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
} catch { $sysInfo["Error"] = "Could not retrieve system info" }

# SCORES
$totalGood  = @($findings | Where-Object { $_.Status -eq "OK"   }).Count
$totalWarn  = @($findings | Where-Object { $_.Status -eq "WARN" }).Count
$totalCrit  = @($findings | Where-Object { $_.Status -eq "CRIT" }).Count
$totalInfo  = @($findings | Where-Object { $_.Status -eq "INFO" }).Count
$totalChecks = $totalGood + $totalWarn + $totalCrit

$overallScore = 0
if ($totalChecks -gt 0) {
    $raw = [math]::Round((($totalGood / $totalChecks) * 100) - ($totalCrit * 5))
    $overallScore = [math]::Max(0, [math]::Min(100, $raw))
}

$grade = "F"
if ($overallScore -ge 90) { $grade = "A" }
elseif ($overallScore -ge 75) { $grade = "B" }
elseif ($overallScore -ge 60) { $grade = "C" }
elseif ($overallScore -ge 40) { $grade = "D" }

$gradeColor = "#ef4444"
if ($grade -eq "A") { $gradeColor = "#22c55e" }
elseif ($grade -eq "B") { $gradeColor = "#84cc16" }
elseif ($grade -eq "C") { $gradeColor = "#f59e0b" }
elseif ($grade -eq "D") { $gradeColor = "#f97316" }

# BUILD HTML
Write-Step "Generating HTML report..."

$sb = [System.Text.StringBuilder]::new()

# Chart data
$catKeys = @($scores.Keys)
$catNamesJS = ($catKeys | ForEach-Object { """$_""" }) -join ","
$catScoresJS = ($catKeys | ForEach-Object {
    $s = $scores[$_]
    if ($s.Total -gt 0) { [math]::Round(($s.Good / $s.Total) * 100) } else { 0 }
}) -join ","

# Table rows
$tableRowsHtml = [System.Text.StringBuilder]::new()
foreach ($f in $findings) {
    $color = "#94a3b8"
    $icon  = "?"
    if ($f.Status -eq "OK")   { $color = "#22c55e"; $icon = "OK" }
    if ($f.Status -eq "WARN") { $color = "#f59e0b"; $icon = "!!" }
    if ($f.Status -eq "CRIT") { $color = "#ef4444"; $icon = "XX" }
    if ($f.Status -eq "INFO") { $color = "#60a5fa"; $icon = "i" }
    $detail = $f.Detail -replace "&","&amp;" -replace "<","&lt;" -replace ">","&gt;"
    [void]$tableRowsHtml.AppendLine("<tr><td class='cat'>$($f.Category)</td><td>$($f.Name)</td><td style='color:$color;font-weight:700;text-align:center'>[$icon]</td><td class='detail'>$detail</td></tr>")
}

# Sys info rows
$sysRowsHtml = [System.Text.StringBuilder]::new()
foreach ($key in $sysInfo.Keys) {
    [void]$sysRowsHtml.AppendLine("<tr><td class='si-key'>$key</td><td class='si-val'>$($sysInfo[$key])</td></tr>")
}

[void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
[void]$sb.AppendLine("<title>Security Report - $($sysInfo['Hostname'])</title>")
[void]$sb.AppendLine('<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>')
[void]$sb.AppendLine('<style>
@import url("https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;900&display=swap");
:root{--bg:#0a0e1a;--surface:#111827;--surface2:#1a2235;--border:#1e3a5f;--accent:#00d4ff;--accent2:#7c3aed;--ok:#22c55e;--warn:#f59e0b;--crit:#ef4444;--info:#60a5fa;--text:#e2e8f0;--muted:#64748b}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:"Exo 2",sans-serif;min-height:100vh;padding:2rem}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(ellipse at 20% 20%,rgba(0,212,255,.07),transparent 60%),radial-gradient(ellipse at 80% 80%,rgba(124,58,237,.07),transparent 60%)}
.header{text-align:center;margin-bottom:2.5rem}
.header::after{content:"";display:block;height:1px;margin-top:1.5rem;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent)}
.logo{font-family:"Share Tech Mono",monospace;font-size:.75rem;color:var(--accent);letter-spacing:4px;text-transform:uppercase;margin-bottom:.5rem}
h1{font-size:2.2rem;font-weight:900;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.subtitle{color:var(--muted);font-size:.9rem;margin-top:.3rem;font-family:"Share Tech Mono",monospace}
.grid-top{display:grid;grid-template-columns:200px 1fr 1fr;gap:1.5rem;margin-bottom:1.5rem}
.grid-charts{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.25rem;position:relative;overflow:hidden}
.card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.card-title{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:3px;color:var(--muted);margin-bottom:1rem;font-family:"Share Tech Mono",monospace}
.grade-card{display:flex;flex-direction:column;align-items:center;justify-content:center}
.grade-letter{font-size:5rem;font-weight:900;line-height:1}
.grade-score{font-size:1.1rem;color:var(--muted);font-family:"Share Tech Mono",monospace}
.stats{display:flex;flex-wrap:wrap;gap:.75rem;align-items:center;justify-content:center}
.stat{padding:.5rem 1rem;border-radius:8px;font-size:.85rem;font-weight:700;display:flex;align-items:center;gap:.4rem}
.stat-ok{background:rgba(34,197,94,.15);color:var(--ok);border:1px solid rgba(34,197,94,.3)}
.stat-warn{background:rgba(245,158,11,.15);color:var(--warn);border:1px solid rgba(245,158,11,.3)}
.stat-crit{background:rgba(239,68,68,.15);color:var(--crit);border:1px solid rgba(239,68,68,.3)}
.stat-info{background:rgba(96,165,250,.15);color:var(--info);border:1px solid rgba(96,165,250,.3)}
.stat-num{font-size:1.6rem}
.si-table{width:100%;border-collapse:collapse;font-size:.82rem}
.si-table tr{border-bottom:1px solid var(--border)}
.si-table tr:last-child{border-bottom:none}
.si-key{color:var(--muted);padding:.35rem 0;font-family:"Share Tech Mono",monospace;width:40%}
.si-val{color:var(--text);font-weight:600}
.chart-wrap{position:relative;height:260px}
.findings-table{width:100%;border-collapse:collapse;font-size:.83rem}
.findings-table thead th{background:var(--surface2);color:var(--muted);text-transform:uppercase;letter-spacing:2px;font-size:.68rem;padding:.7rem .8rem;text-align:left;font-family:"Share Tech Mono",monospace;border-bottom:1px solid var(--border)}
.findings-table tbody tr{border-bottom:1px solid rgba(30,58,95,.5);transition:background .15s}
.findings-table tbody tr:hover{background:var(--surface2)}
.findings-table td{padding:.6rem .8rem;vertical-align:middle}
.cat{color:var(--accent);font-weight:600;font-size:.78rem;white-space:nowrap;font-family:"Share Tech Mono",monospace}
.detail{color:var(--muted);font-size:.8rem}
.footer{text-align:center;margin-top:2rem;color:var(--muted);font-size:.75rem;font-family:"Share Tech Mono",monospace}
</style></head><body>')

[void]$sb.AppendLine('<div class="header">')
[void]$sb.AppendLine('<div class="logo">// Windows Security Checker //</div>')
[void]$sb.AppendLine('<h1>Security Report</h1>')
[void]$sb.AppendLine("<div class='subtitle'>HOST: $($sysInfo['Hostname']) &nbsp;|&nbsp; SCAN: $($sysInfo['Scan Time'])</div>")
[void]$sb.AppendLine('</div>')

[void]$sb.AppendLine('<div class="grid-top">')
[void]$sb.AppendLine("<div class='card grade-card'><div class='card-title'>Security Grade</div><div class='grade-letter' style='color:$gradeColor;text-shadow:0 0 30px ${gradeColor}88'>$grade</div><div class='grade-score'>$overallScore / 100</div></div>")
[void]$sb.AppendLine("<div class='card' style='display:flex;flex-direction:column;justify-content:center'><div class='card-title'>Summary</div><div class='stats'><div class='stat stat-ok'><span class='stat-num'>$totalGood</span> Passed</div><div class='stat stat-warn'><span class='stat-num'>$totalWarn</span> Warnings</div><div class='stat stat-crit'><span class='stat-num'>$totalCrit</span> Critical</div><div class='stat stat-info'><span class='stat-num'>$totalInfo</span> Info</div></div></div>")
[void]$sb.AppendLine("<div class='card'><div class='card-title'>System Info</div><table class='si-table'>$($sysRowsHtml.ToString())</table></div>")
[void]$sb.AppendLine('</div>')

[void]$sb.AppendLine('<div class="grid-charts">')
[void]$sb.AppendLine('<div class="card"><div class="card-title">Score by Category</div><div class="chart-wrap"><canvas id="radarChart"></canvas></div></div>')
[void]$sb.AppendLine('<div class="card"><div class="card-title">Finding Distribution</div><div class="chart-wrap"><canvas id="donutChart"></canvas></div></div>')
[void]$sb.AppendLine('</div>')

[void]$sb.AppendLine('<div class="card"><div class="card-title">Detailed Findings</div>')
[void]$sb.AppendLine('<table class="findings-table"><thead><tr><th>Category</th><th>Check</th><th style="text-align:center">Status</th><th>Detail</th></tr></thead>')
[void]$sb.AppendLine("<tbody>$($tableRowsHtml.ToString())</tbody></table></div>")

[void]$sb.AppendLine("<div class='footer'>Generated by WindowsSecurityCheck.ps1 &nbsp;·&nbsp; $($sysInfo['Scan Time'])</div>")

[void]$sb.AppendLine('<script>')
[void]$sb.AppendLine("new Chart(document.getElementById('radarChart'),{type:'radar',data:{labels:[$catNamesJS],datasets:[{label:'Score %',data:[$catScoresJS],backgroundColor:'rgba(0,212,255,0.15)',borderColor:'#00d4ff',pointBackgroundColor:'#00d4ff',borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,scales:{r:{min:0,max:100,ticks:{stepSize:25,color:'#475569',backdropColor:'transparent',font:{size:9}},grid:{color:'rgba(30,58,95,0.5)'},angleLines:{color:'rgba(30,58,95,0.5)'},pointLabels:{color:'#94a3b8',font:{size:10,family:'Share Tech Mono, monospace'}}}},plugins:{legend:{display:false}}}});")
[void]$sb.AppendLine("new Chart(document.getElementById('donutChart'),{type:'doughnut',data:{labels:['OK','WARN','CRIT','INFO'],datasets:[{data:[$totalGood,$totalWarn,$totalCrit,$totalInfo],backgroundColor:['rgba(34,197,94,0.8)','rgba(245,158,11,0.8)','rgba(239,68,68,0.8)','rgba(96,165,250,0.8)'],borderColor:'#0a0e1a',borderWidth:3,hoverOffset:8}]},options:{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{legend:{position:'bottom',labels:{color:'#94a3b8',padding:16,font:{size:11}}}}}});")
[void]$sb.AppendLine('</script></body></html>')

$html = $sb.ToString()
[System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.Encoding]::UTF8)

Write-Host ""
Write-Host "  Scan Complete!" -ForegroundColor Green
Write-Host ""
Write-Host ("  Grade    : " + $grade + " (" + $overallScore + "/100)") -ForegroundColor $(if($overallScore -ge 75){"Green"}elseif($overallScore -ge 50){"Yellow"}else{"Red"})
Write-Host "  OK       : $totalGood"   -ForegroundColor Green
Write-Host "  Warnings : $totalWarn"   -ForegroundColor Yellow
Write-Host "  Critical : $totalCrit"   -ForegroundColor Red
Write-Host ""
Write-Host "  Report saved to:" -ForegroundColor White
Write-Host "  $OutputPath" -ForegroundColor Cyan
Write-Host ""
try { Start-Process $OutputPath } catch {}

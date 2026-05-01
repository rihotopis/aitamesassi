#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive PC Performance Diagnostic Script
.DESCRIPTION
    Scans BIOS/UEFI, boot time, startup items, services, disk health,
    memory, CPU, processes, Event Viewer, Windows Update, drivers,
    network, SFC, DISM and more. Outputs a plain-text report.
.NOTES
    Target: Acer Nitro 5 (ANV15-52 i7) - Windows 11
    Run as Administrator in PowerShell 5.1+
#>

$ErrorActionPreference = 'SilentlyContinue'
$reportPath = Join-Path $PSScriptRoot "DiagnosticReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$divider = "=" * 80
$findings = [System.Collections.Generic.List[string]]::new()

function Write-Section {
    param([string]$Title, [string]$Body)
    $script:sb.AppendLine($divider)
    $script:sb.AppendLine("  $Title")
    $script:sb.AppendLine($divider)
    $script:sb.AppendLine($Body)
    $script:sb.AppendLine("")
}

$sb = [System.Text.StringBuilder]::new()
$sb.AppendLine("PC PERFORMANCE DIAGNOSTIC REPORT")
$sb.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$sb.AppendLine("Computer : $env:COMPUTERNAME")
$sb.AppendLine("")

# ── 1. SYSTEM INFO ──────────────────────────────────────────────────────────
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$bios = Get-CimInstance Win32_BIOS

$body = @"
OS            : $($os.Caption) Build $($os.BuildNumber)
Install Date  : $($os.InstallDate)
Uptime        : $((Get-Date) - $os.LastBootUpTime)
Manufacturer  : $($cs.Manufacturer)
Model         : $($cs.Model)
CPU           : $($cpu.Name)
Cores/Threads : $($cpu.NumberOfCores) / $($cpu.NumberOfLogicalProcessors)
Total RAM     : $([math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB
BIOS Version  : $($bios.SMBIOSBIOSVersion)  ($($bios.ReleaseDate))
"@
Write-Section "1. SYSTEM OVERVIEW" $body

# ── 2. BOOT / UEFI TIMING ───────────────────────────────────────────────────
$bootEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; Id=100} -MaxEvents 5 2>$null
$buf = [System.Text.StringBuilder]::new()
if ($bootEvents) {
    foreach ($ev in $bootEvents) {
        $xml = [xml]$ev.ToXml()
        $ms  = ($xml.Event.EventData.Data | Where-Object Name -eq 'BootTime').'#text'
        $sec = if ($ms) { [math]::Round([int64]$ms / 1000, 1) } else { 'N/A' }
        $buf.AppendLine("  $($ev.TimeCreated)  -  Boot time: $sec s")
        if ($ms -and [int64]$ms -gt 60000) {
            $findings.Add("[BOOT] Boot on $($ev.TimeCreated) took $sec s (> 60 s)")
        }
    }
} else {
    $buf.AppendLine("  (Boot performance log not available)")
}

$fwBoot = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name FirmwareBootTime -ErrorAction SilentlyContinue).FirmwareBootTime
if ($fwBoot) { $buf.AppendLine("  Firmware (UEFI) boot time: $([math]::Round($fwBoot/1000,1)) s") }

$lastBoot = $os.LastBootUpTime
$uptime   = (Get-Date) - $lastBoot
if ($uptime.TotalDays -gt 14) {
    $findings.Add("[UPTIME] System has not been rebooted for $([math]::Round($uptime.TotalDays)) days")
}
Write-Section "2. BOOT PERFORMANCE" $buf.ToString()

# ── 3. STARTUP PROGRAMS ─────────────────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$startups = Get-CimInstance Win32_StartupCommand
foreach ($s in $startups) {
    $buf.AppendLine("  [$($s.Location)] $($s.Name) - $($s.Command)")
}
$taskStartups = Get-ScheduledTask | Where-Object { $_.Triggers | Where-Object { $_ -is [CimInstance] -and $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' } } | Where-Object State -eq 'Ready'
foreach ($t in $taskStartups) {
    $buf.AppendLine("  [ScheduledTask-Logon] $($t.TaskName)")
}
$startupCount = ($startups | Measure-Object).Count + ($taskStartups | Measure-Object).Count
if ($startupCount -gt 15) {
    $findings.Add("[STARTUP] $startupCount startup items detected (high)")
}
Write-Section "3. STARTUP PROGRAMS ($startupCount items)" $buf.ToString()

# ── 4. RUNNING PROCESSES - TOP 20 BY CPU + TOP 20 BY MEMORY ─────────────────
$buf = [System.Text.StringBuilder]::new()
$procs = Get-Process | Where-Object { $_.ProcessName -ne 'Idle' }

$buf.AppendLine("  --- Top 20 by CPU time (s) ---")
$buf.AppendLine(("  {0,-30} {1,10} {2,12}" -f 'Name','CPU (s)','Mem (MB)'))
foreach ($p in ($procs | Sort-Object CPU -Descending | Select-Object -First 20)) {
    $buf.AppendLine(("  {0,-30} {1,10:N1} {2,12:N0}" -f $p.ProcessName, $p.CPU, ($p.WorkingSet64/1MB)))
}

$buf.AppendLine("")
$buf.AppendLine("  --- Top 20 by Memory (MB) ---")
$buf.AppendLine(("  {0,-30} {1,12}" -f 'Name','Mem (MB)'))
foreach ($p in ($procs | Sort-Object WorkingSet64 -Descending | Select-Object -First 20)) {
    $buf.AppendLine(("  {0,-30} {1,12:N0}" -f $p.ProcessName, ($p.WorkingSet64/1MB)))
}
$totalMem = ($procs | Measure-Object WorkingSet64 -Sum).Sum / 1GB
if ($totalMem -gt ($cs.TotalPhysicalMemory/1GB * 0.85)) {
    $findings.Add("[MEMORY] Process memory usage is above 85% of total RAM")
}
Write-Section "4. RUNNING PROCESSES" $buf.ToString()

# ── 5. CPU USAGE ─────────────────────────────────────────────────────────────
$cpuLoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$body = "  Current average CPU load: $cpuLoad %"
if ($cpuLoad -gt 80) { $findings.Add("[CPU] Current CPU load is $cpuLoad %") }
Write-Section "5. CPU USAGE" $body

# ── 6. MEMORY USAGE ─────────────────────────────────────────────────────────
$freePhys   = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
$totalPhys  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
$usedPhys   = [math]::Round($totalPhys - $freePhys, 2)
$pctUsed    = [math]::Round($usedPhys / $totalPhys * 100, 1)
$pf         = Get-CimInstance Win32_PageFileUsage | Select-Object -First 1
$body = @"
  Total Physical : $totalPhys GB
  Used           : $usedPhys GB  ($pctUsed %)
  Free           : $freePhys GB
  Page File      : $($pf.CurrentUsage) MB used / $($pf.AllocatedBaseSize) MB allocated
"@
if ($pctUsed -gt 85) { $findings.Add("[MEMORY] RAM usage at $pctUsed %") }
if ($pf -and $pf.CurrentUsage -gt ($pf.AllocatedBaseSize * 0.75)) {
    $findings.Add("[PAGEFILE] Page file usage is high ($($pf.CurrentUsage) / $($pf.AllocatedBaseSize) MB)")
}
Write-Section "6. MEMORY USAGE" $body

# ── 7. DISK HEALTH & SPACE ──────────────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
foreach ($d in $disks) {
    $freeGB = [math]::Round($d.FreeSpace/1GB,1)
    $totalGB = [math]::Round($d.Size/1GB,1)
    $pct = [math]::Round(($d.Size - $d.FreeSpace)/$d.Size*100,1)
    $buf.AppendLine("  $($d.DeviceID)  $freeGB GB free / $totalGB GB  ($pct % used)")
    if ($pct -gt 90) { $findings.Add("[DISK] Drive $($d.DeviceID) is $pct % full") }
    if ($freeGB -lt 20) { $findings.Add("[DISK] Drive $($d.DeviceID) has only $freeGB GB free") }
}

# SMART via Get-StorageReliabilityCounter
$buf.AppendLine("")
$buf.AppendLine("  --- SMART / Reliability ---")
$physDisks = Get-PhysicalDisk
foreach ($pd in $physDisks) {
    $rel = $pd | Get-StorageReliabilityCounter 2>$null
    $buf.AppendLine("  Disk: $($pd.FriendlyName)  Media: $($pd.MediaType)  Health: $($pd.HealthStatus)  OpStatus: $($pd.OperationalStatus)")
    if ($rel) {
        $buf.AppendLine("    Temperature: $($rel.Temperature) C  |  Wear: $($rel.Wear)  |  ReadErrors: $($rel.ReadErrorsTotal)  |  PowerOn: $($rel.PowerOnHours) h")
    }
    if ($pd.HealthStatus -ne 'Healthy') {
        $findings.Add("[DISK] $($pd.FriendlyName) health is $($pd.HealthStatus)")
    }
}
Write-Section "7. DISK HEALTH & SPACE" $buf.ToString()

# ── 8. SERVICES - HEAVY & STUCK ─────────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$buf.AppendLine("  --- Non-Microsoft services (Running) ---")
$svcs = Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch 'Microsoft|Windows' }
foreach ($s in ($svcs | Sort-Object DisplayName)) {
    $buf.AppendLine("  $($s.StartMode.PadRight(10)) $($s.DisplayName)")
}
$stoppedAuto = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' }
if ($stoppedAuto) {
    $buf.AppendLine("")
    $buf.AppendLine("  --- Auto-start services NOT running (possible crashes) ---")
    foreach ($s in $stoppedAuto) {
        $buf.AppendLine("  $($s.Name) - $($s.DisplayName)  [Status: $($s.State)]")
    }
    $findings.Add("[SERVICES] $($stoppedAuto.Count) auto-start service(s) are not running")
}
Write-Section "8. SERVICES" $buf.ToString()

# ── 9. WINDOWS UPDATE STATUS ────────────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $pending = $searcher.Search("IsInstalled=0")
    $buf.AppendLine("  Pending updates: $($pending.Updates.Count)")
    foreach ($u in $pending.Updates) {
        $buf.AppendLine("    - $($u.Title)")
    }
    if ($pending.Updates.Count -gt 5) {
        $findings.Add("[UPDATE] $($pending.Updates.Count) pending Windows updates")
    }
} catch {
    $buf.AppendLine("  Could not query Windows Update: $($_.Exception.Message)")
}
# Last installed updates
$buf.AppendLine("")
$buf.AppendLine("  --- Last 10 installed updates ---")
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
foreach ($h in $hotfixes) {
    $buf.AppendLine("  $($h.InstalledOn)  $($h.HotFixID)  $($h.Description)")
}
Write-Section "9. WINDOWS UPDATE" $buf.ToString()

# ── 10. DRIVER STATUS ───────────────────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$problemDevices = Get-PnpDevice | Where-Object { $_.Status -ne 'OK' -and $_.Class -ne $null }
if ($problemDevices) {
    foreach ($dev in $problemDevices) {
        $buf.AppendLine("  [$($dev.Status)] $($dev.Class) - $($dev.FriendlyName)")
    }
    $findings.Add("[DRIVERS] $($problemDevices.Count) device(s) with problems")
} else {
    $buf.AppendLine("  All devices report OK status.")
}
Write-Section "10. DRIVER / DEVICE STATUS" $buf.ToString()

# ── 11. EVENT VIEWER - RECENT ERRORS & WARNINGS ─────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$cutoff = (Get-Date).AddDays(-7)
foreach ($logName in @('System','Application')) {
    $buf.AppendLine("  --- $logName log (Errors, last 7 days, max 25) ---")
    $events = Get-WinEvent -FilterHashtable @{LogName=$logName; Level=2; StartTime=$cutoff} -MaxEvents 25 2>$null
    if ($events) {
        foreach ($ev in $events) {
            $buf.AppendLine("  $($ev.TimeCreated)  [$($ev.ProviderName)] $($ev.Id): $($ev.Message.Substring(0,[math]::Min(120,$ev.Message.Length)).Replace("`n",' '))")
        }
    } else {
        $buf.AppendLine("  No errors found.")
    }
    $buf.AppendLine("")
}
# Critical events (WHEA, BugCheck, etc.)
$criticals = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1; StartTime=$cutoff} -MaxEvents 10 2>$null
if ($criticals) {
    $buf.AppendLine("  --- CRITICAL System events (last 7 days) ---")
    foreach ($ev in $criticals) {
        $buf.AppendLine("  $($ev.TimeCreated)  [$($ev.ProviderName)] $($ev.Id): $($ev.Message.Substring(0,[math]::Min(120,$ev.Message.Length)).Replace("`n",' '))")
    }
    $findings.Add("[EVENTS] $($criticals.Count) CRITICAL event(s) in last 7 days")
}
Write-Section "11. EVENT VIEWER (Recent Errors)" $buf.ToString()

# ── 12. NETWORK STATUS ──────────────────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
foreach ($a in $adapters) {
    $ip = (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    $buf.AppendLine("  $($a.Name)  $($a.InterfaceDescription)  Speed: $($a.LinkSpeed)  IP: $ip")
}
$dns = Resolve-DnsName google.com -ErrorAction SilentlyContinue
if (-not $dns) {
    $buf.AppendLine("  [!] DNS resolution failed for google.com")
    $findings.Add("[NETWORK] DNS resolution is failing")
}
Write-Section "12. NETWORK STATUS" $buf.ToString()

# ── 13. SYSTEM FILE CHECKER (SFC) ───────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$buf.AppendLine("  Running sfc /verifyonly (this may take several minutes)...")
$sfcResult = & sfc /verifyonly 2>&1 | Out-String
$buf.AppendLine($sfcResult.Trim())
if ($sfcResult -match 'found integrity violations') {
    $findings.Add("[SFC] System File Checker found integrity violations")
}
Write-Section "13. SYSTEM FILE CHECKER (SFC)" $buf.ToString()

# ── 14. DISM HEALTH CHECK ───────────────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$buf.AppendLine("  Running DISM /Online /Cleanup-Image /CheckHealth ...")
$dismResult = & DISM /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String
$buf.AppendLine($dismResult.Trim())
if ($dismResult -match 'component store corruption') {
    $findings.Add("[DISM] Component store corruption detected")
}
Write-Section "14. DISM HEALTH CHECK" $buf.ToString()

# ── 15. POWER PLAN ──────────────────────────────────────────────────────────
$activePlan = powercfg /getactivescheme 2>&1 | Out-String
$thermalInfo = ""
$throttle = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty CurrentClockSpeed
$maxClock  = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty MaxClockSpeed
$body = @"
  Active plan : $($activePlan.Trim())
  CPU clock   : $throttle MHz / $maxClock MHz max
"@
if ($throttle -lt ($maxClock * 0.6)) {
    $findings.Add("[POWER] CPU running at $throttle / $maxClock MHz - possible thermal throttling")
}
Write-Section "15. POWER PLAN & THERMAL" $body

# ── 16. TEMP FILES & CLEANUP OPPORTUNITY ─────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
$tempPaths = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "$env:SystemRoot\Temp")
foreach ($tp in $tempPaths) {
    if (Test-Path $tp) {
        $items = Get-ChildItem $tp -Recurse -Force -ErrorAction SilentlyContinue
        $sizeMB = [math]::Round(($items | Measure-Object Length -Sum).Sum / 1MB, 0)
        $buf.AppendLine("  $tp  -  $($items.Count) items, $sizeMB MB")
        if ($sizeMB -gt 1000) { $findings.Add("[TEMP] $tp contains $sizeMB MB of temp files") }
    }
}
Write-Section "16. TEMP FILES" $buf.ToString()

# ── 17. SUMMARY OF FINDINGS ─────────────────────────────────────────────────
$buf = [System.Text.StringBuilder]::new()
if ($findings.Count -eq 0) {
    $buf.AppendLine("  No major issues detected by automated checks.")
    $buf.AppendLine("  Consider checking for malware with a full Windows Defender scan.")
} else {
    $buf.AppendLine("  $($findings.Count) potential issue(s) found:`n")
    $i = 1
    foreach ($f in $findings) {
        $buf.AppendLine("  $i. $f")
        $i++
    }
    $buf.AppendLine("")
    $buf.AppendLine("  RECOMMENDED NEXT STEPS:")
    $buf.AppendLine("  - Address any CRITICAL or DISK issues first.")
    $buf.AppendLine("  - Install pending Windows updates.")
    $buf.AppendLine("  - Reduce startup programs if count is high.")
    $buf.AppendLine("  - Run a full malware scan (Windows Defender / Malwarebytes).")
    $buf.AppendLine("  - If SFC found violations, run: sfc /scannow")
    $buf.AppendLine("  - If DISM found corruption, run: DISM /Online /Cleanup-Image /RestoreHealth")
    $buf.AppendLine("  - Consider a clean boot to isolate third-party service issues.")
}
Write-Section "17. FINDINGS & RECOMMENDATIONS" $buf.ToString()

# ── Write report ─────────────────────────────────────────────────────────────
$sb.ToString() | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "`n✅  Diagnostic report saved to:`n  $reportPath" -ForegroundColor Green
Write-Host "`n$($findings.Count) potential issue(s) flagged. Open the report for details.`n"

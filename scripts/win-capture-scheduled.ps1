<#
.SYNOPSIS
  Capture a site on a schedule (default every 4 hours), headless, without
  touching the Firefox you are browsing in.

.DESCRIPTION
  The interactive capture script closes your Firefox, which is fine when you ask
  for it and unacceptable on a timer. This one runs against a CLONE of your
  profile, headless and with -no-remote, so your own session stays open and
  untouched -- you will not see a window and nothing will steal focus.

  The clone carries what makes the blocker real: the extensions directory,
  extensions.json, addonStartup.json.lz4, prefs.js (which maps extension UUIDs)
  and each extension's own storage, where uBO keeps its filter lists AND your
  custom rules. It leaves out site storage, history and cache -- 35MB rather
  than 270MB. Verified: a headless clone walked the full anti-adblock fallback
  chain, which only happens when a real blocker cancels the first host.

  -no-remote is essential. Without it a second firefox.exe hands its URL to any
  running instance and exits, and because MOZ_LOG is read when a process STARTS,
  the running instance logs nothing -- leaving a 0-byte file that looks like a
  capture. Measured.

  Each run deletes the previous capture first. The filename is fixed, so the
  command that reads it never changes.

.EXAMPLE
  # install the 4-hourly task
  powershell -ExecutionPolicy Bypass -File C:\nwss-har\win-capture-scheduled.ps1 -Install

.EXAMPLE
  # run one capture now, exactly as the task does
  powershell -ExecutionPolicy Bypass -File C:\nwss-har\win-capture-scheduled.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File C:\nwss-har\win-capture-scheduled.ps1 -Uninstall
#>

param(
  [string[]]$Urls = @("https://jmty.jp/"),
  [string]$OutDir = "C:\nwss-har",
  [string]$Name = "capture",
  [int]$SecondsPerUrl = 45,
  [ValidateRange(1,5)][int]$LogLevel = 1,
  [string]$SourceProfile = "",
  [string]$CaptureProfile = "",
  [int]$IntervalHours = 4,
  [string]$TaskName = "nwss-capture",
  [switch]$RefreshProfile,
  [switch]$Install,
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
if (-not $CaptureProfile) { $CaptureProfile = Join-Path $OutDir "capture-profile" }

function Find-Firefox {
  foreach ($c in @("$env:ProgramFiles\Mozilla Firefox\firefox.exe",
                   "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe")) {
    if (Test-Path $c) { return $c }
  }
  throw "firefox.exe not found"
}

# The profile marked Default in profiles.ini -- the one you actually browse in.
function Find-SourceProfile {
  $ini = Join-Path $env:APPDATA "Mozilla\Firefox\profiles.ini"
  if (-not (Test-Path $ini)) { throw "profiles.ini not found" }
  $lines = Get-Content $ini
  $path = $null
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\[Install') {
      for ($j = $i + 1; $j -lt $lines.Count -and $lines[$j] -notmatch '^\['; $j++) {
        if ($lines[$j] -match '^Default=(.+)$') { $path = $Matches[1].Trim() }
      }
    }
  }
  if (-not $path) { throw "no Default= under [Install...] in profiles.ini" }
  if ($path -notmatch '^[A-Za-z]:') { $path = Join-Path (Join-Path $env:APPDATA "Mozilla\Firefox") ($path -replace '/', '\') }
  if (-not (Test-Path $path)) { throw "profile from profiles.ini does not exist: $path" }
  return $path
}

function New-ProfileClone {
  param([string]$Source, [string]$Dest)
  if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
  New-Item -ItemType Directory -Force -Path (Join-Path $Dest "storage\default") | Out-Null
  foreach ($f in @("extensions.json", "addonStartup.json.lz4", "prefs.js", "cookies.sqlite")) {
    $p = Join-Path $Source $f
    if (Test-Path $p) { Copy-Item $p $Dest -Force -ErrorAction SilentlyContinue }
  }
  robocopy (Join-Path $Source "extensions") (Join-Path $Dest "extensions") /E /NFL /NDL /NJH /NJS /NP | Out-Null
  $stor = Join-Path $Source "storage\default"
  if (Test-Path $stor) {
    Get-ChildItem $stor -Directory -Filter "moz-extension*" -ErrorAction SilentlyContinue | ForEach-Object {
      robocopy $_.FullName (Join-Path $Dest ("storage\default\" + $_.Name)) /E /NFL /NDL /NJH /NJS /NP | Out-Null
    }
  }
  $mb = ((Get-ChildItem $Dest -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum) / 1MB
  Write-Host ("  profile clone: {0:N0}MB  -> {1}" -f $mb, $Dest)
}

# --- install / uninstall ----------------------------------------------------
if ($Uninstall) {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "  removed scheduled task '$TaskName'"
  } else { Write-Host "  no scheduled task '$TaskName'" }
  return
}

if ($Install) {
  $self = $MyInvocation.MyCommand.Path
  $argline = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$self`"" +
             " -Urls `"$($Urls -join ',')`" -OutDir `"$OutDir`" -Name `"$Name`"" +
             " -SecondsPerUrl $SecondsPerUrl -LogLevel $LogLevel"
  $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argline
  # Repeat for ~10 years rather than a fixed end date, so it does not silently
  # stop one day; -Once + RepetitionInterval is the only combination that gives
  # an arbitrary N-hour period (Daily only takes days).
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
               -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) `
               -RepetitionDuration (New-TimeSpan -Days 3650)
  # Interactive: headless Firefox still needs a logged-on session, and this
  # avoids storing a password or running as SYSTEM.
  $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
  $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                 -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
                 -MultipleInstances IgnoreNew
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  }
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description "nwss: capture $($Urls -join ', ') every $IntervalHours h" | Out-Null
  Write-Host "  installed '$TaskName': every $IntervalHours hours, first run in ~2 minutes"
  Write-Host "  capture   : $OutDir\$Name.log.moz_log"
  Write-Host "  run now   : Start-ScheduledTask -TaskName $TaskName"
  Write-Host "  remove    : ... -Uninstall"
  return
}

# --- one capture run (this is what the task executes) ------------------------
$firefox = Find-Firefox
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$transcript = Join-Path $OutDir "$Name-runs.log"
"[{0}] run start" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Add-Content -Path $transcript

if (-not $SourceProfile) { $SourceProfile = Find-SourceProfile }
if ($RefreshProfile -or -not (Test-Path (Join-Path $CaptureProfile "extensions"))) {
  New-ProfileClone -Source $SourceProfile -Dest $CaptureProfile
}

$logBase = Join-Path $OutDir "$Name.log"

# Delete the PREVIOUS capture, including every per-process sibling. A run that
# spawns fewer content processes than the last would otherwise leave stale
# child-N files sharing the stem, and the reader would fold a previous page load
# into this one. Exact pattern so nothing else can be caught.
$leaf = '^' + [regex]::Escape((Split-Path $logBase -Leaf)) + '(\.child-\d+)?\.moz_log$'
$removed = 0
Get-ChildItem -LiteralPath $OutDir -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match $leaf } |
  ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue; $removed++ }
Write-Host "  deleted previous capture: $removed file(s)"

$env:MOZ_LOG = "timestamp,nsHttp:$LogLevel"
$env:MOZ_LOG_FILE = $logBase

# --headless: no window, nothing steals focus.
# -no-remote: do NOT hand the url to the Firefox the user is browsing in.
# -profile <clone>: never the live profile, which Firefox would lock.
$args = @("--headless", "-no-remote", "-profile", $CaptureProfile) + $Urls
$proc = Start-Process -FilePath $firefox -ArgumentList $args -PassThru -WindowStyle Hidden
Write-Host "  headless capture running, pid $($proc.Id), $SecondsPerUrl s"
Start-Sleep -Seconds $SecondsPerUrl

# Close ONLY this instance, matched on its command line. Never a PID diff, and
# never "all firefox.exe" -- the user's own browser must not be touched.
Get-CimInstance Win32_Process -Filter "Name='firefox.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like "*$CaptureProfile*" } |
  ForEach-Object {
    try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch { }
  }
Start-Sleep -Seconds 3

$main = Get-Item "$logBase.moz_log" -ErrorAction SilentlyContinue
if (-not $main) {
  $msg = "FAILED: no capture written"
  Write-Host "  $msg"; "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg | Add-Content -Path $transcript
  exit 1
}
if ($main.Length -eq 0) {
  $msg = "FAILED: capture is empty (a running Firefox swallowed the url -- is -no-remote present?)"
  Write-Host "  $msg"; "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg | Add-Content -Path $transcript
  exit 1
}

$all = Get-ChildItem "$logBase*" -ErrorAction SilentlyContinue
$mb  = (($all | Measure-Object -Property Length -Sum).Sum) / 1MB
$msg = "ok: {0:N1}MB across {1} file(s) -> {2}.moz_log" -f $mb, $all.Count, $logBase
Write-Host "  $msg"
"[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg | Add-Content -Path $transcript

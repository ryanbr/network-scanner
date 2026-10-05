<#
.SYNOPSIS
  Capture a site on a schedule (default every 2 hours), headless, without
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
  [string[]]$Urls,
  [string]$TargetsFile = "",
  [string]$OutDir = "C:\nwss-har",
  [string]$Name = "capture",
  [int]$SecondsPerUrl = 45,
  [ValidateRange(1,5)][int]$LogLevel = 1,
  [string]$SourceProfile = "",
  [string]$CaptureProfile = "",
  [int]$IntervalHours = 2,
  [string]$TaskName = "nwss-capture",
  [switch]$RefreshProfile,
  [switch]$Install,
  [switch]$Status,
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

# --- target urls -------------------------------------------------------------
# Targets live in a file OUTSIDE the repo (default <OutDir>\targets.txt), one
# url per line, # for comments. Change the site there and every script follows.
# Keeping them out of the tracked tree is deliberate: the sites being worked on
# are not something to publish, and a default baked into a committed script is
# exactly how that leaks.
function Resolve-Targets {
  param([string[]]$Explicit, [string]$File)
  # Filter blanks: an empty -Urls "" (which a scheduled-task argument list can
  # easily carry) must NOT count as an explicit target and silently beat the
  # targets file -- it would launch the browser with no url at all.
  $explicitClean = @($Explicit | Where-Object { $_ -and $_.Trim() })
  if ($explicitClean.Count -gt 0) { return $explicitClean }
  if (Test-Path -LiteralPath $File) {
    $urls = Get-Content -LiteralPath $File |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ -and -not $_.StartsWith("#") }
    if ($urls.Count -gt 0) { return @($urls) }
  }
  throw "No target urls. Create $File with one url per line, or pass -Urls."
}

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

# A browsing session fills the clone with disposable state: one run took it from
# 35MB to 177MB (cache2 42MB, startupCache 33MB, security_state 24MB, site
# storage 32MB, safebrowsing, places/favicons). Unattended and 4-hourly, that
# grows without bound, so everything regenerable is dropped after each capture.
#
# What is NOT dropped is what makes the blocker real: extensions/, prefs.js,
# extensions.json, addonStartup.json.lz4, cookies.sqlite, and
# storage/default/moz-extension* -- uBO's filter lists and the user's custom
# rules live in that last one.
function Clear-ProfileJunk {
  param([string]$Profile)
  if (-not (Test-Path $Profile)) { return }
  $before = ((Get-ChildItem $Profile -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum) / 1MB
  foreach ($d in @("cache2","startupCache","safebrowsing","thumbnails","sessionstore-backups",
                   "datareporting","crashes","minidumps","gmp","gmp-gmpopenh264","shader-cache",
                   "security_state","saved-telemetry-pings","bookmarkbackups")) {
    $p = Join-Path $Profile $d
    if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
  }
  foreach ($f in @("places.sqlite","favicons.sqlite","sessionstore.jsonlz4","webappsstore.sqlite",
                   "content-prefs.sqlite","storage.sqlite","protections.sqlite")) {
    Get-ChildItem -LiteralPath $Profile -Filter "$f*" -File -ErrorAction SilentlyContinue |
      Remove-Item -Force -ErrorAction SilentlyContinue
  }
  # Site storage grows per visited origin; extension storage must survive.
  $sd = Join-Path $Profile "storage\default"
  if (Test-Path $sd) {
    Get-ChildItem $sd -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -notlike "moz-extension*" } |
      Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  }
  $after = ((Get-ChildItem $Profile -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum) / 1MB
  Write-Host ("  pruned clone: {0:N0}MB -> {1:N0}MB" -f $before, $after)
}

# --- install / uninstall ----------------------------------------------------
if ($Status) {
  $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($t) {
    $i = Get-ScheduledTaskInfo -TaskName $TaskName
    Write-Host ("  task      : {0}, repeats every {1}" -f $t.State, $t.Triggers[0].Repetition.Interval)
    Write-Host ("  last run  : {0}  (result {1})" -f $i.LastRunTime, $i.LastTaskResult)
    Write-Host ("  next run  : {0}" -f $i.NextRunTime)
  } else { Write-Host "  task      : NOT INSTALLED ('$TaskName')" }

  $tf = if ($TargetsFile) { $TargetsFile } else { Join-Path $OutDir "targets.txt" }
  if (Test-Path $tf) {
    $t0 = (Get-Content $tf | Where-Object { $_ -and -not $_.Trim().StartsWith("#") } | Select-Object -First 1)
    Write-Host ("  target    : {0}   ({1})" -f $t0, $tf)
  } else { Write-Host "  target    : no targets file at $tf" }

  $cap = Join-Path $OutDir "$Name.log.moz_log"
  if (Test-Path $cap) {
    $f = Get-Item $cap
    $age = [int]((Get-Date) - $f.LastWriteTime).TotalMinutes
    Write-Host ("  capture   : {0:N1}MB, {1} min old ({2})" -f ($f.Length/1MB), $age, $f.LastWriteTime)
    # Which page the capture is really of -- the document request, not what was asked for.
    $doc = Select-String -Path $cap -Pattern 'uri=https?://[^ ]+' -List -ErrorAction SilentlyContinue
    $hosts = Select-String -Path $cap -Pattern 'uri=https?://([^/ ]+)' -AllMatches -ErrorAction SilentlyContinue |
      ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } |
      Group-Object | Sort-Object Count -Descending | Select-Object -First 3
    if ($hosts) { Write-Host ("  top hosts : {0}" -f (($hosts | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", ")) }
    if ($doc) { }
  } else { Write-Host "  capture   : none at $cap" }

  $runs = Join-Path $OutDir "$Name-runs.log"
  if (Test-Path $runs) {
    Write-Host "  last runs :"
    Get-Content $runs -Tail 5 | ForEach-Object { Write-Host ("    " + $_) }
  }
  return
}

if ($Uninstall) {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "  removed scheduled task '$TaskName'"
  } else { Write-Host "  no scheduled task '$TaskName'" }
  return
}

if ($Install) {
  $self = $MyInvocation.MyCommand.Path
  # Do NOT bake the urls into the task unless they were given explicitly: the
  # whole point of targets.txt is that the site can be changed in one place
  # without touching the schedule. A baked-in -Urls "" would also override it.
  $argline = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$self`"" +
             " -OutDir `"$OutDir`" -Name `"$Name`"" +
             " -SecondsPerUrl $SecondsPerUrl -LogLevel $LogLevel"
  $explicitUrls = @($Urls | Where-Object { $_ -and $_.Trim() })
  if ($explicitUrls.Count -gt 0) { $argline += " -Urls `"$($explicitUrls -join ',')`"" }
  if ($TargetsFile) { $argline += " -TargetsFile `"$TargetsFile`"" }
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
if (-not $TargetsFile) { $TargetsFile = Join-Path $OutDir "targets.txt" }
$Urls = Resolve-Targets -Explicit $Urls -File $TargetsFile
$transcript = Join-Path $OutDir "$Name-runs.log"
"[{0}] run start" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Add-Content -Path $transcript

if (-not $SourceProfile) { $SourceProfile = Find-SourceProfile }
if ($RefreshProfile -or -not (Test-Path (Join-Path $CaptureProfile "extensions"))) {
  New-ProfileClone -Source $SourceProfile -Dest $CaptureProfile
}

# --- one run at a time ------------------------------------------------------
# A manual run and the scheduled run can land on the same second, and they share
# one clone profile and one output path. Firefox refuses the second profile lock
# and shows "Firefox is already running", the second run deletes the files the
# first is still writing, and both end with a 0-byte capture. Measured: task at
# 19:33:41, manual at 19:33:42, Telemetry.FailedProfileLocks.txt written, capture
# 0 bytes. MultipleInstances=IgnoreNew only stops the TASK double-running; it
# cannot see a manual run.
$lockFile = Join-Path $OutDir "$Name.lock"
$lockMine = $false
if (Test-Path -LiteralPath $lockFile) {
  $holder = (Get-Content -LiteralPath $lockFile -ErrorAction SilentlyContinue | Select-Object -First 1)
  $holderPid = 0; [void][int]::TryParse(($holder -split '\s+')[0], [ref]$holderPid)
  $alive = $holderPid -gt 0 -and (Get-Process -Id $holderPid -ErrorAction SilentlyContinue)
  $ageMin = [int]((Get-Date) - (Get-Item $lockFile).LastWriteTime).TotalMinutes
  if ($alive -and $ageMin -lt 15) {
    Write-Host "  another capture is already running (pid $holderPid, ${ageMin}min); skipping this one"
    "[{0}] skipped: capture already running (pid {1})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $holderPid |
      Add-Content -Path $transcript
    exit 0
  }
  Write-Host "  clearing a stale lock (pid $holderPid, ${ageMin}min old)"
  Remove-Item -LiteralPath $lockFile -Force -ErrorAction SilentlyContinue
}
"$PID started $(Get-Date -Format s)" | Set-Content -LiteralPath $lockFile -Encoding ASCII
$lockMine = $true

# A crashed run can leave the clone's profile lock behind, which makes the next
# Firefox show the same dialog. Safe to clear only because nothing is using it.
$stillUsing = Get-CimInstance Win32_Process -Filter "Name='firefox.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like "*$CaptureProfile*" }
if ($stillUsing) {
  Write-Host "  a Firefox is still on the capture profile; closing it first"
  $stillUsing | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch { } }
  Start-Sleep -Seconds 3
}
foreach ($stale in @("parent.lock", ".parentlock", "lock")) {
  $sp = Join-Path $CaptureProfile $stale
  if (Test-Path -LiteralPath $sp) { Remove-Item -LiteralPath $sp -Force -ErrorAction SilentlyContinue }
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
  if ($lockMine) { Remove-Item -LiteralPath $lockFile -Force -ErrorAction SilentlyContinue }
  $msg = "FAILED: no capture written"
  Write-Host "  $msg"; "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg | Add-Content -Path $transcript
  exit 1
}
if ($main.Length -eq 0) {
  if ($lockMine) { Remove-Item -LiteralPath $lockFile -Force -ErrorAction SilentlyContinue }
  $msg = "FAILED: capture is empty (a running Firefox swallowed the url, or another capture was running)"
  Write-Host "  $msg"; "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg | Add-Content -Path $transcript
  exit 1
}

Clear-ProfileJunk -Profile $CaptureProfile

$all = Get-ChildItem "$logBase*" -ErrorAction SilentlyContinue
$mb  = (($all | Measure-Object -Property Length -Sum).Sum) / 1MB

# A headless run is invisible, so the log has to answer "which site did it
# actually visit?" on its own. Record the target AND whether that host appears
# in the capture -- the second is the part that matters, because a target can be
# requested and never reached (dns failure, redirect, stale task arguments).
$targetHost = try { ([uri]$Urls[0]).Host } catch { "" }
$contacted = "unknown"
if ($targetHost) {
  # -SimpleMatch takes the pattern LITERALLY, so it must NOT be regex-escaped:
  # [regex]::Escape() turned "jmty.jp" into "jmty\.jp" and the search then
  # looked for a literal backslash, reporting "contacted: NO" on a capture that
  # plainly contained the host. Search the whole family too -- a request can be
  # logged by a content process rather than the parent.
  $hit = Select-String -Path "$logBase*.moz_log" -Pattern "uri=https://$targetHost" -SimpleMatch -List -ErrorAction SilentlyContinue
  $contacted = if ($hit) { "yes" } else { "NO" }
}
$msg = "ok: {0:N1}MB across {1} file(s) | target {2} | {3} contacted: {4}" -f $mb, $all.Count, $Urls[0], $targetHost, $contacted
Write-Host "  $msg"
"[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg | Add-Content -Path $transcript
if ($lockMine) { Remove-Item -LiteralPath $lockFile -Force -ErrorAction SilentlyContinue }

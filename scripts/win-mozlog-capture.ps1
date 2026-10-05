<#
.SYNOPSIS
  Capture a Firefox network log from your REAL Firefox (your profile, your uBO
  with your own rules), then read it with har-rules.js.

.DESCRIPTION
  Firefox dumps every HTTP channel it creates when MOZ_LOG is set. It is an
  environment variable, so unlike the HAR route there is no DevTools, no
  toolbox, NO PREFS TO WRITE OR RESTORE, and nothing to click:

    set MOZ_LOG=timestamp,nsHttp:5
    set MOZ_LOG_FILE=C:\nwss-har\ff.log
    firefox.exe https://example.com/

  That is the whole mechanism; this script just closes Firefox first (so the new
  environment applies rather than the URL being handed to the running instance),
  launches it with your normal profile, waits, and closes it again.

  WHY FIREFOX RATHER THAN CHROME: Chrome is MV3-only now, so what runs there is
  uBO Lite on declarativeNetRequest. That is a weaker blocker, and measured: a
  declarativeNetRequest block of html-load.cc produced a real
  ERR_BLOCKED_BY_CLIENT and the anti-adblock loader still never moved to the
  next host in its list. Firefox still runs full uBO with your own rules, which
  is the only place the fallback chain has actually been seen.

  BLOCKED REQUESTS: a MOZ_LOG records the channel when it is created, which is
  before a blocker cancels it, so blocked requests generally DO appear. That is
  useful -- it shows what the page TRIED to load -- but it means presence is not
  proof a request succeeded. Save a HAR if you need that distinction.

  SIZE: the default log level is 1 (Error), which carries everything the reader
  uses and nothing else -- measured across three captures as losing zero urls
  while being 87% smaller. A 45s capture is a few MB rather than ~30MB. Level 5
  is available via -LogLevel if you want the connection-manager detail; it was
  the old default and cost ~1MB per second of browsing.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File C:\nwss-har\win-mozlog-capture.ps1 `
    -Urls "https://jmty.jp/" -OutDir "C:\nwss-har" -SecondsPerUrl 45 -ForceClose
#>

param(
  [string[]]$Urls = @("https://jmty.jp/"),
  [string]$OutDir = "C:\nwss-har",
  [int]$SecondsPerUrl = 45,
  [string]$Name = "capture",
  [ValidateRange(1,5)][int]$LogLevel = 1,
  [switch]$Timestamped,
  [switch]$ForceClose
)

$ErrorActionPreference = 'Stop'

function Find-Firefox {
  $candidates = @(
    "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
    "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
  )
  foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
  throw "firefox.exe not found in the usual locations"
}

# Match on the command line, never on a PID diff: a browser spawns and retires
# content processes constantly, and a before/after PID set kills innocent ones.
function Get-FirefoxProcs {
  Get-CimInstance Win32_Process -Filter "Name='firefox.exe'" -ErrorAction SilentlyContinue
}

function Close-Firefox {
  $procs = Get-FirefoxProcs
  if (-not $procs) { return }
  if (-not $ForceClose) {
    throw "Firefox is running. The running instance would just open a tab and log nothing. Close Firefox, or pass -ForceClose."
  }
  Write-Host "closing Firefox gracefully (so your session is saved) ..."
  foreach ($p in $procs) {
    # A browser spawns and retires content processes constantly, so one can
    # exit between the enumeration above and this call. CloseMainWindow then
    # throws, and with $ErrorActionPreference='Stop' that aborts the whole
    # script -- after the capture has already been written, but before it is
    # reported. Losing a race with a process we wanted dead anyway is success.
    try {
      $h = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
      if ($h -and -not $h.HasExited) { $null = $h.CloseMainWindow() }
    } catch {
      # already gone
    }
  }
  for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    if (-not (Get-FirefoxProcs)) { return }
  }
  Write-Host "  still running after 25s; forcing"
  Get-FirefoxProcs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
}

$firefox = Find-Firefox
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
# A FIXED filename by default, so the command that reads the capture never
# changes. -Timestamped keeps every run instead.
if ($Timestamped) {
  $stamp = Get-Date -Format "yyMMdd-HHmmss"
  $logBase = Join-Path $OutDir "ff-$stamp.log"
} else {
  $logBase = Join-Path $OutDir "$Name.log"
}

# Clear THIS capture's previous family first. Firefox writes one log per
# content process (<base>.child-N.moz_log), and a run that spawns fewer
# processes than the last leaves the extra children behind -- they share the
# stem, so the reader would fold a previous page load into this one. Matched by
# exact pattern so nothing else in the directory can be caught by it.
$leafPattern = '^' + [regex]::Escape((Split-Path $logBase -Leaf)) + '(\.child-\d+)?\.moz_log$'
Get-ChildItem -LiteralPath $OutDir -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match $leafPattern } |
  ForEach-Object {
    Write-Host "  clearing previous: $($_.Name)"
    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
  }

Write-Host "firefox : $firefox"
Write-Host "log     : $logBase.moz_log"

Close-Firefox

# Inherited by the launched process. Level 1 (Error) is all we need: every line
# the reader uses -- "uri=", "http request [" and the Sec-Fetch-Dest inside it --
# is logged at E. The verbose levels are connection-manager chatter.
#
# Measured on three real captures: E-only logs lost ZERO urls and produced
# byte-identical results, at 13% of the size. One 45s capture went 29.1MB ->
# 3.8MB and parsed in 11ms instead of 210ms. Raise it with -LogLevel 5 if you
# need the connection detail for something else.
$env:MOZ_LOG = "timestamp,nsHttp:$LogLevel"
$env:MOZ_LOG_FILE = $logBase

Write-Host "launching with your normal profile (uBO and your rules live) ..."
$proc = Start-Process -FilePath $firefox -ArgumentList $Urls -PassThru
Write-Host "  pid $($proc.Id); browsing for $SecondsPerUrl seconds"
Write-Host "  (interact with the page if you like -- everything it requests is logged)"
Start-Sleep -Seconds $SecondsPerUrl

$ForceClose = $true
Close-Firefox
Start-Sleep -Seconds 2

$logs = Get-ChildItem "$logBase*" -ErrorAction SilentlyContinue
if (-not $logs) {
  Write-Host ""
  Write-Host "No log produced. Firefox was probably already running under a different"
  Write-Host "user or elevated, so the URL went to that instance instead."
  exit 1
}
# An EMPTY main log is the signature of a handoff: a second firefox.exe with
# MOZ_LOG set initialises logging (creating this file) and then hands its URL to
# an ALREADY-RUNNING instance and exits. The browsing happens in that instance,
# which was started without MOZ_LOG and logs nothing. Measured: opening a new
# tab in a running Firefox produces exactly this, a 0-byte file -- which looks
# like a capture until you read it.
$main = Get-Item "$logBase.moz_log" -ErrorAction SilentlyContinue
if ($main -and $main.Length -eq 0) {
  Write-Host ""
  Write-Host "The log is EMPTY. Firefox was already running, so the URL opened as a tab in"
  Write-Host "that instance -- and MOZ_LOG is read when a process STARTS, so a running"
  Write-Host "Firefox cannot be made to log by opening a tab in it."
  Write-Host "Re-run with -ForceClose (your tabs are restored: the close is graceful, so"
  Write-Host "Firefox writes its session first)."
  exit 1
}

$total = [math]::Round(($logs | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
Write-Host ""
Write-Host "wrote $($logs.Count) file(s), ${total}MB total:"
$logs | ForEach-Object { Write-Host ("  " + $_.Name + "  " + [math]::Round($_.Length/1MB,1) + "MB") }

$main = "$logBase.moz_log"
$wsl = ($main -replace '^C:', '/mnt/c') -replace '\\', '/'
Write-Host ""
Write-Host "read it with (per-process siblings are picked up automatically):"
Write-Host "  node scripts/har-rules.js '$wsl' --config config-media2.json --site jmty"

<#
.SYNOPSIS
  Capture a Chrome net-log from your REAL Chrome (real profile, real uBO),
  then read it with har-rules.js.

.DESCRIPTION
  Chrome writes a full network log itself, from a command-line flag. No
  DevTools, no prefs, nothing to click, nothing to save by hand:

    chrome --log-net-log=out.json --net-log-capture-mode=IncludeSensitive <url>

  That is the whole mechanism. This script just closes Chrome first (a running
  instance would swallow the new flags and open a tab in the old process,
  silently producing no log), launches it with your normal profile so your
  extensions and their custom rules are live, waits, and closes it again.

  WHAT A NET-LOG DOES NOT CONTAIN: requests an extension blocked. Measured --
  a declarativeNetRequest extension blocked html-load.cc, puppeteer reported
  ERR_BLOCKED_BY_CLIENT, and "html-load" appeared zero times in the
  530-request net-log from that same run. So this shows what Chrome REALLY
  FETCHED, which is what finds a late host in a fallback chain. To see what
  uBO stopped, save a HAR instead (there they arrive as status 0).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File C:\nwss-har\win-netlog-capture.ps1 `
    -Urls "https://jmty.jp/" -OutDir "C:\nwss-har" -SecondsPerUrl 45 -ForceClose
#>

param(
  [string[]]$Urls = @("https://jmty.jp/"),
  [string]$OutDir = "C:\nwss-har",
  [int]$SecondsPerUrl = 45,
  [switch]$ForceClose
)

$ErrorActionPreference = 'Stop'

function Find-Chrome {
  $candidates = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
  )
  foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
  throw "chrome.exe not found in the usual locations"
}

# Match on the command line, never on a PID diff: Chrome spawns and retires
# renderer processes constantly, so a before/after PID set kills innocent ones.
function Get-ChromeProcs {
  Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" -ErrorAction SilentlyContinue
}

function Close-Chrome {
  $procs = Get-ChromeProcs
  if (-not $procs) { return }
  if (-not $ForceClose) {
    throw "Chrome is running. A running instance ignores the net-log flag and just opens a tab. Close Chrome, or pass -ForceClose."
  }
  Write-Host "closing Chrome gracefully (so your session is saved) ..."
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
    if (-not (Get-ChromeProcs)) { return }
  }
  Write-Host "  still running after 25s; forcing"
  Get-ChromeProcs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
}

$chrome = Find-Chrome
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyMMdd-HHmmss"
$log   = Join-Path $OutDir "netlog-$stamp.json"

Write-Host "chrome  : $chrome"
Write-Host "log     : $log"

Close-Chrome

$chromeArgs = @(
  "--log-net-log=$log",
  "--net-log-capture-mode=IncludeSensitive"
) + $Urls

Write-Host "launching with your normal profile (extensions live) ..."
$proc = Start-Process -FilePath $chrome -ArgumentList $chromeArgs -PassThru
Write-Host "  pid $($proc.Id); browsing for $SecondsPerUrl seconds"
Write-Host "  (interact with the page if you like -- everything it fetches is logged)"
Start-Sleep -Seconds $SecondsPerUrl

# Chrome flushes the log on exit. A forced kill still leaves a usable file --
# lib/netlog.js parses a truncated log -- but a clean close is complete.
$ForceClose = $true
Close-Chrome
Start-Sleep -Seconds 1

if (-not (Test-Path $log)) {
  Write-Host ""
  Write-Host "No net-log produced. Chrome was probably already running under a"
  Write-Host "different user or elevated, so the flags went to that instance."
  exit 1
}

$size = [math]::Round((Get-Item $log).Length / 1MB, 1)
Write-Host ""
Write-Host "net-log : $log  (${size}MB)"
$wsl = ($log -replace '^C:', '/mnt/c') -replace '\\', '/'
Write-Host ""
Write-Host "read it with:"
Write-Host "  node scripts/har-rules.js '$wsl' --config config-media2.json --site jmty"

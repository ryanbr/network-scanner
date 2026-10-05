<#
.SYNOPSIS
  Capture HAR files from the REAL Firefox (with its real uBO) and leave them
  somewhere WSL can read, so nwss's har-rules.js can turn them into filters.

.STATUS
  Earlier revisions of this script never produced a HAR, and that was recorded
  here as "auto-export is broken in Firefox 157". That was wrong. The cause was
  this script: the log directory was written to user.js with four backslashes
  instead of two, so the pref held "C:\\nwss-har" -- a path that cannot exist,
  which is why no file and no directory ever appeared. Viewing the pref in
  about:config is what exposed it. Fixed below; see the $escaped line.

  NOTE ON PREFS: once Firefox has read user.js the values are written into
  prefs.js, so restoring user.js at the end does NOT unset them -- they stay
  visible (bold) in about:config. Harmless, and re-applied on the next run, but
  to clear them use the reset arrows in about:config.

  If a run still produces nothing, the manual path is proven end to end:
  F12 > Network > Ctrl+R > right-click > Save All As HAR, then har-rules.js.

.WHY
  Some anti-adblock loaders only walk their fallback host list when a genuine
  content blocker cancels the earlier hosts. Fifteen automated attempts from
  WSL -- CDP interception, EasyList via the rust engine, a real uBO in a fresh
  Firefox, a proxy -- never reproduced it. The established profile does. So
  drive THAT browser, and read the result from WSL.

  Firefox writes a HAR itself on every page load when
  devtools.netmonitor.har.enableAutoExportToFile is set and DevTools is open
  (toolbox.js initHarAutomation). This sets those prefs, opens the browser with
  DevTools, visits each URL, then restores your prefs.

.USAGE
  powershell -ExecutionPolicy Bypass -File win-har-capture.ps1 `
      -Urls "https://jmty.jp/","https://jmty.jp/tokyo/sale-fur/article-1saoos" `
      -OutDir "C:\nwss-har" -SecondsPerUrl 45

  Firefox must be CLOSED first: the profile is locked while it runs, and the
  HAR prefs are only read at startup. Add -ForceClose to have the script close
  it for you -- it asks Firefox to quit normally so sessionstore is written and
  your tabs come back on the next launch, and only force-kills if that fails.
#>
param(
  [string[]]$Urls = @("https://jmty.jp/"),
  [string]$OutDir = "C:\nwss-har",
  [int]$SecondsPerUrl = 45,
  [string]$ProfileName = "",          # blank = the install's default profile
  [switch]$KeepPrefs,                  # leave the HAR prefs in place afterwards
  [switch]$ForceClose                  # close a running Firefox instead of refusing
)

$ff = "C:\Program Files\Mozilla Firefox\firefox.exe"
if (-not (Test-Path $ff)) { Write-Error "Firefox not found at $ff"; exit 1 }

function Close-Firefox {
  param([int]$TimeoutSeconds = 25)
  # Ask politely FIRST: CloseMainWindow lets Firefox write sessionstore, so the
  # user gets their tabs back on next launch. Force-killing skips that.
  $procs = Get-Process firefox -ErrorAction SilentlyContinue
  if (-not $procs) { return $true }
  Write-Host "closing Firefox gracefully (so your session is saved) ..." -ForegroundColor Cyan
  $procs | ForEach-Object { try { $_.CloseMainWindow() | Out-Null } catch {} }
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Process firefox -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
  }
  if (Get-Process firefox -ErrorAction SilentlyContinue) {
    Write-Host "  still running after ${TimeoutSeconds}s -- forcing" -ForegroundColor Yellow
    Get-Process firefox -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 3
  }
  # A crashed/killed instance can leave the profile lock behind.
  Start-Sleep -Seconds 2
  return (-not (Get-Process firefox -ErrorAction SilentlyContinue))
}

if (Get-Process firefox -ErrorAction SilentlyContinue) {
  if (-not $ForceClose) {
    Write-Host "Firefox is running. Close it first -- the profile is locked and the" -ForegroundColor Yellow
    Write-Host "HAR preferences are only read at startup." -ForegroundColor Yellow
    Write-Host "Or re-run with -ForceClose to have this script close it for you" -ForegroundColor Yellow
    Write-Host "(gracefully, so Firefox saves your tabs for session restore)." -ForegroundColor Yellow
    exit 1
  }
  if (-not (Close-Firefox)) { Write-Error "Could not close Firefox"; exit 1 }
}

# --- locate the profile -----------------------------------------------------
$iniPath = "$env:APPDATA\Mozilla\Firefox\profiles.ini"
$ini = Get-Content $iniPath -Raw
if ($ProfileName) {
  $profRel = ($ini -split "`r?`n" | Select-String -Pattern "^Path=.*$ProfileName.*" | Select-Object -First 1) -replace '^Path=',''
} else {
  # The [InstallXXXX] Default= line is what Firefox actually launches, which is
  # NOT necessarily the [ProfileN] marked Default=1.
  $profRel = ($ini -split "`r?`n" | Select-String -Pattern '^Default=Profiles/' | Select-Object -First 1) -replace '^Default=',''
}
if (-not $profRel) { Write-Error "Could not determine profile from $iniPath"; exit 1 }
$profile = Join-Path "$env:APPDATA\Mozilla\Firefox" ($profRel -replace '/','\')
if (-not (Test-Path $profile)) { Write-Error "Profile path not found: $profile"; exit 1 }
Write-Host "profile : $profile"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "har dir : $OutDir"

# --- set the HAR prefs via user.js (applied at startup, removed after) ------
$userJs = Join-Path $profile "user.js"
$backup = Join-Path $profile "user.js.nwss-backup"
if (Test-Path $userJs) { Copy-Item $userJs $backup -Force }
# prefs.js/user.js is C-escaped, so a backslash must be doubled -- exactly
# doubled. Using -replace here emits FOUR (its replacement string takes
# backslashes literally), which stored "C:\\nwss-har" as the log directory and
# was the entire reason auto-export never produced a file. .Replace() is the
# plain string method, no regex, no replacement-token rules.
$escaped = $OutDir.Replace('\','\\')
@"
user_pref("devtools.netmonitor.har.enableAutoExportToFile", true);
user_pref("devtools.netmonitor.har.defaultLogDir", "$escaped");
user_pref("devtools.netmonitor.har.defaultFileName", "nwss-%y%m%d-%H%M%S");
user_pref("devtools.netmonitor.har.forceExport", true);
user_pref("devtools.netmonitor.har.pageLoadedTimeout", 3000);
user_pref("devtools.netmonitor.har.includeResponseBodies", false);
user_pref("devtools.toolbox.selectedTool", "netmonitor");
user_pref("devtools.everOpened", true);
"@ | Set-Content -Path $userJs -Encoding ASCII
Write-Host "prefs   : written to user.js (restored on exit)"

# --- drive the browser ------------------------------------------------------
$before = Get-ChildItem $OutDir -Filter *.har -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
try {
  $first = $Urls[0]
  $proc = Start-Process $ff -ArgumentList @('--devtools', $first) -PassThru
  Write-Host "launched: pid $($proc.Id) -> $first"
  Start-Sleep -Seconds $SecondsPerUrl

  foreach ($u in $Urls | Select-Object -Skip 1) {
    # Remoting into the already-open window: a new tab, same session, same
    # DevTools-armed toolbox.
    Start-Process $ff -ArgumentList @('-new-tab', $u) | Out-Null
    Write-Host "         -> $u"
    Start-Sleep -Seconds $SecondsPerUrl
  }
} finally {
  Close-Firefox -TimeoutSeconds 15 | Out-Null
  if (-not $KeepPrefs) {
    if (Test-Path $backup) { Move-Item $backup $userJs -Force } else { Remove-Item $userJs -Force -ErrorAction SilentlyContinue }
    Write-Host "prefs   : restored"
  }
}

$after = Get-ChildItem $OutDir -Filter *.har -ErrorAction SilentlyContinue
$new = $after | Where-Object { $before -notcontains $_.Name }
if ($new) {
  Write-Host ""
  Write-Host "HAR files written:" -ForegroundColor Green
  $new | ForEach-Object { Write-Host ("  {0}  {1:N0} bytes" -f $_.Name, $_.Length) }
  Write-Host ""
  Write-Host "From WSL:" -ForegroundColor Cyan
  $wsl = ($OutDir -replace '^C:','/mnt/c' -replace '\\','/')
  Write-Host "  node scripts/har-rules.js $wsl/<file>.har --config config-media2.json --site jmty"
} else {
  Write-Host ""
  Write-Host "No HAR produced." -ForegroundColor Yellow
  Write-Host "In Firefox check: F12 > Network, and about:config ->" 
  Write-Host "devtools.netmonitor.har.enableAutoExportToFile should be true."
  Write-Host "If auto-export does not fire, use F12 > Network > right-click > Save All As HAR."
}

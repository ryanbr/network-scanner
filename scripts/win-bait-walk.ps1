<#
.SYNOPSIS
  Walk an anti-adblock fallback chain and enumerate every bait host it offers,
  without naming any of them in advance.

.DESCRIPTION
  These loaders serve a script from a rotating host list and stop at the first
  host the browser's blocker does NOT cancel. So a single capture only ever
  reveals hosts up to the one that answers -- block that one, load again, and
  the next appears. This automates that walk.

  Nothing is hardcoded. Each round finds hosts by the loader's PATH, which does
  not rotate: /script/<base64(page hostname), padding stripped>.js. The token is
  derived from the target url, so a new site needs no configuration and a
  rotated host is found by shape rather than by name.

  Blocking is done with a PAC file pointed at an unroutable proxy, set in the
  CAPTURE CLONE's user.js only. That was chosen after measuring: in Chrome,
  neither CDP request interception (five abort modes) nor a declarativeNetRequest
  extension producing a genuine ERR_BLOCKED_BY_CLIENT made the loader advance.
  In Firefox a plain PAC connection failure does -- a run blocking the two hosts
  uBO let through walked past all four known hosts and revealed a fifth,
  poppyrimpace.com, which matched the operator fingerprint on every signal.

  ROUND 1 IS THE FAITHFUL CAPTURE: no PAC, so it shows what a normal visitor
  gets. Later rounds are deliberately distorted and exist only to enumerate. The
  round-1 capture is what gets left in place for the pipeline.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File C:\nwss-har\win-bait-walk.ps1
#>

param(
  [string[]]$Urls,
  [string]$TargetsFile = "",
  [string]$OutDir = "C:\nwss-har",
  [string]$Name = "capture",
  [int]$SecondsPerUrl = 20,
  [int]$MaxRounds = 6,
  [string]$Config = "",
  [string]$Site = "",
  [switch]$NoDigMatch,
  [string]$Detect = "",
  [string]$CaptureScript = "",
  [string]$PslRoot = "",
  [switch]$KeepPac
)

$ErrorActionPreference = 'Stop'
if (-not $CaptureScript) { $CaptureScript = Join-Path $PSScriptRoot "win-capture-scheduled.ps1" }
if (-not (Test-Path $CaptureScript)) { throw "capture script not found: $CaptureScript" }
# The psl helper must run from the REPO -- it requires ../lib/baitguard and
# node_modules/psl -- so it is never copied next to this script in $OutDir. The
# -Config path already points into the repo, so derive it from there; running
# this script from the repo itself is the other case. Absent helper is not an
# error: Get-Root falls back to its built-in suffix list.
if (-not $PslRoot) {
  $pslCandidates = @()
  if ($Config) { $pslCandidates += (Join-Path (Split-Path -Parent $Config) 'scripts\psl-root.js') }
  $pslCandidates += (Join-Path $PSScriptRoot 'psl-root.js')
  foreach ($c in $pslCandidates) { if (Test-Path -LiteralPath $c) { $PslRoot = $c; break } }
}
if (-not $TargetsFile) { $TargetsFile = Join-Path $OutDir "targets.txt" }

# --- target ------------------------------------------------------------------
if (-not $Urls -or $Urls.Count -eq 0) {
  if (-not (Test-Path $TargetsFile)) { throw "No -Urls and no targets file at $TargetsFile" }
  $Urls = @(Get-Content $TargetsFile | ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith("#") })
}
if (-not $Urls -or $Urls.Count -eq 0) { throw "No target urls" }
$targetHost = ([uri]$Urls[0]).Host

# The loader path is base64 of the page hostname with '=' padding stripped --
# derived, never configured, so it follows the site rather than a host list.
Write-Host "  target  : $targetHost"

# --- dig matching -------------------------------------------------------------
# The same bait_dig / bait_dig-or keys bait-confirm.js reads, so the fingerprint
# lives in ONE place. Applied DURING the walk, not just in the report: a host
# that does not match is not blocked and not added, so a stray regex match
# cannot drag an unrelated domain into the block set and distort later rounds.
$digAll = @(); $digAny = @()
if (-not $NoDigMatch -and $Config) {
  if (-not (Test-Path $Config)) { throw "config not found: $Config" }
  $cfg = Get-Content -Raw -LiteralPath $Config | ConvertFrom-Json
  $siteObj = $null
  foreach ($sc in $cfg.sites) {
    $urls = @($sc.url)
    if (-not $Site) { if ($urls -match [regex]::Escape($targetHost)) { $siteObj = $sc; break } }
    elseif ($urls -match [regex]::Escape($Site)) { $siteObj = $sc; break }
  }
  $pick = {
    param($key)
    if ($siteObj -and $siteObj.PSObject.Properties.Name -contains $key) { return @($siteObj.$key) }
    if ($cfg.PSObject.Properties.Name -contains $key) { return @($cfg.$key) }
    return @()
  }
  $digAll = @(@(& $pick 'bait_dig')    | Where-Object { $_ })
  $digAny = @(@(& $pick 'bait_dig-or') | Where-Object { $_ })

  # bait_rounds lives beside the other bait_* keys so the walk is configured in
  # ONE place. An explicit -MaxRounds still wins, for a one-off deeper or
  # shallower run; without this the count sat in both the parameter default and
  # the caller's command line, which is how the two drift apart.
  if (-not $PSBoundParameters.ContainsKey('MaxRounds')) {
    $cfgRounds = @(@(& $pick 'bait_rounds') | Where-Object { $_ })
    if ($cfgRounds.Count -and [int]$cfgRounds[0] -gt 0) {
      $MaxRounds = [int]$cfgRounds[0]
      Write-Host "  rounds  : $MaxRounds (from bait_rounds)"
    }
  }
  if ($digAll.Count -or $digAny.Count) {
    Write-Host "  dig gate: ALL[$($digAll -join ', ')] ANY[$($digAny -join ', ')]"
  } else {
    Write-Host "  dig gate: no bait_dig/bait_dig-or in config -- discovery ungated"
  }

  # bait_detect makes the loader pattern visible in the config instead of
  # hidden in this script. Still optional: with no key the pattern is DERIVED
  # from the target hostname, which is what keeps a rotated host findable and a
  # new site configuration-free.
  if (-not $PSBoundParameters.ContainsKey('Detect')) {
    # @() AROUND the pipeline: Where-Object collapses a single match to a
    # scalar, and indexing a scalar string gives a CHAR -- the detect pattern
    # came back as "u". The dig lists only escaped it by having >1 element.
    $cfgDetect = @(@(& $pick 'bait_detect') | Where-Object { $_ })
    if ($cfgDetect.Count) { $Detect = $cfgDetect[0] }
  }
}

# Precedence: -Detect, then bait_detect, then derived from the hostname.
if (-not $Detect) {
  $token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($targetHost)) -replace '=+$',''
  $Detect = "uri=https?://([^/ ]+)/script/$([regex]::Escape($token))\.js"
  Write-Host "  token   : $token   (base64 of the hostname)"
  Write-Host "  detect  : $Detect  (derived)"
} else {
  Write-Host "  detect  : $Detect  ($(if ($PSBoundParameters.ContainsKey('Detect')) { 'supplied' } else { 'from bait_detect' }))"
}

# Returns 'match' | 'mismatch' | 'unknown'. A FAILED lookup is never a mismatch:
# dropping a real bait because dns blipped is the expensive direction to be
# wrong in, so unknown is allowed through and flagged.
function Test-DigMatch([string]$domain) {
  if (-not $digAll.Count -and -not $digAny.Count) { return 'match' }
  $recs = @()
  foreach ($t in @('A','NS')) {
    try {
      $r = Resolve-DnsName -Name $domain -Type $t -ErrorAction SilentlyContinue
      if ($r) { $recs += ($r | ForEach-Object { "$($_.IPAddress) $($_.NameHost) $($_.Name)" }) }
    } catch { }
  }
  if (-not $recs.Count) { return 'unknown' }
  $blob = ($recs -join ' ').ToLower()
  foreach ($t in $digAll) { if ($blob -notlike "*$($t.ToLower())*") { return 'mismatch' } }
  if ($digAny.Count) {
    $any = $false
    foreach ($t in $digAny) { if ($blob -like "*$($t.ToLower())*") { $any = $true; break } }
    if (-not $any) { return 'mismatch' }
  }
  return 'match'
}

$profileDir = Join-Path $OutDir "capture-profile"
$userJs     = Join-Path $profileDir "user.js"
$pacFile    = Join-Path $OutDir "$Name-bait.pac"

# Registrable domain. The PAC blocks the root and every subdomain, since the
# shards live on 0.stg.<root> .. 9.stg.<root>.
#
# FALLBACK ONLY. The authority is the real Public Suffix List, reached through
# scripts/psl-root.js (see Resolve-Roots below): psl carries 9,778 suffix rules,
# 8,330 of them multi-part, against the 26 listed here. Of fifteen suffixes
# probed, thirteen were missing from this list -- co.il, com.pl, com.ua, co.th,
# com.ng, co.id, com.vn, com.ph, co.ke, and the private ones github.io,
# vercel.app, pages.dev, web.app.
#
# Getting it wrong is not cosmetic. Write-Pac below matches a bait as a SUFFIX
# (host === bait, or host ends with "." + bait), so a root of "co.il" blocks
# every .co.il host for the rest of the walk -- wrecking the capture it is
# trying to measure -- and the same wrong root is what gets written to the bait
# list. lib/baitguard.js refuses a public-suffix root at publish time, but that
# is after the PAC has already done the damage, which is why this is fixed here
# as well as guarded there.
#
# Kept as a degraded mode for a machine with no node on PATH or no reachable
# repo: worse than psl, far better than nothing, and the publish-time guard
# still backstops whatever it gets wrong.
$script:MultiPartSuffixes = @(
  'co.uk','org.uk','me.uk','ac.uk','gov.uk','co.jp','ne.jp','or.jp','ac.jp',
  'com.au','net.au','org.au','co.nz','net.nz','org.nz','com.br','com.cn',
  'com.tw','co.kr','co.za','com.mx','com.ar','co.in','com.sg','com.hk','com.tr'
)
# Resolved host -> registrable domain, from psl. Batched: node costs ~100ms to
# start over the \\wsl.localhost path this walk uses, so every host in a round
# is resolved in ONE call rather than one call per host.
$script:RootCache = @{}
$script:PslOff    = $false
$script:PslNoted  = $false

function Resolve-Roots([string[]]$names) {
  if ($script:PslOff -or -not $names -or $names.Count -eq 0) { return }
  if (-not $PslRoot) {
    if (-not $script:PslNoted) {
      Write-Host "    NOTE psl helper not found; using the built-in suffix list (26 rules)"
      $script:PslNoted = $true
    }
    $script:PslOff = $true
    return
  }
  # $payload, not $input: $input is an automatic variable in PowerShell.
  $payload = ($names | ForEach-Object { $_.Trim().ToLower().TrimEnd('.') } |
              Where-Object { $_ } | Sort-Object -Unique) -join "`n"
  $got = 0
  # 'Continue' around the call for the same reason the capture invocation needs
  # it: with $ErrorActionPreference = 'Stop' at the top of this script, a child
  # writing ANYTHING to stderr under 2>&1 becomes a terminating error and would
  # abort the whole walk over a warning.
  $prevEAP = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $out = $payload | & node $PslRoot 2>&1
    $code = $LASTEXITCODE
    if ($code -eq 0) {
      foreach ($line in @($out)) {
        $kv = ($line -replace "`r", '') -split "`t", 2
        if ($kv.Count -eq 2 -and $kv[0]) {
          # An EMPTY root means psl says the name has no registrable domain --
          # it IS a public suffix. Cache the host itself rather than the suffix:
          # blocking one host is narrow and wrong-but-harmless, blocking the
          # suffix is the catastrophe this whole change exists to prevent.
          $script:RootCache[$kv[0]] = if ($kv[1]) { $kv[1] } else { $kv[0] }
          $got++
        }
      }
    }
  } catch {
    $code = -1
  } finally {
    $ErrorActionPreference = $prevEAP
  }
  if ($got -eq 0) {
    if (-not $script:PslNoted) {
      Write-Host "    NOTE psl lookup unavailable (node exit $code); using the built-in suffix list (26 rules)"
      $script:PslNoted = $true
    }
    $script:PslOff = $true
  }
}

function Get-Root([string]$h) {
  # Normalise FIRST. The host arrives straight out of the capture --
  # Get-BaitHosts returns $_.Groups[1].Value with no folding, and only
  # Test-DigMatch lowercases -- so "Deer.ICKASIDE.CO.IL" and a root-anchored
  # "host.com." both reach here verbatim. Unnormalised, the root, the sidecar
  # key and the PAC entry all carry the capture's casing, and the publish-time
  # public-suffix guard in lib/baitguard.js saw "CO.IL" as a registrable domain
  # and waved it through. That guard normalises too -- this is the producer
  # half, so the walk's own report and PAC agree with what gets published.
  $h = $h.Trim().ToLower().TrimEnd('.')
  if ($script:RootCache.ContainsKey($h)) { return $script:RootCache[$h] }
  $p = $h.Split('.')
  if ($p.Count -le 2) { return $h }
  $lastTwo = ($p[-2..-1] -join '.')
  if ($script:MultiPartSuffixes -contains $lastTwo) {
    if ($p.Count -le 3) { return $h }
    return ($p[-3..-1] -join '.')
  }
  return $lastTwo
}

function Write-Pac([string[]]$roots) {
  $list = ($roots | ForEach-Object { '"' + $_ + '"' }) -join ', '
  @"
// generated by win-bait-walk.ps1 -- blocks discovered bait hosts so the
// loader is forced to offer the next one in its list.
function FindProxyForURL(url, host) {
  var baits = [$list];
  for (var i = 0; i < baits.length; i++) {
    if (host === baits[i] || host.indexOf("." + baits[i]) === host.length - baits[i].length - 1) {
      return "PROXY 127.0.0.1:1";   // nothing listens -> connection refused
    }
  }
  return "DIRECT";
}
"@ | Set-Content -LiteralPath $pacFile -Encoding ASCII
}

function Set-PacPrefs {
  Remove-PacPrefs
  $pacUrl = "file:///" + ($pacFile -replace '\\','/')
  Add-Content -LiteralPath $userJs -Value @(
    'user_pref("network.proxy.type", 2);',
    "user_pref(`"network.proxy.autoconfig_url`", `"$pacUrl`");"
  )
}

function Remove-PacPrefs {
  if (-not (Test-Path $userJs)) { return }
  $kept = Get-Content -LiteralPath $userJs | Where-Object { $_ -notmatch 'network\.proxy' }
  Set-Content -LiteralPath $userJs -Value $kept
}

# Pull every host that served the loader path out of a capture family.
function Get-BaitHosts([string]$base) {
  $hits = Select-String -Path "$base*.moz_log" -Pattern $Detect -AllMatches -ErrorAction SilentlyContinue
  if (-not $hits) { return @() }
  @($hits | ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

# --- the walk ----------------------------------------------------------------
$completed  = $false      # true only when a round reveals nothing new
$stopReason = "max rounds reached ($MaxRounds)"
$blocked = New-Object System.Collections.Generic.List[string]
$found   = New-Object System.Collections.Generic.List[string]
# What the dig gate actually decided, per root, and on which name. The report at
# the end used to re-derive a verdict with its own hardcoded houston/veda NS check
# against the root -- so it printed "fingerprint differs" for hosts the gate had
# just CONFIRMED and enumerated, because this operator's parked-apex family
# matches only on the serving subdomain. A report that can disagree with the gate
# is worse than no report: it reads as a failure on a successful walk.
$verdicts = @{}
$round   = 0
try {
  while ($round -lt $MaxRounds) {
    $round++
    $roundName = if ($round -eq 1) { $Name } else { "$Name-r$round" }
    if ($round -eq 1) {
      Remove-PacPrefs                      # round 1 is the faithful capture
      Write-Host "`n  round $round : no blocks (what a normal visitor sees)"
    } else {
      Write-Pac $blocked.ToArray()
      Set-PacPrefs
      Write-Host "`n  round $round : blocking $($blocked.Count) host(s): $($blocked -join ', ')"
    }

    # A capture that SKIPS (lock held by the scheduled task) exits 0, exactly
    # like a successful one. Without checking that the file actually advanced,
    # the walk would analyse the PREVIOUS capture and draw conclusions from
    # stale data -- reporting "nothing new" when nothing was captured at all.
    $roundLog = Join-Path $OutDir "$roundName.log.moz_log"
    $before = if (Test-Path $roundLog) { (Get-Item $roundLog).LastWriteTimeUtc } else { [datetime]::MinValue }

    # Keep the capture's output instead of discarding it. It used to go to
    # Out-Null to keep the walk readable, and when captures started coming back
    # truncated the only thing the walk could say was "capture failed; stopping"
    # -- the capture script's own "ok: NMB across N file(s)" line, and whatever
    # error replaced it, went straight to the bit bucket. Child-process output
    # lands on stdout even though the capture script uses Write-Host, so this
    # collects every line.
    # 2>&1 on a native command turns its stderr into ErrorRecords, and this
    # script runs with $ErrorActionPreference='Stop' -- so a capture that writes
    # one line to stderr would TERMINATE the walk before the handling below ever
    # ran, which is worse than the Out-Null it replaced. Measured: a failing
    # capture printed a NativeCommandError and the walk stopped with no verdict.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
      $capOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CaptureScript `
          -Urls $Urls -OutDir $OutDir -Name $roundName -SecondsPerUrl $SecondsPerUrl 2>&1
      $capCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prevEAP }
    if ($capCode -ne 0) {
      Write-Host "    capture failed (exit $capCode); stopping"
      if ($capOut) {
        Write-Host "    --- capture output ---"
        @($capOut) | ForEach-Object { Write-Host ("      " + $_) }
      } else {
        Write-Host "    (the capture produced no output at all)"
      }
      $stopReason = "a capture failed (exit $capCode)"
      break
    }
    # On success keep it to one line: the capture's own summary, which says how
    # much was written and whether the target was actually contacted. A silent
    # success is what let a 4KB capture pass for a 4MB one.
    $capSummary = @($capOut) | Where-Object { $_ -match '^\s*(ok|SKIP|ERROR|WARN):' } | Select-Object -Last 1
    if ($capSummary) { Write-Host ("    " + ([string]$capSummary).Trim()) }
    else {
      Write-Host "    capture reported no summary line -- its output follows"
      @($capOut) | ForEach-Object { Write-Host ("      " + $_) }
    }

    $after = if (Test-Path $roundLog) { (Get-Item $roundLog).LastWriteTimeUtc } else { [datetime]::MinValue }
    if ($after -le $before) {
      Write-Host "    capture did not run (another capture holds the lock); stopping"
      $stopReason = "a capture was skipped (lock held)"
      break
    }

    $hosts = Get-BaitHosts (Join-Path $OutDir "$roundName.log")
    if (-not $hosts -or $hosts.Count -eq 0) { Write-Host "    no loader urls in this capture; stopping"; $stopReason = "a capture contained no loader urls"; break }
    # One psl call for the whole round, before anything is reduced.
    Resolve-Roots $hosts

    $newRoots = @()
    foreach ($h in $hosts) {
      $r = Get-Root $h
      if ($blocked.Contains($r)) { if (-not $found.Contains($h)) { $found.Add($h) }; continue }
      # Dig the host that actually SERVED, not only its registrable domain. This
      # operator runs two families: one with the apex on Cloudflare (howphooey,
      # smoothhmph, html-load.cc -> 104.26./104.20./172.66./172.67.), and one with
      # the apex PARKED and its own footprint only on the serving subdomain --
      # ickaside.com and goshupward.com both resolve to 3.33.251.168 /
      # 15.197.225.128 (AWS Global Accelerator, shared by countless parked
      # domains), while deer.ickaside.com and hunt.goshupward.com both CNAME to
      # sdi.html-load.com. Gating on the root alone made the walk find those
      # hosts and then SKIP them, and widening the gate to the parked apex IPs
      # would have matched half the internet. Accept a match from either name;
      # keep "unknown" distinct from "mismatch" on both.
      $vh = Test-DigMatch $h
      $vr = if ($h -ne $r) { Test-DigMatch $r } else { $vh }
      $verdict = if ($vh -eq 'match' -or $vr -eq 'match') { 'match' }
                 elseif ($vh -eq 'mismatch' -or $vr -eq 'mismatch') { 'mismatch' }
                 else { 'unknown' }
      if ($verdict -eq 'mismatch') {
        Write-Host "    SKIP $r -- dig does not match the fingerprint (not blocked, not listed)"
        continue
      }
      if ($verdict -eq 'unknown') {
        Write-Host "    WARN $r -- dig lookup failed; allowing (a failed lookup is not a mismatch)"
      }
      if (-not $found.Contains($h)) { $found.Add($h) }
      $verdicts[$r] = @{ verdict = $verdict; via = if ($vh -eq 'match') { $h } elseif ($vr -eq 'match') { $r } else { '' } }
      $blocked.Add($r); $newRoots += $r
    }
    Write-Host "    hosts serving the loader: $($hosts -join ', ')"
    if ($newRoots.Count -eq 0) { Write-Host "    nothing new -- the list is exhausted"; $completed = $true; $stopReason = "exhausted"; break }
    Write-Host "    NEW: $($newRoots -join ', ')"

  }
} finally {
  if (-not $KeepPac) { Remove-PacPrefs; Remove-Item -LiteralPath $pacFile -Force -ErrorAction SilentlyContinue }
  # Only round 1 is a faithful capture; rounds 2+ are deliberately distorted and
  # are scratch. Cleaning them HERE rather than inside the loop matters: the loop
  # exits by break on "nothing new", so an in-loop cleanup never ran for the last
  # round and left its whole family behind.
  Get-ChildItem (Join-Path $OutDir "$Name-r*.log*") -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
  Get-ChildItem (Join-Path $OutDir "$Name-r*-runs.log") -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
}

# --- report ------------------------------------------------------------------
$roots = @($blocked | Sort-Object -Unique)
Write-Host "`n  === bait hosts enumerated in $round round(s) ==="
foreach ($r in $roots) {
  $ns = ""
  try { $ns = (Resolve-DnsName -Name $r -Type NS -ErrorAction SilentlyContinue |
               Where-Object { $_.NameHost } | ForEach-Object { $_.NameHost } | Sort-Object) -join ' ' } catch { }
  # The operator fingerprint: all known bait domains sit on one Cloudflare
  # account, while unrelated ad domains on the same pages do not.
  # A failed lookup is NOT a mismatch -- saying "differs" when nothing was
  # resolved reads as evidence against the domain when there is none.
  $rec = $verdicts[$r]
  $fp = if (-not $rec) { "gate not recorded" }
        elseif ($rec.verdict -eq 'match')    { "dig gate CONFIRMED" + $(if ($rec.via) { " via $($rec.via)" } else { "" }) }
        elseif ($rec.verdict -eq 'unknown')  { "dig gate UNKNOWN (lookup failed; a failure is not a mismatch)" }
        else                                 { "dig gate MISMATCH" }
  Write-Host ("    {0,-24} {1}" -f $r, $fp)
  if ($ns) { Write-Host ("        ns: {0}" -f $ns) }
}
# An INCOMPLETE walk must not overwrite a complete one. Measured: a run capped
# at one round replaced a six-host list with two, and the summary still read
# "enumerated in 1 round(s)" with nothing marking it partial. A lock collision
# or a failed capture would do the same, and bait-confirm.js would then silently
# check a shorter list.
$outFile = Join-Path $OutDir "$Name-baits.txt"
if ($completed) {
  # The pool is cumulative knowledge: a session may simply offer fewer hosts
  # than a previous one, so union with what is already known rather than
  # replacing it. A retired bait staying in the list costs nothing.
  $previous = @()
  if (Test-Path -LiteralPath $outFile) {
    $previous = @(Get-Content -LiteralPath $outFile | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  }
  # Record WHICH name satisfied the gate, so bait-confirm.js can re-check the same
  # name at publish time. Without this the confirmer digs only the root from the
  # baits file, and this operator's parked apexes (ickaside.com, goshupward.com ->
  # 3.33.251.168) match no term -- so hosts the walk CONFIRMED were then reported
  # MISMATCH and silently dropped from the output. Sidecar rather than a second
  # column: every existing reader treats a baits line as a bare domain.
  $hostsFile = Join-Path $OutDir "$Name-baits-hosts.txt"
  $hostMap = @{}
  if (Test-Path -LiteralPath $hostsFile) {
    foreach ($line in (Get-Content -LiteralPath $hostsFile)) {
      $kv = $line -split "`t", 2
      if ($kv.Count -eq 2 -and $kv[0] -and $kv[1]) { $hostMap[$kv[0].Trim()] = $kv[1].Trim() }
    }
  }
  foreach ($k in $verdicts.Keys) {
    $via = $verdicts[$k].via
    if ($via) { $hostMap[$k] = $via }
  }
  if ($hostMap.Count) {
    ($hostMap.Keys | Sort-Object | ForEach-Object { "$_`t$($hostMap[$_])" }) |
      Set-Content -LiteralPath $hostsFile -Encoding ASCII
  }

  $merged = @(($roots + $previous) | Sort-Object -Unique)
  $added = @($roots | Where-Object { $previous -notcontains $_ })
  $merged | Set-Content -LiteralPath $outFile -Encoding ASCII
  Write-Host "`n  walk COMPLETE ($stopReason)"
  $newNote = if ($added.Count) { "$($added.Count) new this run" } else { "none new" }
  Write-Host "  written: $outFile  ($($merged.Count) host(s), $newNote)"
} else {
  $partFile = Join-Path $OutDir "$Name-baits.partial.txt"
  $roots | Set-Content -LiteralPath $partFile -Encoding ASCII
  # The sidecar matters MORE on this path than on the complete one. The publisher
  # now confirms partial hosts too, and without "which name satisfied the gate"
  # bait-confirm.js digs only the root -- so this operator's parked apexes
  # (sansyettusk.com -> 3.33.251.168) match no bait_dig term and report MISMATCH,
  # dropping the rotation this walk DID find one step further along. Measured on
  # recorder.ca: round 1 found sansyettusk.com, round 2 returned no loader urls,
  # and the host reached nothing but this file.
  #
  # Written fresh and DELETED when empty, never unioned: a partial describes one
  # run, and a leftover sidecar paired with a newer partial would attribute the
  # wrong name to a host. The publisher keys off the partial's own mtime, so a
  # stale pair must not look current.
  $partHostsFile = Join-Path $OutDir "$Name-baits.partial-hosts.txt"
  $partMap = @{}
  foreach ($k in $verdicts.Keys) {
    if (($roots -contains $k) -and $verdicts[$k].via) { $partMap[$k] = $verdicts[$k].via }
  }
  if ($partMap.Count) {
    ($partMap.Keys | Sort-Object | ForEach-Object { "$_`t$($partMap[$_])" }) |
      Set-Content -LiteralPath $partHostsFile -Encoding ASCII
  } elseif (Test-Path -LiteralPath $partHostsFile) {
    Remove-Item -LiteralPath $partHostsFile -Force
  }
  Write-Host "`n  walk INCOMPLETE -- stopped because $stopReason"
  Write-Host "  the authoritative list was NOT touched: $outFile"
  Write-Host "  this run's partial findings: $partFile"
}
Write-Host "  capture kept: $(Join-Path $OutDir "$Name.log.moz_log")  (round 1, undistorted)"

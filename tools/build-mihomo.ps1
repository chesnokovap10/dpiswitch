# Builds a minimal mihomo.exe for DPI Switch into .\dist
#
# The source is the public fork of mihomo (see DPISWITCH.md there): the
# upstream commit the program was tested with, the cut below already made,
# every dependency in vendor/, and mipstack ahead of upstream's -- the one
# where a peer's ICMP error no longer ends a UDP session through a WireGuard
# outbound, which left BitTorrent's uTP and DHT through the tunnel with
# nothing.
#
# Only what DPI Switch uses is kept:
#  - outbounds: wireguard (AmneziaWG), and direct for direct-split, the one
#    that cuts the ClientHello (tls-split, the fork's own); DIRECT and REJECT
#    are built into the core and do not go through the parser;
#  - inbounds: tun and socks (the prober's listeners);
#  - no gVisor: the TUN inbound runs on the Windows stack ("system") and the
#    WireGuard outbounds on mihomo's own "mips" stack (see awgconf).
#
# mihomo has no per-protocol build tags, so the unused protocols are cut out
# of the two type switches before the build (see Limit-Switch); the linker
# then drops their code. Build tags drop the embedded Tailscale, ZeroTier and
# EasyTier stacks and Hysteria's fake-TCP; -s -w strips debug symbols.
param(
    # pinned commit of the fork: upstream Alpha 9f053c49 (its mipstack has
    # the ICMP fix), the cut, vendor/, the WireGuard outbound reading the
    # stack one packet at a time (the first DNS queries after a start went
    # unanswered on half the starts), the API narrowed to what DPI Switch
    # calls, and UDP on a SOCKS listener with users only through an
    # association, and a direct outbound that cuts the ClientHello
    # (tls-split), cutting the name inside the registered domain's label;
    # see DPISWITCH.md there
    [string]$Commit = "929ab611dc809e2d5b9234d35d415e376ea0deba",
    [string]$Repo = "https://github.com/chesnokovap10/mihomo-dpiswitch.git"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path
$src = Join-Path $env:TEMP "mihomo-src-$($Commit.Substring(0, 12))"
# what dist\mihomo.exe was built from: the commit and the file's SHA-256,
# written once the core has passed the routing tests below. build.ps1 builds
# the core again when it says another commit, or another file, or nothing.
$stamp = Join-Path $root "dist\mihomo.commit"

if (-not (Test-Path $src)) {
    git clone --filter=blob:none $Repo $src
} else {
    # the copy is reset below: a change made in it and not yet committed
    # would go with the reset, without a word
    $dirty = git -C $src status --porcelain
    if ($LASTEXITCODE) { throw "$src is not a copy git can read: remove it to build afresh" }
    if ($dirty) { throw "$src holds changes not committed: commit them in the fork first, or remove the folder to build afresh" }
}
git -C $src fetch --quiet $Repo $Commit
# a previous run left the switches cut: start from the pristine tree
git -C $src reset --quiet --hard
git -C $src checkout --quiet --detach $Commit
# a git command failing does not stop the script: without this check a
# fetch that failed built whatever commit the copy was on
if ((git -C $src rev-parse HEAD) -ne $Commit) { throw "the core's source is not at $Commit" }

# Keeps only the listed cases of the "switch proxyType" in a file. A case runs
# from its "case" line to the next case/default at the same indent.
function Limit-Switch([string]$File, [string[]]$Keep) {
    $path = Join-Path $src $File
    $out = [Collections.Generic.List[string]]::new()
    $in = $false; $skip = $false; $seen = @()
    foreach ($line in [IO.File]::ReadAllLines($path)) {
        if ($line -eq "`tswitch proxyType {") { $in = $true }
        elseif ($in -and $line -match "^`t(case|default)") {
            $skip = $false
            if ($line -match "^`tcase `"([^`"]+)`":") {
                $skip = $Keep -notcontains $Matches[1]
                if (-not $skip) { $seen += $Matches[1] }
            }
        }
        elseif ($in -and $line -eq "`t}") { $in = $false; $skip = $false }
        if (-not $skip) { $out.Add($line) }
    }
    # the layout changed upstream: fail rather than build a core without them
    $missing = $Keep | Where-Object { $seen -notcontains $_ }
    if ($missing) { throw "$File`: no case for $($missing -join ', ')" }
    [IO.File]::WriteAllLines($path, $out)
}
Limit-Switch "adapter\parser.go" @("wireguard", "direct")
Limit-Switch "listener\parse.go" @("socks", "tun")

$tags = "no_tailscale,no_zerotier,no_easytier,no_fake_tcp"
New-Item -ItemType Directory -Force (Join-Path $root dist) | Out-Null
$out = Join-Path $root "dist\mihomo.exe"
# the old stamp goes first: a build that stops halfway leaves none
Remove-Item $stamp -ErrorAction SilentlyContinue
Push-Location $src
# the caller's setting comes back after: build.ps1 -Race needs cgo for its
# own build, and a first run builds the core in between
$cgo = $env:CGO_ENABLED
try {
    $env:CGO_ENABLED = "0"
    go build -trimpath -tags $tags -ldflags "-s -w" -o $out .
    if ($LASTEXITCODE) { throw "the core did not build" }
} finally {
    $env:CGO_ENABLED = $cgo
    Pop-Location
}
Write-Host ("done: {0} ({1:N1} MB, tags: {2})" -f $out, ((Get-Item $out).Length / 1MB), $tags)

# the new core on tunnel only's config with the tunnels dead: nothing may go
# direct. Fallback groups keeping a dead first member, and a member alive
# until checked, are the core's behaviour, not a promise of it -- an update
# can change them (see internal\awgconf\core_routing_test.go)
# Then the help's routing tables, cell by cell, on the new core with the
# tunnels alive or dead for real (TestCoreTables). And what the fork locks
# down: the prober's listener takes its user alone and UDP only through an
# association, the API no config from outside and no upgrade
# (TestCoreLockedDown).
Write-Host "checking the core: tunnel only never goes direct, the tables of the help, the lock-down (~2 min)"
$prev = $env:DPISWITCH_CORE
Push-Location $root
try {
    $env:DPISWITCH_CORE = $out
    go test -tags routing -run 'TestCoreFailClosed|TestCoreTables|TestCoreLockedDown' -count=1 ./internal/awgconf
    if ($LASTEXITCODE) { throw "the new core does not route as the help's tables say, or is not locked down: do not ship it" }
} finally {
    $env:DPISWITCH_CORE = $prev
    Pop-Location
}
$hash = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
Set-Content -NoNewline -Encoding ascii $stamp "$Commit $hash"
Write-Host "stamped: $stamp"

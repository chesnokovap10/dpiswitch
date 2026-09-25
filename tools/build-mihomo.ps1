# Builds a minimal mihomo.exe for DPI Switch into .\dist
#
# Only what DPI Switch uses is kept:
#  - outbounds: wireguard (AmneziaWG) only; DIRECT and REJECT are built into
#    the core and do not go through the parser;
#  - inbounds: tun and socks (the prober's listeners);
#  - no gVisor: the TUN inbound runs on the Windows stack ("system") and the
#    WireGuard outbounds on mihomo's own "mips" stack (see awgconf).
#
# mihomo has no per-protocol build tags, so the unused protocols are cut out
# of the two type switches before the build (see Limit-Switch); the linker
# then drops their code. Build tags drop the embedded Tailscale, ZeroTier and
# EasyTier stacks and Hysteria's fake-TCP; -s -w strips debug symbols.
param(
    # pinned commit the program was tested with
    [string]$Commit = "f103639c808d93a2c34cae56757b458862871b22"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path
$src = Join-Path $env:TEMP "mihomo-src-$($Commit.Substring(0, 12))"

if (-not (Test-Path $src)) {
    git clone --filter=blob:none https://github.com/MetaCubeX/mihomo.git $src
}
git -C $src fetch --quiet origin $Commit
# a previous run left the switches cut: start from the pristine tree
git -C $src reset --quiet --hard
git -C $src checkout --quiet --detach $Commit

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
Limit-Switch "adapter\parser.go" @("wireguard")
Limit-Switch "listener\parse.go" @("socks", "tun")

$tags = "no_tailscale,no_zerotier,no_easytier,no_fake_tcp"
New-Item -ItemType Directory -Force (Join-Path $root dist) | Out-Null
$out = Join-Path $root "dist\mihomo.exe"
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

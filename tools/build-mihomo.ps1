# Builds a slim mihomo.exe for DPI Switch into .\dist
#
# Only what DPI Switch uses is kept. Build tags drop the embedded Tailscale,
# ZeroTier and EasyTier stacks and Hysteria's fake-TCP; -s -w strips debug
# symbols. The result is ~39 MB instead of ~80 MB with identical behaviour.
#
# with_gvisor stays: the TUN inbound uses the gVisor stack. The WireGuard
# outbounds use mihomo's own "mips" stack (see awgconf), not gVisor.
#
# mihomo has no per-protocol build tags (VLESS, Trojan, Hysteria... are
# always compiled in); removing them would require maintaining a fork.
param(
    # pinned commit the program was tested with
    [string]$Commit = "5019cc090ed7cafb76643f964a76b1e97aee2985"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path
$src = Join-Path $env:TEMP "mihomo-src-$($Commit.Substring(0, 12))"

if (-not (Test-Path $src)) {
    git clone --filter=blob:none https://github.com/MetaCubeX/mihomo.git $src
}
git -C $src fetch --quiet origin $Commit
git -C $src checkout --quiet --detach $Commit

$tags = "with_gvisor,no_tailscale,no_zerotier,no_easytier,no_fake_tcp"
New-Item -ItemType Directory -Force (Join-Path $root dist) | Out-Null
$out = Join-Path $root "dist\mihomo.exe"
Push-Location $src
try {
    $env:CGO_ENABLED = "0"
    go build -trimpath -tags $tags -ldflags "-s -w" -o $out .
} finally {
    Pop-Location
}
Write-Host ("done: {0} ({1:N1} MB, tags: {2})" -f $out, ((Get-Item $out).Length / 1MB), $tags)

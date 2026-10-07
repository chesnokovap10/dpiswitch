# Checks the UDP leak guard against the real Windows Filtering Platform:
# builds the checks (TestLive in internal\udpguard, TestLiveGuardHolds in
# internal\supervisor), runs them elevated -- one administrator prompt -- and
# shows what they found.
#
# The checks put the guard's filters into a session of their own for a few
# seconds, send a byte of UDP out of the Wi-Fi or cable adapter by its own
# address to documentation-range addresses nothing answers, and compare what
# the filters drop, as the engine records it, with what they should. The
# filters go with the process; nothing is left behind. The core the service
# runs is let through, so the tunnel goes on.
#
#   .\tools\udpguard-live.ps1
param(
    # the elevated half
    [switch]$ElevatedPart,
    [string]$Dir = "",
    [string]$Out = ""
)

$ErrorActionPreference = "Stop"

if ($ElevatedPart) {
    $env:DPISWITCH_LIVE_WFP = "1"
    $code = 0
    # quoted: PowerShell splits a bare -test.run at its dot
    & (Join-Path $Dir "udpguard.test.exe") "-test.run=TestLive" "-test.v" "-test.count=1" *> $Out
    if ($LASTEXITCODE) { $code = $LASTEXITCODE }
    & (Join-Path $Dir "supervisor.test.exe") "-test.run=TestLiveGuardHolds" "-test.v" "-test.count=1" *>> $Out
    if ($LASTEXITCODE) { $code = $LASTEXITCODE }
    "exit code: $code" | Add-Content $Out
    exit $code
}

Set-Location (Split-Path $PSScriptRoot)
$dir = Join-Path $env:TEMP "udpguard-live"
$out = Join-Path $env:TEMP "udpguard-live.txt"
Remove-Item $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $dir | Out-Null

go test -c -o (Join-Path $dir "udpguard.test.exe") ./internal/udpguard
if ($LASTEXITCODE) { throw "go test -c failed (udpguard)" }
go test -c -o (Join-Path $dir "supervisor.test.exe") ./internal/supervisor
if ($LASTEXITCODE) { throw "go test -c failed (supervisor)" }

Write-Host "running elevated: allow the prompt"
Start-Process powershell -Verb RunAs -Wait -ArgumentList @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"",
    "-ElevatedPart", "-Dir", "`"$dir`"", "-Out", "`"$out`"")

if (-not (Test-Path $out)) { throw "the elevated half left no output: the prompt was refused?" }
Get-Content $out
Remove-Item $dir -Recurse -ErrorAction SilentlyContinue

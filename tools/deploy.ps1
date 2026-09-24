# Replaces the installed dpiswitch.exe with a build and restarts the service
# and the tray. No elevation needed: the service lets interactive users stop
# and start it.
#
#   .\tools\deploy.ps1                 dist\dpiswitch.exe
#   .\tools\deploy.ps1 -Race           dist\dpiswitch-race.exe
#   .\tools\deploy.ps1 -Path <exe>     any build -- the .last.exe kept beside
#                                      the installed one is the way back
param(
    [string]$Path = "",
    [switch]$Race
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot)

if (-not $Path) { $Path = if ($Race) { "dist\dpiswitch-race.exe" } else { "dist\dpiswitch.exe" } }
$src = (Resolve-Path $Path).Path

# the target is what the service runs: its command line without the argument
$svc = Get-CimInstance Win32_Service -Filter "Name='dpiswitch'"
if (-not $svc) { throw "the dpiswitch service is not installed: run dpiswitch.exe install first" }
$target = if ($svc.PathName -match '^"([^"]+)"') { $Matches[1] } else { $svc.PathName -replace '\s+service$', '' }
$hash = (Get-FileHash $src).Hash
if ($hash -eq (Get-FileHash $target).Hash) {
    Write-Host "already deployed: $target"
    return
}

function Wait-Until([scriptblock]$cond, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while (-not (& $cond)) {
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 250
    }
    return $true
}

$down = Get-Date
# The tray runs from the same file and holds it open, so it goes first; it is
# started again at the end if it was running.
$trays = @(Get-Process dpiswitch -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -ne 0 -and $_.Path -eq $target })
$trays | Stop-Process -Force

# The service is asked to stop and waited for, process and all: one killed
# mid-stop is logged by Windows as a crash (event 7031), which muddles any
# later look for real ones.
$pid0 = $svc.ProcessId
sc.exe stop dpiswitch | Out-Null
if (-not (Wait-Until { (Get-Service dpiswitch).Status -eq 'Stopped' } 60)) {
    throw "the service did not stop within a minute; nothing was replaced"
}
if ($pid0) { Wait-Until { -not (Get-Process -Id $pid0 -ErrorAction SilentlyContinue) } 30 | Out-Null }

try {
    # the binary being replaced stays beside it, for a way back
    Copy-Item $target ($target -replace '\.exe$', '.last.exe') -Force
    # a process that has just exited may hold the file a moment longer
    $copied = Wait-Until {
        try { Copy-Item $src $target -Force; $true } catch { $false }
    } 20
    if (-not $copied) { throw "$target stayed locked; the old binary is still in place" }
} finally {
    # whatever happened above, the tunnel does not stay down
    sc.exe start dpiswitch | Out-Null
}
if (-not (Wait-Until { (Get-Service dpiswitch).Status -eq 'Running' } 30)) {
    throw "the service did not start again: see %ProgramData%\dpiswitch\logs\service.log"
}
$up = Get-Date
if ((Get-FileHash $target).Hash -ne $hash) { throw "$target does not match $src after the copy" }
if ($trays.Count -gt 0) { Start-Process $target }

$v = (Get-Item $target).VersionInfo.FileVersion
Write-Host ("deployed {0} ({1}, {2}) to {3}; tunnel down {4:N0} s" -f
    (Split-Path $src -Leaf), $v, $hash.Substring(0, 12).ToLower(), $target, ($up - $down).TotalSeconds)

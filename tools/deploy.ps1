# Replaces the installed dpiswitch.exe with a build and restarts the service
# and the tray.
#
# The service runs as SYSTEM from %ProgramFiles%\DPI Switch, where only
# administrators write -- replacing it takes one administrator prompt. A
# service still registered somewhere else (an installation from before it was
# copied there) is reinstalled from the build, which moves it.
#
#   .\tools\deploy.ps1                 dist\dpiswitch.exe
#   .\tools\deploy.ps1 -Race           dist\dpiswitch-race.exe
#   .\tools\deploy.ps1 -Path <exe>     any build -- the .last.exe kept beside
#                                      the installed one is the way back
param(
    [string]$Path = "",
    [switch]$Race,
    # the elevated half: stop the service, replace its binary, start it
    [switch]$ServicePart
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot)

if (-not $Path) { $Path = if ($Race) { "dist\dpiswitch-race.exe" } else { "dist\dpiswitch.exe" } }
$src = (Resolve-Path $Path).Path
$hash = (Get-FileHash $src).Hash

function Wait-Until([scriptblock]$cond, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while (-not (& $cond)) {
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 250
    }
    return $true
}

function Service-Target {
    $svc = Get-CimInstance Win32_Service -Filter "Name='dpiswitch'"
    if (-not $svc) { return $null }
    if ($svc.PathName -match '^"([^"]+)"') { return $Matches[1] }
    return $svc.PathName -replace '\s+service$', ''
}

$installed = Join-Path $env:ProgramFiles "DPI Switch\dpiswitch.exe"

if ($ServicePart) {
    $target = Service-Target
    # The service is asked to stop and waited for, process and all: one killed
    # mid-stop is logged by Windows as a crash (event 7031), which muddles any
    # later look for real ones.
    $pid0 = (Get-CimInstance Win32_Service -Filter "Name='dpiswitch'").ProcessId
    sc.exe stop dpiswitch | Out-Null
    if (-not (Wait-Until { (Get-Service dpiswitch).Status -eq 'Stopped' } 120)) {
        throw "the service did not stop within two minutes; nothing was replaced"
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
    return
}

$target = Service-Target
if (-not $target) { throw "the dpiswitch service is not installed: install it from the tray first" }
$moved = -not [string]::Equals([IO.Path]::GetFullPath($target), [IO.Path]::GetFullPath($installed),
    [StringComparison]::OrdinalIgnoreCase)
if (-not $moved -and $hash -eq (Get-FileHash $target).Hash) {
    Write-Host "already deployed: $target"
    return
}

$down = Get-Date
# The trays of this session go first: one may run from the file being
# replaced, and each is given the new build too. They are started again at
# the end.
$trays = @(Get-Process dpiswitch -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -ne 0 -and $_.SessionId -eq (Get-Process -Id $PID).SessionId })
$trayPaths = @($trays | ForEach-Object { $_.Path } | Sort-Object -Unique)
$trays | Stop-Process -Force

# The trays come back whatever happens below. The administrator prompt
# declined, or left to expire with nobody at the computer, threw here with
# the trays already stopped: the session was left without one, and the UI
# with it, until someone started it by hand (10.10).
$deployed = $false
try {
    if ($moved) {
        # reinstalled from the build, for this user: it copies itself to
        # Program Files and registers that copy (the prompt's "Done" is to be
        # closed for the script to go on)
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Start-Process $src -ArgumentList "reinstall", "--owner", $sid -Verb RunAs -Wait
    } else {
        $shell = (Get-Process -Id $PID).Path
        # Start-Process joins the list with spaces and quotes nothing: a path with
        # a space in it reached the elevated half as two arguments
        Start-Process $shell -Verb RunAs -Wait -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`"", "-Path", "`"$src`"", "-ServicePart"
    }
    if (-not (Wait-Until { (Get-Service dpiswitch).Status -eq 'Running' } 30)) {
        throw "the service did not start again: see %ProgramData%\dpiswitch\logs\service.log"
    }
    $up = Get-Date
    $target = Service-Target
    if ((Get-FileHash $target).Hash -ne $hash) { throw "$target does not match $src after the copy" }
    $deployed = $true
} finally {
    foreach ($p in $trayPaths) {
        # a tray of its own file gets the build only once the service has it
        if ($deployed -and -not [string]::Equals($p, $target, [StringComparison]::OrdinalIgnoreCase)) {
            Copy-Item $p ($p -replace '\.exe$', '.last.exe') -Force
            Copy-Item $src $p -Force
        }
        # Through explorer, not Start-Process: a child of this shell lives in its
        # job, and the tray died with the terminal (or Claude's session) that ran
        # the deploy.
        explorer.exe $p
    }
}

$v = (Get-Item $target).VersionInfo.FileVersion
Write-Host ("deployed {0} ({1}, {2}) to {3}; tunnel down {4:N0} s" -f
    (Split-Path $src -Leaf), $v, $hash.Substring(0, 12).ToLower(), $target, ($up - $down).TotalSeconds)

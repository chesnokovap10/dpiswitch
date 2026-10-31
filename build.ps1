# Builds dpiswitch.exe into .\dist -- a single executable with the mihomo
# core embedded (see internal\core).
# The version comes from internal\version\version.go; -Version overrides it.
param(
    [string]$Version = "",
    # build without the embedded core (development: mihomo.exe next to the exe)
    [switch]$NoEmbed,
    # debug build with the race detector into dist\dpiswitch-race.exe; needs
    # cgo and gcc (winget install BrechtSanders.WinLibs.POSIX.UCRT)
    [switch]$Race,
    # no vet and tests: for a build right after they passed on this tree
    [switch]$NoTests
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not $Version) {
    $Version = (Select-String -Path internal\version\version.go -Pattern 'Version = "(.+)"').Matches.Groups[1].Value
}
$fileVer = "$Version.0"

# a program failing does not stop a PowerShell script: its exit code is
# looked at, or failing tests went on to build a release
if (-not $NoTests) {
    go vet ./...
    if ($LASTEXITCODE) { throw "go vet failed" }
    go test ./...
    if ($LASTEXITCODE) { throw "go test failed" }
}

if ($Race) {
    $env:CGO_ENABLED = "1"
    if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
        # a winget install reaches PATH only in shells opened after it
        $gcc = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.*\mingw64\bin\gcc.exe" -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $gcc) { throw "-Race needs gcc for cgo: winget install BrechtSanders.WinLibs.POSIX.UCRT" }
        $env:PATH = "$($gcc.DirectoryName);$env:PATH"
    }
    # the tests under the detector first: a race they reach is cheaper to find here
    go test -race ./...
    if ($LASTEXITCODE) { throw "go test -race failed" }
}

# Windows resources: icon, version info and manifest embedded into the exe
go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --out cmd/dpiswitch/rsrc `
    --icon assets/app.ico --manifest gui `
    --product-name "DPI Switch" --file-description "DPI Switch" `
    --product-version $fileVer --file-version $fileVer `
    --original-filename dpiswitch.exe --copyright "chesnokovap10"
if ($LASTEXITCODE) { throw "go-winres failed" }

$tags = ""
if (-not $NoEmbed) {
    # the slim core: built by tools\build-mihomo.ps1 and reused afterwards --
    # while its stamp says it is the commit pinned there, and this very file.
    # A core left in dist from another pin, or put there by hand, was
    # embedded without a word.
    $m = Select-String -Path tools\build-mihomo.ps1 -Pattern '\[string\]\$Commit = "([0-9a-f]{40})"'
    if (-not $m) { throw "no pinned commit found in tools\build-mihomo.ps1" }
    $pin = $m.Matches[0].Groups[1].Value
    $stamped = $false
    if ((Test-Path dist\mihomo.exe) -and (Test-Path dist\mihomo.commit)) {
        $c, $h = (Get-Content dist\mihomo.commit -Raw).Trim() -split ' '
        $stamped = $c -eq $pin -and $h -eq (Get-FileHash dist\mihomo.exe -Algorithm SHA256).Hash.ToLower()
    }
    if (-not $stamped) {
        Write-Host "dist\mihomo.exe is not stamped as $pin`: building the core"
        & .\tools\build-mihomo.ps1
    }
    $core = (Resolve-Path dist\mihomo.exe).Path
    (Get-FileHash $core -Algorithm SHA256).Hash.ToLower() |
        Set-Content -NoNewline -Encoding ascii internal\core\mihomo.exe.sha256
    $in = [IO.File]::OpenRead($core)
    $out = [IO.File]::Create((Join-Path $PWD internal\core\mihomo.exe.gz))
    $gz = New-Object IO.Compression.GZipStream($out, [IO.Compression.CompressionLevel]::Optimal)
    $in.CopyTo($gz); $gz.Dispose(); $out.Dispose(); $in.Dispose()
    $tags = "embedcore"
}

$ld = "-H=windowsgui -s -w -X dpiswitch/internal/version.Version=$Version"
$exe = "dist\dpiswitch.exe"
$flags = @("-trimpath")
if ($Race) {
    # symbols stay: a race report is read by function and line. The version
    # says what it is, in the tray and in every log's first line
    $ld = "-H=windowsgui -X dpiswitch/internal/version.Version=$Version-race"
    $exe = "dist\dpiswitch-race.exe"
    $flags += "-race"
}
New-Item -ItemType Directory -Force dist | Out-Null
go build @flags -tags "$tags" -ldflags $ld -o $exe ./cmd/dpiswitch
if ($LASTEXITCODE) { throw "go build failed" }
$mb = (Get-Item $exe).Length / 1MB
$what = if ($Race) { "race detector" } elseif ($NoEmbed) { "core NOT embedded: mihomo.exe must sit next to it" } else { "core embedded" }
Write-Host ("done: {0} {1} ({2:N1} MB, {3})" -f $exe, $Version, $mb, $what)

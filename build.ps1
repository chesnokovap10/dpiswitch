# Builds dpiswitch.exe into .\dist -- a single executable with the mihomo
# core embedded (see internal\core).
# The version comes from internal\version\version.go; -Version overrides it.
param(
    [string]$Version = "",
    # build without the embedded core (development: mihomo.exe next to the exe)
    [switch]$NoEmbed
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not $Version) {
    $Version = (Select-String -Path internal\version\version.go -Pattern 'Version = "(.+)"').Matches.Groups[1].Value
}
$fileVer = "$Version.0"

go vet ./...
go test ./...

# Windows resources: icon, version info and manifest embedded into the exe
go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --out cmd/dpiswitch/rsrc `
    --icon assets/app.ico --manifest gui `
    --product-name "DPI Switch" --file-description "DPI Switch" `
    --product-version $fileVer --file-version $fileVer `
    --original-filename dpiswitch.exe --copyright "chesnokovap10"

$tags = ""
if (-not $NoEmbed) {
    # the slim core: built once by tools\build-mihomo.ps1, reused afterwards
    if (-not (Test-Path dist\mihomo.exe)) { & .\tools\build-mihomo.ps1 }
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
New-Item -ItemType Directory -Force dist | Out-Null
go build -trimpath -tags "$tags" -ldflags $ld -o dist\dpiswitch.exe ./cmd/dpiswitch
$mb = (Get-Item dist\dpiswitch.exe).Length / 1MB
if ($NoEmbed) {
    Write-Host ("done: dist\dpiswitch.exe {0} ({1:N1} MB, core NOT embedded: mihomo.exe must sit next to it)" -f $Version, $mb)
} else {
    Write-Host ("done: dist\dpiswitch.exe {0} ({1:N1} MB, core embedded)" -f $Version, $mb)
}

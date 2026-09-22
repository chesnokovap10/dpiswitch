# Builds dpiswitch.exe into .\dist
# The version comes from internal\version\version.go; -Version overrides it.
param([string]$Version = "")

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

$ld = "-H=windowsgui -s -w -X dpiswitch/internal/version.Version=$Version"
New-Item -ItemType Directory -Force dist | Out-Null
go build -trimpath -ldflags $ld -o dist\dpiswitch.exe ./cmd/dpiswitch
Write-Host "done: dist\dpiswitch.exe $Version (mihomo.exe must sit next to it)"

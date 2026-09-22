# Сборка dpiswitch.exe в .\dist
# Версия берётся из internal\version\version.go; -Version переопределяет её.
param([string]$Version = "")

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

go vet ./...
go test ./...

$ld = "-H=windowsgui -s -w"
if ($Version) { $ld += " -X dpiswitch/internal/version.Version=$Version" }

New-Item -ItemType Directory -Force dist | Out-Null
go build -trimpath -ldflags $ld -o dist\dpiswitch.exe ./cmd/dpiswitch
Write-Host "готово: dist\dpiswitch.exe (рядом должен лежать mihomo.exe)"

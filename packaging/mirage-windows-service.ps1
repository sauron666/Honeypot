# MIRAGE on Windows — install the director as a Windows service.
#
# Run this in an elevated PowerShell from the folder you unzipped MIRAGE into.
# It uses the built-in Service Control Manager; no third-party tools.
#
#   .\mirage-windows-service.ps1 -Install
#   .\mirage-windows-service.ps1 -Uninstall
#
# The console is then at http://127.0.0.1:8422 on the host.

param(
    [switch]$Install,
    [switch]$Uninstall,
    [string]$InstallDir = "C:\Program Files\MIRAGE",
    [string]$Config     = "C:\ProgramData\MIRAGE\config.yaml"
)

$ServiceName = "MirageDirector"

if ($Uninstall) {
    sc.exe stop $ServiceName | Out-Null
    sc.exe delete $ServiceName | Out-Null
    Write-Host "Removed service $ServiceName."
    exit 0
}

if ($Install) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Split-Path $Config) | Out-Null

    Copy-Item ".\mirage-director.exe" $InstallDir -Force
    Copy-Item ".\miragectl.exe"       $InstallDir -Force
    if (-not (Test-Path $Config)) {
        Copy-Item ".\profiles\p0-box.yaml" $Config
        Write-Host "Wrote a starter config to $Config — edit it before going to production."
    }

    $bin = Join-Path $InstallDir "mirage-director.exe"
    sc.exe create $ServiceName binPath= "`"$bin`" --config `"$Config`"" start= auto DisplayName= "MIRAGE Deception Platform" | Out-Null
    sc.exe description $ServiceName "MIRAGE honeypot/deception platform director." | Out-Null
    sc.exe start $ServiceName | Out-Null
    Write-Host "Installed and started $ServiceName. Console: http://127.0.0.1:8422"
    exit 0
}

Write-Host "Usage: .\mirage-windows-service.ps1 -Install | -Uninstall"

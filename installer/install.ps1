param(
    [string]$InstallRoot = "$env:ProgramFiles\Antivirus GUI"
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required."
    }
}

Assert-Admin

$packageRoot = Split-Path -Parent $PSScriptRoot
$sourceBin = Join-Path $packageRoot "bin"
$targetBin = Join-Path $InstallRoot "bin"
$targetInstaller = Join-Path $InstallRoot "installer"
$serviceExe = Join-Path $targetBin "AntivirusService.exe"

New-Item -ItemType Directory -Force -Path $targetBin | Out-Null
New-Item -ItemType Directory -Force -Path $targetInstaller | Out-Null

Copy-Item -Path (Join-Path $sourceBin "*") -Destination $targetBin -Recurse -Force
Copy-Item -Path (Join-Path $PSScriptRoot "*") -Destination $targetInstaller -Recurse -Force

& $serviceExe --install
sc.exe start AntivirusGuiService | Out-Null

Write-Host "Antivirus GUI installed to $InstallRoot"

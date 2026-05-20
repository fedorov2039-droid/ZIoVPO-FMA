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

$serviceExe = Join-Path $InstallRoot "bin\AntivirusService.exe"

if (Get-Service -Name "AntivirusGuiService" -ErrorAction SilentlyContinue) {
    sc.exe stop AntivirusGuiService | Out-Null
    Start-Sleep -Seconds 2
    if (Test-Path -LiteralPath $serviceExe) {
        & $serviceExe --uninstall
    } else {
        sc.exe delete AntivirusGuiService | Out-Null
    }
}

if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}

Write-Host "Antivirus GUI uninstalled"

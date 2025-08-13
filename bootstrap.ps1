param()
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Invoke-Elevated {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo 'powershell';
        $psi.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`"";
        $psi.Verb = 'RunAs';
        [Diagnostics.Process]::Start($psi) | Out-Null
        exit
    }
}
Invoke-Elevated
try {
    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        winget install --id Microsoft.Powershell --silent --accept-source-agreements --accept-package-agreements
    }
} catch {}
$ps = (Get-Command pwsh -ErrorAction SilentlyContinue)
if ($ps) {
    & $ps.Source -ExecutionPolicy Bypass -File (Join-Path $PWD 'UComplex.ps1')
} else {
    powershell -ExecutionPolicy Bypass -File (Join-Path $PWD 'UComplex.ps1')
}

param()
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Invoke-Elevated {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo 'powershell'
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $psi.Verb = 'RunAs'
        [Diagnostics.Process]::Start($psi) | Out-Null
        exit
    }
}
Invoke-Elevated
$pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
try {
    if (-not (Test-Path $pwsh)) {
        winget install --id Microsoft.Powershell --silent --accept-source-agreements --accept-package-agreements
    }
} catch {}
$dst = Join-Path $env:TEMP 'UComplex.ps1'
Invoke-WebRequest 'https://raw.githubusercontent.com/karaskarol/UComplex/h6xjo9-codex/add-brand-check-for-computer-manufacturers/UComplex.ps1' -OutFile $dst -UseBasicParsing
if (Test-Path $pwsh) {
    & $pwsh -NoProfile -ExecutionPolicy Bypass -File $dst
} else {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dst
}

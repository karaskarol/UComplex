param()
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Invoke-Elevated {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
 bm6yhu-codex/add-brand-check-for-computer-manufacturers
        $psi = New-Object System.Diagnostics.ProcessStartInfo 'powershell'
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $psi.Verb = 'RunAs'
=======
        $psi = New-Object System.Diagnostics.ProcessStartInfo 'powershell';
        $psi.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`"";
        $psi.Verb = 'RunAs';
 main
        [Diagnostics.Process]::Start($psi) | Out-Null
        exit
    }
}
Invoke-Elevated
bm6yhu-codex/add-brand-check-for-computer-manufacturers
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
=======
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
 main
}

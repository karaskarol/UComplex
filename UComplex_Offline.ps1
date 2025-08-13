param()
 bm6yhu-codex/add-brand-check-for-computer-manufacturers
$main = Join-Path $PSScriptRoot 'UComplex.ps1'
$pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
if (Test-Path $pwsh) {
    & $pwsh -NoProfile -ExecutionPolicy Bypass -File $main -Mode Offline @PSBoundParameters
} else {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $main -Mode Offline @PSBoundParameters
}
=======
$script = Join-Path $PSScriptRoot 'UComplex.ps1'
& $script -Mode Offline @PSBoundParameters
main

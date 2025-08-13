param(
    [ValidateSet('Detect','Online','Offline')]
    [string]$Mode = 'Detect',
    [switch]$NoWU,
    [switch]$NoDrivers,
    [switch]$NoApps
)
$ErrorActionPreference = 'Stop'
$LogDir = 'C:\ProgramData\UComplex\logs'
$TextLog = Join-Path $LogDir 'ucomplex.log'
$JsonLog = Join-Path $LogDir 'ucomplex.json'
function Initialize-Logging {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    foreach ($file in @($TextLog,$JsonLog)) {
        if (Test-Path $file -and (Get-Item $file).Length -gt 50MB) { Remove-Item $file -Force }
        if (-not (Test-Path $file)) { New-Item -ItemType File -Path $file | Out-Null }
    }
}
function Write-Log {
    param([string]$Message,[string]$Level='INFO')
    $line = "$(Get-Date -Format o) [$Level] $Message"
    Add-Content -Path $TextLog -Value $line
    Add-JsonEvent -Message $Message -Level $Level
}
function Add-JsonEvent {
    param([string]$Message,[string]$Level)
    $entry = @{timestamp=(Get-Date).ToString('o');level=$Level;message=$Message}
    $json = ($entry | ConvertTo-Json -Compress)
    Add-Content -Path $JsonLog -Value $json
}
function Try-Step {
    param([string]$Name,[scriptblock]$Script)
    Write-Log "Start: $Name"
    try {& $Script; Write-Log "Success: $Name"}
    catch {Write-Log "Error in $Name: $_" 'ERR'}
}
function Detect-Environment {
    $cs = Get-CimInstance Win32_ComputerSystem
    $domain = [bool]$cs.PartOfDomain
    $manufacturer = $cs.Manufacturer.Trim()
    $model = $cs.Model.Trim()
    $runMode = switch ($Mode) {
        'Detect' { if (Test-Path (Join-Path $PSScriptRoot 'bin')) { 'Offline' } else { 'Online' } }
        default { $Mode }
    }
    return [pscustomobject]@{PartOfDomain=$domain;Manufacturer=$manufacturer;Model=$model;Mode=$runMode}
}
function Update-OS {
    if ($NoWU) { Write-Log 'Windows Update skipped'; return }
    Try-Step 'Windows Update' {
        Import-Module PSWindowsUpdate
        Add-WUServiceManager -MicrosoftUpdate
        Install-WindowsUpdate -AcceptAll -Install -IgnoreReboot
    }
}
function Update-Apps {
    if ($NoApps) { Write-Log 'App updates skipped'; return }
    Try-Step 'winget upgrade' {
        winget upgrade --all --silent --accept-source-agreements --accept-package-agreements
    }
    Try-Step 'choco upgrade' {
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            choco upgrade all -y --ignore-checksums
        }
    }
}
function Invoke-VendorTool {
    param([string]$Tool,[string]$Args)
    for ($i=0;$i -lt 2;$i++) {
        Try-Step "$Tool run $($i+1)" {
            & $Tool $Args
        }
    }
}
function Update-Drivers {
    if ($NoDrivers) { Write-Log 'Driver updates skipped'; return }
    $env = Detect-Environment
    switch -regex ($env.Manufacturer) {
        'HP' { Invoke-VendorTool 'HPIA.exe' '/Auto /Silent /NoReboot' }
        'Dell' { Invoke-VendorTool 'dcu-cli.exe' '/scanInstall /silent' }
        'Lenovo' { Invoke-VendorTool 'LenovoSystemUpdate.exe' '/CM' }
        'MSI' { Write-Log 'MSI detected; using Windows Update for drivers'; Update-OS }
        'Gigabyte' { Write-Log 'Gigabyte detected; using Windows Update for drivers'; Update-OS }
        default { Write-Log 'Unknown vendor; using Windows Update for drivers'; Update-OS }
    }
}
function Sync-Policy {
    $share = '\\Server\CompanyPolicies'
    if (-not (Detect-Environment).PartOfDomain) { return }
    if (Test-Path $share) {
        Try-Step 'Sync Policy' { robocopy $share 'C:\CompanyPolicies' /MIR /R:1 /W:1 }
    } else { Write-Log 'Policy share unreachable, skipping' }
}
function Create-ScheduledTask {
    $taskName = 'UComplexUpdate'
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { return }
    $action = New-ScheduledTaskAction -Execute 'pwsh' -Argument "-ExecutionPolicy Bypass -File `"$PSScriptRoot\UComplex.ps1`" -Mode Detect"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 12)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
    Write-Log 'Scheduled Task created'
}
Initialize-Logging
$envInfo = Detect-Environment
Write-Log "Mode: $($envInfo.Mode); Domain: $($envInfo.PartOfDomain); Vendor: $($envInfo.Manufacturer) $($envInfo.Model)"
if ($envInfo.Mode -eq 'Online') {
    Update-OS
    Update-Drivers
    Update-Apps
} else {
    Write-Log 'Offline mode: expecting local packages'
    Update-OS
    Update-Drivers
    Update-Apps
}
Sync-Policy
Create-ScheduledTask
Write-Log 'UComplex run complete'

bm6yhu-codex/add-brand-check-for-computer-manufacturers
=======
 kgjdbc-codex/add-brand-check-for-computer-manufacturers
 main
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
bm6yhu-codex/add-brand-check-for-computer-manufacturers
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
    catch { Write-Log "Error in $($Name): $($_.Exception.Message)" 'ERR' }
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
    $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
    $exe = (Test-Path $pwsh) ? $pwsh : 'powershell.exe'
    $action = New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\UComplex.ps1`" -Mode Detect"
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
=======
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
=======
<#
    UComplex.ps1
    Skrypt PowerShell 7 automatyzujący przygotowanie "zaniedbanego" komputera
    z Windows 10/11 x64 do podłączenia do firmowej sieci.

    Funkcje:
      DetectDomainParams  – wykrywa parametry domeny (suffix DNS, kontrolery, OU)
      DomainJoin          – dołącza komputer do domeny AD z retry policy
      UpdateOS            – aktualizacja systemu (Windows Update / winget)
      UpdateDrivers       – aktualizacja sterowników (vendor tools + PnPUtil)
      UpdateApps          – aktualizacja aplikacji kluczowych przez winget
      SyncPolicy          – synchronizacja plików polityk z serwera firmowego
      VerifyCompliance    – weryfikacja zgodności (zapora, UAC)
      RemediateCompliance – naprawa wykrytych niezgodności
      CreateScheduledTask – zadanie cykliczne uruchamiające powyższe funkcje

    Wymagania: PowerShell 7, .NET 5+, uprawnienia administratora, łączność sieciowa.
#>

Set-StrictMode -Version Latest

#region Logging
$LogDir = 'C:\ProgramData\UComplex\logs'
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $time    = Get-Date
    $line    = "{0:s} {1}" -f $time, $Message
    $textLog = Join-Path $LogDir 'update.log'
    $jsonLog = Join-Path $LogDir 'update.json'

    Add-Content -Path $textLog -Value $line
    ($line | ConvertTo-Json -Compress) | Add-Content -Path $jsonLog

    foreach ($p in @($textLog, $jsonLog)) {
        if ((Test-Path $p) -and ((Get-Item $p).Length -gt 50MB)) {
            Rename-Item $p "$p.old" -Force
        }
    }

    if (-not [System.Diagnostics.EventLog]::SourceExists('UComplex')) {
        New-EventLog -LogName Application -Source 'UComplex'
    }
    Write-EventLog -LogName Application -Source 'UComplex' -EventId 1000 -EntryType Information -Message $Message
}
#endregion Logging

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error 'Uruchom skrypt jako Administrator.'
    exit 1
}

#region DetectDomainParams
function DetectDomainParams {
    Write-Log '=== DetectDomainParams START ==='
    $params = [ordered]@{ Domain=$null; OU=$null; DomainControllers=@() }
    try {
        $suffix = (Get-DnsClient | Where-Object { $_.ConnectionSpecificSuffix }).ConnectionSpecificSuffix | Select-Object -First 1
        if ($suffix) {
            $records = Resolve-DnsName -Type SRV -Name "_ldap._tcp.dc._msdcs.$suffix" -ErrorAction Stop
            $params.DomainControllers = $records | Select-Object -ExpandProperty NameTarget -Unique
            if ($params.DomainControllers) {
                try {
                    $root = Get-ADRootDSE -Server $params.DomainControllers[0] -ErrorAction Stop
                    $params.Domain = $root.defaultNamingContext
                    $params.OU     = $root.defaultNamingContext
                } catch { Write-Log "[Domain] Brak AD module: $($_.Exception.Message)" }
            }
        }
    } catch { Write-Log "[Domain][ERROR] $($_.Exception.Message)" }

    if (-not $params.Domain) {
        $params.Domain = 'corp.example.com'
        $params.OU     = 'OU=Clients,DC=corp,DC=example,DC=com'
    }
    Write-Log "[Domain] Domain=$($params.Domain); OU=$($params.OU)"
    Write-Log '=== DetectDomainParams END ==='
    return [pscustomobject]$params
}
#endregion DetectDomainParams

#region DomainJoin
function DomainJoin {
    param([pscustomobject]$Params)
    Write-Log '=== DomainJoin START ==='
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain) {
        Write-Log "[Domain] Komputer już w domenie $($cs.Domain)"
        Write-Log '=== DomainJoin END ==='
        return
    }

    $cred = Get-Credential -Message 'Podaj poświadczenia domenowe'
    for ($i=1; $i -le 3; $i++) {
        try {
            Add-Computer -DomainName $Params.Domain -OUPath $Params.OU -Credential $cred -ErrorAction Stop
            Write-Log '[Domain] Dołączono do domeny.'
            $joined = $true
            break
        } catch {
            Write-Log "[Domain][ERROR] Próba ${i}: $($_.Exception.Message)"
            Start-Sleep -Seconds (300 + (300 * ($i-1)))
        }
    }
    if (-not $joined) { Write-Log '[Domain][ERROR] Nie udało się dołączyć do domeny.' }
    Write-Log '=== DomainJoin END ==='
}
#endregion DomainJoin

#region UpdateOS
function UpdateOS {
    Write-Log '=== UpdateOS START ==='
    for ($i=1; $i -le 2; $i++) {
        try {
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
            }
            Import-Module PSWindowsUpdate -ErrorAction Stop
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
            winget upgrade --all --accept-source-agreements --silent
            $ok = $true
            break
        } catch {
            Write-Log "[UpdateOS][ERROR] Próba ${i}: $($_.Exception.Message)"
            Start-Sleep -Seconds 30
        }
    }
    if (-not $ok) { Write-Log '[UpdateOS] Aktualizacja systemu nie powiodła się.' }
    Write-Log '=== UpdateOS END ==='
}
#endregion UpdateOS

#region UpdateDrivers
function UpdateDrivers {
    Write-Log '=== UpdateDrivers START ==='
    try {
        $manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
        Write-Log "[Driver] Producent: $manufacturer"
        switch -Regex ($manufacturer) {
            'Dell' {
                if (-not (Get-Command 'dcu-cli.exe' -ErrorAction SilentlyContinue)) {
                    winget install -e --id Dell.CommandUpdate -h > $null 2>&1
                }
                for ($i=1; $i -le 2; $i++) {
                    if (Get-Command 'dcu-cli.exe' -ErrorAction SilentlyContinue) {
                        Start-Process 'dcu-cli.exe' -ArgumentList '/silent /update' -Wait
                    }
                }
            }
            'HP|Hewlett-Packard' {
                if (-not (Get-Command 'HPIA.exe' -ErrorAction SilentlyContinue)) {
                    winget install -e --id HP.ImageAssistant -h > $null 2>&1
                }
                for ($i=1; $i -le 2; $i++) {
                    if (Get-Command 'HPIA.exe' -ErrorAction SilentlyContinue) {
                        Start-Process 'HPIA.exe' -ArgumentList '/Silent /Update' -Wait
                    }
                }
            }
            'Lenovo' {
                if (-not (Get-Command 'tvsu.exe' -ErrorAction SilentlyContinue)) {
                    winget install -e --id Lenovo.SystemUpdate -h > $null 2>&1
                }
                for ($i=1; $i -le 2; $i++) {
                    if (Get-Command 'tvsu.exe' -ErrorAction SilentlyContinue) {
                        Start-Process 'tvsu.exe' -ArgumentList '/CM -search A -action INSTALL -silent' -Wait
                    }
                }
            }
            'MSI' {
                if (-not (Get-Command 'MSI.exe' -ErrorAction SilentlyContinue)) {
                    winget install -e --id Micro-StarInternational.LiveUpdate -h > $null 2>&1
                }
                for ($i=1; $i -le 2; $i++) {
                    if (Get-Command 'MSI.exe' -ErrorAction SilentlyContinue) {
                        Start-Process 'MSI.exe' -ArgumentList '/silent /update' -Wait
                    }
                }
            }
            'Gigabyte|Gigabite' {
                if (-not (Get-Command 'gigabyte.exe' -ErrorAction SilentlyContinue)) {
                    winget install -e --id GIGABYTE.AppCenter -h > $null 2>&1
                }
                for ($i=1; $i -le 2; $i++) {
                    if (Get-Command 'gigabyte.exe' -ErrorAction SilentlyContinue) {
                        Start-Process 'gigabyte.exe' -ArgumentList '/update /silent' -Wait
                    }
                }
            }
            default { Write-Log "[Driver] Producent '$manufacturer' nieobsługiwany." }
        }
    } catch { Write-Log "[Driver][ERROR] $($_.Exception.Message)" }

    # PnPUtil fallback
    for ($i=1; $i -le 2; $i++) {
        try {
            pnputil /scan-devices
            $pnpu = $true
            break
        } catch {
            Write-Log "[Driver][PnPUtil][ERROR] Próba ${i}: $($_.Exception.Message)"
            Start-Sleep -Seconds 15
        }
    }
    if (-not $pnpu) { Write-Log '[Driver][PnPUtil] Nie udało się przeskanować urządzeń.' }
    Write-Log '=== UpdateDrivers END ==='
}
#endregion UpdateDrivers

#region UpdateApps
function UpdateApps {
    Write-Log '=== UpdateApps START ==='
    $apps = @('Microsoft.Office','Google.Chrome','7zip.7zip')
    foreach ($app in $apps) {
        for ($i=1; $i -le 2; $i++) {
            try {
                winget upgrade --id $app --silent --accept-source-agreements
                break
            } catch {
                Write-Log "[Apps][ERROR] $app próba ${i}: $($_.Exception.Message)"
                Start-Sleep -Seconds 10
            }
        }
    }
    Write-Log '=== UpdateApps END ==='
}
#endregion UpdateApps

#region SyncPolicy
function SyncPolicy {
    param(
        [string]$Source      = '\\Server\CompanyPolicies',
        [string]$Destination = 'C:\CompanyPolicies',
        [PSCredential]$Credential
    )
    Write-Log '=== SyncPolicy START ==='
    $success = $false
    try {
        $srv = ($Source -split '\\')[2]
        if (-not (Test-Connection $srv -Count 1 -Quiet)) { throw "Serwer $srv nieosiągalny" }
        if ($Credential) {
            New-PSDrive -Name 'Z' -PSProvider FileSystem -Root $Source -Credential $Credential -ErrorAction Stop | Out-Null
            $src = 'Z:\'
        } else { $src = $Source }
        if (-not (Test-Path $Destination)) { New-Item -Path $Destination -ItemType Directory -Force | Out-Null }
        robocopy $src $Destination /MIR /FFT /Z /XA:H /W:5 /R:2 | Out-Null
        if ($LASTEXITCODE -lt 8) { $success = $true }
    } catch { Write-Log "[Sync][ERROR] $($_.Exception.Message)" }
    if ($Credential) { Remove-PSDrive -Name 'Z' -Force -ErrorAction SilentlyContinue }
    if ($success) { Write-Log '[Sync] Sukces.' } else { Write-Log '[Sync] Błąd synchronizacji.' }
    Write-Log '=== SyncPolicy END ==='
    return $success
}
#endregion SyncPolicy

#region VerifyCompliance
function VerifyCompliance {
    Write-Log '=== VerifyCompliance START ==='
    $issues = @()
    try {
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            Get-NetFirewallProfile | ForEach-Object { if (-not $_.Enabled) { $issues += "FW:$($_.Name)" } }
        } else {
            $fw = (netsh firewall show state | Select-String 'Mode').ToString()
            if ($fw -match 'Disabled') { $issues += 'FW:Legacy' }
        }
        $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
        if ($uac -ne 1) { $issues += 'UAC' }
    } catch { Write-Log "[Verify][ERROR] $($_.Exception.Message)" }
    if ($issues.Count) { foreach ($i in $issues) { Write-Log "[Verify] $i" } } else { Write-Log '[Verify] OK' }
    Write-Log '=== VerifyCompliance END ==='
    return $issues
}
#endregion VerifyCompliance

#region RemediateCompliance
function RemediateCompliance {
    param([string[]]$Issues)
    Write-Log '=== RemediateCompliance START ==='
    foreach ($i in $Issues) {
        if ($i -like 'FW:*') {
            if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
                Set-NetFirewallProfile -Name * -Enabled True -ErrorAction SilentlyContinue
            } else {
                netsh firewall set opmode mode=ENABLE | Out-Null
            }
            Write-Log '[Remediate] Zapora włączona.'
        }
        if ($i -eq 'UAC') {
            Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -ErrorAction SilentlyContinue
            Write-Log '[Remediate] UAC włączone.'
        }
    }
    Write-Log '=== RemediateCompliance END ==='
}
#endregion RemediateCompliance

#region CreateScheduledTask
function CreateScheduledTask {
    Write-Log '=== CreateScheduledTask START ==='
    $action = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument "-File `"$PSCommandPath`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 12) -RepeatIndefinitely
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName 'UComplexUpdate' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Log '=== CreateScheduledTask END ==='
}
#endregion CreateScheduledTask

#region Main
try {
    $domainParams = DetectDomainParams
    DomainJoin -Params $domainParams
    UpdateOS
    UpdateDrivers
    UpdateApps
    if (SyncPolicy) {
        $issues = VerifyCompliance
        if ($issues.Count) {
            RemediateCompliance -Issues $issues
            VerifyCompliance
        }
    }
    CreateScheduledTask
    Write-Log 'UComplex zakończył działanie.'
} catch {
    Write-Log "[MAIN][ERROR] $($_.Exception.Message)"
    exit 1
}
#endregion
main

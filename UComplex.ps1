<#
Skrypt: UComplex.ps1
Opis: Uniwersalny skrypt dla Windows XP, Vista, 7, 8.1 i 10. Wykrywa system operacyjny, wykonuje dostępne aktualizacje (różne mechanizmy), synchronizuje polityki, weryfikuje i naprawia zgodność z firmowymi zasadami oraz sprawdza możliwość uaktualnienia do nowszej wersji OS.
Wymagania: PowerShell 2.0+ (XP/Vista), PowerShell 5.1+ (7/8/10), uprawnienia Administratora, opcjonalnie poświadczenia do udziałów sieciowych.
#>

#region Pomocnicze
function Write-Log {
    param(
        [string]$Message,
        [string]$LogFile = 'C:\Logs\UComplex.log'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$timestamp - $Message"
    Write-Output $entry
    Add-Content -Path $LogFile -Value $entry
}
#endregion

#region Inicjalizacja
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole] 'Administrator')) {
    Write-Error 'Uruchom skrypt UComplex jako Administrator!'
    exit 1
}
if (-not (Test-Path 'C:\Logs')) { New-Item -Path 'C:\Logs' -ItemType Directory | Out-Null }
Write-Log 'Start skryptu UComplex – wykrywanie OS i ścieżek aktualizacji.'
#endregion

#region Check-OSUpgrade
function Check-OSUpgrade {
    Write-Log '=== Check-OSUpgrade START ==='
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $version = [Version]$os.Version
        Write-Log "UComplex – Wersja OS: $($os.Caption) ($version)"
        switch ($true) {
            { $version.Major -le 5 } { Write-Log '[Upgrade] System starodawny (XP) – upgrade manualny poza tym skryptem.'; break }
            { $version.Major -eq 6 -and $version.Minor -lt 3 } { Write-Log '[Upgrade] Rozważ upgrade do Windows 8.1/10 przez Media Creation Tool.'; break }
            { $version.Major -eq 6 -and $version.Minor -ge 3 } { Write-Log '[Upgrade] Możliwy upgrade do Windows 10 przez Windows Update.'; break }
            { $version.Major -ge 10 } { Write-Log '[Upgrade] System już Windows 10 lub nowszy.'; break }
        }
    } catch {
        Write-Log "[Upgrade][ERROR] Błąd sprawdzania OS: $($_.Exception.Message)"
    }
    Write-Log '=== Check-OSUpgrade END ==='
}
#endregion

#region Update-System
function Update-System {
    Write-Log '=== Update-System START ==='
    $ver = (Get-WmiObject Win32_OperatingSystem).Version
    if ($ver -like '5.*') {
        # XP/Vista
        Write-Log '[Update] XP/Vista – wymuszanie Windows Update: wuauclt /detectnow'
        Start-Process 'wuauclt.exe' -ArgumentList '/detectnow' -NoNewWindow -ErrorAction SilentlyContinue
    } else {
        # Windows 7+
        try {
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-Log '[Update] Instalacja modułu PSWindowsUpdate...'
                Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
                Write-Log '[Update] PSWindowsUpdate zainstalowany.'
            }
            Import-Module PSWindowsUpdate -ErrorAction Stop
            $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
            if ($updates.Count -gt 0) {
                Write-Log "[Update] Znaleziono $($updates.Count) aktualizacji – instalacja..."
                Install-WindowsUpdate -AcceptAll -IgnoreReboot -AcceptLicense -AutoReboot
            } else {
                Write-Log '[Update] Brak aktualizacji.'
            }
        } catch {
            Write-Log "[Update][ERROR] PSWU: $($_.Exception.Message)"
        }
    }
    Write-Log '=== Update-System END ==='
}
#endregion

#region Sync-PolicyFiles
function Sync-PolicyFiles {
    param(
        [string]$SourcePath      = '\\Server\CompanyPolicies',
        [string]$DestinationPath = 'C:\CompanyPolicies',
        [PSCredential]$Credential = $null
    )
    Write-Log '=== Sync-PolicyFiles START ==='
    $ok = $false
    try {
        # Sprawdź osiągalność serwera
        $srv = ($SourcePath -split '\\')[2]
        if (-not (Test-Connection $srv -Count 1 -Quiet)) {
            Write-Log "[Sync] Serwer '$srv' nieosiągalny."
            return $false
        }
        # Mapowanie udziału, jeśli potrzeba
        if ($Credential) {
            New-PSDrive -Name 'Z' -PSProvider FileSystem -Root $SourcePath -Credential $Credential -ErrorAction Stop | Out-Null
            $syncSrc = 'Z:\'
        } else {
            $syncSrc = $SourcePath
        }
        # Utwórz katalog docelowy
        if (-not (Test-Path $DestinationPath)) {
            New-Item -Path $DestinationPath -ItemType Directory -ErrorAction Stop | Out-Null
        }
        # Robocopy
        robocopy.exe $syncSrc $DestinationPath /MIR /FFT /Z /XA:H /W:5 /R:2 | Out-Null
        if ($LASTEXITCODE -lt 8) {
            Write-Log '[Sync] Sukces.'
            $ok = $true
        } else {
            Write-Log "[Sync][ERROR] Robocopy zakończony kodem $LASTEXITCODE."
            $ok = $false
        }
    } catch {
        Write-Log "[Sync][ERROR] $($_.Exception.Message)"
    } finally {
        if ($Credential) { Remove-PSDrive -Name 'Z' -Force -ErrorAction SilentlyContinue }
    }
    Write-Log '=== Sync-PolicyFiles END ==='
    return $ok
}
#endregion

#region Verify-PolicyCompliance
function Verify-PolicyCompliance {
    Write-Log '=== Verify-PolicyCompliance START ==='
    $issues = @()
    try {
        # Zapora
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            Get-NetFirewallProfile | ForEach-Object {
                if (-not $_.Enabled) { $issues += "FW:$($_.Name) off" }
            }
        } else {
            # XP/Vista – brak NetFirewallProfile
            $fwState = (netsh firewall show state | Select-String 'Mode').ToString()
            if ($fwState -match 'Disabled') { $issues += 'FW:Legacy off' }
        }
        # UAC
        $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
        if ($uac -ne 1) { $issues += "UAC off($uac)" }
    } catch {
        Write-Log "[Comp][ERROR] $($_.Exception.Message)"
    }
    if ($issues.Count) {
        foreach ($i in $issues) { Write-Log "[Comp] $i" }
    } else {
        Write-Log '[Comp] OK'
    }
    Write-Log '=== Verify-PolicyCompliance END ==='
    return $issues
}
#endregion

#region Remediate-Compliance
function Remediate-Compliance {
    param([string[]]$Issues)
    Write-Log '=== Remediate-Compliance START ==='
    foreach ($i in $Issues) {
        if ($i -like 'FW:*') {
            if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
                Set-NetFirewallProfile -Name * -Enabled True -ErrorAction SilentlyContinue
                Write-Log '[Remediate] Zapora włączona (modern).'
            } else {
                netsh firewall set opmode mode=ENABLE | Out-Null
                Write-Log '[Remediate] Zapora włączona (legacy).'
            }
        }
        if ($i -like 'UAC*') {
            Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -ErrorAction SilentlyContinue
            Write-Log '[Remediate] UAC włączone.'
        }
    }
    Write-Log '=== Remediate-Compliance END ==='
}
#endregion

#region Package-ComplianceReport
function Package-ComplianceReport {
    param(
        [string]$Report  = 'C:\Logs\ComplianceReport.txt',
        [string]$Archive = 'C:\Logs\ComplianceReport.zip'
    )
    Write-Log '=== Package-ComplianceReport START ==='
    if (Test-Path $Report) {
        Compress-Archive -Path $Report -DestinationPath $Archive -Force -ErrorAction SilentlyContinue
        Write-Log "[Report] Spakowano: $Archive"
    } else {
        Write-Log "[Report][WARN] Brak raportu do pakowania."
    }
    Write-Log '=== Package-ComplianceReport END ==='
}
#endregion

#region Główna Logika
try {
    Check-OSUpgrade
    Update-System

    $syncOk = Sync-PolicyFiles
    if (-not $syncOk) {
        Write-Log '[Main] Błąd synchronizacji polityk – przerywam działanie.'
        exit 1
    }

    $issues = Verify-PolicyCompliance
    if ($issues.Count) {
        Remediate-Compliance -Issues $issues
        Verify-PolicyCompliance
    }

    # Generowanie raportu
    $issues | Out-File 'C:\Logs\ComplianceReport.txt' -Encoding utf8
    Package-ComplianceReport

    Write-Log 'Koniec działania skryptu UComplex.'
} catch {
    Write-Log "[Main][ERROR] $($_.Exception.Message)"
    exit 1
}
#endregion

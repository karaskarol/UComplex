<#
  Win11_Update_Orchestrator_final.ps1 — PowerShell 5.1
  Zmiany vs poprzednie:
   • Restart TYLKO gdy w tym cyklu coś zainstalowano ORAZ jest wymagany/pending restart.
   • Odliczanie do restartu (domyślnie 60 s) z paskiem postępu.
   • Odporne na uruchomienie „z wklejki” (bez ścieżki pliku) — AutoResume wtedy wyłączone.
   • PS 5.1 kompatybilny (bez operatora '??').
#>

[CmdletBinding()]
param(
  [switch]$Continue,
  [switch]$NoReboot
)

# ----------------------------- USTAWIENIA -----------------------------------
$Config = [ordered]@{
  UseMicrosoftUpdate        = $true   # Rejestruj Microsoft Update (Office/.NET itp.)
  IncludeDrivers            = $true   # Aktualizacje sterowników
  UpdateWinget              = $true   # winget upgrade --all
  UpdateDefender            = $true   # Update-MpSignature / MpCmdRun
  CleanupComponents         = $true   # DISM StartComponentCleanup
  AutoReboot                = $true   # Automatyczny restart, jeśli wymagany
  AutoResume                = $true   # Wznowienie po restarcie (Harmonogram jako SYSTEM)
  RestartCountdownSeconds   = 60      # Odliczanie przed restartem
  MaxCycles                 = 3
  TaskName                  = 'Win11-Update-Resume'
  TaskDelay                 = 'PT45S'
  StableHome                = 'C:\ProgramData\Win11-Update'
}

# ---------------------------- POMOCNICZE ------------------------------------
function Write-Info($msg){ Write-Host "[INFO] $msg" }
function Write-Warn($msg){ Write-Warning $msg }

function Test-Admin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
  if (-not (Test-Admin)) {
    Write-Warn "Brak uprawnień Administratora – podnoszę uprawnienia..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$($MyInvocation.MyCommand.Path)`"")
    if ($Continue) { $args += '-Continue' }
    if ($NoReboot) { $args += '-NoReboot' }
    $psi.Arguments = $args -join ' '
    $psi.Verb = 'runas'
    [Diagnostics.Process]::Start($psi) | Out-Null
    exit
  }
}

function Start-Logging {
  $global:LogRoot = Join-Path $env:SystemRoot 'Logs\Win11-Update'
  New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
  $global:LogTime = Get-Date -Format 'yyyyMMdd_HHmmss'
  $global:LogFile = Join-Path $LogRoot "Run_$LogTime.log"
  try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop } catch {}
  Write-Info "Log: $LogFile"
}

function Stop-Logging { try { Stop-Transcript | Out-Null } catch {} }

function Ensure-StableHome {
  if (-not $Config.AutoResume) { return }
  # Ustal ścieżkę pliku skryptu. Gdy uruchomiono z wklejki – będzie pusto.
  $scriptPath = $PSCommandPath
  if ([string]::IsNullOrEmpty($scriptPath)) { $scriptPath = $MyInvocation.MyCommand.Path }
  if ([string]::IsNullOrEmpty($scriptPath) -or -not (Test-Path $scriptPath)) {
    Write-Info "Uruchomienie bez pliku – AutoResume wyłączone."
    $Config.AutoResume = $false
    return
  }
  $targetDir = $Config.StableHome
  $target    = Join-Path $targetDir (Split-Path $scriptPath -Leaf)
  if (-not (Test-Path $targetDir)) { New-Item -Path $targetDir -ItemType Directory -Force | Out-Null }
  if ($scriptPath -ne $target) {
    Write-Info "Kopiuję skrypt do: $target"
    Copy-Item -LiteralPath $scriptPath -Destination $target -Force
    Write-Info "Ponowne uruchomienie z lokalizacji docelowej..."
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$target`"")
    if ($Continue) { $args += '-Continue' }
    if ($NoReboot) { $args += '-NoReboot' }
    Start-Process powershell -Verb RunAs -ArgumentList $args
    exit
  }
}

function Enable-MicrosoftUpdate {
  if (-not $Config.UseMicrosoftUpdate) { return }
  try {
    Write-Info 'Rejestracja usługi Microsoft Update...'
    $sm = New-Object -ComObject Microsoft.Update.ServiceManager
    $null = $sm.AddService2('7971f918-a847-4430-9279-4a52d1efe18d',7,'')
    Write-Info 'Microsoft Update: OK'
  } catch { Write-Warn "Nie udało się włączyć Microsoft Update: $($_.Exception.Message)" }
}

function New-UpdateSearcher {
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'Win11_Update_Orchestrator'
  return $session.CreateUpdateSearcher()
}

function Install-UpdatesByCriteria {
  param(
    [Parameter(Mandatory)] [string]$Criteria,
    [string]$Label
  )
  if ([string]::IsNullOrEmpty($Label)) { $Label = $Criteria }
  Write-Info "Wyszukiwanie: $Label"
  $searcher = New-UpdateSearcher
  $result = $searcher.Search($Criteria)
  if ($result.Updates.Count -le 0) {
    Write-Info "Brak aktualizacji dla: $Label"
    return @{ Installed=$false; RebootRequired=$false; Count=0 }
  }
  $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
  for ($i=0; $i -lt $result.Updates.Count; $i++) {
    $upd = $result.Updates.Item($i)
    try { if (-not $upd.EulaAccepted) { $upd.AcceptEula() } } catch {}
    $null = $updatesToInstall.Add($upd)
    Write-Info ("  + {0}" -f $upd.Title)
  }
  if ($updatesToInstall.Count -eq 0) { return @{ Installed=$false; RebootRequired=$false; Count=0 } }
  Write-Info ("Instalacja {0} aktualizacji ({1})..." -f $updatesToInstall.Count, $Label)
  $session   = New-Object -ComObject Microsoft.Update.Session
  $installer = $session.CreateUpdateInstaller()
  $installer.Updates = $updatesToInstall
  $instResult = $installer.Install()
  $reboot = $false
  try { $reboot = [bool]$instResult.RebootRequired } catch {}
  Write-Info ("Wynik: HResult={0}; Restart={1}" -f $instResult.HResult, $reboot)
  return @{ Installed=$true; RebootRequired=$reboot; Count=$updatesToInstall.Count }
}

function Test-PendingReboot {
  $keys = @(
    'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  )
  foreach ($k in $keys) { if (Test-Path $k) { return $true } }
  $pfro = Get-ItemProperty -Path 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
  if ($pfro) { return $true }
  return $false
}

function Ensure-ResumeTask {
  if (-not $Config.AutoResume) { return }
  $existing = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
  if ($existing) { return }
  Write-Info "Tworzenie zadania wznowienia: $($Config.TaskName)"
  $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -Continue"
  $trigger   = New-ScheduledTaskTrigger -AtStartup -Delay $Config.TaskDelay
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
  Register-ScheduledTask -TaskName $Config.TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Remove-ResumeTask {
  $t = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction SilentlyContinue
  if ($t) { try { Unregister-ScheduledTask -TaskName $Config.TaskName -Confirm:$false | Out-Null } catch {} }
}

function Update-WingetApps {
  if (-not $Config.UpdateWinget) { return }
  $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
  if (-not $winget) { Write-Warn 'winget.exe nie znaleziony – pomijam aktualizację aplikacji.'; return }
  Write-Info 'Aktualizacja źródeł winget...'
  & $winget source update | Out-Host
  Write-Info 'Aktualizacja aplikacji przez winget (może potrwać)...'
  & $winget upgrade --all --silent --accept-package-agreements --accept-source-agreements --include-unknown | Out-Host
}

function Update-Defender {
  if (-not $Config.UpdateDefender) { return }
  try {
    if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
      Write-Info 'Microsoft Defender – aktualizacja sygnatur...'
      Update-MpSignature -AsJob | Wait-Job | Out-Null
    } else {
      $alt = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
      if (Test-Path $alt) { Write-Info 'Microsoft Defender – MpCmdRun...'; & $alt -SignatureUpdate | Out-Host }
    }
  } catch { Write-Warn "Defender update błąd: $($_.Exception.Message)" }
}

function Cleanup-Components {
  if (-not $Config.CleanupComponents) { return }
  Write-Info 'DISM StartComponentCleanup...'
  Start-Process -FilePath dism.exe -ArgumentList '/Online','/Cleanup-Image','/StartComponentCleanup','/Quiet' -Wait -NoNewWindow
}

# ----------------------------- PRZEBIEG -------------------------------------
Ensure-Admin
Ensure-StableHome
Start-Logging
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Info "Windows: $([Environment]::OSVersion.VersionString)"
Write-Info "Start: $(Get-Date)"

Enable-MicrosoftUpdate

# Główna pętla
$cycle = 0
$global:WasRebootRequired = $false

while ($cycle -lt [int]$Config.MaxCycles) {
  $cycle++
  Write-Host "`n==== CYKL $cycle / $($Config.MaxCycles) ====" -ForegroundColor Cyan

  $rSoft = Install-UpdatesByCriteria -Criteria "IsInstalled=0 and Type='Software'" -Label 'Software'
  $global:WasRebootRequired = $global:WasRebootRequired -or [bool]$rSoft.RebootRequired

  $rDrv = $null
  if ($Config.IncludeDrivers) {
    $rDrv = Install-UpdatesByCriteria -Criteria "IsInstalled=0 and Type='Driver'" -Label 'Drivers'
    $global:WasRebootRequired = $global:WasRebootRequired -or [bool]$rDrv.RebootRequired
  }

  $installedDrv = ($null -ne $rDrv) -and [bool]$rDrv.Installed
  $anything     = [bool]$rSoft.Installed -or $installedDrv

  $pending = Test-PendingReboot
  # *** Kluczowa zmiana: restart tylko jeśli COŚ zainstalowano w tym cyklu i wymagany/pending jest restart
  $needReboot = ($anything -and ($global:WasRebootRequired -or $pending))

  if ($needReboot) {
    $sec = [int]$Config.RestartCountdownSeconds
    if ($sec -lt 5) { $sec = 5 }
    Write-Host "Restart wymagany. System zrestartuje się za $sec s..." -ForegroundColor Yellow
    if ($Config.AutoReboot -and -not $NoReboot) {
      if ($Config.AutoResume) { Ensure-ResumeTask }
      $msg = "Windows Update zakończone. Restart nastąpi za $sec s. Zapisz pracę."
      try { Stop-Logging } catch {}
      Start-Process -FilePath shutdown.exe -ArgumentList '/r','/t',$sec,'/c',$msg -WindowStyle Hidden
      for ($s = $sec; $s -gt 0; $s--) {
        $pct = [int](((($sec - $s) / [double]$sec) * 100))
        Write-Progress -Activity 'Restart systemu' -Status ("$s s do restartu") -PercentComplete $pct
        Start-Sleep -Seconds 1
      }
      return
    } else {
      Write-Warn 'AutoReboot=FALSE lub -NoReboot – restart pominięty. Zrestartuj ręcznie, aby dokończyć aktualizacje.'
      break
    }
  }

  if (-not $anything) { Write-Info 'Brak kolejnych aktualizacji. Koniec pętli.'; break }
}

# Post-steps tylko jeśli nie czeka restart
if (-not (Test-PendingReboot)) {
  Update-WingetApps
  Update-Defender
  Cleanup-Components
  Remove-ResumeTask
}

Write-Info "Koniec: $(Get-Date)"
Stop-Logging

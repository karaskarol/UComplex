 kgjdbc-codex/add-brand-check-for-computer-manufacturers
# UComplex — uniwersalny post-install i aktualizator Windows (AD i non-AD)

## Funkcje (MVP)
- Windows Update przez [PSWindowsUpdate](https://learn.microsoft.com/powershell/module/pswindowsupdate/)
- Aktualizacja aplikacji przez [winget](https://learn.microsoft.com/windows/package-manager/winget/) z fallback [Chocolatey](https://chocolatey.org/)
- Sterowniki OEM: [HP Image Assistant](https://www.hp.com/go/hpia) i [Dell Command | Update](https://www.dell.com/support/kbdoc/en-us/000177325)
- Detekcja producenta przez [Win32_ComputerSystem](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-computersystem)
- Harmonogram `UComplexUpdate` co 12h
- Logi TXT+JSON w `C:\ProgramData\UComplex\logs`

## Wymagania
- Windows 10/11 x64
- PowerShell 7 (bootstrap instaluje automatycznie)
- .NET 5+
- Uprawnienia administratora
- Połączenie z Internetem lub pełna paczka offline

## Szybki start
```powershell
iex (irm https://raw.githubusercontent.com/karaskarol/UComplex/main/bootstrap.ps1)
```

## Tryb offline
Struktura paczki ZIP:
```
UComplex\
  UComplex.ps1
  UComplex_Offline.ps1
  bin\
  drivers\
  packages\
```
Uruchom `UComplex_Offline.ps1` z lokalnego katalogu.

## Przykłady
```powershell
# tryb automatyczny z detekcją
./UComplex.ps1
# wymuś tryb online bez sterowników
./UComplex.ps1 -Mode Online -NoDrivers
```

## Diagnostyka
- Logi: `C:\ProgramData\UComplex\logs`
- Włącz szczegółowe komunikaty: `-Verbose` lub `$VerbosePreference='Continue'`
- Zatrzymuj na błędach: `-ErrorAction Stop`

## Definition of Done (DoD)
- Jedna komenda uruchamia pełny przebieg aktualizacji
- Działa w domenie i poza nią
- Tryb offline równoważny online
- Brak twardych zależności od zasobów AD
=======
# UComplex

PowerShell 7 script that automates initial configuration of a neglected Windows 10/11 x64 machine before it is connected to the corporate network.

## Requirements
- Windows 10/11 x64
- PowerShell 7
- .NET 5+
- Administrative privileges
- Network connectivity to domain controllers and `\\Server\CompanyPolicies`

## Installation
1. Allow running local scripts:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
   ```
2. Copy `UComplex.ps1` to a local folder.
3. (Optional) Store service account credentials in Windows Credential Manager so domain join and file sync can run unattended.

## Usage
Run once manually:
```powershell
pwsh.exe -File .\UComplex.ps1
```

### Scheduled Task
The script creates a task named **UComplexUpdate** that runs every 12 hours with highest privileges and executes:
`UpdateOS`, `UpdateDrivers`, `UpdateApps`, `SyncPolicy`, and `Verify/Remediate`.

To remove the task:
```powershell
Unregister-ScheduledTask -TaskName UComplexUpdate -Confirm:$false
```

## Logs
Logs are written to `C:\ProgramData\UComplex\logs\update.log` (text) and `update.json` (JSON). Files larger than 50 MB are rotated. Each entry is also sent to the Application event log under source **UComplex**.

## Diagnostics
If something fails, review `update.log` and the Application event log for entries from **UComplex**.

main

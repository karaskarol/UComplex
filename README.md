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

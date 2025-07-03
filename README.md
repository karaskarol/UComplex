# UComplex.ps1

Uniwersalny skrypt PowerShell do aktualizacji systemu, synchronizacji polityk, weryfikacji i naprawy zgodności z firmowymi zasadami oraz sprawdzania możliwości uaktualnienia systemu operacyjnego.

---

## Spis treści

1. [Opis](#opis)  
2. [Wymagania](#wymagania)  
3. [Obsługiwane systemy](#obsługiwane-systemy)  
4. [Instalacja](#instalacja)  
5. [Użycie](#użycie)  
6. [Parametry](#parametry)  
7. [Funkcje](#funkcje)  
8. [Przykłady](#przykłady)  
9. [Logowanie](#logowanie)  
10. [Raport i archiwizacja](#raport-i-archiwizacja)  
11. [FAQ / Rozwiązywanie problemów](#faq--rozwiązywanie-problemów)  
12. [Licencja](#licencja)  

---

## Opis

**UComplex.ps1** to wszechstronny skrypt PowerShell, który:

- Wykrywa wersję systemu i sugeruje możliwy scenariusz upgrade’u (XP/Vista → 7/8/10).  
- Uruchamia aktualizację Windows Update (XP/Vista przez `wuauclt`; 7+ przez moduł PSWindowsUpdate).  
- Synchronizuje firmowe polityki z centralnego udziału sieciowego (robocopy + opcjonalne poświadczenia).  
- Weryfikuje stan zapory i UAC, zwracając listę niezgodności.  
- Automatycznie naprawia wykryte niezgodności.  
- Generuje i pakuje raport zgodności do pliku ZIP.  

Skrypt działa pod PowerShell 2.0+ (XP/Vista) oraz 5.1+ (Win7/8/10).

---

## Wymagania

- Uruchomienie jako Administrator.  
- PowerShell 2.0 lub nowszy (zalecane 5.1+).  
- Dla Windows 7+ dostęp do galerii PowerShell (PSGallery) w celu instalacji PSWindowsUpdate.  
- (Opcjonalnie) Poświadczenia (`Get-Credential`) z prawem do odczytu udziału sieciowego.  

---

## Obsługiwane systemy

| System operacyjny       | PowerShell | Mechanizm aktualizacji        |
|-------------------------|------------|-------------------------------|
| Windows XP / Vista      | 2.0+       | `wuauclt.exe /detectnow`      |
| Windows 7 / 8 / 8.1     | 3.0+       | PSWindowsUpdate               |
| Windows 10              | 5.1+       | PSWindowsUpdate               |

---

## Instalacja

1. Skopiuj plik `UComplex.ps1` do katalogu, z którego planujesz uruchamiać skrypty.  
2. Upewnij się, że ExecutionPolicy pozwala na uruchamianie skryptów:  
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

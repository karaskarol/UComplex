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


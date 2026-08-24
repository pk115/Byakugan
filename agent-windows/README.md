# Byakugan Windows Agent

The native Windows agent collects host CPU, memory, fixed disks, uptime, Windows Update state, reboot state, installed-software count, and Docker container state. It uses outbound HTTPS only and polls Byakugan for authorized Trivy jobs.

## Requirements

- Windows Server 2016+ or Windows 10/11
- Windows PowerShell 5.1+
- Administrator access for installation
- Outbound access to the Byakugan URL
- Optional: `trivy.exe` in the system PATH for vulnerability scans

## Install

Create an enrollment in **Servers & Agents** and copy the one-time token. From an elevated PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
cd .\agent-windows
.\install.ps1 -Url "https://monitor.example.com" -Token "PASTE_ONE_TIME_TOKEN"
```

The installer creates the **Byakugan Agent** startup task running as `SYSTEM`. The configuration is ACL-protected at `%ProgramData%\Byakugan\agent.json`.

Verify it:

```powershell
Get-ScheduledTask -TaskName "Byakugan Agent"
Get-ScheduledTaskInfo -TaskName "Byakugan Agent"
```

## Vulnerability scans

Install Trivy on the Windows host and make `trivy.exe` available in the system PATH. Then create or queue a filesystem/image scan from the Vulnerability Management page. Only normalized finding metadata is uploaded; file contents and secret values are not sent.

## Uninstall

```powershell
.\uninstall.ps1
```

Revoking the enrollment in Byakugan invalidates the token immediately. Historical evidence remains available for audit retention.

# Byakugan Windows Agent

The native Windows agent collects host CPU, memory, fixed disks, uptime, Windows Update state, reboot state, installed-software count, and Docker container state. It uses outbound HTTPS only and polls Byakugan for authorized Trivy jobs.

## Requirements

- Windows Server 2016+ or Windows 10/11
- Windows PowerShell 5.1+
- Administrator access for installation
- Outbound access to the Byakugan URL
- Internet access during installation so the installer can download and checksum-verify the pinned Trivy scanner

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

Upgrade or repair an existing installation without entering its token again:

```powershell
$installer = Join-Path $env:TEMP "byakugan-install.ps1"
Invoke-WebRequest "https://raw.githubusercontent.com/pk115/Byakugan/main/agent-windows/install.ps1" -OutFile $installer
& $installer
```

## Vulnerability scans

The installer downloads a pinned Trivy release, verifies its SHA-256 checksum, and keeps it in the protected Byakugan directory. Create or queue a filesystem/image scan from the Vulnerability Management page. Only normalized finding metadata is uploaded; file contents and secret values are not sent.

## Log shipping

The agent also ships security-relevant Windows events to Byakugan (`POST /api/agent/logs`) using the same event names as the Linux agent and the sample ISO log set:

| Source | Event IDs | Byakugan event |
|---|---|---|
| Security | 4624 (interactive / RDP / unlock logons only) | `LOGIN_SUCCESS` |
| Security | 4625 | `LOGIN_FAILED` (with `reason`, e.g. `bad_password`) |
| Security | 4672 (non-system accounts) | `PRIVILEGE_ASSIGNED` |
| Security | 4720 / 4732 | `USER_CREATED` / `GROUP_MEMBER_ADDED` |
| System | 7036 running / stopped | `SERVICE_START` / `SERVICE_STOP` |
| System | 7045 | `SERVICE_INSTALLED` |
| Microsoft-Windows-Backup | 4 / any Error or Critical | `BACKUP_COMPLETE` / `BACKUP_FAILED` |

The last processed record id per log is kept in `%ProgramData%\Byakugan\log-state.json`; it is advanced only after the server accepted the batch, and duplicates are ignored server-side, so retries are safe. The service must run as `SYSTEM`/administrator to read the Security log.

Optional settings in `%ProgramData%\Byakugan\agent.json` (preserved when the installer repairs the agent):

```json
{ "logs": true, "logIntervalSeconds": 60, "logBackfillHours": 1 }
```

- `logs`: set `false` to disable log shipping (default `true`).
- `logIntervalSeconds`: how often new events are sent (minimum 10, default 60).
- `logBackfillHours`: on the very first run, how far back to read (default 1).

Try it without sending anything (elevated PowerShell), and run the mapping tests:

```powershell
.\byakugan-agent.ps1 -LogDryRun        # prints the normalized events as JSON
.\Test-LogMapping.ps1                  # fabricated events, no server needed
```

Note: service state text in event 7036 is localized; only English `running`/`stopped` are mapped.

## Uninstall

```powershell
.\uninstall.ps1
```

Revoking the enrollment in Byakugan invalidates the token immediately. Historical evidence remains available for audit retention.

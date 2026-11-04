# Run: powershell -File agent-windows\Test-LogMapping.ps1   (no admin, no server; feeds fabricated event data to the mapper)
$ErrorActionPreference = "Stop"
. "$PSScriptRoot\byakugan-agent.ps1" -LoadOnly -ConfigPath "$env:TEMP\byakugan-test\agent.json"
$t = [datetime]"2026-11-04T10:00:00Z"
function Map($log, $id, $data, $level = 4) { Convert-WinEventToLog -LogName $log -Id $id -Level $level -Time $t -Data $data -Computer "WIN01" }
function Check($cond, $msg) { if (!$cond) { throw "FAIL: $msg" }; Write-Host "ok  $msg" }

$e = Map "Security" 4625 @{ TargetUserName = "admin"; IpAddress = "203.0.113.9"; LogonType = "10"; SubStatus = "0xC000006A"; TargetDomainName = "X" }
Check ($e.event -eq "LOGIN_FAILED" -and $e.actor -eq "admin" -and $e.srcIp -eq "203.0.113.9" -and $e.details.reason -eq "bad_password" -and $e.severity -eq "warning" -and $e.timestamp -eq "2026-11-04T10:00:00.000Z") "4625 -> LOGIN_FAILED"
$e = Map "Security" 4624 @{ TargetUserName = "alice"; IpAddress = "10.0.0.7"; LogonType = "10" }
Check ($e.event -eq "LOGIN_SUCCESS" -and $e.result -eq "success") "4624 RDP -> LOGIN_SUCCESS"
Check ($null -eq (Map "Security" 4624 @{ TargetUserName = "alice"; LogonType = "3" })) "4624 network logon skipped"
Check ($null -eq (Map "Security" 4624 @{ TargetUserName = "WIN01$"; LogonType = "2" })) "4624 machine account skipped"
Check ($null -eq (Map "Security" 4672 @{ SubjectUserName = "SYSTEM" })) "4672 SYSTEM skipped"
Check ((Map "Security" 4672 @{ SubjectUserName = "alice" }).event -eq "PRIVILEGE_ASSIGNED") "4672 -> PRIVILEGE_ASSIGNED"
Check ((Map "Security" 4720 @{ SubjectUserName = "adm"; TargetUserName = "bob" }).details.target_user -eq "bob") "4720 -> USER_CREATED"
Check ((Map "Security" 4732 @{ SubjectUserName = "adm"; TargetUserName = "Administrators"; MemberSid = "S-1-5-21-1" }).event -eq "GROUP_MEMBER_ADDED") "4732 -> GROUP_MEMBER_ADDED"
Check ((Map "System" 7036 @{ param1 = "Spooler"; param2 = "running" }).event -eq "SERVICE_START") "7036 running -> SERVICE_START"
Check ((Map "System" 7036 @{ param1 = "Spooler"; param2 = "stopped" }).event -eq "SERVICE_STOP") "7036 stopped -> SERVICE_STOP"
Check ($null -eq (Map "System" 7036 @{ param1 = "Spooler"; param2 = "paused" })) "7036 other state skipped"
Check ((Map "System" 7045 @{ ServiceName = "evil"; ImagePath = "C:\x.exe" }).event -eq "SERVICE_INSTALLED") "7045 -> SERVICE_INSTALLED"
Check ((Map "Microsoft-Windows-Backup" 4 @{}).event -eq "BACKUP_COMPLETE") "backup 4 -> BACKUP_COMPLETE"
Check ((Map "Microsoft-Windows-Backup" 5 @{} 2).event -eq "BACKUP_FAILED") "backup error -> BACKUP_FAILED"
# the server schema: event name regex and ISO timestamp
Check ((Map "Security" 4625 @{ TargetUserName = "a"; LogonType = "3" }).event -match '^[A-Za-z0-9_.:-]{1,80}$') "event name valid for logEventSchema"
Write-Host "Windows log mapping OK"

#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
Stop-ScheduledTask -TaskName "Byakugan Agent" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Byakugan Agent" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Byakugan Agent task removed. Evidence remains in Byakugan for audit retention." -ForegroundColor Green
Write-Host "To remove local configuration too: Remove-Item -Recurse -Force '$env:ProgramData\Byakugan'"

#requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^https?://')][string]$Url,
    [Parameter(Mandatory=$true)][ValidateLength(32,256)][string]$Token,
    [ValidateRange(60,86400)][int]$IntervalSeconds = 300
)
$ErrorActionPreference = "Stop"
$target = Join-Path $env:ProgramData "Byakugan"
New-Item -ItemType Directory -Path $target -Force | Out-Null
$agentSource = Join-Path $PSScriptRoot "byakugan-agent.ps1"
if (Test-Path -LiteralPath $agentSource) {
    Copy-Item -LiteralPath $agentSource -Destination $target -Force
} else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/pk115/Byakugan/main/agent-windows/byakugan-agent.ps1" -OutFile (Join-Path $target "byakugan-agent.ps1")
}
$trivyVersion = "0.72.0"
$trivyArchive = Join-Path $env:TEMP "trivy-$trivyVersion.zip"
$trivyChecksums = Join-Path $env:TEMP "trivy-$trivyVersion-checksums.txt"
$trivyAsset = "trivy_${trivyVersion}_windows-64bit.zip"
$trivyBase = "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion"
Write-Host "Installing Trivy $trivyVersion..."
Invoke-WebRequest -UseBasicParsing -Uri "$trivyBase/$trivyAsset" -OutFile $trivyArchive
Invoke-WebRequest -UseBasicParsing -Uri "$trivyBase/trivy_${trivyVersion}_checksums.txt" -OutFile $trivyChecksums
$expectedHash = ((Get-Content -LiteralPath $trivyChecksums | Where-Object { $_ -match "\s+$([regex]::Escape($trivyAsset))$" } | Select-Object -First 1) -split '\s+')[0]
$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $trivyArchive).Hash.ToLowerInvariant()
if (!$expectedHash -or $actualHash -ne $expectedHash.ToLowerInvariant()) { throw "Trivy download checksum verification failed" }
$bin = Join-Path $target "bin"
New-Item -ItemType Directory -Path $bin -Force | Out-Null
Expand-Archive -LiteralPath $trivyArchive -DestinationPath $bin -Force
Remove-Item -LiteralPath $trivyArchive,$trivyChecksums -Force -ErrorAction SilentlyContinue
@{ url=$Url.TrimEnd('/'); token=$Token; intervalSeconds=$IntervalSeconds; scanPollSeconds=15 } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target "agent.json") -Encoding UTF8
& icacls.exe $target /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$target\byakugan-agent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Stop-ScheduledTask -TaskName "Byakugan Agent" -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "Byakugan Agent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "Byakugan Agent"
Write-Host "Byakugan Agent installed and started. Configuration: $target" -ForegroundColor Green

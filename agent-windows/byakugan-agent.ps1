#requires -Version 5.1
param([string]$ConfigPath = "$env:ProgramData\Byakugan\agent.json")

$ErrorActionPreference = "Stop"
$script:Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$script:Endpoint = ([string]$script:Config.url).TrimEnd("/")
$script:Token = [string]$script:Config.token
$script:Interval = [Math]::Max(60, [int]$script:Config.intervalSeconds)
$script:PollInterval = [Math]::Max(5, [int]$script:Config.scanPollSeconds)

if (!$script:Endpoint -or $script:Token.Length -lt 32) { throw "A valid url and agent token are required" }

function Invoke-ByakuganApi {
    param([string]$Path, [string]$Method = "GET", $Body = $null)
    $params = @{ Uri = "$script:Endpoint$Path"; Method = $Method; Headers = @{ Authorization = "Bearer $script:Token" }; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($null -ne $Body) { $params.ContentType = "application/json"; $params.Body = ($Body | ConvertTo-Json -Depth 12 -Compress) }
    Invoke-RestMethod @params
}

function Get-DockerContainers {
    try {
        $rows = & docker ps -a --format '{{json .}}' 2>$null
        @($rows | ForEach-Object { $item = $_ | ConvertFrom-Json; $name = if ($item.Names) { $item.Names } else { $item.ID }; @{ name = [string]$name; status = [string]$item.Status; running = ([string]$item.State -eq "running") } })
    } catch { @() }
}

function Get-PatchState {
    $pending = 0
    try { $pending = @((New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0").Updates).Count } catch {}
    $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
              (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations')
    @{ pending = [int]$pending; security = [int]$pending; reboot = [bool]$reboot }
}

function Get-AgentPayload {
    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $processors = @(Get-CimInstance Win32_Processor)
    $cpu = [Math]::Min(100, [Math]::Max(0, [double](($processors | Measure-Object LoadPercentage -Average).Average)))
    $total = [int64]$computer.TotalPhysicalMemory
    $free = [int64]$os.FreePhysicalMemory * 1024
    $memory = if ($total) { [Math]::Round((($total - $free) / $total) * 100, 2) } else { 0 }
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $used = [int64]$_.Size - [int64]$_.FreeSpace
        @{ mount = [string]$_.DeviceID; totalBytes = [int64]$_.Size; usedBytes = $used; usedPercent = if ($_.Size) { [Math]::Round(($used / $_.Size) * 100, 2) } else { 0 } }
    })
    $containers = @(Get-DockerContainers)
    $patch = Get-PatchState
    $installed = @(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName).Count
    $boot = if ($os.LastBootUpTime -is [DateTime]) { $os.LastBootUpTime } else { [Management.ManagementDateTimeConverter]::ToDateTime([string]$os.LastBootUpTime) }
    @{
        agentVersion = "0.4.0-windows"; observedAt = (Get-Date).ToUniversalTime().ToString("o"); hostname = $env:COMPUTERNAME
        inventory = @{
            osName = [string]$os.Caption; osVersion = [string]$os.Version; kernel = [string]$os.BuildNumber
            architecture = [string]$os.OSArchitecture; cpuModel = [string]$processors[0].Name
            cpuCount = [int]$computer.NumberOfLogicalProcessors; totalMemoryBytes = $total
            installedPackageCount = [int]$installed; pendingUpdateCount = $patch.pending
            securityUpdateCount = $patch.security; rebootRequired = $patch.reboot
            dockerAvailable = ($containers.Count -gt 0 -or $null -ne (Get-Command docker -ErrorAction SilentlyContinue))
        }
        metrics = @{
            cpuPercent = $cpu; memoryPercent = $memory; swapPercent = $null
            load1 = $null; load5 = $null; load15 = $null
            uptimeSeconds = [int][Math]::Max(0, ((Get-Date) - $boot).TotalSeconds)
            disks = $disks; containers = $containers
        }
    }
}

function Convert-TrivyReport {
    param($Report)
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($result in @($Report.Results)) {
        foreach ($item in @($result.Vulnerabilities)) { if ($findings.Count -lt 5000) { $findings.Add(@{ id=[string]$item.VulnerabilityID; type="VULNERABILITY"; packageName=[string]$item.PkgName; installedVersion=[string]$item.InstalledVersion; fixedVersion=[string]$item.FixedVersion; severity=([string]$item.Severity).ToUpper(); title=[string]$item.Title; resourcePath=[string]$result.Target }) } }
        foreach ($item in @($result.Misconfigurations)) { if ($findings.Count -lt 5000) { $package = if ($item.Type) { $item.Type } else { $item.AVDID }; $findings.Add(@{ id=[string]$item.ID; type="MISCONFIGURATION"; packageName=[string]$package; installedVersion=""; severity=([string]$item.Severity).ToUpper(); title=[string]$item.Title; resourcePath=[string]$result.Target }) } }
        foreach ($item in @($result.Secrets)) { if ($findings.Count -lt 5000) { $findings.Add(@{ id=[string]$item.RuleID; type="SECRET"; packageName=[string]$item.Category; installedVersion=""; severity="HIGH"; title=[string]$item.Title; resourcePath=[string]$result.Target }) } }
    }
    @($findings)
}

function Invoke-ScanJob {
    try { $response = Invoke-ByakuganApi "/api/agent/scan-jobs/next" } catch { Write-Warning $_; return }
    $job = if ($response.job) { $response.job } else { $response }
    if (!$job -or !$job.id) { return }
    $started = Get-Date
    try {
        $trivy = Get-Command trivy -ErrorAction SilentlyContinue
        if (!$trivy) { $localTrivy = Join-Path $PSScriptRoot "bin\trivy.exe"; if (Test-Path -LiteralPath $localTrivy) { $trivy = $localTrivy } }
        if (!$trivy) { throw "TRIVY_NOT_INSTALLED: Re-run the latest Byakugan Windows installer" }
        Invoke-ByakuganApi "/api/agent/scan-jobs/$($job.id)/progress" "POST" @{ progress = 15 } | Out-Null
        $subcommand = switch ($job.targetType) { "FILESYSTEM" { "fs" }; "ROOTFS" { "rootfs" }; "IMAGE" { "image" }; default { throw "UNSUPPORTED_TARGET" } }
        $temp = Join-Path $env:TEMP "byakugan-trivy-$($job.id).json"
        $arguments = @($subcommand,"--quiet","--scanners",(@($job.scanners) -join ','),"--severity",(@($job.severity) -join ','),"--format","json","--output",$temp,[string]$job.target)
        & $trivy @arguments
        if ($LASTEXITCODE -ne 0) { throw "Trivy returned exit code $LASTEXITCODE" }
        $report = Get-Content -LiteralPath $temp -Raw | ConvertFrom-Json; Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        $findings = @(Convert-TrivyReport $report)
        $version = (& $trivy --version | Select-Object -First 1)
        Invoke-ByakuganApi "/api/agent/scan-jobs/$($job.id)/result" "POST" @{ scanner="Trivy"; scannerVersion=[string]$version; observedAt=(Get-Date).ToUniversalTime().ToString("o"); findings=$findings; summary=@{ durationMs=[int]((Get-Date)-$started).TotalMilliseconds; truncated=($findings.Count -ge 5000) } } | Out-Null
    } catch {
        $message = [string]$_; $code = if ($message -like "TRIVY_NOT_INSTALLED*") { "TRIVY_NOT_INSTALLED" } else { "SCAN_FAILED" }
        try { Invoke-ByakuganApi "/api/agent/scan-jobs/$($job.id)/failure" "POST" @{ code=$code; message=$message.Substring(0,[Math]::Min(1000,$message.Length)) } | Out-Null } catch {}
    }
}

$lastEvidence = [DateTime]::MinValue
while ($true) {
    try {
        if (((Get-Date) - $lastEvidence).TotalSeconds -ge $script:Interval) {
            Invoke-ByakuganApi "/api/agent/ingest" "POST" (Get-AgentPayload) | Out-Null
            $lastEvidence = Get-Date
        }
        Invoke-ScanJob
    } catch { Write-Warning "$(Get-Date -Format o) $($_.Exception.Message)" }
    Start-Sleep -Seconds $script:PollInterval
}

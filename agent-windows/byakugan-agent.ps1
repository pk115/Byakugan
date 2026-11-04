#requires -Version 5.1
param([string]$ConfigPath = "$env:ProgramData\Byakugan\agent.json", [switch]$LoadOnly, [switch]$LogDryRun)

$ErrorActionPreference = "Stop"
if (!$LoadOnly) {
    $script:Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $script:Endpoint = ([string]$script:Config.url).TrimEnd("/")
    $script:Token = [string]$script:Config.token
    $script:Interval = [Math]::Max(60, [int]$script:Config.intervalSeconds)
    $script:PollInterval = [Math]::Max(5, [int]$script:Config.scanPollSeconds)

    if (!$script:Endpoint -or $script:Token.Length -lt 32) { throw "A valid url and agent token are required" }
    $script:LogInterval = [Math]::Max(10, $(if ($script:Config.logIntervalSeconds) { [int]$script:Config.logIntervalSeconds } else { 60 }))
    $script:LogBackfillHours = if ($script:Config.logBackfillHours) { [int]$script:Config.logBackfillHours } else { 1 }
    $script:LogsEnabled = $script:Config.logs -ne $false
} else { $script:LogBackfillHours = 1 }

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
        agentVersion = "0.5.0-windows"; observedAt = (Get-Date).ToUniversalTime().ToString("o"); hostname = $env:COMPUTERNAME
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
    function Normalize-Severity([object]$Value) { $candidate = ([string]$Value).ToUpperInvariant(); if (@("UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL") -contains $candidate) { $candidate } else { "UNKNOWN" } }
    foreach ($result in @($Report.Results)) {
        foreach ($item in @($result.Vulnerabilities)) { if ($null -ne $item -and $findings.Count -lt 5000) { $id=if($item.VulnerabilityID){[string]$item.VulnerabilityID}else{"UNKNOWN"};$package=if($item.PkgName){[string]$item.PkgName}else{"unknown"};$findings.Add(@{ id=$id; type="VULNERABILITY"; packageName=$package; installedVersion=[string]$item.InstalledVersion; fixedVersion=[string]$item.FixedVersion; severity=(Normalize-Severity $item.Severity); title=[string]$item.Title; resourcePath=[string]$result.Target }) } }
        foreach ($item in @($result.Misconfigurations)) { if ($null -ne $item -and $findings.Count -lt 5000) { $id=if($item.ID){[string]$item.ID}else{"MISCONFIG"};$package=if($item.Type){[string]$item.Type}elseif($item.AVDID){[string]$item.AVDID}else{"configuration"};$findings.Add(@{ id=$id; type="MISCONFIGURATION"; packageName=$package; installedVersion=""; severity=(Normalize-Severity $item.Severity); title=[string]$item.Title; resourcePath=[string]$result.Target }) } }
        foreach ($item in @($result.Secrets)) { if ($null -ne $item -and $findings.Count -lt 5000) { $id=if($item.RuleID){[string]$item.RuleID}else{"SECRET"};$package=if($item.Category){[string]$item.Category}else{"secret"};$secretSeverity=if($item.Severity){$item.Severity}else{"HIGH"};$findings.Add(@{ id=$id; type="SECRET"; packageName=$package; installedVersion=""; severity=(Normalize-Severity $secretSeverity); title=[string]$item.Title; resourcePath=[string]$result.Target }) } }
    }
    $findings | ForEach-Object { $_ }
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
        $target = [string]$job.target
        if (($subcommand -eq "fs" -or $subcommand -eq "rootfs") -and $target -eq "/") { $target = "$env:SystemDrive\" }
        $arguments = @($subcommand,"--quiet","--scanners",(@($job.scanners) -join ','),"--severity",(@($job.severity) -join ','),"--format","json","--output",$temp,$target)
        $stdout = Join-Path $env:TEMP "byakugan-trivy-$($job.id).stdout.log"; $stderr = Join-Path $env:TEMP "byakugan-trivy-$($job.id).stderr.log"
        $argumentLine = ($arguments | ForEach-Object { '"' + ([string]$_).Replace('"','\"') + '"' }) -join ' '
        $process = Start-Process -FilePath ([string]$trivy) -ArgumentList $argumentLine -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
        while (!$process.WaitForExit(15000)) { try { Invoke-ByakuganApi "/api/agent/scan-jobs/$($job.id)/progress" "POST" @{ progress = 50 } | Out-Null } catch {} }
        $trivyOutput = ((Get-Content -LiteralPath $stderr,$stdout -Raw -ErrorAction SilentlyContinue) -join "`n").Trim()
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
        if ($process.ExitCode -ne 0) { throw "Trivy returned exit code $($process.ExitCode)$(if($trivyOutput){': '+$trivyOutput.Substring(0,[Math]::Min(700,$trivyOutput.Length))})" }
        $report = Get-Content -LiteralPath $temp -Raw | ConvertFrom-Json; Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        $findings = @(Convert-TrivyReport $report)
        $version = (& $trivy --version | Select-Object -First 1)
        Invoke-ByakuganApi "/api/agent/scan-jobs/$($job.id)/result" "POST" @{ scanner="Trivy"; scannerVersion=[string]$version; observedAt=(Get-Date).ToUniversalTime().ToString("o"); findings=$findings; summary=@{ durationMs=[int]((Get-Date)-$started).TotalMilliseconds; truncated=($findings.Count -ge 5000) } } | Out-Null
    } catch {
        $message = [string]$_; $code = if ($message -like "TRIVY_NOT_INSTALLED*") { "TRIVY_NOT_INSTALLED" } else { "SCAN_FAILED" }
        try { Invoke-ByakuganApi "/api/agent/scan-jobs/$($job.id)/failure" "POST" @{ code=$code; message=$message.Substring(0,[Math]::Min(1000,$message.Length)) } | Out-Null } catch {}
    }
}

# ---- Log collection (Security / System / Backup event logs -> POST /api/agent/logs) ----
# Event names match the Linux agent and the sample ISO log set (agent/log-mapping.mjs).
$script:LogStatePath = Join-Path (Split-Path -Parent $ConfigPath) "log-state.json"
$script:FailReasons = @{ "0xc0000064" = "user_unknown"; "0xc000006a" = "bad_password"; "0xc0000234" = "locked_out"; "0xc0000072" = "account_disabled"; "0xc0000070" = "workstation_restricted"; "0xc0000071" = "password_expired" }
$script:SystemAccount = '^(-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|.*\$)$'

function New-LogEvent {
    param([string]$Event, [datetime]$Time, [string]$Computer, [string]$Actor, [string]$SrcIp, [string]$Result, [string]$Severity = "info", [hashtable]$Details = @{})
    $clean = @{}
    foreach ($key in $Details.Keys) { $v = $Details[$key]; if ($null -ne $v -and "$v" -ne "") { $clean[$key] = if ($v -is [string]) { $v.Substring(0, [Math]::Min(1000, $v.Length)) } else { $v } } }
    $e = @{ source = "host"; event = $Event; timestamp = $Time.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); host = $Computer; severity = $Severity; details = $clean }
    if ($Actor) { $e.actor = $Actor }
    if ($SrcIp -and $SrcIp -notmatch '^(-|::1|127\.0\.0\.1)$') { $e.srcIp = $SrcIp }
    if ($Result) { $e.result = $Result }
    $e
}

# One Windows event (EventData as a name->value hashtable) -> normalized log event, or $null when not interesting.
function Convert-WinEventToLog {
    param([string]$LogName, [int]$Id, [int]$Level, [datetime]$Time, [hashtable]$Data, [string]$Computer)
    $t = @{ Time = $Time; Computer = $Computer }
    if ($LogName -eq "Security") {
        switch ($Id) {
            4624 {
                if (@("2","7","10","11") -notcontains [string]$Data.LogonType -or $Data.TargetUserName -match $script:SystemAccount) { return $null }
                return New-LogEvent @t -Event "LOGIN_SUCCESS" -Actor $Data.TargetUserName -SrcIp $Data.IpAddress -Result "success" -Details @{ logon_type = [int]$Data.LogonType; domain = $Data.TargetDomainName; auth_method = $Data.AuthenticationPackageName; workstation = $Data.WorkstationName }
            }
            4625 {
                $reason = $script:FailReasons[([string]$Data.SubStatus).ToLowerInvariant()]
                return New-LogEvent @t -Event "LOGIN_FAILED" -Actor $Data.TargetUserName -SrcIp $Data.IpAddress -Result "failed" -Severity "warning" -Details @{ logon_type = [int]$Data.LogonType; domain = $Data.TargetDomainName; reason = $(if ($reason) { $reason } else { $Data.SubStatus }); workstation = $Data.WorkstationName }
            }
            4672 { if ($Data.SubjectUserName -match $script:SystemAccount) { return $null }; return New-LogEvent @t -Event "PRIVILEGE_ASSIGNED" -Actor $Data.SubjectUserName -Result "success" -Severity "notice" }
            4720 { return New-LogEvent @t -Event "USER_CREATED" -Actor $Data.SubjectUserName -Result "success" -Severity "notice" -Details @{ target_user = $Data.TargetUserName } }
            4732 { return New-LogEvent @t -Event "GROUP_MEMBER_ADDED" -Actor $Data.SubjectUserName -Result "success" -Severity "notice" -Details @{ group = $Data.TargetUserName; member = $Data.MemberSid } }
        }
    } elseif ($LogName -eq "System") {
        if ($Id -eq 7036) {
            # ponytail: service state text is localized on non-English Windows; only English running/stopped are mapped. Match the Binary field if that matters.
            $name = if ($Data.param2 -match '^(?i)running$') { "SERVICE_START" } elseif ($Data.param2 -match '^(?i)stopped$') { "SERVICE_STOP" } else { return $null }
            return New-LogEvent @t -Event $name -Result "success" -Details @{ service = $Data.param1 }
        }
        if ($Id -eq 7045) { return New-LogEvent @t -Event "SERVICE_INSTALLED" -Actor $Data.AccountName -Result "success" -Severity "notice" -Details @{ service = $Data.ServiceName; image_path = $Data.ImagePath; start_type = $Data.StartType } }
    } elseif ($LogName -eq "Microsoft-Windows-Backup") {
        if ($Id -eq 4) { return New-LogEvent @t -Event "BACKUP_COMPLETE" -Result "success" -Details @{ backup_event_id = 4 } }
        if ($Level -in 1, 2) { return New-LogEvent @t -Event "BACKUP_FAILED" -Result "failed" -Severity "error" -Details @{ backup_event_id = $Id } }
    }
    $null
}

$script:LogSources = @(
    @{ key = "security"; log = "Security"; filter = "(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4720 or EventID=4732)" },
    @{ key = "system"; log = "System"; filter = "(EventID=7036 or EventID=7045) and Provider[@Name='Service Control Manager']" },
    @{ key = "backup"; log = "Microsoft-Windows-Backup"; filter = "(EventID=4 or Level=1 or Level=2)" }
)

# Returns @{ events; state }. State (last EventRecordID per log) is only persisted by the caller after a successful send.
function Get-LogEvents {
    param($State, [int]$BackfillHours = 1, [int]$MaxPerLog = 2000)
    $events = New-Object System.Collections.Generic.List[object]; $next = @{}
    if ($State) { foreach ($p in $State.PSObject.Properties) { $next[$p.Name] = $p.Value } }
    foreach ($src in $script:LogSources) {
        if (!(Get-WinEvent -ListLog $src.log -ErrorAction SilentlyContinue)) { continue }
        $last = if ($State -and $null -ne $State.($src.key)) { [int64]$State.($src.key) } else { $null }
        $where = if ($null -ne $last) { "EventRecordID>$last" } else { "TimeCreated[timediff(@SystemTime) <= $($BackfillHours * 3600000)]" }
        $xpath = "*[System[$($src.filter) and $where]]"
        try { $found = @(Get-WinEvent -LogName $src.log -FilterXPath $xpath -Oldest -MaxEvents $MaxPerLog -ErrorAction Stop) }
        catch { if ($_.FullyQualifiedErrorId -notlike "NoMatchingEventsFound*") { Write-Warning "$($src.log): $($_.Exception.Message)" }; continue }
        foreach ($e in $found) {
            $data = @{}
            $n = 0; foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $n++; $key = if ($d.Name) { $d.Name } else { "param$n" }; $data[$key] = [string]$d.'#text' }
            $mapped = Convert-WinEventToLog -LogName $src.log -Id ([int]$e.Id) -Level ([int]$e.Level) -Time $e.TimeCreated -Data $data -Computer $env:COMPUTERNAME
            if ($mapped) { $events.Add($mapped) }
        }
        if ($found.Count) { $next[$src.key] = [int64]$found[-1].RecordId }
    }
    @{ events = $events; state = $next }
}

function Send-LogEvents {
    $state = if (Test-Path -LiteralPath $script:LogStatePath) { try { Get-Content -LiteralPath $script:LogStatePath -Raw | ConvertFrom-Json } catch { $null } } else { $null }
    $result = Get-LogEvents -State $state -BackfillHours $script:LogBackfillHours
    for ($i = 0; $i -lt $result.events.Count; $i += 1000) {
        $batch = @($result.events | Select-Object -Skip $i -First 1000)
        Invoke-ByakuganApi "/api/agent/logs" "POST" @{ events = $batch } | Out-Null   # duplicates are ignored server-side, retries are safe
    }
    $result.state | ConvertTo-Json -Compress | Set-Content -LiteralPath $script:LogStatePath -Encoding UTF8
}

if ($LoadOnly) { return }
if ($LogDryRun) { (Get-LogEvents -State $null -BackfillHours $script:LogBackfillHours).events | ConvertTo-Json -Depth 6; return }

$lastEvidence = [DateTime]::MinValue
$lastLogs = [DateTime]::MinValue
while ($true) {
    try {
        if (((Get-Date) - $lastEvidence).TotalSeconds -ge $script:Interval) {
            Invoke-ByakuganApi "/api/agent/ingest" "POST" (Get-AgentPayload) | Out-Null
            $lastEvidence = Get-Date
        }
        if ($script:LogsEnabled -and ((Get-Date) - $lastLogs).TotalSeconds -ge $script:LogInterval) {
            $lastLogs = Get-Date
            try { Send-LogEvents } catch { Write-Warning "log shipping: $($_.Exception.Message)" }
        }
        Invoke-ScanJob
    } catch { Write-Warning "$(Get-Date -Format o) $($_.Exception.Message)" }
    Start-Sleep -Seconds $script:PollInterval
}

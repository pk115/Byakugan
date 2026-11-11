# Run with Windows PowerShell 5.1: powershell -NoProfile -File agent-windows/Test-ScanJob.ps1
$ErrorActionPreference = "Stop"
. "$PSScriptRoot\byakugan-agent.ps1" -LoadOnly
$testDirectory = Join-Path $env:TEMP ("byakugan-scan-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$originalPath = $env:PATH
$scanner = Join-Path $testDirectory "trivy.exe"
# A local native scanner fixture exercises the real Windows argument parsing and exit code.
Add-Type -OutputAssembly $scanner -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.IO;
class ScannerFixture {
  static int Main(string[] args) {
    if (args.Length == 1 && args[0] == "--version") { Console.WriteLine("Trivy test fixture"); return 0; }
    if (Environment.GetEnvironmentVariable("BYAKUGAN_TEST_FAIL") == "1") { Console.Error.WriteLine("Fixture scan failure"); return 9; }
    string expected = Environment.GetEnvironmentVariable("BYAKUGAN_TEST_TARGET");
    if (args[args.Length-1] != expected) { Console.Error.WriteLine("Target corrupted: " + args[args.Length-1]); return 2; }
    for (int i=0; i<args.Length-1; i++) if(args[i] == "--output") File.WriteAllText(args[i+1], "{\"Results\":[]}");
    return 0;
  }
}
'@
function Invoke-ByakuganApi {
    param([string]$Path, [string]$Method = "GET", $Body = $null)
    if ($Path -eq "/api/agent/scan-jobs/next") { return $script:testJob }
    if ($Path -like "*/failure") { $script:testFailure = $Body }
    if ($Path -like "*/result") { $script:testResult = $Body }
}
try {
    $env:PATH = "$testDirectory;$originalPath"
    foreach ($target in @("/", "$env:SystemDrive\", "$env:SystemDrive\Program Files\", "$env:SystemDrive\apps")) {
        $env:BYAKUGAN_TEST_TARGET = if ($target -eq "/") { "$env:SystemDrive\" } else { $target }
        $script:testJob = @{ id=987654; targetType="FILESYSTEM"; target=$target; scanners=@("vuln"); severity=@("HIGH") }
        $script:testResult = $null; $script:testFailure = $null
        Invoke-ScanJob
        if ($script:testFailure) { throw "Scan target '$target' failed: $($script:testFailure.message)" }
        if (!$script:testResult -or $script:testResult.scanner -ne "Trivy") { throw "Scan result not uploaded" }
        Write-Output "PASS scan target: $target"
    }
    $env:BYAKUGAN_TEST_FAIL = "1"
    $script:testResult = $null; $script:testFailure = $null
    Invoke-ScanJob
    if ($script:testResult -or $script:testFailure.message -notlike '*exit code 9*Fixture scan failure*') {
        throw "Native exit code and stderr were not reported correctly"
    }
    Write-Output "PASS failed scan reports exit code and stderr"
} finally {
    $env:PATH = $originalPath
    Remove-Item Env:BYAKUGAN_TEST_TARGET -ErrorAction SilentlyContinue
    Remove-Item Env:BYAKUGAN_TEST_FAIL -ErrorAction SilentlyContinue
    # Only remove the explicitly created test directory under TEMP.
    Remove-Item -LiteralPath $testDirectory -Recurse -Force
}

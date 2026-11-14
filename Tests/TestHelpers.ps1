<#
    TestHelpers.ps1 - shared setup for the Pester tests.

    Register-RacFakeSystemMock replaces every OS-facing function in Sources.ps1
    with the fake machine from Fixtures/FakeSystem.ps1. File-based detectors run
    against the REAL fake profiles that New-RacFakeAgentEnvironment writes into
    Pester's TestDrive.

    Call these from a BeforeAll block (Pester 5).
#>

$script:RacRepoRoot = Split-Path -Parent $PSScriptRoot
$script:RacModuleManifest = [System.IO.Path]::Combine($script:RacRepoRoot, 'RogueAgentChecker', 'RogueAgentChecker.psd1')

. ([System.IO.Path]::Combine($PSScriptRoot, 'Fixtures', 'New-RacFakeAgentEnvironment.ps1'))
. ([System.IO.Path]::Combine($PSScriptRoot, 'Fixtures', 'FakeSystem.ps1'))

function Register-RacFakeSystemMock {
    <#
        Mock bodies read the fake machine from a global variable because Pester runs
        module-scoped mock bodies in their own scope. AfterAll removes it.
    #>
    $m = 'RogueAgentChecker'
    Mock -ModuleName $m Get-RacComputerName { 'FAKE-WS01' }
    Mock -ModuleName $m Get-RacCurrentIdentity { 'CORP\itadmin' }
    Mock -ModuleName $m Get-RacIsElevated { $true }
    Mock -ModuleName $m Test-RacIsWindows { $true }
    Mock -ModuleName $m Get-RacOsDescription { 'Microsoft Windows 11 Enterprise (fake)' }
    Mock -ModuleName $m Get-RacRawProcess { $global:RacFake.Processes }
    Mock -ModuleName $m Get-RacProcessOwner { '' }
    Mock -ModuleName $m Get-RacRawTcpConnection { $global:RacFake.TcpConnections }
    Mock -ModuleName $m Get-RacRawDnsCache { $global:RacFake.DnsCache }
    Mock -ModuleName $m Get-RacRawScheduledTask { $global:RacFake.ScheduledTasks }
    Mock -ModuleName $m Get-RacScheduledTaskRunInfo { $global:RacFake.ScheduledTaskRunInfo }
    Mock -ModuleName $m Get-RacRawService { $global:RacFake.Services }
    Mock -ModuleName $m Get-RacRawRunKey { $global:RacFake.RunKeys }
    Mock -ModuleName $m Get-RacRawStartupItem { $global:RacFake.StartupItems }
    Mock -ModuleName $m Get-RacRawWmiSubscription { $global:RacFake.WmiSubscriptions }
    Mock -ModuleName $m Get-RacRawEnvironmentVariable { $global:RacFake.EnvironmentVariables }
    Mock -ModuleName $m Get-RacRawCredentialTarget { $global:RacFake.CredentialTargets }
    Mock -ModuleName $m Get-RacRawNativeMessagingHost { $global:RacFake.NativeMessagingHosts }
    Mock -ModuleName $m Get-RacRawWinEvent { $global:RacFake.Events[$LogName] }
    Mock -ModuleName $m Get-RacFileAclSummary {
        # carol's Downloads .env is readable by every user on the box
        if ($Path -match 'carol' -and $Path -match 'Downloads' -and $Path -match '\.env$') {
            return [pscustomobject]@{ BroadRead = $true; Identities = @('BUILTIN\Users') }
        }
        return [pscustomobject]@{ BroadRead = $false; Identities = @() }
    }
}

function Invoke-RacFixtureScan {
    <# Builds the fake machine, mocks the OS, runs a full scan, returns everything a test needs. #>
    param([Parameter(Mandatory = $true)][string]$TestRoot, [string]$AllowListPath)

    if (-not $AllowListPath) { $AllowListPath = [System.IO.Path]::Combine($PSScriptRoot, 'Fixtures', 'allowlist.fixture.json') }
    $environment = New-RacFakeAgentEnvironment -Root ([System.IO.Path]::Combine($TestRoot, 'machine'))
    $global:RacFake = Get-RacFakeSystem -Environment $environment
    Register-RacFakeSystemMock

    $out = [System.IO.Path]::Combine($TestRoot, 'out')
    $result = Invoke-RogueAgentScan -ProfileRoot $environment.ProfilePaths -AllowListPath $AllowListPath `
        -OutputPath $out -ProxyLogPath $environment.ProxyLog -PassThru -WarningAction SilentlyContinue 6>$null

    return [pscustomobject]@{ Environment = $environment; Result = $result; OutputPath = $out }
}

function Get-RacTestFinding {
    <# Filter helper: Get-RacTestFinding $scan -Breadcrumb McpServerConfig -AgentId claude-desktop #>
    param($Scan, [string]$Breadcrumb, [string]$AgentId, [string]$Agent, [string]$TitleLike, [string]$User)
    $f = @($Scan.Result.Findings)
    if ($Breadcrumb) { $f = @($f | Where-Object { $_.Breadcrumb -eq $Breadcrumb }) }
    if ($AgentId) { $f = @($f | Where-Object { $_.AgentId -eq $AgentId }) }
    if ($Agent) { $f = @($f | Where-Object { $_.Agent -eq $Agent }) }
    if ($TitleLike) { $f = @($f | Where-Object { $_.Title -like $TitleLike }) }
    if ($User) { $f = @($f | Where-Object { $_.User -like ('*' + $User + '*') }) }
    return $f
}

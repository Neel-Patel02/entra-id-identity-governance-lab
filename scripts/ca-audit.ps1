<#
.SYNOPSIS
    Project Alpha - Day 3: Conditional Access policy audit for Microsoft Entra ID (Microsoft Graph SDK).

.DESCRIPTION
    Exports every Conditional Access policy with its state, who it targets, which apps, and what it
    enforces - in plain English - then flags:
      - Report-Only policies (enabledForReportingButNotEnforced): logged but NOT enforced
      - Disabled policies
      - Enabled policies that target all users but do NOT exclude the break-glass account (lockout risk)
    Plus tenant-level checks: is MFA required for all users, and is legacy authentication blocked?

    Read-only: makes no changes to the tenant.

.EXAMPLE
    .\ca-audit.ps1
#>
#Requires -Version 7.0

[CmdletBinding()]
param(
    [string[]]$BreakGlassUpns = @('emergency.admin@yourtenant.onmicrosoft.com'),
    [string]$OutputFolder = '.\output'
)

$ErrorActionPreference = 'Stop'
$Scopes = @('Policy.Read.All', 'Directory.Read.All')   # read-only

# --- Helpers ------------------------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO')
    $line  = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red'; OK = 'Green' }[$Level]
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $script:LogFile -Value $line
}

function Connect-Lab {
    $ctx = Get-MgContext
    $missing = if ($ctx) { $Scopes | Where-Object { $_ -notin $ctx.Scopes } } else { $Scopes }
    if (-not $ctx -or $missing) {
        Connect-MgGraph -Scopes $Scopes -NoWelcome
        $ctx = Get-MgContext
    }
    Write-Log "Connected to tenant $($ctx.TenantId) as $($ctx.Account)" 'OK'
}

# Turn object IDs into readable names (cached). Special keywords pass straight through.
$script:NameCache = @{}
$Keywords = 'All', 'None', 'GuestsOrExternalUsers', 'Office365', 'MicrosoftAdminPortals'
function Resolve-Name {
    param([string]$Id, [ValidateSet('User', 'Group', 'App', 'Role')][string]$Kind)
    if (-not $Id) { return $null }
    if ($Id -in $Keywords) { return $Id }
    $key = "$Kind|$Id"
    if ($script:NameCache.ContainsKey($key)) { return $script:NameCache[$key] }
    $name = try {
        switch ($Kind) {
            'User'  { (Get-MgUser -UserId $Id -Property UserPrincipalName).UserPrincipalName }
            'Group' { (Get-MgGroup -GroupId $Id -Property DisplayName).DisplayName }
            'App'   { (Get-MgServicePrincipal -Filter "appId eq '$Id'" -Property DisplayName | Select-Object -First 1).DisplayName ?? $Id }
            'Role'  { (Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $Id -Property DisplayName).DisplayName }
        }
    } catch { "$Id (not found)" }
    $script:NameCache[$key] = $name
    $name
}

function Join-Names {
    param($Ids, [string]$Kind)
    (@($Ids) | Where-Object { $_ } | ForEach-Object { Resolve-Name $_ $Kind }) -join '; '
}

# --- Main ---------------------------------------------------------------------------------------
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$script:LogFile = Join-Path $OutputFolder "ca-audit-$(Get-Date -Format yyyyMMdd).log"

Write-Log '=== ca-audit.ps1 ==='
Connect-Lab

# Break-glass object IDs (CA policies store IDs, not UPNs).
$breakGlassIds = foreach ($upn in $BreakGlassUpns) {
    try { (Get-MgUser -UserId $upn -Property Id).Id }
    catch { Write-Log "Break-glass account $upn not found" 'WARN' }
}

$policies = @(Get-MgIdentityConditionalAccessPolicy -All)
if ($policies.Count -eq 0) { Write-Log 'No Conditional Access policies found.' 'WARN'; return }
Write-Log "Found $($policies.Count) Conditional Access policies" 'OK'

$stateLabel = @{
    'enabled'                           = 'On'
    'disabled'                          = 'Off'
    'enabledForReportingButNotEnforced' = 'Report-only'
}

$report = foreach ($p in $policies) {
    $u     = $p.Conditions.Users
    $apps  = $p.Conditions.Applications
    $grant = $p.GrantControls

    $state         = $stateLabel[$p.State] ?? $p.State
    $targetsAll    = 'All' -in @($u.IncludeUsers)
    $bgExcluded    = $breakGlassIds -and -not ($breakGlassIds | Where-Object { $_ -notin @($u.ExcludeUsers) })
    $clientTypes   = @($p.Conditions.ClientAppTypes)
    $controls      = @($grant.BuiltInControls)
    $isLegacyBlock = ('block' -in $controls) -and ($clientTypes | Where-Object { $_ -in 'exchangeActiveSync', 'other' })
    # The SDK returns an EMPTY AuthenticationStrength object (not $null) when none is set - check its Id.
    $hasAuthStrength = [bool]$grant.AuthenticationStrength.Id
    $requiresMfa     = ('mfa' -in $controls) -or $hasAuthStrength

    # Plain-English summary of what the policy does
    $enforces = if ($controls) { ($controls -join " $($grant.Operator) ").ToUpper() }
                elseif ($hasAuthStrength) { 'AUTH STRENGTH' }
                else { '(session controls only)' }

    $findings = @()
    if ($p.State -eq 'enabledForReportingButNotEnforced') { $findings += 'REPORT-ONLY: logged but NOT enforced - enable or retire' }
    if ($p.State -eq 'disabled')                         { $findings += 'DISABLED: no effect' }
    if ($targetsAll -and -not $bgExcluded -and $p.State -ne 'disabled') {
        $findings += 'RISK: break-glass not excluded (tenant lockout risk)'
    }

    [pscustomobject]@{
        Policy            = $p.DisplayName
        State             = $state
        IncludeUsers      = Join-Names $u.IncludeUsers 'User'
        IncludeGroups     = Join-Names $u.IncludeGroups 'Group'
        IncludeRoles      = Join-Names $u.IncludeRoles 'Role'
        ExcludeUsers      = Join-Names $u.ExcludeUsers 'User'
        ExcludeGroups     = Join-Names $u.ExcludeGroups 'Group'
        BreakGlassExcluded= [bool]$bgExcluded
        Apps              = Join-Names $apps.IncludeApplications 'App'
        ClientAppTypes    = $clientTypes -join '; '
        Enforces          = $enforces
        RequiresMfa       = [bool]$requiresMfa
        BlocksLegacyAuth  = [bool]$isLegacyBlock
        Modified          = $p.ModifiedDateTime
        Finding           = $findings -join ' | '
    }
}

Write-Host "`n--- Conditional Access policies ---" -ForegroundColor Cyan
$report | Sort-Object State, Policy |
    Format-Table Policy, State, IncludeUsers, Apps, Enforces, BreakGlassExcluded, Finding -AutoSize -Wrap

# --- Tenant-level checks ------------------------------------------------------------------------
Write-Host '--- Security floor checks ---' -ForegroundColor Cyan

$mfaAll = $report | Where-Object { $_.State -eq 'On' -and $_.RequiresMfa -and $_.IncludeUsers -match '\bAll\b' -and $_.Apps -match '\bAll\b' }
if ($mfaAll) { Write-Log "MFA required for all users: YES ($($mfaAll.Policy -join ', '))" 'OK' }
else         { Write-Log 'MFA required for all users: NO enforced policy found' 'WARN' }

$legacy = $report | Where-Object { $_.State -eq 'On' -and $_.BlocksLegacyAuth }
if ($legacy) { Write-Log "Legacy authentication blocked: YES ($($legacy.Policy -join ', '))" 'OK' }
else         { Write-Log 'Legacy authentication blocked: NO enforced policy found' 'WARN' }

$reportOnly = @($report | Where-Object State -eq 'Report-only')
if ($reportOnly) { Write-Log "Report-only (not enforced): $($reportOnly.Count) - $($reportOnly.Policy -join ', ')" 'WARN' }

$noBg = @($report | Where-Object Finding -like '*break-glass*')
if ($noBg) { Write-Log "Policies missing break-glass exclusion: $($noBg.Policy -join ', ')" 'ERROR' }
else       { Write-Log 'Break-glass excluded from every all-users policy' 'OK' }

$out = Join-Path $OutputFolder "ca-policies-$(Get-Date -Format yyyyMMdd-HHmmss).csv"
$report | Export-Csv $out -NoTypeInformation
Write-Log "Exported: $out" 'OK'
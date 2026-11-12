<#
.SYNOPSIS
    Project Alpha - Day 3: Identity governance audit for Microsoft Entra ID (Microsoft Graph SDK).

.DESCRIPTION
    Part A - Privileged access: lists every directory role assignment and classifies it as
             STANDING (permanent active), PIM-ELIGIBLE (just-in-time), or PIM-ACTIVATED.
             Standing high-privilege admins are flagged for conversion to PIM eligible.
             The break-glass account is recognised as an expected exception.
    Part B - Inactive users: reports each user's last sign-in, handling users who have NEVER
             signed in (LastSignInDateTime = null) as their own category, and flags disabled
             users that still hold a license (wasted seat).

    Read-only: makes no changes to the tenant.
    Requires Entra ID P1/P2 (signInActivity) and P2 (PIM schedule data).

.EXAMPLE
    .\identity-governance-audit.ps1
    .\identity-governance-audit.ps1 -InactiveDays 30
#>
#Requires -Version 7.0

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$InactiveDays = 90,

    # Break-glass accounts: permanent Global Admin by design - reported as expected, not as a finding.
    [string[]]$BreakGlassUpns = @('emergency.admin@yourtenant.onmicrosoft.com'),

    [string]$OutputFolder = '.\output'
)

$ErrorActionPreference = 'Stop'
$Scopes = @('RoleManagement.Read.Directory', 'AuditLog.Read.All', 'Directory.Read.All')   # read-only

# Roles that can take over the tenant or large parts of it.
$HighPrivilegeRoles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'User Administrator', 'Conditional Access Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Authentication Administrator',
    'Exchange Administrator', 'SharePoint Administrator', 'Intune Administrator', 'Helpdesk Administrator'
)

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

# Cache principal lookups (user / group / service principal) - one Graph call per object.
$script:PrincipalCache = @{}
function Resolve-Principal {
    param([string]$Id)
    if ($script:PrincipalCache.ContainsKey($Id)) { return $script:PrincipalCache[$Id] }
    try {
        $o    = Get-MgDirectoryObject -DirectoryObjectId $Id
        $p    = $o.AdditionalProperties
        $info = [pscustomobject]@{
            Name = $p.userPrincipalName ?? $p.displayName ?? $Id
            Type = ($p.'@odata.type' -replace '#microsoft.graph.', '')
        }
    }
    catch { $info = [pscustomobject]@{ Name = $Id; Type = 'Unknown (deleted?)' } }
    $script:PrincipalCache[$Id] = $info
    $info
}

function ConvertTo-LocalTime {
    param($Utc)
    if (-not $Utc) { return $null }
    [datetime]::SpecifyKind([datetime]$Utc, 'Utc').ToLocalTime()
}

# --- Main ---------------------------------------------------------------------------------------
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$script:LogFile = Join-Path $OutputFolder "identity-governance-audit-$(Get-Date -Format yyyyMMdd).log"
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$breakGlass = $BreakGlassUpns | ForEach-Object { $_.ToLower() }

Write-Log "=== identity-governance-audit.ps1 | Inactive threshold: $InactiveDays days ==="
Connect-Lab

# ================================================================================================
# PART A - Privileged access (standing vs PIM)
# ================================================================================================
$roleNames = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All -Property Id, DisplayName |
    ForEach-Object { $roleNames[$_.Id] = $_.DisplayName }

$rows = [System.Collections.Generic.List[object]]::new()

try {
    # Active = permanent (standing) OR a current PIM activation.
    $active   = @(Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All)
    # Eligible = can activate just-in-time through PIM; no access until activated.
    $eligible = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All)
    $pimData  = $true
}
catch {
    Write-Log "PIM schedule data unavailable ($($_.Exception.Message)). Falling back to plain active assignments - standing vs PIM cannot be distinguished." 'WARN'
    $active   = @(Get-MgRoleManagementDirectoryRoleAssignment -All)
    $eligible = @()
    $pimData  = $false
}

foreach ($a in $active) {
    $pr    = Resolve-Principal $a.PrincipalId
    $role  = $roleNames[$a.RoleDefinitionId] ?? $a.RoleDefinitionId
    $kind  = if (-not $pimData)                 { 'Active (type unknown)' }
             elseif ($a.AssignmentType -eq 'Activated') { 'Active - PIM activation' }
             elseif (-not $a.EndDateTime)       { 'Active - PERMANENT (standing)' }
             else                               { 'Active - time-bound' }
    $rows.Add([pscustomobject]@{
        Role = $role; Principal = $pr.Name; PrincipalType = $pr.Type; Assignment = $kind
        Via = $a.MemberType ?? 'Direct'; Ends = ConvertTo-LocalTime $a.EndDateTime
        HighPrivilege = $role -in $HighPrivilegeRoles
    })
}
foreach ($e in $eligible) {
    $pr   = Resolve-Principal $e.PrincipalId
    $role = $roleNames[$e.RoleDefinitionId] ?? $e.RoleDefinitionId
    $rows.Add([pscustomobject]@{
        Role = $role; Principal = $pr.Name; PrincipalType = $pr.Type; Assignment = 'Eligible (PIM just-in-time)'
        Via = $e.MemberType ?? 'Direct'; Ends = ConvertTo-LocalTime $e.EndDateTime
        HighPrivilege = $role -in $HighPrivilegeRoles
    })
}

# Findings
foreach ($r in $rows) {
    $isBreakGlass = $r.Principal.ToLower() -in $breakGlass
    $finding = switch -Wildcard ($r.Assignment) {
        'Active - PERMANENT*' {
            if ($isBreakGlass -and $r.Role -eq 'Global Administrator') { 'Expected: break-glass (permanent by design)' }
            elseif ($r.HighPrivilege) { 'REVIEW: standing admin - convert to PIM eligible' }
            else { 'Low-privilege standing role' }
        }
        'Eligible*'      { 'OK: just-in-time via PIM' }
        'Active - PIM*'  { 'OK: currently activated via PIM' }
        default          { '' }
    }
    $r | Add-Member -NotePropertyName Finding -NotePropertyValue $finding
}

$rows = $rows | Sort-Object @{ e = { $_.Finding -notlike 'REVIEW*' } }, Role, Principal

Write-Host "`n--- Privileged role assignments ---" -ForegroundColor Cyan
$rows | Format-Table Role, Principal, Assignment, Via, Finding -AutoSize

$standing = @($rows | Where-Object Finding -like 'REVIEW*')
$gaCount  = @($rows | Where-Object { $_.Role -eq 'Global Administrator' -and $_.Assignment -like 'Active*' }).Count
Write-Log "Standing high-privilege admins needing review: $($standing.Count)" ($standing.Count ? 'WARN' : 'OK')
Write-Log "PIM-eligible assignments: $(@($rows | Where-Object Assignment -like 'Eligible*').Count)"
if ($gaCount -gt 4) { Write-Log "Active Global Administrators: $gaCount (Microsoft recommends fewer than 5)" 'WARN' }
else                { Write-Log "Active Global Administrators: $gaCount" 'OK' }

$rolesCsv = Join-Path $OutputFolder "privileged-roles-$stamp.csv"
$rows | Export-Csv $rolesCsv -NoTypeInformation

# ================================================================================================
# PART B - Inactive users (null-safe last sign-in)
# ================================================================================================
$now   = (Get-Date).ToUniversalTime()
# signInActivity is NOT returned unless explicitly requested.
$users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, UserType,
                                   CreatedDateTime, Department, AssignedLicenses, SignInActivity

$report = foreach ($u in $users) {
    $sia = $u.SignInActivity
    # Most recent of interactive / non-interactive / successful. Any of them may be null.
    $last = @($sia.LastSignInDateTime, $sia.LastNonInteractiveSignInDateTime, $sia.LastSuccessfulSignInDateTime) |
            Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

    $daysInactive = if ($last) { [int]($now - [datetime]$last).TotalDays } else { $null }
    $daysOld      = if ($u.CreatedDateTime) { [int]($now - [datetime]$u.CreatedDateTime).TotalDays } else { $null }
    $licensed     = @($u.AssignedLicenses).Count -gt 0

    $status = if (-not $u.AccountEnabled)          { 'Disabled' }
              elseif (-not $last)                  { 'Never signed in' }
              elseif ($daysInactive -ge $InactiveDays) { 'Inactive' }
              else                                 { 'Active' }

    $finding = switch ($status) {
        'Disabled'        { if ($licensed) { 'Disabled but still licensed - remove license / groups' } else { '' } }
        'Never signed in' { if ($daysOld -ge $InactiveDays) { "Stale: never signed in, created $daysOld days ago" }
                            else { "Never signed in (account $daysOld days old - monitor)" } }
        'Inactive'        { "No sign-in for $daysInactive days - review / disable" }
        default           { '' }
    }

    [pscustomobject]@{
        User          = $u.UserPrincipalName
        DisplayName   = $u.DisplayName
        UserType      = $u.UserType
        Department    = $u.Department
        Enabled       = $u.AccountEnabled
        Licensed      = $licensed
        LastSignIn    = ConvertTo-LocalTime $last
        DaysInactive  = $daysInactive
        Created       = ConvertTo-LocalTime $u.CreatedDateTime
        Status        = $status
        Finding       = $finding
    }
}

Write-Host "`n--- Users needing attention ---" -ForegroundColor Cyan
$report | Where-Object Finding | Sort-Object Status, User |
    Format-Table User, Enabled, Licensed, LastSignIn, DaysInactive, Finding -AutoSize

Write-Host "--- User status summary ---" -ForegroundColor Cyan
$report | Group-Object Status | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize

$wasted = @($report | Where-Object { $_.Status -eq 'Disabled' -and $_.Licensed }).Count
if ($wasted) { Write-Log "$wasted disabled user(s) still consuming a license" 'WARN' }

$usersCsv = Join-Path $OutputFolder "user-activity-$stamp.csv"
$report | Export-Csv $usersCsv -NoTypeInformation
Write-Log "Exported: $rolesCsv, $usersCsv (contains UPNs - redact before publishing)" 'OK'
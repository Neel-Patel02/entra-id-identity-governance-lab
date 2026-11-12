<#
.SYNOPSIS
    Project Alpha - Day 3: Investigate failed sign-ins in Microsoft Entra ID (Microsoft Graph SDK).
 
.DESCRIPTION
    Pulls FAILED sign-ins from the Entra sign-in logs for a time window (optionally one user),
    translates the error codes into plain English, prints a per-user summary, flags IPs that
    hit several accounts (possible password spray), and exports evidence CSVs.
 
    Key error codes:
      50126 = Invalid username or password (wrong password)
      50053 = Account locked by Smart Lockout (or sign-in from a known-malicious IP blocked)
 
    Notes:
      - Sign-in logs live in the SIGN-IN logs (Get-MgAuditLogSignIn), not the directory audit logs.
      - Reading sign-in logs via Graph requires Entra ID P1/P2 and AuditLog.Read.All.
      - Graph stores times in UTC; this script shows both UTC and local time.
      - Read-only: makes no changes to the tenant.
 
.EXAMPLE
    .\investigate-signins.ps1 -UserPrincipalName priya.shah@yourtenant.onmicrosoft.com -HoursBack 2
    .\investigate-signins.ps1 -HoursBack 24
#>
#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports
 
[CmdletBinding()]
param(
    [string]$UserPrincipalName,
 
    [ValidateRange(1, 720)]          # sign-in logs are retained 30 days on P1/P2
    [int]$HoursBack = 24,
 
    [ValidateRange(2, 100)]
    [int]$SprayThreshold = 3,        # an IP failing against this many distinct users gets flagged
 
    [string]$OutputFolder = '.\output'
)
 
$ErrorActionPreference = 'Stop'
$Scopes = @('AuditLog.Read.All', 'Directory.Read.All')   # read-only
 
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
 
function Get-ErrorMeaning {
    param([int]$Code)
    switch ($Code) {
        50126   { 'Wrong password' }
        50053   { 'Locked out (Smart Lockout) / malicious IP blocked' }
        50057   { 'Account disabled' }
        50055   { 'Password expired' }
        50034   { 'User does not exist' }
        50074   { 'MFA required (interrupt, not an attack)' }
        50076   { 'MFA required (interrupt, not an attack)' }
        500121  { 'MFA failed / denied' }
        53003   { 'Blocked by Conditional Access' }
        default { 'Other' }
    }
}
 
function ConvertTo-LocalTime {
    param([datetime]$Utc)
    [datetime]::SpecifyKind($Utc, 'Utc').ToLocalTime()
}
 
# --- Main ---------------------------------------------------------------------------------------
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$script:LogFile = Join-Path $OutputFolder "investigate-signins-$(Get-Date -Format yyyyMMdd).log"
 
Write-Log "=== investigate-signins.ps1 | User: $(if ($UserPrincipalName) { $UserPrincipalName } else { 'ALL' }) | Last $HoursBack h ==="
Connect-Lab
 
# 1. Build the filter: failed sign-ins (errorCode not 0) since the start time (UTC, no quotes).
$since  = (Get-Date).ToUniversalTime().AddHours(-$HoursBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter = "createdDateTime ge $since and status/errorCode ne 0"
if ($UserPrincipalName) {
    $safeUpn = $UserPrincipalName.Trim().ToLower().Replace("'", "''")
    $filter += " and userPrincipalName eq '$safeUpn'"
}
Write-Log "Graph filter: $filter"
 
# 2. Fetch (server-side filtering - never pull the whole log and filter locally).
try {
    $signIns = @(Get-MgAuditLogSignIn -Filter $filter -All)
}
catch {
    if ($_.Exception.Message -match 'premium|license') {
        Write-Log 'Sign-in logs via Graph need Entra ID P1/P2. Check Entra > Overview for the license.' 'ERROR'
    }
    throw
}
 
if ($signIns.Count -eq 0) {
    Write-Log "No failed sign-ins found in the last $HoursBack hours. (New events can take 5-15 min to appear.)" 'WARN'
    return
}
Write-Log "Found $($signIns.Count) failed sign-in(s)" 'OK'
 
# 3. Shape + translate each event.
$events = $signIns | ForEach-Object {
    [pscustomobject]@{
        TimeLocal  = ConvertTo-LocalTime $_.CreatedDateTime
        TimeUTC    = $_.CreatedDateTime
        User       = $_.UserPrincipalName
        ErrorCode  = $_.Status.ErrorCode
        Meaning    = Get-ErrorMeaning $_.Status.ErrorCode
        Reason     = $_.Status.FailureReason
        App        = $_.AppDisplayName
        ClientApp  = $_.ClientAppUsed
        IpAddress  = $_.IpAddress
        Location   = (@($_.Location.City, $_.Location.CountryOrRegion) | Where-Object { $_ }) -join ', '
    }
} | Sort-Object TimeUTC
 
# 4. Per-user summary - the "X wrong passwords, then locked at HH:MM" story.
$summary = $events | Group-Object User | ForEach-Object {
    $e        = $_.Group
    $lockouts = @($e | Where-Object ErrorCode -eq 50053)
    [pscustomobject]@{
        User           = $_.Name
        TotalFailures  = $e.Count
        WrongPassword  = @($e | Where-Object ErrorCode -eq 50126).Count
        Lockouts       = $lockouts.Count
        FirstFailure   = ($e | Select-Object -First 1).TimeLocal
        LastFailure    = ($e | Select-Object -Last 1).TimeLocal
        FirstLockedAt  = if ($lockouts) { ($lockouts | Select-Object -First 1).TimeLocal } else { $null }
        DistinctIPs    = @($e.IpAddress | Sort-Object -Unique).Count
        Verdict        = if ($lockouts) { 'LOCKED OUT' } elseif ($e.Count -ge 5) { 'Repeated failures' } else { 'Minor' }
    }
} | Sort-Object TotalFailures -Descending
 
Write-Host "`n--- Failed sign-ins (local time) ---" -ForegroundColor Cyan
$events | Format-Table TimeLocal, User, ErrorCode, Meaning, IpAddress, App -AutoSize
 
Write-Host "--- Summary per user ---" -ForegroundColor Cyan
$summary | Format-Table User, TotalFailures, WrongPassword, Lockouts, FirstFailure, FirstLockedAt, Verdict -AutoSize
 
# 5. Password-spray check: one IP failing against many different users.
$spray = $events | Group-Object IpAddress | Where-Object {
    @($_.Group.User | Sort-Object -Unique).Count -ge $SprayThreshold
} | ForEach-Object {
    [pscustomobject]@{
        IpAddress      = $_.Name
        UsersTargeted  = @($_.Group.User | Sort-Object -Unique).Count
        Failures       = $_.Count
    }
}
if ($spray) {
    Write-Log "Possible password spray: $(@($spray).Count) IP(s) failed against $SprayThreshold+ users" 'WARN'
    $spray | Format-Table -AutoSize
}
else {
    Write-Log "No password-spray pattern (no IP failed against $SprayThreshold+ users)"
}
 
# 6. Export evidence (contains UPNs + IPs - redact before pushing to GitHub).
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$eventsCsv  = Join-Path $OutputFolder "signin-failures-$stamp.csv"
$summaryCsv = Join-Path $OutputFolder "signin-summary-$stamp.csv"
$events  | Export-Csv $eventsCsv  -NoTypeInformation
$summary | Export-Csv $summaryCsv -NoTypeInformation
Write-Log "Evidence exported: $eventsCsv, $summaryCsv (contains UPNs/IPs - redact before publishing)" 'OK'
 
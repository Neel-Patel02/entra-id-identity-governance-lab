# =====================================================================
#  user-lifecycle.ps1  -  JOINER
#  NexusTech Logistics lab (yourtenant)
#
#  What it does, for every row in the CSV:
#    1. Builds the values HR doesn't send (UPN, display name, nickname)
#    2. Picks the location (Country column, or CA if blank)
#    3. Creates the user - or, if they already exist, updates them to match the CSV
#    4. Puts them in their department group (grp-sales, grp-finance, ...)
#  Then a second pass sets everyone's manager.
#
#  Safe to run as many times as you like.
# =====================================================================

# ---------- Settings (change these, not the code below) ----------
$Domain          = "yourtenant.onmicrosoft.com"
$CsvPath         = ".\new-hires.csv"
$DefaultLocation = "CA"
# Random temp password generated at runtime - never hardcode one in a published script.
# Users must change it at first sign-in (ForceChangePasswordNextSignIn below).
$TempPassword    = (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 14 | ForEach-Object { [char]$_ })) + '!a7'

# Only the permissions this script needs (least privilege)
Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All" -NoWelcome

$Users = Import-Csv -Path $CsvPath

# Remembers groups we already looked up, so we don't ask Graph 50 times
$GroupCache = @{}

# ---------- PASS 1: create / update users and add them to groups ----------
foreach ($User in $Users) {

    # 1. Build the values the CSV doesn't have
    $first       = $User.FirstName.Trim()
    $last        = $User.LastName.Trim()
    $upn         = "$first.$last@$Domain"
    $displayName = "$first $last"
    $nickname    = ("$first.$last" -replace "[^a-zA-Z0-9.]", "")   # strip apostrophes, spaces, etc.

    # 2. Location: use Country if filled in, otherwise the default
    if ([string]::IsNullOrWhiteSpace($User.Country)) {
        $location = $DefaultLocation
        Write-Host "  NOTE: $upn has no country - using $DefaultLocation" -ForegroundColor DarkYellow
    }
    else {
        $location = $User.Country.Trim().ToUpper()
    }

    # 3. Create, or update if they already exist
    try {
        $Existing = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue

        if ($Existing) {
            # Don't recreate - make the existing account match the CSV instead
            Update-MgUser -UserId $Existing.Id `
                -Department $User.Department `
                -JobTitle $User.JobTitle `
                -UsageLocation $location `
                -ErrorAction Stop
            $userId = $Existing.Id
            Write-Host "EXISTS (updated): $upn" -ForegroundColor Yellow
        }
        else {
            $params = @{
                DisplayName       = $displayName
                GivenName         = $first
                Surname           = $last
                UserPrincipalName = $upn
                MailNickname      = $nickname
                Department        = $User.Department
                JobTitle          = $User.JobTitle
                UsageLocation     = $location
                AccountEnabled    = $true
                PasswordProfile   = @{
                    Password                      = $TempPassword
                    ForceChangePasswordNextSignIn = $true
                }
            }
            $NewUser = New-MgUser @params -ErrorAction Stop
            $userId  = $NewUser.Id
            Write-Host "CREATED: $upn ($location)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "FAILED: $upn - $($_.Exception.Message)" -ForegroundColor Red
        continue    # no user = nothing to add to a group, move to the next row
    }

    # 4. Department group: grp-sales, grp-finance, grp-warehouse ...
    $groupName = "grp-" + $User.Department.Trim().ToLower()

    if (-not $GroupCache.ContainsKey($groupName)) {
        $Group = Get-MgGroup -Filter "displayName eq '$groupName'" | Select-Object -First 1
        if (-not $Group) {
            $Group = New-MgGroup -DisplayName $groupName `
                -MailEnabled:$false -SecurityEnabled:$true `
                -MailNickname ($groupName -replace "-", "")
            Write-Host "  GROUP CREATED: $groupName" -ForegroundColor Cyan
        }
        $GroupCache[$groupName] = $Group.Id
    }

    try {
        New-MgGroupMember -GroupId $GroupCache[$groupName] -DirectoryObjectId $userId -ErrorAction Stop
        Write-Host "  added to $groupName"
    }
    catch {
        if ($_.Exception.Message -like "*already exist*") {
            Write-Host "  already in $groupName" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  GROUP FAILED: $upn -> $groupName - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ---------- PASS 2: managers (now that everyone exists) ----------
Write-Host "`n--- Setting managers ---"
foreach ($User in $Users) {
    if ([string]::IsNullOrWhiteSpace($User.Manager)) { continue }   # directors have no manager

    $upn = "$($User.FirstName.Trim()).$($User.LastName.Trim())@$Domain"
    try {
        $Employee = Get-MgUser -UserId $upn -ErrorAction Stop
        $Manager  = Get-MgUser -UserId $User.Manager.Trim() -ErrorAction Stop

        Set-MgUserManagerByRef -UserId $Employee.Id -BodyParameter @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($Manager.Id)"
        } -ErrorAction Stop

        Write-Host "MANAGER: $upn -> $($User.Manager)" -ForegroundColor Green
    }
    catch {
        Write-Host "MANAGER FAILED: $upn - $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nDone."

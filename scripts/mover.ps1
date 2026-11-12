$ErrorActionPreference = "Stop"

# --- Configuration ---
$UserUPN          = "Tyler.Campbell@yourtenant.onmicrosoft.com"
$NewDepartment    = "Sales"
$NewManagerUPN    = "Diana.Prince@yourtenant.onmicrosoft.com"
$NewGroup         = "grp-sales"
$OldGroup         = "grp-warehouse"


# --- Resolve IDs ---
$User     = Get-MgUser -UserId $UserUPN
$Manager  = Get-MgUser -UserId $NewManagerUPN
$NewGrp   = Get-MgGroup -Filter "DisplayName eq '$NewGroup'"
$OldGrp   = Get-MgGroup -Filter "DisplayName eq '$OldGroup'"
 

# --- 1a. Update department ---
Update-MgUser -UserId $User.Id -Department $NewDepartment
Write-Host "OK: Department -> $NewDepartment" -ForegroundColor Green

# --- 1b. Set new manager ---
Set-MgUserManagerByRef -UserId $User.Id -BodyParameter @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($Manager.Id)"
}
Write-Host "OK: Manager -> $($Manager.DisplayName)" -ForegroundColor Green

# --- 2. Add to new group FIRST ---
New-MgGroupMember -GroupId $NewGrp.Id -DirectoryObjectId $User.Id
Write-Host "OK: Added to '$NewGroup'" -ForegroundColor Green

# --- 3. Then remove from old group ---
Remove-MgGroupMemberDirectoryObjectByRef -GroupId $OldGrp.Id -DirectoryObjectId $User.Id
Write-Host "OK: Removed from '$OldGroup'" -ForegroundColor Green   
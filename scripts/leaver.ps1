$ErrorActionPreference = "Stop"

# --- Configuration ---
$UserUPN = "Zoe.Bennett@yourtenant.onmicrosoft.com"

Connect-MgGraph -Scopes "User.ReadWrite.All","GroupMember.ReadWrite.All","User.RevokeSessions.All" -NoWelcome

$User = Get-MgUser -UserId $UserUPN
Write-Host "Processing: $($User.DisplayName)" -ForegroundColor Cyan

# --- 1. Disable account (blocks NEW sign-ins) ---
Update-MgUser -UserId $User.Id -AccountEnabled:$false
Write-Host "OK: Account disabled" -ForegroundColor Green

# --- 2. Revoke sessions (kills EXISTING sign-ins) ---
Revoke-MgUserSignInSession -UserId $User.Id | Out-Null
Write-Host "OK: Sessions revoked" -ForegroundColor Green

# --- 3. Remove from all groups (frees the license automatically) ---
$Groups = Get-MgUserMemberOf -UserId $User.Id -All |
    Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }

foreach ($Grp in $Groups) {
    Remove-MgGroupMemberDirectoryObjectByRef -GroupId $Grp.Id -DirectoryObjectId $User.Id
    Write-Host "OK: Removed from $($Grp.AdditionalProperties.displayName)" -ForegroundColor Green
}

Write-Host "Leaver complete: $($User.DisplayName)" -ForegroundColor Cyan
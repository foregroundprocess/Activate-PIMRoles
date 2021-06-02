# PIM-Roles v.1.5
# This script activates PIM roles.
# Install AzureADPreview module first:
# install-module AzureADPreview -scope CurrentUser

import-module AzureADPreview

$MyID = '' # Put ID of your !admin account here. It can be found on Azure AD portal in Users section.
$AccountID = '' # Put your !admin UPN here
$ResourceID = ''    #ID of the tenant. Can be found on Azure AD portal.
$SkipRoles = @("62e90394-69f5-4237-9190-012177145e10", "e8611ab8-c189-46e8-94e1-60213ab1f814") #These roles won't be activated (Global Administrator and Privileged Role Administrator by default). You can add other roles.

$schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule #Create schedule for role assignments
$schedule.Type = "Once"
$schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$schedule.endDateTime = ($schedule.StartDateTime).AddHours(4)   #The number in brackets defines how many hours the roles will remain active.

if ([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens -eq $null -or ([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens).Count -eq 0) {
    #Check if there is an active connection
    Connect-AzureAD -AccountId $AccountID #If not, connect to AzureAD
}

Write-Host "Getting data from PIM..."
$Roles = Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles -ResourceId $ResourceID #Getting list of all roles in tenant
$PIMRoles = Get-AzureADMSPrivilegedRoleAssignment -ProviderId aadRoles -ResourceId $ResourceID -Filter "subjectid eq '$MyID'" #Getting list of all roles assigned to the account
Write-Host "`n"

Write-Host "Activating roles..."
foreach ($PIMrole in $PIMRoles) {
    if ($PIMRole.RoleDefinitionID -notin $SkipRoles -and $PIMRole.AssignmentState -eq "Eligible") {
        #Skip roles we don't want to activate and already active roles
        $RoleName = ($Roles | Where-Object { $_.ID -eq $PIMrole.RoleDefinitionId }).DisplayName #Obtaining name of the current role
        $RoleIsActive = $PIMRoles | Where-Object { $_.RoleDefinitionId -eq $PIMrole.RoleDefinitionId -and $_.AssignmentState -eq "Active" } #Checking if the role has been already activated
        if ($RoleIsActive -eq $null) {
            Write-Host "Activating $RoleName"
            Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId 'aadRoles' -ResourceId $ResourceID -RoleDefinitionId $PIMrole.RoleDefinitionID -SubjectId $MyID -Type 'UserAdd' -AssignmentState 'Active' -schedule $schedule -reason "BAU" #Activating the role
        }
        Else {
            Write-Host "$RoleName is already active"
        }
    }
}

Write-Host "`n"

#Display current activation status
Write-Host "Getting list of active roles..."
$role_result = [PSCustomObject]@{
    Name        = ""
    EndDateTime = ""
}

$PIMRoles = Get-AzureADMSPrivilegedRoleAssignment -ProviderId aadRoles -ResourceId $ResourceID -Filter "subjectid eq '$MyID'"
foreach ($PIMrole in $PIMRoles) {
    if ($PIMRole.AssignmentState -eq "Active") {
        #Selecting only active roles
        $role_result.Name = ($Roles | Where-Object { $_.ID -eq $PIMrole.RoleDefinitionId }).DisplayName
        $role_result.EndDateTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId(($PIMrole.EndDateTime), (Get-TimeZone).ID)
        $role_result
    }
}
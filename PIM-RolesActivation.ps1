# PIM-Roles v1.5.3
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

if ($null -eq [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens -or ([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens).Count -eq 0) {
    #Check if there is an active connection
    Connect-AzureAD -AccountId $AccountID #If not, connect to AzureAD
}

Write-Host "Getting data from PIM..."
$RoleDefinitions = Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles -ResourceId $ResourceID #Getting list of all roles in tenant
$PIMRoles = Get-AzureADMSPrivilegedRoleAssignment -ProviderId aadRoles -ResourceId $ResourceID -Filter "subjectid eq '$MyID'" #Getting list of all roles assigned to the account
Write-Host "`n"

Write-Host "Activating roles..."
$RoleIsActivated = $false
foreach ($PIMrole in $PIMRoles) {
    if ($PIMRole.RoleDefinitionID -notin $SkipRoles -and $PIMRole.AssignmentState -eq "Eligible") {
        #Skip roles we don't want to activate and already active roles
        $RoleName = ($RoleDefinitions | Where-Object { $_.ID -eq $PIMrole.RoleDefinitionId }).DisplayName #Obtaining name of the current role
        $RoleIsActive = $PIMRoles | Where-Object { $_.RoleDefinitionId -eq $PIMrole.RoleDefinitionId -and $_.AssignmentState -eq "Active" } #Checking if the role has been already activated
        if ($null -eq $RoleIsActive) {
            Write-Host "Activating $RoleName"
            Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId 'aadRoles' -ResourceId $ResourceID -RoleDefinitionId $PIMrole.RoleDefinitionID -SubjectId $MyID -Type 'UserAdd' -AssignmentState 'Active' -schedule $schedule -reason "BAU" #Activating the role
            $RoleIsActivated = $true
        }
        Else {
            Write-Host "$RoleName is already active"
        }
    }
}

Write-Host "`n"

#Display current activation status
if ($RoleIsActivated -eq $true) {
    Write-Host "Waiting for activation..."
    Start-Sleep 15
}
	
Write-Host "Getting list of active roles..."
$Output = @()
$ActiveAssignments = Get-AzureADMSPrivilegedRoleAssignment -ProviderId aadRoles -ResourceId $ResourceID -Filter "subjectid eq '$MyID'" | Where-Object { $_.AssignmentState -eq "Active" }
foreach ($ActiveAssignment in $ActiveAssignments) {
    $RoleAssignment = [PSCustomObject]@{
        Name        = ""
        EndDateTime = ""
    }
    $RoleAssignment.Name = ($RoleDefinitions | Where-Object { $_.ID -eq $ActiveAssignment.RoleDefinitionId }).DisplayName
    $RoleAssignment.EndDateTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId(($ActiveAssignment.EndDateTime), (Get-TimeZone).ID)
    $Output += $RoleAssignment
}
$Output | Format-Table
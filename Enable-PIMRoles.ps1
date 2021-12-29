#Requires -module AzureADPreview
<#
.SYNOPSIS
    Powershell script to activate Privileged Identity Management roles 
.DESCRIPTION
    Powershell script to activate Privileged Identity Management roles Before using the script you need to install the Azure AD Preview module
.EXAMPLE
    PS C:\> Enable-PIMRoles
    Enable all eligible roles in PIM
.EXAMPLE
    PS C:\> Enable-PIMRoles -FirstRun
    Enable all eligible roles in PIM and re-write SignInData.json file
.OUTPUTS
    List of the current roles states
.NOTES
    Install AzureAdPreview module using: Install-Module AzureAdPreview
    version: 1.6.2
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]
    $FirstRun
)

#region functions
function Export-AADSignInData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]
        $SignInDetails,

        [Parameter(Mandatory)]
        [string]
        $Path
    )
    $UserAccount = $SignInDetails.Account.Id
    $TenandId = $SignInDetails.TenantId.Guid

    $DataToExport = [PSCustomObject]@{
        Account  = $UserAccount
        TenandId = $TenandId
    }

    $DataToExport | ConvertTo-Json | Out-File $Path
    
}

function  Import-JsonConfigFile {
    param (
        [Parameter(Mandatory)]
        [string]
        $Path
    )

    Get-Content $Path | ConvertFrom-Json
    
}
#endregion

#region settings
$ScriptRoot = $PSScriptRoot
$ConfigPath = "$ScriptRoot\Config\Config.json"
$SignInDataFilePath = "$ScriptRoot\Config\SignInData.json"
$Config = Import-JsonConfigFile $ConfigPath
#endregion

#region import modules
import-module AzureADPreview
#endregion

#region sign-in
if ($FirstRun) {
    Remove-Item -Path $SignInDataFilePath
}

$SignInFileExists = [System.IO.File]::Exists($SignInDataFilePath)
if ($SignInFileExists) {
    $SignInData = Import-JsonConfigFile -Path $SignInDataFilePath
}

if($null -eq [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens -or ([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens).Count -eq 0){
    if (!$SignInFileExists) {
        try {
            $SignInData = AzureAdPreview\Connect-AzureAd -ErrorAction Stop
            Export-AADSignInData -SignInDetails $SignInData -Path $SignInDataFilePath
            $SignInData = [PSCustomObject]@{
                Account = $SignInData.Account.Id
                TenandId = $SignInData.tenant.Id
            }
        }
        catch {
            throw "Unable to establish connection to AAD. $($_.Exception)"
            break
        }
    }
    else{
        try {
            AzureAdPreview\Connect-AzureAd -AccountId $SignInData.Account
        }
        catch {
            throw "Unable to establish connection to AAD. $($_.Exception)"
            break
        }
    }
}
#endregion

#region activate roles
$MyID = (Get-AzureADUser -ObjectId $SignInData.Account).ObjectId

$ResourceID = $SignInData.TenandId
$SkipRoles = $Config.ScriptMainConfig.RolesExclusionList

$Schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule #Create schedule for role assignments
$Schedule.Type = "Once"
$Schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$Schedule.endDateTime = ($Schedule.StartDateTime).AddHours(4)   #The number in brackets defines how many hours the roles will remain active.

Write-Output "Getting data from PIM..."
$Roles = Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles -ResourceId $ResourceID #Getting list of all roles in tenant
$PIMRoles = Get-AzureADMSPrivilegedRoleAssignment -ProviderId aadRoles -ResourceId $ResourceID -Filter "subjectid eq '$MyID'" #Getting list of all roles assigned to the account
Write-Output "`n"

$RoleWasActivated = $false
Write-Output "Activating roles..."
foreach ($PIMrole in $PIMRoles) {
    if ($PIMRole.RoleDefinitionID -notin $SkipRoles -and $PIMRole.AssignmentState -eq "Eligible") {     #Skip Global Administrator and active roles
        $RoleName = ($Roles | Where-Object { $_.ID -eq $PIMrole.RoleDefinitionId }).DisplayName #Obtaining name of the current role
        $RoleIsActive = $PIMRoles | Where-Object { $_.RoleDefinitionId -eq $PIMrole.RoleDefinitionId -and $_.AssignmentState -eq "Active" } #Checking if the role has been already activated
        if ($null -eq $RoleIsActive) {
            Write-Output "Activating $RoleName"
            $RoleWasActivated = $true

            $RoleActivationSplat = @{
                ProviderId = 'aadRoles'
                ResourceId = $ResourceID
                RoleDefinitionId = $PIMrole.RoleDefinitionID
                SubjectId = $MyID
                Type = 'UserAdd'
                AssignmentState = 'Active' 
                Schedule = $schedule
                Reason = "BAU" #Activating the role
            }

            $Null = Open-AzureADMSPrivilegedRoleAssignmentRequest @RoleActivationSplat
        }
        Else {
            Write-Output "$RoleName is already active"
        }
    }
}
#endregion

#region wait and get list of active roles
Write-Output "`n"
	
Write-Output "Getting list of active roles. You don't have to wait and can stop the script now..."
$Output = @()
$ActiveAssignments = $null

$ActiveAssignmentsSplat = @{
    ProviderId = 'aadRoles'
    ResourceId = $ResourceID
    Filter = "subjectid eq '$MyID'"
}

if($RoleWasActivated){
    Start-Sleep -Seconds 30
}

$ActiveAssignments = Get-AzureADMSPrivilegedRoleAssignment @ActiveAssignmentsSplat | Where-Object { $_.AssignmentState -eq "Active" }
foreach ($ActiveAssignment in $ActiveAssignments) {
    $RoleAssignment = [PSCustomObject]@{
        Name        = ""
        EndDateTime = ""
    }
    $RoleAssignment.Name = ($Roles | Where-Object { $_.ID -eq $ActiveAssignment.RoleDefinitionId }).DisplayName
    if ($null -ne $($ActiveAssignment.EndDateTime)) {
        $RoleAssignment.EndDateTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId(($ActiveAssignment.EndDateTime), (Get-TimeZone).ID)
    }
    else{
        $RoleAssignment.EndDateTime = 'No data'
    }
    
    $Output += $RoleAssignment
}

$Output | Format-Table
#endregion
<#
    .SYNOPSIS
    This script disables service accounts.

    .DESCRIPTION
    The DisableSrvAccounts.ps1 script is used to disable service accounts in a Windows environment.

    .INPUTS
    A CSV file containing the sAMAccountName of the service accounts to be disabled.

    .OUTPUTS
    A log file containing the results of the script in C:\temp.

    .EXAMPLE
    DisableSrvAccounts.ps1

    .NOTES
    Author:        Patrick Horne
    Creation Date: 16/03/24

    Change Log:
    V1.0:         Initial Development
#>
function Get-OpenFileDialog {
    [CmdletBinding()]
    param (
        [string]
        $Directory = [Environment]::GetFolderPath('Desktop'),
        
        [string]
        $Filter = 'CSV (*.csv)| *.csv'
    )

    Add-Type -AssemblyName System.Windows.Forms
    $openFileDialog = [System.Windows.Forms.OpenFileDialog]::new()
    $openFileDialog.InitialDirectory = $Directory
    $openFileDialog.Filter = $Filter
    $openFileDialog.ShowDialog()
    $openFileDialog
}
function Import-ValidCSV {
    param (
        [parameter(Mandatory)]
        [ValidateScript({Test-Path $_ -type leaf})]
        [string]
        $inputFile,

        [string[]]
        $requiredColumns
    )

    $csvImport = Import-Csv -LiteralPath $inputFile
    $requiredColumns | ForEach-Object {
        if ($_ -notin $csvImport[0].psobject.properties.name) {
            Write-Error "$inputFile is missing the $_ column"
            exit
        }
    }
    $csvImport
}
function WriteLog {
    param (
        [string]$LogString
    )
        $Stamp      = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
        $LogMessage = "$Stamp $LogString"
        Add-Content $LogFile -Value $LogMessage
}

try {
    $logfilePath = "C:\temp\ServiceAccountDisableLog_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
    $null = $logfile = New-Item -Path $logfilePath -ItemType File -Force -ErrorAction Stop
    WriteLog "Log started on $(Get-Date)"
    Write-Host "Log file created at $logfilePath" -ForegroundColor Green
}
catch {
    Write-Host "Error creating or opening the log file: $_"
    exit
}

#requires -module ActiveDirectory

try {
    Write-Host "Select Service Account Input file" -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    WriteLog "Prompting for Service Account Input file"
    $csvPath = Get-OpenFileDialog
    $SvcUsers = @(Import-ValidCSV -inputFile $csvpath.FileName -requiredColumns 'sAMAccountName')
}
catch {
    Write-Host "An error occurred while importing the CSV file: $_" -ForegroundColor Yellow
    WriteLog "CSV was not selected or did not have the required column name"
    exit
}

$SvcUsersCount = $SvcUsers.Count

Write-Host "There are $SvcUsersCount Service Accounts to Disable" -ForegroundColor Cyan
Start-Sleep -Seconds 2

$Counter = 1
foreach ($SvcUser in $SvcUsers) {
    $sAMAccountName = $SvcUser.sAMAccountName
    $PercentComplete = [int](($Counter/$SvcUsersCount)*100)
    if ($null -ne $Host.UI.RawUI.WindowPosition) {  
        Write-Progress -Id 1 -Activity "Attempting to disable $sAMAccountName" -Status "$PercentComplete% Complete"  -PercentComplete $PercentComplete
    }
    $Counter++
    try {
        $User = Get-ADUser -Identity $sAMAccountName -Properties Description -ErrorAction Stop
        Write-Host "Getting $($User.sAMAccountName)" -ForegroundColor Green
        WriteLog "Getting $User"
        if  ($User.Enabled -eq $true ) {
                $oldDescription = $User.Description
                $newDescription = "Disabled on $(Get-Date -Format 'yyyy-MM-dd') under CHG00124 " + $oldDescription
                Set-ADUser -Identity $User -Description $newDescription -ErrorAction Stop
                Write-Host "Setting $($User.sAMAccountName) description to $newDescription" -ForegroundColor Green
                WriteLog "Setting $($User.sAMAccountName) description to $newDescription"
                $User | Disable-ADAccount -ErrorAction Stop
                Write-Host "$($User.sAMAccountName) has been disabled" -ForegroundColor Green
                WriteLog "$User has been disabled" 
        }
        else {
            Write-Host "$($User.sAMAccountName) was already disabled" -ForegroundColor Yellow
            WriteLog "$User is already disabled - No action taken"
        } 
    }
    catch {
        WriteLog "Error: $_"
    }
}
<#
    .SYNOPSIS
    This script disables service accounts.

    .DESCRIPTION
    The DisableSrvAccounts.ps1 script is used to disable a list of user accounts.

    .INPUTS
    A CSV file containing the sAMAccountName of the user accounts to be disabled.

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
    $SvcUsers = @(Import-ValidCSV -inputFile $csvpath.FileName -requiredColumns 'sAMAccountName' -ErrorAction Stop )
}
catch {
    Write-Host "An error occurred while importing the CSV file: $_" -ForegroundColor Yellow
    WriteLog "CSV was not selected or did not have the required column name"
    exit
}

Write-Host "There are $($SvcUsers.Count) Service Accounts to Disable" -ForegroundColor Cyan
Start-Sleep -Seconds 2

$continue = $true
while ($continue) {
    $changeNumber = Read-Host "Please Enter the Change Numnber you are performing this work under or press Q to Quit"
    if ($changeNumber.ToLower() -eq 'q') {
        Write-Host "Exiting Script" -ForegroundColor Yellow
        WriteLog "User pressed Q to Exit Script"
        exit
    }
    elseif ($changeNumber -match "^CHG\d{6}$") {
        Write-Host "Change Number is $($changeNumber.ToUpper())" -ForegroundColor Cyan
        WriteLog "Change Number is $($changeNumber.ToUpper())"
        $continue = $false
    }
    else {
        Write-Host "Invalid Change Number, please enter in the format CHGXXXXXX" -ForegroundColor Red
        WriteLog "Invalid Change Number entered"
    }
}

$Counter = 1
foreach ($SvcUser in $SvcUsers) {
    $PercentComplete = [int](($Counter/$($SvcUsers.Count))*100)
    if ($null -ne $Host.UI.RawUI.WindowPosition) {  
        Write-Progress -Id 1 -Activity "Attempting to disable $($SvcUser.sAMAccountName)" -Status "$PercentComplete% Complete"  -PercentComplete $PercentComplete
    }
    $Counter++
    try {
        Write-Host "Getting $($SvcUser.sAMAccountName)" -ForegroundColor Gray
        WriteLog "Getting $($SvcUser.sAMAccountName)"
        $User = Get-ADUser -Identity $SvcUser.sAMAccountName -Properties Description -ErrorAction Stop
    }
    catch {
        Write-Host "Error getting $($SvcUser.sAMAccountName): $_" -ForegroundColor Red
        WriteLog "Error getting $($SvcUser.sAMAccountName): $_"
        continue
    }
    if  ($User.Enabled -eq $true ) {
            $oldDescription = $User.Description
            WriteLog "$($User.sAMAccountName) old description was; $($oldDescription)"
            $newDescription = "Disabled on $(Get-Date -Format 'yyyy-MM-dd') under $($changeNumber.ToUpper()). " + $oldDescription
        Try {
            Write-Host "Setting $($User.sAMAccountName) description to $newDescription" -ForegroundColor Gray
            WriteLog "Setting $($User.sAMAccountName) description to $newDescription"
            Set-ADUser -Identity $User -Description $newDescription -ErrorAction Stop
            Write-Host "Success Setting $($User.sAMAccountName)'s description" -ForegroundColor Green
            WriteLog "Success setting $($User.sAMAccountName) new description"
        }
        catch {
            Write-Host "Error Setting $($User.sAMAccountName) description" -ForegroundColor Yellow
            WriteLog "Error Setting $($User.sAMAccountName) description"
        }
        Try {
            Write-Host "Attempting to disable $($User.sAMAccountName)" -ForegroundColor Gray
            WriteLog "Attempting to disable $($User.sAMAccountName)"
            $User | Disable-ADAccount -ErrorAction Stop
            Write-Host "$($User.sAMAccountName) has been disabled" -ForegroundColor Green
            WriteLog "$User has been disabled" 
        }
        catch {
            Write-Host "Error disabling $($User.sAMAccountName): $_" -ForegroundColor Red
            WriteLog "Error disabling $($User.sAMAccountName): $_"
            continue
        }
    }
    else {
        Write-Host "$($User.sAMAccountName) was already disabled, skipping" -ForegroundColor Yellow
        WriteLog "$($User.sAMAccountName) was already disabled - No action taken"
    } 
}
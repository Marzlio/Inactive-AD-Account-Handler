# Import required modules
Import-Module ActiveDirectory

# Define configuration parameters
$Config = @{
    OUsToInclude                = @("DC=yourdomain,DC=com")
    OUsToExclude                = @("OU=Special Users,DC=yourdomain,DC=com")
    TargetOU                    = "OU=Inactive Users,DC=yourdomain,DC=com"
    SMTPServer                  = "smtp.yourdomain.com"
    FromEmail                   = "admin@yourdomain.com"
    ToEmail                     = "it-support@yourdomain.com"
    EmailSubject                = "Accounts Disable Report and Error Log"
    AccountsReportCSV           = "C:\Powershell\Reports\accounts_to_disable_report.csv"
    TempCSV                     = "C:\Powershell\Temp\onprem_lastlogon.csv"
    DisableThresholdDays        = 15
    ReadOnlyMode                = $true
    DomainControllersToExclude  = @()
    DeleteErrorLogs             = $false
    LogChanges                  = $false
    LogFileExtension            = ".log"
    ErrorLogBasePath            = "C:\Powershell\Logs\error"
    ChangesLogBasePath          = "C:\Powershell\Logs\changes"
}

# Initialize-LogFile function
function Initialize-LogFile {
    param (
        [string]$BasePath,
        [string]$Extension = ".log",
        [boolean]$CreateNew,
        [string]$Type # "Error" or "Change"
    )
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $fileName = if ($CreateNew) { "$BasePath$Type_$timestamp$Extension" } else { "$BasePath$Type$Extension" }

    return $fileName
}

# Initialize log files based on configuration
$Config.ErrorLogFile = Initialize-LogFile -BasePath $Config.ErrorLogBasePath -Extension $Config.LogFileExtension -CreateNew (-not $Config.DeleteErrorLogs) -Type "Error"
if ($Config.LogChanges) {
    $Config.ChangesLogFile = Initialize-LogFile -BasePath $Config.ChangesLogBasePath -Extension $Config.LogFileExtension -CreateNew $true -Type "Change"
} else {
    $Config.ChangesLogFile = $null
}

# Log-Change function
function Log-Change {
    param(
        [string]$message
    )
    if ($Config.LogChanges -and $Config.ChangesLogFile) {
        Add-Content -Path $Config.ChangesLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
    }
}

# Function to check if a user is in an excluded OU
function IsUserInExcludedOUs {
    param(
        [string]$distinguishedName,
        [string[]]$OUsToExclude
    )
    foreach ($ou in $OUsToExclude) {
        if ($distinguishedName -like "*$ou*") {
            return $true
        }
    }
    return $false
}


# Function to get domain users with their last logon
function Get-DomainUsersWithLastLogon {
    param(
        [hashtable]$config
    )
        # Query all domain controllers to retrieve last login date and timestamp for all user accounts, adding an exclusion option
        $domainControllers = Get-ADDomainController -Filter * | Where-Object {
            $exclude = $false
            foreach ($excludedDC in $config.DomainControllersToExclude) {
                if ($_.HostName -eq $excludedDC) {
                    $exclude = $true
                    break
                }
            }
            -not $exclude
        }
        
    foreach ($ou in $config.OUsToInclude) {
        try {
            $adUsers = Get-ADUser -Filter {Enabled -eq $true} -SearchBase $ou -Properties LastLogon, LastLogonTimestamp, PasswordNeverExpires
            foreach ($user in $adUsers) {
                if (-not (IsUserInExcludedOUs -distinguishedName $user.DistinguishedName -OUsToExclude $config.OUsToExclude) -and $user.PasswordNeverExpires -eq $false) {
                    $lastLogons = foreach ($dc in $domainControllers) {
                        try {
                            $lastLogon = Get-ADUser -Identity $user -Server $dc.HostName -Properties LastLogon, LastLogonTimestamp
                            [PSCustomObject]@{
                                LastLogon         = $lastLogon.LastLogon
                                LastLogonTimestamp= $lastLogon.LastLogonTimestamp
                                DomainController  = $dc.HostName
                            }
                        }
                        catch {
                            Add-Content -Path $config.ErrorLogFile -Value "Error retrieving last logon for $($user.SamAccountName) from $($dc.HostName): $($_.Exception.Message)"
                        }
                    }
                    if ($lastLogons) {
                        $latestLogon = [DateTime]::FromFileTime(([Int64[]]$lastLogons.LastLogon | Measure-Object -Maximum).Maximum)
                        $latestLogonTimestamp = [DateTime]::FromFileTime(([Int64[]]$lastLogons.LastLogonTimestamp | Measure-Object -Maximum).Maximum)
                        $latestLogon = ($latestLogon, $latestLogonTimestamp) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
                        $users += [PSCustomObject]@{
                            SamAccountName = $user.SamAccountName
                            LastLogon      = $latestLogon
                        }
                    }
                }
            }
        }
        catch {
            Add-Content -Path $config.ErrorLogFile -Value "Error retrieving users from $($ou): $($_.Exception.Message)"
        }
    }
    $users | Export-Csv -Path $config.TempCSV -NoTypeInformation
    return $config.TempCSV
}

# Function to disable and move AD users
function Disable-AndMoveADUsers {
    param(
        [string]$csvPath,
        [hashtable]$config
    )
    if ($config.ReadOnlyMode -eq $true) {
        Write-Host "Running in read-only mode. No accounts will be disabled or moved."
        return
    }

    $disableDate = (Get-Date).AddDays(-$config.DisableThresholdDays)
    $accountsToDisable = Import-Csv -Path $csvPath | Where-Object {([DateTime]::Parse($_.LastLogon) -lt $disableDate)}

    foreach ($account in $accountsToDisable) {
        try {
            $user = Get-ADUser -Identity $account.SamAccountName
            Disable-ADAccount -Identity $user
            Log-Change -message "Disabled account: $($account.SamAccountName)"
            Move-ADObject -Identity $user.DistinguishedName -TargetPath $config.TargetOU
            Log-Change -message "Moved account: $($account.SamAccountName)to $($config.TargetOU)"
            Write-Host "Disabled and moved $($account.SamAccountName) to $($config.TargetOU)"
        }
        catch {
            Add-Content -Path $config.ErrorLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Error retrieving last logon for $($user.SamAccountName) from $($dc.HostName): $($_.Exception.Message)"
        }
    }
    $accountsToDisable | Select-Object SamAccountName, LastLogon | Export-Csv -Path $config.AccountsReportCSV -NoTypeInformation
}

# Function to send an email
function Send-Email {
    param(
        [hashtable]$config,
        [string[]]$attachmentPaths
    )
    $message = New-Object System.Net.Mail.MailMessage
    $message.From = $config.FromEmail
    $message.To.Add($config.ToEmail)
    $message.Subject = $config.EmailSubject
    $message.Body = "Please find the attached error log and accounts disable report. Note that lastLogonTimestamp is also being compared."

    foreach ($attachmentPath in $attachmentPaths) {
        if (Test-Path $attachmentPath) {
            $attachment = New-Object System.Net.Mail.Attachment -ArgumentList $attachmentPath
            $message.Attachments.Add($attachment)
        }
    }

    $smtpClient = New-Object System.Net.Mail.SmtpClient -ArgumentList $config.SMTPServer
    $smtpClient.Send($message)
}

# Script execution steps
$csvPath = Get-DomainUsersWithLastLogon -config $Config
Disable-AndMoveADUsers -csvPath $csvPath -config $Config
Send-Email -config $Config -attachmentPaths @($Config.ErrorLogFile, $Config.AccountsReportCSV)

# Cleanup
Remove-Item $Config.TempCSV -ErrorAction SilentlyContinue
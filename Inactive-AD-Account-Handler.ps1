# Define Configuration Parameters with Default Values
param(
    [string]$BasePath = "C:\Powershell\",
    [string]$Domain = "",
    [string]$ExcludeOUs = @(""),
    [string]$TargetOU = "",
    [string]$SMTPServer = "",
    [string]$FromEmail = "",
    [string]$ToEmail = "",
    [string]$EmailSubject = "Inactive-AD-Account-Handler report: Accounts Disable Report and Error Log",
    [string]$AccountsReportCSV = "Reports\accounts_to_disable_report.csv",
    [int]$DisableThresholdDays = 15,
    [bool]$DeleteErrorLogs = $false,
    [bool]$LogChanges = $true,
    [string]$LogFileExtension = ".log",
    [string]$ErrorLogBasePath = "Logs\error",
    [string]$ChangesLogBasePath = "Logs\changes",
    [string]$DomainControllersToExclude = @(),
    [switch]$Help
)

# Adjust paths based on the base path
$AccountsReportCSVFullPath = Join-Path -Path $BasePath -ChildPath $AccountsReportCSV
$ErrorLogBasePathFullPath = Join-Path -Path $BasePath -ChildPath $ErrorLogBasePath
$ChangesLogBasePathFullPath = Join-Path -Path $BasePath -ChildPath $ChangesLogBasePath

# Import Required Modules
Import-Module ActiveDirectory

$Config = @{
    BasePath                = $BasePath
    OUsToInclude            = @($Domain)
    OUsToExclude            = $ExcludeOUs
    TargetOU                = $TargetOU
    SMTPServer              = $SMTPServer
    FromEmail               = $FromEmail
    ToEmail                 = $ToEmail
    EmailSubject            = $EmailSubject
    AccountsReportCSV       = $AccountsReportCSVFullPath
    DisableThresholdDays    = $DisableThresholdDays
    DomainControllersToExclude = $DomainControllersToExclude
    DeleteErrorLogs         = $DeleteErrorLogs
    LogChanges              = $LogChanges
    LogFileExtension        = $LogFileExtension
    ErrorLogBasePath        = $ErrorLogBasePathFullPath
    ChangesLogBasePath      = $ChangesLogBasePathFullPath
}

if ($Help) {
    Write-Host "Usage: .\inactive-AD-Account-handler.ps1 [-BasePath <string>] [-Domain <string>] [-ExcludeOU <string>] [-TargetOU <string>] [-SMTPServer <string>] ..."
    Write-Host "       [-FromEmail <string>] [-ToEmail <string>] [-EmailSubject <string>] [-AccountsReportCSV <string>]"
    Write-Host "       [-DisableThresholdDays <int>] [-DeleteErrorLogs] ..."
    Write-Host "       [-LogChanges] [-LogFileExtension <string>] [-ErrorLogBasePath <string>] [-ChangesLogBasePath <string>]"
    Write-Host "       [-Help]"
    Write-Host ""
    Write-Host "Description:"
    Write-Host "This script identifies inactive user accounts in Active Directory, disables those accounts, moves them to a designated OU, and emails a report of the actions taken."
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "-BasePath <string>: Specifies the base file path for the script. Default is 'C:\Powershell\'."
    Write-Host "-Domain <string>: Specifies the LDAP path to the domain. Default is 'DC=yourdomain,DC=com'."
    Write-Host "-ExcludeOU <string>: LDAP path to an organizational unit (OU) that contains users who should not be processed. Default is 'OU=Special Users,DC=yourdomain,DC=com'."
    Write-Host "-TargetOU <string>: LDAP path to the OU where inactive accounts will be moved. Default is 'OU=Inactive Users,DC=yourdomain,DC=com'."
    Write-Host "-SMTPServer <string>: Address of the SMTP server used to send the email report. Default is 'smtp.yourdomain.com'."
    Write-Host "-FromEmail <string>: Email address that will appear as the sender of the report. Default is 'admin@yourdomain.com'."
    Write-Host "-ToEmail <string>: Email address to which the report will be sent. Default is 'it-support@yourdomain.com'."
    Write-Host "-EmailSubject <string>: Subject line for the email report. Default is 'Accounts Disable Report and Error Log'."
    Write-Host "-AccountsReportCSV <string>: File path where the report of accounts to be disabled will be saved. Default is 'Reports\accounts_to_disable_report.csv'."
    Write-Host "-DisableThresholdDays <int>: Number of days of inactivity before an account is considered inactive. Default is 15."
    Write-Host "-DeleteErrorLogs: If specified, existing error logs will be deleted at the start of the script run. Not specifying this keeps existing logs."
    Write-Host "-LogChanges: If specified, changes made by the script will be logged."
    Write-Host "-LogFileExtension <string>: The file extension to use for log files. Default is '.log'."
    Write-Host "-ErrorLogBasePath <string>: Base file path for error logs. Default is 'Logs\error'."
    Write-Host "-ChangesLogBasePath <string>: Base file path for change logs. Default is 'Logs\changes'."
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "Runs the script in read-only mode to report what would be changed without actually disabling or moving any accounts."
    Write-Host ""
    Write-Host ".\inactive-AD-Account-handler.ps1 -DisableThresholdDays 30"
    Write-Host "Runs the script with a custom threshold of 30 days of inactivity before disabling accounts."
    exit
}

# Initialize Log Files
function Initialize-LogFile {
    param (
        [string]$BasePath,
        [string]$Extension = ".log",
        [boolean]$CreateNew,
        [string]$Type # "Error" or "Change"
    )
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $fileName = if ($CreateNew) { Join-Path -Path $BasePath -ChildPath "$Type_$timestamp$Extension" } else { Join-Path -Path $BasePath -ChildPath "$Type$Extension" }
    return $fileName
}

$Config.ErrorLogFile = Initialize-LogFile -BasePath $Config.ErrorLogBasePath -Extension $Config.LogFileExtension -CreateNew (-not $Config.DeleteErrorLogs) -Type "Error"
$Config.ChangesLogFile = Initialize-LogFile -BasePath $Config.ChangesLogBasePath -Extension $Config.LogFileExtension -CreateNew $true -Type "Change"

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
    $users = @()
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
    return $users
}

# Function to disable and move AD users
function Disable-AndMoveADUsers {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [psobject[]]$users,
        [hashtable]$config
    )

    $disableDate = (Get-Date).AddDays(-$config.DisableThresholdDays)
    $accountsToDisable = $users | Where-Object {([DateTime]::Parse($_.LastLogon) -lt $disableDate)}

    foreach ($account in $accountsToDisable) {
        $user = Get-ADUser -Identity $account.SamAccountName -Properties *
        if ($PSCmdlet.ShouldProcess($user.Name, "Disable and move")) {
            Disable-ADAccount -Identity $user
            Move-ADObject -Identity $user.DistinguishedName -TargetPath $config.TargetOU
            Log-Change -message "Disabled account: $($account.SamAccountName)"
            Log-Change -message "Moved account: $($account.SamAccountName) to $($config.TargetOU)"
            Write-Host "Disabled and moved $($account.SamAccountName) to $($config.TargetOU)"
        }
    }
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

# Validate configuration before proceeding
function Validate-Config {
    param([hashtable]$config)
    if (-not (Test-Path $config.AccountsReportCSV)) {
        throw "AccountsReportCSV path is invalid or inaccessible."
    }
    # Additional validations should be added here at some point.
}

# Implement centralized error handling
try {
    # Validate configuration
    Validate-Config -config $Config

    # Main script execution
    $users = Get-DomainUsersWithLastLogon -config $Config
    Disable-AndMoveADUsers -users $users -config $Config
    $users | Export-Csv -Path $Config.AccountsReportCSV -NoTypeInformation
    Send-Email -config $Config -attachmentPaths @($Config.ErrorLogFile, $Config.AccountsReportCSV)
} catch {
    # Log error
    Add-Content -Path $Config.ErrorLogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - An unexpected error occurred: $($_.Exception.Message)"
    Write-Host "An error occurred. Please check the error log at $($Config.ErrorLogFile) for more details."
}
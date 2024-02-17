# Import configuration parameters
$configPath = "config.psd1"
$Config = Import-PowerShellDataFile -Path $configPath

# Determine the script's directory
$scriptPath = $PSScriptRoot

# Update configuration paths to be relative to the script's directory
$Config['ReportsPath'] = Join-Path -Path $scriptPath -ChildPath "Reports"
$Config['LogsPath'] = Join-Path -Path $scriptPath -ChildPath "Logs"


# Ensure the folder structure exists for reports and logs
$paths = @($Config.ReportsPath, $Config.LogsPath)
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory
    }
}

# Import required modules
Import-Module ActiveDirectory

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

# Function to get domain users
function Get-ADUsers {
    param([hashtable]$config)

    $allUsers = @()
    foreach ($ou in $config.OUsToInclude) {
        try {
            $users = Get-ADUser -Filter {Enabled -eq $true} -SearchBase $ou -Properties SamAccountName, DistinguishedName, LastLogonTimestamp, PasswordNeverExpires
            $allUsers += $users
        } catch {
        }
    }

    return $allUsers
}

function Get-LastLogonFromAllDCs {
    param(
        [string]$userName
    )


    $domainControllers = Get-ADDomainController -Filter * | Where-Object {
        $Config.DomainControllersToExclude -notcontains $_.HostName -and
        $Config.DomainControllersToExclude -notcontains $_.Name
    }

    $lastLogon = 0
    foreach ($dc in $domainControllers) {
        try {
            $userLastLogon = (Get-ADUser $userName -Server $dc.HostName -Properties LastLogon).LastLogon
            if ($userLastLogon -gt $lastLogon) {
                $lastLogon = $userLastLogon
            }
        } catch {
        }
    }

    if ($lastLogon -eq 0) {
    } else {
        $logonDate = [DateTime]::FromFileTime($lastLogon).ToString("yyyy-MM-dd HH:mm:ss")
    }

    return $lastLogon
}

# Function to get domain users with last logon
function Get-DomainUsersWithLastLogon {
    param(
        [array]$users
    )

    $filteredUsers = foreach ($user in $users) {
        # Get the most recent LastLogon from all DCs
        $lastLogon = Get-LastLogonFromAllDCs -userName $user.SamAccountName

        # If no LastLogon data was found, it's possible the user never logged on, or the data is unavailable
        # Compare LastLogonTimestamp and LastLogon to find the most recent
        if ($lastLogon -eq 0) {
            $mostRecentLogon = [DateTime]::FromFileTime($user.LastLogonTimestamp)
        } else {
            $lastLogonDateTime = [DateTime]::FromFileTime($lastLogon)
            $lastLogonTimestampDateTime = [DateTime]::FromFileTime($user.LastLogonTimestamp)
            if ([DateTime]::Compare($lastLogonDateTime, $lastLogonTimestampDateTime) -gt 0) {
                $mostRecentLogon = $lastLogonDateTime
            } else {
                $mostRecentLogon = $lastLogonTimestampDateTime
            }
        }

        [PSCustomObject]@{
            SamAccountName = $user.SamAccountName
            MostRecentLogon = $mostRecentLogon
        }
    }

    return $filteredUsers
}

# Function to get domain users that have never logged in
function Get-NeverLoggedOnADUsers {
    param(
        [array]$users
    )

    $neverLoggedOnUsers = $users | Where-Object { $_.LastLogonTimestamp -eq $null } | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName    = $_.SamAccountName
            DistinguishedName = $_.DistinguishedName
        }
    }

    return $neverLoggedOnUsers
}
# Function to get users with no password expiration
function Get-UsersWithNoExpire {
    param(
        [array]$users
    )

    $noExpireUsers = $users | Where-Object { $_.PasswordNeverExpires -eq $true } | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName    = $_.SamAccountName
            DistinguishedName = $_.DistinguishedName
        }
    }

    return $noExpireUsers
}

function Cleanup-OldReports {
    param(
        [string]$reportsPath,
        [int]$retentionCount
    )

    $allReports = Get-ChildItem -Path $reportsPath -Filter "*.csv" | Sort-Object LastWriteTime -Descending
    if ($allReports.Count -gt $retentionCount) {
        $oldReports = $allReports[$retentionCount..($allReports.Count - 1)]
        foreach ($report in $oldReports) {
            Remove-Item -Path $report.FullName -Force
        }
    }
}


# Function to send an email
function Send-Email {
    param(
        [hashtable]$config,
        [string]$reportsPath
    )


    if (-not $config.SMTPServer -or -not $config.FromEmail -or -not $config.ToEmail) {
        return
    }

    $message = New-Object System.Net.Mail.MailMessage
    $message.From = $config.FromEmail
    $message.To.Add($config.ToEmail)
    $message.Subject = $config.EmailSubject
    $message.Body = "Please find the attached error log and accounts disable report. Attached is the most recent report for each category."

    # Define report types to search for
    $reportTypes = @("last_logon_users_", "never_logged_on_users_", "no_expire_users_")

    foreach ($reportType in $reportTypes) {
        $latestReport = Get-ChildItem -Path $reportsPath -Filter "$reportType*.csv" |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 1

        if ($latestReport) {
            $attachmentPath = $latestReport.FullName
            $attachment = New-Object System.Net.Mail.Attachment -ArgumentList $attachmentPath
            $message.Attachments.Add($attachment)
        } else {
        }
    }

    $smtpClient = New-Object System.Net.Mail.SmtpClient($config.SMTPServer, $config.SMTPPort)
    $smtpClient.EnableSsl = $config.UseSSL

    # Check if SMTP authentication is required
    if ($config.SMTPUsername -and $config.SMTPPassword) {
        # Assuming SMTPPassword is securely stored or encrypted and needs to be decrypted here
        $securePassword = ConvertTo-SecureString $config.SMTPPassword -AsPlainText -Force
        $credentials = New-Object System.Net.NetworkCredential($config.SMTPUsername, $securePassword)
        $smtpClient.Credentials = $credentials
    }

    try {
        $smtpClient.Send($message)
    }
    catch {
    }
    finally {
        $smtpClient.Dispose()
    }
}

$allUsers = Get-ADUsers -config $Config
$lastLogonUsers = Get-DomainUsersWithLastLogon -users $allUsers
$neverLoggedOnUsers = Get-NeverLoggedOnADUsers -users $allUsers
$noExpireUsers = Get-UsersWithNoExpire -users $allUsers

# Current date in a specific format (e.g., YYYY-MM-DD)
$currentDate = Get-Date -Format "yyyy-MM-dd"

# Exporting reports with date included in the filename
$lastLogonReportPath = Join-Path -Path $Config['ReportsPath'] -ChildPath "last_logon_users_$currentDate.csv"
$neverLoggedOnReportPath = Join-Path -Path $Config['ReportsPath'] -ChildPath "never_logged_on_users_$currentDate.csv"
$noExpireReportPath = Join-Path -Path $Config['ReportsPath'] -ChildPath "no_expire_users_$currentDate.csv"
$lastLogonUsers | Export-Csv -Path $lastLogonReportPath -NoTypeInformation
$neverLoggedOnUsers | Export-Csv -Path $neverLoggedOnReportPath -NoTypeInformation
$noExpireUsers | Export-Csv -Path $noExpireReportPath -NoTypeInformation

# Call the updated Send-Email function with dynamic report paths
Send-Email -config $Config -reportsPath $Config['ReportsPath']
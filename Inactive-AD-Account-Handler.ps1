# Import configuration parameters
$configPath = "config.psd1"
$Config = Import-PowerShellDataFile -Path $configPath

# Check Execution Policy
$currentPolicy = Get-ExecutionPolicy
if ($currentPolicy -eq 'Restricted' -or $currentPolicy -eq 'AllSigned') {
    Write-Host "Current execution policy is '$currentPolicy'. The script requires 'RemoteSigned' or a less restrictive policy to run."
    Write-Host "Please change the execution policy to 'RemoteSigned' by running: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"
    exit
}

# Verify Active Directory Access
try {
    # Attempt to fetch a known AD user object as a test
    $testUser = Get-ADUser -Filter 'Name -like "Test User"' -ErrorAction Stop
    Write-Host "Active Directory access verified."
} catch {
    Write-Host "Failed to access Active Directory. Please ensure the script is run with appropriate permissions."
    exit
}

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

    $generalLogPath = $config.GeneralLogPath
    Write-GeneralLog -Message "Starting to fetch AD users from specified OUs." -Path $generalLogPath

    $allUsers = @()
    foreach ($ou in $config.OUsToInclude) {
        try {
            $users = Get-ADUser -Filter {Enabled -eq $true} -SearchBase $ou -Properties SamAccountName, DistinguishedName, LastLogonTimestamp, PasswordNeverExpires
            $allUsers += $users
            Write-GeneralLog -Message "Fetched users from OU: $ou" -Path $generalLogPath
        } catch {
            Write-ErrorLog -Message "Failed to fetch users from OU: $ou. Error: $_" -Path $config.ErrorLogPath
        }
    }

    return $allUsers
}

function Get-LastLogonFromAllDCs {
    param(
        [string]$userName
    )

    $generalLogPath = $Config.GeneralLogPath
    Write-GeneralLog -Message "Fetching last logon time for user: $userName from all Domain Controllers except exclusions." -Path $generalLogPath

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
            Write-ErrorLog -Message "Failed to fetch last logon for $userName from DC: $($dc.HostName). Error: $_" -Path $Config.ErrorLogPath
        }
    }

    if ($lastLogon -eq 0) {
        Write-GeneralLog -Message "No logon data found for $userName." -Path $generalLogPath
    } else {
        $logonDate = [DateTime]::FromFileTime($lastLogon).ToString("yyyy-MM-dd HH:mm:ss")
        Write-GeneralLog -Message "Latest logon for $userName is at $logonDate." -Path $generalLogPath
    }

    return $lastLogon
}

# Function to get domain users with last logon
function Get-DomainUsersWithLastLogon {
    param(
        [array]$users,
        [int]$inactiveDaysThreshold  # Parameter for the inactive days threshold
    )

    $filteredUsers = foreach ($user in $users) {
        # Check if the user is in any of the OUs to exclude for last logon checks
        if (-not (IsUserInExcludedOUs -distinguishedName $user.DistinguishedName -OUsToExclude $Config.OUsToExclude_Lastlogon)) {
            $lastLogon = Get-LastLogonFromAllDCs -userName $user.SamAccountName

            # Initialize the most recent logon time
            $mostRecentLogon = $null

            # Convert lastLogon to DateTime, if it's not 0; otherwise, use LastLogonTimestamp
            if ($lastLogon -eq 0) {
                if ($user.LastLogonTimestamp -ne $null) {
                    $mostRecentLogon = [DateTime]::FromFileTime($user.LastLogonTimestamp)
                }
            } else {
                $mostRecentLogon = [DateTime]::FromFileTime($lastLogon)
            }

            # Check if the most recent logon is defined and older than the inactive threshold
            if ($mostRecentLogon -ne $null) {
                $currentDate = Get-Date
                $inactiveDateThreshold = $currentDate.AddDays(-$inactiveDaysThreshold)

                if ($mostRecentLogon -lt $inactiveDateThreshold) {
                    [PSCustomObject]@{
                        SamAccountName    = $user.SamAccountName
                        DistinguishedName = $user.DistinguishedName
                        MostRecentLogon   = $mostRecentLogon
                    }
                }
            }
        }
    }

    return $filteredUsers
}

# Function to get domain users that have never logged in
function Get-NeverLoggedOnADUsers {
    param(
        [array]$users
    )

    $generalLogPath = $Config.GeneralLogPath
    $errorLogPath = $Config.ErrorLogPath

    # Log the start of fetching users who have never logged on
    Write-GeneralLog -Message "Starting to fetch users who have never logged on." -Path $generalLogPath

    $neverLoggedOnUsers = @()

    try {
        $neverLoggedOnUsers = $users | Where-Object { $_.LastLogonTimestamp -eq $null } | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
            }
        }

        # Log the count of never logged on users found
        $count = $neverLoggedOnUsers.Count
        Write-GeneralLog -Message "$count users who have never logged on were found." -Path $generalLogPath

    } catch {
        # Log any errors encountered during the fetching process
        Write-ErrorLog -Message "An error occurred while fetching users who have never logged on: $_" -Path $errorLogPath
    }

    return $neverLoggedOnUsers
}

# Function to get users with no password expiration
function Get-UsersWithNoExpire {
    param(
        [array]$users
    )

    $generalLogPath = $Config.GeneralLogPath
    $errorLogPath = $Config.ErrorLogPath

    # Log the start of fetching users with no expire set
    Write-GeneralLog -Message "Starting to fetch users with non-expiring passwords." -Path $generalLogPath

    $noExpireUsers = @()

    try {
        $noExpireUsers = $users | Where-Object { $_.PasswordNeverExpires -eq $true } | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
            }
        }

        # Log the count of users found
        $count = $noExpireUsers.Count
        Write-GeneralLog -Message "$count users with non-expiring passwords found." -Path $generalLogPath

    } catch {
        # Log any errors encountered during the process
        Write-ErrorLog -Message "An error occurred while fetching users with non-expiring passwords: $_" -Path $errorLogPath
    }

    return $noExpireUsers
}

function Cleanup-OldReports {
    param(
        [string]$reportsPath,
        [int]$retentionCount
    )

    $generalLogPath = $Config.GeneralLogPath
    $errorLogPath = $Config.ErrorLogPath

    # Log the start of the cleanup process
    Write-GeneralLog -Message "Starting cleanup of old reports." -Path $generalLogPath

    $allReports = Get-ChildItem -Path $reportsPath -Filter "*.csv" | Sort-Object LastWriteTime -Descending

    if ($allReports.Count -gt $retentionCount) {
        $oldReports = $allReports[$retentionCount..($allReports.Count - 1)]
        foreach ($report in $oldReports) {
            try {
                Remove-Item -Path $report.FullName -Force
                # Log successful deletion
                Write-GeneralLog -Message "Deleted old report: $($report.Name)" -Path $generalLogPath
            } catch {
                # Log any errors encountered during deletion
                Write-ErrorLog -Message "Failed to delete old report: $($report.Name). Error: $_" -Path $errorLogPath
            }
        }
    } else {
        Write-GeneralLog -Message "No old reports to delete. Retention count is set to $retentionCount." -Path $generalLogPath
    }
}

function Write-GeneralLog {
    param(
        [string]$Message,
        [string]$Path
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $Path -Append -Encoding UTF8
}

function Write-ErrorLog {
    param(
        [string]$Message,
        [string]$Path
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - ERROR - $Message" | Out-File -FilePath $Path -Append -Encoding UTF8
}

# Function to send an email
function Send-Email {
    param(
        [hashtable]$config,
        [string]$reportsPath
    )

    $generalLogPath = $config.GeneralLogPath
    $errorLogPath = $config.ErrorLogPath

    # Start sending email log
    Write-GeneralLog -Message "Starting to send email." -Path $generalLogPath

    if (-not $config.SMTPServer) {
        $message = "SMTPServer is not specified in the config. Email will not be sent."
        Write-GeneralLog -Message $message -Path $generalLogPath
        Write-Host $message
        return
    }

    $message = New-Object System.Net.Mail.MailMessage
    $message.From = $config.FromEmail
    $message.To.Add($config.ToEmail)
    $message.Subject = $config.EmailSubject
    $message.Body = "Please find the attached reports for disabled accounts and error logs."

    # Attach all reports generated by the script
    $reportFiles = Get-ChildItem -Path $reportsPath -Filter "*.csv"
    foreach ($file in $reportFiles) {
        $attachment = New-Object System.Net.Mail.Attachment -ArgumentList $file.FullName
        $message.Attachments.Add($attachment)
    }

    $smtpClient = New-Object System.Net.Mail.SmtpClient($config.SMTPServer, $config.SMTPPort)
    $smtpClient.EnableSsl = $config.UseSSL

    if ($config.SMTPUsername -and $config.SMTPPassword) {
        $smtpClient.Credentials = New-Object System.Net.NetworkCredential($config.SMTPUsername, $config.SMTPPassword)
    }

    try {
        $smtpClient.Send($message)
        $successMessage = "Email sent successfully."
        Write-GeneralLog -Message $successMessage -Path $generalLogPath
        Write-Host $successMessage
    } catch {
        $errorMessage = "Failed to send email. Error: $_"
        Write-ErrorLog -Message $errorMessage -Path $errorLogPath
        Write-Host $errorMessage
    }
}

$allUsers = Get-ADUsers -config $Config
$lastLogonUsers = Get-DomainUsersWithLastLogon -users $allUsers -inactiveDaysThreshold $Config.InactiveDaysThreshold
$neverLoggedOnUsers = Get-NeverLoggedOnADUsers -users $allUsers
$noExpireUsers = Get-UsersWithNoExpire -users $allUsers


# Get current date and time in a filesystem-friendly format
$currentDateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Process users who have not logged in within the threshold
foreach ($user in $lastLogonUsers) {
    if ($Config.WhatIfMode) {
        # If WhatIfMode is true, use the -WhatIf parameter
        Disable-ADAccount -Identity $user.SamAccountName -ErrorAction SilentlyContinue -WhatIf
        Move-ADObject -Identity $user.DistinguishedName -TargetPath $Config.TargetOU -ErrorAction SilentlyContinue -WhatIf
    } else {
        # If WhatIfMode is false, execute without -WhatIf
        Disable-ADAccount -Identity $user.SamAccountName -ErrorAction SilentlyContinue
        Move-ADObject -Identity $user.DistinguishedName -TargetPath $Config.TargetOU -ErrorAction SilentlyContinue
    }
}

# Adjust the message based on WhatIfMode
if ($Config.WhatIfMode) {
    Write-Output "User processing (disable and move) simulated with -WhatIf. Review the output."
} else {
    Write-Output "User processing (disable and move) executed."
}

# Assuming $neverLoggedOnUsers contains the users who have never logged in
if ($Config.DisableNeverLoggedOn) {
    foreach ($user in $neverLoggedOnUsers) {
        if ($Config.WhatIfMode) {
            # Simulate disabling if WhatIfMode is true
            Disable-ADAccount -Identity $user.SamAccountName -ErrorAction SilentlyContinue -WhatIf
        } else {
            # Actually disable the account if WhatIfMode is false
            Disable-ADAccount -Identity $user.SamAccountName -ErrorAction SilentlyContinue
        }

        # Optionally, move the disabled accounts to TargetOU (if required)
        # Check and implement based on your organizational policies
        if (-not $Config.WhatIfMode) {
            Move-ADObject -Identity $user.DistinguishedName -TargetPath $Config.TargetOU -ErrorAction SilentlyContinue
        }
    }

    # Log or print a message indicating that never logged on user processing is complete
    if ($Config.WhatIfMode) {
        Write-Output "Simulation: Never logged on user accounts would be disabled."
    } else {
        Write-Output "Never logged on user accounts have been disabled."
    }
}

# Setup report paths with date and time included in the filename
$lastLogonReportPath = Join-Path -Path $Config['ReportsPath'] -ChildPath "last_logon_users_$currentDateTime.csv"
$neverLoggedOnReportPath = Join-Path -Path $Config['ReportsPath'] -ChildPath "never_logged_on_users_$currentDateTime.csv"
$noExpireReportPath = Join-Path -Path $Config['ReportsPath'] -ChildPath "no_expire_users_$currentDateTime.csv"
$lastLogonUsers | Export-Csv -Path $lastLogonReportPath -NoTypeInformation
$neverLoggedOnUsers | Export-Csv -Path $neverLoggedOnReportPath -NoTypeInformation
$noExpireUsers | Export-Csv -Path $noExpireReportPath -NoTypeInformation

# Assuming reports are generated and saved in the specified ReportsPath
Send-Email -config $Config -reportsPath $Config['ReportsPath']
# After reports have been generated and emailed
Cleanup-OldReports -reportsPath $Config['ReportsPath'] -retentionCount $Config.ReportRetentionCount
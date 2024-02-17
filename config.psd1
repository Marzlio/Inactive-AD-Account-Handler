@{
    OUsToInclude = @()
    OUsToExclude = @()
    TargetOU = ""
    InactiveDaysThreshold = 15
    DisableNeverLoggedOn = $true  # Set to $false to skip disabling never logged on accounts
    WhatIfMode = $true  # Set to $false to execute account modifications
    DomainControllersToExclude = @("DC01.example.com", "DC02.example.com")  # Example domain controllers to exclude
    SMTPServer = ""  # Your SMTP server address
    SMTPPort = 587  # Common port for TLS/StartTLS. Use 465 for SSL.
    UseSSL = $true  # Set to $true for SSL/TLS
    SMTPUsername = "your_email@example.com"  # SMTP authentication username, if required
    SMTPPassword = "your_password"  # SMTP authentication password, consider encrypting this
    FromEmail = "your_email@example.com"
    ToEmail = "recipient_email@example.com"
    EmailSubject = "Accounts Disable Report and Error Log"
    ReportRetentionCount = 5
    LogFileExtension = ".log"
    GeneralLogPath = "Logs\General.log"  # Path for general activity log
    ErrorLogPath = "Logs\Error.log"      # Path for error log
}

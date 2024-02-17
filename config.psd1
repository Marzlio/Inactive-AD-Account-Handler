@{
    OUsToInclude = @()
    OUsToExclude = @()
    TargetOU = ""
    SMTPServer = ""
    SMTPPort = 587  # Default SMTP port for TLS/StartTLS
    UseSSL = $true  # Specifies if SSL/TLS should be used
    SMTPUsername = ""  # Optional: Required if the SMTP server needs authentication
    SMTPPassword = ""  # Optional: Required if the SMTP server needs authentication. Consider securing this.
    FromEmail = ""
    ToEmail = ""
    EmailSubject = "Accounts Disable Report and Error Log"
    DisableThresholdDays = 1
    ReadOnlyMode = $true
    DomainControllersToExclude = @()
    DeleteErrorLogs = $false
    LogChanges = $false
    LogFileExtension = ".log"
    ReportRetentionCount = 5  # Keep the 5 newest reports
    GeneralLogPath = "Logs\General.log"
    ErrorLogPath = "Logs\Error\Error.log"
    LoggingLevel = 'INFO'  # Options could be DEBUG, INFO, WARN, ERROR
    # Do not include dynamic paths here
}

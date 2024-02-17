
# Inactive-AD-Account-Handler

This PowerShell script, `Inactive-AD-Account-Handler.ps1`, automates the management of Active Directory (AD) user accounts. It identifies accounts that have been inactive for a specified period, disables those accounts, moves them to a designated Organizational Unit (OU), and generates a report detailing the actions taken. This script aids administrators in maintaining security and organizational efficiency by automating the lifecycle management of user accounts.

## Features

- **Customizable Inactivity Threshold**: Set a custom threshold for inactivity to identify inactive accounts.
- **Exclusion List**: Specify OUs from which users should not be disabled, protecting critical accounts.
- **Email Reporting**: Automatically generate and send reports detailing disabled accounts and encountered errors.
- **Logging**: Maintain detailed logs of actions taken and errors encountered for audit purposes.

## Prerequisites

Before running this script, ensure you have:

- PowerShell 5.1 or later.
- Active Directory PowerShell module.
- Required permissions for AD operations and email sending.

## Installation

1. **Download the Script**: Clone this repository or directly download the `Inactive-AD-Account-Handler.ps1` file.
2. **Install Active Directory PowerShell Module**:
   ```powershell
   Install-Module -Name ActiveDirectory
   ```
3. **Set Execution Policy**: Enable script execution with:
   ```powershell
   Set-ExecutionPolicy RemoteSigned
   ```

## Configuration

The script's behavior can be customized by adjusting parameters within the `$Config` hashtable in the script. Below is a description of each configuration option:

- `OUsToInclude`: Specifies the Organizational Units (OUs) from which users will be evaluated. Example: `@("OU=Users,DC=example,DC=com")`.
- `OUsToExclude`: OUs that should be excluded from the script's operations, preventing users within these OUs from being processed. Example: `@("OU=VIP,DC=example,DC=com")`.
- `TargetOU`: The Organizational Unit to which disabled accounts will be moved. Specify the LDAP path. Example: `"OU=DisabledAccounts,DC=example,DC=com"`.
- `InactiveDaysThreshold`: Number of days of inactivity after which a user account is considered inactive and subject to processing. Example: `15`.
- `DisableNeverLoggedOn`: If set to `$true`, accounts that have never logged on will be disabled. Set to `$false` to skip this action.
- `WhatIfMode`: Enables a simulation mode where no changes are made to Active Directory. Useful for planning and testing. Set to `$false` to apply changes.
- `DomainControllersToExclude`: Specifies domain controllers to exclude from the script's operations, useful in large environments or when certain DCs are unreachable. Example: `@("DC01.example.com", "DC02.example.com")`.
- `SMTPServer`: The address of the SMTP server used for sending email notifications. Example: `"smtp.example.com"`.
- `SMTPPort`: The port used by the SMTP server. Common ports are 587 for TLS/StartTLS and 465 for SSL.
- `UseSSL`: Specifies whether SSL/TLS is used for the SMTP connection. Set to `$true` for SSL/TLS.
- `SMTPUsername` and `SMTPPassword`: Credentials for SMTP server authentication. Consider securely handling the password.
- `FromEmail` and `ToEmail`: Email addresses for the sender and recipient(s) of the report, respectively.
- `EmailSubject`: Subject line for the email report sent by the script.
- `ReportRetentionCount`: The number of recent reports to retain. Older reports beyond this count will be deleted.
- `GeneralLogPath` and `ErrorLogPath`: Specifies paths for general and error logs, respectively, aiding in troubleshooting and audit.

Ensure to review and adjust these settings according to your environment's requirements and security policies.


## Troubleshooting

**Issue**: Script does not execute due to execution policy restrictions.
**Solution**: Ensure you've set the execution policy to allow script execution with `Set-ExecutionPolicy RemoteSigned`.

**Issue**: Email reports are not being sent.
**Solution**: Verify SMTP server details, and ensure the executing account has permission to send emails through the specified server.

## Contributing

Your contributions are welcome! To contribute:

1. Fork this repository.
2. Create a feature branch: `git checkout -b feature/YourFeature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/YourFeature`
5. Submit a pull request.

## License

This script is open-source under the MIT License, permitting free use, modification, and distribution with appropriate credit.

## Disclaimer

This script is provided "as is", with no warranties. Always test in a development environment before deploying to production.

## Contact

For support, feature requests, or to report bugs, please open an issue in the GitHub repository.

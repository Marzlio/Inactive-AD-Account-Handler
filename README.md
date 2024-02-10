
# Inactive-AD-Account-Handler

This PowerShell script, `Inactive-AD-Account-Handler.ps1`, automates the management of Active Directory (AD) user accounts. It identifies accounts that have been inactive for a specified period, disables those accounts, moves them to a designated Organizational Unit (OU), and generates a report detailing the actions taken. This script aids administrators in maintaining security and organizational efficiency by automating the lifecycle management of user accounts.

## Features

- **Customizable Inactivity Threshold**: Set a custom threshold for inactivity to identify inactive accounts.
- **Exclusion List**: Specify OUs from which users should not be disabled, protecting critical accounts.
- **Email Reporting**: Automatically generate and send reports detailing disabled accounts and encountered errors.
- **Read-Only Mode**: Generate reports without making changes, perfect for audit and compliance reviews.
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

Customize the script's behavior by modifying parameters within the `$Config` hashtable:

- `Domain`, `ExcludeOU`, `TargetOU`: Define LDAP paths for the domain and organizational units.
- `SMTPServer`, `FromEmail`, `ToEmail`: Set up email notification details.
- `DisableThresholdDays`: Define the inactivity threshold for disabling accounts.

## Detailed Usage

Execute the script in PowerShell with administrative privileges. You can run the script with default settings or specify parameters for customization:

```powershell
.\Inactive-AD-Account-Handler.ps1 -DisableThresholdDays 30 -LogChanges
```

### Parameters

- `-Domain <string>`: LDAP path for the domain.
- `-ExcludeOU <string>`: OU to exclude from processing.
- Additional parameters include `SMTPServer`, `FromEmail`, and `ToEmail` for detailed control over script operation.
- `WhatIf`: Simulate script execution without making changes.

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

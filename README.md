# Inactive-AD-Account-Handler
This PowerShell script identifies Active Directory (AD) user accounts that have not logged in for a specified number of days (default is 15 days), disables those accounts, and moves them to a designated Organizational Unit (OU). It is designed to help system administrators manage account lifecycles by automating the process of disabling and relocating inactive accounts, improving security and organizational cleanliness.

## Features

- **Customizable Inactivity Threshold**: Set the number of days an account can be inactive before it is considered for disabling.
- **Exclusion List**: Specify OUs to exclude from the script to protect critical accounts from being disabled.
- **Email Reporting**: Automatically sends an email report detailing which accounts were disabled and any errors encountered during the script's execution.
- **Read-Only Mode**: A read-only mode that generates reports without making any changes, useful for testing and verification purposes.

## Prerequisites

Before running this script, ensure you have the following:

- PowerShell 5.1 or higher.
- Active Directory PowerShell module installed.
- Appropriate permissions to read AD user properties, disable accounts, move objects within AD, and send emails from your server.

## Configuration

To configure the script to suit your environment, adjust the following parameters in the `$Config` hashtable:

- `OUsToInclude`: Array of OUs to include in the script's scope.
- `OUsToExclude`: Array of OUs to exclude from processing.
- `TargetOU`: The OU to which disabled accounts will be moved.
- `SMTPServer`, `FromEmail`, `ToEmail`: SMTP server and email addresses for sending reports.
- `DisableThresholdDays`: Number of days of inactivity threshold.
- `ReadOnlyMode`: Set to `$true` for report-only mode, `$false` to apply changes.

## Usage

1. **Open PowerShell**: Start PowerShell with the "Run as Administrator" option.
2. **Navigate to the Script**: Change your directory to where the script is located.
3. **Execute the Script**: Run the script by typing `.\Inactive-AD-Account-Handler.ps1`.

Ensure that you have configured the script's parameters according to your needs before running it.

## Contributing

Contributions to this script are welcome! If you have improvements or bug fixes, please follow these steps:

1. Fork the repository.
2. Create a new branch for your changes.
3. Submit a pull request with a detailed description of your changes.

## License

Specify your licensing information here. If not applicable, state that the script is available as open-source under the MIT License, allowing free use and distribution with attribution.

## Disclaimer

This script is provided "as is", without warranty of any kind. Use it at your own risk. Always test scripts in a non-production environment before deploying them into production.

## Contact

For support or to report issues create an issue in the GitHub repository.
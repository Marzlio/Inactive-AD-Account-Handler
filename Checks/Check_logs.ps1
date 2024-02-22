# Import the Active Directory Module
Import-Module ActiveDirectory

# Retrieve the list of all domain controllers in the domain
$domainControllers = Get-ADDomainController -Filter *

# Define the necessary audit policy categories to check
$requiredAuditPolicies = @{
    "AuditAccountManagement" = "Audit Account Management";  # Human-readable name
    "AuditLogonEvents" = "Audit Logon Events";              # Human-readable name
}

# Instruction link for enabling audit policies
$enableAuditPolicyLink = "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings"

# Loop through each domain controller
foreach ($dc in $domainControllers) {
    Write-Host "Checking audit policy on domain controller: $($dc.HostName)"
    
    # Check the audit policy configuration for each required policy
    foreach ($policyKey in $requiredAuditPolicies.Keys) {
        $policyName = $requiredAuditPolicies[$policyKey]
        $auditPolicyOutput = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            param($policyKey)
            AuditPol.exe /get /category:* | Select-String $policyKey
        } -ArgumentList $policyKey

        # Check if both Success and Failure auditing are enabled
        if ($auditPolicyOutput -match "Success and Failure") {
            Write-Host "$policyName on $($dc.HostName): Enabled for Success and Failure"
        } else {
            Write-Host "$policyName on $($dc.HostName): NOT fully enabled (Success and Failure required)."
            Write-Host "See how to enable audit policies at: $enableAuditPolicyLink"
        }
    }
}

# Define the time range to query changes. For example, the last 7 days
$startDate = (Get-Date).AddDays(-7)
$endDate = Get-Date

# Define the comprehensive list of event IDs for user, group, and computer management
$eventIDs = 4625, 4720, 4722, 4723, 4725, 4726, 4738, 4740, 4781, 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4754, 4756, 4757, 4758, 4741, 4742, 4743, 5136, 5137, 5138, 5139, 5141

# Loop through each domain controller
foreach ($dc in $domainControllers) {
    Write-Host "Checking domain controller: $($dc.HostName)"
    
    # Query the Security log on the current domain controller for the defined event IDs within the time range
    Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{
        LogName='Security';
        ID=$eventIDs;
        StartTime=$startDate;
        EndTime=$endDate
    } -ErrorAction SilentlyContinue | ForEach-Object {
        # Parse the Event for Details
        $eventXml = [xml]$_ | Select-Object -ExpandProperty ToXml
        $eventDetail = @{
            TimeCreated = $_.TimeCreated
            EventID = $_.Id
            Detail = $eventXml.Event.EventData.Data
        }
        # Output the event details
        [PSCustomObject]$eventDetail
    } | Format-Table -AutoSize
}

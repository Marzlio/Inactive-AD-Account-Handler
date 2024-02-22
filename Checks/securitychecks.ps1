Import-Module ActiveDirectory

# Initialize a script-wide variable to hold the domain controllers' reports
$global:dcReports = @{}

function Check-PasswordPolicyOnAllDCs {
    $domainControllers = Get-ADDomainController -Filter *
    foreach ($dc in $domainControllers) {
        $passwordPolicyResults = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
            return [PSCustomObject]@{
                Check       = "PasswordPolicy"
                Description = "Check Minimum Password Length"
                Value       = $passwordPolicy.MinPasswordLength
                Status      = if ($passwordPolicy.MinPasswordLength -lt 12) { "Fail" } else { "Pass" }
            }
        }
        
        if (-not $global:dcReports.ContainsKey($dc.Name)) {
            $global:dcReports[$dc.Name] = @()
        }

        $global:dcReports[$dc.Name] += $passwordPolicyResults
    }
}

function Check-AdminAccountExistence {
    $domainControllers = Get-ADDomainController -Filter *
    foreach ($dc in $domainControllers) {
        $adminExists = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            $adminAccount = Get-ADUser -Filter {SamAccountName -eq "Administrator"}
            if ($adminAccount) {
                return $true
            } else {
                return $false
            }
        }
        $result = if ($adminExists) { "Pass" } else { "Fail" }
        $description = "Check if Administrator account exists"
        $checkResult = [PSCustomObject]@{
            Check       = "AdminAccountExistence"
            Description = $description
            Value       = if ($adminExists) { "Exists" } else { "Does not exist" }
            Status      = $result
        }
        $global:dcReports[$dc.Name] += $checkResult
    }
}

function Check-WindowsFirewallStatus {
    $domainControllers = Get-ADDomainController -Filter *
    foreach ($dc in $domainControllers) {
        $firewallStatus = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            $status = Get-NetFirewallProfile -Profile Domain | Select-Object -ExpandProperty Enabled
            return $status
        }
        $enabledStatus = if ($firewallStatus -eq "True") { "Enabled" } else { "Disabled" }
        $result = if ($firewallStatus) { "Pass" } else { "Fail" }
        $description = "Windows Firewall Domain Profile Status"
        $checkResult = [PSCustomObject]@{
            Check       = "WindowsFirewallDomainProfile"
            Description = $description
            Value       = $enabledStatus
            Status      = $result
        }
        $global:dcReports[$dc.Name] += $checkResult
    }
}

function Check-AppliedPatchesOnAllDCs {
    $domainControllers = Get-ADDomainController -Filter *
    foreach ($dc in $domainControllers) {
        $latestPatch = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            $patches = Get-HotFix | Sort-Object -Property InstalledOn -Descending
            if ($patches.Count -gt 0) {
                $latestPatch = $patches[0]
                $lastPatchDate = [datetime]$latestPatch.InstalledOn
                $currentDate = Get-Date
                $timeSpan = $currentDate - $lastPatchDate
                $isWithin30Days = $timeSpan -lt [TimeSpan]::FromDays(30)
                return [PSCustomObject]@{
                    HotFixID    = $latestPatch.HotFixID
                    InstalledOn = $latestPatch.InstalledOn
                    IsRecent    = $isWithin30Days
                }
            } else {
                return [PSCustomObject]@{
                    HotFixID    = "N/A"
                    InstalledOn = "No patches applied"
                    IsRecent    = $false
                }
            }
        }

        $description = "Latest Applied Patch"
        $status = if ($latestPatch.IsRecent) { "Pass" } else { "Fail" }
        $checkResult = [PSCustomObject]@{
            Check       = "AppliedPatches"
            Description = $description
            Value       = "$($latestPatch.HotFixID) - $($latestPatch.InstalledOn)"
            Status      = $status
        }
        $global:dcReports[$dc.Name] += $checkResult
    }
}

function Check-AVStatusOnAllDCs {
    $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
    $avReport = @()

    foreach ($dc in $domainControllers) {
        $avStatus = Invoke-Command -ComputerName $dc -ScriptBlock {
            Import-Module Defender -ErrorAction SilentlyContinue
            $status = Get-MpComputerStatus
            if ($status) {
                return @{
                    ComputerName              = $env:COMPUTERNAME
                    AMServiceEnabled          = $status.AMServiceEnabled
                    AntispywareEnabled        = $status.AntispywareEnabled
                    AntivirusEnabled          = $status.AntivirusEnabled
                    RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
                    LastUpdate                = $status.AntivirusSignatureLastUpdated
                    UpdateStatus              = $status.NISEngineVersion
                }
            } else {
                return @{
                    ComputerName = $env:COMPUTERNAME
                    Status       = "Defender not found or disabled"
                }
            }
        }

        $avReport += New-Object PSObject -Property $avStatus
    }

    return $avReport
}

function Generate-DCReports {
    $global:dcReports.Keys | ForEach-Object {
        $dcName = $_
        $report = $global:dcReports[$dcName]
        $csvPath = "$PSScriptRoot\${dcName}_SecurityReport.csv"
        $report | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "Report for $dcName exported to $csvPath"
    }
}


# Execute Checks
Write-Host "Starting Security Best Practices Check across all Domain Controllers..."
Check-PasswordPolicyOnAllDCs
Check-AdminAccountExistence
Check-WindowsFirewallStatus
Check-AppliedPatchesOnAllDCs
Check-AVStatusOnAllDCs

# Generate AV Report
$avReport = Check-AVStatusOnAllDCs

# Export Report to CSV
$reportPath = "$PSScriptRoot\AVStatusReport.csv"
$avReport | Export-Csv -Path $reportPath -NoTypeInformation

Write-Host "AV Status Report generated at $reportPath"

# After all checks are complete, generate the reports
Generate-DCReports
Write-Host "Security Best Practices Check Completed."

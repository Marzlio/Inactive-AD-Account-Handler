# Function to retrieve domain controllers 
function Get-DomainControllers {
    try {
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        return $Domain.FindAllDomainControllers()
    } catch {
        Write-Error "Failed to retrieve domain controllers. Ensure you have appropriate permissions."
    }
}

# Get the list of domain controllers
$DomainControllers = Get-DomainControllers

# Iterate through each domain controller 
foreach ($DC in $DomainControllers) {
    $DCName = $DC.Name
    Write-Host "Processing: $DCName"

    # Generate filename based on the domain controller name
    $CSVOutputFile = "security_report_$DCname.csv" 

    # Execute the security product check remotely on the DC
    Invoke-Command -ComputerName $DCName -ScriptBlock {

        # Target Security Vendors 
        $AVVendors = "Crowdstrike", "Symantec", "McAfee", "Sophos", "Trend Micro", "Kaspersky" 

        # -------------------- Service Detection -------------------- 
        Get-Service | Where-Object { 
            $_.DisplayName -match ($AVVendors -join "|") 
        } | Select-Object Status, Name, DisplayName, StartType

        # -------------------- Registry Detection -------------------- 
        $RegPaths = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

        foreach ($path in $RegPaths) {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $_.DisplayName -match ($AVVendors -join "|") -or 
                    $_.Publisher -match ($AVVendors -join "|") 
                } | Select-Object DisplayName, Publisher, StartType
        }

        # -------------------- Detailed Microsoft Defender Check -------------------- 
        if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            Get-MpComputerStatus | Format-List -Property AMEngineVersion, AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled 
        } else {
            $DefenderPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
            if (Test-Path $DefenderPath) {
                Write-Host "Microsoft Defender likely present (older version)"
                Get-ItemProperty -Path $DefenderPath 
            }
        }

        # -------------------- Carbon Black Detection -------------------- 
        # Registry
        $CBRegPaths = "HKLM:\SOFTWARE\CarbonBlack",  "HKLM:\SOFTWARE\Wow6432Node\CarbonBlack"
        foreach ($path in $CBRegPaths) {
            if (Test-Path $path) {
                Write-Host "Carbon Black likely present"
                Get-ChildItem -Path $path | Get-ItemProperty
            }
        }

        # Carbon Black Service 
        Get-Service | Where-Object {$_.DisplayName -like "*Carbon Black*"}

    } | Export-Csv -Path $CSVOutputFile -NoTypeInformation  # Output to separate CSV file
}

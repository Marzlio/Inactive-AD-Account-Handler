@{
    OUsToInclude = @()
    OUsToExclude = @()
    TargetOU = ""
    InactiveDaysThreshold = 15
    DisableNeverLoggedOn = $true  # Set to $false to skip disabling never logged on accounts
    WhatIfMode = $true  # Set to $false to execute account modifications
    DomainControllersToExclude = @("DC01.example.com", "DC02.example.com")  # Example domain controllers to exclude
}

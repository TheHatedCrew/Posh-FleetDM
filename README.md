# Posh-FleetDM
PowerShell module for the FleetDM API.

Tested with PowerShell 5.1.x and 7.1.x, other versions may be unsupported.
This software is provided as is and without any form of warranty or guarantee.  Use at your own risk.
Version 4.0.0 available, tested with FleetDM 4.0.1.
Older versions are available that are compatible with older versions of FleetDM, but some may lack features.

**Loading the module:**

In PowerShell you need to execute the following command to import the module to make use of its functions:

    Import-Module .\Posh-FleetDM.psd1

**Get a list of commands available in the module:**

    Get-Command -Module Posh-FleetDM

**Getting help with any command in the module:**

    Get-Help Open-FleetSession
    Get-Help Remove-FleetHost
    .
    .

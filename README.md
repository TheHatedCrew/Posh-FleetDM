# Posh-FleetDM
PowerShell module for the FleetDM API.

Version 4.7.0, compatible with FleetDM 4.x.  Some features may only function with FleetDM 4.7 or newer.

- New FleetDM Policy commands.  (New, Get, Remove, Results.)
- New MaxHosts option on Get-FleetHosts command. (Optional, non-breaking.)
- Improved help.
- Removed Get-FleetWindowsHosts command.

Tested with PowerShell 5.1.x and 7.1.x, other versions may be unsupported.
This software is provided as is and without any form of warranty or guarantee.  Use at your own risk.

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

Please visit the releases page to download at https://github.com/TheHatedCrew/Posh-FleetDM/releases

$BaseFleetAPIPath = '/api/v1/fleet'
$DefaultTimeOut = 30
$DefaultConnectAuthTimeOut = 10
function Open-FleetSession
{
    <#
	    .SYNOPSIS
	    Creates a new FleetDM session.
	    .DESCRIPTION
	    This function creates a new token on the FleetDM server and returns a session object for use with other functions.
	    .PARAMETER ComputerName
	    The hostname, FQDN, or IP of the FleetDM host.
        .PARAMETER Port
	    The port used to communicate with the FleetDM host.
	    .PARAMETER Email
	    The email used to login to the FleetDM host.
        .PARAMETER Password
	    The password for the user used to login to the FleetDM host.
        .PARAMETER NoTLS
	    When enabled causes functions to use unsecure protocols to communicate with the FleetDM host.
        .EXAMPLE
	    Open-FleetSession -ComputerName examplehost.exampledomain.example -Port 80 -UserName exampleemail -Password examplepassword -NoTLS
        .EXAMPLE
        $ExampleFleetSession = Open-FleetSession examplehost 443 example examplepassword
	    .NOTES
	    Passwords for the FleetDM API are handled as plain text.  Certificate validation must be disabled if using self-signed certificates with TLS.
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [string]$ComputerName,
        [Parameter(Mandatory = $false,
        Position = 1)]
        [string]$Port = $null,
        [Parameter(Mandatory = $true,
        Position = 2)]
        [string]$Email,
        [Parameter(Mandatory = $true,
        Position = 3)]
        [string]$Password,
        [Parameter(Mandatory = $false)]
        [switch]$NoTLS
    )

    $Body = (@{'email'="$Email";'password'="$Password"} | ConvertTo-Json -Compress)
    Write-Verbose $Body

    If (-not $Port) {If ($NoTLS -eq $true) {$Port = 80} else {$Port = 443}}
    If ($NoTLS -eq $true) {$HPrefix = 'http://'; $WPrefix = 'ws://'} else {$HPrefix = 'https://'; $WPrefix = 'wss://'}

    $ComputerFullURI = ($HPrefix + $ComputerName + ':' + $Port + $BaseFleetAPIPath + '/login')
    Write-Verbose $ComputerFullURI

    $Token = Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -Uri $ComputerFullURI -Body $Body

    Write-Verbose $Token
    Write-Verbose $HPrefix
    Write-Verbose $WPrefix
    Write-Verbose $Port

    If ($null -eq $Token) {Return $null}

    $Session = [PSCustomObject]@{
        Token = $Token.token
        ServerHTTP = ($HPrefix + $ComputerName + ':' + $Port + $BaseFleetAPIPath)
        ServerWS = ($WPrefix + $ComputerName + ':' + $Port + $BaseFleetAPIPath)
    }

    Write-Verbose $Session

    Return $Session
}
function New-FleetSession
{
    <#
	    .SYNOPSIS
	    Creates a new FleetDM session variable using an existing token.
	    .DESCRIPTION
	    This function returns a session object for use with other functions.
	    .PARAMETER ComputerName
	    The hostname, FQDN, or IP of the FleetDM host.
        .PARAMETER Port
	    The port used to communicate with the FleetDM host.
	    .PARAMETER Token
	    The token used to authenticate to the FleetDM host.
        .PARAMETER NoTLS
	    When enabled causes functions to use unsecure protocols to communicate with the FleetDM host.
        .EXAMPLE
	    New-FleetSession -ComputerName examplehost.exampledomain.example -Port 80 -Token $ExampleToken -NoTLS
        .EXAMPLE
        $ExampleFleetSession = New-FleetSession examplehost 443 'oiafdf08w0ahf0hsdod0fj0as'
	    .NOTES
	    This function does not verify the validity of the token.  Certificate validation must be disabled if using self-signed certificates with TLS.
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [string]$ComputerName,
        [Parameter(Mandatory = $false,
        Position = 1)]
        [string]$Port = $null,
        [Parameter(Mandatory = $true,
        Position = 2)]
        [string]$Token,
        [Parameter(Mandatory = $false)]
        [switch]$NoTLS
    )

    If (-not $Port) {If ($NoTLS -eq $true) {$Port = 80} else {$Port = 443}}
    If ($NoTLS -eq $true) {$HPrefix = 'http://'; $WPrefix = 'ws://'} else {$HPrefix = 'https://'; $WPrefix = 'wss://'}

    Write-Verbose $Token
    Write-Verbose $HPrefix
    Write-Verbose $WPrefix
    Write-Verbose $Port

    $Session = [PSCustomObject]@{
        Token = $Token
        ServerHTTP = ($HPrefix + $ComputerName + ':' + $Port + $BaseFleetAPIPath)
        ServerWS = ($WPrefix + $ComputerName + ':' + $Port + $BaseFleetAPIPath)
    }

    Write-Verbose $Session

    Return $Session
}
function Close-FleetSession
{
    <#
	    .SYNOPSIS
	    Closes a FleetDM session.
	    .DESCRIPTION
	    This function ends a session causing the token to become invalid.
        .PARAMETER Session
	    The FleetDM Session variable.
        .EXAMPLE
	    Close-FleetSession -Session $ExampleFleetSession
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/logout')
    Write-Verbose $ComputerFullURI

    Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
}
function Get-FleetSessionUser
{
    <#
	    .SYNOPSIS
	    Returns user information for the FleetDM session.
	    .DESCRIPTION
	    This function will return the user information associated with the FleetDM token of the session.
        .PARAMETER Session
	    The FleetDM Session variable.
        .EXAMPLE
	    Get-FleetSessionUser -Session $ExampleFleetSession
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/me')
    Write-Verbose $ComputerFullURI

    $UserInfo = Invoke-RestMethod -Method 'GET' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $UserInfo

    If ($null -eq $UserInfo) {Return $null} else {Return $UserInfo.user}
}
function Get-FleetHosts
{
    <#
	    .SYNOPSIS
	    Returns FleetDM hosts list.
	    .DESCRIPTION
	    This function returns a list of all hosts registered with FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .EXAMPLE
	    Get-FleetHosts -Session $ExampleFleetSession
        .NOTES
        This function can return a maximum of 10,000 hosts.
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/hosts?page=0&per_page=10000&order_key=hostname')
    Write-Verbose $ComputerFullURI

    $HostInfo = Invoke-RestMethod -Method 'GET' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $HostInfo

    If ($null -eq $HostInfo) {Return $null} else {Return $HostInfo.hosts}
}
function Get-FleetWindowsHosts
{
    <#
	    .SYNOPSIS
	    Returns FleetDM hosts list for Windows hosts.
	    .DESCRIPTION
	    This function returns a list of all Windows hosts registered with FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .EXAMPLE
	    Get-FleetWindowsHosts -Session $ExampleFleetSession
        .NOTES
        This function can return a maximum of 10,000 hosts.
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/hosts?page=0&per_page=10000&order_key=hostname')
    Write-Verbose $ComputerFullURI

    $HostInfo = Invoke-RestMethod -Method 'GET' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $HostInfo

    If ($null -eq $HostInfo) {Return $null} else {Return ($HostInfo.hosts | Where-Object {$_.platform -eq 'windows'})}
}
function Remove-FleetHost
{
    <#
	    .SYNOPSIS
	    Removes a host from FleetDM.
	    .DESCRIPTION
	    This function removes the specified host from FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER HostID
	    The ID of the host to remove from FleetDM.
        .EXAMPLE
	    Remove-FleetHost -Session $ExampleFleetSession -HostID 42
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [int]$HostID
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/hosts/' + $HostID)
    Write-Verbose $ComputerFullURI

    $HostInfo = Invoke-RestMethod -Method 'DELETE' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $HostInfo
}
function Get-FleetLabels
{
    <#
	    .SYNOPSIS
	    Returns FleetDM labels list.
	    .DESCRIPTION
	    This function returns a list of all labels saved in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .EXAMPLE
	    Get-FleetLabels -Session $ExampleFleetSession
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/labels')
    Write-Verbose $ComputerFullURI

    $LabelInfo = Invoke-RestMethod -Method 'GET' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $LabelInfo

    If ($null -eq $LabelInfo) {Return $null} else {Return $LabelInfo.labels}
}
function New-FleetLabel
{
    <#
	    .SYNOPSIS
	    Creates a new FleetDM label.
	    .DESCRIPTION
	    This function creates a new label in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER LabelName
	    The name of the new FleetDM label.
	    .PARAMETER LabelSQL
	    The SQL of the new FleetDM label.
        .PARAMETER LabelDescription
	    The description of the new FleetDM label.
        .PARAMETER LabelPlatform
        The platform for the new label.
        .EXAMPLE
	    New-FleetLabel -Session $ExampleFleetSession -LabelName 'Example Label' -LabelSQL "SELECT name FROM os_version WHERE name LIKE `'Microsoft Windows Server%`';" -LabelDescription 'MS Windows Servers.' -LabelPlatform 'windows'
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [string]$LabelName,
        [Parameter(Mandatory = $true,
        Position=2)]
        [string]$LabelSQL,
        [Parameter(Mandatory = $true,
        Position=3)]
        [string]$LabelDescription,
        [Parameter(Mandatory = $true,
        Position=4)]
        [string]$LabelPlatform
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $Body = (@{'description'="$LabelDescription";'name'="$LabelName";'query'="$LabelSQL";'platform'="$LabelPlatform"} | ConvertTo-Json -Compress)
    Write-Verbose $Body

    $ComputerFullURI = ($Session.ServerHTTP + '/labels')
    Write-Verbose $ComputerFullURI
    
    $LabelInfo = Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header -Body $Body
    Write-Verbose $LabelInfo

    If ($null -eq $LabelInfo) {Return $null} else {Return $LabelInfo.label}
}
function Remove-FleetLabel
{
    <#
	    .SYNOPSIS
	    Removes a FleetDM label.
	    .DESCRIPTION
	    This function removes a label in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER LabelID
        The ID of the label to remove from FleetDM.
        .EXAMPLE
	    Remove-FleetLabel -Session $ExampleFleetSession -LabelID 10
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [string]$LabelID
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/labels/id/' + $LabelID)
    Write-Verbose $ComputerFullURI
    
    $LabelInfo = Invoke-RestMethod -Method 'DELETE' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $LabelInfo
}

### EDIT AREA ###

function Get-FleetPolicies
{
    <#
	    .SYNOPSIS
	    Returns FleetDM polices.
	    .DESCRIPTION
	    This function returns a list of all policies saved in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .EXAMPLE
	    Get-FleetPolicies -Session $ExampleFleetSession
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/global/policies')
    Write-Verbose $ComputerFullURI

    $PolicyInfo = Invoke-RestMethod -Method 'GET' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $PolicyInfo

    If ($null -eq $PolicyInfo) {Return $null} else {Return $PolicyInfo.policies}
}
function New-FleetLabel
{
    <#
	    .SYNOPSIS
	    Creates a new FleetDM label.
	    .DESCRIPTION
	    This function creates a new label in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER LabelName
	    The name of the new FleetDM label.
	    .PARAMETER LabelSQL
	    The SQL of the new FleetDM label.
        .PARAMETER LabelDescription
	    The description of the new FleetDM label.
        .PARAMETER LabelPlatform
        The platform for the new label.
        .EXAMPLE
	    New-FleetLabel -Session $ExampleFleetSession -LabelName 'Example Label' -LabelSQL "SELECT name FROM os_version WHERE name LIKE `'Microsoft Windows Server%`';" -LabelDescription 'MS Windows Servers.' -LabelPlatform 'windows'
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [string]$LabelName,
        [Parameter(Mandatory = $true,
        Position=2)]
        [string]$LabelSQL,
        [Parameter(Mandatory = $true,
        Position=3)]
        [string]$LabelDescription,
        [Parameter(Mandatory = $true,
        Position=4)]
        [string]$LabelPlatform
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $Body = (@{'description'="$LabelDescription";'name'="$LabelName";'query'="$LabelSQL";'platform'="$LabelPlatform"} | ConvertTo-Json -Compress)
    Write-Verbose $Body

    $ComputerFullURI = ($Session.ServerHTTP + '/labels')
    Write-Verbose $ComputerFullURI
    
    $LabelInfo = Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header -Body $Body
    Write-Verbose $LabelInfo

    If ($null -eq $LabelInfo) {Return $null} else {Return $LabelInfo.label}
}
function Remove-FleetLabel
{
    <#
	    .SYNOPSIS
	    Removes a FleetDM label.
	    .DESCRIPTION
	    This function removes a label in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER LabelID
        The ID of the label to remove from FleetDM.
        .EXAMPLE
	    Remove-FleetLabel -Session $ExampleFleetSession -LabelID 10
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [string]$LabelID
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/labels/id/' + $LabelID)
    Write-Verbose $ComputerFullURI
    
    $LabelInfo = Invoke-RestMethod -Method 'DELETE' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $LabelInfo
}

### END EDIT AREA ###
function Get-FleetQueries
{
    <#
	    .SYNOPSIS
	    Returns FleetDM saved query list.
	    .DESCRIPTION
	    This function returns a list of all saved queries in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .EXAMPLE
	    Get-FleetQueryList -Session $ExampleFleetSession
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/queries')
    Write-Verbose $ComputerFullURI

    $QueryInfo = Invoke-RestMethod -Method 'GET' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $QueryInfo

    If ($null -eq $QueryInfo) {Return $null} else {Return $QueryInfo.queries}
}
function New-FleetQuery
{
    <#
	    .SYNOPSIS
	    Creates a new saved FleetDM query.
	    .DESCRIPTION
	    This function creates a new saved query in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER QueryName
	    The name of the new FleetDM query.
	    .PARAMETER QuerySQL
	    The SQL of the new FleetDM query.
        .PARAMETER QueryDescription
	    The description of the new FleetDM query.
        .EXAMPLE
	    New-FleetQuery -Session $ExampleFleetSession -QueryName 'Example Query' -QuerySQL 'SELECT * FROM osquery_info;' -QueryDescription 'Get OSQuery information.'
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [string]$QueryName,
        [Parameter(Mandatory = $true,
        Position=2)]
        [string]$QuerySQL,
        [Parameter(Mandatory = $false,
        Position=3)]
        [string]$QueryDescription = $null
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $Body = (@{'description'="$QueryDescription";'name'="$QueryName";'query'="$QuerySQL"} | ConvertTo-Json -Compress)
    Write-Verbose $Body

    $ComputerFullURI = ($Session.ServerHTTP + '/queries')
    Write-Verbose $ComputerFullURI
    
    $QueryInfo = Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header -Body $Body
    Write-Verbose $QueryInfo

    If ($null -eq $QueryInfo) {Return $null} else {Return $QueryInfo.queries}
}
function Remove-FleetQuery
{
    <#
	    .SYNOPSIS
	    Removes a saved query from FleetDM.
	    .DESCRIPTION
	    This function removes the specified query from FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER QueryID
	    The ID of the query to remove from FleetDM.
        .EXAMPLE
	    Remove-FleetQuery -Session $ExampleFleetSession -QueryID 22
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [int]$QueryID
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $ComputerFullURI = ($Session.ServerHTTP + '/queries/id/' + $QueryID)
    Write-Verbose $ComputerFullURI

    $QueryInfo = Invoke-RestMethod -Method 'DELETE' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header
    Write-Verbose $QueryInfo
}
function Get-FleetQueryResults
{
    <#
	    .SYNOPSIS
	    Returns the results of a FleetDM live query.
	    .DESCRIPTION
	    This function returns the results of a running live query in FleetDM.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER QueryCampaignID
	    The ID of the query campaign from FleetDM.
	    .PARAMETER QueryTimeOut
	    The timeout in seconds for the FleetDM query.
        .EXAMPLE
	    Get-FleetQueryResults -Session $ExampleFleetSession -QueryCampaignID 123 -QueryTimeOut 120
        .NOTES
        This function should be called quickly after starting a live query to get accurate results.  This function is called automatically when using the -Results option on either Start-FleetQuery commands.
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [int]$QueryCampaignID,
        [Parameter(Mandatory = $false,
        Position=2)]
        [int]$QueryTimeOut = $DefaultTimeOut
    )

    $ComputerFullURI = ($Session.ServerWS + '/results/websocket')
    Write-Verbose $ComputerFullURI

    $FleetWebSocket = New-Object Net.WebSockets.ClientWebSocket
    $FleetCT = New-Object Threading.CancellationToken($false)
    
    Write-Verbose "ATTEMPTING WEBSOCKET CONNECTION"
    $TimeOutCounter = 0
    $FleetConnection = $FleetWebSocket.ConnectAsync($ComputerFullURI, $FleetCT)
    While (!$FleetConnection.IsCompleted -and ($TimeOutCounter -le ($DefaultConnectAuthTimeOut * 10))) { Start-Sleep -Milliseconds 100; $TimeOutCounter++ }
    If (!$FleetConnection.IsCompleted) {return $null}
    Write-Verbose "WEBSOCKET OPEN"

    $FleetAuth = (@{'type'='auth';'data'=@{'token'="$($Session.Token)"}} | ConvertTo-Json -Compress)
    $FleetCampaign = (@{'type'='select_campaign';'data'=@{'campaign_id'=$QueryCampaignID}} | ConvertTo-Json -Compress)
    [ArraySegment[byte]]$FleetAuthPayload = [Text.Encoding]::UTF8.GetBytes($FleetAuth)
    [ArraySegment[byte]]$FleetCampaignPayload = [Text.Encoding]::UTF8.GetBytes($FleetCampaign)
    Write-Verbose $FleetAuth
    Write-Verbose $FleetCampaign

    Write-Verbose "ATTEMPTING AUTH PAYLOAD SEND"
    $TimeOutCounter = 0
    $FleetCom = $FleetWebsocket.SendAsync($FleetAuthPayload, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $FleetCT)
    While (!$FleetCom.IsCompleted -and ($TimeOutCounter -le ($DefaultConnectAuthTimeOut * 10))) { Start-Sleep -Milliseconds 100; $TimeOutCounter++ }
    Write-Verbose "AUTH PAYLOAD SENT"

    Write-Verbose "ATTEMPTING CAMPAIGN PAYLOAD SEND"
    $TimeOutCounter = 0
    $FleetCom = $FleetWebsocket.SendAsync($FleetCampaignPayload, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $FleetCT)
    While (!$FleetCom.IsCompleted -and ($TimeOutCounter -le ($DefaultConnectAuthTimeOut * 10))) { Start-Sleep -Milliseconds 100; $TimeOutCounter++ }
    Write-Verbose "CAMPAIGN PAYLOAD SENT"

    $FleetRxBuffer = [Net.WebSockets.WebSocket]::CreateClientBuffer(1024,1024)
    $FleetRxResult = $null
    
    While (($FleetWebSocket.State -eq 'Open') -and ($FleetRxResult -notlike "*`"status`":`"finished`"*"))
    {
        Write-Verbose "WAITING FOR DATA FROM WEBSOCKET"

        $TimeOutCounter = 0
        $FleetCom = $FleetWebSocket.ReceiveAsync($FleetRxBuffer, $FleetCT)
        While ((!$FleetCom.IsCompleted) -and ($FleetWebSocket.State -eq 'Open') -and ($TimeOutCounter -le ($QueryTimeOut * 10))) {Start-Sleep -Milliseconds 100; $TimeOutCounter++; Write-Verbose "WAITING FOR WEBSOCKET BUFFER FILL $TimeOutCounter"}

        If ($FleetCom.IsCompleted) {$FleetRxResult += [Text.Encoding]::UTF8.GetString($FleetRxBuffer, 0, $FleetCom.Result.Count)} else {$FleetWebSocket.Dispose()}
        
        Write-Verbose $FleetRxResult
    }
    Write-Verbose "READ FROM WEBSOCKET COMPLETE"

    If ($FleetWebSocket.State -eq 'Open') {$FleetWebSocket.Dispose()}

    If ($null -eq $FleetRxResult) {return $null}
    else {
        $FleetReturnData = $FleetRxResult -replace '}{','},{'
        $FleetReturnData = '{"return":[' + $FleetReturnData + ']}'
        $FleetReturnData = (((($FleetReturnData | ConvertFrom-Json).return) | Where-Object {$_.type -eq 'result'}).data).rows
       Return $FleetReturnData
    }
}
function Start-FleetQuery
{
    <#
	    .SYNOPSIS
	    Starts a new FleetDM live query.
	    .DESCRIPTION
	    This function starts a new FleetDM live query using host or label ID numbers.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER Query
	    The SQL of the FleetDM query.
	    .PARAMETER Hosts
	    The array of FleetDM host IDs to target with the query.
        .PARAMETER Labels
        The array of FleetDM label IDs to target with the query.
        .PARAMETER QueryTimeOut
	    The timeout in seconds for the FleetDM query.
        .PARAMETER Results
	    Causes the command to return the results of the FleetDM query instead of the query information.
        .EXAMPLE
	    Start-FleetQuery -Session $ExampleFleetSession -Query 'SELECT * FROM osquery_info;' -Hosts @(123,456,789) -QueryTimeOut 60
        .EXAMPLE
        $ExampleResults = Start-FleetQuery -Session $ExampleFleetSession -Query 'SELECT * FROM osquery_info;' -Labels @(321,654,987) -Results
        .NOTES
        Using the -Results option will return the query results as an array of PowerShell objects.
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position=1)]
        [string]$Query,
        [Parameter(Mandatory = $false,
        Position=2)]
        [int[]]$Hosts = @(),
        [Parameter(Mandatory = $false,
        Position=3)]
        [int[]]$Labels = @(),
        [Parameter(Mandatory = $false,
        Position=4)]
        [int]$QueryTimeOut = $DefaultTimeOut,
        [Parameter(Mandatory = $false)]
        [switch]$Results
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $Body = (@{'query'="$Query";'selected'=@{'hosts'=$Hosts;'labels'=$Labels}} | ConvertTo-Json -Compress)
    Write-Verbose $Body

    $ComputerFullURI = ($Session.ServerHTTP + '/queries/run')
    Write-Verbose $ComputerFullURI

    $QueryID = Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header -Body $Body
    Write-Verbose $QueryID
    
    If ($null -eq $QueryID) {Return $null}
    If ($Results) {Return (Get-FleetQueryResults -Session $Session -QueryCampaignID $QueryID.campaign.id -QueryTimeOut $QueryTimeOut)} else {Return $QueryID.campaign}
}
function Start-FleetQueryUsingNames
{
    <#
	    .SYNOPSIS
	    Starts a new FleetDM live query.
	    .DESCRIPTION
	    This function starts a new FleetDM live query using host or label names.
        .PARAMETER Session
	    The FleetDM Session variable.
        .PARAMETER Query
	    The SQL of the FleetDM query.
	    .PARAMETER Hosts
	    The array of FleetDM host names to target with the query.
        .PARAMETER Labels
        The array of FleetDM label names to target with the query.
        .PARAMETER QueryTimeOut
	    The timeout in seconds for the FleetDM query.
        .PARAMETER Results
	    Causes the command to return the results of the FleetDM query instead of the query information.
        .EXAMPLE
	    Start-FleetQueryUsingNames -Session $ExampleFleetSession -Query 'SELECT * FROM osquery_info;' -Hosts @('host1.example.example','host2.example.example') -QueryTimeOut 60
        .EXAMPLE
        $ExampleResults = Start-FleetQueryUsingNames -Session $ExampleFleetSession -Query 'SELECT * FROM osquery_info;' -Labels @('MS Windows','Example Label') -Results
        .NOTES
        Using the -Results option will return the query results as an array of PowerShell objects.
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
        Position = 0)]
        [PSCustomObject]$Session,
        [Parameter(Mandatory = $true,
        Position = 1)]
        [string]$Query,
        [Parameter(Mandatory = $false,
        Position = 2)]
        [string[]]$Hosts,
        [Parameter(Mandatory = $false,
        Position = 3)]
        [string[]]$Labels,
        [Parameter(Mandatory = $false,
        Position=4)]
        [int]$QueryTimeOut = $DefaultTimeOut,
        [Parameter(Mandatory = $false)]
        [switch]$Results
    )
        
    $Header = @{'Authorization'="Bearer " + $Session.Token}
    Write-Verbose $Header.Authorization

    $Body = (@{'query'="$Query";'selected'=@{'hosts'=$Hosts;'labels'=$Labels}} | ConvertTo-Json -Compress)
    Write-Verbose $Body

    $ComputerFullURI = ($Session.ServerHTTP + '/queries/run_by_names')
    Write-Verbose $ComputerFullURI

    $QueryID = Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -Uri $ComputerFullURI -Headers $Header -Body $Body
    Write-Verbose $QueryID
    
    If ($null -eq $QueryID) {Return $null}
    If ($Results) {Return (Get-FleetQueryResults -Session $Session -QueryCampaignID $QueryID.campaign.id -QueryTimeOut $QueryTimeOut)} else {Return $QueryID.campaign}
}
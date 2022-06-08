[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-path $_})]
    [string]$ConfigurationPath
)
    Function Test-Port 
    {
        [CmdletBinding()]
        Param (
            [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$True)]
            [String[]]$ComputerName,
            [Int]$Port,
            [Int]$Timeout = 1000
        )
    
        Begin 
        {
            $result = [System.Collections.ArrayList]::new()
        }
        Process 
        {
            ForEach ($originalComputerName in $ComputerName) 
            {
                $remoteHostname = $originalComputerName
                $remotePort = $Port
    
                Try
                {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $portOpened = $tcpClient.ConnectAsync($remoteHostname, $remotePort).Wait($Timeout)
                }
                Catch
                {
                    $portOpened = $null
                }
                Finally
                {
                    $null = $result.Add([PSCustomObject]@{
                        RemoteHostname       = $remoteHostname
                        RemotePort           = $remotePort
                        PortOpened           = $portOpened
                        TimeoutInMillisecond = $Timeout
                        })
                }
            }
        }
        End 
        {
            Return $result
        }
    }
    Function Get-InstallationSource {
    [CmdletBinding()]
    Param(
        [string]$Url,
        [ValidateScript({Test-Path $_})]
        [string]$DownloadPath,
        [string]$FileName,
        [string]$ProxyServer

        )
    Begin {
        $HttpClient = [System.Net.WebClient]::new()
        if (![string]::IsNullOrEmpty($ProxyServer)) {
            $Proxy = [System.Net.WebProxy]::new($ProxyServer)
            $Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            $HttpClient.Proxy= $Proxy
        }
    }
    Process {
        try {
            
            $HttpClient.DownloadFile($url,"$DownloadPath\$FileName")
            $Message = "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Succesfully downloaded '$url'."
        }
        Catch {
            $Message =  "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Could Not Download File from url '$url'. Error: $($Error.Exception.Message)"
            Write-Error $Message
        }
        Finally{
            Write-Verbose $Message
            
        }

    }
    end {
        $HttpClient.Dispose()
    }
    }

Function Test-Inventory {
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [PsCustomObject]$InventoryObject
    )
Process {

    (-not ($InventoryObject.DependencyAgentExists -or $InventoryObject.LogAnalyticsAgentExists -or $InventoryObject.ArcAgentExists))
}
}

#region Script Main
Write-verbose "[$(Get-Date -Format G)]  Script Started."
# Prepare Running Host (Import Config, Create Directory, Dowload Files.)
try {
    $Config = Import-PowerShellDataFile -Path $ConfigurationPath -ErrorAction Stop
    if(-not (Test-path $Config.Settings.DownloadPath)) {
        New-Item -Path $Config.Settings.DownloadPath -ItemType Directory -ErrorAction stop | out-null 
    }
    if (-not $Config.Settings.DownloadManually) {
        $Config.Settings.DownloadUrls | Foreach-object {Get-InstallationSource -DownloadPath $Config.Settings.DownloadPath -Url $_.Url -FileName $_.FileName -ProxyServer $Config.Settings.ProxyServer -ErrorAction Stop}
    } else {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] skipping download. Please download files prior to script start."
    }
    
}
Catch {

    Throw "Could not read the configuration file '$ConfigurationPath' or could not Download Source files. Exiting Script. Error: $($error[0].Exception.Message)"
}
Try {
$Result = Start-Process -FilePath "$($Config.Settings.DownloadPath)\MMASetup-AMD64.exe" -ArgumentList @("/c","/t:$($Config.Settings.DownloadPath)") -Wait -Passthru -ErrorAction Stop
        if ($Result.ExitCode -eq 0) {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Successfuly extracted momagent.msi."} 

}
Catch {

    Throw "Coduld not extract files from 'MMASetup-AMD64.exe Error': $($error[0].Exception.Message)"
}
# Test for Wsman Success.
$ServerList = $config.Servers.ComputerName 
$Testresult = @($ServerList | test-port -port $Config.Settings.WsmanPort)
$FailedServers= $Testresult.Where({$_.PortOpened -ne $true}).RemoteHostname -Join ','

if ($FailedServers) {
Write-Verbose "[$(Get-Date -Format G)][$($Env:COMPUTERNAME)] Could not connect to following servers for using WSMAN. Will not work on these servers. Servers: '$FailedServers'"
}

# create Sessions
$Session = New-PSSession -ComputerName ($Testresult | where {$_.PortOpened -eq $true}).RemoteHostName

$InventoryScript = {
    $VerbosePreference=$using:VerbosePreference
    $InstalledSoftware = Get-ChildItem -path 'hklm:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','hklm:SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | ForEach-Object {$_.GetValue('DisplayNAme')}
    [PSCustomObject]@{
        DependencyAgentExists = $InstalledSoftware -contains 'Dependency Agent'
        LogAnalyticsAgentExists = $InstalledSoftware -contains 'Microsoft Monitoring Agent'
        ArcAgentExists = $InstalledSoftware -contains 'Azure Connected Machine Agent'
    }
}
$InstallScript = {
    Param($ServerSettings)
    $VerbosePreference=$using:VerbosePreference
    Write-Verbose "[$($Env:COMPUTERNAME)] Install operation started."
    # Install dependency agent
    $Result=Start-process -FilePath "$($ServerSettings.ServerTempPath)\InstallDependencyAgent-Windows.exe" -ArgumentList @('/S') -wait -PassThru
        if ($Result.ExitCode -eq 0) {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Installation Dependency Agent is succesful."} else {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Installation of Dependency Agent failed. ExitCode: $($Result.ExitCode) "
        }
    # Prepare Resource Tag String
    $TagsArray = Foreach ($Item in $ServerSettings.Tags.GetEnumerator()) {
        "$($Item.Name)=$($Item.Value)"
        }
    $TagsString = $TagsArray -join ','
    Write-verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Tags: '$TagsString'"
    
        # Install Log Analytics Agent without proxy
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] No proxy is defined. Agent will need direct access to endpoints."
        
        $ArgumentList = @("/i", "$($ServerSettings.ServerTempPath)\MOMAgent.msi" , "/l*v", "$($ServerSettings.ServerTempPath)\$($Env:ComputerName)_MOMAgent.log", "/qn", ' NOAPM=1', 'ADD_OPINSIGHTS_WORKSPACE=1',"OPINSIGHTS_WORKSPACE_ID=$($ServerSettings.WorkspaceId)", "OPINSIGHTS_WORKSPACE_KEY=$($ServerSettings.WorkspaceKey)", 'AcceptEndUserLicenseAgreement=1' )
        if (-not [string]::IsNullOrEmpty($ServerSettings.ProxyServer)) {
            Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] MMA agent will be configured to use proxy. Proxy = $($ServerSettings.ProxyServer)."
            $ArgumentList+="OPINSIGHTS_PROXY_URL=$($ServerSettings.ProxyServer)"
        }
        $Result = Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList $ArgumentList -Wait -PassThru
        
        if ($Result.ExitCode -eq 0) {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Installation of MMA agent is successful."} else {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Installation of MMA agent failed. ExitCode: $($Result.ExitCode) "
        }
        #>
        #Install Arc Agent
        
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $Result = Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList @("/i", "$($ServerSettings.ServerTempPath)\AzureConnectedMachineAgent.msi" , "/l*v", "$($ServerSettings.ServerTempPath)\$($Env:ComputerName)_AzureConnectedMachineAgent.log", "/qn") -Wait -PassThru
                if ($Result.ExitCode -eq 0) {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Installation of Azure Connected Machine Agent is successful."} else {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Installation of Azure Connected Machine Agent failed. ExitCode: $($Result.ExitCode) "
        }

        # set proxy if required
        if (-not [string]::IsNullOrEmpty($ServerSettings.ProxyServer)) {
            Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Arc agent will be configured to use proxy. Proxy = $($ServerSettings.ProxyServer)."
            $Result = Start-Process -FilePath "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList @('config', 'set', "proxy.url $($ServerSettings.ProxyServer)" ) -Wait -PassThru
            if ($Result.ExitCode -eq 0) {
                Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Sucessfully set proxy for Arc Agent."} else {
                Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Could not set proxy for arc agent. ExitCode: $($Result.ExitCode) "
                }
        }

        
        $Result = Start-Process -FilePath "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList @('connect', "--service-principal-id $($ServerSettings.servicePrincipalClientId)", "--service-principal-secret $($ServerSettings.servicePrincipalSecret)" , "--resource-group $($ServerSettings.ResourceGroup)", "--tenant-id $($ServerSettings.TenantID)", "--location $($ServerSettings.Location)","--subscription-id $($ServerSettings.Subscriptionid)","--cloud AzureCloud","--tags $TagsString","--correlation-id $($ServerSettings.CorrelationID)") -Wait -PassThru
                        if ($Result.ExitCode -eq 0) {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Onboarding of Azure Connected Machine Agent is successful."} else {
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Onboarding of Azure Connected Machine Agent failed. ExitCode: $($Result.ExitCode) "
        }
        
        Write-Verbose "[$($Env:COMPUTERNAME)][$(Get-Date -Format G)] Install operation ended."
    } 

Foreach ($server in $session) {
# get existing agents from Computers
$ExistingAgents = Invoke-Command -ScriptBlock $InventoryScript -Session $server

if ($ExistingAgents | Test-Inventory) {

$CreateFolder = {
    if (-not (Test-path $using:Config.Settings.ServerTempPath)) {
       New-Item -Path $using:Config.Settings.ServerTempPath -ItemType Directory -Force | out-null
    }

}
# Copy Files
Invoke-Command -Session $Session -ScriptBlock $CreateFolder
$FileList = $((gci $Config.Settings.DownloadPath | where {$_.Name -in @('AzureConnectedMachineAgent.msi','InstallDependencyAgent-Windows.exe','MOMAgent.msi')}).FullName)
Write-Verbose "[$($Server.ComptuerName)][$(Get-Date -Format G)] Files will be copied: '$($FileList -join ',')'"
$session | Foreach-object {Copy-Item $FileList -Destination $Config.Settings.ServerTempPath -ToSession $_ -Force}

# InstallAgents
$TagsHash = @{
    Name = 'Tags'
    Expression = {@(($Config.Servers | Where-Object {$_.ComputerName -eq $server.ComputerName}).Tags)}
}
$CorrelationIDhash = @{
    Name = 'CorrelationID'
    Expression = {(New-Guid).Guid}
}
$ServerSettings = [PsCustomObject]$Config.Settings | Select-Object -Property *,$TagsHash,$CorrelationIDhash

Invoke-Command -Session $Server -ScriptBlock $InstallScript -ArgumentList $ServerSettings
$OperationResult = Invoke-Command -Session $Server -ScriptBlock $InventoryScript
Write-Verbose "[$($Server.ComptuerName)][$(Get-Date -Format G)] Agents installed: $OperationResult"

} else {
    Write-Verbose "[$($Server.ComptuerName)][$(Get-Date -Format G)] one of the agents is already installed on $($Server.ComptuerName). AgentInfo: $ExistingAgents" 
}
}


#endregion
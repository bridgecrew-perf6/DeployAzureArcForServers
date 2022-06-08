@{  
    # Add your servers with the tags. At least one tag is required. 
    Servers =@(
        @{ComputerName = 'Server1.contoso.com';Tags = @{Environment='Prod';Role='AppServers'}}
        @{ComputerName = 'Server2.contoso.com';Tags = @{Environment='Test';Role='AppServers'}}
    )
    Settings = @{
        # Script will download the files from Downloarurls each time script runs on local machine to this DownloadPath folder. Script creates this folder if it does not exist.
        DownloadPath = 'c:\Downloads'
        # ServerTempPath is the folder for copying files on the remote computers. Script creates this folder if it does not exist.
        ServerTempPath = 'c:\ArcTemp'
        # Port for Remoting Test. Scirpt operates only on computers if this port is successfully connected. Do not change unless you have diffrent port for PowerShell Remoting.
        WSmanPort = 5985
        # Please do not change these urls below. these urls are the source for Agents.
        DownloadUrls = @(
            @{FileName = 'InstallDependencyAgent-Windows.exe';Url = 'https://aka.ms/dependencyagentwindows'}
            @{FileName = 'MMASetup-AMD64.exe';Url = 'https://download.microsoft.com/download/1/c/3/1c3e9669-63fc-4452-8a38-f66e1d7d26d7/MMASetup-AMD64.exe'}
            @{FileName = 'AzureConnectedMachineAgent.msi';Url = 'https://aka.ms/AzureConnectedMachineAgent'}
            #@{FileName = 'install_windows_azcmagent.ps1';Url = 'https://aka.ms/azcmagent-windows'}
        )
        DownloadManually = $false
        # Populate the below information from azure. Pretty self explanatory.
        ResourceGroup = 'ContosoAll'
        Location = 'WestEurope'
        TenantID = 'hedehofdo'
        WorkspaceKey = 'xxx'
        WorkspaceId = 'yyy'
        Subscriptionid = 'zzzz'
        ServicePrincipalClientId = 'asdfas-asdasd-asdsa'
        ServicePrincipalSecret = 'SALğ,pwoerZA'
        Cloud = 'AzureCloud'
        # If proxy is rquired set your proxy server below, if no proxy is required please set to $null
        ProxyServer = $null
    }
}

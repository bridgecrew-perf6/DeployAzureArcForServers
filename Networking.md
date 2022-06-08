## AzureArc Requirements for Azure Arc

TCP Port 443 for the following
- aka.ms
- download.microsoft.com
- packages.microsoft.com
- login.windows.net
- login.microsoftonline.com
- pas.windows.net
- management.azure.com
- *.his.arc.azure.com
- *.guestconfiguration.azure.com
- guestnotificationservice.azure.com
- *.guestnotificationservice.azure.com
- azgn*.servicebus.windows.net
- *.blob.core.windows.net
- dc.services.visualstudio.com

https://docs.microsoft.com/en-us/azure/azure-arc/servers/network-requirements

## Azure Automation Network Requirements
TCP Port 443 for the following
- Global URL: *.azure-automation.net 
- Agent service: https://<workspaceId>.agentsvc.azure-automation.net
- *.ods.opinsights.azure.com
- *.oms.opinsights.azure.com
- *.blob.core.windows.net
- *.azure-automation.net
- *.azure-automation.net

https://docs.microsoft.com/en-us/azure/automation/automation-network-configuration

## Log Analytics Agent 
443 and 80 for the following.
Please make sure (Bypass HTTPS Inspecection)
- *.ods.opinsights.azure.com
- *.oms.opinsights.azure.com
- *.blob.core.windows.net

https://docs.microsoft.com/en-us/azure/azure-monitor/agents/log-analytics-agent

## Windows Update
permit HTTP RANGE for following
- *.dl.delivery.mp.microsoft.com
- *.delivery.mp.microsoft.com
- *.download.windowsupdate.com

https://docs.microsoft.com/en-us/windows/deployment/update/windows-update-troubleshooting#issues-related-to-httpproxy

## WSUS
Your first WSUS server must have outbound access to ports 80 and 443 on the following domains:

- windowsupdate.microsoft.com
- *.windowsupdate.microsoft.com
- *.windowsupdate.microsoft.com
- *.update.microsoft.com
- *.update.microsoft.com
- *.windowsupdate.com
- download.windowsupdate.com
- download.microsoft.com
- *.download.windowsupdate.com
- wustat.windows.com
- ntservicepack.microsoft.com
- go.microsoft.com
- dl.delivery.mp.microsoft.com
- dl.delivery.mp.microsoft.com

https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus#:~:text=Your%20first%20WSUS%20server%20must,*.windowsupdate.microsoft.com 
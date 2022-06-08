# Deploy AzureArc for Servers

Azure Arc Agent bootstrapper script which installs all agents and configures the agents on multiple servers using PowerShell Remoting.

Prepare your Azure environment gather your configuration parameters and then leave the rest to the script.

- Installs agents only on bare metal servers. If any of the following agents are installed on the target server (regardless the version of the agent), script skips this server.
    - DependencyAgent
    - Log Analytics Agent
    - AzureConnected machine agent.
- All configuration is in a PSD file. The script requires only one parameter which is the path of this psd file.
- remote operations like script execution and file copy are all based on Powershell Remoting which needs to be enabled on target servers (by default it is enabled on 2012+ windows operating systems.)
- Current support is limited to Windows Servers.
- Scripts needs to be allowed in Execution Policy of the target servers.
- Tags must be specified. Resources with no tags assigned are likely to be unmanaged, script enforces to use them.


> **Note:** DSC isnt used, to prevent interference with existing dsc configurations, since we are installing only 3 agents and runnign 1-2 config lines dsc wasnt found to be feasible for such purpose.

# How To Run the script



# References
Useful links before starting to deploy Arc For Servers.
- [Firewall/Proxy requirements](Networking.md)
- [Preperation](Preperation.md)
- [Agents](Agents.md)

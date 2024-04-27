################################
### Puffin Security agent Installer for Powershell.
### Puffin Security - info@puffinsecurity.com
################################

<#
.SYNOPSIS
    PuffinSecurity Agent Uninstaller.
.DESCRIPTION
    This script uninstalls our agent from the system.
    For stability purposes Sysmon and VCRedis is left in the system.
    For details please check the website or contact us.
#>

$ErrorActionPreference      = "Stop"


$PROGRAM_FILES              = (${env:ProgramFiles(x86)}, ${env:ProgramFiles} -ne $null)[0]

$WAZUH_AGENT_DOWNLOAD_URL   = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi"
$WAZUH_INSTALLER_FILENAME   = "wazuh-agent-installer.msi"
$WAZUH_PATH                 = "$PROGRAM_FILES\ossec-agent"
$CUSTOMIZATIONS_PATH        = "$PROGRAM_FILES\ossec-agent\puffinsecurity\"

########
# Verify if the agent is installed
if (!(Get-Service wazuh-agent -ErrorAction SilentlyContinue)) {
    ########
    # Remove our customizations folder
    rm -r $CUSTOMIZATIONS_PATH

    ########
    # Download the installer and uninstall the agent
    Invoke-WebRequest -Uri $WAZUH_AGENT_DOWNLOAD_URL -OutFile $WAZUH_INSTALLER_FILENAME | Wait-Process
    msiexec.exe /x $WAZUH_INSTALLER_FILENAME /qn /quiet | Wait-Process

    rm $WAZUH_INSTALLER_FILENAME
}

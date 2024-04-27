################################
### Script to execute Chainsaw - Identify Malicious activity recorded in WinEvtLogs using Sigma Rules
### Originally created by SOCFortress LLP - info@socfortress.co
### Upgraded by PuffinSecurity - info@puffinsecurity.com
################################

##########
# Chainsaw Version: v2.5.0
##########

<#
.SYNOPSIS
    PuffinSecurity Chainsaw Runtime.
.DESCRIPTION
    This script runs Chainsaw and parses the output so our agent can pick it up.
#>

$ErrorActionPreference = "SilentlyContinue"

##########
# Variable Setup
$PROGRAM_FILES              = (${env:ProgramFiles(x86)}, ${env:ProgramFiles} -ne $null)[0]

$HUNT_START_TIMESTAMP       = Get-Date -Date (Get-Date).AddMinutes(-5).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S'

$CHAINSAW_PATH              = "$PROGRAM_FILES\ossec-agent\puffinsecurity\chainsaw"
$CHAINSAW_TMP_PATH          = "$env:TMP\chainsaw_output"
$CHAINSAW_TMP_OUTPUT        = "$env:TMP\chainsaw_output\results.json"

$SIGMA_ZIP_PATH             = "$CHAINSAW_PATH\sigma_all_rules.zip"
$SIGMA_WINDOWS_RULES_PATH   = "$CHAINSAW_PATH\rules\windows"
$SIGMA_MAPPINGS_PATH        = "$CHAINSAW_PATH\mappings\sigma-event-logs-all.yml"
$SIGMA_VERSION_FILE         = "$CHAINSAW_PATH\version.txt"
$SIGMA_RELEASES_URL         = "https://api.github.com/repos/SigmaHQ/sigma/releases"

$WINDOWS_EVENT_LOG_PATH     = "C:\Windows\System32\winevt"
$ACTIVE_RESPONSES_PATH      = "$PROGRAM_FILES\ossec-agent\active-response\active-responses.log"

##########
# Update Sigma Rules
function DownloadAndExtractSigma{
    Invoke-WebRequest -Uri $url -OutFile $SIGMA_ZIP_PATH
    Expand-Archive -Path $SIGMA_ZIP_PATH -DestinationPath $CHAINSAW_PATH -Force
    
    $releaseTag | Out-File $SIGMA_VERSION_FILE
}

# Get the latest release data from SIGMA
$releaseData = Invoke-RestMethod -Uri "$SIGMA_RELEASES_URL/latest"
$releaseTag = $releaseData.tag_name
$url = "$SIGMA_RELEASES_URL/$releaseTag/sigma_all_rules.zip"

if (Test-Path $SIGMA_VERSION_FILE) {
    # Read the last known version
    $lastKnownVersion = Get-Content $SIGMA_VERSION_FILE

    # Only download if the versions are different
    if ($lastKnownVersion -ne $releaseTag) {
        DownloadAndExtract
    }
} else {
    DownloadAndExtract
}

##########
# Hunt for events using Chainsaw
# Create Chainsaw Output Folder if it doesn't exist
If(!(test-path $CHAINSAW_TMP_PATH)) {
    New-Item -ItemType Directory -Force -Path $CHAINSAW_TMP_PATH
}

# Run Chainsaw and store JSONs in TMP folder
& '$CHAINSAW_PATH\chainsaw.exe' hunt $WINDOWS_EVENT_LOG_PATH -s $SIGMA_WINDOWS_RULES_PATH --mapping $SIGMA_MAPPINGS_PATH --from $HUNT_START_TIMESTAMP --output $CHAINSAW_TMP_OUTPUT --json --level high --level critical

##########
# Parse Chainsaw output
# Convert JSON to new line entry for every 'group'
function Convert-JsonToNewLine($json) {
    foreach($document in $json) {
        $document.document | ConvertTo-Json -Compress -Depth 99 | foreach-object {
            [pscustomobject]@{
                group = $document.group
                kind = $document.kind
                document = $_
                event = $document.document.data.Event.EventData
                path = $document.document.path
                system = $document.document.data.Event.System
                name = $document.name
                timestamp = $document.timestamp
                authors = $document.authors
                level = $document.level
                source = $document.source
                status = $document.status
                falsepositives = $document.falsepositives
                id = $document.id
                logsource = $document.logsource
                references = $document.references
                tags = $document.tags
            } | ConvertTo-Json -Compress
        }
    }
}

# Convert JSONs to new line entry and append to active-responses.log
Get-ChildItem $CHAINSAW_TMP_PATH -Filter *.json | Foreach-Object {
    $Chainsaw_Array = Get-Content $_.FullName | ConvertFrom-Json
    Convert-JsonToNewLine $Chainsaw_Array | Out-File -Append -Encoding ascii $ACTIVE_RESPONSES_PATH
}

##########
# Cleanup
rm -r $CHAINSAW_TMP_PATH

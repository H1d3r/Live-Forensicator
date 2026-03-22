
# Live Forensicator Powershell Script
# Coded by Ebuka John Onyejegbu

[cmdletbinding()]
param( 
    
    
  [String]$LOG4J,
  [String]$RAM,
  [String]$EVTX,
  [String]$OPERATOR,
  [String]$CASE,
  [String]$TITLE,
  [String]$LOCATION,
  [String]$DEVICE,
  [String]$RANSOMWARE,
  [String]$WEBLOGS,
  [String]$PCAP,
  [String]$HASHCHECK,
  [String]$ENCRYPTED,
  [switch]$UPDATE,
  [switch]$VERSION,
  [switch]$DECRYPT,
  [switch]$USAGE
)

$ErrorActionPreference = 'silentlycontinue'

##################################################
#region        Versioning & Update               #
##################################################
$version_file = $PSScriptRoot + "\" + "Updated" + "\" + "version.txt"
$current_version = $PSScriptRoot + "\" + "version.txt"

$MyVersion = Get-Content -Path .\version.txt

if ($VERSION.IsPresent) {
  Write-Host -Fore Cyan "[!] You are currently running $MyVersion" 
  Write-Host -Fore Cyan ''
  exit 0
}


##################################################
#region        Auto Check Update                 #
##################################################

$localVersion = Get-Content -Path "$PSScriptRoot\version.txt"

# GitHub repository details
$repoOwner = "johnng007"
$repoName = "Live-Forensicator"
$branch = "main"
$versionFile = "version.txt"
$rawUrl = "https://raw.githubusercontent.com/$repoOwner/$repoName/$branch/Windows/$versionFile"

# Function to check for updates
function CheckForUpdates {
  try {
    # Fetch the version from GitHub
    $remoteVersion = (Invoke-RestMethod -Uri $rawUrl).Trim() -replace '\s+'

    # Compare local and remote versions
    if ($localVersion -lt $remoteVersion) {
      Write-Host -ForegroundColor Cyan "[!] A new version $remoteVersion is available on Github. Please upgrade your copy of Forensicator."
    }
    else {
      Write-Host -ForegroundColor Cyan "[!] You are using the latest version $localVersion No updates available."
    }
  }
  catch {
    Write-Host -ForegroundColor Red "Failed to check for updates. You probably don't have an internet connection."
    Write-Host -ForegroundColor Red "Error: $_"
  }
}

# Call the function to check for updates
CheckForUpdates

#endregion 


$t = @"

___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                          $MyVersion

"@

for ($i = 0; $i -lt $t.length; $i++) {
  if ($i % 2) {
    $c = "red"
  }
  elseif ($i % 5) {
    $c = "yellow"
  }
  elseif ($i % 7) {
    $c = "green"
  }
  else {
    $c = "white"
  }
  Write-Host $t[$i] -NoNewline -ForegroundColor $c
}
Write-Host ''

Write-Host ''
Write-Host ''
Write-Host ''
Write-Host -ForegroundColor DarkCyan '[!] Live Forensicator'
Write-Host ''
Write-Host -ForegroundColor DarkCyan '[!] Performs Live Forensics on Live Hosts while grabbing required data for further analysis.'
Write-Host -ForegroundColor DarkCyan '[!] By Ebuka John Onyejegbu.'
Write-Host -ForegroundColor DarkCyan '[!] https://github.com/Johnng007/Live-Forensicator'
Write-Host ''


#################################################
##region Functions for Version Check and Update##
#################################################
if ($UPDATE) {
  Write-Host -Fore DarkCyan "[*] Downloading & Comparing Version Files" -Level INFO -Section "CORE"
  New-Item -Name "Updated" -ItemType "directory" -Force | Out-Null
  Set-Location Updated

  $destination = 'version.txt'

  if (((Test-NetConnection www.githubusercontent.com -Port 80 -InformationLevel "Detailed").TcpTestSucceeded) -eq $true) {
	
    Invoke-WebRequest -Uri $source -OutFile $rawUrl	
  }

  else {
    Write-Host -Fore DarkCyan "[*] githubusercontent.com is not reacheable, please check your connection" -Level WARN -Section "CORE"
    Set-Location $PSScriptRoot
    Remove-Item 'Updated' -Force -Recurse
    exit 0
  }

  if ((Get-FileHash $version_file).hash -eq (Get-FileHash $current_version).hash) {
	 
    Write-Host -Fore Cyan "[*] Congratualtion you have the current version" -Level SUCCESS -Section "CORE"
    Set-Location $PSScriptRoot
    Remove-Item 'Updated' -Force -Recurse
    exit
  }

  else {
    Write-Host -Fore DarkCyan "[!] You have an outdated version, we are sorting that out..." 
    $source = 'https://github.com/Johnng007/Live-Forensicator/archive/refs/heads/main.zip'
    $destination = 'Live-Forensicator-main.zip'
    Invoke-WebRequest -Uri $source -OutFile $destination
    Write-Host -Fore DarkCyan "[*] Extracting the downloads....." -Level INFO -Section "CORE"
    Expand-Archive -Force $PSScriptRoot\Updated\Live-Forensicator-main.zip -DestinationPath $PSScriptRoot\Updated 
    Write-Host -Fore DarkCyan "[*] Cleaning Up...." -Level INFO -Section "CORE"
    Remove-Item -Path $PSScriptRoot\Updated\Live-Forensicator-main.zip -Force
    Remove-Item -Path $PSScriptRoot\Updated\version.txt -Force
    Write-Host -Fore Cyan "[*] All Done Enjoy the new version in the Updated Folder"
    Set-Location $PSScriptRoot
    exit 0
  }	
} 

#endregion

##################################################
#region    ARTIFACT DECRYPTION SWITCH            #
##################################################

function Unprotect-FileNative {
    param(
        [string]$FilePath,
        [string]$KeyB64,
        [string]$Suffix = ".forensicator"
    )

    if(-not $FilePath.EndsWith($Suffix)){
        Write-ForensicLog -Fore Yellow "[!] $FilePath does not have expected suffix $Suffix" -Level WARN -Section "CRYPT"
        return
    }

    $outPath  = $FilePath -replace [regex]::Escape($Suffix),''
    $password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($KeyB64))

    try{
        $inStream = [System.IO.File]::OpenRead($FilePath)

        # Read the 16-byte salt written during encryption
        $salt = [byte[]]::new(16)
        [void]$inStream.Read($salt, 0, 16)

        $pbkdf2   = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                        $password, $salt, 100000,
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256
                    )
        $keyBytes = $pbkdf2.GetBytes(32)
        $ivBytes  = $pbkdf2.GetBytes(16)
        $pbkdf2.Dispose()

        $aes         = [System.Security.Cryptography.AesManaged]::new()
        $aes.Key     = $keyBytes
        $aes.IV      = $ivBytes
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $decryptor    = $aes.CreateDecryptor()
        $outStream    = [System.IO.File]::Create($outPath)
        $cryptoStream = [System.Security.Cryptography.CryptoStream]::new(
                            $inStream,
                            $decryptor,
                            [System.Security.Cryptography.CryptoStreamMode]::Read
                        )
        $cryptoStream.CopyTo($outStream)
    }
    catch{
        # Clean up incomplete output file if decryption failed
        # Most likely cause is a wrong key
        if($outStream){ $outStream.Dispose() }
        if(Test-Path $outPath){ Remove-Item $outPath -Force }
        throw
    }
    finally{
        if($cryptoStream){ $cryptoStream.Dispose() }
        if($outStream)   { $outStream.Dispose()    }
        if($inStream)    { $inStream.Dispose()     }
        if($decryptor)   { $decryptor.Dispose()    }
        if($aes)         { $aes.Dispose()          }
    }

    if(Test-Path $outPath){
        Remove-Item $FilePath -Force
    }
}


if($DECRYPT){

    $DefaultPath = "$PSScriptRoot\$env:COMPUTERNAME\"

    # Determine target path — check default location first
    if(Test-Path $DefaultPath){
        $forensicatorFiles = Get-ChildItem $DefaultPath -Filter "*.forensicator" -ErrorAction SilentlyContinue
    }

    if(-not $forensicatorFiles){
        Write-ForensicLog -ForegroundColor DarkCyan "[!] Cannot find encrypted file in default location." -Level WARN -Section "CRYPT"
        $TargetPath = Read-Host -Prompt "Enter full path to folder containing the encrypted file"

        # Validate the provided path exists and contains .forensicator files
        if(-not (Test-Path $TargetPath)){
            Write-ForensicLog -ForegroundColor Red "[!] Path does not exist: $TargetPath" -Level ERROR -Section "CRYPT"
            exit 1
        }

        $forensicatorFiles = Get-ChildItem "$TargetPath\*" -Filter "*.forensicator" -Recurse -Force |
                             Where-Object { -not $_.PSIsContainer }

        if(-not $forensicatorFiles){
            Write-ForensicLog -ForegroundColor Red "[!] No .forensicator files found in: $TargetPath" -Level ERROR -Section "CRYPT"
            exit 1
        }
    }
    else{
        $TargetPath = $DefaultPath
    }

    # Prompt for key
    $KeyInput = Read-Host -Prompt "Enter Decryption Key"

    if([string]::IsNullOrWhiteSpace($KeyInput)){
        Write-ForensicLog -ForegroundColor Red "[!] No key provided — aborting" -Level ERROR -Section "CRYPT"
        exit 1
    }

    # Validate key is valid Base64 before attempting decryption
    try{
        [void][Convert]::FromBase64String($KeyInput)
    }
    catch{
        Write-ForensicLog -ForegroundColor Red "[!] Key does not appear to be valid Base64 — check your key.txt" -Level ERROR -Section "CRYPT"
        exit 1
    }

    # Gather all .forensicator files under the target path
    $FilesToDecrypt = Get-ChildItem -Path "$TargetPath\*" `
                                    -Filter "*.forensicator" `
                                    -Recurse -Force |
                      Where-Object { -not $_.PSIsContainer }

    $total    = $FilesToDecrypt.Count
    $success  = 0
    $failed   = 0

    Write-ForensicLog -ForegroundColor DarkCyan "[*] Found $total file(s) to decrypt"

    foreach($file in $FilesToDecrypt){
        Write-ForensicLog "Decrypting $($file.Name)..."
        try{
            Unprotect-FileNative -FilePath $file.FullName -KeyB64 $KeyInput
            $success++
        }
        catch{
            Write-ForensicLog -ForegroundColor Red "[!] Failed to decrypt $($file.Name) — wrong key or corrupted file" -Level ERROR -Section "CRYPT"
            Write-ForensicLog -ForegroundColor Red "    $($_.Exception.Message)" -Level ERROR -Section "CRYPT"
            $failed++
        }
    }

    Write-ForensicLog -ForegroundColor Cyan "[!] Decryption complete — $success succeeded, $failed failed" -Level INFO -Section "CRYPT"

    exit 0
}
else{

}

#endregion 




##################################################
#region             USAGE                        #
##################################################

if ($USAGE) {
	
  Write-Host ''
  Write-Host -ForegroundColor Cyan 'FORESNSICATOR USAGE'
  Write-Host ''
  Write-Host -ForegroundColor DarkCyan 'Note: This may not be up to date please check github'
  Write-Host ''
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1   This runs the Basic checks on a system.'
  Write-Host ''
  Write-Host -ForegroundColor Cyan 'FLAGS'
  Write-Host -ForegroundColor Cyan 'The below flags can be added to the Basic Usage'
  Write-Host ''
  Write-Host -ForegroundColor DarkCyan '[*] -EVTX EVTX               Also grab Event Logs'
  Write-Host -ForegroundColor DarkCyan '[*] -WEBLOGS WEBLOGS         Also grab Web Logs.'
  Write-Host -ForegroundColor DarkCyan '[*] -PCAP PCAP               Run network tracing and capture PCAP for 120seconds'
  Write-Host -ForegroundColor Cyan "[!] requires the etl2pcapng file in share folder"
  Write-Host -ForegroundColor DarkCyan '[*] -RAM RAM                 Extract RAM Dump'
  Write-Host -ForegroundColor Cyan "[!] requires the winpmem file in share folder"
  Write-Host -ForegroundColor DarkCyan '[*] -LOG4J LOG4J             Checks for vulnerable log4j files'
  Write-Host -ForegroundColor DarkCyan '[*] -ENCRYPTED ENCRYPTED     Encrypts Artifacts after collecting them'
  Write-Host -ForegroundColor Cyan "[!] requires the FileCryptography file in share folder"
  Write-Host -ForegroundColor Cyan "[!] requires the Nirsoft BrowserView file in share folder"
  Write-Host -ForegroundColor DarkCyan '[*] -HASHCHECK HASHCHECK     Check executable hashes for latest malware'
  Write-Host -ForegroundColor DarkCyan ''
  Write-Host -ForegroundColor DarkCyan 'SWITCHES' 
  Write-Host -ForegroundColor DarkCyan ''
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1 -VERSION           This checks the version of Foresicator you have'
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1 -UPDATE            This checks for and updates your copy of Forensicator'
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1 -DECRYPT DECRYPT   This decrypts a Foresicator encrypted Artifact'
  Write-Host -ForegroundColor Cyan "[!] requires the FileCryptography file in share folder"
  Write-Host -ForegroundColor DarkCyan '[*] .\Forensicator.ps1 -USAGE             Prints this help file'

  exit 0
}
else {
	
}

#endregion 


#############################################################################################################
#region   LOGGING INITIALISATION
#############################################################################################################

$LogFolder    = "$PSScriptRoot\LOGS"
$LogTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile      = "$LogFolder\$env:COMPUTERNAME`_$LogTimestamp.log"

New-Item $LogFolder -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

$script:LogEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:ErrorCount = 0

# ---------------------------------------------------------
# DEFINE ALL FUNCTIONS FIRST before any execution code
# ---------------------------------------------------------
function Write-ForensicLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","CRITICAL","SUCCESS","FINDING")]
        [string]$Level   = "INFO",
        [string]$Section = "",
        [string]$Detail  = ""
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $script:LogEntries.Add([PSCustomObject]@{
        Timestamp = $timestamp
        Level     = $Level
        Section   = $Section
        Message   = $Message
        Detail    = $Detail
        Host      = $env:COMPUTERNAME
        User      = $env:USERNAME
    })

    $color = switch($Level){
        "INFO"     { "DarkCyan" }
        "WARN"     { "Yellow"   }
        "ERROR"    { "Red"      }
        "CRITICAL" { "Magenta"  }
        "SUCCESS"  { "Green"    }
        "FINDING"  { "Cyan"     }
        default    { "White"    }
    }

    Write-Host -ForegroundColor $color "[$timestamp][$Level]$(if($Section){" [$Section]"}) $Message$(if($Detail){" | $Detail"})"
    #Write-Host -ForegroundColor $color "$(if($Section){" [$Section]"}) $Message$(if($Detail){" | $Detail"})"
}

function Save-ForensicLogs {
    if($script:LogEntries.Count -eq 0){ return }

    try{
        $script:LogEntries | ConvertTo-Json -Depth 3 |
            Out-File "$LogFolder\$env:COMPUTERNAME`_$LogTimestamp`_structured.json" -Encoding UTF8

        $script:LogEntries | Export-Csv `
            "$LogFolder\$env:COMPUTERNAME`_$LogTimestamp`_structured.csv" `
            -NoTypeInformation -Encoding UTF8

        $findings = $script:LogEntries |
                    Where-Object { $_.Level -in @("FINDING","CRITICAL","ERROR") }

        $scripterror = $script:LogEntries |
                    Where-Object { $_.Level -in @("CRITICAL","ERROR") }

        if($findings.Count -gt 0){
            $findings | Export-Csv `
                "$LogFolder\$env:COMPUTERNAME`_$LogTimestamp`_findings_only.csv" `
                -NoTypeInformation -Encoding UTF8
        }

        Write-Host "[!] Logs saved to $LogFolder" -ForegroundColor Cyan
        Write-Host "[!] Total entries  : $($script:LogEntries.Count)" -ForegroundColor Cyan
        Write-Host "[!] Findings: $($findings.Count)" -ForegroundColor Cyan
        Write-Host "[!] Errors: $($scripterror.Count)" -ForegroundColor Cyan
        Write-Host "[!] System errors  : $($script:ErrorCount)" -ForegroundColor Cyan
    }
    catch{
        Write-Warning "[!] Could not save structured logs: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------
# NOW START TRANSCRIPT — functions are defined so catch
# block can safely call Write-ForensicLog
# ---------------------------------------------------------
Write-Host ""
try{
    Start-Transcript -Path $LogFile -Append -ErrorAction Stop
    #Write-ForensicLog "Transcript logging started: $LogFile" -Level INFO
}
catch{
    # Write-ForensicLog is now defined so this call is safe
    Write-ForensicLog "Could not start transcript: $($_.Exception.Message)" -Level WARN
}

# ---------------------------------------------------------
# GLOBAL ERROR HANDLER — Save-ForensicLogs now defined
# ---------------------------------------------------------
trap{
    $script:ErrorCount++
    Write-ForensicLog "UNHANDLED ERROR at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" -Level ERROR
    Write-ForensicLog $_.ScriptStackTrace -Level ERROR
    continue
}

Write-Host ""

# ---------------------------------------------------------
# EXIT HANDLER — Save-ForensicLogs now defined
# ---------------------------------------------------------
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Save-ForensicLogs
} | Out-Null

Write-ForensicLog "Forensicator Initialised on $env:COMPUTERNAME as $env:USERNAME" -Level INFO -Section "INFO"

#endregion



Write-Host ""

#################################################
#region      Defining Constants                 #
#################################################

# configuration file path
$configFile = "$PSScriptRoot\config.json"

# Read and parse the configuration file
$configData = Get-Content $configFile | ConvertFrom-Json

$Hostname = $env:computername

$userUID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

#endregion



##################################################
#region             CHECK ADMIN RIGHTS           #
##################################################

Write-ForensicLog "[*] Checking for administrative rights" -Level INFO -Section "CORE"

# Function to check if running as administrator
function Test-IsAdministrator {
  $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $isDomainAdmin = $currentUser.IsInRole("Domain Admins")
  return $isAdmin -or $isDomainAdmin
}

# Check if running as administrator
if (-not (Test-IsAdministrator)) {
  Write-ForensicLog "[!] Forensicator is not running with admin rights" -Level WARN -Section "CORE"
  Write-ForensicLog "[!] To get the best of results, please run as an admin!" -Level WARN -Section "CORE"

}
else {
  Write-ForensicLog "[!] Forensicator is running with admin rights" -Level SUCCESS -Section "CORE"
}

#endregion

Write-ForensicLog ""

##################################################
#region      Check if the share folder exists    #
##################################################

Write-ForensicLog "[*] Checking for Forensicator-Share folder" -Level INFO -Section "CORE"

$Folder = 'Forensicator-Share'

if (Test-Path -Path $Folder) {

  Write-ForensicLog "[!] Great, You have the Forensicator-Share folder" -Level SUCCESS -Section "CORE"
}
else {
  Write-ForensicLog "[!] Forensicator-Share folder not found, some flags and functions will not work! use the -UPDATE flag to import the complete Arsenal.." -Level WARN -Section "CORE"
  Write-ForensicLog "[!] Moving on...." -Level INFO -Section "CORE"
}

#endregion

Write-Host ""

#######################################################################
#region PARAMETER SETTINGS  ###########################################
#######################################################################

#FOR OPERATOR

if ($OPERATOR) {
   
  $Handler = $OPERATOR
   
} 
else {
	
  $Handler = Read-Host -Prompt 'Enter Investigator Name'	

}

#FOR CASE REFERENCE
if ($CASE) {
   
  $CASENO = $CASE
   
} 
else {
	
  $CASENO = Read-Host -Prompt 'Enter Case Reference'

}

#EXHIBIT REFERENCE
if ($TITLE) {
   
  $Ref = $TITLE
   
} 
else {
	
  $Ref = Read-Host -Prompt 'Enter Investigation Title'

}

#LOCATION
if ($LOCATION) {
   
  $Loc = $LOCATION
   
} 
else {
	
  $Loc = Read-Host -Prompt 'Enter examination location'

}

#DESCRIPTION
if ($DEVICE) {
   
  $Des = $DEVICE
   
} 
else {
	
  $Des = Read-Host -Prompt 'Enter description of device e.g. "Asus Laptop"'

}


#endregion

Write-Host ""

#Write-ForensicLog "[*] Starting Forensicator on $env:COMPUTERNAME with parameters: Handler=$Handler, Case=$CASENO, Title=$Ref, Location=$Loc, Description=$Des" -Level INFO -Section "CORE"


$ForensicatorDateFormat = "yyyy'-'MM'-'dd HH':'mm':'ss"

$ForensicatorStartTime = Get-Date -Format $ForensicatorDateFormat

# creating a directory to store the artifacts of this host
mkdir $env:computername -Force | Out-Null

# Moving to the new folder
#Set-Location $env:computername


# Setting index output file
$ForensicatorIndexFile = "$PSScriptRoot\$env:COMPUTERNAME\index.html"

# Setting Extras Output file
$ForensicatorExtrasFile = "$PSScriptRoot\$env:COMPUTERNAME\extras.html"

# Setting Network Information Output
$NetworkFile = "$PSScriptRoot\$env:COMPUTERNAME\network.html"

# Setting Users Information Output
$UserFile = "$PSScriptRoot\$env:COMPUTERNAME\users.html"

# Setting System Information Output
$SystemFile = "$PSScriptRoot\$env:COMPUTERNAME\system.html"

# Setting Processes Output
$ProcessFile = "$PSScriptRoot\$env:COMPUTERNAME\processes.html"

# Setting Other Checks Output
$OthersFile = "$PSScriptRoot\$env:COMPUTERNAME\others.html"

# Setting Evtx Checks Output
$EvtxUserFile = "$PSScriptRoot\$env:COMPUTERNAME\evtx_user.html"

# Setting Evtx Logon Events Checks Output
$LogonEventsFile = "$PSScriptRoot\$env:COMPUTERNAME\evtx_logons.html"

# Setting Evtx Object Access Checks Output
$ObjectEventsFile = "$PSScriptRoot\$env:COMPUTERNAME\evtx_object.html"

# Setting Evtx Process Execution Checks Output
$ProcessEventsFile = "$PSScriptRoot\$env:COMPUTERNAME\evtx_process.html"

# Setting Detection Output
$DetectionFile = "$PSScriptRoot\$env:COMPUTERNAME\detection.html"


##################################################
#region Network Information and Settings         #
##################################################
Write-ForensicLog "[*] Gathering Network & Network Settings" -Level INFO -Section "NETWORK"

#Gets DNS cache. Replaces ipconfig /dislaydns
$DNSCache = Get-DnsClientCache | Select-Object Entry, Name, Status, TimeToLive, Data #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $DNSCache) {
  $DNSCacheFragment += "<tr>"
  $DNSCacheFragment += "<td>$($process.Entry)</td>"
  $DNSCacheFragment += "<td>$($process.Name)</td>"
  $DNSCacheFragment += "<td>$($process.Status)</td>"
  $DNSCacheFragment += "<td>$($process.TimeToLive)</td>"
  $DNSCacheFragment += "<td>$($process.Data)</td>"
  $DNSCacheFragment += "</tr>"
}

$NetworkAdapter = Get-CimInstance -class Win32_NetworkAdapter  | Select-Object -Property AdapterType, ProductName, Description, MACAddress, Availability, NetconnectionStatus, NetEnabled, PhysicalAdapter #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetworkAdapter) {
  $NetworkAdapterFragment += "<tr>"
  $NetworkAdapterFragment += "<td>$($process.AdapterType)</td>"
  $NetworkAdapterFragment += "<td>$($process.ProductName)</td>"
  $NetworkAdapterFragment += "<td>$($process.Description)</td>"
  $NetworkAdapterFragment += "<td>$($process.MACAddress)</td>"
  $NetworkAdapterFragment += "<td>$($process.Availability)</td>"
  $NetworkAdapterFragment += "<td>$($process.NetconnectionStatus)</td>"
  $NetworkAdapterFragment += "<td>$($process.NetEnabled)</td>"
  $NetworkAdapterFragment += "<td>$($process.PhysicalAdapter)</td>"
  $NetworkAdapterFragment += "</tr>"
}

#Replaces ipconfig:
$IPConfiguration = Get-CimInstance Win32_NetworkAdapterConfiguration |  Select-Object Description, @{Name = 'IpAddress'; Expression = { $_.IpAddress -join '; ' } }, @{Name = 'IpSubnet'; Expression = { $_.IpSubnet -join '; ' } }, MACAddress, @{Name = 'DefaultIPGateway'; Expression = { $_.DefaultIPGateway -join '; ' } }, DNSDomain, DNSHostName, DHCPEnabled, ServiceName #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $IPConfiguration) {
  $IPConfigurationFragment += "<tr>"
  $IPConfigurationFragment += "<td>$($process.Description)</td>"
  $IPConfigurationFragment += "<td>$($process.MACAddress)</td>"
  $IPConfigurationFragment += "<td>$($process.DNSDomain)</td>"
  $IPConfigurationFragment += "<td>$($process.DNSHostName)</td>"
  $IPConfigurationFragment += "<td>$($process.DHCPEnabled)</td>"
  $IPConfigurationFragment += "<td>$($process.ServiceName)</td>"
  $IPConfigurationFragment += "</tr>"
}

$NetIPAddress = foreach ($ip in Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch "^(127\.|169\.254)"
}) {

    $adapter = Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        InterfaceAlias   = $ip.InterfaceAlias
        IPAddress        = $ip.IPAddress
        Status     = $adapter.Status
        LinkSpeed  = $adapter.LinkSpeed
    }
}

foreach ($process in $NetIPAddress) {

  $NetIPAddressFragment += "<tr>"
  $NetIPAddressFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetIPAddressFragment += "<td>$($process.IPAddress)</td>"
  $NetIPAddressFragment += "<td>$($process.Status)</td>"
  $NetIPAddressFragment += "<td>$($process.LinkSpeed)</td>"
  $NetIPAddressFragment += "</tr>"

}

$NetConnectProfile = Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetConnectProfile) {
  $NetConnectProfileFragment += "<tr>"
  $NetConnectProfileFragment += "<td>$($process.Name)</td>"
  $NetConnectProfileFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetConnectProfileFragment += "<td>$($process.NetworkCategory)</td>"
  $NetConnectProfileFragment += "<td>$($process.IPV4Connectivity)</td>"
  $NetConnectProfileFragment += "<td>$($process.IPv6Connectivity)</td>"
  $NetConnectProfileFragment += "</tr>"
}

$NetAdapter = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetAdapter) {
  $NetAdapterFragment += "<tr>"
  $NetAdapterFragment += "<td>$($process.Name)</td>"
  $NetAdapterFragment += "<td>$($process.InterfaceDescription)</td>"
  $NetAdapterFragment += "<td>$($process.Status)</td>"
  $NetAdapterFragment += "<td>$($process.MacAddress)</td>"
  $NetAdapterFragment += "<td>$($process.LinkSpeed)</td>"
  $NetAdapterFragment += "</tr>"
}

#Replaces arp -a:
$NetNeighbor = Get-NetNeighbor | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetNeighbor) {
  $NetNeighborFragment += "<tr>"
  $NetNeighborFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetNeighborFragment += "<td>$($process.IPAddress)</td>"
  $NetNeighborFragment += "<td>$($process.LinkLayerAddress)</td>"
  $NetNeighborFragment += "</tr>"
}

#Replaces netstat commands
$NetTCPConnect = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } } #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetTCPConnect) {
  $NetTCPConnectFragment += "<tr>"
  $NetTCPConnectFragment += "<td>$($process.LocalAddress)</td>"
  $NetTCPConnectFragment += "<td>$($process.LocalPort)</td>"
  $NetTCPConnectFragment += "<td>$($process.RemoteAddress)</td>"
  $NetTCPConnectFragment += "<td>$($process.RemotePort)</td>"
  $NetTCPConnectFragment += "<td>$($process.State)</td>"
  $NetTCPConnectFragment += "<td>$($process.OwningProcess)</td>"
  $NetTCPConnectFragment += "</tr>"
}

#Get Wi-fi Names and Passwords
$WlanPasswords = netsh.exe wlan show profiles | Select-String "\:(.+)$" | ForEach-Object { $wlanname = $_.Matches.Groups[1].Value.Trim(); $_ } | ForEach-Object { (netsh wlan show profile name="$wlanname" key=clear) }  | Select-String 'Key Content\W+\:(.+)$' | ForEach-Object { $wlanpass = $_.Matches.Groups[1].Value.Trim(); [PSCustomObject]@{ PROFILE_NAME = $wlanname; PASSWORD = $wlanpass } }

$WlanPasswordsFragment = ""

foreach ($process in $WlanPasswords) {
  $WlanPasswordsFragment += "<tr>"
  $WlanPasswordsFragment += "<td>$($process.PROFILE_NAME)</td>"
  $WlanPasswordsFragment += "<td>$($process.PASSWORD)</td>"
  $WlanPasswordsFragment += "</tr>"
}


#Get Firewall Information. Replaces netsh firewall show config
$FirewallRule = Get-NetFirewallRule | select-object Name, DisplayName, Description, Direction, Action, EdgeTraversalPolicy, Owner, EnforcementStatus #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $FirewallRule) {
  $FirewallRuleFragment += "<tr>"
  $FirewallRuleFragment += "<td>$($process.Name)</td>"
  $FirewallRuleFragment += "<td>$($process.DisplayName)</td>"
  $FirewallRuleFragment += "<td>$($process.Description)</td>"
  $FirewallRuleFragment += "<td>$($process.Direction)</td>"
  $FirewallRuleFragment += "<td>$($process.Action)</td>"
  $FirewallRuleFragment += "<td>$($process.EdgeTraversalPolicy)</td>"
  $FirewallRuleFragment += "<td>$($process.Owner)</td>"
  $FirewallRuleFragment += "<td>$($process.EnforcementStatus)</td>"
  $FirewallRuleFragment += "</tr>"
}

#Outgoing SMB Session
$outboundSmbSessions = Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 445 -and $_.State -eq "Established" }
foreach ($process in $outboundSmbSessions) {
  $outboundSmbSessionsFragment += "<tr>"
  $outboundSmbSessionsFragment += "<td>$($process.LocalAddress)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.LocalPort)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.RemoteAddress)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.RemotePort)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.State)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.AppliedSetting)</td>"
  $outboundSmbSessionsFragment += "<td>$($process.OwningProcess)</td>"
  $outboundSmbSessionsFragment += "</tr>"
}

#Display active samba sessions
$SMBSessions = Get-SMBSession -ea silentlycontinue #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $SMBSessions) {
  $SMBSessionsFragment += "<tr>"
  $SMBSessionsFragment += "<td>$($process.SessionId)</td>"
  $SMBSessionsFragment += "<td>$($process.ClientComputerName)</td>"
  $SMBSessionsFragment += "<td>$($process.ClientUserName)</td>"
  $SMBSessionsFragment += "<td>$($process.NumOpens)</td>"
  $SMBSessionsFragment += "</tr>"
}

#Display active samba shares
$SMBShares = Get-SMBShare | Select-Object description, path, volume #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $SMBShares) {
  $SMBSharesFragment += "<tr>"
  $SMBSharesFragment += "<td>$($process.description)</td>"
  $SMBSharesFragment += "<td>$($process.path)</td>"
  $SMBSharesFragment += "<td>$($process.volume)</td>"
  $SMBSharesFragment += "</tr>"
}

#Get IP routes to non-local destinations
$NetHops = Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0, 6) -Ne "fe80::") } #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $NetHops) {
  $NetHopsFragment += "<tr>"
  $NetHopsFragment += "<td>$($process.ifIndex)</td>"
  $NetHopsFragment += "<td>$($process.DestinationPrefix)</td>"
  $NetHopsFragment += "<td>$($process.NextHop)</td>"
  $NetHopsFragment += "<td>$($process.RouteMetric)</td>"
  $NetHopsFragment += "<td>$($process.InterfaceMetric)</td>"
  $NetHopsFragment += "<td>$($process.InterfaceAlias)</td>"
  $NetHopsFragment += "</tr>"
}

#Get network adapters that have IP routes to non-local destinations
$AdaptHops = Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0, 6) -Ne "fe80::") } | Get-NetAdapter #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
foreach ($process in $AdaptHops) {
  $AdaptHopsFragment += "<tr>"
  $AdaptHopsFragment += "<td>$($process.Name)</td>"
  $AdaptHopsFragment += "<td>$($process.InterfaceDescription)</td>"
  $AdaptHopsFragment += "<td>$($process.ifIndex)</td>"
  $AdaptHopsFragment += "<td>$($process.Status)</td>"
  $AdaptHopsFragment += "<td>$($process.MacAddress)</td>"
  $AdaptHopsFragment += "<td>$($process.LinkSpeed)</td>"
  $AdaptHopsFragment += "</tr>"
}

#Get IP routes that have an infINFOe valid lifetime
$IpHops = Get-NetRoute | Where-Object -FilterScript { $_.ValidLifetime -Eq ([TimeSpan]::MaxValue) } #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
# Populate the HTML table with process information
foreach ($process in $IpHops) {
  $IpHopsFragment += "<tr>"
  $IpHopsFragment += "<td>$($process.ifIndex)</td>"
  $IpHopsFragment += "<td>$($process.DestinationPrefix)</td>"
  $IpHopsFragment += "<td>$($process.NextHop)</td>"
  $IpHopsFragment += "<td>$($process.RouteMetric)</td>"
  $IpHopsFragment += "<td>$($process.InterfaceMetric)</td>"
  $IpHopsFragment += "<td>$($process.InterfaceAlias)</td>"
  $IpHopsFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "NETWORK"

#endregion

Write-ForensicLog ""

##################################################
#region User & Account Information               #
##################################################

Write-ForensicLog "[*] Gathering User & Account Information" -Level INFO -Section "USER"

$systemname = Get-CimInstance -Class Win32_ComputerSystem | Select-Object Name, DNSHostName, Domain, Manufacturer, Model, PrimaryOwnerName, TotalPhysicalMemory, Workgroup  #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$systemnameFragment = ""
# Populate the HTML table with process information
foreach ($process in $systemname) {
  $systemnameFragment += "<tr>"
  $systemnameFragment += "<td>$($process.Name)</td>"
  $systemnameFragment += "<td>$($process.DNSHostName)</td>"
  $systemnameFragment += "<td>$($process.Domain)</td>"
  $systemnameFragment += "<td>$($process.Manufacturer)</td>"
  $systemnameFragment += "<td>$($process.Model)</td>"
  $systemnameFragment += "<td>$($process.PrimaryOwnerName)</td>"
  $systemnameFragment += "<td>$($process.TotalPhysicalMemory)</td>"
  $systemnameFragment += "<td>$($process.Workgroup)</td>"
  $systemnameFragment += "</tr>"
}

#$useraccounts = Get-CimInstance -Class Win32_UserAccount  | Select-Object -Property AccountType,Domain,LocalAccount,Name,PasswordRequired,SID,SIDType | ConvertTo-Html -fragment
#$logonsessionhistory = Get-CimInstance -Class Win32_LogonSession | Select-Object -Property LogonID, LogonType, StartTime, @{Name = 'Start Time'; Expression = { $_.ConvertToDateTime($_.starttime) } }   | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
#######ADDITIONS
$logonsession = (((quser) -replace '^>', '') -replace '\s{2,}', ',').Trim() | ConvertFrom-Csv #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
#$userprocesses = Get-Process -includeusername | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$logonsessionFragment = ""
# Populate the HTML table with process information
foreach ($process in $logonsession) {
  $logonsessionFragment += "<tr>"
  $logonsessionFragment += "<td>$($process.USERNAME)</td>"
  $logonsessionFragment += "<td>$($process.SESSIONNAME)</td>"
  $logonsessionFragment += "<td>$($process.STATE)</td>"
  $logonsessionFragment += "<td>$($process.ID)</td>"
  $logonsessionFragment += "<td>$($process.'IDLE TIME')</td>"
  $logonsessionFragment += "<td>$($process.'LOGON TIME')</td>"
  $logonsessionFragment += "</tr>"
}

$userprocesses = Get-Process -includeusername | Select-Object Name, Id, Username, CPU, Memory, Path 
# Populate the HTML table with process information
$userprocessesFragment = ""
foreach ($process in $userprocesses) {
  $userprocessesFragment += "<tr>"
  $userprocessesFragment += "<td>$($process.Name)</td>"
  $userprocessesFragment += "<td>$($process.Id)</td>"
  $userprocessesFragment += "<td>$($process.UserName)</td>"
  $userprocessesFragment += "<td>$($process.CPU)</td>"
  $userprocessesFragment += "<td>$($process.Memory)</td>"
  $userprocessesFragment += "<td>$($process.Path)</td>"
  $userprocessesFragment += "</tr>"
}

#$userprofiles = Get-CimInstance -Class Win32_UserProfile | Select-object -property Caption, LocalPath, SID, @{Name = 'Last Used'; Expression = { $_.ConvertToDateTime($_.lastusetime) } } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$userprofiles = Get-CimInstance -Class Win32_UserProfile | Select-object -property LocalPath, SID, lastusetime
# Populate the HTML table with process information
$profileFragment = ""

foreach ($process in $userprofiles) {
  $profileFragment += "<tr>"
  $profileFragment += "<td>$($process.LocalPath)</td>"
  $profileFragment += "<td>$($process.SID)</td>"
 # $profileFragment += "<td>$([Management.ManagementDateTimeConverter]::ToDateTime($process.lastusetime))</td>"
  $profileFragment += "<td>$($process.lastusetime)</td>"
  $profileFragment += "</tr>"
}


#$administrators = Get-LocalGroupMember -Group "Administrators" | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$administrators = Get-LocalGroupMember -Group "Administrators"
# Populate the HTML table with process information
$adminFragment = ""

foreach ($process in $administrators) {
  $adminFragment += "<tr>"
  $adminFragment += "<td>$($process.Name)</td>"
  $adminFragment += "<td>$($process.ObjectClass)</td>"
  $adminFragment += "<td>$($process.PrincipalSource)</td>"
  $adminFragment += "</tr>"
}


#$LocalGroup = Get-LocalGroup | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$LocalGroup = Get-LocalGroup
# Populate the HTML table with process information
$localFragment = ""
foreach ($process in $LocalGroup) {
  $localFragment += "<tr>"
  $localFragment += "<td>$($process.Name)</td>"
  $localFragment += "<td>$($process.Description)</td>"
  $localFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "USER"

#endregion

Write-ForensicLog ""

##################################################
#region Installed Programs                       #
##################################################

Write-ForensicLog "[*] Gathering Installed Programs" -Level INFO -Section "INSTALLED_PROGRAMS"

#$InstProgs = Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$InstProgs = Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage
# Populate the HTML table with process information
foreach ($process in $InstProgs) {
  $InstProgsFragment += "<tr>"
  $InstProgsFragment += "<td>$($process.Name)</td>"
  $InstProgsFragment += "<td>$($process.Version)</td>"
  $InstProgsFragment += "<td>$($process.Vendor)</td>"
  $InstProgsFragment += "<td>$($process.InstallDate)</td>"
  $InstProgsFragment += "<td>$($process.InstallSource)</td>"
  $InstProgsFragment += "<td>$($process.PackageName)</td>"
  $InstProgsFragment += "<td>$($process.LocalPackage)</td>"
  $InstProgsFragment += "</tr>"
}

#$InstalledApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

$InstalledApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
# Populate the HTML table with process information
foreach ($process in $InstalledApps) {
  $InstalledAppsFragment += "<tr>"
  $InstalledAppsFragment += "<td>$($process.DisplayName)</td>"
  $InstalledAppsFragment += "<td>$($process.DisplayVersion)</td>"
  $InstalledAppsFragment += "<td>$($process.Publisher)</td>"
  $InstalledAppsFragment += "<td>$($process.InstallDate)</td>"
  $InstalledAppsFragment += "</tr>"
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "INSTALLED_PROGRAMS"

#endregion

Write-ForensicLog ""

##################################################
#region System Info                              #
##################################################

Write-ForensicLog "[*] Gathering System Information" -Level INFO -Section "SYSTEM_INFO"

#Environment Settings
#$env = Get-ChildItem ENV: | Select-Object name, value | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$env = Get-ChildItem ENV: | Select-Object name, value
# Populate the HTML table with process information
foreach ($process in $env) {
  $envFragment += "<tr>"
  $envFragment += "<td>$($process.name)</td>"
  $envFragment += "<td>$($process.value)</td>"
  $envFragment += "</tr>"
}

#System Info
#$systeminfo = Get-CimInstance -Class Win32_ComputerSystem  | Select-Object -Property Name, Caption, SystemType, Manufacturer, Model, DNSHostName, Domain, PartOfDomain, WorkGroup, CurrentTimeZone, PCSystemType, HyperVisorPresent | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$systeminfo = Get-CimInstance -Class Win32_ComputerSystem  | Select-Object -Property Name, Caption, SystemType, Manufacturer, Model, DNSHostName, Domain, PartOfDomain, WorkGroup, CurrentTimeZone, PCSystemType, HyperVisorPresent
# Populate the HTML table with process information
foreach ($process in $systeminfo) {
  $systeminfoFragment += "<tr>"
  $systeminfoFragment += "<td>$($process.Name)</td>"
  $systeminfoFragment += "<td>$($process.Caption)</td>"
  $systeminfoFragment += "<td>$($process.SystemType)</td>"
  $systeminfoFragment += "<td>$($process.Manufacturer)</td>"
  $systeminfoFragment += "<td>$($process.Model)</td>"
  $systeminfoFragment += "<td>$($process.DNSHostName)</td>"
  $systeminfoFragment += "<td>$($process.Domain)</td>"
  $systeminfoFragment += "<td>$($process.PartOfDomain)</td>"
  $systeminfoFragment += "<td>$($process.WorkGroup)</td>"
  $systeminfoFragment += "<td>$($process.CurrentTimeZone)</td>"
  $systeminfoFragment += "<td>$($process.PCSystemType)</td>"
  $systeminfoFragment += "<td>$($process.HyperVisorPresent)</td>"
  $systeminfoFragment += "</tr>"
}

#OS Info
#$OSinfo = Get-CimInstance -Class Win32_OperatingSystem   | Select-Object -Property Name, Description, Version, BuildNumber, InstallDate, SystemDrive, SystemDevice, WindowsDirectory, LastBootupTime, Locale, LocalDateTime, NumberofUsers, RegisteredUser, Organization, OSProductSuite | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$OSinfo = Get-CimInstance -Class Win32_OperatingSystem   | Select-Object -Property Name, Description, Version, BuildNumber, InstallDate, SystemDrive, SystemDevice, WindowsDirectory, LastBootupTime, Locale, LocalDateTime, NumberofUsers, RegisteredUser, Organization, OSProductSuite
# Populate the HTML table with process information
foreach ($process in $OSinfo) {
  $OSinfoFragment += "<tr>"
  $OSinfoFragment += "<td>$($process.Name)</td>"
  $OSinfoFragment += "<td>$($process.Description)</td>"
  $OSinfoFragment += "<td>$($process.Version)</td>"
  $OSinfoFragment += "<td>$($process.BuildNumber)</td>"
  $OSinfoFragment += "<td>$($process.InstallDate)</td>"
  $OSinfoFragment += "<td>$($process.SystemDrive)</td>"
  $OSinfoFragment += "<td>$($process.SystemDevice)</td>"
  $OSinfoFragment += "<td>$($process.WindowsDirectory)</td>"
  $OSinfoFragment += "<td>$($process.LastBootupTime)</td>"
  $OSinfoFragment += "<td>$($process.Locale)</td>"
  $OSinfoFragment += "<td>$($process.LocalDateTime)</td>"
  $OSinfoFragment += "<td>$($process.NumberofUsers)</td>"
  $OSinfoFragment += "<td>$($process.RegisteredUser)</td>"
  $OSinfoFragment += "<td>$($process.Organization)</td>"
  $OSinfoFragment += "<td>$($process.OSProductSuite)</td>"
  $OSinfoFragment += "</tr>"
}

#Hotfixes
#$Hotfixes = Get-Hotfix | Select-Object -Property CSName, Caption, Description, HotfixID, InstalledBy, InstalledOn | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Hotfixes = Get-Hotfix | Select-Object -Property CSName, Caption, Description, HotfixID, InstalledBy, InstalledOn
# Populate the HTML table with process information
foreach ($process in $Hotfixes) {
  $HotfixesFragment += "<tr>"
  $HotfixesFragment += "<td>$($process.CSName)</td>"
  $HotfixesFragment += "<td>$($process.Caption)</td>"
  $HotfixesFragment += "<td>$($process.Description)</td>"
  $HotfixesFragment += "<td>$($process.HotfixID)</td>"
  $HotfixesFragment += "<td>$($process.InstalledBy)</td>"
  $HotfixesFragment += "<td>$($process.InstalledOn)</td>"
  $HotfixesFragment += "</tr>"
}

#Get Windows Defender Status
#$WinDefender = Get-MpComputerStatus | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$WinDefender = Get-MpComputerStatus | Select-Object -Property AMProductVersion, AMRunningMode, AMServiceEnabled, AntispywareEnabled, AntispywareSignatureLastUpdated, AntivirusEnabled, AntivirusSignatureLastUpdated, BehaviorMonitorEnabled, DefenderSignaturesOutOfDate, DeviceControlPoliciesLastUpdated, DeviceControlState, NISSignatureLastUpdated, QuickScanEndTime, RealTimeProtectionEnabled
# Populate the HTML table with process information
foreach ($process in $WinDefender) {
  $WinDefenderFragment += "<tr>"
  $WinDefenderFragment += "<td>$($process.AMProductVersion)</td>"
  $WinDefenderFragment += "<td>$($process.AMRunningMode)</td>"
  $WinDefenderFragment += "<td>$($process.AMServiceEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntispywareEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntispywareSignatureLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.AntivirusEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.AntivirusSignatureLastUpdatedn)</td>"
  $WinDefenderFragment += "<td>$($process.BehaviorMonitorEnabled)</td>"
  $WinDefenderFragment += "<td>$($process.DefenderSignaturesOutOfDate)</td>"
  $WinDefenderFragment += "<td>$($process.DeviceControlPoliciesLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.DeviceControlState)</td>"
  $WinDefenderFragment += "<td>$($process.NISSignatureLastUpdated)</td>"
  $WinDefenderFragment += "<td>$($process.QuickScanEndTime)</td>"
  $WinDefenderFragment += "<td>$($process.RealTimeProtectionEnabled)</td>"
  $WinDefenderFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "SYSTEM_INFO"

#endregion

Write-ForensicLog ""

##################################################
#region Live Running Processes & Scheduled Tasks #
##################################################

Write-ForensicLog "[*] Gathering Processes and Tasks" -Level INFO -Section "PROCESSES"


#$Processes = Get-Process | Select-Object Handles, StartTime, PM, VM, SI, id, ProcessName, Path, Product, FileVersion | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Processes = Get-Process | Select-Object Handles, StartTime, PM, VM, SI, id, ProcessName, Path, Product, FileVersion
# Populate the HTML table with process information
foreach ($process in $Processes) {
  $ProcessesFragment += "<tr>"
  $ProcessesFragment += "<td>$($process.Handles)</td>"
  $ProcessesFragment += "<td>$($process.StartTime)</td>"
  $ProcessesFragment += "<td>$($process.PM)</td>"
  $ProcessesFragment += "<td>$($process.VM)</td>"
  $ProcessesFragment += "<td>$($process.SI)</td>"
  $ProcessesFragment += "<td>$($process.id)</td>"
  $ProcessesFragment += "<td>$($process.ProcessName)</td>"
  $ProcessesFragment += "<td>$($process.Path)</td>"
  $ProcessesFragment += "<td>$($process.Product)</td>"
  $ProcessesFragment += "<td>$($process.FileVersion)</td>"
  $ProcessesFragment += "</tr>"
}

#Items set to run on startup
#$StartupProgs = Get-CimInstance Win32_StartupCommand | Select-Object Command, User, Caption | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$StartupProgs = Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User
# Populate the HTML table with process information
foreach ($process in $StartupProgs) {
  $StartupProgsFragment += "<tr>"
  $StartupProgsFragment += "<td>$($process.Name)</td>"
  $StartupProgsFragment += "<td>$($process.command)</td>"
  $StartupProgsFragment += "<td>$($process.Location)</td>"
  $StartupProgsFragment += "<td>$($process.User)</td>"
  $StartupProgsFragment += "</tr>"
}

# Scheduled Tasks
#$ScheduledTask = Get-ScheduledTask | Where-Object State -eq running | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$ScheduledTask = Get-ScheduledTask | Select-Object TaskPath, TaskName, State
# Populate the HTML table with process information
foreach ($process in $ScheduledTask) {
  $ScheduledTaskFragment += "<tr>"
  $ScheduledTaskFragment += "<td>$($process.TaskPath)</td>"
  $ScheduledTaskFragment += "<td>$($process.TaskName)</td>"
  $ScheduledTaskFragment += "<td>$($process.State)</td>"
  $ScheduledTaskFragment += "</tr>"
}

# Get Running Tasks and Their state
#$ScheduledTask2 = Get-ScheduledTask | Where-Object State -eq running | Get-ScheduledTaskInfo | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$ScheduledTask2 = Get-ScheduledTask | Get-ScheduledTaskInfo | Select-Object -Property LastRunTime, LastTaskResult, NextRunTime, NumberOfMissedRuns, TaskName, TaskPath, PSComputerName
# Populate the HTML table with process information
foreach ($process in $ScheduledTask2) {
  $ScheduledTask2Fragment += "<tr>"
  $ScheduledTask2Fragment += "<td>$($process.LastRunTime)</td>"
  $ScheduledTask2Fragment += "<td>$($process.LastTaskResult)</td>"
  $ScheduledTask2Fragment += "<td>$($process.NextRunTime)</td>"
  $ScheduledTask2Fragment += "<td>$($process.NumberOfMissedRuns)</td>"
  $ScheduledTask2Fragment += "<td>$($process.TaskName)</td>"
  $ScheduledTask2Fragment += "<td>$($process.TaskPath)</td>"
  $ScheduledTask2Fragment += "<td>$($process.PSComputerName)</td>"
  $ScheduledTask2Fragment += "</tr>"
}

#Services
#$Services = Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Services = Get-Service | Select-Object -Property DisplayName, ServiceName, Status, StartType, @{Name = 'StartName'; Expression = { $_.StartName } }, @{Name = 'Description'; Expression = { (Get-CimInstance -Class Win32_Service -Filter "Name='$($_.Name)'").Description } }

foreach ($process in $Services) {
  $ServicesFragment += "<tr>"
  $ServicesFragment += "<td>$($process.ServiceName)</td>"
  $ServicesFragment += "<td>$($process.DisplayName)</td>"
  $ServicesFragment += "<td>$($process.Status)</td>"
  $ServicesFragment += "<td>$($process.StartType)</td>"
  $ServicesFragment += "<td>$($process.Description)</td>"
  $ServicesFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "PROCESSES"

#endregion

Write-ForensicLog ""

##################################################
#region Settings from the Registry			     #
##################################################

Write-ForensicLog "[*] Checking Registry for persistance" -Level INFO -Section "REGISTRY"

function Get-RegistryHtml {
    param($Path)

    try{
        $data = Get-ItemProperty -Path $Path -ErrorAction Stop

        if($data){
            return $data | ConvertTo-Html -As List -Fragment |
                   Select-Object -Skip 1 |
                   Select-Object -SkipLast 1
        }
        else{
            return "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>No Entry Found</td></tr>"
        }
    }
    catch{
        return "<tr><td colspan='9' style='text-align:center;color:#e74c3c;'>Key not found or inaccessible</td></tr>"
    }
}

$RegRun = Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

$RegRunOnce = Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

$RegRunOnceEx = Get-RegistryHtml "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "REGISTRY"

#endregion

Write-ForensicLog ""

##################################################
#region Checking other worthwhiles			     #
##################################################

Write-ForensicLog "[*] Running Peripheral Checks..." -Level INFO -Section "PERIPHERAL_CHECKS"


$LogicalDrives = Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType, FreeSpace, Size, VolumeName

if ($LogicalDrives) {

    foreach ($process in $LogicalDrives) {
        $LogicalDrivesFragment += "<tr>"
        $LogicalDrivesFragment += "<td>$($process.DeviceID)</td>"
        $LogicalDrivesFragment += "<td>$($process.DriveType)</td>"
        $LogicalDrivesFragment += "<td>$($process.FreeSpace)</td>"
        $LogicalDrivesFragment += "<td>$($process.Size)</td>"
        $LogicalDrivesFragment += "<td>$($process.VolumeName)</td>"
        $LogicalDrivesFragment += "</tr>"
    }

}
else {
    $LogicalDrivesFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}


#Gets list of USB devices
#$USBDevices = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | Select-Object FriendlyName, Driver, mfg, DeviceDesc | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1 
$USBDevices = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | Select-Object FriendlyName, Driver, mfg, DeviceDesc
# Populate the HTML table with process information
if ($USBDevices) {
foreach ($process in $USBDevices) {
  $USBDevicesFragment += "<tr>"
  $USBDevicesFragment += "<td>$($process.FriendlyName)</td>"
  $USBDevicesFragment += "<td>$($process.Driver)</td>"
  $USBDevicesFragment += "<td>$($process.mfg)</td>"
  $USBDevicesFragment += "<td>$($process.DeviceDesc)</td>"
  $USBDevicesFragment += "</tr>"
}

} else {
    $USBDevicesFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

###Gets list of imaging devices (cameras, webcams, etc)

$Imagedevice = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
    Where-Object {
        $_.PNPClass -eq "Image" -or $_.Caption -match 'camera|webcam'
    } |
    Select-Object Caption, Manufacturer, DeviceID, Status, Present

if ($Imagedevice) {
foreach ($process in $Imagedevice) {
  $ImagedeviceFragment += "<tr>"
  $ImagedeviceFragment += "<td>$($process.Caption)</td>"
  $ImagedeviceFragment += "<td>$($process.Manufacturer)</td>"
  $ImagedeviceFragment += "<td>$($process.Status)</td>"
  $ImagedeviceFragment += "<td>$($process.Present)</td>"
  $ImagedeviceFragment += "</tr>"
}
} else {
    $ImagedeviceFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

#All currently connected PNP devices
#$UPNPDevices = Get-PnpDevice -PresentOnly -class 'USB', 'DiskDrive', 'Mouse', 'Keyboard', 'Net', 'Image', 'Media', 'Monitor' | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$UPNPDevices = Get-PnpDevice -PresentOnly |
           Where-Object {
               $_.Class -in @('USB','DiskDrive','Mouse','Keyboard','Net','Image','Media','Monitor')
           } |
           Select-Object Status, Class, FriendlyName, InstanceId


if ($UPNPDevices) {
foreach ($process in $UPNPDevices) {
  $UPNPDevicesFragment += "<tr>"
  $UPNPDevicesFragment += "<td>$($process.Status)</td>"
  $UPNPDevicesFragment += "<td>$($process.Class)</td>"
  $UPNPDevicesFragment += "<td>$($process.FriendlyName)</td>"
  $UPNPDevicesFragment += "<td>$($process.InstanceId)</td>"
  $UPNPDevicesFragment += "</tr>"
}
} else {
    $UPNPDevicesFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

#All previously connected disk drives not currently accounted for. Useful if target computer has had drive replaced/hidden
#$UnknownDrives = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select-Object FriendlyName | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$UnknownDrives = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName } |
    Select-Object FriendlyName, Mfg,
        @{Name="Serial";Expression={$_.PSChildName}},
        @{Name="LastWriteTime";Expression={
            (Get-Item $_.PSPath).LastWriteTime
        }} |
    Sort-Object LastWriteTime -Descending

if ($UnknownDrives) {
foreach ($process in $UnknownDrives) {
  $UnknownDrivesFragment += "<tr>"
  $UnknownDrivesFragment += "<td>$($process.FriendlyName)</td>"
  $UnknownDrivesFragment += "<td>$($process.Mfg)</td>"
  $UnknownDrivesFragment += "<td>$($process.Serial)</td>"
  $UnknownDrivesFragment += "<td>$($process.LastWriteTime)</td>"
  $UnknownDrivesFragment += "</tr>"
}
} else {
    $UnknownDrivesFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

#Gets all link files created in last 180 days. Perhaps export this as a separate CSV and make it keyword searchable?
#$LinkFiles = Get-CimInstance Win32_ShortcutFile | Select-Object Filename, Caption, @{NAME = 'CreationDate'; Expression = { $_.ConvertToDateTime($_.CreationDate) } }, @{Name = 'LastAccessed'; Expression = { $_.ConvertToDateTime($_.LastAccessed) } }, @{Name = 'LastModified'; Expression = { $_.ConvertToDateTime($_.LastModified) } }, Target | Where-Object { $_.LastModified -gt ((Get-Date).AddDays(-180)) } | Sort-Object LastModified -Descending | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
#$LinkFiles = Get-CimInstance Win32_ShortcutFile | Select-Object Filename, Caption, @{NAME = 'CreationDate'; Expression = { $_.ConvertToDateTime($_.CreationDate) } }, @{Name = 'LastAccessed'; Expression = { $_.ConvertToDateTime($_.LastAccessed) } }, @{Name = 'LastModified'; Expression = { $_.ConvertToDateTime($_.LastModified) } }, Target | Where-Object { $_.LastModified -gt ((Get-Date).AddDays(-180)) } | Sort-Object LastModified -Descending
#$LinkFiles = Get-CimInstance Win32_ShortcutFile | Select-Object Name, FileName, CreationDate, LastAccessed, FileType

$lnkFiles = Get-ChildItem -Path "C:\Users" -Recurse -Filter *.lnk -ErrorAction SilentlyContinue

$WshShell = New-Object -ComObject WScript.Shell

$shortcuts = foreach ($file in $lnkFiles) {
    try {
        $shortcut = $WshShell.CreateShortcut($file.FullName)

        [PSCustomObject]@{
            Name         = $file.Name
            Path         = $file.FullName
            Target       = $shortcut.TargetPath
            Arguments    = $shortcut.Arguments
            LastAccess   = $file.LastAccessTime
            Created      = $file.CreationTime
        }
    }
    catch { }
}


if ($shortcuts) {
    foreach ($s in $shortcuts) {
        $LinkFilesFragment += "<tr>"
        $LinkFilesFragment += "<td>$($s.Name)</td>"
        $LinkFilesFragment += "<td>$($s.Target)</td>"
        $LinkFilesFragment += "<td>$($s.Arguments)</td>"
        $LinkFilesFragment += "<td>$($s.LastAccess)</td>"
        $LinkFilesFragment += "</tr>"
    }
}
else {
    $LinkFilesFragment += "<tr><td colspan='4'>No shortcuts found</td></tr>"
}



#Gets last 100 days worth of Powershell History
#$PSHistory = Get-History -count 500 | Select-Object id, commandline, startexecutiontime, endexecutiontime | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
#$PSHistory = Get-History -count 500 | Select-Object id, commandline, startexecutiontime, endexecutiontime


$sessionHistory = Get-History -ErrorAction SilentlyContinue |
    Select-Object Id, CommandLine, StartExecutionTime, EndExecutionTime

$fileHistory = Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
    ForEach-Object {
        Get-Content $_.FullName | ForEach-Object {
            [PSCustomObject]@{
                Source = "File"
                Command = $_
            }
        }
    }

$PSHistory = @($sessionHistory) + @($fileHistory)


if ($PSHistory) {
    foreach ($cmd in $PSHistory) {
        $PSHistoryFragment += "<tr>"
        $PSHistoryFragment += "<td>$($cmd.User)</td>"
        $PSHistoryFragment += "<td>$($cmd.Command)</td>"
        $PSHistoryFragment += "</tr>"
    }
}
else {
    $PSHistoryFragment += "<tr><td colspan='2'>No PowerShell history found</td></tr>"
}



#All execs in Downloads folder. This may cause an error if the script is run from an external USB or Network drive.
#$Downloads = Get-ChildItem C:\Users\*\Downloads\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$Downloads = Get-ChildItem C:\Users\*\Downloads\* -recurse | Select-Object  Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }

if ($Downloads) {
foreach ($process in $Downloads) {
  $DownloadsFragment += "<tr>"
  $DownloadsFragment += "<td>$($process.Name)</td>"
  $DownloadsFragment += "<td>$($process.FullName)</td>"
  $DownloadsFragment += "<td>$($process.CreationTimeUTC)</td>"
  $DownloadsFragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $DownloadsFragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $DownloadsFragment += "<td>$($process.Attributes)</td>"
  $DownloadsFragment += "</tr>"
}
} else {
    $DownloadsFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

#Executables Running From Obscure Places
#$HiddenExecs1 = Get-ChildItem C:\Users\*\AppData\Local\Temp\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$HiddenExecs1 = Get-ChildItem C:\Users\*\AppData\Local\Temp\* -recurse | Select-Object  Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }

if ($HiddenExecs1) {
foreach ($process in $HiddenExecs1) {
  $HiddenExecs1Fragment += "<tr>"
  $HiddenExecs1Fragment += "<td>$($process.Name)</td>"
  $HiddenExecs1Fragment += "<td>$($process.FullName)</td>"
  $HiddenExecs1Fragment += "<td>$($process.CreationTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $HiddenExecs1Fragment += "<td>$($process.Attributes)</td>"
  $HiddenExecs1Fragment += "</tr>"
}
} else {
    $HiddenExecs1Fragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

#$HiddenExecs2 = Get-ChildItem C:\Temp\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$HiddenExecs2 = Get-ChildItem C:\Temp\* -recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }

if ($HiddenExecs2) {
foreach ($process in $HiddenExecs2) {
  $HiddenExecs2Fragment += "<tr>"
  $HiddenExecs2Fragment += "<td>$($process.Name)</td>"
  $HiddenExecs2Fragment += "<td>$($process.FullName)</td>"
  $HiddenExecs2Fragment += "<td>$($process.CreationTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $HiddenExecs2Fragment += "<td>$($process.Attributes)</td>"
  $HiddenExecs2Fragment += "</tr>"
}
} else {
    $HiddenExecs2Fragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

#$HiddenExecs3 = Get-ChildItem C:\PerfLogs\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$HiddenExecs3 = Get-ChildItem C:\PerfLogs\* -recurse | Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }

if ($HiddenExecs3) {
foreach ($process in $HiddenExecs3) {
  $HiddenExecs3Fragment += "<tr>"
  $HiddenExecs3Fragment += "<td>$($process.Name)</td>"
  $HiddenExecs3Fragment += "<td>$($process.FullName)</td>"
  $HiddenExecs3Fragment += "<td>$($process.CreationTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $HiddenExecs3Fragment += "<td>$($process.Attributes)</td>"
  $HiddenExecs3Fragment += "</tr>"
}
} else {
    $HiddenExecs3Fragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

#$HiddenExecs4 = Get-ChildItem C:\Users\*\Documents\* -recurse  |  Select-Object  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' } | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1
$HiddenExecs4 = Get-ChildItem C:\Users\*\Documents\* -recurse |  Select-Object Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { $_.extension -eq '.exe' }

if ($HiddenExecs4) {
foreach ($process in $HiddenExecs4) {
  $HiddenExecs4Fragment += "<tr>"
  $HiddenExecs4Fragment += "<td>$($process.Name)</td>"
  $HiddenExecs4Fragment += "<td>$($process.FullName)</td>"
  $HiddenExecs4Fragment += "<td>$($process.CreationTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$($process.LastAccessTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$($process.LastWriteTimeUTC)</td>"
  $HiddenExecs4Fragment += "<td>$($process.Attributes)</td>"
  $HiddenExecs4Fragment += "</tr>"
}
} else {
    $HiddenExecs4Fragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Nothing found</td></tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "PERIPHERAL_CHECKS"

#endregion

Write-ForensicLog ""

###########################################################################################################
#region #######  VIEW USER GP RESULTS    ##################################################################
###########################################################################################################
# get GPO REsult if on domain

$cs = Get-CimInstance Win32_ComputerSystem

if ($cs.PartOfDomain) {
    
  Write-ForensicLog "[*] Collecting GPO Results" -Level INFO -Section "GPORESULT"

  GPRESULT /H "$PSScriptRoot\$env:COMPUTERNAME\GPOReport.html" /F

  Write-ForensicLog "[!] Done" -Level SUCCESS -Section "GPORESULT"
}
else {
  Write-ForensicLog "[!] Computer is not joined to a domain...moving on" -Level INFO -Section "GPORESULT"
}

Write-ForensicLog ""

#endregion


###########################################################################################################
#region  MEMORY (RAM) CAPTURE    ##########################################################################
###########################################################################################################

if($RAM){

  Write-ForensicLog ""

    mkdir "$PSScriptRoot\$env:COMPUTERNAME\RAM" -ErrorAction SilentlyContinue | Out-Null

    # ---------------------------------------------------------
    # FULL PHYSICAL RAM — requires winpmem kernel driver
    # There is no native Windows equivalent for full acquisition
    # ---------------------------------------------------------
    $arch     = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    $winpmem  = if($arch -eq "64-bit"){
                    "$PSScriptRoot\Forensicator-Share\winpmem_mini_x64_rc2.exe"
                } else {
                    "$PSScriptRoot\Forensicator-Share\winpmem_mini_x86.exe"
                }

    $rawPath  = "$PSScriptRoot\$env:COMPUTERNAME\RAM\$env:COMPUTERNAME.raw"

    if(Test-Path $winpmem){

        Write-ForensicLog "[*] Acquiring physical RAM via winpmem..." -Level INFO -Section "RAM_CAPTURE"

        $proc = Start-Process -FilePath $winpmem `
                              -ArgumentList $rawPath `
                              -Wait -PassThru -NoNewWindow

        if(Test-Path $rawPath){

    $file    = Get-Item $rawPath
    $sizeMB  = [Math]::Round($file.Length / 1MB, 2)

    # ---------------------------------------------------------
    # Get system RAM
    # ---------------------------------------------------------
    try{
        $expectedRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        $expectedMB  = [Math]::Round($expectedRAM / 1MB, 2)
    }
    catch{
        $expectedMB = 0
    }

    # ---------------------------------------------------------
    # Compare dump vs system RAM
    # ---------------------------------------------------------
    if($expectedMB -gt 0){
        $percent = [Math]::Round(($sizeMB / $expectedMB) * 100, 2)
    }
    else{
        $percent = 0
    }

    # ---------------------------------------------------------
    # Evaluation logic
    # ---------------------------------------------------------
    if($sizeMB -lt 100){
        Write-ForensicLog "[!] RAM dump too small ($sizeMB MB) — acquisition likely failed" -Level ERROR -Section "RAM_CAPTURE" -Detail "Acquired RAM size is less than 100 MB. This may indicate acquisition failure, or antivirus blocking the tool from writing the dump."
    }
    else{
        if($proc.ExitCode -ne 0){
            Write-ForensicLog -ForegroundColor Yellow "[!] RAM acquired but tool returned exit code $($proc.ExitCode) — likely non-critical" -Level WARNING -Section "RAM_CAPTURE" -Detail "winpmem returned a non-zero exit code ($($proc.ExitCode)). However, the RAM dump was created and is of a reasonable size. This may indicate a non-critical issue with the tool, or antivirus interference causing it to return an error code despite successful acquisition."
        }

        if($percent -ge 90){
            Write-ForensicLog "[+] RAM acquired — $rawPath ($sizeMB MB | ~$percent% of system RAM)" -Level INFO -Section "RAM_CAPTURE" -Detail "Acquired RAM size is 90% or more of expected system RAM. This is a strong indicator of successful acquisition, though antivirus interference cannot be fully ruled out."
        }
        elseif($percent -ge 70){
            Write-ForensicLog "[!] RAM partially acquired — $rawPath ($sizeMB MB | ~$percent% of system RAM)" -Level WARNING -Section "RAM_CAPTURE" -Detail "Acquired RAM size is between 70% and 90% of expected system RAM. This may indicate partial acquisition or interference from antivirus software."
        }
        else{
            Write-ForensicLog "[!] RAM acquisition incomplete — $rawPath ($sizeMB MB | ~$percent% of system RAM)" -Level ERROR -Section "RAM_CAPTURE" -Detail "Acquired RAM size is less than 70% of expected system RAM. This may indicate acquisition failure, or antivirus blocking the tool from writing the dump."
        }

        if($expectedMB -gt 0){
            Write-ForensicLog "[i] Expected RAM: $expectedMB MB" -Level INFO -Section "RAM_CAPTURE" -Detail "System RAM as reported by WMI (Win32_ComputerSystem.TotalPhysicalMemory)"
        }
    }
}
else{
    Write-ForensicLog "[!] RAM acquisition failed — output file not found" -Level ERROR -Section "RAM_CAPTURE" -Detail "Expected RAM dump at $rawPath but file was not created. This may be due to acquisition failure, or antivirus blocking the tool from writing the dump."
}

    }
    else{

        Write-ForensicLog "[!] winpmem not found at $winpmem" -Level WARNING -Section "RAM_CAPTURE" -Detail "Expected winpmem at $winpmem for physical RAM acquisition. This may be due to the tool not being present, or antivirus blocking it. Attempting fallback collection of volatile memory artefacts instead."
        Write-ForensicLog "[!] Falling back to volatile memory snapshot (no physical RAM dump)" -Level WARNING -Section "RAM_CAPTURE"

        # ---------------------------------------------------------
        # FALLBACK — volatile memory artefacts collectable without
        # a kernel driver. Not a RAM image but captures the most
        # forensically relevant in-memory state.
        # ---------------------------------------------------------

        # 1. Full process list with commandlines, parent, and memory
        Write-ForensicLog "[*] Collecting process memory map..." -Level INFO -Section "RAM_CAPTURE"

        $processes = Get-CimInstance Win32_Process |
                     Select-Object ProcessId, ParentProcessId, Name,
                                   CommandLine, WorkingSetSize,
                                   VirtualSize, HandleCount,
                                   @{N="StartTime";E={$_.CreationDate}} |
                     Sort-Object WorkingSetSize -Descending



$ProcFragment = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Process Memory Map</title>

<style>

body{
    font-family: Segoe UI, Arial, sans-serif;
    background:#f4f6f8;
    margin:20px;
}

h2{
    color:#2c3e50;
}

.summary{
    background:white;
    padding:10px;
    margin-bottom:15px;
    border-left:5px solid #3498db;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
}

table{
    border-collapse: collapse;
    width:100%;
    background:white;
    box-shadow:0 2px 6px rgba(0,0,0,0.15);
}

th{
    background:#34495e;
    color:white;
    padding:10px;
    text-align:left;
    position:sticky;
    top:0;
}

td{
    padding:8px;
    border-bottom:1px solid #ddd;
    font-size:13px;
}

tr:nth-child(even){
    background:#f9fbfd;
}

tr:hover{
    background:#eef6ff;
}


.badge{
    background:#e74c3c;
    color:white;
    padding:3px 6px;
    border-radius:4px;
    font-size:12px;
}


</style>

</head>
<body>

<h2>Process Memory Map</h2>

<div class="summary">
Total URLs: $($Records.Count) |
Malicious URLs: $(( $Records | Where-Object {$_.IsMalicious}).Count)
</div>

<table>

<thead>
<tr>
<th>PID</th>
<th>PPID</th>
<th>Name</th>
<th>CommandLine</th>
<th>WorkingSet MB</th>
<th>Handles</th>
<th>StartTime</th>
</tr>
</thead>

<tbody>
"@



        foreach($p in $processes){
            $ProcFragment += "<tr>"
            $ProcFragment += "<td>$($p.ProcessId)</td>"
            $ProcFragment += "<td>$($p.ParentProcessId)</td>"
            $ProcFragment += "<td>$($p.Name)</td>"
            $ProcFragment += "<td>$([System.Web.HttpUtility]::HtmlEncode($p.CommandLine))</td>"
            $ProcFragment += "<td>$([Math]::Round($p.WorkingSetSize/1MB,1))</td>"
            $ProcFragment += "<td>$($p.HandleCount)</td>"
            $ProcFragment += "<td>$($p.StartTime)</td>"
            $ProcFragment += "</tr>"
        }



$ProcFragment += @"
</tbody>
</table>

</body>
</html>
"@


        $ProcFragment | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\ProcessMemoryMap.html" -Encoding UTF8

        # 2. Loaded modules per process — surfaces injected DLLs
        Write-ForensicLog "[*] Collecting loaded modules..." -Level INFO -Section "RAM_CAPTURE"




$ModFragment = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Loaded modules per process</title>

<style>

body{
    font-family: Segoe UI, Arial, sans-serif;
    background:#f4f6f8;
    margin:20px;
}

h2{
    color:#2c3e50;
}

.summary{
    background:white;
    padding:10px;
    margin-bottom:15px;
    border-left:5px solid #3498db;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
}

table{
    border-collapse: collapse;
    width:100%;
    background:white;
    box-shadow:0 2px 6px rgba(0,0,0,0.15);
}

th{
    background:#34495e;
    color:white;
    padding:10px;
    text-align:left;
    position:sticky;
    top:0;
}

td{
    padding:8px;
    border-bottom:1px solid #ddd;
    font-size:13px;
}

tr:nth-child(even){
    background:#f9fbfd;
}

tr:hover{
    background:#eef6ff;
}


.badge{
    background:#e74c3c;
    color:white;
    padding:3px 6px;
    border-radius:4px;
    font-size:12px;
}


</style>

</head>
<body>

<h2>Loaded modules per process</h2>

<div class="summary">
Total URLs: $($Records.Count) |
Malicious URLs: $(( $Records | Where-Object {$_.IsMalicious}).Count)
</div>

<table>

<thead>
<tr>
<th>PID</th>
<th>Process</th>
<th>Module</th>
<th>Path</th>
<th>FileVersion</th>
</tr>
</thead>

<tbody>
"@



        Get-Process | ForEach-Object {
            $proc = $_
            try{
                $proc.Modules | ForEach-Object {
                    $ModFragment += "<tr>"
                    $ModFragment += "<td>$($proc.Id)</td>"
                    $ModFragment += "<td>$($proc.Name)</td>"
                    $ModFragment += "<td>$($_.ModuleName)</td>"
                    $ModFragment += "<td>$([System.Web.HttpUtility]::HtmlEncode($_.FileName))</td>"
                    $ModFragment += "<td>$($_.FileVersionInfo.FileVersion)</td>"
                    $ModFragment += "</tr>"
                }
            }
            catch{ } # Access denied on system processes is expected
        }



$ModFragment += @"
</tbody>
</table>

</body>
</html>
"@



        $ModFragment | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\LoadedModules.html" -Encoding UTF8

        # 3. Network connections with owning PID
        Write-ForensicLog "[*] Collecting network connections..." -Level INFO -Section "RAM_CAPTURE"

        $connections = Get-NetTCPConnection |
                       Select-Object LocalAddress, LocalPort,
                                     RemoteAddress, RemotePort,
                                     State, OwningProcess,
                                     @{N="ProcessName";E={
                                         try{(Get-Process -Id $_.OwningProcess -EA Stop).Name}
                                         catch{"N/A"}
                                     }}

$NetFragment = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Network connections per process</title>

<style>

body{
    font-family: Segoe UI, Arial, sans-serif;
    background:#f4f6f8;
    margin:20px;
}

h2{
    color:#2c3e50;
}

.summary{
    background:white;
    padding:10px;
    margin-bottom:15px;
    border-left:5px solid #3498db;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
}

table{
    border-collapse: collapse;
    width:100%;
    background:white;
    box-shadow:0 2px 6px rgba(0,0,0,0.15);
}

th{
    background:#34495e;
    color:white;
    padding:10px;
    text-align:left;
    position:sticky;
    top:0;
}

td{
    padding:8px;
    border-bottom:1px solid #ddd;
    font-size:13px;
}

tr:nth-child(even){
    background:#f9fbfd;
}

tr:hover{
    background:#eef6ff;
}


.badge{
    background:#e74c3c;
    color:white;
    padding:3px 6px;
    border-radius:4px;
    font-size:12px;
}


</style>

</head>
<body>

<h2>Network connections per process</h2>

<table>

<thead>
<tr>
<th>Local Address</th>
<th>Local Port</th>
<th>Remote Address</th>
<th>Remote Port</th>
<th>State</th>
<th>PID</th>
<th>Process</th>
</tr>
</thead>

<tbody>
"@



        foreach($c in $connections){
            $NetFragment += "<tr>"
            $NetFragment += "<td>$($c.LocalAddress)</td>"
            $NetFragment += "<td>$($c.LocalPort)</td>"
            $NetFragment += "<td>$($c.RemoteAddress)</td>"
            $NetFragment += "<td>$($c.RemotePort)</td>"
            $NetFragment += "<td>$($c.State)</td>"
            $NetFragment += "<td>$($c.OwningProcess)</td>"
            $NetFragment += "<td>$($c.ProcessName)</td>"
            $NetFragment += "</tr>"
        }



$NetFragment += @"
</tbody>
</table>

</body>
</html>
"@




        $NetFragment | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\NetworkConnections.html" -Encoding UTF8

        # 4. Handles — open named pipes and mutants surface C2 IOCs
        # Requires SysInternals handle.exe for full fidelity
        # Best native alternative is querying WMI for named pipes
        Write-ForensicLog -ForegroundColor DarkCyan "[*] Collecting named pipes..."

        $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') |
                 ForEach-Object { [PSCustomObject]@{ PipeName = $_ } }

        $PipeFragment  = "<table><thead><tr><th>Named Pipe</th></tr></thead><tbody>"
        foreach($pipe in $pipes){
            $PipeFragment += "<tr><td>$($pipe.PipeName)</td></tr>"
        }
        $PipeFragment += "</tbody></table>"
        $PipeFragment | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\NamedPipes.html" -Encoding UTF8

        # 5. Clipboard contents — volatile, lost on reboot
        Write-ForensicLog "[*] Collecting clipboard..." -Level INFO -Section "RAM_CAPTURE"
        try{
            Add-Type -AssemblyName System.Windows.Forms
            $clipboard = [System.Windows.Forms.Clipboard]::GetText()
            if(-not [string]::IsNullOrWhiteSpace($clipboard)){
                $clipboard | Out-File "$PSScriptRoot\$env:COMPUTERNAME\RAM\Clipboard.txt" -Encoding UTF8
            }
        }
        catch{
            Write-ForensicLog "[!] Could not retrieve clipboard contents" -Level ERROR -Section "RAM_CAPTURE" -Details $_.Exception.Message
        }

        Write-ForensicLog "[!] Volatile snapshot complete — no physical RAM image" -Level WARNING -Section "RAM_CAPTURE"
        Write-ForensicLog "[!] For full acquisition ensure winpmem is present and run the script with -RAM switch" -Level WARNING -Section "RAM_CAPTURE"
    }

    Write-ForensicLog "[!] Done" -Level SUCCESS -Section "RAM_CAPTURE" -Details "RAM acquisition complete (physical dump or volatile snapshot)"
}
else{
    Write-ForensicLog "[!] RAM capture not selected...moving on" -Level INFO -Section "RAM_CAPTURE"
}

#endregion

Write-ForensicLog ""


###########################################################################################################
#region  BROWSER HISTORY EXTRACTION              ##########################################################
###########################################################################################################

Write-ForensicLog "[*] Extracting Browser History" -Level INFO -Section "BROWSER_HISTORY"

mkdir $PSScriptRoot\$env:COMPUTERNAME\BROWSING_HISTORY -ErrorAction SilentlyContinue | Out-Null

$sqlitePath = "$PSScriptRoot\Forensicator-Share\sqlite3.exe"

if(-not (Test-Path $sqlitePath)){
    Write-ForensicLog "[!] sqlite3.exe not found at $sqlitePath — cannot extract SQLite-based history" -Level ERROR -Section "BROWSER_HISTORY" -Details "SQLLite not found in $sqlitePath SQLite-based browsers (Chrome, Edge, Firefox) will be skipped"
   
}

# ---------------------------------------------------------
# USER ENUMERATION — done first, used throughout
# Pulls all real user profiles, skips system/default accounts
# ---------------------------------------------------------
$users = Get-CimInstance Win32_UserProfile |
         Where-Object {
             $_.Special     -eq $false -and
             $_.LocalPath   -notmatch '(Public|Default|NetworkService|LocalService|systemprofile)$' -and
             (Test-Path $_.LocalPath)
         } |
         ForEach-Object { $_.LocalPath }

if($users.Count -eq 0){
    # Fallback to filesystem enumeration if WMI returns nothing
    $users = Get-ChildItem "$env:SystemDrive\Users" -Directory |
             Where-Object { $_.Name -notmatch '^(Public|Default|default user|All Users)$' } |
             ForEach-Object { $_.FullName }
}

Write-ForensicLog "[*] Found $($users.Count) user profile(s) to process" -Level FINDING -Section "BROWSER_HISTORY" -Details "Number of Users Found: $($users.Count)"

# ---------------------------------------------------------
# MALICIOUS URL LIST — used for flagging bad URLs in history
# ---------------------------------------------------------
$maliciousUrlsFilePath = "$PSScriptRoot\Forensicator-Share\malicious_URLs.txt"


$configFile = "$PSScriptRoot\config.json"
  $configData = Get-Content $configFile | ConvertFrom-Json



if($null -ne $configData){
    $urlSource = $configData.url_source
}

if(-not (Test-Path $maliciousUrlsFilePath)){
    Write-ForensicLog "[*] malicious_URLs.txt not found — attempting download..." -Level INFO -Section "BROWSER_HISTORY"
    try{
        # Quick TCP reachability check without Test-NetConnection overhead
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $connected = $tcp.ConnectAsync("bazaar.abuse.ch", 443).Wait(3000)
        $tcp.Dispose()

        if($connected){
            Write-ForensicLog "[*] Downloading from abuse.ch..." -Level INFO -Section "BROWSER_HISTORY"
            Invoke-WebRequest -Uri $urlSource -OutFile $maliciousUrlsFilePath -UseBasicParsing -TimeoutSec 30
        }
        else{
            Write-ForensicLog "[!] bazaar.abuse.ch unreachable — malicious URL checking disabled" -Level ERROR -Section "BROWSER_HISTORY"
        }
    }
    catch{
        Write-ForensicLog "[!] Download failed — malicious URL checking disabled" -Level ERROR -Section "BROWSER_HISTORY"
    }
}

# Build HashSet for O(1) domain lookup — critical when checking
# thousands of URLs against a large IOC list
$maliciousDomainSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

if(Test-Path $maliciousUrlsFilePath){
    Get-Content $maliciousUrlsFilePath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#") } |
        ForEach-Object { [void]$maliciousDomainSet.Add($_.Trim().ToLower()) }

    Write-ForensicLog "[*] Loaded $($maliciousDomainSet.Count) malicious domain(s)" -Level INFO -Section "BROWSER_HISTORY" -Details "Source: $($maliciousDomainSet.Count) domains from $urlSource"
}

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
function Get-UrlDomain {
    param([string]$Url)
    try{
        return ([System.Uri]$Url).Host.ToLower()
    }
    catch{ return $Url.ToLower() }
}


function Test-MaliciousUrl {
    param([string]$Url)

    if($maliciousDomainSet.Count -eq 0){ return $false }

    $urlLower = $Url.ToLower()

    # --- Direct URL match ---
    if($maliciousDomainSet.Contains($urlLower)){
        return $true
    }

    # --- Domain extraction ---
    $domain = Get-UrlDomain $urlLower

    # Exact domain match
    if($maliciousDomainSet.Contains($domain)){
        return $true
    }

    # Parent domain match (sub.evil.com -> evil.com)
    $parts = $domain -split "\."

    for($i = 1; $i -lt $parts.Count - 1; $i++){
        $parent = ($parts[$i..($parts.Count-1)]) -join "."
        if($maliciousDomainSet.Contains($parent)){
            return $true
        }
    }

    return $false
}

function Convert-ChromeTime {
    param([long]$t)
    if($t -le 0){ return "N/A" }
    try{ return ([datetime]'1601-01-01').AddSeconds($t / 1000000).ToString("yyyy-MM-dd HH:mm:ss") }
    catch{ return "N/A" }
}

function Convert-FirefoxTime {
    param([long]$t)
    if($t -le 0){ return "N/A" }
    try{ return ([datetime]'1970-01-01').AddMilliseconds($t / 1000).ToString("yyyy-MM-dd HH:mm:ss") }
    catch{ return "N/A" }
}

function Escape-Html {
    param([string]$s)
    if([string]::IsNullOrEmpty($s)){ return "" }
    return $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;")
}

function Invoke-SQLiteQuery {
    param([string]$DbPath, [string]$Query)
    $tempDb = "$env:TEMP\frnsctr_$(New-Guid).db"
    try{
        Copy-Item $DbPath $tempDb -Force -ErrorAction Stop
        # Use a separator that cannot appear in URLs or timestamps
        # ASCII 0x1F = Unit Separator — safe for this purpose
        $sep     = [char]0x1F
        $results = & $sqlitePath $tempDb -separator $sep $Query 2>$null
        return [PSCustomObject]@{ Rows = $results; Separator = $sep }
    }
    catch{
        Write-Verbose "[!] SQLite query failed on $DbPath — $($_.Exception.Message)" -Level ERROR -Section "BROWSER_HISTORY" -Details "Failed to query $DbPath with query: $Query"
        return [PSCustomObject]@{ Rows = @(); Separator = [char]0x1F }
    }
    finally{
        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
    }
}



function Build-HistoryHtml {
    param([array]$Records, [string]$Title)

$htmlbrowser = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>$Title</title>

<style>

body{
    font-family: Segoe UI, Arial, sans-serif;
    background:#f4f6f8;
    margin:20px;
}

h2{
    color:#2c3e50;
}

.summary{
    background:white;
    padding:10px;
    margin-bottom:15px;
    border-left:5px solid #3498db;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
}

table{
    border-collapse: collapse;
    width:100%;
    background:white;
    box-shadow:0 2px 6px rgba(0,0,0,0.15);
}

th{
    background:#34495e;
    color:white;
    padding:10px;
    text-align:left;
    position:sticky;
    top:0;
}

td{
    padding:8px;
    border-bottom:1px solid #ddd;
    font-size:13px;
}

tr:nth-child(even){
    background:#f9fbfd;
}

tr:hover{
    background:#eef6ff;
}

.malicious{
    background:#ffdddd !important;
    font-weight:bold;
}

.badge{
    background:#e74c3c;
    color:white;
    padding:3px 6px;
    border-radius:4px;
    font-size:12px;
}

.clean{
    color:#7f8c8d;
}

.url{
    word-break:break-all;
}

</style>

</head>
<body>

<h2>$Title</h2>

<div class="summary">
Total URLs: $($Records.Count) |
Malicious URLs: $(( $Records | Where-Object {$_.IsMalicious}).Count)
</div>

<table>

<thead>
<tr>
<th>User</th>
<th>Browser</th>
<th>Profile</th>
<th>URL</th>
<th>Last Visit</th>
<th>Malicious</th>
</tr>
</thead>

<tbody>
"@

foreach($r in $Records){

$class = if($r.IsMalicious){ "class='malicious'" } else { "" }

$htmlbrowser += "<tr $class>"

$htmlbrowser += "<td>$(Escape-Html $r.User)</td>"
$htmlbrowser += "<td>$($r.Browser)</td>"
$htmlbrowser += "<td>$(Escape-Html $r.Profile)</td>"
$htmlbrowser += "<td class='url'>$(Escape-Html $r.URL)</td>"
$htmlbrowser += "<td>$($r.LastVisit)</td>"

if($r.IsMalicious){
$htmlbrowser += "<td><span class='badge'>MALICIOUS</span></td>"
}
else{
$htmlbrowser += "<td><span class='clean'>Clean</span></td>"
}

$htmlbrowser += "</tr>"
}

$htmlbrowser += @"
</tbody>
</table>

</body>
</html>
"@

return $htmlbrowser
}

function Save-HistoryOutput {
    param([array]$Records, [string]$Browser, [string]$UserName, [string]$ProfileSuffix="")

    if($Records.Count -eq 0){ return }

    $safeSuffix = $ProfileSuffix -replace '[^a-zA-Z0-9_-]','_'
    $fileBase   = "$PSScriptRoot\$env:COMPUTERNAME\BROWSING_HISTORY\${Browser}_${UserName}$(if($safeSuffix){"_$safeSuffix"})"
    $title      = "$Browser — $UserName$(if($ProfileSuffix){" ($ProfileSuffix)"})"

    Build-HistoryHtml $Records $title |
        Out-File "$fileBase.html" -Encoding UTF8

    $malicious = $Records | Where-Object { $_.IsMalicious }
    if($malicious.Count -gt 0){
        Build-HistoryHtml $malicious "MALICIOUS — $title" |
            Out-File "$PSScriptRoot\$env:COMPUTERNAME\BROWSING_HISTORY\MALICIOUS_${Browser}_${UserName}$(if($safeSuffix){"_$safeSuffix"}).html" -Encoding UTF8
        Write-ForensicLog "[!] $($malicious.Count) malicious URL(s) in $Browser history — $UserName$(if($ProfileSuffix){" / $ProfileSuffix"})" -Level FINDING -Section "BROWSER_HISTORY" -Details "$($malicious.Count) malicious URL(s) found in $Browser history for user $UserName$(if($ProfileSuffix){" / profile $ProfileSuffix"})"
    }
}

# ---------------------------------------------------------
# CHROMIUM-BASED BROWSERS (Chrome, Edge, Brave, Opera)
# Dynamically discovers ALL profiles under User Data\
# not just Default — catches secondary signed-in profiles
# ---------------------------------------------------------
function Process-ChromiumBrowser {
    param(
        [string]$UserPath,
        [string]$BrowserName,
        [string]$UserDataRelPath
    )

    $userDataPath = "$UserPath\$UserDataRelPath"
    if(-not (Test-Path $userDataPath)){ return }

    $userName    = Split-Path $UserPath -Leaf
    $profileDirs = Get-ChildItem $userDataPath -Directory |
                   Where-Object { $_.Name -match '^(Default|Profile \d+)$' }

    foreach($profileDir in $profileDirs){
        $dbPath = "$($profileDir.FullName)\History"
        if(-not (Test-Path $dbPath)){ continue }

        $query  = "SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC"
        $result = Invoke-SQLiteQuery $dbPath $query
        $sep    = $result.Separator

        $records = foreach($row in $result.Rows){
            if([string]::IsNullOrWhiteSpace($row)){ continue }

            # Split on separator — last token is always the timestamp
            # everything before it is the URL (handles pipes in URLs)
            $parts = $row -split [regex]::Escape($sep)
            if($parts.Count -lt 2){ continue }

            $url       = ($parts[0..($parts.Count-2)] -join $sep).Trim()
            $timeRaw   = $parts[-1].Trim()

            $visitTime = "N/A"
            [long]$ts  = 0
            if([long]::TryParse($timeRaw, [ref]$ts)){
                $visitTime = Convert-ChromeTime $ts
            }

            [PSCustomObject]@{
                User        = $userName
                Browser     = $BrowserName
                Profile     = $profileDir.Name
                URL         = $url
                LastVisit   = $visitTime
                IsMalicious = Test-MaliciousUrl $url
            }
        }

        $profileSuffix = if($profileDir.Name -ne "Default"){ $profileDir.Name } else { "" }
        Save-HistoryOutput $records $BrowserName $userName $profileSuffix
    }
}

# ---------------------------------------------------------
# FIREFOX
# Dynamically discovers all release/default profiles
# ---------------------------------------------------------
function Process-FirefoxHistory {
    param([string]$UserPath)

    $profilesPath = "$UserPath\AppData\Roaming\Mozilla\Firefox\Profiles"
    if(-not (Test-Path $profilesPath)){ return }

    $userName = Split-Path $UserPath -Leaf

    foreach($profile in Get-ChildItem $profilesPath -Directory){
        $dbPath = "$($profile.FullName)\places.sqlite"
        if(-not (Test-Path $dbPath)){ continue }

        $query  = "SELECT url, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC"
        $result = Invoke-SQLiteQuery $dbPath $query
        $sep    = $result.Separator

        $records = foreach($row in $result.Rows){
            if([string]::IsNullOrWhiteSpace($row)){ continue }

            $parts   = $row -split [regex]::Escape($sep)
            if($parts.Count -lt 2){ continue }

            $url      = ($parts[0..($parts.Count-2)] -join $sep).Trim()
            $timeRaw  = $parts[-1].Trim()

            $visitTime = "N/A"
            [long]$ts  = 0
            if([long]::TryParse($timeRaw, [ref]$ts)){
                $visitTime = Convert-FirefoxTime $ts
            }

            [PSCustomObject]@{
                User        = $userName
                Browser     = "Firefox"
                Profile     = $profile.Name
                URL         = $url
                LastVisit   = $visitTime
                IsMalicious = Test-MaliciousUrl $url
            }
        }

        Save-HistoryOutput $records "Firefox" $userName $profile.Name
    }
}

# ---------------------------------------------------------
# INTERNET EXPLORER — TypedURLs (registry, no SQLite needed)
# Limitation noted: clicked links require WebCacheV01.dat
# (ESE database, needs esentutl — outside scope here)
# ---------------------------------------------------------
function Process-IEHistory {
    param([string]$UserPath)

    $userName = Split-Path $UserPath -Leaf

    if(-not (Test-Path "HKU:\")){ 
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
    }

    try{
        $sid = (New-Object System.Security.Principal.NTAccount($userName)).Translate(
                   [System.Security.Principal.SecurityIdentifier]).Value
    }
    catch{ return }

    $regPath = "HKU:\$sid\Software\Microsoft\Internet Explorer\TypedURLs"
    if(-not (Test-Path $regPath)){ return }

    $key     = Get-Item $regPath -ErrorAction SilentlyContinue
    $records = foreach($valueName in $key.GetValueNames()){
        $url = $key.GetValue($valueName)
        [PSCustomObject]@{
            User        = $userName
            Browser     = "Internet Explorer"
            Profile     = "Default"
            URL         = $url
            LastVisit   = "N/A (TypedURLs only)"
            IsMalicious = Test-MaliciousUrl $url
        }
    }

    Save-HistoryOutput $records "IE" $userName
}

# ---------------------------------------------------------
# PROCESS ALL USERS
# Chromium browser paths are declared inline so adding a new
# browser only requires one new entry in the $chromiumBrowsers table
# ---------------------------------------------------------
$chromiumBrowsers = @(
    @{ Name="Chrome"; RelPath="AppData\Local\Google\Chrome\User Data"           },
    @{ Name="Edge";   RelPath="AppData\Local\Microsoft\Edge\User Data"           },
    @{ Name="Brave";  RelPath="AppData\Local\BraveSoftware\Brave-Browser\User Data" },
    @{ Name="Opera";  RelPath="AppData\Roaming\Opera Software\Opera Stable"      }
)

foreach($user in $users){
    $userName = Split-Path $user -Leaf
    Write-ForensicLog "[*] Processing $userName" -Level INFO -Section "BROWSER_HISTORY" -Details "Processing user profile at $user"

    foreach($browser in $chromiumBrowsers){
        Process-ChromiumBrowser -UserPath $user `
                                -BrowserName $browser.Name `
                                -UserDataRelPath $browser.RelPath
    }

    Process-FirefoxHistory $user
    Process-IEHistory      $user
}

Write-ForensicLog "[!] Browser history extraction complete — results in BROWSING_HISTORY\" -Level SUCCESS -Section "BROWSER_HISTORY"


#endregion




###########################################################################################################
#region  CHECKING FOR RANSOMWARE ENCRYPTED FILES    #######################################################
###########################################################################################################

if($RANSOMWARE){

  Write-ForensicLog ""
    Write-ForensicLog "[*] Checking For Ransomware Indicators" -Level INFO -Section "RANSOMWARE_SCAN"
    Write-ForensicLog "[!] NOTE: This may take a while depending on disk size" -Level WARNING -Section "RANSOMWARE_SCAN"

    # ---------------------------------------------------------
    # KNOWN PLAINTEXT-HEADER EXTENSIONS
    # These are naturally high entropy — excluded from entropy
    # scan to eliminate the biggest source of false positives
    # ---------------------------------------------------------
    $excludedEntropyExtensions = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    @(
        '.jpg','.jpeg','.png','.gif','.bmp','.tif','.tiff','.webp','.ico',
        '.mp3','.mp4','.m4a','.m4v','.aac','.ogg','.flac','.wav','.wma',
        '.avi','.mkv','.mov','.wmv','.flv','.mpeg','.mpg',
        '.zip','.gz','.7z','.rar','.bz2','.xz','.cab','.iso',
        '.pdf','.docx','.xlsx','.pptx','.odt','.ods',
        '.exe','.dll','.sys'   # PE files have naturally high entropy sections
    ) | ForEach-Object { [void]$excludedEntropyExtensions.Add($_) }

    # ---------------------------------------------------------
    # RANSOMWARE EXTENSIONS from config
    # ---------------------------------------------------------
    $ransomExtensionSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    if($null -ne $configData -and $configData.PSObject.Properties["Ransomeware_Extensions"]){
        $configData.Ransomeware_Extensions |
            ForEach-Object { [void]$ransomExtensionSet.Add($_) }
        Write-ForensicLog "[*] Loaded $($ransomExtensionSet.Count) ransomware extension(s) from config" -Level INFO -Section "RANSOMWARE_SCAN" -Details "Source: $($ransomExtensionSet.Count) extensions from config"
    }

    # ---------------------------------------------------------
    # RANSOM NOTE NAMES
    # ---------------------------------------------------------
    $ransomNotesFile = "$PSScriptRoot\Forensicator-Share\ransom_notes.txt"
    $repoUrl         = "https://github.com/ThreatLabz/ransomware_notes/archive/refs/heads/main.zip"
    $tempZip         = "$env:TEMP\ransomnotes_$(New-Guid).zip"
    $tempExtract     = "$env:TEMP\ransomnotes_$(New-Guid)"

    if(-not (Test-Path $ransomNotesFile)){
        Write-ForensicLog "[*] Downloading ransomware note dataset..." -Level INFO -Section "RANSOMWARE_SCAN" -Details "Attempting to download ransomware note dataset from $repoUrl"
        try{
            $tcp       = [System.Net.Sockets.TcpClient]::new()
            $reachable = $tcp.ConnectAsync("github.com", 443).Wait(3000)
            $tcp.Dispose()

            if($reachable){
                Invoke-WebRequest $repoUrl -OutFile $tempZip -UseBasicParsing -TimeoutSec 60
                Expand-Archive $tempZip -DestinationPath $tempExtract -Force

                Get-ChildItem $tempExtract -Recurse -File |
                    Select-Object -ExpandProperty Name |
                    Sort-Object -Unique |
                    Out-File $ransomNotesFile -Encoding UTF8

                Write-ForensicLog "[+] Ransom note list saved ($ransomNotesFile)" -Level INFO -Section "RANSOMWARE_SCAN" -Details "Ransom note list saved to $ransomNotesFile"
            }
            else{
                Write-ForensicLog "[!] github.com unreachable — skipping note dataset download" -Level WARNING -Section "RANSOMWARE_SCAN" -Details "Could not reach github.com to download ransomware note dataset"
            }
        }
        catch{
            Write-ForensicLog "[!] Failed to download ransomware notes: $($_.Exception.Message)" -Level ERROR -Section "RANSOMWARE_SCAN" -Details "Attempted Download from URL: $repoUrl Failed"
        }
        finally{
            Remove-Item $tempZip      -Force -ErrorAction SilentlyContinue
            Remove-Item $tempExtract  -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Build HashSet for O(1) case-insensitive note name lookup
    $ransomNoteSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    if(Test-Path $ransomNotesFile){
        Get-Content $ransomNotesFile |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { [void]$ransomNoteSet.Add($_.Trim()) }
    }
    Write-ForensicLog "[*] Loaded $($ransomNoteSet.Count) ransom note indicator(s)" -Level INFO -Section "RANSOMWARE_SCAN" -Details "Source: $($ransomNoteSet.Count) note names from $repoUrl"

    # ---------------------------------------------------------
    # ENTROPY — samples beginning, middle, and end of file
    # Catches partially encrypted files that a head-only read misses
    # ---------------------------------------------------------
    function Get-FileEntropy {
        param([string]$Path, [long]$FileSize)

        try{
            $stream    = [System.IO.File]::OpenRead($Path)
            $chunkSize = 65536  # 64KB per sample
            $buffer    = [byte[]]::new($chunkSize * 3)
            $totalRead = 0

            # Sample start
            $read       = $stream.Read($buffer, 0, $chunkSize)
            $totalRead += $read

            # Sample middle
            if($FileSize -gt $chunkSize * 2){
                $stream.Seek([long]($FileSize / 2), [System.IO.SeekOrigin]::Begin) | Out-Null
                $read       = $stream.Read($buffer, $chunkSize, $chunkSize)
                $totalRead += $read
            }

            # Sample end
            if($FileSize -gt $chunkSize){
                $stream.Seek([Math]::Max(0, $FileSize - $chunkSize), [System.IO.SeekOrigin]::Begin) | Out-Null
                $read       = $stream.Read($buffer, $chunkSize * 2, $chunkSize)
                $totalRead += $read
            }

            $stream.Close()
            if($totalRead -le 0){ return 0 }

            $counts = [int[]]::new(256)
            for($i = 0; $i -lt $totalRead; $i++){ $counts[$buffer[$i]]++ }

            $entropy = 0.0
            foreach($count in $counts){
                if($count -le 0){ continue }
                $p        = $count / $totalRead
                $entropy -= $p * [Math]::Log($p, 2)
            }
            return $entropy
        }
        catch{ return 0 }
    }

    # ---------------------------------------------------------
    # SHADOW COPY DELETION CHECK
    # These are the canonical methods ransomware uses to prevent
    # recovery — presence of any of these in recent event logs
    # or running processes is a strong indicator
    # ---------------------------------------------------------
    function Get-ShadowCopyDeletionIndicators {

        $indicators = @()

        # Method 1 — check if VSS snapshots still exist
        # If a machine that had snapshots now has none, deletion may have occurred
        $vssSnapshots = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
        if($null -eq $vssSnapshots -or $vssSnapshots.Count -eq 0){
            $indicators += [PSCustomObject]@{
                Method   = "No VSS snapshots present"
                Detail   = "No shadow copies found — may have been deleted or never created"
                Severity = "Medium"
            }
        }
        else{
            Write-ForensicLog "[+] $($vssSnapshots.Count) VSS snapshot(s) still present" -Level INFO -Section "RANSOMWARE_SCAN" -Details "Snapshot count: $($vssSnapshots.Count) — presence of snapshots does not rule out ransomware but is a positive sign"
        }

        # Method 2 — Security event log: Process creation events (4688)
        # Looks for vssadmin, wmic, wbadmin, bcdedit with deletion args
        $deletionPatterns = @(
            'vssadmin.*delete.*shadows',
            'wmic.*shadowcopy.*delete',
            'wbadmin.*delete.*catalog',
            'bcdedit.*/set.*recoveryenabled.*no',
            'bcdedit.*/set.*bootstatuspolicy',
            'diskshadow.*delete'
        )

        try{
            # Look back 7 days for process creation events
            $cutoff = (Get-Date).AddDays(-7)
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4688
                StartTime = $cutoff
            } -ErrorAction SilentlyContinue |
            Where-Object {
                $msg = $_.Message
                $deletionPatterns | Where-Object { $msg -match $_ }
            }

            foreach($e in $events){
                $indicators += [PSCustomObject]@{
                    Method   = "Process creation (Event 4688)"
                    Detail   = ($e.Message -replace '\s+',' ').Substring(0,[Math]::Min(300,$e.Message.Length))
                    Severity = "High"
                }
            }
        }
        catch{
            Write-Verbose "[!] Could not query Security event log — may need elevated privileges" -Level ERROR -Section "RANSOMWARE_SCAN"
        }

        # Method 3 — PowerShell/System event logs for wbadmin/vssadmin
        try{
            $psEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-PowerShell/Operational'
                Id        = 4104
                StartTime = (Get-Date).AddDays(-7)
            } -ErrorAction SilentlyContinue |
            Where-Object {
                $msg = $_.Message
                $deletionPatterns | Where-Object { $msg -match $_ }
            }

            foreach($e in $psEvents){
                $indicators += [PSCustomObject]@{
                    Method   = "PowerShell ScriptBlock (Event 4104)"
                    Detail   = ($e.Message -replace '\s+',' ').Substring(0,[Math]::Min(300,$e.Message.Length))
                    Severity = "High"
                }
            }
        }
        catch{ }

        # Method 4 — Check if bcdedit has recovery disabled RIGHT NOW
        try{
            $bcdedit = & bcdedit /enum {current} 2>$null
            if($bcdedit -match 'recoveryenabled\s+No'){
                $indicators += [PSCustomObject]@{
                    Method   = "Boot recovery disabled (bcdedit)"
                    Detail   = "bcdedit shows recoveryenabled=No on current boot entry"
                    Severity = "High"
                }
            }
            if($bcdedit -match 'bootstatuspolicy\s+IgnoreAllFailures'){
                $indicators += [PSCustomObject]@{
                    Method   = "Boot status policy tampered (bcdedit)"
                    Detail   = "bootstatuspolicy=IgnoreAllFailures — suppresses recovery boot menu"
                    Severity = "High"
                }
            }
        }
        catch{ }

        # Method 5 — Check currently running processes for deletion tools
        $suspiciousProcs = Get-CimInstance Win32_Process |
            Where-Object {
                $_.CommandLine -match 'vssadmin.*delete|wmic.*shadowcopy.*delete|wbadmin.*delete|diskshadow'
            }

        foreach($proc in $suspiciousProcs){
            $indicators += [PSCustomObject]@{
                Method   = "Live process — shadow deletion in progress"
                Detail   = "PID $($proc.ProcessId): $($proc.CommandLine)"
                Severity = "Critical"
            }
        }

        return $indicators
    }

    # ---------------------------------------------------------
    # SCAN PATHS
    # ---------------------------------------------------------
    $ScanPaths = @(
        "$env:SystemDrive\Users",
        "$env:SystemDrive\ProgramData",
        "$env:SystemRoot\Temp"
    )

    $RansomNotesFound  = @()
    $HighEntropyFiles  = @()
    $RansomExtFiles    = @()
    $RecentFiles       = @()
    $cutoffTime        = (Get-Date).AddHours(-1)

    foreach($scanPath in $ScanPaths){
        if(-not (Test-Path $scanPath)){ continue }

        Write-ForensicLog "[*] Scanning $scanPath ..." -Level INFO -Section "RANSOMWARE_SCAN" -Details "Scanning $scanPath for ransom notes, suspicious extensions, high entropy, and recent modifications"

        Get-ChildItem $scanPath -Recurse -File -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            $file = $_
            $ext  = $file.Extension.ToLower()

            # Ransom note check — case insensitive via HashSet
            if($ransomNoteSet.Contains($file.Name)){
                $RansomNotesFound += $file
            }

            # Ransomware extension check
            if($ransomExtensionSet.Count -gt 0 -and $ransomExtensionSet.Contains($ext)){
                $RansomExtFiles += [PSCustomObject]@{
                    File      = $file.FullName
                    Extension = $ext
                    Size      = $file.Length
                    LastWrite = $file.LastWriteTimeUTC
                }
            }

            # Entropy check — skip naturally high-entropy formats
            # Only check files >10KB to avoid noise from tiny files
            if($file.Length -gt 10240 -and -not $excludedEntropyExtensions.Contains($ext)){
                $entropy = Get-FileEntropy $file.FullName $file.Length
                if($entropy -gt 7.8){
                    $HighEntropyFiles += [PSCustomObject]@{
                        File      = $file.FullName
                        Extension = $ext
                        Entropy   = [Math]::Round($entropy, 3)
                        Size      = $file.Length
                        LastWrite = $file.LastWriteTimeUTC
                    }
                }
            }

            # Mass modification detection
            if($file.LastWriteTime -gt $cutoffTime){
                $RecentFiles += $file
            }
        }
    }

    # ---------------------------------------------------------
    # SHADOW COPY DELETION
    # ---------------------------------------------------------
    Write-ForensicLog "[*] Checking shadow copy deletion indicators..." -Level INFO -Section "RANSOMWARE_SCAN"
    $ShadowIndicators = Get-ShadowCopyDeletionIndicators

    # ---------------------------------------------------------
    # HTML OUTPUT
    # ---------------------------------------------------------


    foreach($note in $RansomNotesFound){
        $RansomNoteFragment += "<tr style='background-color:#ffcccc;'>"
        $RansomNoteFragment += "<td>Ransom Note</td>"
        $RansomNoteFragment += "<td>$($note.FullName)</td>"
        $RansomNoteFragment += "<td>Filename matches known ransom note: $($note.Name)</td>"
        $RansomNoteFragment += "<td>$($note.LastWriteTimeUTC)</td>"
        $RansomNoteFragment += "</tr>"
    }

    foreach($f in $RansomExtFiles){
        $RansomExtFragment += "<tr style='background-color:#ffddcc;'>"
        $RansomExtFragment += "<td>Ransomware Extension</td>"
        $RansomExtFragment += "<td>$($f.File)</td>"
        $RansomExtFragment += "<td>Extension: $($f.Extension)</td>"
        $RansomExtFragment += "<td>$($f.LastWrite)</td>"
        $RansomExtFragment += "</tr>"
    }

    foreach($f in $HighEntropyFiles){
        $HighEntropyFragment += "<tr style='background-color:#fff3cc;'>"
        $HighEntropyFragment += "<td>High Entropy File</td>"
        $HighEntropyFragment += "<td>$($f.File)</td>"
        $HighEntropyFragment += "<td>Entropy: $($f.Entropy) / 8.0 (ext: $($f.Extension))</td>"
        $HighEntropyFragment += "<td>$($f.LastWrite)</td>"
        $HighEntropyFragment += "</tr>"
    }

    

    # Shadow copy deletion table — separate fragment


    foreach($s in $ShadowIndicators){
        $color = switch($s.Severity){
            "Critical" { "#ffcccc" }
            "High"     { "#a85125" }
            "Medium"   { "#fff3cc" }
            default    { "#ffffff" }
        }
        $ShadowFragment += "<tr style='background-color:$color;'>"
        $ShadowFragment += "<td>$($s.Severity)</td>"
        $ShadowFragment += "<td>$($s.Method)</td>"
        $ShadowFragment += "<td>$($s.Detail)</td>"
        $ShadowFragment += "</tr>"
    }


    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------
    Write-Host ""
    Write-ForensicLog "[!] Ransomware Scan Summary" -Level INFO -Section "RANSOMWARE_SCAN"
    Write-ForensicLog "    Ransom notes detected       : $($RansomNotesFound.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Details "$($RansomNotesFound.Count) Files matching known ransom note names"
    Write-ForensicLog "    Ransomware extensions found : $($RansomExtFiles.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Details "$($RansomExtFiles.Count) Files with known ransomware extensions"
    Write-ForensicLog "    High entropy files          : $($HighEntropyFiles.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Details "$($HighEntropyFiles.Count) Files with high entropy indicating possible encryption"
    Write-ForensicLog "    Files modified in last hour : $($RecentFiles.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Details "$($RecentFiles.Count) Files modified within the last hour"
    Write-ForensicLog "    Shadow deletion indicators  : $($ShadowIndicators.Count)" -Level FINDING -Section "RANSOMWARE_SCAN" -Details "$($ShadowIndicators.Count) Indicators of shadow copy deletion"

    if($RansomNotesFound.Count -gt 0 -or $RansomExtFiles.Count -gt 0){
        Write-ForensicLog "[!] RANSOMWARE INDICATORS FOUND — escalate immediately" -Level FINDING -Section "RANSOMWARE_SCAN"
    }
    elseif($HighEntropyFiles.Count -gt 50 -and $RecentFiles.Count -gt 200){
        Write-ForensicLog "[!] High entropy + mass modification — possible active encryption" -Level FINDING -Section "RANSOMWARE_SCAN"
    }
    elseif($ShadowIndicators | Where-Object { $_.Severity -in @("High","Critical") }){
        Write-ForensicLog "[!] Shadow copy deletion detected — possible ransomware preparation" -Level FINDING -Section "RANSOMWARE_SCAN"
    }

    Write-ForensicLog -ForegroundColor Cyan "[!] Done"

    
} else {
    $ShadowFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Ransomware scan skipped or nothing found</td></tr>"
    $HighEntropyFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Ransomware scan skipped or nothing found</td></tr>"
    $RansomExtFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Ransomware scan skipped or nothing found</td></tr>"
    $RansomNoteFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>Ransomware scan skipped or nothing found</td></tr>"
}

#endregion

Write-ForensicLog ""

###########################################################################################################
#region NETWORK TRACE
###########################################################################################################

# configuration file path
#$configFile = "$PSScriptRoot\config.json"

# Read and parse the configuration file
#$configData = Get-Content $configFile | ConvertFrom-Json

mkdir $PSScriptRoot\$env:COMPUTERNAME\PCAP -ErrorAction SilentlyContinue | Out-Null

$session = "ForensicatorCapture"
$etlPath = "$PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:COMPUTERNAME.etl"
$netshduration = $configData.net_capture_duration

Write-ForensicLog "[*] Starting Network Trace" -Level INFO -Section "NETWORKTRACE"

# create session
New-NetEventSession -Name $session -LocalFilePath $etlPath | Out-Null

# add packet capture provider
Add-NetEventPacketCaptureProvider -SessionName $session `
                                  -Level 4 `
                                  -CaptureType BothPhysicalAndSwitch | Out-Null


# start capture
Start-NetEventSession -Name $session | Out-Null



Write-ForensicLog "[*] Capturing for $netshduration seconds..." -Level INFO -Section "NETWORKTRACE"
Start-Sleep -Seconds $netshduration


Stop-NetEventSession -Name $session
Remove-NetEventSession -Name $session

Write-ForensicLog "[!] Trace Completed — ETL saved to $etlPath" -Level SUCCESS -Section "NETWORKTRACE" -Details "Captured $netshduration seconds of network traffic to $etlPath"

#endregion



if($PCAP){

  Write-ForensicLog ""

    #mkdir $PSScriptRoot\$env:COMPUTERNAME\PCAP -ErrorAction SilentlyContinue | Out-Null
    $pcapPath = "$PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:COMPUTERNAME.pcapng"
    $netshduration   = $configData.net_capture_duration
    # Check pktmon supports direct pcapng output (build 2004+)
    $build = [System.Environment]::OSVersion.Version.Build
    

    if($build -ge 19041){
        Write-ForensicLog "[*] Starting Network Trace via pktmon" -Level INFO -Section "NETWORKTRACE"
        # Direct pcapng output — no conversion needed
        pktmon start --capture --pkt-size 0 --log-mode circular `
               --file-name $pcapPath 2>&1 | Out-Null

        Write-ForensicLog "[*] Capturing for $netshduration seconds..." -Level INFO -Section "NETWORKTRACE"
        Start-Sleep -Seconds $netshduration

        pktmon stop | Out-Null

        Write-ForensicLog "[!] Capture complete — PCAP saved to $pcapPath" -Level SUCCESS -Section "NETWORKTRACE" -Details "Captured $netshduration seconds of network traffic to $pcapPath"

    }
    else{

        Write-ForensicLog "[*] Starting Network Trace" -Level INFO -Section "NETWORKTRACE"
  Write-ForensicLog "[*] Running....." -Level INFO -Section "NETWORKTRACE"
   $netshduration   = $configData.net_capture_duration
  netsh trace start capture=yes Ethernet.Type=IPv4 tracefile=$PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.et1 | Out-Null
  Start-Sleep -s $netshduration
  $job = Start-Job { netsh trace stop } | Out-Null
  Wait-Job $job
  Receive-Job $job

  Write-ForensicLog "[!] Trace Completed" -Level SUCCESS -Section "NETWORKTRACE"

  Write-ForensicLog "[*] Converting to PCAP" -Level INFO -Section "NETWORKTRACE"


  if ((gwmi win32_operatingsystem | Select-Object osarchitecture).osarchitecture -eq "64-bit") {
    

    & $PSScriptRoot\Forensicator-Share\etl2pcapng64.exe $PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.et1 $PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.pcap
	
  }
  else {
    
    & $PSScriptRoot\Forensicator-Share\etl2pcapng86.exe $PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.et1 $PSScriptRoot\$env:COMPUTERNAME\PCAP\$env:computername.pcap

  }


    }

    Write-ForensicLog "[!] Done" -Level SUCCESS -Section "NETWORKTRACE"
}
 



#endregion




###########################################################################################################
#region  Export Event Logs       ##########################################################################
###########################################################################################################



if ($EVTX) {

  Write-ForensicLog ""
	
  Write-ForensicLog "[*] Gettting hold of some event logs" -Level INFO -Section "EVENTLOGS"
   
  # capture the EVENTLOGS
  # Logs to extract from server
  $logArray = @("System", "Security", "Application")

  # Grabs the server name to append to the log file extraction
  $servername = $env:computername

  # Provide the path with ending "\" to store the log file extraction.
  $destinationpath = "$PSScriptRoot\$env:COMPUTERNAME\EVTLOGS\"

  # If the destination path does not exist it will create it
  if (!(Test-Path -Path $destinationpath)) {
	
    New-Item -ItemType directory -Path $destinationpath | Out-Null
  }

  # Get the current date in YearMonthDay format
  $logdate = Get-Date -format yyyyMMddHHmm

  # Start Process Timer
  $StopWatch = [system.diagnostics.stopwatch]::startNew()


  Foreach ($log in $logArray) {
	
    # If using Clear and backup
    $destination = $destinationpath + $servername + "-" + $log + "-" + $logdate + ".evtx"

    Write-ForensicLog "[!] Finalizing" -Level INFO -Section "EVENTLOGS"

    # Extract each log file listed in $logArray from the local server.
    wevtutil epl $log $destination
  }

  Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EVENTLOGS"
  # End Code

  # Stop Timer
  $StopWatch.Stop()
  $TotalTime = $StopWatch.Elapsed.TotalSeconds
  $TotalTime = [math]::Round($totalTime, 2)

  Write-ForensicLog "[!] Extracting the logs took $TotalTime to Complete." -Level SUCCESS -Section "EVENTLOGS" -Details "Time taken to extract logs: $TotalTime seconds"


} 
else {

}

#endregion


############################################################
#region GETTING HOLD OF IIS & APACHE WEBLOGS ###############
############################################################

if ($WEBLOGS) {

  Write-ForensicLog ""

  #Lets get hold of some weblogs
  Write-ForensicLog "[*] Lets Get hold of some weblogs" -Level INFO -Section "WEBLOGS"
  Write-ForensicLog "[!] NOTE: This can take a while if you have large Apache/IIS Log Files" -Level INFO -Section "WEBLOGS"

  #checking if logs exists in the IIS Log directory
  if (!(Get-ChildItem C:\inetpub\logs\ *.log)) {
    Write-ForensicLog "[!] Cannot find any logs in IIS Log Directory" -Level WARN -Section "WEBLOGS"
  }
  else {
	
    #create IIS log Dirs
    mkdir "$PSScriptRoot\$env:COMPUTERNAME\IISLogs" | Out-Null

    Copy-Item -Path 'C:\inetpub\logs\*' -Destination "$PSScriptRoot\$env:COMPUTERNAME\IISLogs" -Recurse | Out-Null

	
  }


  #checking for Tomcat and try to get log files


  mkdir "$PSScriptRoot\$env:COMPUTERNAME\TomCatLogs" | Out-Null
  # Define the destination directory where you want to copy the logs
  $destinationDirectory = "$PSScriptRoot\$env:COMPUTERNAME\TomCatLogs"

  # Check if Tomcat is installed by checking the registry
  $regKey = "HKLM:\SOFTWARE\Apache Software Foundation\Tomcat"
  if (Test-Path $regKey) {
    Write-ForensicLog "Tomcat is installed. Proceeding with log file copy."
    
    # Get Tomcat installation directory from registry
    $tomcatInstallDir = (Get-ItemProperty -Path $regKey).InstallPath

    # Construct the source directory for Tomcat logs
    $sourceDirectory = Join-Path -Path $tomcatInstallDir -ChildPath "logs"

    # Check if the logs directory exists
    if (Test-Path $sourceDirectory) {
      # Create the destination directory if it doesn't exist
      if (-not (Test-Path $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory | Out-Null
      }

      # Copy the Tomcat log files to the destination directory
      Copy-Item -Path "$sourceDirectory\*.log" -Destination $destinationDirectory -Force -Recurse
        
      Write-ForensicLog "TomCat Log files copied successfully to $destinationDirectory" -Level SUCCESS -Section "WEBLOGS"
    }
    else {
      Write-ForensicLog "Tomcat logs directory not found. Cannot proceed with log file copy." -Level WARN -Section "WEBLOGS"
    }
  }
  else {
    Write-ForensicLog "Tomcat is not installed. Cannot proceed with log file copy." -Level WARN -Section "WEBLOGS"
  }


} 
else {

}

#endregion


#############################################################################################################
#region   View Log4j Paths        ###########################################################################
#############################################################################################################

if ($LOG4J) {
  Write-ForensicLog ""
   
  Write-ForensicLog "[*] Checking for log4j on all drives .....this may take a while." -Level INFO -Section "LOG4J"

  mkdir "$PSScriptRoot\$env:COMPUTERNAME\LOG4J" | Out-Null	
  # Checking for Log4j
  $DriveList = (Get-PSDrive -PSProvider FileSystem).Root
  ForEach ($Drive In $DriveList) {
    $Log4j = Get-ChildItem $Drive -rec -force -include *.jar -ea 0 | ForEach-Object { select-string 'JndiLookup.class' $_ } | Select-Object -exp Path | Out-File "$PSScriptRoot\$env:COMPUTERNAME\LOG4J\$env:computername.txt"

  }
   
  Write-ForensicLog "[!] Done" -Level SUCCESS -Section "LOG4J"
   
   
} 
else {

}

#endregion




if ($HASHCHECK) {
  
Write-ForensicLog ""

#############################################################################################################
#region   MALWARE HASH LOOKUP — OPTIMISED
#############################################################################################################

Write-ForensicLog "Starting malware hash lookup" -Level INFO -Section "HASHLOOKUP"

# ---------------------------------------------------------
# SCAN TARGET CONFIGURATION
# Prioritised paths — most likely locations for malware
# Scanned in order, most suspicious first
# Add or remove paths to suit your environment
# ---------------------------------------------------------
$scanConfig = [ordered]@{

    # Tier 1 — Highest priority, always scan
    # These are the most common malware staging locations
    "UserWritable" = @{
        Paths = @(
            "$env:SystemDrive\Users",
            "$env:TEMP",
            "$env:SystemRoot\Temp",
            "$env:ProgramData"
        )
        Priority  = 1
        Recurse   = $true
        MaxAgeDays = 90     # only files modified in last 90 days
    }

    # Tier 2 — High priority system locations
    # Legitimate software rarely drops new files here
    "SystemBinaries" = @{
        Paths = @(
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64",
            "$env:SystemRoot\Tasks"
        )
        Priority   = 2
        Recurse    = $false  # non-recursive — legit files are not in subdirs
        MaxAgeDays = 180
    }

    # Tier 3 — Program directories
    # Slower, more false positives but catches trojanised installs
    "ProgramFiles" = @{
        Paths = @(
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)}
        )
        Priority   = 3
        Recurse    = $true
        MaxAgeDays = 60
    }

    # Tier 4 — Full drive scan (optional, slowest)
    # Only enable if Tier 1-3 clean and deeper analysis needed
    # Comment out if you want faster results
    <#
    "FullScan" = @{
        Paths = @( "$env:SystemDrive\" )
        Priority   = 4
        Recurse    = $true
        MaxAgeDays = 365
    }
    #>
}

# Paths to always skip regardless of scan tier
# Add any known-clean noisy directories here
$skipPaths = @(
    "$env:SystemRoot\WinSxS",
    "$env:SystemRoot\servicing",
    "$env:SystemRoot\assembly",
    "$env:SystemRoot\Microsoft.NET",
    "$env:SystemDrive\`$Recycle.Bin",
    "$env:SystemDrive\`$Windows.~WS",
    "$env:SystemDrive\`$Windows.~BT"
)

$skipPathSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$skipPaths | ForEach-Object { [void]$skipPathSet.Add($_) }

$execExtensions = if($null -ne $configData -and $configData.PSObject.Properties["executables_extensions"]){
    $configData.executables_extensions
} else {
    @("*.exe","*.dll","*.bat","*.cmd","*.ps1","*.vbs","*.js","*.hta","*.scr","*.com")
}

$hashSource   = if($null -ne $configData -and $configData.PSObject.Properties["hash_source"]){
    $configData.hash_source
} else {
    "https://bazaar.abuse.ch/export/txt/md5/recent/"
}

$hashFilePath = "$PSScriptRoot\Forensicator-Share\md5hashes.txt"
mkdir "$PSScriptRoot\$env:COMPUTERNAME\HashMatches" -ErrorAction SilentlyContinue | Out-Null

# ---------------------------------------------------------
# HASH FILE — download or refresh if stale
# ---------------------------------------------------------
$needsDownload = -not (Test-Path $hashFilePath)
if(-not $needsDownload){
    $ageDays = (New-TimeSpan -Start (Get-Item $hashFilePath).LastWriteTime -End (Get-Date)).TotalDays
    if($ageDays -gt 7){
        $needsDownload = $true
        Write-ForensicLog "Hash file is $([Math]::Round($ageDays,0)) days old — refreshing" `
                          -Level WARN -Section "HASHLOOKUP"
    }
}

if($needsDownload){
    try{
        $tcp = [System.Net.Sockets.TcpClient]::new()
        if($tcp.ConnectAsync("bazaar.abuse.ch", 443).Wait(3000)){
            Invoke-WebRequest -Uri $hashSource -OutFile $hashFilePath `
                              -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            Write-ForensicLog "Hash file downloaded" -Level SUCCESS -Section "HASHLOOKUP"
        }
        $tcp.Dispose()
    }
    catch{
        Write-ForensicLog "Hash file download failed: $($_.Exception.Message)" `
                          -Level ERROR -Section "HASHLOOKUP"
    }
}

if(-not (Test-Path $hashFilePath)){
    Write-ForensicLog "No hash file available — cannot proceed" -Level ERROR -Section "HASHLOOKUP" -Details "Hash lookup stage requires a local hash file. Attempted to download from $hashSource but failed. Check network connectivity and try again."
}

# ---------------------------------------------------------
# LOAD HASHES INTO HASHSET
# ---------------------------------------------------------
Write-ForensicLog "Loading hash database" -Level INFO -Section "HASHLOOKUP"

$knownBadHashes = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
Get-Content $hashFilePath |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith("#") } |
    ForEach-Object { [void]$knownBadHashes.Add($_.Trim().ToLower()) }

Write-ForensicLog "Loaded $($knownBadHashes.Count) known-bad hashes" -Level INFO -Section "HASHLOOKUP"

# ---------------------------------------------------------
# FILE COLLECTION
# Gather candidate files across all tiers before hashing
# Applying all filters here means the hash stage only touches
# files that actually need checking
# ---------------------------------------------------------
Write-ForensicLog "Collecting candidate files across scan tiers" -Level INFO -Section "HASHLOOKUP"

$candidateFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$cutoffDates    = @{}

foreach($tier in $scanConfig.GetEnumerator() | Sort-Object { $_.Value.Priority }){

    $tierName  = $tier.Key
    $tierConf  = $tier.Value
    $cutoff    = (Get-Date).AddDays(-$tierConf.MaxAgeDays)
    $cutoffDates[$tierName] = $cutoff

    Write-ForensicLog "Collecting Tier $($tierConf.Priority) — $tierName" `
                      -Level INFO -Section "HASHLOOKUP"

    foreach($path in $tierConf.Paths){
        if(-not (Test-Path $path)){ continue }

        foreach($ext in $execExtensions){
            try{
                Get-ChildItem -Path $path `
                              -Filter $ext `
                              -Recurse:$tierConf.Recurse `
                              -Force `
                              -ErrorAction SilentlyContinue |
                Where-Object {
                    -not $_.PSIsContainer           -and
                    $_.Length -gt 0                 -and
                    $_.Length -le 500MB             -and
                    $_.LastWriteTime -gt $cutoff    -and
                    # Skip files in excluded paths
                    -not ($skipPathSet | Where-Object { $_.FullName -like "$_*" })
                } |
                ForEach-Object { $candidateFiles.Add($_) }
            }
            catch{ }
        }
    }
}

# Deduplicate by full path — a file may be caught by multiple tiers
$candidateFiles = $candidateFiles |
                  Sort-Object FullName -Unique

Write-ForensicLog "Candidate files to hash: $($candidateFiles.Count)" `
                  -Level INFO -Section "HASHLOOKUP"

# ---------------------------------------------------------
# PARALLEL HASHING
# Uses runspaces for PS5.1 compatibility
# ForEach-Object -Parallel requires PS7 — runspaces work on both
# ---------------------------------------------------------
$hashResults  = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$threadCount  = [Math]::Min([Environment]::ProcessorCount, 8)  # cap at 8 threads

Write-ForensicLog "Hashing with $threadCount parallel threads" -Level INFO -Section "HASHLOOKUP"

$scriptBlock = {
    param($FilePath, $KnownBadHashes)

    try{
        $md5Alg    = [System.Security.Cryptography.MD5]::Create()
        $sha256Alg = [System.Security.Cryptography.SHA256]::Create()
        $stream    = [System.IO.File]::OpenRead($FilePath)

        $md5Hash    = ([BitConverter]::ToString($md5Alg.ComputeHash($stream))    -replace "-","").ToLower()
        $stream.Position = 0
        $sha256Hash = ([BitConverter]::ToString($sha256Alg.ComputeHash($stream)) -replace "-","").ToLower()

        $stream.Dispose()
        $md5Alg.Dispose()
        $sha256Alg.Dispose()

        $md5Match    = $KnownBadHashes.Contains($md5Hash)
        $sha256Match = $KnownBadHashes.Contains($sha256Hash)

        if($md5Match -or $sha256Match){
            return [PSCustomObject]@{
                FilePath    = $FilePath
                MD5         = $md5Hash
                SHA256      = $sha256Hash
                MD5Match    = $md5Match
                SHA256Match = $sha256Match
            }
        }
    }
    catch{ }
    return $null
}

# Runspace pool
$pool    = [RunspaceFactory]::CreateRunspacePool(1, $threadCount)
$pool.Open()
$jobs    = [System.Collections.Generic.List[hashtable]]::new()
$total   = $candidateFiles.Count
$counter = 0

foreach($file in $candidateFiles){
    $counter++

    if($counter % 200 -eq 0){
        Write-Progress -Activity "Hashing files" `
                       -Status "[$counter / $total] $($file.Name)" `
                       -PercentComplete ([Math]::Round(($counter / $total) * 100))
    }

    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($scriptBlock)
    [void]$ps.AddArgument($file.FullName)
    [void]$ps.AddArgument($knownBadHashes)

    $jobs.Add(@{
        PS     = $ps
        Handle = $ps.BeginInvoke()
        File   = $file
    })

    # Collect completed jobs in batches to keep memory controlled
    if($jobs.Count -ge $threadCount * 4){
        $completed = $jobs | Where-Object { $_.Handle.IsCompleted }
        foreach($job in $completed){
            $result = $job.PS.EndInvoke($job.Handle)
            if($result){ $hashResults.Add($result) }
            $job.PS.Dispose()
            [void]$jobs.Remove($job)
        }
    }
}

# Collect remaining jobs
foreach($job in $jobs){
    $job.Handle.AsyncWaitHandle.WaitOne() | Out-Null
    $result = $job.PS.EndInvoke($job.Handle)
    if($result){ $hashResults.Add($result) }
    $job.PS.Dispose()
}

$pool.Close()
$pool.Dispose()
Write-Progress -Activity "Hashing files" -Completed

# ---------------------------------------------------------
# ENRICH MATCHES with file metadata
# Done after hashing — only on matched files (hopefully few)
# ---------------------------------------------------------
$hashMatches = foreach($match in $hashResults){
    try{
        $fileInfo = Get-Item $match.FilePath -ErrorAction Stop
        $owner    = (Get-Acl $match.FilePath -ErrorAction SilentlyContinue).Owner

        [PSCustomObject]@{
            DetectedFile  = $match.FilePath
            FileName      = $fileInfo.Name
            Extension     = $fileInfo.Extension
            FileSizeKB    = [Math]::Round($fileInfo.Length / 1KB, 1)
            MD5           = $match.MD5
            SHA256        = $match.SHA256
            MD5Match      = $match.MD5Match
            SHA256Match   = $match.SHA256Match
            LastModified  = $fileInfo.LastWriteTimeUTC.ToString("yyyy-MM-dd HH:mm:ss")
            CreationTime  = $fileInfo.CreationTimeUTC.ToString("yyyy-MM-dd HH:mm:ss")
            Owner         = $owner
        }
    }
    catch{ }
}

Write-ForensicLog "Scan complete — Scanned: $total | Matches: $($hashMatches.Count)" `
                  -Level $(if($hashMatches.Count -gt 0){ "FINDING" } else { "SUCCESS" }) `
                  -Section "HASHLOOKUP" `
                  -Detail "Threads: $threadCount"

# ---------------------------------------------------------
# HTML OUTPUT
# ---------------------------------------------------------


if($hashMatches.Count -gt 0){
    foreach($m in $hashMatches){
        $HashMatchFragment += "<tr style='background-color:#ffcccc;'>"
        $HashMatchFragment += "<td>$($m.DetectedFile)</td>"
        $HashMatchFragment += "<td>$($m.Extension)</td>"
        $HashMatchFragment += "<td>$($m.FileSizeKB)</td>"
        $HashMatchFragment += "<td><code>$($m.MD5)</code></td>"
        $HashMatchFragment += "<td><code>$($m.SHA256)</code></td>"
        $HashMatchFragment += "<td>$(if($m.MD5Match)   {'&#9888; YES'} else {''})</td>"
        $HashMatchFragment += "<td>$(if($m.SHA256Match){'&#9888; YES'} else {''})</td>"
        $HashMatchFragment += "<td>$($m.LastModified)</td>"
        $HashMatchFragment += "<td>$($m.CreationTime)</td>"
        $HashMatchFragment += "<td>$($m.Owner)</td>"
        $HashMatchFragment += "</tr>"
    }

    $hashMatches | Export-Csv `
        "$PSScriptRoot\$env:COMPUTERNAME\HashMatches\MalwareHashMatch.csv" `
        -NoTypeInformation -Encoding UTF8

    Write-ForensicLog "$($hashMatches.Count) malware match(es) found" `
                      -Level FINDING -Section "HASHLOOKUP"
}
else{
    $HashMatchFragment += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>No hash matches found across $total files scanned</td></tr>"
}




Write-ForensicLog "Hash lookup complete" -Level SUCCESS -Section "HASHLOOKUP"



} 
else {
  $HashMatchFragment += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>Hash lookup skipped or nothing found</td></tr>"

}

#endregion

Write-ForensicLog ""


#####################################################################################################################
######################################################################################################################
#region     EVENT LOG ANALYSIS SECTION		     	     #################################################################
######################################################################################################################
######################################################################################################################
<#
$logonTypeMap = @{
    "2"  = @{ Name="Interactive";        Risk="Medium"; Note="Console/RunAs logon" }
    "3"  = @{ Name="Network";            Risk="Medium"; Note="SMB/WMI/net use" }
    "4"  = @{ Name="Batch";              Risk="Low";    Note="Scheduled task" }
    "5"  = @{ Name="Service";            Risk="Low";    Note="Service account" }
    "7"  = @{ Name="Unlock";             Risk="Medium"; Note="Workstation unlock" }
    "8"  = @{ Name="NetworkCleartext";   Risk="High";   Note="Plaintext credentials over network" }
    "9"  = @{ Name="NewCredentials";     Risk="High";   Note="RunAs /netonly — lateral movement" }
    "10" = @{ Name="RemoteInteractive";  Risk="Medium"; Note="RDP" }
    "11" = @{ Name="CachedInteractive";  Risk="Medium"; Note="Cached credentials" }
}
#>
<#
$failureReasons = @{
    "0xC000005E" = "No logon servers available"
    "0xC0000064" = "Username does not exist"
    "0xC000006A" = "Wrong password"
    "0xC000006D" = "Bad username or auth package"
    "0xC000006E" = "Account restriction"
    "0xC000006F" = "Outside allowed logon hours"
    "0xC0000070" = "Workstation restriction"
    "0xC0000071" = "Password expired"
    "0xC0000072" = "Account disabled"
    "0xC0000193" = "Account expired"
    "0xC0000224" = "Password must change"
    "0xC0000234" = "Account locked out"
    "0xC00002EE" = "An error occurred during logon"
}
#>
#############################################################################################################
#region   EVENT LOG ANALYSIS — GROUP ENUMERATION (4798 / 4799)
#############################################################################################################


Write-ForensicLog "[*] Checking for user/group enumeration events" -Level INFO -Section "EventLog"

$GroupMembershipID = @(
  4798,
  4799

)
$GroupMembershipFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $GroupMembershipID }
$GroupMembership = Get-WinEvent -FilterHashtable $GroupMembershipFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $GroupMembershipEventXml = ([xml]$_.ToXml()).Event
  $GroupMembershipEnumAccount = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $GroupMembershipPerformedBy = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $GroupMembershipPerformedLogon = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
  $GroupMembershipPerformedPID = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessId' }).'#text'
  $GroupMembershipPerformedPName = ($GroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time        = [DateTime]$GroupMembershipEventXml.System.TimeCreated.SystemTime
    PerformedOn = $GroupMembershipEnumAccount
    PerformedBy = $GroupMembershipPerformedBy
    LogonType   = $GroupMembershipPerformedLogon
    PID         = $GroupMembershipPerformedPID
    ProcessName = $GroupMembershipPerformedPName
  }
} 

if ($GroupMembership.Count -eq 0) {
    $GroupMembershipFragment += "<tr><td colspan='7' style='text-align:center;color:#27ae60;'>No group enumeration events found</td></tr>"
}

# Populate the HTML table with process information
foreach ($process in $GroupMembership) {
  $GroupMembershipFragment += "<tr>"
  $GroupMembershipFragment += "<td>$([DateTime]$process.Time)</td>"
  $GroupMembershipFragment += "<td>$($process.PerformedOn)</td>"
  $GroupMembershipFragment += "<td>$($process.PerformedBy)</td>"
  $GroupMembershipFragment += "<td>$($process.LogonType)</td>"
  $GroupMembershipFragment += "<td>$($process.PID)</td>"
  $GroupMembershipFragment += "<td>$($GroupMembershipPerformedPName)</td>"
  $GroupMembershipFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion



###############################################################################
### RDP Logins                        #########################################
###############################################################################

Write-ForensicLog "[*] Fetching RDP Logins" -Level INFO -Section "EventLog"

$RDPGroupID = @(
  4624,
  4778
)

$RDPFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $RDPGroupID } 
$RDPLogins = Get-WinEvent -FilterHashtable $RDPFilter | Where-Object { $_.properties[8].value -eq 10 } | ForEach-Object {
  # convert the event to XML and grab the Event node
  $RDPEventXml = ([xml]$_.ToXml()).Event
  $RDPLogonUser = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $RDPLogonUserDomain = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
  $RDPLogonIP = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time            = [DateTime]$RDPEventXml.System.TimeCreated.SystemTime
    LogonUser       = $RDPLogonUser
    LogonUserDomain = $RDPLogonUserDomain
    LogonIP         = $RDPLogonIP
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($RDPLogins.Count -eq 0) {
    $RDPLoginsFragment += "<tr><td colspan='4' style='text-align:center;color:#27ae60;'>No RDP logins found</td></tr>"
}

# Populate the HTML table with process information
foreach ($process in $RDPLogins) {
  $RDPLoginsFragment += "<tr>"
  $RDPLoginsFragment += "<td>$([DateTime]$process.Time)</td>"
  $RDPLoginsFragment += "<td>$($process.LogonUser)</td>"
  $RDPLoginsFragment += "<td>$($process.LogonUserDomain)</td>"
  $RDPLoginsFragment += "<td>$($process.LogonIP)</td>"
  $RDPLoginsFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion

###############################################################################
### RDP Logins All History            #########################################
###############################################################################

Write-ForensicLog "[*] Fetching History of All RDP Logons to this system" -Level INFO -Section "EventLog"

$RDPGroupID = @(
  1149
)

$RDPAuths = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=1149]]</Select></Query></QueryList>'
[xml[]]$xml = $RDPAuths | ForEach-Object { $_.ToXml() }
$EventData = Foreach ($event in $xml.Event) {
  New-Object PSObject -Property @{
    TimeCreated = (Get-Date ($event.System.TimeCreated.SystemTime) -Format 'yyyy-MM-dd hh:mm:ss K')
    User        = $event.UserData.EventXML.Param1
    Domain      = $event.UserData.EventXML.Param2
    Client      = $event.UserData.EventXML.Param3
  }
} #$EventData | FT

if ($EventData.Count -eq 0) {
    $RDPAuthsFragment += "<tr><td colspan='4' style='text-align:center;color:#27ae60;'>No RDP authentication events found</td></tr>"
}

# Populate the HTML table with process information
foreach ($process in $EventData) {
  $RDPAuthsFragment += "<tr>"
  $RDPAuthsFragment += "<td>$($process.TimeCreated)</td>"
  $RDPAuthsFragment += "<td>$($process.User)</td>"
  $RDPAuthsFragment += "<td>$($process.Domain)</td>"
  $RDPAuthsFragment += "<td>$($process.Client)</td>"
  $RDPAuthsFragment += "</tr>"
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Outgoing RDP Connections            #########################################
###############################################################################

Write-ForensicLog "[*] Fetching All outgoing RDP connection History" -Level INFO -Section "EventLog"


# Define the properties array properly
$properties = @(
  @{n = 'TimeStamp'; e = { $_.TimeCreated } }
  @{n = 'LocalUser'; e = { [System.Security.Principal.SecurityIdentifier]::new($_.UserID).Translate([System.Security.Principal.NTAccount]).Value } }
  @{n = 'Target RDP host'; e = { $_.Properties[1].Value } }
)

# Retrieve the events
$OutRDP = Get-WinEvent -FilterHashTable @{LogName = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'; ID = '1102' } | Select-Object $properties

if ($OutRDP.Count -eq 0) {
    $OutRDPFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No outgoing RDP connection events found</td></tr>"
}

# INFOialize the HTML fragment
$OutRDPFragment = ""

# Populate the HTML table with event information
foreach ($event in $OutRDP) {
  $OutRDPFragment += "<tr>"
  $OutRDPFragment += "<td>$($event.TimeStamp)</td>"
  $OutRDPFragment += "<td>$($event.LocalUser)</td>"
  $OutRDPFragment += "<td>$($event.'Target RDP host')</td>"  
  $OutRDPFragment += "</tr>"
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Created Users                 #############################################
###############################################################################


Write-ForensicLog "[*] Fetching Created Users" -Level INFO -Section "EventLog"

$CreatedUsersGroupID = @(
  4720
)

$CreatedUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $CreatedUsersGroupID }
$CreatedUsers = Get-WinEvent -FilterHashtable $CreatedUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CreatedUsersEventXml = ([xml]$_.ToXml()).Event
  $CreatedUser = ($CreatedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $CreatedUsersTarget = ($CreatedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time        = [DateTime]$CreatedUsersEventXml.System.TimeCreated.SystemTime
    CreatedUser = $CreatedUser
    CreatedBy   = $CreatedUsersTarget
  }
} # | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($CreatedUsers.Count -eq 0) {
    $CreatedUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No user creation events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $CreatedUsers) {
  $CreatedUsersFragment += "<tr>"
  $CreatedUsersFragment += "<td>$([DateTime]$CreatedUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $CreatedUsersFragment += "<td>$($CreatedUser)</td>"
  $CreatedUsersFragment += "<td>$($CreatedUsersTarget)</td>"  
  $CreatedUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"


###############################################################################
### Password Resets               #############################################
###############################################################################


Write-ForensicLog "[*] Checking for password resets" -Level INFO -Section "EventLog"

$PassResetGroupID = @(
  4724
)

$PassResetFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $PassResetGroupID }
$PassReset = Get-WinEvent -FilterHashtable $PassResetFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $PassResetEventXml = ([xml]$_.ToXml()).Event
  $PassResetTargetUser = ($PassResetEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $PassResetActionedBy = ($PassResetEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time       = [DateTime]$PassResetEventXml.System.TimeCreated.SystemTime
    TargetUser = $PassResetTargetUser
    ActionedBy = $PassResetActionedBy
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($PassReset.Count -eq 0) {
    $PassResetFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No password reset events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $PassReset) {
  $PassResetFragment += "<tr>"
  $PassResetFragment += "<td>$([DateTime]$PassResetEventXml.System.TimeCreated.SystemTime)</td>"
  $PassResetFragment += "<td>$($PassResetTargetUser)</td>"
  $PassResetFragment += "<td>$($PassResetActionedBy)</td>"  
  $PassResetFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"


###############################################################################
### Added users to Group          #############################################
###############################################################################

Write-ForensicLog "[*] Checking for user, group, object access and credential manager actions" -Level INFO -Section "EventLog"

$AddedUsersGroupID = @(
  4732,
  4728
)
$AddedUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $AddedUsersGroupID }
$AddedUsers = Get-WinEvent -FilterHashtable $AddedUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $AddedUsersEventXml = ([xml]$_.ToXml()).Event
  $AddedUsersAddedBy = ($AddedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $AddedUsersTarget = ($AddedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'MemberSid' }).'#text'
  #SID CONVERSION
  $AddedUsersGobjSID = New-Object System.Security.Principal.SecurityIdentifier($AddedUsersTarget)
  $AddedUsersGobjUser = $AddedUsersGobjSID.Translate([System.Security.Principal.NTAccount])
  # output the properties you need
  [PSCustomObject]@{
    Time    = [DateTime]$AddedUsersEventXml.System.TimeCreated.SystemTime
    AddedBy = $AddedUsersAddedBy
    Target  = $AddedUsersGobjUser
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($AddedUsers.Count -eq 0) {
    $AddedUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No events of users being added to groups found</td></tr>"
}

foreach ($event in $AddedUsers) {
  $AddedUsersFragment += "<tr>"
  $AddedUsersFragment += "<td>$([DateTime]$AddedUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $AddedUsersFragment += "<td>$($AddedUsersAddedBy)</td>"
  $AddedUsersFragment += "<td>$($AddedUsersGobjUser)</td>"  
  $AddedUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Enabled Users                 #############################################
###############################################################################

Write-ForensicLog "[*] Checking for enabled users" -Level INFO -Section "EventLog"

$EnabledUsersGroupID = @(
  4722

)
$EnabledUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $EnabledUsersGroupID }
$EnabledUsers = Get-WinEvent -FilterHashtable $EnabledUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $EnabledUsersEventXml = ([xml]$_.ToXml()).Event
  $EnabledBy = ($EnabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $EnabledTarget = ($EnabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time           = [DateTime]$EnabledUsersEventXml.System.TimeCreated.SystemTime
    EnabledBy      = $EnabledBy
    EnabledAccount = $EnabledTarget
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($EnabledUsers.Count -eq 0) {
    $EnabledUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No user enablement events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $EnabledUsers) {
  $EnabledUsersFragment += "<tr>"
  $EnabledUsersFragment += "<td>$([DateTime]$EnabledUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $EnabledUsersFragment += "<td>$($EnabledBy)</td>"
  $EnabledUsersFragment += "<td>$($EnabledTarget)</td>"  
  $EnabledUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Disabled Users                #############################################
###############################################################################

Write-ForensicLog "[*] Checking for disabled users" -Level INFO -Section "EventLog"

$DisabledUsersGroupID = @(
  4723

)
$DisabledUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $DisabledUsersGroupID }
$DisabledUsers = Get-WinEvent -FilterHashtable $DisabledUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $DisabledUsersEventXml = ([xml]$_.ToXml()).Event
  $DisabledBy = ($DisabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $DisabledTarget = ($DisabledUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time       = [DateTime]$DisabledUsersEventXml.System.TimeCreated.SystemTime
    DisabledBy = $DisabledBy
    Disabled   = $DisabledTarget
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($DisabledUsers.Count -eq 0) {
    $DisabledUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No user disablement events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $DisabledUsers) {
  $DisabledUsersFragment += "<tr>"
  $DisabledUsersFragment += "<td>$([DateTime]$DisabledUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $DisabledUsersFragment += "<td>$($DisabledBy)</td>"
  $DisabledUsersFragment += "<td>$($DisabledTarget)</td>"  
  $DisabledUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Deleted Users                #############################################
###############################################################################

Write-ForensicLog "[*] Checking for deleted users" -Level INFO -Section "EventLog"

$DeletedUsersGroupID = @(
  4726

)
$DeletedUsersFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $DeletedUsersGroupID }
$DeletedUsers = Get-WinEvent -FilterHashtable $DeletedUsersFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $DeletedUsersEventXml = ([xml]$_.ToXml()).Event
  $DeletedBy = ($DeletedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $DeletedTarget = ($DeletedUsersEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time           = [DateTime]$DeletedUsersEventXml.System.TimeCreated.SystemTime
    DeletedBy      = $DeletedBy
    DeletedAccount = $DeletedTarget
  }
} #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($DeletedUsers.Count -eq 0) {
    $DeletedUsersFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No user deletion events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $DeletedUsers) {
  $DeletedUsersFragment += "<tr>"
  $DeletedUsersFragment += "<td>$([DateTime]$DeletedUsersEventXml.System.TimeCreated.SystemTime)</td>"
  $DeletedUsersFragment += "<td>$($DeletedBy)</td>"
  $DeletedUsersFragment += "<td>$($DeletedTarget)</td>"  
  $DeletedUsersFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Account Lockout               #############################################
###############################################################################

Write-ForensicLog "[*] Checking for account lockout events" -Level INFO -Section "EventLog"

$LockOutGroupID = @(
  4740

)
$LockOutFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $LockOutGroupID }
$LockOut = Get-WinEvent -FilterHashtable $LockOutFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $LockOutEventXml = ([xml]$_.ToXml()).Event
  $LockedOutAcct = ($LockOutEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
  $System = ($LockOutEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = [DateTime]$LockOutEventXml.System.TimeCreated.SystemTime
    LockedOutAccount = $LockedOutAcct
    System           = $System
  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($LockOut.Count -eq 0) {
    $LockOutFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No account lockout events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $LockOut) {
  $LockOutFragment += "<tr>"
  $LockOutFragment += "<td>$([DateTime]$LockOutEventXml.System.TimeCreated.SystemTime)</td>"
  $LockOutFragment += "<td>$($LockedOutAcct)</td>"
  $LockOutFragment += "<td>$($System)</td>"  
  $LockOutFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Credential Manager Backup                   ###############################
###############################################################################

Write-ForensicLog "[*] Checking for credential manager backup events" -Level INFO -Section "EventLog"

$CredManBackupGroupID = @(
  5376

)
$CredManBackupFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $CredManBackupGroupID }
$CredManBackup = Get-WinEvent -FilterHashtable $CredManBackupFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CredManBackupEventXml = ([xml]$_.ToXml()).Event
  $CredManBackupAcct = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $CredManBackupAcctLogon = ($CredManBackupEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = [DateTime]$CredManBackupEventXml.System.TimeCreated.SystemTime
    BackupAccount    = $CredManBackupAcct
    AccountLogonType = $CredManBackupAcctLogon

  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($CredManBackup.Count -eq 0) {
    $CredManBackupFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No credential manager backup events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $CredManBackup) {
  $CredManBackupFragment += "<tr>"
  $CredManBackupFragment += "<td>$([DateTime]$CredManBackupEventXml.System.TimeCreated.SystemTime)</td>"
  $CredManBackupFragment += "<td>$($CredManBackupAcct)</td>"
  $CredManBackupFragment += "<td>$($CredManBackupAcctLogon)</td>"  
  $CredManBackupFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

###############################################################################
### Credential Manager Restore                  ###############################
###############################################################################

Write-ForensicLog "[*] Checking for credential manager restore events" -Level INFO -Section "EventLog"

$CredManRestoreGroupID = @(
  5377

)
$CredManRestoreFilter = @{LogName = 'Security'; ProviderName = 'Microsoft-Windows-Security-Auditing'; ID = $CredManRestoreGroupID }
$CredManRestore = Get-WinEvent -FilterHashtable $CredManRestoreFilter | ForEach-Object {
  # convert the event to XML and grab the Event node
  $CredManRestoreEventXml = ([xml]$_.ToXml()).Event
  $RestoredAcct = ($CredManRestoreEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
  $CredManRestoreAcctLogon = ($CredManRestoreEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
  # output the properties you need
  [PSCustomObject]@{
    Time             = [DateTime]$CredManRestoreEventXml.System.TimeCreated.SystemTime
    RestoredAccount  = $RestoredAcct
    AccountLogonType = $CredManRestoreAcctLogon

  }
}# | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($CredManRestore.Count -eq 0) {
    $CredManRestoreFragment += "<tr><td colspan='3' style='text-align:center;color:#27ae60;'>No credential manager restore events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $CredManRestore) {
  $CredManRestoreFragment += "<tr>"
  $CredManRestoreFragment += "<td>$([DateTime]$CredManRestoreEventXml.System.TimeCreated.SystemTime)</td>"
  $CredManRestoreFragment += "<td>$($RestoredAcct)</td>"
  $CredManRestoreFragment += "<td>$($CredManRestoreAcctLogon)</td>"  
  $CredManRestoreFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion


#############################################################################################################
#region   EVENT LOG ANALYSIS   LOGON EVENTS           #######################################################
#############################################################################################################

Write-ForensicLog "[*] Checking for logon events" -Level INFO -Section "EventLog"

# SUCCESSFUL LOGON EVENTS

# Define variables for the event log name and event ID
$logName = "Security"
$eventID = 4624
#$eventID = 4625

# Query the event log for logon events
$logonEvents = Get-EventLog -LogName $logName -InstanceId $eventID -Newest 1000

# Create an array to hold the logon event details
$logonDetails = @()

# Loop through each logon event and extract the relevant details
foreach ($logonEvent in $logonEvents) {
  $eventProperties = [ordered]@{
    "Time"                   = $logonEvent.TimeGenerated
    "User"                   = $logonEvent.ReplacementStrings[5]
    "Logon Type"             = $logonEvent.ReplacementStrings[8]
    "Source Network Address" = $logonEvent.ReplacementStrings[18]
    "Status"                 = $logonEvent.ReplacementStrings[11]
  }
  $logonDetails += New-Object PSObject -Property $eventProperties
}

# Convert the logon details to HTML
#$Successhtml = $logonDetails #| ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

if ($logonDetails.Count -eq 0) {
    $logonEventsFragment += "<tr><td colspan='5' style='text-align:center;color:#27ae60;'>No logon events found</td></tr>"
}

# Populate the HTML table with event information
foreach ($event in $logonEvents) {
  $logonEventsFragment += "<tr>"
  $logonEventsFragment += "<td>$($logonEvent.TimeGenerated)</td>"
  $logonEventsFragment += "<td>$($logonEvent.ReplacementStrings[5])</td>"
  $logonEventsFragment += "<td>$($logonEvent.ReplacementStrings[8])</td>"
  $logonEventsFragment += "<td>$($logonEvent.ReplacementStrings[18])</td>"
  $logonEventsFragment += "<td>$($logonEvent.ReplacementStrings[11])</td>"  
  $logonEventsFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion


#############################################################################################
#region FAILED LOGON EVENTS           #######################################################
#############################################################################################

Write-ForensicLog "[*] Checking for failed logon events" -Level INFO -Section "EventLog"

# Define variables for the event log name and event ID
$logName = "Security"
#$eventID = 4624
$eventID = 4625

# Query the event log for logon events


    $Events = $null
    try{
        $Events = $logonEventsFailed = Get-EventLog -LogName $logName -InstanceId $eventID -Newest 1000 -ErrorAction Stop
        Write-ForensicLog "[*] Retrieved $($Events.Count) failed logon event(s)" -Level SUCCESS -Section "EventLog" -Detail "Failed Logon Retrieved $($Events.Count) events"
    }
    catch [System.Exception]{
        if($_.Exception.Message -match "No matches found"){
            Write-ForensicLog "[!] No failed logon events found" -Level WARN -Section "EventLog" -Detail "Failed Logon Retrieved 0 events"
            Write-ForensicLog "[!] This is expected if failed logon auditing is not configured" -Level WARN -Section "EventLog"
            $logonEventsFailedFragment += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>No failed logon events found</td></tr>"
        }
        else{
            Write-ForensicLog "[!] Query failed: $($_.Exception.Message)" -Level ERROR -Section "EventLog" -Detail "Failed Logon Query Failed"
        }
    }

# Create an array to hold the logon event details
$logonDetails = @()

# Loop through each logon event and extract the relevant details
foreach ($logonEvent in $logonEventsFailed) {
  $eventProperties = [ordered]@{
    "Time"                   = $logonEvent.TimeGenerated
    "User"                   = $logonEvent.ReplacementStrings[5]
    "Logon Type"             = $logonEvent.ReplacementStrings[8]
    "Source Network Address" = $logonEvent.ReplacementStrings[18]
    "Status"                 = $logonEvent.ReplacementStrings[11]
  }
  $logonDetails += New-Object PSObject -Property $eventProperties
}

# Convert the logon details to HTML
#$Failedhtml = $logonDetails | ConvertTo-Html -As LIST -fragment | Select-Object -Skip 1 | Select-Object -SkipLast 1

<#if ($logonDetails.Count -eq 0) {
    $logonEventsFailedFragment += "<tr><td colspan='5' style='text-align:center;color:#27ae60;'>No failed logon events found</td></tr>"
}
#>
# Populate the HTML table with event information
foreach ($event in $logonEventsFailed) {
  $logonEventsFailedFragment += "<tr>"
  $logonEventsFailedFragment += "<td>$($logonEvent.TimeGenerated)</td>"
  $logonEventsFailedFragment += "<td>$($logonEvent.ReplacementStrings[5])</td>"
  $logonEventsFailedFragment += "<td>$($logonEvent.ReplacementStrings[8])</td>"
  $logonEventsFailedFragment += "<td>$($logonEvent.ReplacementStrings[18])</td>"
  $logonEventsFailedFragment += "<td>$($logonEvent.ReplacementStrings[11])</td>"  
  $logonEventsFailedFragment += "</tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion

#############################################################################################################
#region   EVENT LOG ANALYSIS   OBJECT ACCESS          #######################################################
#############################################################################################################

Write-ForensicLog "[*] Checking for object access events" -Level INFO -Section "EventLog"

# ---------------------------------------------------------
# OBJECT ACCESS EVENTS — 4656 (handle requested) 
#                         4663 (object accessed)
# Requires: Audit Object Access enabled in Local Security Policy
# Requires: Elevated privileges to read Security log
# ---------------------------------------------------------

$StartTime = (Get-Date).AddDays(-30)  # Sensible default — adjust as needed
$EndTime   = Get-Date
$EventLog  = "Security"
$EventIDs  = @(4656, 4663)

# ---------------------------------------------------------
# CHECK 1 — confirm we can read the Security log at all
# ---------------------------------------------------------
$canReadLog = $false
try{
    Get-WinEvent -LogName $EventLog -MaxEvents 1 -ErrorAction Stop | Out-Null
    $canReadLog = $true
}
catch [System.UnauthorizedAccessException]{
    Write-ForensicLog "[!] Access denied reading Security log — run as Administrator" -Level ERROR -Section "EventLog" -Detail "Object Access Log Access Denied"
}
catch{
    Write-ForensicLog "[!] Cannot access Security log: $($_.Exception.Message)" -Level ERROR -Section "EventLog" -Detail "Object Access Log Access Failed"
}

# ---------------------------------------------------------
# CHECK 2 — confirm Object Access auditing is actually enabled
# Without this 4656/4663 will never be generated regardless
# of how far back you look
# ---------------------------------------------------------
if($canReadLog){
    try{
        $auditPol = & auditpol /get /subcategory:"File System" 2>$null
        if($auditPol -notmatch "Success|Failure"){
            Write-ForensicLog "[!] Object Access auditing (File System) does not appear to be enabled" -Level WARN -Section "EventLog"
        }
    }
    catch{ }
}



if($canReadLog){

    $Query = @"
<QueryList>
  <Query Path="$EventLog">
    <Select Path="$EventLog">*[System[(EventID=$($EventIDs[0]) or EventID=$($EventIDs[1])) and TimeCreated[@SystemTime&gt;='$($StartTime.ToUniversalTime().ToString("o"))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString("o"))']]]</Select>
  </Query>
</QueryList>
"@

    $Events = $null
    try{
        $Events = Get-WinEvent -FilterXml $Query -ErrorAction Stop
        Write-ForensicLog -ForegroundColor DarkCyan "[*] Retrieved $($Events.Count) object access event(s)" -Level SUCCESS -Section "EventLog" -Detail "Object Access Retrieved $($Events.Count) events (FilterXml) in the last $((New-TimeSpan -Start $StartTime -End $EndTime).Days) days"
    }
    catch [System.Exception]{
        if($_.Exception.Message -match "No events were found"){
            Write-ForensicLog "[!] No object access events found in the last $((New-TimeSpan -Start $StartTime -End $EndTime).Days) days" -Level WARN -Section "EventLog" -Detail "Object Access Retrieved 0 events (FilterXml) in the last $((New-TimeSpan -Start $StartTime -End $EndTime).Days) days"
            Write-ForensicLog "[!] This is expected if Object Access auditing is not configured" -Level WARN -Section "EventLog"
            $ObjectHtmlTable1 += "<tr><td colspan='10' style='text-align:center;color:#27ae60;'>No object access events found in the last $((New-TimeSpan -Start $StartTime -End $EndTime).Days) days</td></tr>"
        }
        else{
            Write-ForensicLog "[!] Query failed: $($_.Exception.Message)" -Level ERROR -Section "EventLog" -Detail "Object Access Query Failed"
        }
    }

    foreach($Event in $Events){
        # Parse via XML instead of property index — property offsets
        # differ between 4656 and 4663 and vary by Windows version
        try{
            $xml  = [xml]$Event.ToXml()
            $data = @{}
            foreach($node in $xml.Event.EventData.Data){
                if($node.Name){ $data[$node.Name] = $node.'#text' }
            }

            $time       = $Event.TimeCreated.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            $eventId    = $Event.Id
            $user       = $data["SubjectUserName"]
            $domain     = $data["SubjectDomainName"]
            $objectName = $data["ObjectName"]
            $objectType = $data["ObjectType"]
            $access     = $data["AccessMask"]
            $process    = $data["ProcessName"]

            # Translate common access masks to readable names
            $accessLabel = switch($access){
                "0x1"    { "ReadData" }
                "0x2"    { "WriteData" }
                "0x4"    { "AppendData" }
                "0x20"   { "Execute" }
                "0x10000"{ "Delete" }
                "0x40000"{ "Write DAC" }
                "0x80000"{ "Write Owner" }
                default  { $access }
            }

            # Skip noisy system accounts — focus on real user activity
            if($user -match '^\$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$'){ continue }

            # Skip registry and pipe objects — file objects are the signal
            if($objectType -match 'Key|Pipe|Token'){ continue }


            $ObjectHtmlTable1 += "<td>$time</td>"
            $ObjectHtmlTable1 += "<td>$eventId</td>"
            $ObjectHtmlTable1 += "<td>$user</td>"
            $ObjectHtmlTable1 += "<td>$domain</td>"
            $ObjectHtmlTable1 += "<td>$objectName</td>"
            $ObjectHtmlTable1 += "<td>$objectType</td>"
            $ObjectHtmlTable1 += "<td>$accessLabel</td>"
            $ObjectHtmlTable1 += "<td>$process</td>"

        }
        catch{
            Write-Verbose "[!] Failed to parse event $($Event.Id): $($_.Exception.Message)" -Level ERROR -Section "EventLog"
        }
    }
}


Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"

#endregion


#############################################################################################################
#region   EVENT LOG ANALYSIS — PROCESS EXECUTION (CLEAN)
#############################################################################################################

Write-ForensicLog "[*] Collecting process execution events" -Level INFO -Section "EventLog"

# ---------------------------------------------------------
# SYSTEM ACCOUNTS TO SKIP (reduce noise)
# ---------------------------------------------------------
$systemAccounts = @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE')

# ---------------------------------------------------------
# QUERY (RESILIENT — handles malformed events)
# ---------------------------------------------------------
$startDate = (Get-Date).AddDays(-30)
$endDate   = Get-Date
$events    = $null

try{
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688,4689
        StartTime = $startDate
        EndTime   = $endDate
    } -ErrorAction Stop

    Write-ForensicLog "[*] Retrieved $($events.Count) events (FilterHashtable)" -Level INFO -Section "EventLog" -Detail "Process Execution Retrieved $($events.Count) events (FilterHashtable)"
}
catch{
    Write-ForensicLog "[!] Filter failed — falling back to XPath" -Level WARN -Section "EventLog"

    try{
        $events = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688 or EventID=4689)]]" |
                  Where-Object {
                      $_.TimeCreated -ge $startDate -and $_.TimeCreated -le $endDate
                  }

        Write-ForensicLog "[*] Retrieved $($events.Count) events (XPath fallback)" -Level INFO -Section "EventLog" -Detail "Process Execution Retrieved $($events.Count) events (XPath fallback)"
    }
    catch{
        Write-ForensicLog "[!] Failed to query events: $($_.Exception.Message)" -Level ERROR -Section "EventLog"
    }
}

if(-not $events){
    Write-ForensicLog "[!] No events found" -Level WARN -Section "EventLog"
    $ObjectHtmlTable2 += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>No process execution events found in the last $((New-TimeSpan -Start $startDate -End $endDate).Days) days</td></tr>"
}


# ---------------------------------------------------------
# PROCESS EVENTS
# ---------------------------------------------------------
foreach($event in $events){
    try{
        $xml  = [xml]$event.ToXml()
        $data = @{}

        foreach($node in $xml.Event.EventData.Data){
            if($node.Name){ $data[$node.Name] = $node.'#text' }
        }

        $user   = $data["SubjectUserName"]
        $domain = $data["SubjectDomainName"]

        # Skip system noise
        if($systemAccounts -contains $user){ continue }
        if($user -match '\$$'){ continue }

        $time        = $event.TimeCreated.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        $processName = $data["NewProcessName"]
        $processId   = $data["NewProcessId"]
        $parentName  = $data["ParentProcessName"]
        $parentId    = $data["ProcessId"]
        $commandLine = $data["CommandLine"]

        $ObjectHtmlTable2 += "<tr>"
        $ObjectHtmlTable2 += "<td>$time</td>"
        $ObjectHtmlTable2 += "<td>$user</td>"
        $ObjectHtmlTable2 += "<td>$domain</td>"
        $ObjectHtmlTable2 += "<td>$processName</td>"
        $ObjectHtmlTable2 += "<td>$processId</td>"
        $ObjectHtmlTable2 += "<td>$parentName</td>"
        $ObjectHtmlTable2 += "<td>$parentId</td>"
        $ObjectHtmlTable2 += "<td>$commandLine</td>"
        $ObjectHtmlTable2 += "</tr>"
    }
    catch{
        Write-Verbose "[!] Failed to parse event: $($_.Exception.Message)" -Level ERROR -Section "EventLog"
        continue
    }
}



Write-ForensicLog "[!] Done" -Level SUCCESS -Section "EventLog"



#endregion



Write-ForensicLog ""

#############################################################################################################
#region   BITLOCKER KEY EXTRACTION
#############################################################################################################

Write-ForensicLog "[*] Checking BitLocker encryption status and extracting recovery keys" -Level INFO -Section "BitLocker"

# ---------------------------------------------------------
# REQUIRES ELEVATION
# BitLocker key material is only accessible as Administrator
# ---------------------------------------------------------
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if(-not $isElevated){
    Write-ForensicLog "[!] BitLocker key extraction requires Administrator privileges" -Level ERROR -Section "BitLocker"
    return
}

# ---------------------------------------------------------
# CHECK BITLOCKER MODULE AVAILABILITY
# BitLocker cmdlets require the BitLocker feature/module
# Available on: Win 8+/Server 2012+ with BitLocker feature
# Falls back to WMI if module not available
# ---------------------------------------------------------
$useBitLockerModule = $false
if(Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue){
    $useBitLockerModule = $true
    Write-ForensicLog "[*] BitLocker PowerShell module available, I will use it" -Level Info -Section "BitLocker"
}
else{
    Write-ForensicLog "[!] BitLocker module not available — falling back to WMI/manage-bde" -Level Warning -Section "BitLocker"
}

# ---------------------------------------------------------
# KEY PROTECTOR TYPE MAP
# ---------------------------------------------------------
$protectorTypeMap = @{
    "Tpm"                       = "TPM"
    "TpmPin"                    = "TPM + PIN"
    "TpmStartupKey"             = "TPM + Startup Key"
    "TpmPinStartupKey"          = "TPM + PIN + Startup Key"
    "RecoveryPassword"          = "Recovery Password (48-digit)"
    "Password"                  = "Password"
    "ExternalKey"               = "External Key (USB)"
    "Certificate"               = "Certificate"
    "SidProtector"              = "Active Directory SID"
    "Unknown"                   = "Unknown"
}

$BitLockerResults = @()

# ---------------------------------------------------------
# METHOD 1 — BitLocker PowerShell module
# Most complete — returns all protectors including passwords
# ---------------------------------------------------------
if($useBitLockerModule){

    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue

    foreach($vol in $volumes){

        $mountPoint     = $vol.MountPoint
        $encryptionPct  = $vol.EncryptionPercentage
        $protectionStatus = $vol.ProtectionStatus
        $encryptionMethod = $vol.EncryptionMethod
        $lockStatus     = $vol.LockStatus
        $volumeType     = $vol.VolumeType

        # Skip volumes with no encryption at all
        if($vol.VolumeStatus -eq "FullyDecrypted" -and $protectionStatus -eq "Off"){ continue }

        foreach($protector in $vol.KeyProtector){

            $protectorType  = $protector.KeyProtectorType.ToString()
            $protectorId    = $protector.KeyProtectorId
            $protectorLabel = $protectorTypeMap[$protectorType] ?? $protectorType

            # Recovery password is the key material we care most about
            $keyMaterial = switch($protectorType){
                "RecoveryPassword" { $protector.RecoveryPassword }
                "ExternalKey"      { $protector.KeyFileName       }
                "Certificate"      { $protector.CertificateThumbprint }
                "Password"         { "** Present but not extractable via module **" }
                default            { "N/A" }
            }

            $BitLockerResults += [PSCustomObject]@{
                MountPoint        = $mountPoint
                VolumeType        = $volumeType
                VolumeStatus      = $vol.VolumeStatus
                EncryptionMethod  = $encryptionMethod
                EncryptionPct     = $encryptionPct
                ProtectionStatus  = $protectionStatus
                LockStatus        = $lockStatus
                ProtectorType     = $protectorLabel
                ProtectorId       = $protectorId
                KeyMaterial       = $keyMaterial
            }
        }

        # If no key protectors enumerated but volume is encrypted
        # note it so the investigator knows to use manage-bde manually
        if($vol.KeyProtector.Count -eq 0 -and $vol.VolumeStatus -ne "FullyDecrypted"){
            $BitLockerResults += [PSCustomObject]@{
                MountPoint        = $mountPoint
                VolumeType        = $volumeType
                VolumeStatus      = $vol.VolumeStatus
                EncryptionMethod  = $encryptionMethod
                EncryptionPct     = $encryptionPct
                ProtectionStatus  = $protectionStatus
                LockStatus        = $lockStatus
                ProtectorType     = "None enumerated"
                ProtectorId       = "N/A"
                KeyMaterial       = "Run: manage-bde -protectors -get $mountPoint"
            }
        }
    }
}

# ---------------------------------------------------------
# METHOD 2 — manage-bde fallback
# Works even without the BitLocker module
# Parses text output — less structured but universally available
# ---------------------------------------------------------
else{

    # Get all fixed and removable drive letters
    $drives = Get-CimInstance Win32_LogicalDisk |
              Where-Object { $_.DriveType -in @(2,3) } |
              Select-Object -ExpandProperty DeviceID

    foreach($drive in $drives){
        try{
            $bdeOutput = & manage-bde -protectors -get $drive 2>$null
            if(-not $bdeOutput){ continue }

            $bdeText = $bdeOutput -join "`n"

            # Skip if not encrypted
            if($bdeText -match "No key protectors"){ continue }
            if($bdeText -match "BitLocker Drive Encryption: Volume $drive" -and
               $bdeText -match "Protection Status:\s+Protection Off" -and
               $bdeText -notmatch "Recovery Password"){ continue }

            # Get volume status separately
            $statusOutput = & manage-bde -status $drive 2>$null
            $statusText   = $statusOutput -join "`n"

            $encMethod   = if($statusText -match "Encryption Method:\s+(.+)"){   $matches[1].Trim() } else { "N/A" }
            $encPct      = if($statusText -match "Percentage Encrypted:\s+(.+)"){ $matches[1].Trim() } else { "N/A" }
            $lockStatus  = if($statusText -match "Lock Status:\s+(.+)"){          $matches[1].Trim() } else { "N/A" }
            $protection  = if($statusText -match "Protection Status:\s+(.+)"){    $matches[1].Trim() } else { "N/A" }

            # Extract each protector block from manage-bde output
            # manage-bde separates protectors with blank lines and labels
            $protectorBlocks = $bdeText -split "(?=\n\s{4}[A-Z])"

            foreach($block in $protectorBlocks){

                $pType = if($block -match "Numerical Password")        { "Recovery Password (48-digit)" }
                         elseif($block -match "TPM And PIN")           { "TPM + PIN" }
                         elseif($block -match "TPM And Startup Key")   { "TPM + Startup Key" }
                         elseif($block -match "TPM")                   { "TPM" }
                         elseif($block -match "External Key")          { "External Key (USB)" }
                         elseif($block -match "Password")              { "Password" }
                         elseif($block -match "Certificate")           { "Certificate" }
                         else                                          { continue }

                # Extract ID
                $pIdd  = if($block -match "ID:\s+(\{[^}]+\})"){ $matches[1] } else { "N/A" }

                # Extract recovery password if present
                $pKey = if($block -match "Password:\s+([\d-]{54,})"){
                            $matches[1].Trim()
                        }
                        elseif($block -match "Key File Name:\s+(.+)"){
                            $matches[1].Trim()
                        }
                        else{ "N/A" }

                $BitLockerResults += [PSCustomObject]@{
                    MountPoint        = $drive
                    VolumeType        = "N/A"
                    VolumeStatus      = "N/A"
                    EncryptionMethod  = $encMethod
                    EncryptionPct     = $encPct
                    ProtectionStatus  = $protection
                    LockStatus        = $lockStatus
                    ProtectorType     = $pType
                    ProtectorId       = $pIdd
                    KeyMaterial       = $pKey
                }
            }
        }
        catch{
            Write-Verbose "[!] manage-bde failed on $drive — $($_.Exception.Message)" -Level ERROR -Section "BITLOCKER"
        }
    }
}

# ---------------------------------------------------------
# ALSO CHECK ACTIVE DIRECTORY IF DOMAIN JOINED
# Recovery keys are often escrowed to AD — retrieve them
# Requires AD module and appropriate permissions
# ---------------------------------------------------------
$isDomainJoined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain

if($isDomainJoined){
    Write-ForensicLog "[*] Domain joined — checking AD for escrowed recovery keys" -Level INFO -Section "BITLOCKER"

    if(Get-Command Get-ADObject -ErrorAction SilentlyContinue){
        try{
            $computerName = $env:COMPUTERNAME
            $adComputer   = Get-ADComputer $computerName -ErrorAction Stop

            # BitLocker recovery info is stored in msFVE-RecoveryInformation child objects
            $recoveryObjects = Get-ADObject -Filter * `
                                            -SearchBase $adComputer.DistinguishedName `
                                            -Properties "msFVE-RecoveryPassword","msFVE-RecoveryGuid","whenCreated" `
                                            -ErrorAction SilentlyContinue |
                               Where-Object { $_.ObjectClass -eq "msFVE-RecoveryInformation" }

            foreach($obj in $recoveryObjects){
                $BitLockerResults += [PSCustomObject]@{
                    MountPoint        = "AD Escrowed Key"
                    VolumeType        = "N/A"
                    VolumeStatus      = "Stored in Active Directory"
                    EncryptionMethod  = "N/A"
                    EncryptionPct     = "N/A"
                    ProtectionStatus  = "N/A"
                    LockStatus        = "N/A"
                    ProtectorType     = "Recovery Password (AD Escrow)"
                    ProtectorId       = $obj."msFVE-RecoveryGuid"
                    KeyMaterial       = $obj."msFVE-RecoveryPassword"
                }
            }

            Write-ForensicLog "[*] Found $($recoveryObjects.Count) AD escrowed key(s)" -Level SUCCESS -Section "BITLOCKER"
        }
        catch{
            Write-ForensicLog "[!] Could not retrieve AD escrowed keys: $($_.Exception.Message)" -Level WARN -Section "BITLOCKER"
        }
    }
    else{
        Write-ForensicLog "[!] AD module not available — skipping AD escrow check" -Level WARN -Section "BITLOCKER"
    }
}

# ---------------------------------------------------------
# BUILD HTML
# ---------------------------------------------------------


foreach($r in $BitLockerResults){


    # Wrap key material in monospace and flag if missing
    $keyDisplay = if($r.KeyMaterial -and $r.KeyMaterial -ne "N/A"){
        "<code>$($r.KeyMaterial)</code>"
    } else {
        "<span style='color:#999;'>Not available</span>"
    }

    $BitLockerFragment += "<tr"
    $BitLockerFragment += "<td>$($r.MountPoint)</td>"
    $BitLockerFragment += "<td>$($r.VolumeType)</td>"
    $BitLockerFragment += "<td>$($r.VolumeStatus)</td>"
    $BitLockerFragment += "<td>$($r.EncryptionMethod)</td>"
    $BitLockerFragment += "<td>$($r.EncryptionPct)</td>"
    $BitLockerFragment += "<td>$($r.ProtectionStatus)</td>"
    $BitLockerFragment += "<td>$($r.LockStatus)</td>"
    $BitLockerFragment += "<td>$($r.ProtectorType)</td>"
    $BitLockerFragment += "<td><code>$($r.ProtectorId)</code></td>"
    $BitLockerFragment += "<td>$keyDisplay</td>"
    $BitLockerFragment += "</tr>"
}


#$BitLockerFragment

$recoveryKeys = $BitLockerResults | Where-Object { $_.ProtectorType -match "Recovery Password" }
Write-ForensicLog -ForegroundColor Cyan "[!] $($BitLockerResults.Count) BitLocker protector(s) found across $($BitLockerResults.MountPoint | Sort-Object -Unique | Measure-Object | Select-Object -ExpandProperty Count) volume(s)"
if($recoveryKeys.Count -gt 0){
    Write-ForensicLog "[!] $($recoveryKeys.Count) recovery password(s) extracted — store securely" -Level SUCCESS -Section "BITLOCKER"
} else {
    Write-ForensicLog "[!] No recovery passwords found — if volumes are encrypted, keys may not be extractable via PowerShell" -Level WARN -Section "BITLOCKER"
    Write-ForensicLog "[!] Check the HTML report for details and consider using manage-bde manually if needed" -Level WARN -Section "BITLOCKER"
    $BitLockerFragment += "<tr><td colspan='12' style='text-align:center;color:#27ae60;'>No BitLocker protectors found or no recovery passwords extractable</td></tr>"
}

Write-ForensicLog "[!] Done" -Level SUCCESS -Section "BITLOCKER"

#endregion

Write-ForensicLog ""

#############################################################################################################
#region   SIGMA RULE ENGINE
#############################################################################################################

# ---------------------------------------------------------
# PREREQUISITES CHECK
# sigma-cli requires Python 3.8+ and the pySigma Windows backend
# Stage once on your IR toolkit:
#   pip install sigma-cli
#   sigma plugin install windows
# ---------------------------------------------------------
function Test-SigmaPrerequisites {
    $pythonOk = $false
    $sigmaOk  = $false

    try{
        $pyVersion = & python --version 2>&1
        if($pyVersion -match "Python 3\.([89]|1[0-9])"){ $pythonOk = $true }
    }
    catch{ }

    try{
        $sigmaVersion = & sigma version 2>&1
        if($sigmaVersion -match "sigma"){ $sigmaOk = $true }
    }
    catch{ }

    return @{ Python = $pythonOk; Sigma = $sigmaOk }
}

# ---------------------------------------------------------
# SIGMA RULE MANAGEMENT
# Downloads curated Windows rules from SigmaHQ
# Caches locally — refreshes if older than 7 days
# ---------------------------------------------------------
$sigmaRulesPath  = "$PSScriptRoot\Forensicator-Share\sigma-rules"
$sigmaRepoUrl    = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
$sigmaZip        = "$env:TEMP\sigma_$(New-Guid).zip"
$sigmaExtract    = "$env:TEMP\sigma_$(New-Guid)"

# Rule categories relevant to IR — maps to SigmaHQ folder structure
$relevantRulesets = @(
    "rules\windows\process_creation",
    "rules\windows\powershell",
    "rules\windows\registry",
    "rules\windows\network_connection",
    "rules\windows\file_event",
    "rules\windows\pipe_created",
    "rules\windows\image_load"
)

function Get-SigmaRules {
    param([string]$RulesPath)

    $needsDownload = -not (Test-Path $RulesPath)
    if(-not $needsDownload){
        $ageDays = (New-TimeSpan -Start (Get-Item $RulesPath).LastWriteTime -End (Get-Date)).TotalDays
        if($ageDays -gt 7){ $needsDownload = $true }
    }

    if($needsDownload){
        Write-ForensicLog "Downloading Sigma rules from SigmaHQ" -Level INFO -Section "SIGMA"
        try{
            $tcp = [System.Net.Sockets.TcpClient]::new()
            if(-not $tcp.ConnectAsync("github.com", 443).Wait(3000)){
                Write-ForensicLog "github.com unreachable — using cached rules if available" `
                                  -Level WARN -Section "SIGMA"
                $tcp.Dispose()
                return $false
            }
            $tcp.Dispose()

            Invoke-WebRequest -Uri $sigmaRepoUrl `
                              -OutFile $sigmaZip `
                              -UseBasicParsing `
                              -TimeoutSec 120 `
                              -ErrorAction Stop

            Expand-Archive $sigmaZip -DestinationPath $sigmaExtract -Force

            # Copy only the relevant rule categories
            $sourceRoot = Get-ChildItem $sigmaExtract -Directory | Select-Object -First 1

            foreach($ruleset in $relevantRulesets){
                $src = "$($sourceRoot.FullName)\$ruleset"
                $dst = "$RulesPath\$ruleset"
                if(Test-Path $src){
                    New-Item $dst -ItemType Directory -Force | Out-Null
                    Copy-Item "$src\*.yml" $dst -Force
                }
            }

            Write-ForensicLog "Sigma rules downloaded and staged" -Level SUCCESS -Section "SIGMA"
            return $true
        }
        catch{
            Write-ForensicLog "Sigma rules download failed: $($_.Exception.Message)" `
                              -Level ERROR -Section "SIGMA"
            return $false
        }
        finally{
            Remove-Item $sigmaZip     -Force -ErrorAction SilentlyContinue
            Remove-Item $sigmaExtract -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    return $true
}

# ---------------------------------------------------------
# SIGMA RULE PARSER — pure PowerShell, no Python needed
# Parses YAML Sigma rules and converts detection logic to
# XPath queries compatible with Get-WinEvent -FilterXml
#
# Supports:
#   - keywords detection
#   - field-based detection (selection blocks)
#   - condition: selection
#   - condition: keywords
#   - EventID mapping
#   - LogSource mapping to Windows event log names
# ---------------------------------------------------------

# Log source to Windows event log name mapping
$logSourceMap = @{
    # Category mappings
    "process_creation"   = "Security"
    "ps_script"          = "Microsoft-Windows-PowerShell/Operational"
    "ps_module"          = "Microsoft-Windows-PowerShell/Operational"
    "ps_classic_script"  = "Windows PowerShell"
    "registry_event"     = "Microsoft-Windows-Sysmon/Operational"
    "file_event"         = "Microsoft-Windows-Sysmon/Operational"
    "network_connection" = "Microsoft-Windows-Sysmon/Operational"
    "pipe_created"       = "Microsoft-Windows-Sysmon/Operational"
    "image_load"         = "Microsoft-Windows-Sysmon/Operational"
    # Product/service overrides
    "security"           = "Security"
    "system"             = "System"
    "application"        = "Application"
}

# Event ID mappings per log source category
$eventIdMap = @{
    "process_creation"   = @(4688, 1)     # 4688=Security, 1=Sysmon
    "ps_script"          = @(4104)
    "ps_module"          = @(4103)
    "ps_classic_script"  = @(400, 800)
    "registry_event"     = @(12, 13, 14)
    "file_event"         = @(11)
    "network_connection" = @(3)
    "pipe_created"       = @(17, 18)
    "image_load"         = @(7)
}

function ConvertFrom-SigmaRule {
    param([string]$RulePath)

    try{
        $content = Get-Content $RulePath -Raw -ErrorAction Stop

        # -------------------------------------------------
        # YAML PARSER — lightweight, handles Sigma structure
        # Sigma YAML is simple enough to parse without a
        # full YAML library
        # -------------------------------------------------
        function Parse-SigmaYaml {
            param([string]$Yaml)

            $result   = @{}
            $lines    = $Yaml -split "`n"
            $i        = 0
            $stack    = [System.Collections.Generic.Stack[hashtable]]::new()
            $current  = $result
            $indent   = 0

            while($i -lt $lines.Count){
                $line = $lines[$i]
                if($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)){ $i++; continue }

                $lineIndent = ($line -match '^(\s+)') ? $matches[1].Length : 0

                # Key: value pair
                if($line -match '^\s*([^:\s][^:]*?):\s*(.*)$'){
                    $key   = $matches[1].Trim()
                    $value = $matches[2].Trim()

                    if([string]::IsNullOrEmpty($value)){
                        # Start of a nested block
                        $nested = @{}
                        $current[$key] = $nested
                    }
                    elseif($value -match '^\|'){
                        # Block scalar — collect following indented lines
                        $blockLines = @()
                        $i++
                        while($i -lt $lines.Count){
                            $nextLine = $lines[$i]
                            if([string]::IsNullOrWhiteSpace($nextLine) -or
                               ($nextLine -match '^(\s+)' -and $matches[1].Length -gt $lineIndent)){
                                $blockLines += $nextLine.Trim()
                                $i++
                            } else { break }
                        }
                        $current[$key] = $blockLines
                        continue
                    }
                    else{
                        $current[$key] = $value.Trim("'").Trim('"')
                    }
                }
                # List item
                elseif($line -match '^\s*-\s+(.+)$'){
                    # handled in block scalar collection
                }

                $i++
            }
            return $result
        }

        # Extract key sections using regex — more reliable than
        # full YAML parse for Sigma's specific structure
        $title       = if($content -match '(?m)^title:\s*(.+)$')         { $matches[1].Trim() }  else { "Unknown" }
        $description = if($content -match '(?m)^description:\s*(.+)$')   { $matches[1].Trim() }  else { "" }
        $status      = if($content -match '(?m)^status:\s*(.+)$')        { $matches[1].Trim() }  else { "" }
        $level       = if($content -match '(?m)^level:\s*(.+)$')         { $matches[1].Trim() }  else { "medium" }
        $tags        = if($content -match '(?m)^tags:\s*\n((?:\s+-\s+.+\n?)+)'){ $matches[1] -split "`n" | Where-Object { $_ -match '-\s+(.+)' } | ForEach-Object { $matches[1].Trim() } } else { @() }

        # Skip experimental/deprecated rules — too noisy
        if($status -in @("deprecated","unsupported","experimental")){
            return $null
        }

        # Log source
        $logCategory = if($content -match '(?m)^\s+category:\s*(.+)$')  { $matches[1].Trim() }  else { "" }
        $logProduct  = if($content -match '(?m)^\s+product:\s*(.+)$')   { $matches[1].Trim() }  else { "" }
        $logService  = if($content -match '(?m)^\s+service:\s*(.+)$')   { $matches[1].Trim() }  else { "" }

        # Resolve log name
        $logName = $logSourceMap[$logCategory] ??
                   $logSourceMap[$logService]  ??
                   "Security"

        # Resolve event IDs
        $eventIds = $eventIdMap[$logCategory] ?? @()

        # Condition
        $condition = if($content -match '(?m)^\s+condition:\s*(.+)$'){ $matches[1].Trim() } else { "selection" }

        # -------------------------------------------------
        # DETECTION BLOCK EXTRACTION
        # Handles selection blocks and keyword lists
        # -------------------------------------------------
        $detectionSection = ""
        if($content -match '(?ms)^detection:\n(.+?)(?=^[a-z]|\z)'){
            $detectionSection = $matches[1]
        }

        if([string]::IsNullOrWhiteSpace($detectionSection)){ return $null }

        # Parse selection blocks — each named block is a hashtable
        $selections = @{}
        $blockPattern = '(?ms)^\s{4}(\w+):\s*\n((?:\s{6,}.+\n?)+)'

        foreach($blockMatch in [regex]::Matches($detectionSection, $blockPattern)){
            $blockName  = $blockMatch.Groups[1].Value
            $blockLines = $blockMatch.Groups[2].Value -split "`n" |
                          Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

            $blockData = @{}
            $currentField = $null

            foreach($line in $blockLines){
                # Field definition: FieldName|modifier:
                if($line -match '^\s+([^:|\s]+)(\|[^:]+)?:\s*$'){
                    $currentField = $matches[1].Trim()
                    $modifier     = $matches[2]
                    $blockData[$currentField] = @{ Values = @(); Modifier = $modifier }
                }
                # Field with inline value
                elseif($line -match '^\s+([^:|\s]+)(\|[^:]+)?:\s*(.+)$'){
                    $currentField = $matches[1].Trim()
                    $modifier     = $matches[2]
                    $value        = $matches[3].Trim().Trim("'").Trim('"')
                    $blockData[$currentField] = @{ Values = @($value); Modifier = $modifier }
                }
                # List item under current field
                elseif($line -match '^\s+-\s+(.+)$' -and $currentField){
                    $value = $matches[1].Trim().Trim("'").Trim('"')
                    $blockData[$currentField].Values += $value
                }
            }

            $selections[$blockName] = $blockData
        }

        # Keyword lists (flat list under 'keywords:')
        $keywords = @()
        if($detectionSection -match '(?ms)^\s{4}keywords:\s*\n((?:\s+-\s+.+\n?)+)'){
            $keywords = $matches[1] -split "`n" |
                        Where-Object { $_ -match '^\s+-\s+(.+)$' } |
                        ForEach-Object { $matches[1].Trim().Trim("'").Trim('"') }
        }

        return [PSCustomObject]@{
            Title      = $title
            Description= $description
            Level      = $level
            Status     = $status
            Tags       = $tags
            LogName    = $logName
            EventIds   = $eventIds
            Condition  = $condition
            Selections = $selections
            Keywords   = $keywords
            RulePath   = $RulePath
        }
    }
    catch{
        Write-Verbose "Failed to parse Sigma rule $RulePath : $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------
# SIGMA FIELD TO XPATH MAPPING
# Maps Sigma field names to Windows event XML field names
# ---------------------------------------------------------
$fieldMap = @{
    # Process creation (4688 / Sysmon 1)
    "CommandLine"         = "CommandLine"
    "Image"               = "NewProcessName"
    "OriginalFileName"    = "OriginalFileName"
    "ParentImage"         = "ParentProcessName"
    "ParentCommandLine"   = "ParentCommandLine"
    "User"                = "SubjectUserName"
    "ProcessId"           = "NewProcessId"

    # PowerShell (4104)
    "ScriptBlockText"     = "ScriptBlockText"
    "Path"                = "Path"

    # Network
    "DestinationPort"     = "DestPort"
    "DestinationIp"       = "DestAddress"
    "SourceIp"            = "SourceAddress"

    # Registry
    "TargetObject"        = "TargetObject"
    "Details"             = "Details"
    "EventType"           = "EventType"

    # File
    "TargetFilename"      = "TargetFilename"

    # Common
    "EventID"             = "EventID"
    "Channel"             = "Channel"
}

function ConvertTo-XPathFromSigma {
    param([PSCustomObject]$Rule)

    if($null -eq $Rule -or $Rule.Selections.Count -eq 0){ return $null }

    $xpathParts = @()

    foreach($selectionName in $Rule.Selections.Keys){
        $selection  = $Rule.Selections[$selectionName]
        $fieldParts = @()

        foreach($field in $selection.Keys){
            $fieldDef   = $selection[$field]
            $values     = $fieldDef.Values
            $modifier   = $fieldDef.Modifier

            # Map Sigma field name to Windows event field name
            $winField = $fieldMap[$field] ?? $field

            if($values.Count -eq 0){ continue }

            $valueParts = foreach($val in $values){
                # Escape XPath special characters
                $escaped = $val -replace "'","&apos;" `
                                -replace '"',"&quot;" `
                                -replace '&','&amp;' `
                                -replace '<','&lt;' `
                                -replace '>','&gt;'

                # Handle Sigma modifiers
                if($modifier -match 'contains'){
                    "contains(EventData/Data[@Name='$winField'], '$escaped')"
                }
                elseif($modifier -match 'startswith'){
                    "starts-with(EventData/Data[@Name='$winField'], '$escaped')"
                }
                elseif($modifier -match 'endswith'){
                    # XPath 1.0 has no ends-with — use contains as approximation
                    "contains(EventData/Data[@Name='$winField'], '$escaped')"
                }
                elseif($modifier -match 'windash'){
                    # windash — match both / and - as parameter prefixes
                    $withDash   = $escaped -replace '^-','/'
                    $withSlash  = $escaped -replace '^/','-'
                    "(contains(EventData/Data[@Name='$winField'], '$escaped') or contains(EventData/Data[@Name='$winField'], '$withDash') or contains(EventData/Data[@Name='$winField'], '$withSlash'))"
                }
                elseif($modifier -match 're'){
                    # Regex — XPath 1.0 has no regex support
                    # Skip regex conditions to avoid false negatives
                    # from broken XPath
                    $null
                }
                else{
                    # Default — exact match
                    "EventData/Data[@Name='$winField']='$escaped'"
                }
            }

            $valueParts = $valueParts | Where-Object { $_ }

            if($valueParts.Count -gt 0){
                $fieldParts += "(" + ($valueParts -join " or ") + ")"
            }
        }

        if($fieldParts.Count -gt 0){
            $xpathParts += "(" + ($fieldParts -join " and ") + ")"
        }
    }

    if($xpathParts.Count -eq 0){ return $null }

    # Handle condition logic
    $xpathFilter = switch -Regex ($Rule.Condition){
        "selection"                         { $xpathParts -join " and " }
        "1 of selection\*"                  { $xpathParts -join " or "  }
        "all of selection\*"                { $xpathParts -join " and " }
        "keywords"                          {
            $kwParts = $Rule.Keywords | ForEach-Object {
                "contains(., '$($_ -replace "'","&apos;")')"
            }
            $kwParts -join " or "
        }
        default                             { $xpathParts -join " and " }
    }

    if([string]::IsNullOrWhiteSpace($xpathFilter)){ return $null }

    # Build event ID filter
    $idClause = if($Rule.EventIds.Count -gt 0){
        "(" + ($Rule.EventIds | ForEach-Object { "EventID=$_" }) -join " or " + ")"
    } else { $null }

    $startISO = [datetime]::UtcNow.AddDays(-30).ToString("o")
    $timeFilter = "TimeCreated[@SystemTime&gt;='$startISO']"

    $systemFilter = if($idClause){
        "$idClause and $timeFilter"
    } else {
        $timeFilter
    }

    return @"
<QueryList>
  <Query Id="0" Path="$($Rule.LogName)">
    <Select Path="$($Rule.LogName)">*[System[$systemFilter] and EventData[$xpathFilter]]</Select>
  </Query>
</QueryList>
"@
}

# ---------------------------------------------------------
# SIGMA SCAN ENGINE
# Loads rules, converts to XPath, queries event logs
# ---------------------------------------------------------
function Invoke-SigmaScan {
    param(
        [string]$RulesPath,
        [int]   $DaysBack   = 30,
        [ValidateSet("critical","high","medium","low","informational")]
        [string]$MinLevel   = "medium"
    )

    $levelOrder = @{
        "critical"      = 5
        "high"          = 4
        "medium"        = 3
        "low"           = 2
        "informational" = 1
    }
    $minLevelNum = $levelOrder[$MinLevel]

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Load and convert all relevant rules
    $ruleFiles = Get-ChildItem $RulesPath -Filter "*.yml" -Recurse -ErrorAction SilentlyContinue
    Write-ForensicLog "Loading $($ruleFiles.Count) Sigma rules" -Level INFO -Section "SIGMA" -Detail "Loaded $($ruleFiles.Count) Sigma rules"

    $convertedRules = @()
    foreach($ruleFile in $ruleFiles){
        $rule = ConvertFrom-SigmaRule $ruleFile.FullName
        if($null -eq $rule){ continue }

        # Skip below minimum severity
        if($levelOrder[$rule.Level] -lt $minLevelNum){ continue }

        $xpath = ConvertTo-XPathFromSigma $rule
        if($null -eq $xpath){ continue }

        $convertedRules += @{ Rule = $rule; XPath = $xpath }
    }

    Write-ForensicLog "Converted $($convertedRules.Count) rules to XPath queries" -Level FINDING -Section "SIGMA" -Detail "Total rules: $($ruleFiles.Count)"
                      

    # Execute each rule against the event log
    $ruleCount = 0
    foreach($entry in $convertedRules){
        $ruleCount++
        $rule  = $entry.Rule
        $xpath = $entry.XPath

        Write-Progress -Activity "Running Sigma Rules" `
                       -Status "[$ruleCount/$($convertedRules.Count)] $($rule.Title)" `
                       -PercentComplete ([Math]::Round(($ruleCount / $convertedRules.Count) * 100))

        # Verify the log exists before querying
        try{
            Get-WinEvent -LogName $rule.LogName -MaxEvents 1 -ErrorAction Stop | Out-Null
        }
        catch{ continue }

        try{
            $events = Get-WinEvent -FilterXml $xpath -ErrorAction Stop

            foreach($event in $events){
                try{
                    $xmlData = [xml]$event.ToXml()
                    $data    = @{}
                    foreach($node in $xmlData.Event.EventData.Data){
                        if($node.Name){ $data[$node.Name] = $node.'#text' }
                    }

                    $results.Add([PSCustomObject]@{
                        RuleTitle   = $rule.Title
                        RuleLevel   = $rule.Level
                        RuleTags    = $rule.Tags -join ", "
                        EventId     = $event.Id
                        LogName     = $rule.LogName
                        TimeCreated = $event.TimeCreated.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                        User        = $data["SubjectUserName"] ?? $data["TargetUserName"] ?? "N/A"
                        CommandLine = $data["CommandLine"]     ?? $data["ScriptBlockText"] ?? "N/A"
                        Process     = $data["NewProcessName"]  ?? $data["Image"] ?? "N/A"
                        RuleFile    = Split-Path $rule.RulePath -Leaf
                    })

                    Write-ForensicLog "SIGMA HIT: $($rule.Title)" `
                                      -Level FINDING `
                                      -Section "SIGMA" `
                                      -Detail "Level: $($rule.Level) | EventId: $($event.Id) | Time: $($event.TimeCreated)"
                }
                catch{ }
            }
        }
        catch{
            if($_.Exception.Message -notmatch "No events were found"){ }
        }
    }

    Write-Progress -Activity "Running Sigma Rules" -Completed
    return $results
}

# ---------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------
Write-ForensicLog "Initialising Sigma detection engine" -Level INFO -Section "SIGMA"

$prereqs = Test-SigmaPrerequisites
if(-not $prereqs.Python -or -not $prereqs.Sigma){
    Write-ForensicLog "sigma-cli not available — using built-in pure PowerShell rule engine" -Level INFO -Section "SIGMA" `
                      
}

$rulesReady = Get-SigmaRules -RulesPath $sigmaRulesPath

if(-not $rulesReady -and -not (Test-Path $sigmaRulesPath)){
    Write-ForensicLog "No Sigma rules available — skipping detection" -Level ERROR -Section "SIGMA" -Detail "Ensure sigma-cli is installed or that the rules are cached locally at $sigmaRulesPath" `
}

$sigmaFindings = Invoke-SigmaScan -RulesPath $sigmaRulesPath `
                                   -DaysBack  30 `
                                   -MinLevel  "medium"

# ---------------------------------------------------------
# HTML OUTPUT
# ---------------------------------------------------------


$levelColors = @{
    "critical"      = "#ff4444"
    "high"          = "#ffcccc"
    "medium"        = "#ffddcc"
    "low"           = "#fff3cc"
    "informational" = "#f0f0f0"
}

if($sigmaFindings.Count -gt 0){
    foreach($f in $sigmaFindings | Sort-Object { 
        switch($_.RuleLevel){
            "critical"{"0"} "high"{"1"} "medium"{"2"} "low"{"3"} default{"4"}
        }
    }){
        $color    = $levelColors[$f.RuleLevel] ?? "#ffffff"
        $cmdShort = if($f.CommandLine.Length -gt 200){ 
                        $f.CommandLine.Substring(0,200) + "..." 
                    } else { 
                        $f.CommandLine 
                    }

        $SigmaFragment += "<tr style='background-color:$color;'>"
        $SigmaFragment += "<td>$($f.TimeCreated)</td>"
        $SigmaFragment += "<td><strong>$($f.RuleTitle)</strong></td>"
        $SigmaFragment += "<td>$($f.RuleLevel.ToUpper())</td>"
        $SigmaFragment += "<td>$($f.RuleTags)</td>"
        $SigmaFragment += "<td>$($f.EventId)</td>"
        $SigmaFragment += "<td>$($f.User)</td>"
        $SigmaFragment += "<td>$($f.Process)</td>"
        $SigmaFragment += "<td><code>$cmdShort</code></td>"
        $SigmaFragment += "<td>$($f.RuleFile)</td>"
        $SigmaFragment += "</tr>"
    }

    # Export findings for external analysis
    $sigmaFindings | Export-Csv `
        "$PSScriptRoot\$env:COMPUTERNAME\SigmaFindings.csv" `
        -NoTypeInformation -Encoding UTF8
}
else{
    $SigmaFragment += "<tr><td colspan='9' style='text-align:center;color:#27ae60;'>No Sigma rule matches found</td></tr>"
}


Write-ForensicLog "Sigma scan complete — $($sigmaFindings.Count) finding(s)" `
                  -Level $(if($sigmaFindings.Count -gt 0){ "FINDING" } else { "SUCCESS" }) `
                  -Section "SIGMA"

#endregion

Write-ForensicLog ""

###########################################################################################################
###########################################################################################################
########################## START OF STYLES AND HTML FORMATTING             ################################
###########################################################################################################
###########################################################################################################

#Write-ForensicLog -Fore DarkCyan "[!] Hang on, the Forensicator is compiling your results"

###########################################################################################################
#region ########################## CREATING AND FORMATTING THE HTML FILES  ################################
###########################################################################################################

Write-ForensicLog "[*] Creating and Formatting the HTML files" -Level INFO -Section "CORE"


function ForensicatorIndex {

  @"
<!DOCTYPE html>
<html>
<head>
<!-- Basic Page Info -->
<meta charset="utf-8" />
<title>Live Forensicator - Results for $env:computername</title>

<!-- Mobile Specific Metas -->
<meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
<!-- Google Font -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
rel="stylesheet" />
<!-- CSS -->
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
<div class="pre-loader">
<div class="pre-loader-box">
<div class="loader-logo">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
</div>
<div class="loader-progress" id="progress_div">
<div class="bar" id="bar1"></div>
</div>
<div class="percent" id="percent1">0%</div>
<div class="loading-text">Loading...</div>
</div>
</div>
<div class="header">
<div class="header-left">
<div class="menu-icon bi bi-list"></div>
<div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
<div class="header-search">
<form>
<div class="form-group mb-0">
<i class="dw dw-search2 search-icon"></i>
<input type="text" class="form-control search-input" placeholder="Search Here" />
<div class="dropdown">
<a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
<i class="ion-arrow-down-c"></i>
</a>
<div class="dropdown-menu dropdown-menu-right">
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">From</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">To</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">Subject</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="text-right">
<button class="btn btn-primary">Search</button>
</div>
</div>
</div>
</div>
</form>
</div>
</div>
<div class="header-right">
<div class="user-info-dropdown">
<div class="dropdown">
<a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
<span class="bi bi-laptop" style="font-size: 1.50em;">
</span>
<span class="user-name">$env:computername</span>
</a>
</div>
</div>
<div class="github-link">
<a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/github.svg"
alt="" /></a>
</div>
</div>
</div>
<div class="right-sidebar">
<div class="right-sidebar-body customscroll">
<div class="right-sidebar-body-content">
<h4 class="weight-600 font-18 pb-10">Header Background</h4>
<div class="sidebar-btn-group pb-30 mb-10">
<a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
<a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
</div>
<h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
<div class="sidebar-btn-group pb-30 mb-10">
<a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
<a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
</div>
</div>
</div>
</div>
<div class="left-side-bar header-white active">
<div class="brand-logo">
<a href="index.html">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="dark-logo" />
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="light-logo" />
</a>
<div class="close-sidebar" data-toggle="left-sidebar-close">
<i class="ion-close-round"></i>
</div>
</div>
<div class="menu-block customscroll">
<div class="sidebar-menu">
<ul id="accordion-menu">
<li class="dropdown">
<a href="index.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-house"></span><span class="mtext">Home</span>
</a>
</li>
<li class="dropdown">
<a href="users.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
</a>
</li>
<li class="dropdown">
<a href="system.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
</a>
</li>
<li class="dropdown">
<a href="network.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
</a>
</li>
<li class="dropdown">
<a href="processes.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
</a>
</li>
<li class="dropdown">
<a href="others.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
</a>
</li>

<li class="dropdown">
<a href="javascript:;" class="dropdown-toggle">
<span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
</a>
<ul class="submenu">
<li><a href="evtx_user.html">User Actions</a></li>
<li>
<a href="evtx_logons.html">Logon Events</a>
</li>
<li><a href="evtx_object.html">Object Access</a></li>
<li><a href="evtx_process.html">Process Execution</a></li>
</ul>
</li>
<li class="dropdown">
<a href="detection.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Detections</span>
</a>
</li>
<li>
<div class="dropdown-divider"></div>
</li>
<li>
<div class="sidebar-small-cap">Extra</div>
</li>
<li class="dropdown">
<a href="extras.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
</a>
</li>
</ul>
</div>
</div>
</div>
<div class="mobile-menu-overlay"></div>
<div class="main-container">
<div class="pd-ltr-20 xs-pd-20-10">
<div class="min-height-200px">
<div class="page-header">
<div class="row">
<div class="col-md-6 col-sm-12">
<div class="title">
<h4>Home</h4>
</div>
<nav aria-label="breadcrumb" role="navigation">
<ol class="breadcrumb">
<li class="breadcrumb-item">
<a href="index.html">Home</a>
</li>
<li class="breadcrumb-item active" aria-current="page">
Index
</li>
</ol>
</nav>
</div>
</div>
</div>
<div class="main-container">
<div class="pd-ltr-20">
<div class="card-box pd-20 height-100-p mb-30">
<div class="row align-items-center">
<div class="col-md-4">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
</div>
<div class="col-md-8">
<h4 class="font-20 weight-500 mb-10 text-capitalize">
Live Forensics Results for
<div class="weight-600 font-30 text-blue">$env:computername</div>
</h4>
<p class="font-18 max-width-600">
This HTML File and its associated files were generated by the
Live Forensicator script, we believe the contents will aid
you to understand if the system has been compromised, the
final conclusion is up to the investigator.
</p>
</div>
</div>
</div>
</div>
</div>
<div class="main-container">
<div class="pd-ltr-20">
<!-- Bordered table  start -->
<div class="pd-20 card-box mb-30">
<div class="clearfix mb-20">
<div class="pull-left">
<h4 class="text-blue h4">Key Information</h4>
<p>
This space contains information about the examiner, case and exhibit details
Analysis Start and end time is also recorded.
</p>
</div>
</div>
<table class="table table-bordered">
<thead>
<tr>
<th scope="col">#</th>
<th scope="col">Details</th>
<th scope="col">Values</th>
</tr>
</thead>
<tbody>
<tr>
<th scope="row">1</th>
<td>Case reference:</td>
<td>$CASENO</td>
</tr>
<tr>
<th scope="row">2</th>
<td>Examiner Name:</td>
<td>$Handler</td>
</tr>
<tr>
<th scope="row">3</th>
<td>Exhibit reference:</td>
<td>$Ref</td>
</tr>
</tr>
<tr>
<th scope="row">4</th>
<td>Device:</td>
<td>$Des</td>
</tr>
</tr>
<tr>
<th scope="row">5</th>
<td>Examination Location:</td>
<td>$Loc</td>
</tr>
</tr>
<tr>
<th scope="row">6</th>
<td>Start Time and Date:</td>
<td>$ForensicatorStartTime</td>
</tr>
</tr>
<tr>
<th scope="row">7</th>
<td>End Time and Date:</td>
<td>$ForensicatorEndTime</td>
</tr>
</tbody>
</table>
</div>
<!--Bordered table End -->
</div>
</div>
<!-- Export Datatable End -->
</div>
<div class="footer-wrap pd-20 mb-20 card-box">
Live Forensicator - Coded By
<a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
</div>
</div>
</div>
<!-- js -->
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
<!-- buttons for Export datatable -->
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
<!-- Datatable Setting js -->
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
</body>
</html>

"@
}

# Call the function to generate the report
ForensicatorIndex | Out-File -FilePath $ForensicatorIndexFile


#############################################################################################################
#region   STYLES FOR NETWORKS                                   #############################################
#############################################################################################################

function NetworkStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>


          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">DNS Cache</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Entry</th>
                  <th >Name</th>
                  <th >Status</th>
                  <th >TimeToLive</th>
                  <th >Data</th>
                </tr>
              </thead>
              <tbody>
                $DNSCacheFragment
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network Adapters</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">AdapterType</th>
                  <th >ProductName</th>
                  <th >Description</th>
                  <th >MACAddress</th>
                  <th >Availability</th>
                  <th >NetconnectionStatus</th>
                  <th >NetEnabled</th>
                  <th >PhysicalAdapter</th>
                </tr>
              </thead>
              <tbody>
               $NetworkAdapterFragment
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current IP Configuration</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Description</th>
                  <th >MACAddress</th>
                  <th >DNSDomain</th>
                  <th >DNSHostName</th>
                  <th >DHCPEnabled</th>
                  <th >ServiceName</th>
                </tr>
              </thead>
              <tbody>
               $IPConfigurationFragment
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network Adapter IP Address - IPv4 & IPv6</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">InterfaceAlias</th>
                  <th >IPaddress</th>
                  <th >EnabledStatus</th>
                  <th >OperatingStatus</th>
                </tr>
              </thead>
              <tbody>
               $NetIPAddressFragment
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network Connection Profile</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th >InterfaceAlias</th>
                  <th >NetworkCategory</th>
                  <th >IPV4Connectivity</th>
                  <th >IPv6Connectivity</th>
                </tr>
              </thead>
              <tbody>
               $NetConnectProfileFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network Adapters & Bandwidth</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th >InterfaceDescription</th>
                  <th >Status</th>
                  <th >MacAddress</th>
                  <th >LinkSpeed</th>
                </tr>
              </thead>
              <tbody>
               $NetAdapterFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Addres Resolution Protocol Cache</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">InterfaceAlias</th>
                  <th >IPAddress</th>
                  <th >LinkLayerAddress</th>
                </tr>
              </thead>
              <tbody>
               $NetNeighborFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current TCP Connections and Associated Processes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">LocalAddress</th>
                  <th >LocalPort</th>
                  <th >RemoteAddress</th>
                  <th >RemotePort</th>
                  <th >State</th>
                  <th >OwningProcess</th>
                </tr>
              </thead>
              <tbody>
               $NetTCPConnectFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Associated WIFI Networks and Passwords</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">PROFILE_NAME</th>
                  <th >PASSWORD</th>
                </tr>
              </thead>
              <tbody>
               $WlanPasswordsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current Firewall Rules</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th >DisplayName</th>
                  <th >Description</th>
                  <th >Direction</th>
                  <th >Action</th>
                  <th >EdgeTraversalPolicy</th>
                  <th >Owner</th>
                  <th >EnforcementStatus</th>
                </tr>
              </thead>
              <tbody>
               $FirewallRuleFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Outbound SMB Sessions</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">LocalAddress</th>
                  <th >LocalPort</th>
                  <th >RemoteAddress</th>
                  <th >RemotePort</th>
                  <th >State</th>
                  <th >AppliedSetting</th>
                  <th >OwningProcess</th>
                </tr>
              </thead>
              <tbody>
                 $outboundSmbSessionsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Active SMB Sessions (If Device is a Server)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">SessionId</th>
                  <th >ClientComputerName</th>
                  <th >ClientUserName</th>
                  <th >NumOpens</th>
                </tr>
              </thead>
              <tbody>
               $SMBSessionsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Active SMB Shares on this device</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">description</th>
                  <th >path</th>
                  <th >volume</th>
                </tr>
              </thead>
              <tbody>
               $SMBSharesFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">IP Route to non local Destination</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">ifIndex</th>
                  <th >DestinationPrefix</th>
                  <th >NextHop</th>
                  <th >RouteMetric</th>
                  <th >ifMetric</th>
                  <th >Interface</th>
                </tr>
              </thead>
              <tbody>
               $NetHopsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Network adapters with IP Route to non local Destination</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th >InterfaceDescription</th>
                  <th >ifIndex</th>
                  <th >Status</th>
                  <th >MacAddress</th>
                  <th >LinkSpeed</th>
                </tr>
              </thead>
              <tbody>
               $AdaptHopsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Ip hops with valid infINFOe lifetime</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">ifIndex</th>
                  <th >DestinationPrefix</th>
                  <th >NextHop</th>
                  <th >RouteMetric</th>
                  <th >InterfaceMetric</th>
                  <th >InterfaceAlias</th>
                </tr>
              </thead>
              <tbody>
               $IpHopsFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->




        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
NetworkStyle | Out-File -FilePath $NetworkFile

#endregion


#############################################################################################################
#region   STYLES FOR USER SECTION                               #############################################
#############################################################################################################

function UserStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current User Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">UserName</th>
                  <th >Domain</th>
                  <th >User UUID</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td class="table-plus">$Env:UserName</td>
                  <td>$Env:UserDomain</td>
                  <td>$userUID</td>
                </tr>
            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">System Details</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>DNSHostName</th>
                  <th>Domain</th>
                  <th>Manufacturer</th>
                  <th>Model</th>
                  <th>PrimaryOwnerName</th>
                  <th>TotalPhysicalMemory</th>
                  <th>Workgroup</th>
                </tr>
              </thead>
              <tbody>
               $systemnameFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Logon Sessions</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">USERNAME</th>
                  <th>SESSIONNAME</th>
                  <th>STATE</th>
                  <th>ID</th>
                  <th>IDLE TIME</th>
                  <th>LOGON TIME</th>
                </tr>
              </thead>
              <tbody>
               $logonsessionFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Processes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap ">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Id</th>
                  <th>User Name</th>
                  <th>CPU</th>
                  <th>Memory</th>
                  <th>Path</th>
                </tr>
              </thead>
              <tbody>
               $userprocessesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Profile</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Local Path</th>
                  <th>SID</th>
                  <th>Last Used</th>
                </tr>
              </thead>
              <tbody>
               $profileFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Administrator Accounts</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Object Class</th>
                  <th>Principle Source</th>
                </tr>
              </thead>
              <tbody>
               $adminFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Local Groups</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
               $localFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->




        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
UserStyle | Out-File -FilePath $UserFile

#endregion

#############################################################################################################
#region   STYLES FOR INSTALLED PROGS | SYSTEM INFO              #############################################
#############################################################################################################

function SystemStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Installed Programs</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Version</th>
                  <th>Vendor</th>
                  <th>InstallDate</th>
                  <th>InstallSource</th>
                  <th>PackageName</th>
                  <th>LocalPackage</th>
                </tr>
              </thead>
              <tbody>
               $InstProgsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->



        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Installed Programs - From Registry</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">DisplayName</th>
                  <th>DisplayVersion</th>
                  <th>Publisher</th>
                  <th>InstallDate</th>
                </tr>
              </thead>
              <tbody>
               $InstalledAppsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Environment Variables</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">name</th>
                  <th>value</th>
                </tr>
              </thead>
              <tbody>
               $envFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">System Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Caption</th>
                  <th>SystemType</th>
                  <th>Manufacturer</th>
                  <th>Model</th>
                  <th>DNSHostName</th>
                  <th>Domain</th>
                  <th>PartOfDomain</th>
                  <th>WorkGroup</th>
                  <th>CurrentTimeZone</th>
                  <th>PCSystemType</th>
                  <th>HyperVisorPresent</th>
                </tr>
              </thead>
              <tbody>
               $systeminfoFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Operating System Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Description</th>
                  <th>Version</th>
                  <th>BuildNumber</th>
                  <th>InstallDate</th>
                  <th>SystemDrive</th>
                  <th>SystemDevice</th>
                  <th>WindowsDirectory</th>
                  <th>LastBootupTime</th>
                  <th>Locale</th>
                  <th>LocalDateTime</th>
                  <th>NumberofUsers</th>
                  <th>RegisteredUser</th>
                  <th>Organization</th>
                  <th>OSProductSuite</th>
                </tr>
              </thead>
              <tbody>
               $OSinfoFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Hotfixes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">CSName</th>
                  <th>Caption</th>
                  <th>Description</th>
                  <th>HotfixID</th>
                  <th>InstalledBy</th>
                  <th>InstalledOn</th>
                </tr>
              </thead>
              <tbody>
               $HotfixesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Windows Defender Status</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">AMProductVersion</th>
                  <th>AMRunningMode</th>
                  <th>AMServiceEnabled</th>
                  <th>AntispywareEnabled</th>
                  <th>AntispywareSignatureLastUpdated</th>
                  <th>AntivirusEnabled</th>
                  <th>AntivirusSignatureLastUpdated</th>
                  <th>BehaviorMonitorEnabled</th>
                  <th>DefenderSignaturesOutOfDate</th>
                  <th>DeviceControlPoliciesLastUpdated</th>
                  <th>DeviceControlState</th>
                  <th>NISSignatureLastUpdated</th>
                  <th>QuickScanEndTime</th>
                  <th>RealTimeProtectionEnabled</th>
                </tr>
              </thead>
            <tbody>
               $WinDefenderFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
SystemStyle | Out-File -FilePath $SystemFile

#endregion



#############################################################################################################
#region   STYLES FOR PROCESSES, SCHEDULED TASK | REGISTRY       #############################################
#############################################################################################################

function ProcessStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Processes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Handles</th>
                  <th>StartTime</th>
                  <th>PM</th>
                  <th>VM</th>
                  <th>SI</th>
                  <th>id</th>
                  <th>ProcessName</th>
                  <th>Path</th>
                  <th>Product</th>
                  <th>FileVersion</th>
                </tr>
              </thead>
              <tbody>
               $ProcessesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Startup Programs</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>command</th>
                  <th>Location</th>
                  <th>User</th>
                </tr>
              </thead>
              <tbody>
               $StartupProgsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Scheduled Task</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">TaskPath</th>
                  <th>TaskName</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
               $ScheduledTaskFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Scheduled Task & State</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">LastRunTime</th>
                  <th>LastTaskResult</th>
                  <th>NextRunTime</th>
                  <th>NumberOfMissedRuns</th>
                  <th>TaskName</th>
                  <th>TaskPath</th>
                  <th>PSComputerName</th>
                </tr>
              </thead>
              <tbody>
               $ScheduledTask2Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Services</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">ServiceName</th>
                  <th>DisplayName</th>
                  <th>Status</th>
                  <th>StartType</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
               $ServicesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Persistance in RegRun Registry</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Values</th>
                </tr>
              </thead>
              <tbody>
               $RegRun
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Persistance in RegRunOnce Registry</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Values</th>
                </tr>
              </thead>
              <tbody>
               $RegRunOnce
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Persistance in RegRunOnceEx Registry</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Values</th>
                </tr>
              </thead>
              <tbody>
               $RegRunOnceEx
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
ProcessStyle | Out-File -FilePath $ProcessFile

#endregion

#############################################################################################################
#region   OTHER NOTABLE CHECKS         ######################################################################
#############################################################################################################

function OthersStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Other-Checks
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Logical Drives</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">DeviceID</th>
                  <th>DriveType</th>
                  <th>FreeSpace</th>
                  <th>Size</th>
                  <th>VolumeName</th>
                </tr>
              </thead>
              <tbody>
                 $LogicalDrivesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">USB Devices</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">FriendlyName</th>
                  <th>Driver</th>
                  <th>mfg</th>
                  <th>DeviceDesc</th>
                </tr>
              </thead>
              <tbody>
               $USBDevicesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->


        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Connected & Disconnected Webcams</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Caption</th>
                  <th>Manufacturer</th>
                  <th>Status</th>
                  <th>Present</th>
                </tr>
              </thead>
              <tbody>
               $ImagedeviceFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">UPNPDevices</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Status</th>
                  <th>Class</th>
                  <th>FriendlyName</th>
                  <th>Instance ID</th>
                </tr>
              </thead>
              <tbody>
               $UPNPDevicesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All Previously Connected Drives</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">FriendlyName</th>
                  <th>Manufacturer</th>
                  <th>Serial</th>
                  <th>Last Seen</th>  
                </tr>
              </thead>
              <tbody>
               $UnknownDrivesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All Link Files Created in the last 180days</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Target</th>
                  <th>Arguments</th>
                  <th>LastAccessed</th>
                </tr>
              </thead>
              <tbody>
               $LinkFilesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">500Days Powershell History</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">User</th>
                  <th>command</th>
                </tr>
              </thead>
              <tbody>
               $PSHistoryFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables in the Downloads folder</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>FullName</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $DownloadsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables In AppData</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>FullName</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $HiddenExecs1Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables In Temp</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>FullName</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $HiddenExecs2Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables In Perflogs</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>FullName</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $HiddenExecs3Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Executables In Documents Folder</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>FullName</th>
                  <th>CreationTimeUTC</th>
                  <th>LastAccessTimeUTC</th>
                  <th>LastWriteTimeUTC</th>
                  <th>Attributes</th>
                </tr>
              </thead>
              <tbody>
               $HiddenExecs4Fragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">BitLocker Drives</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Mount Point</th>
                  <th>Volume Type</th>
                  <th>Status</th>
                  <th>Encryption</th>
                  <th>Encrypted %</th>
                  <th>Protection</th>
                  <th>Lock Status</th>
                  <th>Protector Type</th>
                  <th>Protector ID</th>
                  <th>Key Material</th>
                </tr>
              </thead>
              <tbody>
               $BitLockerFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
OthersStyle | Out-File -FilePath $OthersFile

#endregion


###########################################################################################################
#region ########################## CREATING AND FORMATTING THE EXTRAS FILE  ###############################
###########################################################################################################



function ForensicatorExtras {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="dark-logo" />
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-download"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Extras</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Extras
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <div class="main-container">
          <div class="pd-ltr-20">
            <!-- Bordered table  start -->
            <!-- Simple Datatable start -->
            <div class="card-box mb-30">
              <div class="pd-20">
                <h4 class="text-blue h4">Extra Outputs</h4>
                <p class="mb-0">
                  Note: Not all checks will have a location output because the system might not meet the condition for the check.
                </p>
              </div>
              <div class="pb-20">
                <table class="data-table table nowrap">
                  <thead>
                    <tr>
                      <th class="table-plus">Extra Checks</th>
                      <th class="datatable-nosort">Location</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Group Policy Report</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="GPOReport.html">GPOReport.html</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">WINPMEM RAM CAPTURE</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="RAM">/RAM</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">BROWSING HISTORY DUMP</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="./BROWSING_HISTORY/">BROWSING HISTORY</a>
                      </td>
                    </tr>

                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">NETWORK TRACE</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="PCAP">/PCAP</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">EVENT LOGS</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="EVTXLOGS">/EVTXLOGS</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">IIS Logs</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="IISLogs">/IISLogs</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">TomCat Logs</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="TomCatLogs">/TomCatLogs</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Discovered Log4j</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="LOG4J">/LOG4J</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Matched Hashes</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="HashMatches">/HashMatches</a>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
            <!-- Simple Datatable End -->
            <!-- Bordered table End -->
          </div>
        </div>
        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>

  <!-- js -->

  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>


</body>

</html>

"@
}

# Call the function to generate the report
ForensicatorExtras | Out-File -FilePath $ForensicatorExtrasFile

#endregion


##################################################################################################################
##################################################################################################################
### EVENT LOG ANALYSIS STYLING         ###########################################################################
##################################################################################################################
##################################################################################################################


#############################################################################################################
#region   EVENT LOG ANALYSIS   USER ACTIVITIES        #######################################################
#############################################################################################################

function EvtxUserStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Activities
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">A user's local group membership was enumerated</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>Performed On</th>
                  <th>Performed By</th>
                  <th>Logon Type</th>
                  <th>PID</th>
                  <th>Process Name</th>
                </tr>
              </thead>
              <tbody>
               $GroupMembershipFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">RDP Login Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>Logon User</th>
                  <th>Logon User Domain</th>
                  <th>Logon IP</th>
                </tr>
              </thead>
              <tbody>
               $RDPLoginsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All RDP Login History</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">TimeCreated</th>
                  <th>User</th>
                  <th>Domain</th>
                  <th>Client</th>
                </tr>
              </thead>
              <tbody>
               $RDPAuthsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All Outgoing RDP Connection History</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">TimeStamp</th>
                  <th>LocalUser</th>
                  <th>Target RDP Host</th>
                </tr>
              </thead>
              <tbody>
               $OutRDPFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Creation Activity</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>CreatedUser</th>
                  <th>CreatedBy</th>
                </tr>
              </thead>
              <tbody>
               $CreatedUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Password Reset Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>TargetUser</th>
                  <th>ActionedBy</th>
                </tr>
              </thead>
              <tbody>
               $PassResetFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Users Added to Group</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>AddedBy</th>
                  <th>Target</th>
                </tr>
              </thead>
              <tbody>
               $AddedUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Enabling Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>EnabledBy</th>
                  <th>EnabledAccount</th>
                </tr>
              </thead>
              <tbody>
               $EnabledUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Disabling Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>DisabledBy</th>
                  <th>Disabled</th>
                </tr>
              </thead>
              <tbody>
               $DisabledUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User Deletion Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>DeletedBy</th>
                  <th>DeletedAccount</th>
                </tr>
              </thead>
              <tbody>
               $DeletedUsersFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">User LockOut Activities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>LockedOutAccount</th>
                  <th>System</th>
                </tr>
              </thead>
              <tbody>
               $LockOutFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Credential Manager Backup Activity</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>BackupAccount</th>
                  <th>AccountLogonType</th>
                </tr>
              </thead>
              <tbody>
               $CredManBackupFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Credential Manager Restore Activity</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>RestoredAccount</th>
                  <th>AccountLogonType</th>
                </tr>
              </thead>
              <tbody>
               $CredManRestoreFragment
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
EvtxUserStyle | Out-File -FilePath $EvtxUserFile

#endregion

#############################################################################################################
#region   STYLES FOR EVENT LOG ANALYSIS   LOGON EVENTS         #############################################
#############################################################################################################

function LogonEventsStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Logon-Events
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Successful Logon Events</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>User</th>
                  <th>Logon Type</th>
                  <th>SourceNetworkAddress</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
               $logonEventsFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->



        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Failed Logon Events</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>User</th>
                  <th>Logon Type</th>
                  <th>SourceNetworkAddress</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
               $logonEventsFailedFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
LogonEventsStyle | Out-File -FilePath $LogonEventsFile

#endregion




#############################################################################################################
#region   STYLES FOR EVENT LOG ANALYSIS   Object Access         #############################################
#############################################################################################################

function ObjectEventsStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Object-Access
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Object Access Events</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>Event ID</th>
                  <th>User</th>
                  <th>Domain</th>
                  <th>Object Name</th>
                  <th>Object Type</th>
                  <th>Access</th>
                  <th>Process</th>
                </tr>
              </thead>
              <tbody>
               $ObjectHtmlTable1
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
ObjectEventsStyle | Out-File -FilePath $ObjectEventsFile

#endregion



#############################################################################################################
#region   STYLES FOR EVENT LOG ANALYSIS   PROCESS EVENTS        #############################################
#############################################################################################################

function ProcessEventsStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>
          </li>
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Process-Events
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>



        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Process Execution Events</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr$rowStyle>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>User</th>
                  <th>Domain</th>
                  <th>Process</th>
                  <th>PID</th>
                  <th>Parent Process</th>
                  <th>Parent PID</th>
                  <th>CommandLine</th>
                </tr>
              </thead>
              <tbody>
               $ObjectHtmlTable2
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->




        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
ProcessEventsStyle | Out-File -FilePath $ProcessEventsFile

#endregion


#############################################################################################################
#region   DETECTION CHECKS         ######################################################################
#############################################################################################################

function DetectionStyle {

  @"

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, INFOial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="javascript:;" class="dropdown-toggle">
              <span class="micon bi bi-bezier"></span><span class="mtext">Event Log Analysis</span>
            </a>
            <ul class="submenu">
              <li><a href="evtx_user.html">User Actions</a></li>
              <li>
                <a href="evtx_logons.html">Logon Events</a>
              </li>
              <li><a href="evtx_object.html">Object Access</a></li>
              <li><a href="evtx_process.html">Process Execution</a></li>
            </ul>
          </li>

            <li class="dropdown">
            <a href="detection.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-terminal"></span><span class="mtext">Detections</span>
            </a>


          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Detections
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Malicious Hash Check </h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">File</th>
                  <th>Extension</th>
                  <th>Size KB</th>
                  <th>MD5</th>
                  <th>SHA256</th>
                  <th>MD5 Hit</th>
                  <th>SHA256 Hit</th>
                  <th>Last Modified (UTC)</th>
                  <th>Created (UTC)</th>
                  <th>Owner</th>
                </tr>
              </thead>
              <tbody>
               $HashMatchFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->


        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Ransomware Notes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Ransom Note</th>
                  <th>File Name</th>
                  <th>Wellknown Ransomware Note Matched</th>
                  <th>Last Accessed (UTC)</th>
                </tr>
              </thead>
              <tbody>
               $RansomNoteFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">High Entropy Files</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">High Entropy File</th>
                  <th>File</th>
                  <th>Entropy</th>
                  <th>Last Accessed (UTC)</th>
                </tr>
              </thead>
              <tbody>
               $HighEntropyFilesFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->


        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Ransomware Extension</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Ransomware Extension</th>
                  <th>File</th>
                  <th>Extension</th>
                  <th>Last Accessed (UTC)</th>
                </tr>
              </thead>
              <tbody>
               $RansomExtFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Shadow Copy Deletion</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Severity</th>
                  <th>Method</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
               $ShadowFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Sigma Rules</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Time</th>
                  <th>Rule</th>
                  <th>Level</th>
                  <th>MITRE Tags</th>
                  <th>Event ID</th>
                  <th>User</th>
                  <th>Process</th>
                  <th>CommandLine / ScriptBlock</th>
                  <th>Rule File</th>
                </tr>
              </thead>
              <tbody>
               $SigmaFragment
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

"@
}

# Call the function to generate the report
DetectionStyle | Out-File -FilePath $DetectionFile

Write-ForensicLog "[*] Done" -Level SUCCESS -Section "CORE" -Detail "HTML Report generation complete"

#endregion

Write-ForensicLog ""


################################################################################################################################
## ENCRYPTION SECTION                                       ###################################################################
###############################################################################################################################



if($ENCRYPTED){

    Write-ForensicLog "[*] Archiving artifacts..." -Level INFO -Section "ENCRYPTION" -Detail "Archiving artifacts..."

    $ArtifactFolder = "$PSScriptRoot\$env:COMPUTERNAME"
    $ZipPath        = "$ArtifactFolder\$env:COMPUTERNAME.zip"

# ---------------------------------------------------------
# ZIP — streaming large file support
# CreateEntryFromFile fails on files >2GB due to .NET 32-bit
# stream length limit. Stream large files manually in chunks.
# Skip compression on binary/already-compressed formats.
# ---------------------------------------------------------
@('System.IO.Compression','System.IO.Compression.FileSystem') |
    ForEach-Object { [void][Reflection.Assembly]::LoadWithPartialName($_) }

# Extensions where compression is pointless or harmful
$noCompressExtensions = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
@('.raw','.img','.dd','.vmem','.dmp','.zip','.gz','.7z',
  '.rar','.mp4','.mp3','.jpg','.jpeg','.png') |
    ForEach-Object { [void]$noCompressExtensions.Add($_) }

# Threshold above which we stream manually instead of CreateEntryFromFile
# Set to 1.8GB to stay safely under the 2GB limit
$largeFileThreshold = [long]1.8GB

Push-Location $ArtifactFolder

$FileList = Get-ChildItem '*.*' -File -Recurse

try{
    # Use ZipArchiveMode::Update so existing entries are preserved
    # if the zip already partially exists
    $WriteArchive = [IO.Compression.ZipFile]::Open($ZipPath, 'Update')

    foreach($File in $FileList){

        # Skip the zip file itself
        if($File.FullName -eq $ZipPath){ continue }

        $RelativePath   = (Resolve-Path -LiteralPath $File.FullName -Relative) -replace '^.\\'
        $compressionLvl = if($noCompressExtensions.Contains($File.Extension)){
                              [IO.Compression.CompressionLevel]::NoCompression
                          } else {
                              [IO.Compression.CompressionLevel]::Optimal
                          }

        try{
            if($File.Length -gt $largeFileThreshold){

                # Stream manually in 64MB chunks to bypass the 2GB limit
                Write-ForensicLog "[*] Streaming large file: $($File.Name) ($([Math]::Round($File.Length/1GB,2)) GB)" -Level INFO -Section "ARCHIVING" -Detail "Streaming large file: $($File.Name) ($([Math]::Round($File.Length/1GB,2)) GB)"

                $entry      = $WriteArchive.CreateEntry($RelativePath, $compressionLvl)
                $entryStream = $entry.Open()
                $fileStream  = [System.IO.File]::OpenRead($File.FullName)

                try{
                    $bufferSize = 64MB
                    $buffer     = [byte[]]::new($bufferSize)
                    $totalBytes = 0

                    while(($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0){
                        $entryStream.Write($buffer, 0, $bytesRead)
                        $totalBytes += $bytesRead

                        # Progress indicator for large files
                        $pct = [Math]::Round(($totalBytes / $File.Length) * 100, 0)
                        Write-Progress -Activity "Archiving $($File.Name)" `
                                       -Status "$pct% ($([Math]::Round($totalBytes/1MB,0)) MB / $([Math]::Round($File.Length/1MB,0)) MB)" `
                                       -PercentComplete $pct
                    }

                    Write-Progress -Activity "Archiving $($File.Name)" -Completed
                }
                finally{
                    $entryStream.Dispose()
                    $fileStream.Dispose()
                }

            }
            else{
                # Standard path for files under the threshold
                [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $WriteArchive,
                    $File.FullName,
                    $RelativePath,
                    $compressionLvl
                ) | Out-Null
            }
        }
        catch{
            Write-Warning "$($File.FullName) could not be archived.`n$($_.Exception.Message)" -Level ERROR -Section "ARCHIVING" -Detail "$($File.FullName) could not be archived. due to error: `n$($_.Exception.Message)"
        }
    }
}
catch{
    Write-Error $_.Exception
}
finally{
    $WriteArchive.Dispose()
    Write-Progress -Activity "Archiving" -Completed -ErrorAction SilentlyContinue
    Get-ChildItem * -Exclude *.zip -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
}

Pop-Location

    Write-ForensicLog "[*] Archive complete, encrypting..." -Level INFO -Section "ENCRYPTION" -Detail "Archive complete, encrypting..."

    # ---------------------------------------------------------
    # KEY GENERATION
    # Use RNGCryptoServiceProvider instead of Get-Random
    # Get-Random uses a seeded PRNG — not suitable for key material
    # RNGCryptoServiceProvider uses the OS CSPRNG (same source as
    # CryptGenRandom) which is cryptographically strong
    # ---------------------------------------------------------
    function New-CryptoRandomPassword {
        param([int]$Length = 32)
        $chars  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        $rng    = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $result = [System.Text.StringBuilder]::new($Length)
        $byte   = [byte[]]::new(1)

        while($result.Length -lt $Length){
            $rng.GetBytes($byte)
            # Discard values outside the usable range to avoid modulo bias
            if($byte[0] -lt ($chars.Length * [Math]::Floor(256 / $chars.Length))){
                [void]$result.Append($chars[$byte[0] % $chars.Length])
            }
        }
        $rng.Dispose()
        return $result.ToString()
    }

    $Password = New-CryptoRandomPassword -Length 32
    $KeyB64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Password))

    Write-ForensicLog "[!] ENCRYPTION KEY: $KeyB64" -Level SUCCESS -Section "ENCRYPTION" -Detail "This key is required for decryption — keep it safe!"
    "YOUR ENCRYPTION KEY IS: $KeyB64" | Out-File -Force "$PSScriptRoot\key.txt"
    Write-ForensicLog "[!] Key saved to key.txt — keep it safe" -Level INFO -Section "ENCRYPTION" -Detail "Key saved to key.txt — keep it safe"

    # ---------------------------------------------------------
    # ENCRYPT — pure .NET AES-256-CBC, no external module
    # ---------------------------------------------------------
    function Protect-FileNative {
        param(
            [string]$FilePath,
            [string]$KeyB64,
            [string]$Suffix = ".forensicator"
        )

        # Derive a 256-bit key and 128-bit IV from the password
        # using PBKDF2 (Rfc2898DeriveBytes) with a random salt
        # This is far stronger than using the raw password as a key
        $salt       = [byte[]]::new(16)
        $rng        = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $rng.GetBytes($salt)
        $rng.Dispose()

        $password   = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($KeyB64))
        $pbkdf2     = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                          $password, $salt, 100000,
                          [System.Security.Cryptography.HashAlgorithmName]::SHA256
                      )
        $keyBytes   = $pbkdf2.GetBytes(32)   # AES-256
        $ivBytes    = $pbkdf2.GetBytes(16)   # AES block size
        $pbkdf2.Dispose()

        $aes            = [System.Security.Cryptography.AesManaged]::new()
        $aes.Key        = $keyBytes
        $aes.IV         = $ivBytes
        $aes.Mode       = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding    = [System.Security.Cryptography.PaddingMode]::PKCS7

        $encryptor      = $aes.CreateEncryptor()
        $outPath        = "$FilePath$Suffix"

        try{
            $inStream   = [System.IO.File]::OpenRead($FilePath)
            $outStream  = [System.IO.File]::Create($outPath)

            # Write salt at the top of the file so decryption can re-derive the key
            # Format: [16 bytes salt][encrypted data]
            $outStream.Write($salt, 0, $salt.Length)

            $cryptoStream = [System.Security.Cryptography.CryptoStream]::new(
                                $outStream,
                                $encryptor,
                                [System.Security.Cryptography.CryptoStreamMode]::Write
                            )

            $inStream.CopyTo($cryptoStream)
            $cryptoStream.FlushFinalBlock()
        }
        finally{
            if($cryptoStream){ $cryptoStream.Dispose() }
            if($outStream)   { $outStream.Dispose()    }
            if($inStream)    { $inStream.Dispose()     }
            $encryptor.Dispose()
            $aes.Dispose()
        }

        # Remove source only after confirming output was written
        if(Test-Path $outPath){
            Remove-Item $FilePath -Force
        }
    }

    # Companion decryption function — include this in your documentation
    function Unprotect-FileNative {
        param(
            [string]$FilePath,
            [string]$KeyB64,
            [string]$Suffix = ".forensicator"
        )

        if(-not $FilePath.EndsWith($Suffix)){
            Write-Warning "$FilePath does not have expected suffix $Suffix" -Level ERROR -Section "DECRYPTION" -Detail "No file with suffix $Suffix found for decryption"
        }

        $outPath  = $FilePath -replace [regex]::Escape($Suffix),''
        $password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($KeyB64))

        try{
            $inStream = [System.IO.File]::OpenRead($FilePath)

            # Read the 16-byte salt written by Protect-FileNative
            $salt = [byte[]]::new(16)
            [void]$inStream.Read($salt, 0, 16)

            $pbkdf2   = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                            $password, $salt, 100000,
                            [System.Security.Cryptography.HashAlgorithmName]::SHA256
                        )
            $keyBytes = $pbkdf2.GetBytes(32)
            $ivBytes  = $pbkdf2.GetBytes(16)
            $pbkdf2.Dispose()

            $aes         = [System.Security.Cryptography.AesManaged]::new()
            $aes.Key     = $keyBytes
            $aes.IV      = $ivBytes
            $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $decryptor    = $aes.CreateDecryptor()
            $outStream    = [System.IO.File]::Create($outPath)
            $cryptoStream = [System.Security.Cryptography.CryptoStream]::new(
                                $inStream,
                                $decryptor,
                                [System.Security.Cryptography.CryptoStreamMode]::Read
                            )
            $cryptoStream.CopyTo($outStream)
        }
        finally{
            if($cryptoStream){ $cryptoStream.Dispose() }
            if($outStream)   { $outStream.Dispose()    }
            if($inStream)    { $inStream.Dispose()     }
            if($decryptor)   { $decryptor.Dispose()    }
            if($aes)         { $aes.Dispose()          }
        }

        if(Test-Path $outPath){
            Remove-Item $FilePath -Force
        }
    }

    # ---------------------------------------------------------
    # ENCRYPT ALL ZIP FILES
    # ---------------------------------------------------------
    $FilesToEncrypt = Get-ChildItem -Path "$ArtifactFolder\*" `
                                    -Include '*.zip' `
                                    -Exclude "*forensicator*" `
                                    -Recurse -Force |
                      Where-Object { -not $_.PSIsContainer }

    foreach($file in $FilesToEncrypt){
        Write-ForensicLog "Encrypting $($file.Name)..."
        Protect-FileNative -FilePath $file.FullName -KeyB64 $KeyB64
    }

    Write-ForensicLog "[*] Encryption complete — $($FilesToEncrypt.Count) file(s) encrypted" -Level SUCCESS -Section "ENCRYPTION" -Detail "Files encrypted: $($FilesToEncrypt.Count)"
    Write-ForensicLog "[!] Key is in $PSScriptRoot\key.txt" -Level INFO -Section "ENCRYPTION"

    Set-Location $PSScriptRoot

}else{

}





Write-ForensicLog ''

Write-ForensicLog "Summarizing Forensicator logs files" -Level INFO -Section "CORE"

#End time date stamp
$ForensicatorEndTime = Get-Date -Format $ForensicatorDateFormat

#############################################################################################################
#region   LOGGING FINALISATION
#############################################################################################################

# Save structured logs
Save-ForensicLogs

Write-ForensicLog "Done" -Level SUCCESS -Section "CORE"

Write-ForensicLog ''

Write-ForensicLog "Stoping Transcript and ending Forensicator" -Level INFO -Section "CORE"

# Stop transcript last — captures the Save-ForensicLogs output too
try{
    Stop-Transcript
}
catch{ }

Write-ForensicLog "Done - Happy Investigation" -Level SUCCESS -Section "CORE"


<<<<<<< HEAD
#endregion
=======
#endregion
>>>>>>> 742e95de46b078424489b2dc2bc9b7a43d18f575

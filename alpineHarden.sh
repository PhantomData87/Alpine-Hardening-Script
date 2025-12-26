#!/bin/sh
#Alpine defualt configuration: Missing: 

# Default setup interface
# interface: eth0
# ip: 192.168.0.6x
# netmask: 24
# gateway: 192.168.0.1

# Alpine tested on: 3.22.1, 3.22.2

# !!! Missing features:
#fail2ban: Configure it more once all services are ready
#restrict busybox?
#what is busybox-paths.d/busybox?, 
#selinux, landlock, lockdown, yama, safesetid, loadpin?
#AIDE,
#debsums regular checks, 
#apt-show-versions for patch management, 
#process accounting, 
#automation tools, 
#A hard DO NOT OVERWRITE EXISTING PARTITIONS unless deleting them intentionally
#Skip device check if mountpoint is set to root ("/") directory
#Network monitoring? ARP requests, DHCP requestss
#Awall firewall
#Firewall; Filter arp and other network requests
#Make configAutostart() function to add in the following scripts: set kernel.modules_disabled = 1, turning on and off firewall for timed ntp, dns, or apk updates, DNS check and validation, kernel update notifications, file integrity monitor, malware scanning, ...
#Develop a plan to manually perform security audits: chkrootkit, RKHunter, aide, lynis periodic scan
#User accounting: sysstat
#SSH multi-factor authentication
#Find a way to permit pings from LAN, but not WAN. Finally, let these pings contain (nearly) no data.
#Think about ARP packets, filtering DHCP packets away, minimal DNS packets, and further restrictions on NTP packets.
#Using linux `tc` to limit bandwidth and througput of specific packets
#Switch over to nftables by ditching UFW at some point
#Look into /etc/lvm/lvm.conf & /etc/lvm/lvmlocal.conf
#Figure out why chronyd is failing
# Have a clean way to resolve hard or symbolic file links permissions (besides copying the file)
# Fix logo variables?
# Figure out why a seperate sshd user spawning in sshd service as non-root still has trouble reading shadow (despite being given priviledges to do so)
# Central or decentralized identity user account management
# Restrict dns queires in /etc/resolv?
# Add to ssh an option to install moduli file remotely
# Check if ACPID service missing RTNETLINK1 affects acpi functions
# Consider if /usr/lib requires chmod and chown modifications
# Change server ports more easily
# Immutable files?
# Better way to log ssh users? Multi-factor without PAM?
# rksh is restricting sftp-server
# !!! = TODO remidner

# Log meanings in this script:
# INFO: States what is currently happening in the script.
# UNEXPECTED: A command hasn't executed as expected.
# CRITICAL: A command hasn't executed, and may leave a large quantity of UNEXPECTED log messages.
# BAD FORMAT: A verification test found unproper formatting
# SYSTEM TEST MISMATCH: A verification test has not encounter an expected output
# WARNING: Does not belong to this script, but instead belongs from another program that tries to warn about possible errors, but was not filtered

# Expensive operations:
export sshExpensiveOperation=false # To re-compute /etc/ssh/moduli. It requires a lot of space (~3.6Gb), and time (significantly more on embedded devices in the order of a month wait).

# Alpine configuration variables (CHANGE THESE)
export logFile="/tmp/hardeningAlpine.log"
export logIP="REPLACEME"
export username="REPLACEME"
export sshUsernameKey="REPLACEME"
export tempSshPass="REPLACEME"
export rootSize="REPLACEME"
export homeSize="REPLACEME"
export varSize="REPLACEME"
export varTmpSize="REPLACEME"
export varLogSize="REPLACEME"
export localhostName="REPLACEME"
export lvmName="REPLACEME"
export keyboardLayout="us"
export timezone="REPLACEME"
export dnsList="REPLACEME"
export apkRepoList="REPLACEME"
export devDevice="REPLACEME"
export tempRootPass="REPLACEME"
export mountPoint="/mnt/alpine"
export partitionStart=2 # Leave this as 1 to assume we can make the first partition
export kernelPartitionStart=1 # Leave this as 1 to assume we can make the first partition
export partitionSector="REPLACEME" # Leave this as 2048, as it determines which sector on the device to use. Leave it alone, unless you know what you are doing
export kernelPartitionSector="REPLACEME" # Leave this as 2048, as it determines which sector on the device to use. Leave it alone, unless you know what you are doing
export kernelVersion="REPLACEME" # Could not have this reliable
export gitPackageCommitHash="REPLACEME" # Scroll through original aports git repo to set the desired hash
export localNetwork="REPLACEME"
export localNetmask="REPLACEME"
export umask="077"

# Usernames to be created. This does not include chrony and sshd, since they are already created
export buildUsername="REPLACEME" # Username that can build the linux kernel, and install it
export powerUsername="REPLACEME"	# Username that can execute the acpid daemon
export loggerUsername="REPLACEME"	# Username that runs syslogd
export backgroundUsername="REPLACEME"	# Username that runs crond
export monitorUsername="REPLACEME" # Username that can read and send logs across the network. !!! Highest privledge !!!
export collectorUsername="REPLACEME" # Username that can inspect nearly the entire system for logs.
export previewUsername="REPLACEME" # Username that only receives a simple output, and leaves
export serverCommandUsername="REPLACEME" # Username with restricted commands to execute
export backupUsername="REPLACEME" # Username made to backup select files
export firewallUsername="REPLACEME" # Only user authorized for firewall stuff
export fail2banUsername="REPLACEME" # Only user authorized for blocking network packets
export updateUsername="REPLACEME" # Only user authorized for apk update
export extractUsername="REPLACEME" # A user that will be deleted after 4 hours, and is used to pick up sensitive information (like ssh keys)

# SSH ports
export sshPortStatus="REPLACEME"
export sshPortBackup="REPLACEME"
export sshPortCommand="REPLACEME"
export sshPortLog="REPLACEME"
export sshPortExtract="REPLACEME"

# For all Banners. Remove symbol: ` and add a space after symbol if at the end of the line it has: \
export bannerIssue="###############################################################
#                  _    _           _     _                   #
#                 / \  | | ___ _ __| |_  | |                  #
#                / _ \ | |/ _ \ '__| __  | |                  #
#               / ___ \| |  __/ |  | |_  |_|                  #
#              /_/   \_\_|\___|_|   \__  (_)                  #
#                                                             #
#  You are entering a secured area!                           #
#                                                             #
#  Your IP, Login Time and Username has been noted and        #
#  has been sent to the server administrator!                 #
#                                                             #
#  This service is restricted to authorized users only.       #
#  All activities on this system are logged.                  #
#                                                             #
#  Unauthorized access will be fully investigated and         #
#  reported to the appropriate law enforcement agencies.      #
###############################################################" # Obtained from: https://gist.github.com/hvmonteiro/7f897cd8ae3993195855040056f87dc6
export bannerMotd="
 ____                        _                       _____ _          
|  _ \ _   _ _ __ __ _  __ _| |_ ___  _ __ _   _ _  |_   _| |__   ___ 
| |_) | | | | '__/ _  |/ _  | __/ _ \| '__| | | (_)   | | | '_ \ / _ \ 
|  __/| |_| | | | (_| | (_| | || (_) | |  | |_| |_    | | | | | |  __/
|_|    \__,_|_|  \__, |\__,_|\__\___/|_|   \__, (_)   |_| |_| |_|\___|
                 |___/                     |___/                      
 ____                                            _          _ 
|  _ \ _ __ ___        ___   ___ ___ _   _ _ __ (_) ___  __| |
| |_) | '__/ _ \_____ / _ \ / __/ __| | | | '_ \| |/ _ \/ _  |
|  __/| | |  __/_____| (_) | (_| (__| |_| | |_) | |  __/ (_| |
|_|   |_|  \___|      \___/ \___\___|\__,_| .__/|_|\___|\__,_|
                                          |_|             

Welcome to an unspecified Alpine Linux device!

System last updated: 00:00 00/00/0000 UTC
System last health scan: 00:00 00/00/0000 UTC
System last log sent: 00:00 00/00/0000 UTC" # Ran with figlet command, reference: https://ar.pinterest.com/pin/dante-the-divine-comedy-2-purgatory-diagrammatic-arrangement-of-mount-purgatory--10062799147380479/

# Variables that can be prefilled, but are automatically asked when needed
export packageDevice="" # Write /dev/devicePath
export packageNamingJustNum=true # Choose "true" or "false" to indicate partioning naming scheme as: "1" or "p1"
export mountDevice="" # Write /dev/devicePath
export namingJustNum=true # Choose "true" or "false" to indicate partioning naming scheme as: "1" or "p1"

# Variables for pre setup (Leave it alone)
gAlpineSetup=false
gPartition=false
gKernelSetup=false

# Variables for post setup (Leave it alone)
gKernel=false
gLocal=false
gRemote=false

# Switch variables not meant to be edit
export version="1.0"
export verbose=false
pre=false
post=false
verify=false
rmAlpine=false

# Variables meant to increase readability
hardeningPatchUrl="https://github.com/anthraxx/linux-hardened/releases/download/v$kernelVersion-hardened1/linux-hardened-v$kernelVersion-hardened1"
p="p" # Partition letter. Increases readability by avoiding "$(echo p)" into $p

# Additional logging variables
export ufwLogging="full" # "low"="on", "medium", "high", "full" : https://thelinuxcode.com/check-my-ufw-log/ : /var/log/ufw.log
export fail2banLogging="INFO" # "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG" : /var/log/fail2ban.log
export sshLogging="VERBOSE" # "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3" : /var/log/sshdUser.log

# Log function
log() {
    if [ -z "$logFile" ]; then logFile="/tmp/hardeningAlpine.log"; fi
    if ! $verbose || [ -z "$verbose" ]; then return 0; fi
    local message="$(date '+%Y-%m-%d %H:%M:%S'): $1" 2>/dev/null
    echo "$message" 2>/dev/null | tee -a "$logFile" 2>/dev/null
}

# Display help
printHelp() {
echo "A script to be run within a fresh alpine environment
Usage: ./alpineHarden.sh [ACTIONS] [CONFIGURATIONS]
Version: $version

Actions: User must specify atleast one action
	-h, --help	Display this help message
	-v, --verbose	Enable verbose logging or display more help information
	--pre		Run pre-setup environment alpine installation in fresh live iso
	--post		Run post-setup environment alpine installation, and apply hardening techniques
	--verify	Verifies if all configurations have been applied
	--formatKernel	Prepare block device to contain a valid alpine kernel to be locally managed. Calls --kernel at the end
	--uninstall	Remove alpine installation
	--all		Shorthand for --pre, --post and --verify"
    if $verbose; then echo ""; else return 0; fi
echo "Configuration: If not specified, then assume user wants everything below enabled
Found in --pre;
	--alpineConfig	Use the existing commands and scripts derived from setup-alpine
	--partition	Setup the custom expected partitions for this system
Found in --post and --verify;
	--local		Configure services and security on local machine
	--remote	Configure external mechanisms for local machine
	--kernel	Configure to install a locally sourced kernel from external device

Expensive operations, controlled via variable:
sshExpensiveOperation:	Generates a new moduli file that filters out weaker bits. This takes a significant amount of space and time when run with; --post --sshd

Internal variables to configure script:
version:		Version of the script (required)
logFile:		Where to save log messages (required)
logIP:			IP address that is a logging server
rootSize:		Declare the size of the root partition for lvm
homeSize:		Declare the size of the home partition for lvm
varSize:		Declare the size of the var partition for lvm
varTmpSize:		Declare the size of the tmp partition for lvm
varLogSize:		Declare the size of the log partition for lvm
localhostName:		Default local host name to be applied on local machine and lvm partitions
lvmName:		Name of the lvm group to be used with device
keyboardLayout:		Declare the layout keyboard configuration
timezone:		Declare the timezone in Country/Origin format
dnsList:		Declare the resolv.conf list
apkRepoList:		Declare the repository(-ies) to obtain packages for main, community, and testing
devDevice:		Declare the udev device type
tempRootPass:		Declare the temporary default root pass
tempSshPass:		Declare the temporary ssh password for all ssh keys generated
mountPoint:		Declare the directory to make a new mount point for a later chroot environment
mountDevice:		Declare the block device to install alpine system to
packageDevice:		Declare the block device that contains a valid kernel
namingJustNum:		Declare that the block device uses a naming scheme that uses only numbers and does not include 'p'
packageNamingJustNum:	Declare that the block device uses a naming scheme that uses only numbers and does not include 'p'
partitionStart:		Declare the partition from the Alpine stored device to tamper with
kernelPartitionStart:	Declare the partition from the Kernel storage device to tamper with
partitionSector: 	Declare the beginning sector to use within the Alpine stored device
kernelPartitionSector:	Declare the beginning sector to use within the kernel storage device
kernelVersion:		Declare which kernel edition we will be using
gitPackageCommitHash:	Declare where in the git repository we will interact with based on prior history
localNetwork:		Declare the local LAN network this machine is connect to by providing a base IPv4 address
localNetmask:		Declare the local LAN network's netmask that will be appeneded to localNetwork
sshPort[Username]:	Declare the default port for ssh servers. Will not tolerate port 22, and must be a system port (0-1023).
umaks:			Declare the standard umask when creating a new file. Determines the default file permissions assigned to a newly created file.
bannerIssue:		Declare the message displayed to most unauthenticated users
bannerMotd:		Decalre the message displayed to most authenticated users
Note: $logFile will be set if the variable is empty upon execution.

Internal variables for created usernames
sshUsernameKey:		Public key of trusted username (ssh required)
monitorUsername:	A username that can read log files, send them through the network, and can login by ssh
previewUsername:	A username that is severely restricted to see status information, and can login by ssh
serverCommandUsername:  A username that is severely restricted to execute very few binaries, and can login by ssh
backupUsername:		A username with limited capabilities to explore the system to backup important files, and can login by ssh
powerUsername:		A system user meant to handle applications like acpid
loggerUsername:		A system user meant to handle applications like syslogd
backgroundUsername:	A system user meant to handle applications like crond
collectorUsername:      A system user that is permitted to explore the rest of the system
firewallUsername:	A system user that is meant to run firewall related applications
fail2banUsername:	A system user meant to handle applications like fail2ban
updateUsername:		A system user that is meant to occasionally update the system
buildUsername:		A system user meant to build a linux kernel
extractUsername:	A user that will be deleted in 4 hours, but has sensitive information about several users
Note: Most of these usernames are only applied if --users is executed, or --kernel"
    exit;
}

# Interpret args
interpretArgs() {
    local wantHelp=false
    for i in "${@}"; do
      case "$i" in
        -h|--help) wantHelp=true;;
        -v|--verbose) verbose=true;;
        --alpineConfig) gAlpineSetup=true;;
        --partition) gPartition=true;;
        --formatKernel) gKernelSetup=true;;
        --local) gLocal=true;;
        --remote) gRemote=true;;
        --kernel) gKernel=true;;
        --uninstall) rmAlpine=true;;
        --verify) verify=true;;
        --post) post=true;;
        --pre) pre=true;;
	--all) pre=true && post=true && verify=true;;
        *)
          echo "BAD FORMAT: Unknown option: $i"
          wantHelp=true
          ;;
      esac
    done

    # Wants to print help menu?
    if $wantHelp; then
        printHelp
        exit
    fi

    # No option selected?
    if ! $pre && ! $post && ! $verify && ! $rmAlpine && ! $gKernelSetup; then
        echo 'BAD FORMAT: Must provide an action!'
        printHelp
        exit
    fi

    # Log file existence
    touch $logFile 2>/dev/null || echo "SYSTEM TEST MISMATCH: Cannot create log file!"
    if ! [ -r "$logFile" ] || ! [ -w "$logFile" ]; then echo "CRITICAL: Cannot write and read log file in: $logFile"; exit; fi

    # Null check
    if [ -z "$version" ]; then echo "BAD FORMAT: Provide any number to indicate the version of this script!"; exit; fi
    if [ -z "$logFile" ]; then echo "BAD FORMAT: Will default to /tmp/hardeningAlpine.log due to this being empty!"; fi
    if [ -z "$logIP" ]; then echo "BAD FORMAT: No ip to indicate a remote logging server!"; exit; fi
    if [ -z "$buildUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$buildUsername and include a name!"; exit; fi
    if [ -z "$monitorUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$monitorUsername and include a name!"; exit; fi
    if [ -z "$powerUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$powerUsername and include a name!"; exit; fi
    if [ -z "$loggerUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$loggerUsername and include a name!"; exit; fi
    if [ -z "$backgroundUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$backgroundUsername and include a name!"; exit; fi
    if [ -z "$collectorUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$collectorUsername and include a name!"; exit; fi
    if [ -z "$previewUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$previewUsername and include a name!"; exit; fi
    if [ -z "$serverCommandUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$serverCommandUsername and include a name!"; exit; fi
    if [ -z "$backupUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$backupUsername and include a name!"; exit; fi
    if [ -z "$firewallUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$firewallUsername and include a name!"; exit; fi
    if [ -z "$fail2banUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$fail2banUsername and include a name!"; exit; fi
    if [ -z "$updateUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$updateUsername and include a name!"; exit; fi
    if [ -z "$extractUsername" ]; then echo "BAD FORMAT: Declare username that will be seperated from certain root permissions! Edit: \$extractUsername and include a name!"; exit; fi
    if [ -z "$sshUsernameKey" ]; then echo "BAD FORMAT: Public key variable must be configured before usage! Edit: \$sshUsernameKey and include a public key!"; exit; fi
    if [ -z "$rootSize" ]; then echo "BAD FORMAT: Missing required value in rootSize"; exit; fi
    if [ -z "$homeSize" ]; then echo "BAD FORMAT: Missing required value in homeSize"; exit; fi
    if [ -z "$varSize" ]; then echo "BAD FORMAT: Missing required value in varSize"; exit; fi
    if [ -z "$varTmpSize" ]; then echo "BAD FORMAT: Missing required value in varTmpSize"; exit; fi
    if [ -z "$varLogSize" ]; then echo "BAD FORMAT: Missing required value in varLogSize"; exit; fi
    if [ -z "$localhostName" ]; then echo "BAD FORMAT: Missing required value in localhostName"; exit; fi
    if [ -z "$lvmName" ]; then echo "BAD FORMAT: Missing required value in lvmName"; exit; fi
    if [ -z "$keyboardLayout" ]; then echo "BAD FORMAT: Missing required value in keyboardLayout"; exit; fi
    if [ -z "$timezone" ]; then echo "BAD FORMAT: Missing required value in timezone"; exit; fi
    if [ -z "$dnsList" ]; then echo "BAD FORMAT: Missing required value in dnsList"; exit; fi
    if [ -z "$apkRepoList" ]; then echo "BAD FORMAT: Missing required value in apkRepoList"; exit; fi
    if [ -z "$devDevice" ]; then echo "BAD FORMAT: Missing required value in devDevice"; exit; fi
    if [ -z "$tempRootPass" ]; then echo "BAD FORMAT: Enter a password for the root user. It cannot be empty!"; exit; fi
    if [ -z "$tempSshPass" ]; then echo "BAD FORMAT: Enter a password for ssh key generation! It cannot be empty!"; exit; fi
    if [ -z "$mountPoint" ]; then echo "BAD FORMAT: Missing a path for mounting!"; exit; fi
    if [ -z "$partitionStart" ]; then echo "BAD FORMAT: a!"; exit; fi
    if [ -z "$kernelPartitionStart" ]; then echo "BAD FORMAT: Must indicate boot partition that will be formed or used!"; exit; fi
    if [ -z "$partitionSector" ]; then echo "BAD FORMAT: Must indicate the sector of the block device that indicates where our first partition resides!"; exit; fi
    if [ -z "$kernelPartitionSector" ]; then echo "BAD FORMAT: Must indicate kernel storage partition that will be formed or used!"; exit; fi
    if [ -z "$kernelVersion" ]; then echo "BAD FORMAT: Must indicate the version of the linux kernel that is planned to be used!"; exit; fi
    if [ -z "$gitPackageCommitHash" ]; then echo "BAD FORMAT: Must indicate the git branch hash that is expected to be used!"; exit; fi
    if [ -z "$localNetwork" ]; then echo "BAD FORMAT: Must provide a IPv4 base address for the local network!"; exit; fi
    if [ -z "$localNetmask" ]; then echo "BAD FORMAT: Must provide a IPv4 local network netmask!"; exit; fi
    if [ -z "$sshPortBackup" ]; then echo "BAD FORMAT: Must provide a valid port number that is in range of 1-1023, and is not 22!"; exit; fi
    if [ -z "$sshPortCommand" ]; then echo "BAD FORMAT: Must provide a valid port number that is in range of 1-1023, and is not 22!"; exit; fi
    if [ -z "$sshPortExtract" ]; then echo "BAD FORMAT: Must provide a valid port number that is in range of 1-1023, and is not 22!"; exit; fi
    if [ -z "$sshPortLog" ]; then echo "BAD FORMAT: Must provide a valid port number that is in range of 1-1023, and is not 22!"; exit; fi
    if [ -z "$sshPortStatus" ]; then echo "BAD FORMAT: Must provide a valid port number that is in range of 1-1023, and is not 22!"; exit; fi
    if [ -z "$umask" ]; then echo "BAD FORMAT: Must provide a non-empty umaks value!"; exit; fi
    if [ -z "$bannerIssue" ]; then echo "BAD FORMAT: Must provide a non-empty warning to unauthenticated users!"; exit; fi
    if [ -z "$bannerMotd" ]; then echo "BAD FORMAT: Must provide a non-empty welcoming to authenticated users!"; exit; fi

    # Format check
    if ! (echo $logIP | grep -Eq ^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$); then echo "BAD FORMAT: Not a valid IPv4 format IP address for logging capabilities! Edit: logIP"; exit; fi
    if ! (echo $localNetwork | grep -Eq ^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$); then echo "BAD FORMAT: Not a valid IPv4 format IP address for local LAN network! Edit: localNetwork"; exit; fi
    for i in $dnsList; do # Verify valid ipv4 format of dnslist
        if ! (echo $i | grep -Eq ^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$); then echo "BAD FORMAT: Not a valid ip address declared within the dnsList: $i" 2>/dev/null; exit; fi
    done
    for j in $apkRepoList; do
        if ! (echo $j | grep -Eq "^https://[^ ]*[^/]$"); then echo "BAD FORMAT: Not a valid repository declared. Either not a https link, or user has included a '/' at the end: $j" 2>/dev/null; exit; fi
    done
    if (! echo $rootSize | grep -Eq ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$\|^[0-9]*[.]\{0,1\}[0-9]+EX$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size expected in rootSize: $rootSize" 2>/dev/null; exit; fi
    if (! echo $homeSize | grep -Eq ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$\|^[0-9]*[.]\{0,1\}[0-9]+EX$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size expected in homeSize: $homeSize" 2>/dev/null; exit; fi
    if (! echo $varSize | grep -Eq ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$\|^[0-9]*[.]\{0,1\}[0-9]+EX$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size expected in varSize: $varSize" 2>/dev/null; exit; fi
    if (! echo $varTmpSize | grep -Eq ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$\|^[0-9]*[.]\{0,1\}[0-9]+EX$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size expected in varTmpSize: $varTmpSize" 2>/dev/null; exit; fi
    if (! echo $varLogSize | grep -Eq ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$\|^[0-9]*[.]\{0,1\}[0-9]+EX$\|^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size expected in varLogSize: $varLogSize" 2>/dev/null; exit; fi
    if (! echo $timezone | grep -Eq [A-z]+/[A-z]); then echo "BAD FORMAT: Not a valid timezone declaration! $timezone" 2>/dev/null; exit; fi
    if (! echo $sshPortBackup | grep -Eq ^[0-9]) && [ $sshPortBackup -le 1023 ] && [ $sshPortBackup -ge 0 ] && [ $sshPortBackup != 22 ]; then echo "BAD FORMAT: Must provide a valid port number for \$sshPortBackup that is in range of 1-1023, and is not 22!"; exit; fi
    if (! echo $sshPortCommand | grep -Eq ^[0-9]) && [ $sshPortCommand -le 1023 ] && [ $sshPortCommand -ge 0 ] && [ $sshPortCommand != 22 ]; then echo "BAD FORMAT: Must provide a valid port number for \$sshPortCommand that is in range of 1-1023, and is not 22!"; exit; fi
    if (! echo $sshPortExtract | grep -Eq ^[0-9]) && [ $sshPortExtract -le 1023 ] && [ $sshPortExtract -ge 0 ] && [ $sshPortExtract != 22 ]; then echo "BAD FORMAT: Must provide a valid port number for \$sshPortExtract that is in range of 1-1023, and is not 22!"; exit; fi
    if (! echo $sshPortLog | grep -Eq ^[0-9]) && [ $sshPortLog -le 1023 ] && [ $sshPortLog -ge 0 ] && [ $sshPortLog != 22 ]; then echo "BAD FORMAT: Must provide a valid port number for \$sshPortLog that is in range of 1-1023, and is not 22!"; exit; fi
    if (! echo $sshPortStatus | grep -Eq ^[0-9]) && [ $sshPortStatus -le 1023 ] && [ $sshPortStatus -ge 0 ] && [ $sshPortStatus != 22 ]; then echo "BAD FORMAT: Must provide a valid port number for \$sshPortStatus that is in range of 1-1023, and is not 22!"; exit; fi
    if (! echo $umask | grep -Eq ^[0-9][0-9][0-9]); then echo "BAD FORMAT: Must provide a valid umask in 3 digit format; like 022 or 077!"; exit; fi

    # Behavior check
    if [ "$mountPoint" = "/" ] && $pre; then echo "SYSTEM TEST MISMATCH: Cannot have pre-installation declared on / point. Specify elsewhere."; exit; fi

    log "INFO: Finished reading all variables: $*"
}

# Print what this script will apply
printVariables() {
    echo ""
    echo "File related variables:"

    # Mention global variables
    echo "Partition sizes; Root: $rootSize | Home: $homeSize | Var: $varSize | Var/Tmp: $varTmpSize | Var/Log: $varLogSize"
    echo "Time and resolv; Timezone: $timezone | Dns list: $dnsList"
    echo "File locations; Log: $logFile | Mount: $mountPoint"
    echo ""
    echo "Script configuration:"
    echo "Mode; Pre: $pre | Post: $post | Verify: $verify | Delete: $rmAlpine | Verbosity: $verbose | Fresh kernel installation: $gKernelSetup"
    echo "Script; Remote logging server address: $logIP"

    # Last chance to back out
    while true; do
        read -p "Are the above settings and variables configured correctly? y/n: " yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) exit;;
        esac
    done
}

# Detect mount point
mountFind() {
    # Check if primary variables are already set, if so then exit prematurely
    if [ ! -z "$mountDevice" ] && [ ! -z "$packageDevice" ]; then return 0; fi

    # Notify script
    log "INFO: Started to find block devices!"
    local devName=""
    local devBlock=""
    local devSize=""
    local devLabel=""
    local choiceMain=""
    local skip=false
    local blockFormatSize=1024

    # Let user read list printed from above, and have user manually specify which device to use
    while true; do
        # Print a list of possible devices
        echo "Device		Size		Label"
        cat /proc/partitions | grep -ivE ram\|loop\|major\|dm\- | while read -r devDevice; do
            if [ "$devDevice" = '' ]; then continue; fi
            devName=$(echo $devDevice | awk -F ' {1,}' '{print($4)}')
            devBlock=$(echo $devDevice | awk -F ' {1,}' '{print($3)}')
            devSize=$(awk "BEGIN {if ((($devBlock*$blockFormatSize)/1073741824) > 1) {print (($devBlock*$blockFormatSize)/1073741824) \" GB\"} else {print (($devBlock*$blockFormatSize)/1048576) \" MB\"}}")
            devLabel=$(ls -l /dev/disk/by-label/ | grep -w $devName)
            echo "$devName	$devSize	$devLabel"
        done

        # User selection for core device
        while [ -z "$choiceMain" ]; do
            read -p "From the list above. Specify the device to be primarely used [Type 'no' to abort]: " choiceMain
            case $choiceMain in
                NO ) exit;;
                No ) exit;;
                nO ) exit;;
                no ) exit;;
                *) break;;
            esac
        done

        # User selection for core device
        while [ -z "$choiceAports" ]; do
            read -p "From the list above. Specify where systemm packages are stored [Type 'no' to abort, type 'skip' to ignore]: " choiceAports
            case $choiceAports in
                NO ) exit;;
                No ) exit;;
                nO ) exit;;
                no ) exit;;
                skip ) skip=true;;
                *) break;;
            esac
        done

        # Check if device exists
        if [ ! -e "/dev/$choiceMain" ]; then choiceMain=''; fi
        if [ ! -e "/dev/$choiceAports" ] && ! $skip; then choiceAports=''; fi
        if [ ! -z "$choiceMain" ] && [ ! -z "$choiceAports" ]; then break; else log "UNEXPECTED: The block device does not exist"; fi
    done

    # Determine if partition type has a p or not: https://unix.stackexchange.com/questions/500887/given-a-block-device-how-to-detect-if-names-of-partitions-must-contain-p
    if [ ! -z "$(echo $choiceMain | grep -E -o [1234567890]*$)" ]; then export namingJustNum=false; else export namingJustNum=true; fi
    if [ ! -z "$(echo $choiceAports | grep -E -o [1234567890]*$)" ]; then export packageNamingJustNum=false; else export packageNamingJustNum=true; fi
    export mountDevice="/dev/$choiceMain"
    export packageDevice="/dev/$choiceAports"

    echo "INFO: User input will no longer be required. (Unless deleting installation, or setting up the kernel for the first time)"
    log "INFO: Device to be affected: $mountDevice | Kernel located in device: $packageDevice | Affected device does not have 'p' in partition? : $namingJustNum | kernel storage device does not have 'p' in partition? : $packageNamingJustNum"
    log "INFO: Finished finding block devices"
}

kernelExternalMount() {
    # Find where to find mounted devices
    mountFind

    # Check if kernel mounting is warranted, if so then mount
    if [ ! "$packageDevice" = "/dev/skip" ] && [ -z "$(mount | grep -i $packageDevice)" ]; then
        # Check home directory existance, then mount
        if [ -d "$mountPoint/home/maintain" ]; then 
            if $packageNamingJustNum; then chroot $mountPoint /bin/mount -t xfs "$packageDevice$kernelPartitionStart" /home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount kernel partition to $mountPoint/home/maintain"; else chroot $mountPoint /bin/mount -t xfs "$packageDevice$p$kernelPartitionStart" /home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount kernel partition to $mountPoint/home/maintain"; fi
        else log "INFO: Kernel storage device can't mount to $mountPoint/home/maintain"; fi
    else log "INFO: Kernel storage devices skipped, or already mounted!"; fi
}

# Safely mount expected drives and prepare chroot environment
mountAlpine() {
    # Find where to find mounted devices
    mountFind

    # Check if mountpoint is current filesystem
    if [ "$mountPoint" = "/" ]; then log "INFO: Nothing to mount! Mount point is set to current filesystem root."; return 0; fi

    # Check if drives are already mounted at mount pount ($mountPoint)
    if [ ! -z "$(mount | grep -i $mountPoint)" ]; then log "INFO: Atleast some drives are already mounted!"; return 0; fi
    log "INFO: Started mounting alpine!"

    # Start mounting the whole alpine directory
    log "INFO: Started mounting partitions to expected regions"
    vgchange -ay 2>/dev/null || log "CRITICAL: Could not enable logical partitions"
    mkdir -p "$mountPoint" 2>/dev/null || log "CRITICAL: Lacked capabilities to write $mountPoint or it already exists"
    mount -t ext4 /dev/"$lvmName"/"$localhostName".root "$mountPoint" 2>/dev/null || log "CRITICAL: Lacked capabilities to mount $lvmName to $mountPoint"
    mkdir -p "$mountPoint"/boot 2>/dev/null || log "UNEXPECTED: Lacked capabilities to write to $mountPoint/boot"
    mkdir -p "$mountPoint"/boot/efi 2>/dev/null || log "UNEXPECTED: Lacked capabilities to write to $mountPoint/boot/efi"
    mkdir -p "$mountPoint"/home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to write to $mountPoint"
    mkdir -p "$mountPoint"/var 2>/dev/null || log "UNEXPECTED: Lacked capabilities to write to $mountPoint"
    mount -t ext4 /dev/"$lvmName"/"$localhostName".home "$mountPoint"/home 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount $lvmName to $mountPoint"
    if $namingJustNum; then mount -t vfat "$mountDevice$partitionStart" "$mountPoint"/boot/efi 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount efi partition to $mountPoint/boot/efi"; else mount -t vfat "$mountDevice$p$partitionStart" "$mountPoint"/boot/efi 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount efi partition to $mountPoint/boot/efi"; fi
    mount -t ext4 /dev/"$lvmName"/"$localhostName".var "$mountPoint"/var 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount var partition to $mountPoint/var"
    mkdir -p "$mountPoint"/var/log 2>/dev/null || log "UNEXPECTED: Lacked capabilities to write to $mountPoint/var"
    mkdir -p "$mountPoint"/var/tmp 2>/dev/null || log "UNEXPECTED: Lacked capabilities to write to $mountPoint/var"
    mount -t ext4 /dev/"$lvmName"/"$localhostName".var.log "$mountPoint"/var/log 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount var/log partition to $mountPoint/var/log"
    mount -t ext4 /dev/"$lvmName"/"$localhostName".var.tmp "$mountPoint"/var/tmp 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount var/tmp partition to $mountPoint/var/tmp"
    log "INFO: Finish mounting partitions to expected regions"

    # Required for a valid chroot environment
    log "INFO: Preparing chroot environment"
    mkdir -p "$mountPoint"/proc 2>/dev/null || log "UNEXPECTED: Could not create /proc directory for chroot environment"
    mkdir -p "$mountPoint"/sys 2>/dev/null || log "UNEXPECTED: Could not create /sys directory for chroot environment"
    mkdir -p "$mountPoint"/dev 2>/dev/null || log "UNEXPECTED: Could not create /dev directory for chroot environment"
    mkdir -p "$mountPoint"/run 2>/dev/null || log "UNEXPECTED: Could not create /run directory for chroot environment"
    mount -t proc proc "$mountPoint"/proc 2>/dev/null || log log "CRITICAL: Could not make /proc available in chroot environment"
    mount -o bind /sys "$mountPoint"/sys 2>/dev/null || log "CRITICAL: Could not make /sys available in chroot environment"
    mount -o bind /dev "$mountPoint"/dev 2>/dev/null || log "CRITICAL: Could not make /dev available in chroot environment"
    mount -o bind /run "$mountPoint"/run 2>/dev/null || log "CRITICAL: Could not make /run available in chroot environment"
    log "INFO: Finished setting up bindings for chroot environment"

    # Finish mounting
    log "INFO: Finished mounting alpine!"
}

# Safely umount expected drives and prepare chroot environment
unmountAlpine() {
    # Find where to find mounted devices
    mountFind

    # Check if kernel un-mounting is warranted, if so then mount
    if [ ! "$packageDevice" = "/dev/skip" ] && [ ! -z "$(mount | grep -i $packageDevice)" ]; then
        # Check home directory existance, then mount
        if [ -d "$mountPoint/home/maintain" ]; then chroot $mountPoint /bin/umount /home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to umount kernel partition from $mountPoint/home/maintain"; else log "INFO: Kernel storage device can't umount to $mountPoint/home/maintain"; fi
    else log "INFO: Kernel storage devices skipped, or already un-mounted!"; fi

    # Check if mountpoint is current filesystem
    if [ "$mountPoint" = "/" ]; then log "INFO: Nothing to umount! Mount point is set to current filesystem root."; return 0; fi

    # Check if drives are already unmounted at mount pount ($mountPoint)
    if [ -z "$(mount | grep -i $mountPoint)" ]; then log "INFO: Drives are already unmounted!"; return 0; fi

    # Unmoount devices from known chroot environment
    log "INFO: Started umount-ing alpine!"
    vgchange -ay 2>/dev/null || log "UNEXPECTED: Could not enable logical partitions to unmount partitions"
    umount "$mountPoint"/boot/efi 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/boot/efi"
    umount "$mountPoint"/var/tmp 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/var/tmp"
    umount "$mountPoint"/var/log 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/var/log"
    umount "$mountPoint"/var 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/var"
    umount "$mountPoint"/home/maintain 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/home/maintain"
    umount "$mountPoint"/home 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/home"
    umount "$mountPoint"/proc 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/proc"
    umount "$mountPoint"/sys 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/sys"
    umount "$mountPoint"/dev 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/dev"
    umount "$mountPoint"/run 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint/run"
    umount "$mountPoint" 2>/dev/null|| log "UNEXPECTED: Could not umount on: $mountPoint"
    log "INFO: Finished unmounting alpine environment"

    # Finish unmounting
    log "INFO: Finished umount-ing alpine!"
}

# Reset partitions and installation on detected drive
removeAlpine() {
    # Find where to find mounted devices
    mountFind

    # Check if mountpoint is current filesystem
    if [ "$mountPoint" = "/" ]; then log "INFO: Nothing to delete! Mount point is set to current filesystem root."; return 0; fi

    # Check if partitions exist
    if [ -z "$(ls $mountDevice* | grep 2)" ]; then echo "SYSTEM TEST MISMATCH: Device does not have a second partition, thus it was already deleted"; exit; fi

    # Ask the user if they wish to delete alpine
    while true; do
        read -p "Delete alpine installation found in $mountPoint from $mountDevice device? y/n: " yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) return 0;;
        esac
    done

    # Unmount drives if they are still present
    log "INFO: Started removing alpine installation on $mountDevice media"
    unmountAlpine
    rmdir "$mountPoint" 2>/dev/null|| log "UNEXPECTED: Could not remove $mountPoint"

    # Remove vg and pv recognition from lvm
    vgremove "$lvmName" || log "UNEXPECTED: Could not remove $lvmname as a valid recognized name from system"
    if $namingJustNum; then pvremove "$mountDevice$(($partitionStart+1))" || log "UNEXPECTED: Could not remove lvm signature from physical device"; else pvremove "$mountDevice$p$(($partitionStart+1))" || log "UNEXPECTED: Could not remove lvm signature from physical device"; fi

    # Remove recognized partitions from device
    if $namingJustNum; then parted -a optimal "$mountDevice" 'rm 2' 2>/dev/null || log "CRITICAL: Could not remove LVM partition 2 on physical device"; else parted -a optimal "$mountDevice" 'rm 3' 2>/dev/null || log "CRITICAL: Could not remove LVM partition 3 on physical device"; fi
    if $namingJustNum; then parted -a optimal "$mountDevice" 'rm 1' 2>/dev/null || log "CRITICAL: Could not remove EFI partition 1 on physical device"; else parted -a optimal "$mountDevice" 'rm 2' 2>/dev/null || log "CRITICAL: Could not remove EFI partition 2 on physical device"; fi

    # Confirmation message
    log "INFO: Finished removing alpine installation on $mountDevice media"
}

setupAlpine() {
    log "INFO: Started default alpine installation"
    setup-hostname "$localhostName" 2>/dev/null || log "UNEXPECTED: Could not declare device's hostname"
    rc-service --quiet networking stop 2>/dev/null || log "UNEXPECTED: Could not stop networking services"
    rc-service --quiet hostname restart 2>/dev/null || log "UNEXPECTED: Could not restart hostname services"
    rc-service --quiet networking start 2>/dev/null || log "UNEXPECTED: Could start networking services"
    setup-devd -C "$devDevice" 2>/dev/null || log "UNEXPECTED: Could not set mdev for devd"
    setup-dns "$dnsList" 2>/dev/null || log "CRITICAL: Could not set up local dns"
    ntpd -q -p us.pool.ntp.org 2>/dev/null || log "CRITICAL: Could not set up local time with ntpd"
    rc-update --quiet add networking boot 2>/dev/null || log "UNEXPECTED: Could not add networking and boot services to rc"
    rc-update --quiet add seedrng boot 2>/dev/null || rc-update --quiet add urandom boot 2>/dev/null || log "UNEXPECTED: Could not add seedrng and boot to rc"
    rc-update --quiet add crond 2>/dev/null || log "UNEXPECTED: Could not setup crond to rc"
    rc-update --quiet add acpid 2>/dev/null || log "UNEXPECTED: Could not setup acpid to rc"
    openrc boot 2>/dev/null || log "UNEXPECTED: Could not interact with boot runlevel"
    openrc default 2>/dev/null || log "UNEXPECTED: Could not interact with default runlevel"
    echo "127.0.0.1  $localhostName.$localhostName $localhostName" > /etc/hosts 2>/dev/null 2>/dev/null || log "CRITICAL: Could not declare local resolved names to /etc/hosts"
    echo "# APK Repositories configured by automated tool:" > /etc/apk/repositories 2>/dev/null || log "UNEXPECTED: Did not reset prior apk repository list"
    if [ -f "/etc/apk/repositories" ]; then rm /etc/apk/repositories; fi
    for i in $apkRepoList; do
        echo "$i/main" >> /etc/apk/repositories 2>/dev/null || log "CRITICAL: Could not add a main repository for apk: $i/main"
        echo "@additional $i/community" >> /etc/apk/repositories 2>/dev/null || log "UNEXPECTED: Could not add a community repository for apk: $i/community"
        echo "@se $i/testing" >> /etc/apk/repositories 2>/dev/null || log "UNEXPECTED: Could not add a testing repository for apk: $i/testing"
    done
    apk update >/dev/null # First instance keeps failing despite time correctly set
    apk update
    setup-timezone "$timezone" 2>/dev/null || log "UNEXPECTED: Could not set timezone"
    setup-ntp chrony 2>/dev/null || log "UNEXPECTED: Did not setup chronyd as the default ntp service"
    setup-sshd openssh 2>/dev/null || log "CRITICAL: Did not setup an sshd service"
    setup-keymap "$keyboardLayout" "$keyboardLayout" 2>/dev/null || log "UNEXPECTED: Could not setup device's keyboard keymap"
    rc-update --quiet del loadkmap boot 2>/dev/null || log "UNEXPECTED: Could not remove unncessary service that fails on boot"
    echo "root:$tempRootPass" | chpasswd || log "UNEXPECTED: Did not change root password"
    apk add parted lvm2 e2fsprogs xfsprogs tzdata grub-efi grub || log "Unexpected: Could not install all required software"
    log "INFO: Almost finished default alpine installation!"
}

# Inspired by: https://techgirlkb.guru/2019/08/how-to-create-cis-compliant-partitions-on-aws/
setupDisks() {
    # Find where to find mounted devices
    mountFind

    # Install software
    log "INFO: Installing required software"
    apk add parted lvm2 e2fsprogs xfsprogs || log "CRITICAL: Could not install all software"

    log "INFO: Started partitioning disk on $mountDevice"
    
    # Partition the device
    local s="s"
    parted -a optimal "$mountDevice" 'unit s' 2>/dev/null || log "INFO: Could not set unit when partitioning disks"
    parted -a optimal "$mountDevice" "mkpart primary fat32 $partitionSector$s 1050623s" 2>/dev/null
    parted -a optimal "$mountDevice" "set $partitionStart boot on" 2>/dev/null || log "UNEXPECTED: Could not declare $partitionStart partition as boot drive"; 
    parted -a optimal "$mountDevice" 'mkpart primary ext4 1050624s 100%' 2>/dev/null || log "CRITICAL: Could not declare final partition as LVM"
    parted -a optimal "$mountDevice" "set $(($partitionStart+1)) lvm on" 2>/dev/null
    parted -a optimal "$mountDevice" "align-check optimal $partitionStart" 2>/dev/null || log "UNEXPECTED: Could not optimize placement of boot partition"
    parted -a optimal "$mountDevice" "align-check optimal $(($partitionStart+1))" 2>/dev/null || log "UNEXPECTED: Could not optimize placement of partitions"
    mdev -s 2>/dev/null || log "CRITICAL: Could not restart mdev service"

    log "INFO: Partitioning completed"

    # Setup LVM environment
    if $namingJustNum; then pvcreate -ff "$mountDevice$(($partitionStart+1))" || log "CRITICAL: Could not declare lvm partition signature"; else pvcreate -ff "$mountDevice$p$(($partitionStart+1))" || log "CRITICAL: Could not declare lvm partition signature"; fi
    if $namingJustNum; then vgcreate "$lvmName" "$mountDevice$(($partitionStart+1))" || log "CRITICAL: Could not declare lvm logical group"; else vgcreate "$lvmName" "$mountDevice$p$(($partitionStart+1))" || log "CRITICAL: Could not declare lvm logical group"; fi
    log "INFO: Created pv and vg device"
    lvcreate -n "$localhostName".root -L "$rootSize" "$lvmName" || log "CRITICAL: Could not make root partition"
    log "INFO: Created root partition"
    lvcreate -n "$localhostName".home -L "$homeSize" "$lvmName" || log "UNEXPECTED: Coild not make home partition"
    log "INFO: Created home partition"
    lvcreate -n "$localhostName".var -L "$varSize" "$lvmName" || log "UNEXPECTED: Could not make var partition"
    log "INFO: Created var partition"
    lvcreate -n "$localhostName".var.tmp -L "$varTmpSize" "$lvmName" || log "UNEXPECTED: Could not make var/tmp partition"
    log "INFO: Created var/tmp partition"
    lvcreate -n "$localhostName".var.log -L "$varLogSize" "$lvmName" || log "UNEXPECTED: Could not make var/log partition"
    log "INFO: Created var/log partition"
    rc-update add lvm 2>/dev/null || log "UNEXPECTED: Did not add lvm services to rc"
    vgchange -ay 2>/dev/null || log "UNEXPECTED: Could not enable logical partitions"
    log "INFO: Finished LVM setup"

    # Format drives
    if $namingJustNum; then mkfs.vfat "$mountDevice$partitionStart" 2>/dev/null || log "CRITICAL: Could not format boot partition"; else mkfs.vfat "$mountDevice$p$partitionStart" 2>/dev/null || log "CRITICAL: Could not format boot partition"; fi
    mkfs.ext4 -F /dev/"$lvmName"/"$localhostName".home 2>/dev/null || log "UNEXPECTED: Could not format home partition"
    mkfs.ext4 -F /dev/"$lvmName"/"$localhostName".root 2>/dev/null || log "CRITICAL: Could not format root partition"
    mkfs.ext4 -F /dev/"$lvmName"/"$localhostName".var 2>/dev/null || log "UNEXPECTED: Could not format var partition"
    mkfs.ext4 -F /dev/"$lvmName"/"$localhostName".var.log 2>/dev/null || log "UNEXPECTED: Could not format var/log partition"
    mkfs.ext4 -F /dev/"$lvmName"/"$localhostName".var.tmp 2>/dev/null || log "UNEXPECTED: Could not format var/tmp partition"
    log "INFO: Finished formatting"

    # Mount drives to correct configuration
    mountAlpine

    # Execute setup-disk command provided by alpine
    setup-disk "$mountPoint" || log "CRITICAL: Did not install setup to $namingJustNum"
    log "INFO: Default alpine provided installation completed"

    # Change fstab file configuration
    log "INFO: Modifying fstab file"
    chroot $mountPoint /bin/sed -i "s/tmpfs\t\/tmp\ttmpfs\tnosuid,nodev\t0\t0/tmpfs\t\/tmp\ttmpfs\tnoatime,nodev,noexec,nosuid,size\=512m\t0\t0/g" /etc/fstab 2>/dev/null || log "UNEXPECTED: Could not harden fstab mounting"
    chroot $mountPoint /bin/echo -e "tmpfs\t/dev/shm\ttmpfs\tnodev,nosuid,noexec\t0\t0" >> /etc/fstab 2>/dev/null || log "UNEXPECTED: Could not harden fstab mounting"
    chroot $mountPoint /bin/sed -i "s/\/dev\/$lvmName\/$localhostName.home\t\/home\text4\trw,relatime 0 2/\/dev\/$lvmName\/$localhostName.home\t\/home\text4\trw,relatime,noatime,acl,user_xattr,nodev,nosuid 0 2/1" /etc/fstab 2>/dev/null || log "UNEXPECTED: Could not harden fstab mounting"
    chroot $mountPoint /bin/sed -i "s/\/dev\/$lvmName\/$localhostName.var\t\/var\text4\trw,relatime 0 2/\/dev\/$lvmName\/$localhostName.var\t\/var\text4\trw,relatime,noatime,nodev,nosuid 0 2/1" /etc/fstab 2>/dev/null || log "UNEXPECTED: Could not harden fstab mounting"
    chroot $mountPoint /bin/sed -i "s/\/dev\/$lvmName\/$localhostName.var.log\t\/var\/log\text4\trw,relatime 0 2/\/dev\/$lvmName\/$localhostName.var.log\t\/var\/log\text4\trw,relatime,noatime,nodev,nosuid 0 2/1" /etc/fstab 2>/dev/null || log "UNEXPECTED: Could not harden fstab mounting"
    chroot $mountPoint /bin/sed -i "s/\/dev\/$lvmName\/$localhostName.var.tmp\t\/var\/tmp\text4\trw,relatime 0 2/\/dev\/$lvmName\/$localhostName.var.tmp\t\/var\/tmp\text4\trw,relatime,noatime,nodev,nosuid,noexec 0 2/1" /etc/fstab 2>/dev/null || log "UNEXPECTED: Could not harden fstab mounting"

    # Ensure grub has no timeout when booting into it's menu
    chroot $mountPoint /bin/sed -i 's/GRUB_TIMEOUT=\(.*\)/GRUB_TIMEOUT=0/g' /etc/default/grub || log "UNEXPECTED: Could not lower timeout for grub configuration"
    chroot $mountPoint /bin/chmod 400 /etc/default/grub || log "UNEXPECTED: Could not set to 400 permission on /etc/default/grub"

    # Confirmation message
    log "INFO: Finished partitioning disk on $mountDevice" /dev/"$lvmName"/"$localhostName"
}

formatKernel() {
    # Find where to find mounted devices
    log "INFO: Checking requirements to setup kernel"
    mountFind
    if [ "$choiceAports" = "skip" ]; then log "INFO: No block device specified to install kernel in"; return 0; fi

    log "INFO: Setting up kernel to: $packageDevice. Begin formatting it"
    chroot $mountPoint /sbin/apk add xfsprogs parted 2>/dev/null || log "CRITICAL: Could not install required software"
    chroot $mountPoint /usr/sbin/parted -a optimal "$packageDevice" "mkpart primary xfs $kernelPartitionSector$(echo s) 100%" 2>/dev/null || log "CRITICAL: Could not declare kernel block device partition"
    chroot $mountPoint /usr/sbin/parted -a optimal "$packageDevice" 'align-check optimal 1' 2>/dev/null || log "UNEXPECTED: Could not optimize placement of kernel block partition"
    if $packageNamingJustNum; then chroot $mountPoint /sbin/mkfs.xfs -f "$packageDevice$kernelPartitionStart" 2>/dev/null || log "CRITICAL: Could not format kernel block device"; else chroot $mountPoint /sbin/mkfs.xfs -f "$packageDevice$p$kernelPartitionStart" 2>/dev/null || log "CRITICAL: Could not format kernel block device"; fi
    
    log "INFO: Mounting kernel storage device to /home/maintain directory"
    chroot $mountPoint /bin/mkdir -p /home/maintain 2>/dev/null || log "UNEXPECTED: Could not create home directory to mount towards"
    kernelExternalMount
    
    log 'INFO: Finished preparing kernel storage device. Moving onto automatic configuration from configKernel()'
    configKernel
}

# Modify kernel with ncurses-dev; chroot /mnt/alpine /usr/bin/make menuconfig -C /home/maintain/aports/main/linux-lts/src/linux-6.12
configKernel() {
    if [ "$choiceAports" = 'skip' ]; then log "BAD FORMAT: Skipping kernel configuration due to lacking a kernel storage device"; return 0; fi
    if [ ! -f "$mountPoint/home/maintain/linuxConfig.config" ]; then log "BAD FORMAT: There is no linux configuration file present as linuxConfig.config. Please place one in $mountPoint/home/maintain/"; echo "There is no linux configuration file present as linuxConfig.config. Please place one in $mountPoint/home/maintain/"; return 0; fi

    log "INFO: Installing required tools for this section"
    chroot $mountPoint /sbin/apk add alpine-sdk kernel-hardening-checker@additional 2>/dev/null || log "CRITICAL: Could not install required packages for kernel"

    if [ -z "$(chroot $mountPoint /bin/grep $buildUsername /etc/passwd)" ]; then
        log "INFO: Setting up $buildUsername user"
        chroot $mountPoint /bin/mkdir -p /home/maintain 2>/dev/null || log "UNEXPECTED: Could not make a new directory"
        chroot $mountPoint /usr/sbin/adduser -h /home/maintain -S -D -s /sbin/nologin $buildUsername 2>/dev/null || log "CRITICAL: Could not create an account for building the kernel"
        chroot $mountPoint /usr/sbin/addgroup $buildUsername abuild 2>/dev/null || log "CRITICAL: Could not include $buildUsername into abuild group"
        chroot $mountPoint /usr/sbin/addgroup $buildUsername wheel 2>/dev/null || log "UNEXPECTED: Could not include $buildUsername into admin group"
    fi

    if [ ! -d "$mountPoint/home/maintain/aports/.git" ]; then
        log "INFO: Obtaining github repo to install kernel"
        chroot $mountPoint /bin/chown "$buildUsername:root" /home/maintain 2>/dev/null || log "UNEXPECTED: Could not ensure home directory of $buildUsername is owner"
        chroot $mountPoint /usr/bin/git -C /home/maintain clone git://git.alpinelinux.org/aports.git || log "CRITICAL: Could not obtain github repo to install kernel"
    fi

    log "INFO: Restricting directories"
    chroot $mountPoint /bin/chmod 760 /home/maintain 2>/dev/null || log "UNEXPECTED: Could not enable /home/maintain directory"
    chroot $mountPoint /bin/chmod 760 /home/maintain/aports 2>/dev/null || log "UNEXPECTED: Could not enable /home/maintain/aports directory"
    chroot $mountPoint /bin/chmod 760 /home/maintain/aports/main 2>/dev/null || log "UNEXPECTED: Could not enable /home/maintain/aports/main directory"
    chroot $mountPoint /bin/chmod 760 /home/maintain/aports/main/linux-lts 2>/dev/null || log "UNEXPECTED: Could not enable /home/maintain/aports/main/linux-lts directory"

    log "INFO: Synchronizing github repo"
    if [ -f "$mountPoint/home/maintain/aports/.git/index.lock" ]; then chroot $mountPoint /bin/rm /home/maintain/aports/.git/index.lock 2>/dev/null || log "INFO: Unable to remove git lock"; fi
    if [ -d "$mountPoint/home/maintain/aports/main/linux-lts/src" ]; then chroot $mountPoint /bin/rm -R /home/maintain/aports/main/linux-lts/src 2>/dev/null || log "INFO: Unable to remove old kenrel source files"; log "INFO: Finished removing old src directory in aports/main/linux-lts"; fi
    if [ -d "$mountPoint/home/maintain/aports/main/linux-lts/pkg" ]; then chroot $mountPoint /bin/rm -R /home/maintain/aports/main/linux-lts/pkg 2>/dev/null || log "INFO: Unable to remove old kenrel built files"; log "INFO: Finished removing old pkg directory in aports/main/linux-lts"; fi
    chroot $mountPoint /usr/bin/git config --global --add safe.directory /home/maintain/aports || log "UNEXPECTED: Could not guanratee that git thinks /home/maintain/aports is safe directory"
    chroot $mountPoint /usr/bin/git -C /home/maintain/aports reset --hard "$gitPackageCommitHash" || log "UNEXPECTED: Could not set branch to expected kernel version $kernelVersion"
    chroot $mountPoint /bin/chown "$buildUsername:root" -R /home/maintain 2>/dev/null || log "UNEXPECTED: Could not ensure home directory of $buildUsername is owner"
    chroot $mountPoint /bin/chmod +x /home/maintain/aports/main/linux-lts/APKBUILD 2>/dev/null || log "CRITICAL: Could not enable execution to APKBUILD"
    local archType="$(uname -m)"

    log "INFO: Enabling Doas configuration for $buildUsername to execute some commands with doas"
    chroot $mountPoint /bin/echo "permit nopass :wheel as $buildUsername cmd /usr/bin/abuild-keygen args -a -i -n" > $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuilld-keygen permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass :wheel cmd mkdir" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide mkdir permissions to members apart of wheel group"
    chroot $mountPoint /bin/echo "permit nopass :wheel cmd cp" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide cp permissions to members apart of wheel group"
    chroot $mountPoint /bin/echo "permit nopass :wheel as $buildUsername cmd /usr/bin/abuild args -C /home/maintain/aports/main/linux-lts checksum" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuild checksum permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass :wheel as $buildUsername cmd /usr/bin/abuild args -C /home/maintain/aports/main/linux-lts -crK" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuild build permissions to be run as $buildUsername"
    chroot $mountPoint /bin/chmod 0400 /etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/doas.d/kernelBuild.conf file permissions"


    if [ ! -f "$mountPoint/home/maintain/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" ] || [ ! -f "$mountPoint/home/maintain/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" ]; then
        log "INFO: Obtaining kernel patches based on linux hardening alpine guide"
        chroot $mountPoint /usr/bin/wget -O "/home/maintain/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" "$hardeningPatchUrl.patch" || log "UNEXPECTED: Could not download patch into kernel"
        chroot $mountPoint /usr/bin/wget -O "/home/maintain/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" "$hardeningPatchUrl.patch.sig" || log "UNEXPECTED: Couldd not download patch signature key into kernel"
        chroot $mountPoint /bin/chown "$buildUsername:root" "/home/maintain/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" 2>/dev/null || log "UNEXPECTED: Could not ensure kernel patch file is owned by $buildUsername"
        chroot $mountPoint /bin/chown "$buildUsername:root" "/home/maintain/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" 2>/dev/null || log "UNEXPECTED: Could not ensure kernel patch signature file is owned by $buildUsername"
    fi

    if [ -z "$(chroot $mountPoint /bin/ls /etc/apk/keys | grep -v alpine-devel)" ]; then
        log "INFO: Generating signing key"
        chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild-keygen -a -i -n || log "UNEXPECTED: Could not generate keys for $buildUsername"
        chroot $mountPoint /bin/chmod a+r /etc/apk/keys/* 2>/dev/null || log "UNEXPECTED: Could not enable keys stored in /etc/apk/keys to be read by $buildUsername"
    fi

    log "INFO: Configurating APKBUILD file to include only relevant files"
    chroot $mountPoint /bin/sed -i ':a;N;$!ba;s/lts.aarch64.config\n\tlts.armv7.config\n\tlts.loongarch64.config\n\tlts.ppc64le.config\n\tlts.riscv64.config\n\tlts.s390x.config\n\tlts.x86.config\n\tlts.x86_64.config/REPLACEME.patch1\n\tREPLACEME.patch2\n\tlts.REPLACEME.config/g' /home/maintain/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not prepare APKBUILD's source first configuration"
    chroot $mountPoint /bin/sed -i ':a;N;$!ba;s/virt.aarch64.config\n\tvirt.armv7.config\n\tvirt.ppc64le.config\n\tvirt.x86.config\n\tvirt.x86_64.config/virt.REPLACEME.config/g' /home/maintain/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not prepare APKBUILD's source second configuration"
    chroot $mountPoint /bin/sed -i "s/lts.REPLACEME.config/lts.$archType.config/1" /home/maintain/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not finish APKBUILD's source second configuration"
    chroot $mountPoint /bin/sed -i "s/virt.REPLACEME.config/virt.$archType.config/1" /home/maintain/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not finish APKBUILD's source third configuration"
    chroot $mountPoint /bin/sed -i "s/REPLACEME.patch1/0098-linux-hardened-v$kernelVersion.patch/1" /home/maintain/aports/main/linux-lts/APKBUILD || log "UNEXPECTED: Could not finish APKBUILD's source first configuration" || log "UNEXPECTED: Could not finish APKBUILD's source optinal hardening patch file"
    chroot $mountPoint /bin/sed -i "s/REPLACEME.patch2/0099-linux-hardened-v$kernelVersion.patch.sig/1" /home/maintain/aports/main/linux-lts/APKBUILD || log "UNEXPECTED: Could not finish APKBUILD's source first configuration" || log "UNEXPECTED: Could not finish APKBUILD's source optional hardening patch signature file"

    # Ensure we have the right kernel configuration file
    if [ "$(chroot $mountPoint /usr/bin/md5sum /home/maintain/linuxConfig.config)" != "$(chroot $mountPoint /usr/bin/md5sum /home/maintain/aports/main/linux-lts/lts.$archType.config)" ]; then
        # Move the new file
        log "INFO: Moving file linuxConfig.config into lts.$archType.config with the following md5sum: $(chroot $mountPoint /usr/bin/md5sum /home/maintain/linuxConfig.config) = $(chroot $mountPoint /usr/bin/md5sum /home/maintain/aports/main/linux-lts/lts.$archType.config)"
        chroot $mountPoint /bin/cp /home/maintain/linuxConfig.config "/home/maintain/aports/main/linux-lts/lts.$archType.config" 2>/dev/null || log "CRITICAL: Wrong kernel configuration file is set!"
        chroot $mountPoint /bin/chown "$buildUsername:root" "/home/maintain/aports/main/linux-lts/lts.$archType.config" 2>/dev/null || log "UNEXPECTED: Could not ensure kernel config file is owned by $buildUsername"
    fi

    log "INFO: Performing checksum on everything"
    chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild -C /home/maintain/aports/main/linux-lts checksum || log "UNEXPECTED: Could not compile checksum of everything modified so far"

    if [ -z "$(chroot $mountPoint /sbin/apk list | grep linux-lts | grep $kernelVersion | grep installed)" ]; then
        if [ ! -d "$mountPoint/home/maintain/packages/main/$archType" ]; then
    	    if [ -z "$(chroot $mountPoint /bin/ls /home/maintain/packages/main/"$archType" | grep -v linux-lts)" ]; then
    		log "INFO: Compiling kernel at; $(date)"
    		time -o /tmp/compileTime chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild -C /home/maintain/aports/main/linux-lts -crK 2>&1 | tee /tmp/kernelLog || log "CRITICAL: Could not finish compiling kernel"
    		
                log "INFO: The kernel took to compile: $(cat /tmp/compileTime)"
    		rm /tmp/compileTime || log "UNEXPECTED: Could not remove temporary file to keep track the length of time it took the kernel to compile"
    	    fi
        fi
 	log "INFO: Installing kernel at; $(date)"
    	chroot $mountPoint /sbin/apk del linux-lts || log "CRITICAL: Could not remove existing kernel for new installation"
    	chroot $mountPoint /sbin/apk update --repository "/home/maintain/packages/main/" || log "CRITICAL: Could not update repository for new installation"
    	chroot $mountPoint /sbin/apk add --repository "/home/maintain/packages/main/" linux-lts="$kernelVersion-r0" || log "CRITICAL: Could not install kernel $kernelVersion to local system"
    fi

    log "INFO: Cleaning up kernel files and modifications"
    chroot $mountPoint /bin/rm /etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Permission doas file has not been deleted to enforce principle of least priviledge"
    chroot $mountPoint /sbin/apk del alpine-sdk kernel-hardening-checker@additional 2>/dev/null || log "UNEXPECTED: Could not remove development build packages"

    log "INFO: Modifying grub with new kernel parameters"
    chroot $mountPoint /bin/chmod u+w /etc/default/grub || log "UNEXPECTED: Could not set to 600 permission on /etc/default/grub"
    chroot $mountPoint /bin/sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="modules=sd=mod,usb-storage,ext4 quiet rootfstype=ext4 hardened_usercopy=1 init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on page_alloc.shuffle=1 slab_nomerge pti=on nosmt hash_pointers=always slub_debug=ZF slub_debug=P page_poison=1 iommu.passthrough=0 iommu.strict=1 mitigations=auto,nosmt kfence.sample_interval=100"/g' /etc/default/grub || log "UNEXPECTED: Could not implement kernel parameters that enforce security"
    chroot $mountPoint /bin/chmod u-w /etc/default/grub || log "UNEXPECTED: Could not set to 400 permission on /etc/default/grub"
    chroot $mountPoint /usr/sbin/update-grub || log "UNEXPECTED: Could not implement changes for grub"

    log "INFO: Kernel modifications have been succesfully configured!"
}

# !!!
# Is removing dead usernames good practice?

# Check inittab to implace restrict shell
# Check /etc/busybox-paths.d/busybox
# https://wiki.alpinelinux.org/wiki/How_to_get_regular_stuff_working
# Found executables via: find /usr/bin ! -perm 777 -and ! -perm 0500
# Resources:
# Creating restricted shells if missing: https://unix.stackexchange.com/questions/605646/how-do-you-install-rbash-in-centos-7
# Configurating rc.services: https://github.com/OpenRC/openrc/blob/master/service-script-guide.md
# Introduction to linux capabilities: https://blog.container-solutions.com/linux-capabilities-in-practice
# Changing ssh private key: https://serverfault.com/questions/50775/how-do-i-change-my-private-key-passphrase
# Disable root account: https://www.linuxfordevices.com/tutorials/linux/enable-disable-root-login-in-linux
# Not resources: 
# SSH server: ChrootDirectory
# Password quality?,
# Saying yes to pam: https://www.baeldung.com/linux/usepam-yes-ssh-effects
# Forcing a limited set of commands on specific ssh users: https://shaner.life/the-little-known-ssh-forcecommand/
# Proper /etc/limits.conf
# set ulimit in sysctl via fs.file and alike (find if this is related to exclusively PAM or not), 
# Interesting ideas; https://www.kicksecure.com/wiki/Dev/Strong_Linux_User_Account_Isolation#libpam-tmpdir, https://www.kicksecure.com/wiki/Dev/Strong_Linux_User_Account_Isolation#sudo_password_sniffing, https://www.kicksecure.com/wiki/Dev/Strong_Linux_User_Account_Isolation#su_restrictions, https://0xffsec.com/handbook/shells/restricted-shells/, https://security.stackexchange.com/questions/187901/what-can-an-attacker-do-in-this-scenario-unwritable-bashrc-profile-etc, https://krython.com/post/configuring-system-log-files-alpine-linux, https://dev.to/sebos/using-chroot-to-restrict-linux-applications-for-enhanced-security-33b3, https://thelinuxcode.com/setup-linux-chroot-jails/
# SSHD resources that are worth keeping:
# SSH audit tool: https://github.com/jtesta/ssh-audit
# All cryptogrpahic functions supported by sshd: https://superuser.com/questions/1763269/how-to-disable-rsa-and-ecdsa-keys-in-openssh-server-on-fedora-linux
# Hardening guide: https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
# Simplified hardening guide: https://www.sshaudit.com/hardening_guides.html
# https://linux.die.net/man/7/capabilities
# https://man.freebsd.org/cgi/man.cgi?query=doas.conf&sektion=5&format=html
# Problem: https://www.spinics.net/lists/openssh-unix-dev/msg06335.html
# make setcap use -n option to limit only sshd user id
# Capsh seems interesting, but need more practice or another way to prevent capabilities from clearing (libraries: libcap): current command: capsh --keep=1 --caps="cap_net_bind_service,cap_setuid,cap_setgid,cap_setpcap=pie" --ihn="cap_net_bind_service,cap_setuid,cap_setgid" --addamb="cap_net_bind_service,cap_setuid,cap_setgid,cap_setpcap" --secbits=240 --shell=/bin/sh --user=sshReceive -- -c /usr/sbin/sshd
# Prevent ufw from logging into dmesg via rsyslog
# Awall? Shorewall?
# Resources worth keeping: 
# https://codelucky.com/ufw-advanced-linux-firewall/
# https://wiki.alpinelinux.org/wiki/Nftables
# https://wiki.alpinelinux.org/wiki/Category:Firewall
# https://dev.to/caffinecoder54/creating-a-lightweight-linux-firewall-with-ufw-and-fail2ban-35po
# https://www.linode.com/community/questions/11143/top-tip-firewalld-and-ipset-country-blacklist
# https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers & https://home.regit.org/netfilter-en/nftables-quick-howto/ (minimum packet size is 28 - 36 bytes)
# Other packages and commands of interest: agetty (agetty), lsof & lsfd (util-linux-misc)
# SSH test command: doas -u obtain /usr/sbin/sshd -f /home/.keys/obtain/obtain-sshd.conf -E /var/log/sshdExtract.log
configLocalInstallation() {
    log "INFO: Installing packages"
    chroot $mountPoint /sbin/apk add coreutils findutils dmesg logger setpriv doas doas-doc libcap-getcap libcap-setcap shadow@additional loksh@additional at@additional acpid ufw@additional nftables fail2ban || log "UNEXPECTED: Could not install service packages"

    #log "Removing unncessary default packages"
    # Why is alpine-conf hooked to alpine-base..., and why does update-kernel and update-conf exist?
    #chroot $mountPoint /sbin/apk del -f alpine-conf || log "UNEXPECTED: Could not remove alpine-conf package"

    log "INFO: Stopping temporarely certain services"
    if [ -f "$mountPoint/var/run/acpid.pid" ]; then chroot $mountPoint /sbin/rc-service acpid stop || log "UNEXPECTED: Could not stop acpid daemon to remove old pid file"; fi
    if [ -f "$mountPoint/var/run/chronyd.pid" ]; then chroot $mountPoint /sbin/rc-service fail2ban restart && chroot $mountPoint /sbin/rc-service fail2ban stop || log "UNEXPECTED: Could not ensure all fail2ban files were generated"; fi

    log "INFO: Creating groups for certain executables, data files, and directorys"
    local expectedGroups="busybox coreutils lvm suid diskUtil cmdUtil doas apk rshell logread iptables logrotate chrony python sshpub sshexec sshsftp acpi readGroup $collectorUsername $updateUsername $firewallUsername $fail2banUsername $powerUsername $loggerUsername $backgroundUsername"
    for newGroup in $expectedGroups; do
        if [ -z "$(chroot $mountPoint /bin/grep $newGroup: /etc/group)" ]; then chroot $mountPoint /usr/sbin/addgroup -S $newGroup 2>/dev/null || log "CRITICAL: Could not create a $newGroup group"; fi
    done

    log "INFO: Creating missing system users to run services with limited priviledge"
		# Creating system user to execute acpid events
    if [ -z "$(chroot $mountPoint /bin/grep $powerUsername /etc/passwd)" ]; then chroot $mountPoint /usr/sbin/adduser -H -h /dev/null -S -D -G $powerUsername -s /sbin/nologin $powerUsername 2>/dev/null || log "CRITICAL: Could not create an account for running acpid daemon"; fi
    chroot $mountPoint /usr/sbin/addgroup $powerUsername acpi 2>/dev/null || log "UNEXPECTED: Could not add acpi group to $powerUsername user"
    chroot $mountPoint /usr/sbin/addgroup $powerUsername readGroup 2>/dev/null || log "UNEXPECTED: Could not add readGroup group to $powerUsername user"
		# Creating system user to execute UFW
    if [ -z "$(chroot $mountPoint /bin/grep $firewallUsername /etc/passwd)" ]; then chroot $mountPoint /usr/sbin/adduser -H -h /dev/null -S -D -G $firewallUsername -s /sbin/nologin $firewallUsername 2>/dev/null || log "CRITICAL: Could not create an account for running firewall"; fi
    chroot $mountPoint /usr/sbin/addgroup $firewallUsername iptables 2>/dev/null || log "UNEXPECTED: Could not add iptables group to firewall user" # Required since it relies on iptables
    chroot $mountPoint /usr/sbin/addgroup $firewallUsername python 2>/dev/null || log "UNEXPECTED: Could not add python group to firewall user" # Required since it relies on python to execute code
    chroot $mountPoint /usr/sbin/addgroup $firewallUsername busybox 2>/dev/null || log "UNEXPECTED: Could not add busybox group to firewall user" # Required for disabling firewall (their script executes /bin/sh)
		# Creating system user to execute fail2ban
    if [ -z "$(chroot $mountPoint /bin/grep $fail2banUsername /etc/passwd)" ]; then chroot $mountPoint /usr/sbin/adduser -H -h /dev/null -S -D -G $fail2banUsername -s /sbin/nologin $fail2banUsername 2>/dev/null || log "CRITICAL: Could not create an account for running fail2ban"; fi
    chroot $mountPoint /usr/sbin/addgroup $fail2banUsername iptables 2>/dev/null || log "UNEXPECTED: Could not add iptables group to fail2ban user" # Required since it relies on iptables
    chroot $mountPoint /usr/sbin/addgroup $fail2banUsername python 2>/dev/null || log "UNEXPECTED: Could not add python group to fail2ban user" # Required since it relies on python to execute code
    chroot $mountPoint /usr/sbin/addgroup $fail2banUsername logread 2>/dev/null || log "UNEXPECTED: Could not add logread group to fail2ban user" # Required to function reading other service logs
    chroot $mountPoint /usr/sbin/addgroup $fail2banUsername logrotate 2>/dev/null || log "UNEXPECTED: Could not add logrotate group to fail2ban user" # Will ocassional try to rotate its own logs
		# Creating system user to execute syslogd
    if [ -z "$(chroot $mountPoint /bin/grep $loggerUsername /etc/passwd)" ]; then chroot $mountPoint /usr/sbin/adduser -H -h /dev/null -S -D -G $loggerUsername -s /sbin/nologin $loggerUsername 2>/dev/null || log "CRITICAL: Could not create an account for running syslogd"; fi
		# Creating system user to execute crond
    if [ -z "$(chroot $mountPoint /bin/grep $backgroundUsername /etc/passwd)" ]; then chroot $mountPoint /usr/sbin/adduser -H -h /dev/null -S -D -G $backgroundUsername -s /sbin/nologin $backgroundUsername 2>/dev/null || log "CRITICAL: Could not create an account for running crond"; fi
		# Creating system user that can execute apk, and only apk
    if [ -z "$(chroot $mountPoint /bin/grep $updateUsername /etc/passwd)" ]; then chroot $mountPoint /usr/sbin/adduser -H -h /dev/null -S -D -G $updateUsername -s /sbin/nologin $updateUsername 2>/dev/null || log "CRITICAL: Could not create an account for running apk"; fi
    chroot $mountPoint /usr/sbin/addgroup $updateUsername apk 2>/dev/null || log "UNEXPECTED: Could not add apk group to apk updater user"
    chroot $mountPoint /usr/sbin/addgroup $updateUsername doas 2>/dev/null || log "UNEXPECTED: Could not add doas group to apk updater user"
		# Creating privileged system user to retrieve certain data for $backupUsername to backup
    if [ -z "$(chroot $mountPoint /bin/grep $collectorUsername /etc/passwd)" ]; then chroot $mountPoint /usr/sbin/adduser -H -h /dev/null -S -D -G $collectorUsername -s /sbin/nologin $collectorUsername 2>/dev/null || log "CRITICAL: Could not create an account for running fail2ban"; fi
    chroot $mountPoint /usr/sbin/addgroup $collectorUsername coreutils 2>/dev/null || log "UNEXPECTED: Could not add coreutils group to local archieve user"
    chroot $mountPoint /usr/sbin/addgroup $collectorUsername busybox 2>/dev/null || log "UNEXPECTED: Could not add busybox group to local archieve user"
    chroot $mountPoint /usr/sbin/addgroup $collectorUsername diskUtil 2>/dev/null || log "UNEXPECTED: Could not add diskUtil group to local archieve user"
    chroot $mountPoint /usr/sbin/addgroup $collectorUsername lvm 2>/dev/null || log "UNEXPECTED: Could not add lvm group to local archieve user"
    chroot $mountPoint /usr/sbin/addgroup $collectorUsername doas 2>/dev/null || log "UNEXPECTED: Could not add doas group to local archieve user"
		# Creating privileged system user meant to detect any hacking attempts, and to log it
    if [ -z "$(chroot $mountPoint /bin/grep $monitorUsername /etc/passwd)" ]; then
        chroot $mountPoint /bin/mkdir -p /home/"$monitorUsername" 2>/dev/null || log "UNEXPECTED: Could not make a new directory for $monitorUsername"
        chroot $mountPoint /usr/sbin/adduser -h /home/"$monitorUsername" -s /bin/rksh -D $monitorUsername 2>/dev/null || log "CRITICAL: Could not create an account for monitoring the system"
    fi
    chroot $mountPoint /usr/sbin/addgroup $monitorUsername rshell 2>/dev/null || log "UNEXPECTED: Could not add rshell group to remote reading logging user"
    chroot $mountPoint /usr/sbin/addgroup $monitorUsername logread 2>/dev/null || log "UNEXPECTED: Could not add logread group to remote reading logging user"
    chroot $mountPoint /usr/sbin/addgroup $monitorUsername sshpub 2>/dev/null || log "UNEXPECTED: Could not add sshpub group to remote reading logging user"
    chroot $mountPoint /usr/sbin/addgroup $monitorUsername sshexec 2>/dev/null || log "UNEXPECTED: Could not add sshexec group to remote reading logging user"
    chroot $mountPoint /usr/sbin/addgroup $monitorUsername sshsftp 2>/dev/null || log "UNEXPECTED: Could not add sshsftp group to remote reading logging user"

    log "INFO: Creating missing users to interact remotely with system"
		# Creating user to display system status
    if [ -z "$(chroot $mountPoint /bin/grep $previewUsername /etc/passwd)" ]; then
        chroot $mountPoint /bin/mkdir -p /home/"$previewUsername" 2>/dev/null || log "UNEXPECTED: Could not make a new directory for $previewUsername"
        chroot $mountPoint /usr/sbin/adduser -h /home/"$previewUsername" -s /bin/rksh -D $previewUsername 2>/dev/null || log "CRITICAL: Could not create an account for receiving status of system"
    fi
    chroot $mountPoint /usr/sbin/addgroup $previewUsername rshell 2>/dev/null || log "UNEXPECTED: Could not add rshell group to output user"
    chroot $mountPoint /usr/sbin/addgroup $previewUsername sshpub 2>/dev/null || log "UNEXPECTED: Could not add sshpub group to output user"
    chroot $mountPoint /usr/sbin/addgroup $previewUsername sshexec 2>/dev/null || log "UNEXPECTED: Could not add sshexec group to output user"
		# Creating user to execute a limited set of commands
    if [ -z "$(chroot $mountPoint /bin/grep $serverCommandUsername /etc/passwd)" ]; then
        chroot $mountPoint /bin/mkdir -p /home/"$serverCommandUsername" 2>/dev/null || log "UNEXPECTED: Could not make a new directory for $serverCommandUsername"
        chroot $mountPoint /usr/sbin/adduser -h /home/"$serverCommandUsername" -s /bin/rksh -D $serverCommandUsername 2>/dev/null || log "CRITICAL: Could not create an account for issuing commands to server"
    fi
    chroot $mountPoint /usr/sbin/addgroup $serverCommandUsername rshell 2>/dev/null || log "UNEXPECTED: Could not add rshell group to command user"
    chroot $mountPoint /usr/sbin/addgroup $serverCommandUsername cmdUtil 2>/dev/null || log "UNEXPECTED: Could not add cmdUtil group to command user"
    chroot $mountPoint /usr/sbin/addgroup $serverCommandUsername sshpub 2>/dev/null || log "UNEXPECTED: Could not add sshpub group to command user"
    chroot $mountPoint /usr/sbin/addgroup $serverCommandUsername sshexec 2>/dev/null || log "UNEXPECTED: Could not add sshexec group to command user"
		# Creating sftp user to retrieve backup data 
    if [ -z "$(chroot $mountPoint /bin/grep $backupUsername /etc/passwd)" ]; then
        chroot $mountPoint /bin/mkdir -p /home/"$backupUsername" 2>/dev/null || log "UNEXPECTED: Could not make a new directory for $backupUsername"
        chroot $mountPoint /usr/sbin/adduser -h /home/"$backupUsername" -s /bin/rksh -D $backupUsername 2>/dev/null || log "CRITICAL: Could not create an account for backing up important data"
    fi
    chroot $mountPoint /usr/sbin/addgroup $backupUsername rshell 2>/dev/null || log "UNEXPECTED: Could not add rshell group to backup maintainer user"
    chroot $mountPoint /usr/sbin/addgroup $backupUsername sshpub 2>/dev/null || log "UNEXPECTED: Could not add sshpub group to backup maintainer user"
    chroot $mountPoint /usr/sbin/addgroup $backupUsername sshexec 2>/dev/null || log "UNEXPECTED: Could not add sshexec group to backup maintainer user"
    chroot $mountPoint /usr/sbin/addgroup $backupUsername sshsftp 2>/dev/null || log "UNEXPECTED: Could not add sshsftp group to backup maintainer user"
		# Creating temporary user to extract secrets from
    if [ -z "$(chroot $mountPoint /bin/grep $extractUsername /etc/passwd)" ]; then
        chroot $mountPoint /bin/mkdir -p /home/"$extractUsername" 2>/dev/null || log "UNEXPECTED: Could not make a new directory for $extractUsername"
        chroot $mountPoint /usr/sbin/adduser -h /home/"$extractUsername" -s /bin/rksh -D $extractUsername 2>/dev/null || log "CRITICAL: Could not create an account for extracting sensitive data"
    fi
    chroot $mountPoint /usr/sbin/addgroup $extractUsername rshell 2>/dev/null || log "UNEXPECTED: Could not add rshell group to extracing sensitive data user"
    chroot $mountPoint /usr/sbin/addgroup $extractUsername sshpub 2>/dev/null || log "UNEXPECTED: Could not add sshpub group to extracing sensitive data user"
    chroot $mountPoint /usr/sbin/addgroup $extractUsername sshexec 2>/dev/null || log "UNEXPECTED: Could not add sshexec group to extracing sensitive data user"
    chroot $mountPoint /usr/sbin/addgroup $extractUsername sshsftp 2>/dev/null || log "UNEXPECTED: Could not add sshsftp group to extracing sensitive data user"

    log "INFO: Locking root account, and making certain restricted accounts have any password as invalid"
    chroot $mountPoint /usr/bin/passwd -dl root 2>/dev/null || log "UNEXPECTED: Could not lock root user login"
    chroot $mountPoint /usr/sbin/usermod -p '*' $extractUsername 2>/dev/null || log "UNEXPECTED: Could not disable user login for $extractUsername"
    chroot $mountPoint /usr/sbin/usermod -p '*' $monitorUsername 2>/dev/null || log "UNEXPECTED: Could not disable user login for $monitorUsername"
    chroot $mountPoint /usr/sbin/usermod -p '*' $previewUsername 2>/dev/null || log "UNEXPECTED: Could not disable user login for $previewUsername"
    chroot $mountPoint /usr/sbin/usermod -p '*' $serverCommandUsername 2>/dev/null || log "UNEXPECTED: Could not disable user login for $serverCommandUsername"
    chroot $mountPoint /usr/sbin/usermod -p '*' $backupUsername 2>/dev/null || log "UNEXPECTED: Could not disable user login for $backupUsername"
    chroot $mountPoint /usr/bin/chsh -s /sbin/nologin root 2>/dev/null || log "UNEXPECTED: Could not disable login shell for root account"

    log "INFO: Permitting root to cause changes to certain files"
    chroot $mountPoint /bin/chmod u+w /etc/issue 2>/dev/null || log "UNEXPECTED: Could not guarantee that /etc/issue be modified by root"
    chroot $mountPoint /bin/chmod u+w /etc/motd 2>/dev/null || log "UNEXPECTED: Could not guarantee that /etc/motd be modified by root"
    chroot $mountPoint /bin/chmod u+w /etc/inittab 2>/dev/null || log "UNEXPECTED: Could not guarantee that /etc/inittab be modified by root"
    chroot $mountPoint /bin/chmod u+w /etc/securetty 2>/dev/null || log "UNEXPECTED: Could not guarantee that /etc/securetty be modified by root"
    chroot $mountPoint /bin/chmod u+w /etc/profile 2>/dev/null || log "UNEXPECTED: Could not guarantee that /etc/profile be modified by root"
    chroot $mountPoint /bin/chmod u+w /etc/mdev.conf 2>/dev/null || log "UNEXPECTED: Could not guarantee that /etc/mdev.conf be modified by root"
    chroot $mountPoint /bin/chmod u+w /etc/init.d/acpid 2>/dev/null || log "UNEXPECTED: Could not enable writing permission on /etc/init.d/acpid"
    if [ -f "$mountPoint/etc/init.d/sshdStatus" ]; then chroot $mountPoint /bin/chmod u+w /etc/init.d/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not guanratee sshd init for $previewUsername is writable"; fi
    if [ -f "$mountPoint/etc/init.d/sshdBackup" ]; then chroot $mountPoint /bin/chmod u+w /etc/init.d/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not guanratee sshd init for $backupUsername is writable"; fi
    if [ -f "$mountPoint/etc/init.d/sshdCommand" ]; then chroot $mountPoint /bin/chmod u+w /etc/init.d/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not guanratee sshd init for $serverCommandUsername is writable"; fi
    if [ -f "$mountPoint/etc/init.d/sshdLog" ]; then chroot $mountPoint /bin/chmod u+w /etc/init.d/sshdLog 2>/dev/null || log "UNEXPECTED: Could not guanratee sshd init for $monitorUsername is writable"; fi
    chroot $mountPoint /bin/chmod u+w /etc/init.d/chronyd 2>/dev/null || log "UNEXPECTED: Could not enable writing permission on /etc/init.d/chronyd"
    chroot $mountPoint /bin/chmod u+w /etc/init.d/fail2ban 2>/dev/null || log "UNEXPECTED: Could not enable writing permission on /etc/init.d/fail2ban"
    chroot $mountPoint /bin/chmod u+w /etc/ssh/moduli 2>/dev/null || log "UNEXPECTED: Could not change moduli's permission to writable"
    if [ -f "$mountPoint/etc/doas.d/daemon.conf" ]; then chroot $mountPoint /bin/chmod u+w /etc/doas.d/daemon.conf 2>/dev/null || log "UNEXPECTED: Could not make /etc/doas.d/daemon.conf writable"; fi
    chroot $mountPoint /bin/chmod u+w /etc/ssh/ssh_config 2>/dev/null || log "UNEXPECTED: Could not change /etc/ssh/ssh_config permissions to writable"
    chroot $mountPoint /bin/chmod u+w /etc/default/ufw 2>/dev/null || log "UNEXPECTED: Could not change /etc/default/ufw permissions to writable"
    if [ -f "$mountPoint/etc/fail2ban/jail.local" ]; then chroot $mountPoint /bin/chmod u+w /etc/fail2ban/jail.local 2>/dev/null || log "UNEXPECTED: Could not guanratee local jail permissions are writable"; fi
    chroot $mountPoint /bin/chmod u+w /etc/fail2ban/fail2ban.conf 2>/dev/null || log "UNEXPECTED: Could not change fail2ban configuration file permissions to writable"

# !!! PAM
# Reading: 
# https://docs.oracle.com/cd/E19253-01/816-4557/pam-15/index.html
# https://linux.die.net/man/8/pam_shells
# https://linux.die.net/man/8/pam_permit
# https://linux.die.net/man/8/pam_rootok
# https://linux.die.net/man/5/pam.d
# auth (identity), account (access permission), password (credentials), session (user session)
# 
# requisite: fail, exit, result fail
# required; fail, continue, result fail
# optional; pass/fail ignored, but can execute some things
# include; add configuration from another file
# sufficient; suceed, enough, result pass (nothing else is called)
# 
# action: pick from PAM modules, read what each pam module does for arguments
# 
# 
# Check for pam: ldd /bin/login,
# no output means no pam
    log "INFO: Configurating PAM"

# !!! Chroot jail
# Resource: https://github.com/remaskm/Chroot-Jail-Escape-Write-up
# Binding: https://serverfault.com/questions/440426/sftp-file-symlinks-in-a-jailed-chrooted-directory
# File binding inspiration: https://unix.stackexchange.com/questions/4897/providing-bin-and-lib-inside-a-chroot-jail
# Chroot weakness: https://y198nt.github.io/posts/chroot_jailbreak/
# Best practices: https://thelinuxcode.com/setup-linux-chroot-jails/
    log "INFO: Creating chroot jails"

# !!! RKSH CONFIG FILE
# Resource: https://www.ibm.com/docs/en/aix/7.2.0?topic=shell-restricted-korn
# Fix sftp issue form using rksh
    log "INFO: Rksh configuration for each user"

    # Issue banner & motd. Inspiration: https://linux-audit.com/the-real-purpose-of-login-banners-on-linux/
    log "INFO: Changing /etc/issue and /etc/motd"
    chroot $mountPoint /bin/echo "$bannerIssue" > $mountPoint/etc/issue 2>/dev/null || log "UNEXPECTED: Could not change warning message for unauthenticated users"
    chroot $mountPoint /bin/echo "$bannerMotd" > $mountPoint/etc/motd 2>/dev/null || log "UNEXPECTED: Could not change greeting message for authenticated users"

    # Disable TTY interfaces from inittab to limit entry points of root access
    log "INFO: Disabling root login via serial consoles"
    chroot $mountPoint /bin/sed -i 's/^tty/#tty/g' /etc/inittab 2>/dev/null || log "UNEXPECTED: Could not stop the creation of getty instances"
    chroot $mountPoint /bin/sed -i 's/^\:\:ctrlaltdel/#\:\:ctrlaltdel/g' /etc/inittab 2>/dev/null || log "UNEXPECTED: Could not remove keyboard sequence reboot command"
    chroot $mountPoint /bin/echo > $mountPoint/etc/securetty 2>/dev/null || log "UNEXPECTED: Could not modify which interfaces a root user can login from"

    # Modifying /etc/profile and mdev.conf
    log "INFO: Increasing umask value in /etc/profile and mdev.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}umask\(.*\)/umask $umask/g" /etc/profile || log "UNEXPECTED: Could not change umask from default 022"
    chroot $mountPoint /bin/sed -i 's/^random\(.*\)/random  root:root 0664/g' /etc/mdev.conf 2>/dev/null || log "UNEXPECTED: Could not ensure linux random device is read only by anyone else"
    chroot $mountPoint /bin/sed -i 's/^net\/tun\(.*\)/net\/tun[0-9]*   root:netdev 0660/g' /etc/mdev.conf 2>/dev/null || log "UNEXPECTED: Could not ensure linux random device is not accessible for anyone else"
    chroot $mountPoint /bin/sed -i 's/^net\/tap\(.*\)/net\/tap[0-9]*   root:netdev 0660/g' /etc/mdev.conf 2>/dev/null || log "UNEXPECTED: Could not ensure linux random device is not accessible for anyone else"

    log "INFO: Creating sshd /etc/init.d/ init services for each permitted user"
    chroot $mountPoint /bin/cp /etc/init.d/sshd /etc/init.d/sshdStatus || log "UNEXPECTED: Could not create special init file for $previewUsername"
    chroot $mountPoint /bin/cp /etc/init.d/sshd /etc/init.d/sshdBackup || log "UNEXPECTED: Could not create special init file for $backupUsername"
    chroot $mountPoint /bin/cp /etc/init.d/sshd /etc/init.d/sshdCommand || log "UNEXPECTED: Could not create special init file for $serverCommandUsername"
    chroot $mountPoint /bin/cp /etc/init.d/sshd /etc/init.d/sshdLog || log "UNEXPECTED: Could not create special init file for $monitorUsername"
    chroot $mountPoint /bin/cp /etc/init.d/sshd /etc/init.d/sshdExtract || log "UNEXPECTED: Could not create special init file for $extractUsername"

    log "INFO: Modifying /etc/init.d services"
		# Commands
    chroot $mountPoint /bin/sed -i "s/^command=\"\(.*\)/command=\"\/usr\/bin\/doas\"/g" /etc/init.d/acpid 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/acpid to change starting command to be doas"
    chroot $mountPoint /bin/sed -i "s/^command=\"\(.*\)/command=\"\/usr\/bin\/doas\"/g" /etc/init.d/chronyd 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/chronyd to change starting command to be doas"
    chroot $mountPoint /bin/sed -i "s/^command=\"\(.*\)/command=\"\/usr\/bin\/doas\"/g" /etc/init.d/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdStatus to change starting command to be doas"
    chroot $mountPoint /bin/sed -i "s/^command=\"\(.*\)/command=\"\/usr\/bin\/doas\"/g" /etc/init.d/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdBackup to change starting command to be doas"
    chroot $mountPoint /bin/sed -i "s/^command=\"\(.*\)/command=\"\/usr\/bin\/doas\"/g" /etc/init.d/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdCommand to change starting command to be doas"
    chroot $mountPoint /bin/sed -i "s/^command=\"\(.*\)/command=\"\/usr\/bin\/doas\"/g" /etc/init.d/sshdLog 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdLog to change starting command to be doas"
    chroot $mountPoint /bin/sed -i "s/^command=\"\(.*\)/command=\"\/usr\/bin\/doas\"/g" /etc/init.d/sshdExtract 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdExtract to change starting command to be doas"
    chroot $mountPoint /bin/sed -i "s/^FAIL2BAN=\"\(.*\)/FAIL2BAN=\"\/usr\/bin\/doas -u $fail2banUsername \/usr\/bin\/fail2ban-client \$\{FAIL2BAN_OPTIONS\}\"/g" /etc/init.d/fail2ban 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/fail2ban to change variable that starts and turns off fail2ban"
		# Command args
    chroot $mountPoint /bin/sed -i "s/^command_args=\"\(.*\)/command_args=\"-u $powerUsername \/sbin\/acpid -l --foreground --pidfile \/var\/run\/acpid\/acpid.pid --lockfile \/var\/run\/acpid\/acpid.lock --socketfile \/var\/run\/acpid\/acpid.socket --socketgroup acpi --socketmode 660\"/g" /etc/init.d/acpid 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/acpid to change command_args for acpid service"
    chroot $mountPoint /bin/sed -i "s/^command_args=\"\(.*\)/command_args=\"-u chrony \/usr\/sbin\/chronyd -u chrony -U -F 1 -f \/etc\/chrony\/chrony.conf -L 0 -l \/var\/log\/chronyd.log\"/g" /etc/init.d/chronyd 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/chronyd to change command_args for chronyd service"
    chroot $mountPoint /bin/sed -i "s/^command_args=\"\(.*\)/command_args=\"-u $previewUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$previewUsername\/$previewUsername-sshd.conf -E \/var\/log\/sshdStatus.log\"/g" /etc/init.d/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdStatus to change command_args for sshd $previewUsername user service"
    chroot $mountPoint /bin/sed -i "s/^command_args=\"\(.*\)/command_args=\"-u $backupUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$backupUsername\/$backupUsername-sshd.conf -E \/var\/log\/sshdBackup.log\"/g" /etc/init.d/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdBackup to change command_args for sshd $backupUsername user service"
    chroot $mountPoint /bin/sed -i "s/^command_args=\"\(.*\)/command_args=\"-u $serverCommandUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$serverCommandUsername\/$serverCommandUsername-sshd.conf -E \/var\/log\/sshdCommand.log\"/g" /etc/init.d/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdCommand to change command_args for sshd $serverCommandUsername user service"
    chroot $mountPoint /bin/sed -i "s/^command_args=\"\(.*\)/command_args=\"-u $monitorUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$monitorUsername\/$monitorUsername-sshd.conf -E \/var\/log\/sshdLog.log\"/g" /etc/init.d/sshdLog 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdLog to change command_args for sshd $monitorUsername user service"
    chroot $mountPoint /bin/sed -i "s/^command_args=\"\(.*\)/command_args=\"-u $extractUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$extractUsername\/$extractUsername-sshd.conf -E \/var\/log\/sshdExtract.log\"/g" /etc/init.d/sshdExtract 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdExtract to change command_args for sshd $monitorUsername user service"
		# Pid file
    chroot $mountPoint /bin/sed -i "s/^pidfile=\"\(.*\)/pidfile=\"\/run\/acpid\/\$RC_SVCNAME.pid\"/g" /etc/init.d/acpid 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/acpid to change pidfile for acpid service"
    chroot $mountPoint /bin/sed -i "s/^pidfile=\"\(.*\)/pidfile=\"\$\{SSHD_PIDFILE:-\"\/run\/sshdStatus\/\$RC_SVCNAME.pid\"\}\"/g" /etc/init.d/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdStatus to change pid location for $previewUsername"
    chroot $mountPoint /bin/sed -i "s/^pidfile=\"\(.*\)/pidfile=\"\$\{SSHD_PIDFILE:-\"\/run\/sshdBackup\/\$RC_SVCNAME.pid\"\}\"/g" /etc/init.d/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdBackup to change pid location for $backupUsername"
    chroot $mountPoint /bin/sed -i "s/^pidfile=\"\(.*\)/pidfile=\"\$\{SSHD_PIDFILE:-\"\/run\/sshdCommand\/\$RC_SVCNAME.pid\"\}\"/g" /etc/init.d/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdCommand to change pid location for $serverCommandUsername"
    chroot $mountPoint /bin/sed -i "s/^pidfile=\"\(.*\)/pidfile=\"\$\{SSHD_PIDFILE:-\"\/run\/sshdLog\/\$RC_SVCNAME.pid\"\}\"/g" /etc/init.d/sshdLog 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdLog to change pid location for $monitorUsername"
    chroot $mountPoint /bin/sed -i "s/^pidfile=\"\(.*\)/pidfile=\"\$\{SSHD_PIDFILE:-\"\/run\/sshdLog\/\$RC_SVCNAME.pid\"\}\"/g" /etc/init.d/sshdExtract 2>/dev/null || log "UNEXPECTED: Could not modify /etc/init.d/sshdExtract to change pid location for $extractUsername"

    log "INFO: Configurating doas"
		# Create permenant file
    chroot $mountPoint /bin/echo "# Doas configuration for limited system services
# ACPID
permit nopass root as $powerUsername cmd /usr/sbin/acpid args -l --foreground --pidfile /var/run/acpid/acpid.pid --lockfile /var/run/acpid/acpid.lock --socketfile /var/run/acpid/acpid.socket --socketgroup acpi --socketmode 660
# Chronyd
permit nopass root as chrony cmd /usr/sbin/chronyd args -u chrony -U -F 1 -f /etc/chrony/chrony.conf -L 0 -l /var/log/chronyd.log
# SSHD
permit nopass root as $previewUsername cmd /usr/sbin/sshd args -f /home/.keys/$previewUsername/$previewUsername-sshd.conf -E /var/log/sshdStatus.log
permit nopass root as $backupUsername cmd /usr/sbin/sshd args -f /home/.keys/$backupUsername/$backupUsername-sshd.conf -E /var/log/sshdBackup.log
permit nopass root as $serverCommandUsername cmd /usr/sbin/sshd args -f /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf -E /var/log/sshdCommand.log
permit nopass root as $monitorUsername cmd /usr/sbin/sshd args -f /home/.keys/$monitorUsername/$monitorUsername-sshd.conf -E /var/log/sshdLog.log
# Fail2ban
permit nopass root as $fail2banUsername cmd /usr/bin/fail2ban-client args start
permit nopass root as $fail2banUsername cmd /usr/bin/fail2ban-client args stop
permit nopass root as $fail2banUsername cmd /usr/bin/fail2ban-client args reload" > $mountPoint/etc/doas.d/daemon.conf 2>/dev/null || log "UNEXPECTED: Could not modify doas configuration file!"
		# Create temp file
    chroot $mountPoint /bin/echo "# Doas configuration for temp ssh service
permit nopass root as $previewUsername cmd /usr/sbin/sshd args -f /home/.keys/$extractUsername/$extractUsername-sshd.conf -E /var/log/sshdExtract.log" > $mountPoint/etc/doas.d/tempUser.conf 2>/dev/null || log "UNEXPECTED: Could not create temp doas configuration file!"

# !!! ACPID CONFIGURATION
    log "INFO: Configurating ACPID"

# !!! CHRONY CONFIGURATION
    log "INFO: Configurating Chrony"

# !!! SSHD
    log "INFO: Configurating SSH"
		# Lockingdown and creating user-based sshd_config
    for i in $extractUsername $monitorUsername $previewUsername $serverCommandUsername $backupUsername; do
        chroot $mountPoint /bin/echo "# Standard sshd_config options
#Port REPLACEME
AddressFamily inet
#ListenAddress
#HostKey REPLACEME
RekeyLimit 256M 1h
SyslogFacility AUTH
LogLevel $sshLogging
LoginGraceTime 15
PermitRootLogin no
StrictModes yes
MaxAuthTries 2
MaxSessions 2
PubkeyAuthentication yes
#AuthorizedKeysFile REPLACEME
#AuthorizedPrincipalsIsFile
#AuthorizedKeysCommand
#AuthorizedKeysCommandUser
HostbasedAuthentication no
IgnoreUserKnownHosts no
IgnoreRhosts yes
PasswordAuthentication no
PermitEmptyPasswords no
#KdbInteractiveAuthentication yes
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
UsePAM no
#AllowAgentForwarding yes
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
PermitTTY yes
PrintMotd yes
#PrintLastLog yes
TCPKeepAlive yes
PermitUserEnvironment no
Compression yes
ClientAliveInterval 150
ClientAliveCountMax 2
UseDNS no
#PidFile REPLACEME
#MaxStartups 10:30:100
PermitTunnel no
##ChrootDirectory none
#VersionAddendum none
Banner /etc/issue
#Subsystem REPLACEME

# AlpineHarden.sh additions
DisableForwarding yes
FingerprintHash sha256
ChannelTimeout session=20m
Ciphers aes256-gcm@openssh.com,aes256-ctr
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com
MACs hmac-sha2-512-etm@openssh.com
PubkeyAcceptedKeyTypes ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com
AllowUsers $i@$localNetwork/$localNetmask" > $mountPoint/home/.keys/$i/$i-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not create sshd_config profile for $i in /home/.keys/$i/$i-sshd.conf"
    done
		# Modifying specific sshd profile configurations based on user
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}Port REPLACEME\(.*\)/Port $sshPortStatus/g" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Port could not be configured for /home/.keys/$previewUsername/$previewUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}Port REPLACEME\(.*\)/Port $sshPortBackup/g" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Port could not be configured for /home/.keys/$backupUsername/$backupUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}Port REPLACEME\(.*\)/Port $sshPortCommand/g" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Port could not be configured for /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}Port REPLACEME\(.*\)/Port $sshPortLog/g" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Port could not be configured for /home/.keys/$monitorUsername/$monitorUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}Port REPLACEME\(.*\)/Port $sshPortExtract/g" /home/.keys/$extractUsername/$extractUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Port could not be configured for /home/.keys/$extractUsername/$extractUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}HostKey REPLACEME\(.*\)/HostKey \/home\/.keys\/$previewUsername\/ssh_host_$previewUsername-key/g" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: HostKey could not be configured for /home/.keys/$previewUsername/$previewUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}HostKey REPLACEME\(.*\)/HostKey \/home\/.keys\/$backupUsername\/ssh_host_$backupUsername-key/g" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: HostKey could not be configured for /home/.keys/$backupUsername/$backupUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}HostKey REPLACEME\(.*\)/HostKey \/home\/.keys\/$serverCommandUsername\/ssh_host_$serverCommandUsername-key/g" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: HostKey could not be configured for /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}HostKey REPLACEME\(.*\)/HostKey \/home\/.keys\/$monitorUsername\/ssh_host_$monitorUsername-key/g" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: HostKey could not be configured for /home/.keys/$monitorUsername/$monitorUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}HostKey REPLACEME\(.*\)/HostKey \/home\/.keys\/$extractUsername\/ssh_host_$extractUsername-key/g" /home/.keys/$extractUsername/$extractUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: HostKey could not be configured for /home/.keys/$extractUsername/$extractUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}AuthorizedKeysFile REPLACEME\(.*\)/AuthorizedKeysFile \/home\/.keys\/$previewUsername\/authorized_keys/g" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: AuthorizedKeysFile could not be configured for /home/.keys/$previewUsername/$previewUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}AuthorizedKeysFile REPLACEME\(.*\)/AuthorizedKeysFile \/home\/.keys\/$backupUsername\/authorized_keys/g" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: AuthorizedKeysFile could not be configured for /home/.keys/$backupUsername/$backupUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}AuthorizedKeysFile REPLACEME\(.*\)/AuthorizedKeysFile \/home\/.keys\/$serverCommandUsername\/authorized_keys/g" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: AuthorizedKeysFile could not be configured for /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}AuthorizedKeysFile REPLACEME\(.*\)/AuthorizedKeysFile \/home\/.keys\/$monitorUsername\/authorized_keys/g" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: AuthorizedKeysFile could not be configured for /home/.keys/$monitorUsername/$monitorUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}AuthorizedKeysFile REPLACEME\(.*\)/AuthorizedKeysFile \/home\/.keys\/$extractUsername\/authorized_keys/g" /home/.keys/$extractUsername/$extractUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: AuthorizedKeysFile could not be configured for /home/.keys/$extractUsername/$extractUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}PidFile REPLACEME\(.*\)/PidFile \/var\/run\/sshdStatus\/sshd.pid/g" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: PidFile could not be configured for /home/.keys/$previewUsername/$previewUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}PidFile REPLACEME\(.*\)/PidFile \/var\/run\/sshdBackup\/sshd.pid/g" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: PidFile could not be configured for /home/.keys/$backupUsername/$backupUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}PidFile REPLACEME\(.*\)/PidFile \/var\/run\/sshdCommand\/sshd.pid/g" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: PidFile could not be configured for /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}PidFile REPLACEME\(.*\)/PidFile \/var\/run\/sshdLog\/sshd.pid/g" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: PidFile could not be configured for /home/.keys/$monitorUsername/$monitorUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}PidFile REPLACEME\(.*\)/PidFile \/var\/run\/sshdExtract\/sshd.pid/g" /home/.keys/$extractUsername/$extractUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: PidFile could not be configured for /home/.keys/$extractUsername/$extractUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}Subsystem REPLACEME\(.*\)/Subsystem sftp \/usr\/lib\/ssh\/sftp-server/g" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Subsystem could not be configured for /home/.keys/$backupUsername/$backupUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}Subsystem REPLACEME\(.*\)/Subsystem sftp \/usr\/lib\/ssh\/sftp-server/g" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Subsystem could not be configured for /home/.keys/$monitorUsername/$monitorUsername-sshd.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}Subsystem REPLACEME\(.*\)/Subsystem sftp \/usr\/lib\/ssh\/sftp-server/g" /home/.keys/$extractUsername/$extractUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Subsystem could not be configured for /home/.keys/$extractUsername/$extractUsername-sshd.conf"

#pidfile relocation for each user: PidFile
#authroized keys re-direction as hardcoded: AuthorizedKeysFile
#private key re-direction as hardcoded: HostKey
#different port: Port
#https://blog.matrixpost.net/using-match-directives-in-ssh/
#https://www.man7.org/linux/man-pages/man5/sshd_config.5.html

#previewUsername (no shell basically)
#backupUsername (sftp)
#serverCommandUsername (limited shell, lol)
#monitorUsername (sftp?)
#extractUsername (sftp)

		# Lockdown ssh_config
    echo "Host *
    AddressFamily inet
    BatchMode no
    ChallengeResponseAuthentication yes
    CheckHostIP yes
    Compression yes
    CompressionLevel 9
    ConnectTimeout 99999
    ForwardAgent no
    ForwardX11 no
    GatewayPorts no
    HashKnownHosts yes
    LogLevel $sshLogging
    PasswordAuthentication no
    PermitLocalCommand no
    PreferredAuthentications publickey
    TCPKeepAlive yes
    Tunnel no
    UsePrivilegedPort no
    PubkeyAuthentication yes" > $mountPoint/etc/ssh/ssh_config 2>/dev/null || log "UNEXPECTED: Could not harden /etc/ssh/ssh_config file"
		# Create storage place of ssh keys
    chroot $mountPoint /bin/mkdir -p "/home/.keys" 2>/dev/null || log "UNEXPECTED: Could not make ssh directory as /home/.keys"
    chroot $mountPoint /bin/mkdir -p "/home/.keys/$extractUsername" 2>/dev/null || log "UNEXPECTED: Could not make ssh directory for $extractUsername"
    chroot $mountPoint /bin/mkdir -p "/home/.keys/$monitorUsername" 2>/dev/null || log "UNEXPECTED: Could not make ssh directory for $monitorUsername"
    chroot $mountPoint /bin/mkdir -p "/home/.keys/$previewUsername" 2>/dev/null || log "UNEXPECTED: Could not make ssh directory for $previewUsername"
    chroot $mountPoint /bin/mkdir -p "/home/.keys/$serverCommandUsername" 2>/dev/null || log "UNEXPECTED: Could not make ssh directory for $serverCommandUsername"
    chroot $mountPoint /bin/mkdir -p "/home/.keys/$backupUsername" 2>/dev/null || log "UNEXPECTED: Could not make ssh directory for $backupUsername"
		# Generate ssh keys for authorized users
    if [ ! -f "$mountPoint/home/.keys/$extractUsername/authorized_keys" ]; then chroot $mountPoint /bin/echo "$sshUsernameKey" > "$mountPoint/home/.keys/$extractUsername/authorized_keys" || log "CRITICAL: Failed to add ssh public key to /home/.keys for $extractUsername"; fi
    if [ ! -f "$mountPoint/home/.keys/$monitorUsername/authorized_keys" ]; then chroot $mountPoint /usr/bin/ssh-keygen -f "/home/$extractUsername/$localhostName.$monitorUsername-key" -t ed25519 -P "$tempSshPass" || log "CRITICAL: Could not generate sshd key for $monitorUsername"; chroot $mountPoint /bin/mv -f /home/$extractUsername/$localhostName.$monitorUsername-key.pub /home/.keys/$monitorUsername/authorized_keys 2>/dev/null || log "CRITICAL: Could not create authorized_keys file for $monitorUsername"; fi
    if [ ! -f "$mountPoint/home/.keys/$previewUsername/authorized_keys" ]; then chroot $mountPoint /usr/bin/ssh-keygen -f "/home/$extractUsername/$localhostName.$previewUsername-key" -t ed25519 -P "$tempSshPass" || log "CRITICAL: Could not generate sshd key for $previewUsername"; chroot $mountPoint /bin/mv -f /home/$extractUsername/$localhostName.$previewUsername-key.pub /home/.keys/$previewUsername/authorized_keys 2>/dev/null || log "CRITICAL: Could not create authorized_keys file for $previewUsername"; fi
    if [ ! -f "$mountPoint/home/.keys/$serverCommandUsername/authorized_keys" ]; then chroot $mountPoint /usr/bin/ssh-keygen -f "/home/$extractUsername/$localhostName.$serverCommandUsername-key" -t ed25519 -P "$tempSshPass" || log "CRITICAL: Could not generate sshd key for $serverCommandUsername"; chroot $mountPoint /bin/mv -f /home/$extractUsername/$localhostName.$serverCommandUsername-key.pub /home/.keys/$serverCommandUsername/authorized_keys 2>/dev/null || log "CRITICAL: Could not create authorized_keys file for $serverCommandUsername"; fi
    if [ ! -f "$mountPoint/home/.keys/$backupUsername/authorized_keys" ]; then chroot $mountPoint /usr/bin/ssh-keygen -f "/home/$extractUsername/$localhostName.$backupUsername-key" -t ed25519 -P "$tempSshPass" || log "CRITICAL: Could not generate sshd key for $backupUsername"; chroot $mountPoint /bin/mv -f /home/$extractUsername/$localhostName.$backupUsername-key.pub /home/.keys/$backupUsername/authorized_keys 2>/dev/null || log "CRITICAL: Could not create authorized_keys file for $backupUsername"; fi
		# Generate seperate per-user sshd host keys
    if [ ! -f "$mountPoint/home/.keys/$previewUsername/ssh_host_$previewUsername-key" ]; then chroot $mountPoint /usr/bin/ssh-keygen -t ed25519 -N "" -f "/home/.keys/$previewUsername/ssh_host_$previewUsername-key" 2>/dev/null || log "UNEXPECTED: Could not generate private and public host key for $previewUsername"; fi
    if [ ! -f "$mountPoint/home/.keys/$backupUsername/ssh_host_$backupUsername-key" ]; then chroot $mountPoint /usr/bin/ssh-keygen -t ed25519 -N "" -f "/home/.keys/$backupUsername/ssh_host_$backupUsername-key" 2>/dev/null || log "UNEXPECTED: Could not generate private and public host key for $backupUsername"; fi
    if [ ! -f "$mountPoint/home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key" ]; then chroot $mountPoint /usr/bin/ssh-keygen -t ed25519 -N "" -f "/home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key" 2>/dev/null || log "UNEXPECTED: Could not generate private and public host key for $serverCommandUsername"; fi
    if [ ! -f "$mountPoint/home/.keys/$monitorUsername/ssh_host_$monitorUsername-key" ]; then chroot $mountPoint /usr/bin/ssh-keygen -t ed25519 -N "" -f "/home/.keys/$monitorUsername/ssh_host_$monitorUsername-key" 2>/dev/null || log "UNEXPECTED: Could not generate private and public host key for $monitorUsername"; fi
    if [ ! -f "$mountPoint/home/.keys/$extractUsername/ssh_host_$extractUsername-key" ]; then chroot $mountPoint /usr/bin/ssh-keygen -t ed25519 -N "" -f "/home/.keys/$extractUsername/ssh_host_$extractUsername-key" 2>/dev/null || log "UNEXPECTED: Could not generate private and public host key for $extractUsername"; fi
		# Too expensive to be done correctly and efficiently on embedded devices (or live iso). This will have a skip option
    if $sshExpensiveOperation; then
        log "INFO: Re-generating sshd moduli file for unique prime numbers"
        chroot $mountPoint /usr/bin/ssh-keygen -M generate -O bits=8192 /etc/ssh/8192.candidates 2>/dev/null || log "UNEXPECTED: Could not generate prime number canadites"
        chroot $mountPoint /usr/bin/ssh-keygen -M screen -f /etc/ssh/8192.candidates /etc/ssh/8192.screened 2>/dev/null || log "UNEXPECTED: Could not screen prime number canadites appropriately"
        chroot $mountPoint /bin/rm /etc/ssh/8192.candidates 2>/dev/null || log "UNEXPECTED: Could not remove 8192.candidates"
        chroot $mountPoint /bin/mv /etc/ssh/8192.screened /etc/ssh/moduli 2>/dev/null || log "UNEXPECTED: Could not replace /etc/ssh/moduli with 8192.screened's prime numbers"
    fi
		# Prune weaker primes from moduli file
    if [ ! -z "$(chroot $mountPoint /usr/bin/awk '$5 < 3071' /etc/ssh/moduli)" ]; then
        log "INFO: Removing small Diffie-Hellman moduli that are less than 3071 bits"
        chroot $mountPoint /usr/bin/awk '$5 >= 3071' /etc/ssh/moduli > $mountPoint/etc/ssh/moduli.safer 2>/dev/null || log "UNEXPECTED: Could not filter out bits less than 3071 in /etc/ssh/moduli"
        chroot $mountPoint /bin/mv /etc/ssh/moduli.safer /etc/ssh/moduli 2>/dev/null || log "UNEXPECTED: Could not override /etc/ssh/moduli with less vulnerable bits"
    fi
	# Removing old pid file directory, and old ssh host keys
    if [ -d "$mountPoint/var/run/sshd" ]; then chroot $mountPoint /sbin/rc-service sshd stop || log "UNEXPECTED: Could not stop sshd daemon"; chroot $mountPoint /bin/rm -rdf /var/run/sshd 2>/dev/null || log "UNEXPECTED: Could not remove old sshd pid directory"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_ecdsa_key" ]; then chroot $mountPoint /bin/rm -f /etc/ssh/ssh_host_ecdsa_key 2>/dev/null || log "UNEXPECTED: Could not remove old ssh host key /etc/ssh/ssh_host_ecdsa_key!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_ed25519_key" ]; then chroot $mountPoint /bin/rm -f /etc/ssh/ssh_host_ed25519_key 2>/dev/null || log "UNEXPECTED: Could not remove old ssh host key /etc/ssh/ssh_host_ed25519_key!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_rsa_key" ]; then chroot $mountPoint /bin/rm -f /etc/ssh/ssh_host_rsa_key 2>/dev/null || log "UNEXPECTED: Could not remove old ssh host key /etc/ssh/ssh_host_rsa_key!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_ecdsa_key.pub" ]; then chroot $mountPoint /bin/rm -f /etc/ssh/ssh_host_ecdsa_key.pub 2>/dev/null || log "UNEXPECTED: Could not remove old ssh host key /etc/ssh/ssh_host_ecdsa_key.pub!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_ed25519_key.pub" ]; then chroot $mountPoint /bin/rm -f /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || log "UNEXPECTED: Could not remove old ssh host key /etc/ssh/ssh_host_ed25519_key.pub!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_rsa_key.pub" ]; then chroot $mountPoint /bin/rm -f /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null || log "UNEXPECTED: Could not remove old ssh host key /etc/ssh/ssh_host_rsa_key.pub!"; fi

    log "INFO: Configurating UFW"
		# Clear prior UFW behavior to default
    chroot $mountPoint /usr/sbin/ufw --force reset 2>/dev/null || log "CRITICAL: Could not reset firewall properely"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'after.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove after.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'before.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove before.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'user.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove user.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'after6.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove after6.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'before6.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove before6.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'user6.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove user6.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ -mindepth 1 -delete 2>/dev/null || log "UNEXPECTED: Could not ensure there are no other application rules"
		# Set UFW logging level
    chroot $mountPoint /usr/sbin/ufw logging "$ufwLogging" 2>/dev/null || log "UNEXPECTED: Logging was not properely enabled";
		# Default UFW deny behavior, and prohibit IPV6
    chroot $mountPoint /usr/sbin/ufw default deny outgoing 2>/dev/null || log "CRITICAL: Failed to set default deny outgoing to ufw firewall"
    chroot $mountPoint /usr/sbin/ufw default deny incoming 2>/dev/null || log "CRITICAL: Failed to set default deny incoming to ufw firewall"
    chroot $mountPoint /usr/sbin/ufw default deny routed 2>/dev/null || log "CRITICAL: Failed to set default deny routing packets to ufw firewall"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}IPV6\(.*\)=\(.*\)yes/IPV6=no/g' /etc/default/ufw 2>/dev/null || log "UNEXPECTED: No pattern to remove IPV6 from UFW has worked"
		# Define specific app profiles for UFW
    chroot $mountPoint /usr/sbin/ufw app default allow 2>/dev/null || log "UNEXPECTED: Failed to guarantee ufw firewall accept newly made profiles"
    chroot $mountPoint /bin/echo "[SSHServer]
title=SSH network listener
description=For remote management of server via ssh
ports=$sshPortStatus/tcp|$sshPortBackup/tcp|$sshPortCommand/tcp|$sshPortLog/tcp" > $mountPoint/etc/ufw/applications.d/ssh || log "UNEXPECTED: Failed to permit SSH port $sshPortStatus,$sshPortBackup,$sshPortCommand,$sshPortLog through firewall"
    chroot $mountPoint /bin/echo "[SSHServerTemp]
title=SSH extract files network listener
description=For $extractUsername to temporarely connect
ports=$sshPortExtract/tcp" > $mountPoint/etc/ufw/applications.d/sshTemp || log "UNEXPECTED: Failed to permit temporary SSH port $sshPortExtract through firewall"
    chroot $mountPoint /bin/echo "[APKUpdate]
title=APK tool
description=When this computer needs to update packages, then this will be enabled
ports=80/tcp|443/tcp" > $mountPoint/etc/ufw/applications.d/apk || log "UNEXPECTED: Failed to permit APK ports 80 and 443 through firewall"
    chroot $mountPoint /bin/echo "[NTPListener]
title=Chronyd network listener
description=For chronyd service running in background
ports=123/udp|323/udp" > $mountPoint/etc/ufw/applications.d/ntp || log "UNEXPECTED: Failed to permit NTP ports 123 and 323 through firewall"
    chroot $mountPoint /bin/echo -e "[DNSListener]
title=DNS network listener
description=For a dns service running in background
ports=53" > $mountPoint/etc/ufw/applications.d/dns || log "UNEXPECTED: Failed to permit DNS port 53 through firewall"
    chroot $mountPoint /usr/sbin/ufw app update SSHServer || log "CRITICAL: Could not ensure ufw recognizes the ssh profile"
    chroot $mountPoint /usr/sbin/ufw app update SSHServerTemp || log "CRITICAL: Could not ensure ufw recognizes the temp ssh profile"
    chroot $mountPoint /usr/sbin/ufw app update DNSListener || log "UNEXPECTED: Could not ensure ufw recognizes the dns profile"
    chroot $mountPoint /usr/sbin/ufw app update APKUpdate || log "UNEXPECTED: Could not ensure ufw recognizes the apk profile"
    chroot $mountPoint /usr/sbin/ufw app update NTPListener || log "UNEXPECTED: Could not ensure ufw recognizes the ntp profile"
    chroot $mountPoint /usr/sbin/ufw app default deny 2>/dev/null || log "CRITICAL: Failed to set default deny creation and modification of application profiles for ufw firewall"
		# Open http, https, dns, and ntp ports
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app APKUpdate 2>/dev/null || log "UNEXPECTED: Failed to permit HTTP/HTTPS port 80/443 esgress through firewall"
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app DNSListener 2>/dev/null || log "UNEXPECTED: Failed to permit DNS port 53 esgress through firewall"
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app NTPListener 2>/dev/null || log "UNEXPECTED: Failed to permit NTP port 123 esgress through firewall"
		# Add rate limit and open ssh port
    chroot $mountPoint /usr/sbin/ufw limit in log from "$localNetwork"/"$localNetmask" to "$localNetwork"/"$localNetmask" app SSHServer 2>/dev/null || log "CRITICAL: Failed to limit ports $sshPortStatus,$sshPortBackup,$sshPortCommand,$sshPortLog for ingress traffic for ufw firewall"
    chroot $mountPoint /usr/sbin/ufw limit in log from "$localNetwork"/"$localNetmask" to "$localNetwork"/"$localNetmask" app SSHServerTemp 2>/dev/null || log "CRITICAL: Failed to limit port $sshPortExtract for ingress traffic for ufw firewall"
		# Removing newly downloaded files if ufw was previously uninstalled
    if [ -f "$mountPoint/etc/init.d/ufw.apk-new" ]; then chroot $mountPoint /bin/rm /etc/init.d/ufw.apk-new 2>/dev/null || log "UNEXPECTED: Could not remove redundant default file: /etc/init.d/ufw.apk-new"; fi
    if [ -f "$mountPoint/etc/ufw/ufw.conf.apk-new" ]; then chroot $mountPoint /bin/rm /etc/ufw/ufw.conf.apk-new 2>/dev/null || log "UNEXPECTED: Could not remove redundant default file: /etc/ufw/ufw.conf.apk-new"; fi
    if [ -f "$mountPoint/etc/default/ufw.apk-new" ]; then chroot $mountPoint /bin/rm /etc/default/ufw.apk-new 2>/dev/null || log "UNEXPECTED: Could not remove redundant default file: /etc/default/ufw.apk-new"; fi
		# Removing UFW code that checks for root access
    chroot $mountPoint /bin/sed -i "s/    if uid != 0/    if 1 == 2 and uid != 0/1" /usr/lib/python3.12/site-packages/ufw/backend.py 2>/dev/null || log "CRITICAL: Could not modify ufw backend python library to bypass root required access"
    chroot $mountPoint /bin/sed -i "s/            if statinfo.st_uid != 0/            if 1 == 2 and statinfo.st_uid != 0/1" /usr/lib/python3.12/site-packages/ufw/backend.py 2>/dev/null || log "UNEXPECTED: Could not turn off warning of certain files owned by non-root account in ufw"

    log "INFO: Configurating fail2ban"
		# Fail2ban file creation
    chroot $mountPoint /bin/touch /etc/fail2ban/jail.local || log "CRITICAL: Failed to create configuration file for fail2ban"    
    chroot $mountPoint /bin/echo -e '[INCLUDES]\nbefore = paths-debian.conf\n' > $mountPoint/etc/fail2ban/jail.local || log "UNEXPECTED: Fail to include other relevant standard jail settings"
    chroot $mountPoint /bin/echo -e '[DEFAULT]\nbantime = 1h\nfindtime = 1h\nmaxretry = 3\nbantime.increment = true\nbantime.maxtime = 6000\nbantime.factor = 2\nbantime.overalljails = true\nignorecommand =\nmaxmatches = %(maxretry)s\nbackend = auto\nusedns = warn\nlogencoding = auto\nenabled = false\nmode = normal\nfilter = %(__name__)s[mode=%(mode)s]\n' >> $mountPoint/etc/fail2ban/jail.local || log "UNEXPECTED: Fail to declare default jail settings"
    chroot $mountPoint /bin/echo -e 'destemail=root@localhost\nsender = root@<fq-hostname>\nmta = sendmail\nprotocol = tcp\nchain = <known/chain>\nport = 0:65535\nfail2ban_agent = Fail2Ban%(fail2ban_version)s\nbanaction = iptables-multiport\nbanaction_allports = iptables_allports\naction_ = %(banaction)s[port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]\naction_mw = %(action)s%(mta)s-whois[sender="%(sender)", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]\naction_mwl = %(mta)s-whois-lines[sender="%(sender)", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]\naction_xarf = %(action)sxarf-login-attack[service=%(__name__), logpath="%(logpath)s", port="%(port)s""]\naction_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"] %(mta)s-whois-lines[sender="%(sender)", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]\naction_blocklist_de = blocklist_de[email="%(sender)s", service="%(__name__)s", apikey="%(blocklist_de_apikey)s", agent="%(fail2ban_agent)s"]\naction_abuseipdb = abuseipdb\naction = %(action_)s' >> $mountPoint/etc/fail2ban/jail.local || log "UNEXPECTED: Mostly failed to declare email and management settings for jail"
		# Fail2ban default behavior for fail2ban.conf
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}allowipv6\(.*\)=\(.*\)/allowipv6 = no/g" /etc/fail2ban/fail2ban.conf || log "UNEXPECTED: Could not disable IPv6 configuration on fail2ban.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}loglevel\(.*\)=\(.*\)/loglevel = $fail2banLogging/g" /etc/fail2ban/fail2ban.conf || log "UNEXPECTED: Could not change logging level on fail2ban.conf"

    # !!! LOGGING (syslog)
# A function that enables proper logging and monitoring of a variety of different concerns
# Log configuration: logrotate.conf
# File system health monitoring: e2scrub.conf (lvm monitor)
#revist crontab, 
# look into rc.conf; rc_logger & rc_log_path
# add to /etc/chrony/chrony.conf the "log" option into the file
# look into /etc/logrotate.d/*
# utmp, btmp, and wtmp for recording user logging in

    # RC.conf configuration: rc.conf & /etc/conf.d
    log "INFO: Configurating syslogd!"

    # !!! AUTOMATIC SCRIPTING (cron)
# Adding simple scripts to cron
# Add simple script for updating packages
# Add simple script for threat detection
# Add simple checksum scans
# Add script to automatically populate /var/run with services: ssh, chrony, and fail2ban
    log "INFO: Configurating crond!"

# !!! DELETE USER SCRIPT
#rc-service atd start
#echo -e "#!/bin/sh\nuserdel -f $extractUsername\nrm -rF /home/$extractUsername\nrm -rF /home/.keys/$extractUsername\nufw delete limit in log from $localNetwork/$localNetmask to $localNetwork/$localNetmask app SSHServerTemp\nrm -f /etc/ufw/applications.d/sshTemp\nrc-service atd stop\nrc-service sshdExtract stop\nrc-update del sshdExtract\nrm /etc/doas.d/tempUser.conf\nrm /etc/init.d/sshdExtract" > /etc/removal.sh
#chmod 700 /tmp/removal.sh
#chown cron:cron /tmp/removal.sh
#at -f /tmp/removal.sh now + 4 hours
    log "INFO: Creating script to delete $extractUsername in 4 hours!"

    log "INFO: Setting permissions on /bin executables"
    chroot $mountPoint /bin/chmod 0510 /bin/busybox 2>/dev/null || log "UNEXPECTED: Could not change permissions for; busybox"
    chroot $mountPoint /bin/chmod 0500 /bin/coreutils 2>/dev/null || log "UNEXPECTED: Could not change permissions for; coreutils"
    chroot $mountPoint /bin/chmod 0500 /bin/rc-status 2>/dev/null || log "UNEXPECTED: Could not change permissions for; rc-status"
    chroot $mountPoint /bin/chmod 0500 /bin/setpriv 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setpriv"
    chroot $mountPoint /bin/chmod 0500 /bin/dmesg 2>/dev/null || log "UNEXPECTED: Could not change permissions for; dmesg"
    chroot $mountPoint /bin/chmod 0500 /bin/kmod 2>/dev/null || log "UNEXPECTED: Could not change permissions for; kmod"
    chroot $mountPoint /bin/chmod 4510 /bin/bbsuid 2>/dev/null || log "UNEXPECTED: Could not change permissions for; bbsuid"
    # Ensuring rksh exist by creating a copy of ksh
    chroot $mountPoint /bin/cp /bin/ksh /bin/rksh --update=none 2>/dev/null || log "CRITICAL: Could not create rksh to facilitate restricted ksh shell when users login in"
    chroot $mountPoint /bin/chmod 0400 /bin/ksh 2>/dev/null || log "UNEXPECTED: Could not change /bin/ksh file permissions"
    chroot $mountPoint /bin/chmod 0510 /bin/rksh 2>/dev/null || log "UNEXPECTED: Could not change /bin/rksh file permissions"

    log "INFO: Setting permissions on /sbin executables"
    chroot $mountPoint /bin/chmod 0500 /sbin/xfs_repair 2>/dev/null || log "UNEXPECTED: Could not change permissions for; xfs_repair"
    chroot $mountPoint /bin/chmod 0500 /sbin/mkfs.xfs 2>/dev/null || log "UNEXPECTED: Could not change permissions for; mkfs.xfs"
    chroot $mountPoint /bin/chmod 0500 /sbin/fsck.xfs 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fsck.xfs"
    chroot $mountPoint /bin/chmod 0500 /sbin/lvmpersist 2>/dev/null || log "UNEXPECTED: Could not change permissions for; lvmpersist"
    chroot $mountPoint /bin/chmod 0500 /sbin/lvm 2>/dev/null || log "UNEXPECTED: Could not change permissions for; lvm"
    chroot $mountPoint /bin/chmod 0500 /sbin/mke2fs 2>/dev/null || log "UNEXPECTED: Could not change permissions for; mke2fs"
    chroot $mountPoint /bin/chmod 0500 /sbin/e2fsck 2>/dev/null || log "UNEXPECTED: Could not change permissions for; e2fsck"
    chroot $mountPoint /bin/chmod 0500 /sbin/ldconfig 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ldconfig"
    chroot $mountPoint /bin/chmod 0500 /sbin/apk 2>/dev/null || log "UNEXPECTED: Could not change permissions for; apk"
    chroot $mountPoint /bin/chmod 0500 /sbin/supervise-daemon 2>/dev/null || log "UNEXPECTED: Could not change permissions for; supervise-daemon"
    chroot $mountPoint /bin/chmod 0500 /sbin/start-stop-daemon 2>/dev/null || log "UNEXPECTED: Could not change permissions for; start-stop-daemon"
    chroot $mountPoint /bin/chmod 0500 /sbin/rc-update 2>/dev/null || log "UNEXPECTED: Could not change permissions for; rc-update"
    chroot $mountPoint /bin/chmod 0500 /sbin/rc-sstat 2>/dev/null || log "UNEXPECTED: Could not change permissions for; rc-sstat"
    chroot $mountPoint /bin/chmod 0500 /sbin/rc-service 2>/dev/null || log "UNEXPECTED: Could not change permissions for; rc-service"
    chroot $mountPoint /bin/chmod 0500 /sbin/openrc-run 2>/dev/null || log "UNEXPECTED: Could not change permissions for; openrc-run"
    chroot $mountPoint /bin/chmod 0500 /sbin/openrc 2>/dev/null || log "UNEXPECTED: Could not change permissions for; openrc"
    chroot $mountPoint /bin/chmod 0500 /sbin/mkmntdirs 2>/dev/null || log "UNEXPECTED: Could not change permissions for; mkmntdirs"
    chroot $mountPoint /bin/chmod 0500 /sbin/ifupdown 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ifupdown"
    chroot $mountPoint /bin/chmod 0500 /sbin/nlplug-findfs 2>/dev/null || log "UNEXPECTED: Could not change permissions for; nlplug-findfs"
    chroot $mountPoint /bin/chmod 0500 /sbin/mkinitfs 2>/dev/null || log "UNEXPECTED: Could not change permissions for; mkinitfs"
    chroot $mountPoint /bin/chmod 0500 /sbin/bootchartd 2>/dev/null || log "UNEXPECTED: Could not change permissions for; bootchartd"
    chroot $mountPoint /bin/chmod 0510 /sbin/acpid 2>/dev/null || log "UNEXPECTED: Could not change /sbin/acpid file permissions"

    log "INFO: Setting permissions on /usr/bin executables"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/xargs 2>/dev/null || log "UNEXPECTED: Could not change permissions for; xargs"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/find 2>/dev/null || log "UNEXPECTED: Could not change permissions for; find"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/sha512sum 2>/dev/null || log "UNEXPECTED: Could not change permissions for; sha512sum"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/fmt 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fmt"
    chroot $mountPoint /bin/chmod 0550 /usr/bin/env 2>/dev/null || log "UNEXPECTED: Could not change permissions for; env"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/econftool 2>/dev/null || log "UNEXPECTED: Could not change permissions for; econftool"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ssh 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssh"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ssh-pkcs11-helper 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssh-pkcs11-helper"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ssh-keyscan 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssh-keyscan"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ssh-copy-id 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssh-copy-id"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ssh-agent 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssh-agent"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ssh-add 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssh-add"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/sftp 2>/dev/null || log "UNEXPECTED: Could not change permissions for; sftp"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/scp 2>/dev/null || log "UNEXPECTED: Could not change permissions for; scp"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/findssl.sh 2>/dev/null || log "UNEXPECTED: Could not change permissions for; findssl.sh"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ssh-keygen 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssh-keygen"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/chronyc 2>/dev/null || log "UNEXPECTED: Could not change permissions for; chronyc"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/scmp_sys_resolver 2>/dev/null || log "UNEXPECTED: Could not change permissions for; scmp_sys_resolver"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/p11-kit 2>/dev/null || log "UNEXPECTED: Could not change permissions for; p11-kit"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/openssl 2>/dev/null || log "UNEXPECTED: Could not change permissions for; openssl"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ldd 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ldd"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/iconv 2>/dev/null || log "UNEXPECTED: Could not change permissions for; iconv"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/getent 2>/dev/null || log "UNEXPECTED: Could not change permissions for; getent"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/getconf 2>/dev/null || log "UNEXPECTED: Could not change permissions for; getconf"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/scanelf 2>/dev/null || log "UNEXPECTED: Could not change permissions for; scanelf"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/ssl_client 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssl_client"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/uniso 2>/dev/null || log "UNEXPECTED: Could not change permissions for; uniso"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/logger 2>/dev/null || log "UNEXPECTED: Could not change permissions for; logger"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/lddtree 2>/dev/null || log "UNEXPECTED: Could not change permissions for; lddtree"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-syslinux2cfg 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-syslinux2cfg"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-script-check 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-script-check"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-render-label 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-render-label"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-mkstandalone 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-mkstandalone"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-mkrescue 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-mkrescue"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-mkrelpath 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-mkrelpath"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-mkpasswd-pbkdf2 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-mkpasswd-pbkdf2"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-mknetdir 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-mknetdir"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-mklayout 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-mklayout"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-mkimage 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-mkimage"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-menulst2cfg 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-menulst2cfg"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-kbdcomp 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-kbdcomp"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-glue-efi 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-glue-efi"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-fstest 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-fstest"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-file 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-file"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/grub-editenv 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-editenv"
    chroot $mountPoint /bin/chmod 0510 /usr/bin/doas 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/doas file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/passwd 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/passwd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/gpasswd 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/gpasswd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/expiry 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/expiry file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/chsh 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/chsh file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/chfn 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/chfn file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/chage 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/chage file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/bin/at 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/at file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/batch 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/batch file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/acpi_listen 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/acpi_listen file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/bin/python3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; python3.12"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/pydoc3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; pydoc3.12"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/2to3-3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; 2to3-3.12"
    chroot $mountPoint /bin/chmod 0550 /usr/bin/fail2ban-server 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fail2ban-server"
    chroot $mountPoint /bin/chmod 0550 /usr/bin/fail2ban-regex 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fail2ban-regex"
    chroot $mountPoint /bin/chmod 0550 /usr/bin/fail2ban-client 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fail2ban-client"
    chroot $mountPoint /bin/chmod 0550 /usr/bin/env 2>/dev/null || log "UNEXPECTED: Could not change /usr/bin/env file permissions"

    log "INFO: Setting permissions on /usr/sbin executables"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/partprobe 2>/dev/null || log "UNEXPECTED: Could not change permissions for; partprobe"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/parted 2>/dev/null || log "UNEXPECTED: Could not change permissions for; parted"
    chroot $mountPoint /bin/chmod 0510 /usr/sbin/sshd 2>/dev/null || log "UNEXPECTED: Could not change permissions for; sshd"
    chroot $mountPoint /bin/chmod 0510 /usr/sbin/chronyd 2>/dev/null || log "UNEXPECTED: Could not change permissions for; chronyd"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/copy-modloop 2>/dev/null || log "UNEXPECTED: Could not change permissions for; copy-modloop"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/update-grub 2>/dev/null || log "UNEXPECTED: Could not change permissions for; update-grub"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-sparc64-setup 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-sparc64-setup"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-set-default 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-set-default"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-reboot 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-reboot"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-probe 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-probe"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-ofpathname 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-ofpathname"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-mkconfig 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-mkconfig"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-macbless 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-macbless"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-install 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-install"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grub-bios-setup 2>/dev/null || log "UNEXPECTED: Could not change permissions for; grub-bios-setup"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/lbu 2>/dev/null || log "UNEXPECTED: Could not change permissions for; lbu"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/update-kernel 2>/dev/null || log "UNEXPECTED: Could not change permissions for; update-kernel"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/update-conf 2>/dev/null || log "UNEXPECTED: Could not change permissions for; update-conf"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-xorg-base 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-xorg-base"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-xen-dom0 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-xen-dom0"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-wayland-base 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-wayland-base"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-user 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-user"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-timezone 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-timezone"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-sshd 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-sshd"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-proxy 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-proxy"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-ntp 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-ntp"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-mta 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-mta"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-lbu 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-lbu"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-keymap 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-keymap"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-interfaces 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-interfaces"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-hostname 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-hostname"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-dns 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-dns"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-disk 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-disk"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-devd 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-devd"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-desktop 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-desktop"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-bootable 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-bootable"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-apkrepos 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-apkrepos"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-apkcache 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-apkcache"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-alpine 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-alpine"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/setup-acf 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setup-acf"
    chroot $mountPoint /bin/chmod 0510 /usr/sbin/setcap 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/setcap file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/sbin/getcap 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/getcap file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/vipw 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/vipw file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/usermod 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/usermod file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/userdel 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/userdel file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/useradd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/useradd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/pwck 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/pwck file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/newusers 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/newusers file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/logoutd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/logoutd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/grpck 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/grpck file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/groupmod 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/groupmod file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/groupmems 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/groupmems file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/groupdel 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/groupdel file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/groupadd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/groupadd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/chpasswd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/chpasswd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/chgpasswd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/chgpasswd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/unix_chkpwd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/unix_chkpwd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/pwhistory_helper 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/pwhistory_helper file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/pam_timestamp_check 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/pam_timestamp_check file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/pam_namespace_helper 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/pam_namespace_helper file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/mkhomedir_helper 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/mkhomedir_helper file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/atd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/atd file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/atrun 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/atrun file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/faillock 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/faillock file permissions"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/kacpimon 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/kacpimon file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/sbin/chronyd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/chronyd file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/sbin/sshd 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/sshd file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/sbin/xtables-nft-multi 2>/dev/null || log "UNEXPECTED: Could not change permissions for; xtables-nft-multi"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/iptables-apply 2>/dev/null || log "UNEXPECTED: Could not change permissions for; iptables-apply"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/nft 2>/dev/null || log "UNEXPECTED: Could not change permissions for; nft"
    chroot $mountPoint /bin/chmod 0550 /usr/sbin/ufw 2>/dev/null || log "UNEXPECTED: Could not change /usr/sbin/ufw file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/sbin/logrotate 2>/dev/null || log "UNEXPECTED: Could not change permissions for; logrotate"

    log "INFO: Setting permission on /etc files and directories"
    chroot $mountPoint /bin/chmod 0400 /etc/security/access.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/access.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/security/faillock.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/faillock.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/security/group.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/group.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/security/limits.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/limits.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/security/namespace.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/namespace.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/security/namespace.init 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/namespace.init file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/security/pam_env.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/pam_env.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/security/pwhistory.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/pwhistory.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/security/time.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/time.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/pam.d/chsh 2>/dev/null || log "UNEXPECTED: Could not change /etc/pam.d/chsh file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/pam.d/shadow-utils 2>/dev/null || log "UNEXPECTED: Could not change /etc/pam.d/shadow-utils file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/doas.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/doas.conf file permissions"
    chroot $mountPoint /bin/chmod 0510 /etc/acpi/handler.sh 2>/dev/null || log "UNEXPECTED: Could not change /etc/acpi/handler.sh file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/acpi/events/anything 2>/dev/null || log "UNEXPECTED: Could not change /etc/acpi/events/anything file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/alpine-release 2>/dev/null || log "UNEXPECTED: Could not change alpine-release file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/e2scrub.conf 2>/dev/null || log "UNEXPECTED: Could not change e2scrub.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/fstab 2>/dev/null || log "UNEXPECTED: Could not change fstab file permissions"
    chroot $mountPoint /bin/chmod 0640 /etc/group 2>/dev/null || log "UNEXPECTED: Could not change group file permissions"
    chroot $mountPoint /bin/chmod 0640 /etc/group- 2>/dev/null || log "UNEXPECTED: Could not change group- file permissions"
    chroot $mountPoint /bin/chmod 0404 /etc/hostname 2>/dev/null || log "UNEXPECTED: Could not change hostname file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/hosts 2>/dev/null || log "UNEXPECTED: Could not change hosts file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/inittab 2>/dev/null || log "UNEXPECTED: Could not change inittab file permissions"
    chroot $mountPoint /bin/chmod 0404 /etc/inputrc 2>/dev/null || log "UNEXPECTED: Could not change inputrc file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/issue 2>/dev/null || log "UNEXPECTED: Could not change issue file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/mdev.conf 2>/dev/null || log "UNEXPECTED: Could not change mdev.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/mke2fs.conf 2>/dev/null || log "UNEXPECTED: Could not change mke2fs.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/modules 2>/dev/null || log "UNEXPECTED: Could not change modules file permissions"
    chroot $mountPoint /bin/chmod 0404 /etc/motd 2>/dev/null || log "UNEXPECTED: Could not change modules file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/nsswitch.conf 2>/dev/null || log "UNEXPECTED: Could not change nsswitch.conf file permissions"
    chroot $mountPoint /bin/chmod 0604 /etc/passwd 2>/dev/null || log "UNEXPECTED: Could not change passwd file permissions"
    chroot $mountPoint /bin/chmod 0604 /etc/passwd- 2>/dev/null || log "UNEXPECTED: Could not change passwd- file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/profile 2>/dev/null || log "UNEXPECTED: Could not change profile file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/protocols 2>/dev/null || log "UNEXPECTED: Could not change protocols file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/rc.conf 2>/dev/null || log "UNEXPECTED: Could not change rc.conf file permissions"
    chroot $mountPoint /bin/chmod 0404 /etc/resolv.conf 2>/dev/null || log "UNEXPECTED: Could not change resolv.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/securetty 2>/dev/null || log "UNEXPECTED: Could not change /etc/securetty file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/services 2>/dev/null || log "UNEXPECTED: Could not change services file permissions"
    chroot $mountPoint /bin/chmod 0640 /etc/shadow 2>/dev/null || log "UNEXPECTED: Could not change shadow file permissions"
    chroot $mountPoint /bin/chmod 0640 /etc/shadow- 2>/dev/null || log "UNEXPECTED: Could not change shadow- file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/shells 2>/dev/null || log "UNEXPECTED: Could not change shells file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/sysctl.conf 2>/dev/null || log "UNEXPECTED: Could not change sysctl.conf file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/default/grub 2>/dev/null || log "UNEXPECTED: Could not change /etc/default/grub file permissions"
    chroot $mountPoint /bin/chmod 0550 /etc/acpi/PWRF/00000080 2>/dev/null || log "UNEXPECTED: Could not change /etc/acpi/PWRF/00000080 file permissions"
    chroot $mountPoint /bin/chmod 0600 /etc/apk/arch 2>/dev/null || log "UNEXPECTED: Could not change /etc/apk/arch file permissions"
    chroot $mountPoint /bin/chmod 0400 /etc/apk/repositories 2>/dev/null || log "UNEXPECTED: Could not change /etc/apk/repositories file permissions"
    chroot $mountPoint /bin/chmod 0644 /etc/apk/world 2>/dev/null || log "UNEXPECTED: Could not change /etc/apk/world file permissions to there default"
    chroot $mountPoint /bin/chmod 0644 /etc/busybox-paths.d/busybox 2>/dev/null || log "UNEXPECTED: Could not change /etc/busybox-paths.d/busybox file permissions"
    chroot $mountPoint /bin/chmod 0604 /etc/chrony/chrony.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/chrony/chrony.conf file permissions"
    chroot $mountPoint /bin/chmod 0600 /etc/crontabs/root 2>/dev/null || log "UNEXPECTED: Could not change /etc/crontabs/root file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/grub.d/00_header 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d/00_header file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/grub.d/10_linux 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d/10_linux file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/grub.d/20_linux_xen 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d/20_linux_xen file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/grub.d/25_bli 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d/25_bli file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/grub.d/30_os-prober 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d/30_os-prober file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/grub.d/30_uefi-firmware 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d/30_uefi-firmware file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/grub.d/40_custom 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d/40_custom file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/grub.d/41_custom 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d/41_custom file permissions"
    chroot $mountPoint /bin/chmod 0600 /etc/keymap/us.bmap.gz 2>/dev/null || log "UNEXPECTED: Could not change /etc/keymap/us.bmap.gz file permissions"
    chroot $mountPoint /bin/chmod 0600 /etc/lvm/lvm.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/lvm/lvm.conf file permissions"
    chroot $mountPoint /bin/chmod 0600 /etc/lvm/lvmlocal.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/lvm/lvmlocal.conf file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/network/if-pre-up.d/bridge 2>/dev/null || log "UNEXPECTED: Could not change /etc/network/if-pre-up.d/bridge file permissions"
    chroot $mountPoint /bin/chmod 0750 /etc/network/if-up.d/dad 2>/dev/null || log "UNEXPECTED: Could not change /etc/network/if-up.d/dad file permissions"
    chroot $mountPoint /bin/chmod 0600 /etc/secfixes.d/alpine 2>/dev/null || log "UNEXPECTED: Could not change /etc/secfixes.d/alpine file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/acpid 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/acpid file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/atd 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/atd file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/binfmt 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/binfmt file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/bootmisc 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/bootmisc file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/cgroups 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/cgroups file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/chronyd 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/chronyd file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/consolefont 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/consolefont file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/crond 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/crond file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/devfs 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/devfs file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/dmesg 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/dmesg file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/fail2ban 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/fail2ban file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/firstboot 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/firstboot file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/fsck 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/fsck file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/hostname 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/hostname file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/hwclock 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/hwclock file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/hwdrivers 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/hwdrivers file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/killprocs 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/killprocs file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/klogd 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/klogd file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/loadkmap 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/loadkmap file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/local 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/local file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/localmount 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/localmount file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/loopback 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/loopback file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/lvm 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/lvm file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/machine-id 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/machine-id file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/mdev 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/mdev file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/modloop 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/modloop file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/modules 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/modules file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/mount-ro 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/mount-ro file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/mtab 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/mtab file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/net-online 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/net-online file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/netmount 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/netmount file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/networking 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/networking file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/ntpd 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/ntpd file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/numlock 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/numlock file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/osclock 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/osclock file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/procfs 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/procfs file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/rdate 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/rdate file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/root 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/root file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/runsvdir 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/runsvdir file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/s6-svscan 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/s6-svscan file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/save-keymaps 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/save-keymaps file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/save-termencoding 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/save-termencoding file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/savecache 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/savecache file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/seedrng 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/seedrng file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sshd 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sshd file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sshdStatus file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sshdBackup file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sshdCommand file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sshdLog 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sshdLog file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sshdExtract 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sshdExtract file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/staticroute 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/staticroute file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/swap 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/swap file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/swclock 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/swclock file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sysctl 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sysctl file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sysfs 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sysfs file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/sysfsconf 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/sysfsconf file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/syslog 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/syslog file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/termencoding 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/termencoding file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/user 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/user file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/watchdog 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/watchdog file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/doas.d/daemon.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/doas.d/daemon.conf file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/doas.d/tempUser.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/doas.d/tempUser.conf file permissions"
    chroot $mountPoint /bin/chmod 0000 /etc/ssh/sshd_config 2>/dev/null || log "UNEXPECTED: Could not change /etc/ssh/sshd_config permissions to readable"
    chroot $mountPoint /bin/chmod 0440 /etc/ssh/ssh_config 2>/dev/null || log "UNEXPECTED: Could not change /etc/ssh/ssh_config permissions to readable"
    chroot $mountPoint /bin/chmod 0440 /etc/ssh/moduli 2>/dev/null || log "UNEXPECTED: Could not change moduli's permission to readable"
    chroot $mountPoint /bin/chmod 0440 /etc/default/ufw 2>/dev/null || log "UNEXPECTED: Could not change /etc/default/ufw permissions to readable"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/ssh 2>/dev/null || log "UNEXPECTED: Could not change ssh profile permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/sshTemp 2>/dev/null || log "UNEXPECTED: Could not change temp ssh profile permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/apk 2>/dev/null || log "UNEXPECTED: Could not change apk profile permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/ntp 2>/dev/null || log "UNEXPECTED: Could not change ntp profile permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/dns 2>/dev/null || log "UNEXPECTED: Could not change dns profile permissions"
    chroot $mountPoint /bin/chmod 0550 /etc/ufw/before.init 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/before.init"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/before.rules 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/before.rules"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/before6.rules 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/before6.rules"
    chroot $mountPoint /bin/chmod 0550 /etc/ufw/after.init 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/after.init"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/after.rules 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/after.rules"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/after6.rules 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/after6.rules"
    chroot $mountPoint /bin/chmod 0640 /etc/ufw/user.rules 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/user.rules"
    chroot $mountPoint /bin/chmod 0640 /etc/ufw/user6.rules 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/user6.rules"
    chroot $mountPoint /bin/chmod 0640 /etc/ufw/ufw.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/ufw.conf"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/sysctl.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/sysctl.conf"
    chroot $mountPoint /bin/chmod 0440 /etc/ethertypes 2>/dev/null || log "UNEXPECTED: Could not change ethertypes file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/nftables.nft 2>/dev/null || log "UNEXPECTED: Could not change nftables.nft file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/ufw 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/ufw file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/nftables 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/nftables file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/iptables 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/iptables file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/ip6tables 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/ip6tables file permissions"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/ebtables 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d/ebtables file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/fail2ban/jail.conf 2>/dev/null || log "UNEXPECTED: Could not change original jail permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/fail2ban/paths-common.conf 2>/dev/null || log "UNEXPECTED: Could not change common-paths permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/fail2ban/paths-debian.conf 2>/dev/null || log "UNEXPECTED: Could not change debian-paths permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/logrotate.conf 2>/dev/null || log "UNEXPECTED: Could not change logrotate.conf file permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/fail2ban/jail.d/alpine-ssh.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/fail2ban/jail.d/alpine-ssh.conf permissions"
    chroot $mountPoint /bin/chmod 0440 /etc/fail2ban/jail.local 2>/dev/null || log "UNEXPECTED: Could not change local jail permissions to readable"
    chroot $mountPoint /bin/chmod 0440 /etc/fail2ban/fail2ban.conf 2>/dev/null || log "UNEXPECTED: Could not change fail2ban configuration file permissions to readable"
    chroot $mountPoint /bin/chmod 00550 /etc/acpi 2>/dev/null || log "UNEXPECTED: Could not change /etc/acpi directory permissions"
    chroot $mountPoint /bin/chmod 00550 /etc/acpi/PWRF 2>/dev/null || log "UNEXPECTED: Could not change /etc/acpi/PWRF directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/apk 2>/dev/null || log "UNEXPECTED: Could not change /etc/apk directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/apk/keys 2>/dev/null || log "UNEXPECTED: Could not change /etc/apk/keys directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/apk/protected_paths.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/apk/protected_paths.d directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/busybox-paths.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/busybox-paths.d directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/chrony 2>/dev/null || log "UNEXPECTED: Could not change /etc/chrony directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/conf.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/conf.d directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/crontabs 2>/dev/null || log "UNEXPECTED: Could not change /etc/crontabs directory permissions"
    chroot $mountPoint /bin/chmod 00701 /etc/default 2>/dev/null || log "UNEXPECTED: Could not change /etc/default directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/grub.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/grub.d directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/init.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/init.d directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/keymap 2>/dev/null || log "UNEXPECTED: Could not change /etc/keymap directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/lbu 2>/dev/null || log "UNEXPECTED: Could not change /etc/lbu directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/local.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/local.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/logrotate.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/logrotate.d directory permissions"
    chroot $mountPoint /bin/chmod 00710 /etc/lvm 2>/dev/null || log "UNEXPECTED: Could not change /etc/lvm directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/lvm/archive 2>/dev/null || log "UNEXPECTED: Could not change /etc/lvm/archive directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/lvm/backup 2>/dev/null || log "UNEXPECTED: Could not change /etc/lvm/backup directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/lvm/profile 2>/dev/null || log "UNEXPECTED: Could not change /etc/lvm/profile directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/mkinitfs 2>/dev/null || log "UNEXPECTED: Could not change /etc/mkinitfs directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/mkinitfs/features.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/mkinitfs/features.d directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/modprobe.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/modprobe.d directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/modules-load.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/modules-load.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/network 2>/dev/null || log "UNEXPECTED: Could not change /etc/network directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/network/if-down.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/network/if-down.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/network/if-post-down.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/network/if-post-down.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/network/if-post-up.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/network/if-post-up.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/network/if-pre-down.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/network/if-pre-down.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/network/if-pre-up.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/network/if-pre-up.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/network/if-up.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/network/if-up.d directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/opt 2>/dev/null || log "UNEXPECTED: Could not change /etc/opt directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/periodic 2>/dev/null || log "UNEXPECTED: Could not change /etc/periodic directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/periodic/15min 2>/dev/null || log "UNEXPECTED: Could not change /etc/periodic/15min permission"
    chroot $mountPoint /bin/chmod 00700 /etc/periodic/daily 2>/dev/null || log "UNEXPECTED: Could not change /etc/periodic/daily permission"
    chroot $mountPoint /bin/chmod 00700 /etc/periodic/hourly 2>/dev/null || log "UNEXPECTED: Could not change /etc/periodic/hourly permission"
    chroot $mountPoint /bin/chmod 00700 /etc/periodic/monthly 2>/dev/null || log "UNEXPECTED: Could not change /etc/periodic/monthly permission"
    chroot $mountPoint /bin/chmod 00700 /etc/periodic/weekly 2>/dev/null || log "UNEXPECTED: Could not change /etc/periodic/weekly permission"
    chroot $mountPoint /bin/chmod 00000 /etc/pkcs11 2>/dev/null || log "UNEXPECTED: Could not change /etc/pkcs11 directory permissions"
    chroot $mountPoint /bin/chmod 00500 /etc/profile.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/profile.d directory permissions"
    chroot $mountPoint /bin/chmod 00705 /etc/runlevels 2>/dev/null || log "UNEXPECTED: Could not change /etc/runlevels directory permissions"
    chroot $mountPoint /bin/chmod 00705 /etc/runlevels/boot 2>/dev/null || log "UNEXPECTED: Could not change /etc/runlevels/boot directory permissions"
    chroot $mountPoint /bin/chmod 00705 /etc/runlevels/default 2>/dev/null || log "UNEXPECTED: Could not change /etc/runlevels/default directory permissions"
    chroot $mountPoint /bin/chmod 00705 /etc/runlevels/nonetwork 2>/dev/null || log "UNEXPECTED: Could not change /etc/runlevels/nonetwork directory permissions"
    chroot $mountPoint /bin/chmod 00705 /etc/runlevels/shutdown 2>/dev/null || log "UNEXPECTED: Could not change /etc/runlevels/shutdown directory permissions"
    chroot $mountPoint /bin/chmod 00705 /etc/runlevels/sysinit 2>/dev/null || log "UNEXPECTED: Could not change /etc/runlevels/sysinit directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/secfixes.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/secfixes.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/ssh 2>/dev/null || log "UNEXPECTED: Could not change /etc/ssh directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/ssl 2>/dev/null || log "UNEXPECTED: Could not change /etc/ssl directory permissions"
    chroot $mountPoint /bin/chmod 00700 /etc/ssl1.1 2>/dev/null || log "UNEXPECTED: Could not change /etc/ssl1.1 directory permissions"
    chroot $mountPoint /bin/chmod 00500 /etc/sysctl.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/sysctl.d directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/a 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/a directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/d 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/d directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/g 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/g directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/k 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/k directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/l 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/l directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/p 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/p directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/r 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/r directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/s 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/s directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/t 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/t directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/v 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/v directory permissions"
    chroot $mountPoint /bin/chmod 00755 /etc/terminfo/x 2>/dev/null || log "UNEXPECTED: Could not change /etc/terminfo/x directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/udhcpc 2>/dev/null || log "UNEXPECTED: Could not change /etc/udhcpc directory permissions"
    chroot $mountPoint /bin/chmod 00500 /etc/zoneinfo 2>/dev/null || log "UNEXPECTED: Could not change /etc/zoneinfo directory permissions"
    chroot $mountPoint /bin/chmod 00510 /etc/doas.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/doas.d directory permissions"
    chroot $mountPoint /bin/chmod 00500 /etc/security 2>/dev/null || log "UNEXPECTED: Could not change /etc/security directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/security/limits.d 2>/dev/null 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/limits.dy directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/security/namespace.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/security/namespace.d directory permissions"
    chroot $mountPoint /bin/chmod 00500 /etc/pam.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/pam.d directory permissions"
    chroot $mountPoint /bin/chmod 00640 /etc/at.allow 2>/dev/null || log "UNEXPECTED: Could not change /etc/at.allow directory permissions"
    chroot $mountPoint /bin/chmod 00550 /etc/acpi/events 2>/dev/null || log "UNEXPECTED: Could not change /etc/acpi/events directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/ssh/ssh_config.d 2>/dev/null || log "UNEXPECTED: Could not change ssh_config.d directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/ssh/sshd_config.d 2>/dev/null || log "UNEXPECTED: Could not change sshd_config.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/ssh 2>/dev/null || log "UNEXPECTED: Could not change ssh directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/ufw 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/ufw/applications.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/ufw/applications.d permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/iptables 2>/dev/null || log "UNEXPECTED: Could not change /etc/iptables directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/nftables.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/nftables.d directory permissions"
    chroot $mountPoint /bin/chmod 00000 /etc/fail2ban/fail2ban.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/fail2ban/fail2ban.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/fail2ban/action.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/fail2ban/action.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/fail2ban/filter.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/fail2ban/filter.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/fail2ban/jail.d 2>/dev/null || log "UNEXPECTED: Could not change /etc/fail2ban/jail.d directory permissions"
    chroot $mountPoint /bin/chmod 00750 /etc/fail2ban 2>/dev/null || log "UNEXPECTED: Could not change /etc/fail2ban directory permissions"
# /etc/pam.d/chfn
# /etc/pam.d/chpasswd
# /etc/pam.d/chsh
# /etc/pam.d/groupmems
# /etc/pam.d/newusers
# /etc/pam.d/shadow-utils
# /etc/security/access.conf
# /etc/security/faillock.conf
# /etc/security/group.conf
# /etc/security/limits.conf
# /etc/security/limits.d
# /etc/security/namespace.conf
# /etc/security/namespace.d
# /etc/security/namespace.init
# /etc/security/pam_env.conf
# /etc/security/pwhistory.conf
# /etc/security/time.conf

    log "INFO: Changing anything else remaining in /usr"
# /usr/lib/pam.d/base-account
# /usr/lib/pam.d/base-auth
# /usr/lib/pam.d/base-password
# /usr/lib/pam.d/base-session
# /usr/lib/pam.d/base-session-noninteractive
# /usr/lib/pam.d/login
# /usr/lib/pam.d/other
# /usr/lib/pam.d/su
# /usr/lib/security/pam_access.so
# /usr/lib/security/pam_canonicalize_user.so
# /usr/lib/security/pam_debug.so
# /usr/lib/security/pam_deny.so
# /usr/lib/security/pam_echo.so
# /usr/lib/security/pam_env.so
# /usr/lib/security/pam_exec.so
# /usr/lib/security/pam_faildelay.so
# /usr/lib/security/pam_faillock.so
# /usr/lib/security/pam_filter
# /usr/lib/security/pam_filter.so
# /usr/lib/security/pam_ftp.so
# /usr/lib/security/pam_group.so
# /usr/lib/security/pam_issue.so
# /usr/lib/security/pam_keyinit.so
# /usr/lib/security/pam_limits.so
# /usr/lib/security/pam_listfile.so
# /usr/lib/security/pam_localuser.so
# /usr/lib/security/pam_loginuid.so
# /usr/lib/security/pam_mail.so
# /usr/lib/security/pam_mkhomedir.so
# /usr/lib/security/pam_motd.so
# /usr/lib/security/pam_namespace.so
# /usr/lib/security/pam_nologin.so
# /usr/lib/security/pam_permit.so
# /usr/lib/security/pam_pwhistory.so
# /usr/lib/security/pam_rootok.so
# /usr/lib/security/pam_securetty.so
# /usr/lib/security/pam_setquota.so
# /usr/lib/security/pam_shells.so
# /usr/lib/security/pam_stress.so
# /usr/lib/security/pam_succeed_if.so
# /usr/lib/security/pam_time.so
# /usr/lib/security/pam_timestamp.so
# /usr/lib/security/pam_umask.so
# /usr/lib/security/pam_unix.so
# /usr/lib/security/pam_usertype.so
# /usr/lib/security/pam_warn.so
# /usr/lib/security/pam_wheel.so
# /usr/lib/security/pam_xauth.so
    chroot $mountPoint /bin/chmod 0640 /usr/lib/os-release 2>/dev/null || log "UNEXPECTED: Could not change /usr/lib/os-release file permissions for /etc/os-release"
    chroot $mountPoint /bin/chmod 0750 /usr/lib/ufw 2>/dev/null || log "UNEXPECTED: Could not change /usr/lib/ufw file permissions"
    chroot $mountPoint /bin/chmod 0750 /usr/lib/ufw/ufw-init 2>/dev/null || log "UNEXPECTED: Could not change /usr/lib/ufw/ufw-init file permissions"
    chroot $mountPoint /bin/chmod 0750 /usr/lib/ufw/ufw-init-functions 2>/dev/null || log "UNEXPECTED: Could not change /usr/lib/ufw/ufw-init-functions file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/lib/ssh/sftp-server 2>/dev/null || log "UNEXPECTED: Could not change /usr/lib/ssh/sftp-server file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/lib/ssh/ssh-pkcs11-helper 2>/dev/null || log "UNEXPECTED: Could not change /usr/lib/ssh/ssh-pkcs11-helper file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/lib/ssh/sshd-auth 2>/dev/null || log "UNEXPECTED: Could not change /usr/lib/ssh/sshd-auth file permissions"
    chroot $mountPoint /bin/chmod 0510 /usr/lib/ssh/sshd-session 2>/dev/null || log "UNEXPECTED: Could not change /usr/lib/ssh/sshd-session file permissions"
    chroot $mountPoint /bin/chmod 0444 "/usr/share/zoneinfo/$timezone" 2>/dev/null || log "UNEXPECTED: Could not change /usr/share/zoneinfo/$timezone file permissions for /etc/localtime"

    log "INFO: Changing anything else remaining in /var"
    chroot $mountPoint /bin/mkdir -p /var/run/acpid 2>/dev/null || log "UNEXPECTED: Could not create directory for acpid pid file"
    chroot $mountPoint /bin/mkdir -p /var/run/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not create directory for $previewUsername sshd pid file"
    chroot $mountPoint /bin/mkdir -p /var/run/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not create directory for $backupUsername sshd pid file"
    chroot $mountPoint /bin/mkdir -p /var/run/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not create directory for $serverCommandUsername sshd pid file"
    chroot $mountPoint /bin/mkdir -p /var/run/sshdLog 2>/dev/null || log "UNEXPECTED: Could not create directory for sshd $monitorUsername pid file"
    chroot $mountPoint /bin/mkdir -p /var/run/sshdExtract 2>/dev/null || log "UNEXPECTED: Could not create directory for sshd $extractUsername pid file"
    chroot $mountPoint /bin/mkdir -p /var/run/fail2ban 2>/dev/null || log "UNEXPECTED: Could not create directory for fail2ban pid file"
    chroot $mountPoint /bin/chmod 00750 /var/run/acpid 2>/dev/null || log "UNEXPECTED: Could not change /var/run/acpid directory permissions"
    chroot $mountPoint /bin/chmod 00750 /var/run/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not change /var/run/sshdStatus directory permissions"
    chroot $mountPoint /bin/chmod 00750 /var/run/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not change /var/run/sshdBackup directory permissions"
    chroot $mountPoint /bin/chmod 00750 /var/run/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not change /var/run/sshdCommand directory permissions"
    chroot $mountPoint /bin/chmod 00750 /var/run/sshdLog 2>/dev/null || log "UNEXPECTED: Could not change /var/run/sshdLog directory permissions"
    chroot $mountPoint /bin/chmod 00750 /var/run/sshdExtract 2>/dev/null || log "UNEXPECTED: Could not change /var/run/sshdExtract directory permissions"
    chroot $mountPoint /bin/touch /var/log/sshdStatus.log 2>/dev/null || log "UNEXPECTED: Could not generate a log file meant for sshd service whom $previewUsername is user"
    chroot $mountPoint /bin/touch /var/log/sshdBackup.log 2>/dev/null || log "UNEXPECTED: Could not generate a log file meant for sshd service whom $backupUsername is user"
    chroot $mountPoint /bin/touch /var/log/sshdCommand.log 2>/dev/null || log "UNEXPECTED: Could not generate a log file meant for sshd service whom $serverCommandUsername is user"
    chroot $mountPoint /bin/touch /var/log/sshdLog.log 2>/dev/null || log "UNEXPECTED: Could not generate a log file meant for sshd service whom $monitorUsername is user"
    chroot $mountPoint /bin/touch /var/log/sshdExtract.log 2>/dev/null || log "UNEXPECTED: Could not generate a log file meant for sshd service whom $extractUsername is user"
    chroot $mountPoint /bin/chmod 0240 /var/log/sshdStatus.log 2>/dev/null || log "UNEXPECTED: Could not change /var/log/sshdStatus.log file permissions"
    chroot $mountPoint /bin/chmod 0240 /var/log/sshdBackup.log 2>/dev/null || log "UNEXPECTED: Could not change /var/log/sshdBackup.log file permissions"
    chroot $mountPoint /bin/chmod 0240 /var/log/sshdCommand.log 2>/dev/null || log "UNEXPECTED: Could not change /var/log/sshdCommand.log file permissions"
    chroot $mountPoint /bin/chmod 0240 /var/log/sshdLog.log 2>/dev/null || log "UNEXPECTED: Could not change /var/log/sshdLog.log file permissions"
    chroot $mountPoint /bin/chmod 0240 /var/log/sshdExtract.log 2>/dev/null || log "UNEXPECTED: Could not change /var/log/sshdExtract.log file permissions"
    chroot $mountPoint /bin/chmod 0440 /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$previewUsername/$previewUsername-sshd.conf file permissions"
    chroot $mountPoint /bin/chmod 0440 /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$backupUsername/$backupUsername-sshd.conf file permissions"
    chroot $mountPoint /bin/chmod 0440 /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf file permissions"
    chroot $mountPoint /bin/chmod 0440 /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$monitorUsername/$monitorUsername-sshd.conf file permissions"
    chroot $mountPoint /bin/chmod 0440 /home/.keys/$extractUsername/$extractUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$extractUsername/$extractUsername-sshd.conf file permissions"
    chroot $mountPoint /bin/chmod 0750 /var/run/fail2ban 2>/dev/null || log "UNEXPECTED: Could not change /var/run/fail2ban directory permissions"
    chroot $mountPoint /bin/chmod 0240 /var/log/acpid.log 2>/dev/null || log "UNEXPECTED: Could not change /var/log/acpid.log file permissions"
    chroot $mountPoint /bin/touch /var/log/chronyd.log 2>/dev/null || log "UNEXPECTED: Could not generate a log file for chronyd service"
    chroot $mountPoint /bin/chmod 0240 /var/log/chronyd.log 2>/dev/null || log "UNEXPECTED: Could not change /var/log/chronyd.log file permissions"
    chroot $mountPoint /bin/touch /var/log/fail2ban.log 2>/dev/null || log "UNEXPECTED: Could not generate a log file for fail2ban service"
    chroot $mountPoint /bin/chmod 240 /var/log/fail2ban.log 2>/dev/null || log "UNEXPECTED: Could not change /var/log/fail2ban.log file permissions"
    chroot $mountPoint /bin/chmod 0640 /var/log/messages 2>/dev/null || log "UNEXPECTED: Could not change /var/log/messages file permissions"
    chroot $mountPoint /bin/chmod 0460 /var/lib/fail2ban/fail2ban.sqlite3 2>/dev/null || log "UNEXPECTED: Could not change /var/lib/fail2ban/fail2ban.sqlite3 file permissions"

    log "INFO: Setting home files and directories"
    chroot $mountPoint /bin/chmod 00500 /root 2>/dev/null || log "UNEXPECTED: Could not change /root directory permissions to read only"
    chroot $mountPoint /bin/chmod 00550 "/home/.keys" 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/ directory permissions"
        # Permissions of: SSH authorization directories, SSH authorization file
    for i in $extractUsername $monitorUsername $previewUsername $serverCommandUsername $backupUsername; do # For each user, ensure the following is owned by them
        chroot $mountPoint /bin/chmod 00500 "/home/$i" 2>/dev/null || log "UNEXPECTED: Could not change /home/$i directory permissions to read only"
        chroot $mountPoint /bin/chmod 00501 "/home/.keys/$i/" 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$i/ directory permissions"
        chroot $mountPoint /bin/chmod 0404 "/home/.keys/$i/authorized_keys" 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$i/authorized_keys file permission"
        chroot $mountPoint /bin/chmod 0400 "/home/.keys/$i/ssh_host_$i-key" 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$i/ssh_host_$i-key file permission"
        chroot $mountPoint /bin/chmod 0400 "/home/.keys/$i/ssh_host_$i-key.pub" 2>/dev/null || log "UNEXPECTED: Could not change /home/.keys/$i/ssh_host_$i-key.pub file permission"
    done
	# SSH private key permissions for each user
    for i in $monitorUsername $previewUsername $serverCommandUsername $backupUsername; do # For each user, ensure the following is owned by them
        chroot $mountPoint /bin/chmod 0400 "/home/$extractUsername/$localhostName.$i-key" 2>/dev/null || log "UNEXPECTED: Could not change /home/$extractUsername/$localhostName.$i-key file permissions"
    done

    log "INFO: Finalalizing directory permissions"
    chroot $mountPoint /bin/chmod 00701 /bin 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /bin"
    chroot $mountPoint /bin/chmod 00701 /sbin 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /sbin"
    chroot $mountPoint /bin/chmod 00701 /usr 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /usr"
    chroot $mountPoint /bin/chmod 00701 /usr/bin/ 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /usr/bin"
    chroot $mountPoint /bin/chmod 00701 /usr/sbin/ 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /usr/sbin"
    chroot $mountPoint /bin/chmod 00751 /etc 2>/dev/null || log "UNEXPECTED: Could not make it harder to use /etc directory"
    chroot $mountPoint /bin/chmod 00701 /var 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /var"
    chroot $mountPoint /bin/chmod 00501 /home 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /home"
    chroot $mountPoint /bin/chmod 00500 /root 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /root"
    
    log "INFO: Changing ownership of certain files and directories"
        # Chrony
    chroot $mountPoint /bin/chown root:chrony /usr/sbin/chronyd 2>/dev/null || log "UNEXPECTED: Could not change ownership of /usr/sbin/chronyd"
    chroot $mountPoint /bin/chown chrony:logread /var/log/chronyd.log 2>/dev/null || log "UNEXPECTED: Could not change ownership of /var/log/chronyd.log to chrony:logread"
	# acpid 
    chroot $mountPoint /bin/chown "root:$powerUsername" /sbin/acpid 2>/dev/null || log "UNEXPECTED: Could not change ownership of /sbin/acpid"
    chroot $mountPoint /bin/chown "root:$powerUsername" /usr/bin/acpi_listen 2>/dev/null || log "UNEXPECTED: Could not change ownership of /usr/bin/acpi_listen"
    chroot $mountPoint /bin/chown "root:$powerUsername" /usr/sbin/kacpimon 2>/dev/null || log "UNEXPECTED: Could not change ownership of /usr/sbin/kacpimon"
    chroot $mountPoint /bin/chown "root:$powerUsername" /etc/acpi 2>/dev/null || log "UNEXPECTED: Could not change ownership of /etc/acpi"
    chroot $mountPoint /bin/chown "root:$powerUsername" /etc/acpi/events 2>/dev/null || log "UNEXPECTED: Could not change ownership of /etc/acpi/events"
    chroot $mountPoint /bin/chown "root:$powerUsername" /etc/acpi/events/anything 2>/dev/null || log "UNEXPECTED: Could not change ownership of /etc/acpi/events/anything"
    chroot $mountPoint /bin/chown "root:$powerUsername" /etc/acpi/PWRF 2>/dev/null || log "UNEXPECTED: Could not change ownership of /etc/acpi/PWRF"
    chroot $mountPoint /bin/chown "root:$powerUsername" /etc/acpi/PWRF/00000080 2>/dev/null || log "UNEXPECTED: Could not change ownership of /etc/acpi/00000080"
    chroot $mountPoint /bin/chown "root:$powerUsername" /etc/acpi/handler.sh 2>/dev/null || log "UNEXPECTED: Could not change ownership of /etc/acpi/handler.sh"
    chroot $mountPoint /bin/chown "$powerUsername:logread" /var/log/acpid.log 2>/dev/null || log "UNEXPECTED: Could not change ownership of /var/log/acpid.log to chrony:logread"
    chroot $mountPoint /bin/chown "$powerUsername:$powerUsername" /var/run/acpid 2>/dev/null || log "UNEXPECTED: Could not change ownership of /var/run/acpid"
         # sshd
    chroot $mountPoint /bin/chown root:root /etc/ssh/sshd_config 2>/dev/null || log "UNEXPECTED: Could not change ownership of sshd_config"
    chroot $mountPoint /bin/chown root:root /etc/ssh/ssh_config.d 2>/dev/null || log "UNEXPECTED: Could not change ownership of ssh_config.d"
    chroot $mountPoint /bin/chown root:root /etc/ssh/sshd_config.d 2>/dev/null || log "UNEXPECTED: Could not change ownership of sshd_config.d"
    chroot $mountPoint /bin/chown root:root /etc/init.d/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not change ownership of sshdStatus"
    chroot $mountPoint /bin/chown root:root /etc/init.d/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not change ownership of sshdBackup"
    chroot $mountPoint /bin/chown root:root /etc/init.d/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not change ownership of sshdCommand"
    chroot $mountPoint /bin/chown root:root /etc/init.d/sshdLog 2>/dev/null || log "UNEXPECTED: Could not change ownership of sshdLog"
    chroot $mountPoint /bin/chown root:root /etc/init.d/sshdExtract 2>/dev/null || log "UNEXPECTED: Could not change ownership of sshdExtract"
    chroot $mountPoint /bin/chown root:sshexec /usr/sbin/sshd 2>/dev/null || log "UNEXPECTED: Could not change ownership of /usr/sbin/sshd"
    chroot $mountPoint /bin/chown root:sshexec /usr/sbin/sshd 2>/dev/null || log "UNEXPECTED: Could not change ownership of /usr/sbin/sshd"
    chroot $mountPoint /bin/chown root:sshexec /etc/ssh 2>/dev/null || log "UNEXPECTED: Could not change ownership of ssh_config"
    chroot $mountPoint /bin/chown root:sshexec /etc/ssh/moduli 2>/dev/null || log "UNEXPECTED: Could not change ownership of moduli"
    chroot $mountPoint /bin/chown root:root /etc/ssh/sshd_config.d 2>/dev/null || log "UNEXPECTED: Could not change ownership of sshd_config.d"
    chroot $mountPoint /bin/chown root:sshsftp /usr/lib/ssh/sftp-server 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/lib/ssh/sftp-server"
    chroot $mountPoint /bin/chown root:sshexec /usr/lib/ssh/ssh-pkcs11-helper 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/lib/ssh/ssh-pkcs11-helper"
    chroot $mountPoint /bin/chown root:sshexec /usr/lib/ssh/sshd-auth 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/lib/ssh/sshd-auth"
    chroot $mountPoint /bin/chown root:sshexec /usr/lib/ssh/sshd-session 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/lib/ssh/sshd-session"
    chroot $mountPoint /bin/chown "$previewUsername:$previewUsername" /var/run/sshdStatus 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/run/sshdStatus"
    chroot $mountPoint /bin/chown "$backupUsername:$backupUsername" /var/run/sshdBackup 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/run/sshdBackup"
    chroot $mountPoint /bin/chown "$serverCommandUsername:$serverCommandUsername" /var/run/sshdCommand 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/run/sshdCommand"
    chroot $mountPoint /bin/chown "$monitorUsername:$monitorUsername" /var/run/sshdLog 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/run/sshdLog"
    chroot $mountPoint /bin/chown "$extractUsername:$extractUsername" /var/run/sshdExtract 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/run/sshdExtract"
    chroot $mountPoint /bin/chown "root:$previewUsername" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /home/.keys/$previewUsername/$previewUsername-sshd.conf"
    chroot $mountPoint /bin/chown "root:$backupUsername" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /home/.keys/$backupUsername/$backupUsername-sshd.conf"
    chroot $mountPoint /bin/chown "root:$serverCommandUsername" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf"
    chroot $mountPoint /bin/chown "root:$monitorUsername" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /home/.keys/$monitorUsername/$monitorUsername-sshd.conf"
    chroot $mountPoint /bin/chown "root:$extractUsername" /home/.keys/$extractUsername/$extractUsername-sshd.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /home/.keys/$extractUsername/$extractUsername-sshd.conf"
    chroot $mountPoint /bin/chown "$previewUsername:logread" /var/log/sshdStatus.log 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/log/sshdStatus.log"
    chroot $mountPoint /bin/chown "$backupUsername:logread" /var/log/sshdBackup.log 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/log/sshdBackup.log"
    chroot $mountPoint /bin/chown "$serverCommandUsername:logread" /var/log/sshdCommand.log 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/log/sshdCommand.log"
    chroot $mountPoint /bin/chown "$monitorUsername:logread" /var/log/sshdLog.log 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/log/sshdLog.log"
    chroot $mountPoint /bin/chown "$extractUsername:logread" /var/log/sshdExtract.log 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/log/sshdExtract.log"
        # ufw
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/applications.d 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/applications.d"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/applications.d/ssh 2>/dev/null || log "UNEXPECTED: Could not change ownership for; ssh profile"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/applications.d/sshTemp 2>/dev/null || log "UNEXPECTED: Could not change ownership for; temp ssh profile"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/applications.d/apk 2>/dev/null || log "UNEXPECTED: Could not change ownership for; apk profile"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/applications.d/ntp 2>/dev/null || log "UNEXPECTED: Could not change ownership for; ntp profile"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/applications.d/dns 2>/dev/null || log "UNEXPECTED: Could not change ownership for; dns profile"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/before.init 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/before.init"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/before.rules 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/before.rules"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/before6.rules 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/before6.rules"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/after.init 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/after.init"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/after.rules 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/after.rules"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/after6.rules 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/after6.rules"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/sysctl.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/sysctl.conf"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/default/ufw 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/default/ufw"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /usr/sbin/ufw 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/sbin/ufw"
    chroot $mountPoint /bin/chown "$firewallUsername:root" /usr/lib/ufw 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/lib/ufw"
    chroot $mountPoint /bin/chown "$firewallUsername:root" /usr/lib/ufw/ufw-init 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/lib/ufw/ufw-init"
    chroot $mountPoint /bin/chown "$firewallUsername:root" /usr/lib/ufw/ufw-init-functions 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/lib/ufw/ufw-init-functions"
    chroot $mountPoint /bin/chown "$firewallUsername:root" /etc/ufw/ufw.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/ufw.conf"
    chroot $mountPoint /bin/chown "$firewallUsername:root" /etc/ufw/user.rules 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/user.rules"
    chroot $mountPoint /bin/chown "$firewallUsername:root" /etc/ufw/user6.rules 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/user6.rules"
        # fail2ban
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /usr/bin/fail2ban-client 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/bin/fail2ban-client"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /usr/bin/fail2ban-server 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/bin/fail2ban-server"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /usr/bin/fail2ban-regex 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/bin/fail2ban-regex"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/fail2ban.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/fail2ban.conf"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/jail.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/jail.conf"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/jail.local 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/jail.local"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/paths-common.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/paths-common.conf"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/paths-debian.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/paths-debian.conf"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/fail2ban.d 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/fail2ban.d"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/action.d 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/action.d"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/filter.d 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/filter.d"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/jail.d 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/jail.d"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /etc/fail2ban/jail.d/alpine-ssh.conf 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/fail2ban/jail.d/alpine-ssh.conf"
    chroot $mountPoint /bin/chown "root:$fail2banUsername" /var/lib/fail2ban/fail2ban.sqlite3 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/lib/fail2ban/fail2ban.sqlite3"
    chroot $mountPoint /bin/chown "$fail2banUsername:logread" /var/log/fail2ban.log 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/log/fail2ban.log"
    chroot $mountPoint /bin/chown "$fail2banUsername:$fail2banUsername" /var/run/fail2ban 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/run/fail2ban"
        # General files used by more than one service
    chroot $mountPoint /bin/chown root:rshell /bin/rksh 2>/dev/null || log "UNEXPECTED: Could not change ownership of /bin/rksh file"
    chroot $mountPoint /bin/chown root:logread /var/log/messages 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/log/messages"
    chroot $mountPoint /bin/chown root:python /usr/bin/env 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/bin/env"
    chroot $mountPoint /bin/chown root:python /usr/bin/python3.12 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/bin/python3.12"
    chroot $mountPoint /bin/chown root:busybox /bin/busybox 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /bin/busybox"
    chroot $mountPoint /bin/chown root:iptables /usr/sbin/xtables-nft-multi 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/sbin/xtables-nft-multi"
    chroot $mountPoint /bin/chown root:logrotate /usr/sbin/logrotate 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /usr/sbin/logrotate"
    chroot $mountPoint /bin/chown root:readGroup /etc/group 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/group"
    chroot $mountPoint /bin/chown "$root:sshpub" "/home/.keys" 2>/dev/null || log "UNEXPECTED: Could not change ownership of /home/.keys"
        # Ownership of: SSH authorization directories, SSH authorization file
    for i in $extractUsername $monitorUsername $previewUsername $serverCommandUsername $backupUsername; do # For each user, ensure the following is owned by them
        chroot $mountPoint /bin/chown "$i:$i" "/home/.keys/$i" 2>/dev/null || log "UNEXPECTED: Could not change ownership of /home/.keys/$i"
        chroot $mountPoint /bin/chown "$i:$i" "/home/.keys/$i/authorized_keys" 2>/dev/null || log "UNEXPECTED: Could not change ownership of /home/.keys/$i/authorized_keys"
        chroot $mountPoint /bin/chown "$i:$i" "/home/.keys/$i/ssh_host_$i-key" 2>/dev/null || log "UNEXPECTED: Could not change ownership of /home/.keys/$i/ssh_host_$i-key"
        chroot $mountPoint /bin/chown "$i:$i" "/home/.keys/$i/ssh_host_$i-key.pub" 2>/dev/null || log "UNEXPECTED: Could not change ownership of /home/.keys/$i/ssh_host_$i-key.pub"
    done
	# SSH private key ownership for each user
    for i in $monitorUsername $previewUsername $serverCommandUsername $backupUsername; do # For each user, ensure the following is owned by them
        chroot $mountPoint /bin/chown "$extractUsername:$extractUsername" "/home/$extractUsername/$localhostName.$i-key" 2>/dev/null || log "UNEXPECTED: Could not change ownership of /home/$extractUsername/$localhostName.$i-key"
    done

    log "INFO: Granting root capabilities to certain executables" # Changing file ownership removes prior capabilities, thus is belongs here
    chroot $mountPoint /usr/sbin/setcap "cap_sys_time=pe" /usr/sbin/chronyd 2>/dev/null || log "CRITICAL: Could not give chronyd executable the capability to set system time"
    chroot $mountPoint /usr/sbin/setcap "cap_net_bind_service=ep" /usr/sbin/sshd 2>/dev/null || log "CRITICAL: Could not give sshd executable the permission to bind to system ports, change UID, and change GID"
    chroot $mountPoint /usr/sbin/setcap "cap_net_admin=pe" /usr/sbin/xtables-nft-multi 2>/dev/null || log "CRITICAL: Could not give xtables-nft-multi executable the capability to modify system firewall configurations"

    log "INFO: Recognizing rc service files"
    chroot $mountPoint /sbin/rc-update del sshd default 2>/dev/null || log "UNEXPECTED: Could not remove sshd from rc"
    chroot $mountPoint /sbin/rc-update add sshdStatus default 2>/dev/null || log "UNEXPECTED: Could not add sshdStatus to launch automatically"
    chroot $mountPoint /sbin/rc-update add sshdBackup default 2>/dev/null || log "UNEXPECTED: Could not add sshdBackup to launch automatically"
    chroot $mountPoint /sbin/rc-update add sshdCommand default 2>/dev/null || log "UNEXPECTED: Could not add sshdCommand to launch automatically"
    chroot $mountPoint /sbin/rc-update add sshdLog default 2>/dev/null || log "UNEXPECTED: Could not add sshdLog to launch automatically"
    chroot $mountPoint /sbin/rc-update add sshdExtract default 2>/dev/null || log "UNEXPECTED: Could not add sshdExtract to launch automatically"
    chroot $mountPoint /usr/sbin/ufw enable 2>/dev/null || log "UNEXPECTED: ufw could not be enabled"
    chroot $mountPoint /sbin/rc-update add ufw default 2>/dev/null || log "UNEXPECTED: Could not add ufw to launch automatically"
    chroot $mountPoint /sbin/rc-update add fail2ban default 2>/dev/null || log "INFO: Fail2ban was already added to boot"

    log "INFO: Restarting services"
    chroot $mountPoint /sbin/rc-service acpid restart || log "UNEXPECTED: Could not restart acpid daemon"
    chroot $mountPoint /sbin/rc-service chronyd restart || log "UNEXPECTED: Could not restart chronyd daemon"
#    chroot $mountPoint /sbin/rc-service sshdStatus restart || log "UNEXPECTED: Could not restart sshdStatus daemon"
#    chroot $mountPoint /sbin/rc-service sshdBackup restart || log "UNEXPECTED: Could not restart sshdBackup daemon"
#    chroot $mountPoint /sbin/rc-service sshdCommand restart || log "UNEXPECTED: Could not restart sshdCommand daemon"
#    chroot $mountPoint /sbin/rc-service sshdLog restart || log "UNEXPECTED: Could not restart sshdLog daemon"
#    chroot $mountPoint /sbin/rc-service sshdExtract restart || log "UNEXPECTED: Could not restart sshdExtract daemon"
    chroot $mountPoint /sbin/rc-service ufw restart 2>/dev/null || log "UNEXPECTED: Could not restart ufw daemon"
    chroot $mountPoint /sbin/rc-service fail2ban restart 2>/dev/null || log "UNEXPECTED: Could not restart fail2ban daemon"

    log "INFO: Successfully reached end of configurating users!"

# !!! SELinux
# Packages installed: policycoreutils@se libselinux@additional libsepol@additional libselinux-utils@additional
}

# !!!
configRemoteCapabilities() {
    log "INFO: One day"
}

# Needs scripting; kernel.yama.ptrace_scope, kernel.modules_disabled, user.max_user_namespaces?, kernel.warn_limit
verifyKernel() {
    local missing=0

    # Ownership check
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/maintain -user $buildUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong directory ownership for /home/maintain"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find "/home/maintain/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" -user $buildUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/maintain/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find "/home/maintain/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" -user $buildUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/maintain/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find "/home/maintain/aports/main/linux-lts/lts.$archType.config" -user $buildUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/maintain/aports/main/linux-lts/lts.$archType.config"; fi

    # Directory permission verification
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/maintain -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/maintain"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/maintain/aports -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/maintain/aports"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/maintain/aports/main -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/maintain/aports/main"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/maintain/aports/main/linux-lts -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/maintain/aports/main/linux-lts"; fi

    # Checking for sysctls based on KSPP (Kernel Self Protection Project): https://kspp.github.io/Recommended_Settings#kernel-command-line-options
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.kptr_restrict 2>/dev/null | awk '{print $3}' 2>/dev/null)" -lt "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.kptr_restrict 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.kptr_restrict is not greater or equal to 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.dmesg_restrict 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.dmesg_restrict 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.dmesg_restrict != 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.modules_disabled 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.modules_disabled 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.modules_disabled != 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.perf_event_paranoid 2>/dev/null | awk '{print $3}' 2>/dev/null)" -lt "2" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.perf_event_paranoid 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.perf_event_paranoid is not greater or equal to 2"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.kexec_load_disabled 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.kexec_load_disabled 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.kexec_load_disabled != 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.randomize_va_space 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "2" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.randomize_va_space 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.randomize_va_space != 2"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.yama.ptrace_scope 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "3" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.yama.ptrace_scope 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.yama.ptrace_scope != 3"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl user.max_user_namespaces 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "0" ] && [ -z "$(chroot $mountPoint /sbin/sysctl user.max_user_namespaces 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; user.max_user_namespaces != 0"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl dev.tty.ldisc_autoload 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "0" ] && [ -z "$(chroot $mountPoint /sbin/sysctl dev.tty.ldisc_autoload 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; dev.tty.ldisc_autoload != 0"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl dev.tty.legacy_tiocsti 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "0" ] && [ -z "$(chroot $mountPoint /sbin/sysctl dev.tty.legacy_tiocsti 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; dev.tty.legacy_tiocsti != 0"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.unprivileged_bpf_disabled 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.unprivileged_bpf_disabled 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.unprivileged_bpf_disabled != 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.warn_limit 2>/dev/null | awk '{print $3}' 2>/dev/null)" -lt "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.warn_limit 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.warn_limit is not greater or equal to 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl kernel.oops_limit 2>/dev/null | awk '{print $3}' 2>/dev/null)" -lt "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl kernel.oops_limit 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; kernel.oops_limit is not greater or equal to 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl net.core.bpf_jit_harden 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "2" ] && [ -z "$(chroot $mountPoint /sbin/sysctl net.core.bpf_jit_harden 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; net.core.bpf_jit_harden != 2"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl vm.unprivileged_userfaultfd 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "0" ] && [ -z "$(chroot $mountPoint /sbin/sysctl vm.unprivileged_userfaultfd 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; vm.unprivileged_userfaultfd != 0"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl fs.protected_symlinks 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl fs.protected_symlinks 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; fs.protected_symlinks != 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl fs.protected_hardlinks 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "1" ] && [ -z "$(chroot $mountPoint /sbin/sysctl fs.protected_hardlinks 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; fs.protected_hardlinks != 1"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl fs.protected_fifos 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "2" ] && [ -z "$(chroot $mountPoint /sbin/sysctl fs.protected_fifos 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; fs.protected_fifos != 2"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl fs.protected_regular 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "2" ] && [ -z "$(chroot $mountPoint /sbin/sysctl fs.protected_regular 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; fs.protected_regular != 2"; fi
    if [ "$(chroot $mountPoint /sbin/sysctl fs.suid_dumpable 2>/dev/null | awk '{print $3}' 2>/dev/null)" != "0" ] && [ -z "$(chroot $mountPoint /sbin/sysctl fs.suid_dumpable 2>&1 | grep unknown)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Active kernel has misconfiguration that was found in sysctl; fs.suid_dumpable != 0"; fi

    # Grub linux cmdline based on KSSP
    if [ -z "$(chroot $mountPoint /bin/grep 'modules=sd-mod,usb-storage,ext4 quiet rootfstype=ext4 hardened_usercopy=1 init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on page_alloc.shuffle=1 slab_nomerge pti=on nosmt hash_pointers=always slub_debug=ZF slub_debug=P page_poison=1 iommu.passthrough=0 iommu.strict=1 mitigations=auto,nosmt kfence.sample_interval=100' /etc/default/grub | grep 'GRUB_CMDLINE_LINUX_DEFAULT' 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Linux kernel command line has not been properely set in grub"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for kernel: $missing"; else echo "INFO: Not a single missed test for kernel!"; fi
}

verifyInstallSetup() {
    local missing=0

    # Verify setupAlpine()
    if [ ! -f "$mountPoint/etc/keymap/"$keyboardLayout".bmap.gz" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Keyboard layout not found or differs from expected value"; fi
    if [ "$(chroot $mountPoint /usr/bin/md5sum /usr/share/zoneinfo/$timezone 2>/dev/null | awk '{split($0,a); print(a[1])}')" != "$(chroot $mountPoint /usr/bin/md5sum /etc/localtime 2>/dev/null | awk '{split($0,a); print(a[1])}')" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Expected timezone is off or does not exist!"; fi
    if [ "$(chroot $mountPoint /bin/hostname 2>/dev/null)" != "localhost" ] && [ "$(hostname 2>/dev/null)" != "$localhostName" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Hostname does not match to expected values"; fi
    if [ "$(chroot $mountPoint /bin/cat /etc/hosts 2>/dev/null | grep 127.0.0.1)" != '127.0.0.1  localhost.localhost localhost' ] && [ "$(chroot $mountPoint /bin/cat /etc/hosts 2>/dev/null | grep 127.0.0.1)" != "127.0.0.1  $localhostName.$localhostName $localhostName" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Hostname is not resolved in local /etc/hosts file"; fi
    if [ ! -f "$mountPoint/sbin/mdev" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Device is not configured with mdev for lightweigth performance"; fi
    for i in $dnsList; do # Verify dns list is in /etc/resolv.conf
        if [ "$(chroot $mountPoint /bin/cat /etc/resolv.conf 2>/dev/null | grep $i)" != "nameserver $i" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not find expected dns server in resolv.conf: $i"; fi
    done    
    if [ -z "$(chroot $mountPoint /bin/cat /etc/apk/repositories 2>/dev/null | grep https)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Not using a https repository"; fi

    # Verify that the correct services are listed for setupAlpine()
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep networking)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Networking service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep sshd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep crond)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: CronD service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep acpid)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: AcpiD service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep chronyd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: ChronyD service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep seedrng)" ] && [ "$(rc-chroot $mountPoint /sbin/service -l 2>/dev/null | grep urandom)" != 'urandom' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: seedrng or urandom service is not managed currently by OpenRC"; fi

    # Verify mandatory packages for future installations for setupAlpine()
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep parted)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find parted package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep lvm)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find lvm package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep e2fsprogs)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find e2fsprogs package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep xfsprogs)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find xfsprogs package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep tzdata)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find tzdata package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep grub)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find grub package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep grub-efi)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find grub-efi package"; fi

    # Verify setupDisks() disk partition scheme
    if [ -z "$(chroot $mountPoint /sbin/lvdisplay /dev/"$lvmName"/"$localhostName".home 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not find home partition"; fi
    if [ -z "$(chroot $mountPoint /sbin/lvdisplay /dev/"$lvmName"/"$localhostName".root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not find root partition"; fi
    if [ -z "$(chroot $mountPoint /sbin/lvdisplay /dev/"$lvmName"/"$localhostName".var 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not find var partition"; fi
    if [ -z "$(chroot $mountPoint /sbin/lvdisplay /dev/"$lvmName"/"$localhostName".var.log 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not find var.log partition"; fi
    if [ -z "$(chroot $mountPoint /sbin/lvdisplay /dev/"$lvmName"/"$localhostName".var.tmp 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not find var.tmp partition"; fi

    # Fstab for setupDisks()
    if [ -z "$(chroot $mountPoint /bin/grep "tmpfs\t\/tmp\ttmpfs\tnoatime,nodev,noexec,nosuid,size\=512m\t0\t0" /etc/fstab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: tmpfs for /tmp in fstab is not harden"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "tmpfs\t/dev/shm\ttmpfs\tnodev,nosuid,noexec\t0\t0" /etc/fstab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: tmpfs for /dev/shm in fstab is not harden"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "\/dev\/$lvmName\/$localhostName.home\t\/home\text4\trw,relatime,noatime,acl,user_xattr,nodev,nosuid 0 2" /etc/fstab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: home partition in fstab is not harden"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "\/dev\/$lvmName\/$localhostName.var\t\/var\text4\trw,relatime,noatime,nodev,nosuid 0 2" /etc/fstab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: var partition in fstab is not harden"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "\/dev\/$lvmName\/$localhostName.var.log\t\/var\/log\text4\trw,relatime,noatime,nodev,nosuid 0 2" /etc/fstab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: var.log partition in fstab is not harden"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "\/dev\/$lvmName\/$localhostName.var.tmp\t\/var\/tmp\text4\trw,relatime,noatime,nodev,nosuid,noexec 0 2" /etc/fstab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: var.tmp partition in fstab is not harden"; fi

    # Grub has a small timeout
    if [ -z "$(chroot $mountPoint /bin/grep 'GRUB_TIMEOUT=0' /etc/default/grub 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: The grub menu appears when booting! Possibly interactable"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for initial installation: $missing"; else echo "INFO: Not a single missed test for initial installation!"; fi
}

# !!!
verifyLocalInstallation() {
    local missing=0

    # Package check
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep coreutils)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find coreutils package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep findutils)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find findutils package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep dmesg)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find dmesg package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep logger)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find logger package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep setpriv)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find setpriv package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep doas)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find doas package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep doas-doc)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find doas-doc package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep libcap-getcap)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find libcap-getcap package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep libcap-setcap)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find libcap-setcap package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep loksh)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find loksh package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep shadow)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find shadow package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep acpid)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find acpid package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep \{at\})" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find \'at\' package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep ufw)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find ufw package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep nftables)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find nftables package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep fail2ban)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find fail2ban package"; fi
    
    # User existance checks
    if [ -z "$(chroot $mountPoint /bin/grep at /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User at was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $powerUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $powerUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $loggerUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $loggerUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $backgroundUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $backgroundUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep chrony /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User chrony was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $firewallUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $firewallUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $fail2banUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $fail2banUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $updateUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $updateUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $collectorUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $collectorUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $monitorUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $monitorUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $previewUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $previewUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $backupUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $backupUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $serverCommandUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $serverCommandUsername was not found"; fi

    # Group existance checks
    if [ -z "$(chroot $mountPoint /bin/grep busybox /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group busybox was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep coreutils /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group coreutils was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep lvm /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group lvm was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep suid /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group suid was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep diskUtil /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group diskUtil was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep cmdUtil /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group cmdUtil was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep doas /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group doas was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep apk /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group apk was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep rshell /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group rshell was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep logread /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group logread was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep iptables /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group iptables was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep logrotate /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group logrotate was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep chrony /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group chrony was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep python /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group python was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshpub /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group sshpub was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshexec /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group sshexec was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshsftp /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group sshsftp was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep acpi /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group acpi was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep readGroup /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group readGroup was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $collectorUsername /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group $collectorUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $updateUsername /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group $updateUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $firewallUsername /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group $firewallUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $fail2banUsername /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group $fail2banUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $powerUsername /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group $powerUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $loggerUsername /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group $loggerUsername was not found"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $backgroundUsername /etc/group)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Group $backgroundUsername was not found"; fi

    # User in certain group checks
	# Syslogd
	# Acpid
    if [ -z "$(chroot $mountPoint /bin/grep acpi /etc/group | grep $powerUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $powerUsername was not found in group acpi"; fi
    if [ -z "$(chroot $mountPoint /bin/grep readGroup /etc/group | grep $powerUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $powerUsername was not found in group readGroup"; fi
	# Chronyd
	# SSHD
        # Firewall
    if [ -z "$(chroot $mountPoint /bin/grep iptables /etc/group | grep $firewallUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $firewallUsername was not found in group iptables"; fi
    if [ -z "$(chroot $mountPoint /bin/grep python /etc/group | grep $firewallUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $firewallUsername was not found in group python"; fi
    if [ -z "$(chroot $mountPoint /bin/grep busybox /etc/group | grep $firewallUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $firewallUsername was not found in busybox python"; fi
        # Fail2ban
    if [ -z "$(chroot $mountPoint /bin/grep iptables /etc/group | grep $fail2banUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $fail2banUsername was not found in group iptables"; fi
    if [ -z "$(chroot $mountPoint /bin/grep python /etc/group | grep $fail2banUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $fail2banUsername was not found in group python"; fi
    if [ -z "$(chroot $mountPoint /bin/grep logread /etc/group | grep $fail2banUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $fail2banUsername was not found in group logread"; fi
    if [ -z "$(chroot $mountPoint /bin/grep logrotate /etc/group | grep $fail2banUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $fail2banUsername was not found in group logrotate"; fi
        # Apk
    if [ -z "$(chroot $mountPoint /bin/grep apk /etc/group | grep $updateUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $updateUsername was not found in group apk"; fi
    if [ -z "$(chroot $mountPoint /bin/grep doas /etc/group | grep $updateUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $updateUsername was not found in group doas"; fi
        # Log gatherer
    if [ -z "$(chroot $mountPoint /bin/grep coreutils /etc/group | grep $collectorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $collectorUsername was not found in group coreutils"; fi
    if [ -z "$(chroot $mountPoint /bin/grep busybox /etc/group | grep $collectorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $collectorUsername was not found in group busybox"; fi
    if [ -z "$(chroot $mountPoint /bin/grep diskUtil /etc/group | grep $collectorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $collectorUsername was not found in group diskUtil"; fi
    if [ -z "$(chroot $mountPoint /bin/grep lvm /etc/group | grep $collectorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $collectorUsername was not found in group lvm"; fi
    if [ -z "$(chroot $mountPoint /bin/grep doas /etc/group | grep $collectorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $collectorUsername was not found in group doas"; fi
    	# Remote log sender
    if [ -z "$(chroot $mountPoint /bin/grep rshell /etc/group | grep $monitorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $monitorUsername was not found in group rshell"; fi
    if [ -z "$(chroot $mountPoint /bin/grep logread /etc/group | grep $monitorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $monitorUsername was not found in group logread"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshpub /etc/group | grep $monitorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $monitorUsername was not found in group sshpub"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshexec /etc/group | grep $monitorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $monitorUsername was not found in group sshexec"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshsftp /etc/group | grep $monitorUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $monitorUsername was not found in group sshsftp"; fi
    	# Preview stats of server
    if [ -z "$(chroot $mountPoint /bin/grep rshell /etc/group | grep $previewUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $previewUsername was not found in group rshell"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshpub /etc/group | grep $previewUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $previewUsername was not found in group sshpub"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshexec /etc/group | grep $previewUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $previewUsername was not found in group sshexec"; fi
        # Remote execute command
    if [ -z "$(chroot $mountPoint /bin/grep rshell /etc/group | grep $serverCommandUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $serverCommandUsername was not found in group rshell"; fi
    if [ -z "$(chroot $mountPoint /bin/grep cmdUtil /etc/group | grep $serverCommandUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $serverCommandUsername was not found in group cmdUtil"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshpub /etc/group | grep $serverCommandUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $serverCommandUsername was not found in group sshpub"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshexec /etc/group | grep $serverCommandUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $serverCommandUsername was not found in group sshexec"; fi
        # Backup files user
    if [ -z "$(chroot $mountPoint /bin/grep rshell /etc/group | grep $backupUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $backupUsername was not found in group rshell"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshpub /etc/group | grep $backupUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $backupUsername was not found in group sshpub"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshexec /etc/group | grep $backupUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $backupUsername was not found in group sshexec"; fi
    if [ -z "$(chroot $mountPoint /bin/grep sshsftp /etc/group | grep $backupUsername)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $backupUsername was not found in group sshsftp"; fi
    # Is root account locked, and password disabled for other accounts??
    if [ -z "$(chroot $mountPoint /bin/grep root /etc/passwd | grep /sbin/nologin)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Root user does not use /sbin/nologin shell!"; fi
    if [ ! -z "$(chroot $mountPoint /usr/bin/passwd -S root | grep 'root P')" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Root user account still has a password set!"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/passwd -S root | grep 'root L')" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Root user account is not locked!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $monitorUsername /etc/shadow | grep \*)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: $monitorUsername user may still have a valid login!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $previewUsername /etc/shadow | grep \*)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: $previewUsername user may still have a valid login!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $serverCommandUsername /etc/shadow | grep \*)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: $serverCommandUsername user may still have a valid login!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep $backupUsername /etc/shadow | grep \*)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: $backupUsername user may still have a valid login!"; fi


# !!! PAM

# !!! CHROOT

    # TTY interfaces disablement
    if [ ! -z "$(chroot $mountPoint /bin/grep "^tty" /etc/inittab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: There is atleast one tty interface enabled"; fi
    if [ ! -z "$(chroot $mountPoint /bin/grep "^\:\:ctrlaltdel" /etc/inittab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Keyboard sequence can still shutdown the device!"; fi
    if [ ! -z "$(chroot $mountPoint /bin/cat /etc/securetty 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: There is atleast a tty interface enabled for login"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/inittab -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/inittab"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/securetty -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/securetty"; fi

    # Umask
    if [ -z "$(chroot $mountPoint /bin/grep "^umask $umask" /etc/profile 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH:The umask has not been set to $umask in /etc/profile"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^random  root:root 0664" /etc/mdev.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH:The umask has not been set for random device in /etc/mdev.conf"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^net\/tun\[0-9\]\*   root:netdev 0660" /etc/mdev.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH:The umask has not been set for tun device in /etc/mdev.conf"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^net\/tap\[0-9\]\*   root:netdev 0660" /etc/mdev.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH:The umask has not been set for tap device in /etc/mdev.conf"; fi

    # Configurations in /etc/init.d/ check
	# acpid
    if [ -z "$(chroot $mountPoint /bin/grep "^command=\"\/usr\/bin\/doas\"$" /etc/init.d/acpid 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/acpid service is misconfigured in command"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command_args=\"-u $powerUsername \/sbin\/acpid -l --foreground --pidfile \/var\/run\/acpid\/acpid.pid --lockfile \/var\/run\/acpid\/acpid.lock --socketfile \/var\/run\/acpid\/acpid.socket --socketgroup acpi --socketmode 660\"$" /etc/init.d/acpid 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/acpid service is misconfigured in command_args"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^pidfile=\"\/run\/acpid\/\$RC_SVCNAME.pid\"$" /etc/init.d/acpid 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/acpid service is misconfigured in pidfile"; fi
	# sshd
    if [ -z "$(chroot $mountPoint /bin/grep "^command=\"\/usr\/bin\/doas\"$" /etc/init.d/sshdStatus 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdStatus service is misconfigured in command"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command=\"\/usr\/bin\/doas\"$" /etc/init.d/sshdBackup 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdBackup service is misconfigured in command"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command=\"\/usr\/bin\/doas\"$" /etc/init.d/sshdCommand 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdCommand service is misconfigured in command"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command=\"\/usr\/bin\/doas\"$" /etc/init.d/sshdLog 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdLog service is misconfigured in command"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command_args=\"-u $previewUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$previewUsername\/$previewUsername-sshd.conf -E \/var\/log\/sshdStatus.log\"$" /etc/init.d/sshdStatus 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdStatus service is misconfigured in command_args"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command_args=\"-u $backupUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$backupUsername\/$backupUsername-sshd.conf -E \/var\/log\/sshdBackup.log\"$" /etc/init.d/sshdBackup 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdBackup service is misconfigured in command_args"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command_args=\"-u $serverCommandUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$serverCommandUsername\/$serverCommandUsername-sshd.conf -E \/var\/log\/sshdCommand.log\"$" /etc/init.d/sshdCommand 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdCommand service is misconfigured in command_args"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command_args=\"-u $monitorUsername \/usr\/sbin\/sshd -f \/home\/.keys\/$monitorUsername\/$monitorUsername-sshd.conf -E \/var\/log\/sshdLog.log\"$" /etc/init.d/sshdLog 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdLog service is misconfigured in command_args"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^pidfile=\"\${SSHD_PIDFILE:-\"\/run\/sshdStatus\/\$RC_SVCNAME.pid\"}\"$" /etc/init.d/sshdStatus 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdStatus service is misconfigured in pidfile"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^pidfile=\"\${SSHD_PIDFILE:-\"\/run\/sshdBackup\/\$RC_SVCNAME.pid\"}\"$" /etc/init.d/sshdBackup 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdBackup service is misconfigured in pidfile"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^pidfile=\"\${SSHD_PIDFILE:-\"\/run\/sshdCommand\/\$RC_SVCNAME.pid\"}\"$" /etc/init.d/sshdCommand 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdCommand service is misconfigured in pidfile"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^pidfile=\"\${SSHD_PIDFILE:-\"\/run\/sshdLog\/\$RC_SVCNAME.pid\"}\"$" /etc/init.d/sshdLog 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/sshdLog service is misconfigured in pidfile"; fi
	# chrony
    if [ -z "$(chroot $mountPoint /bin/grep "^command=\"\/usr\/bin\/doas\"$" /etc/init.d/chronyd 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/chronyd service is misconfigured in command"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^command_args=\"-u chrony \/usr\/sbin\/chronyd -u chrony -U -F 1 -f \/etc\/chrony\/chrony.conf -L 0 -l \/var\/log\/chronyd.log\"$" /etc/init.d/chronyd 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/chronyd service is misconfigured in command_args"; fi
	# fail2ban
    if [ -z "$(chroot $mountPoint /bin/grep "^FAIL2BAN=\"\/usr\/bin\/doas -u $fail2banUsername \/usr\/bin\/fail2ban-client \${FAIL2BAN_OPTIONS}\"$" /etc/init.d/fail2ban 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: /etc/init.d/fail2ban service is misconfigured in FAIL2BAN"; fi

    # Doas configuration check
	# ACPID
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as $powerUsername cmd \/usr\/sbin\/acpid args -l --foreground --pidfile \/var\/run\/acpid\/acpid.pid --lockfile \/var\/run\/acpid\/acpid.lock --socketfile \/var\/run\/acpid\/acpid.socket --socketgroup acpi --socketmode 660$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; $powerUsername!"; fi
	# SSHD
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as $previewUsername cmd \/usr\/sbin\/sshd args -f \/home\/.keys\/$previewUsername\/$previewUsername-sshd.conf -E \/var\/log\/sshdStatus.log$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; sshd $previewUsername user service!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as $backupUsername cmd \/usr\/sbin\/sshd args -f \/home\/.keys\/$backupUsername\/$backupUsername-sshd.conf -E \/var\/log\/sshdBackup.log$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; sshd $backupUsername user service!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as $serverCommandUsername cmd \/usr\/sbin\/sshd args -f \/home\/.keys\/$serverCommandUsername\/$serverCommandUsername-sshd.conf -E \/var\/log\/sshdCommand.log$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; sshd $serverCommandUsername user service!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as $monitorUsername cmd \/usr\/sbin\/sshd args -f \/home\/.keys\/$monitorUsername\/$monitorUsername-sshd.conf -E \/var\/log\/sshdLog.log$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; sshd $monitorUsername user service!"; fi
	# Chrony
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as chrony cmd \/usr\/sbin\/chronyd args -u chrony -U -F 1 -f \/etc\/chrony\/chrony.conf -L 0 -l \/var\/log\/chronyd.log$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; chrony!"; fi
	# Fail2ban
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as $fail2banUsername cmd \/usr\/bin\/fail2ban-client args start$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; $fail2banUsername in starting!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as $fail2banUsername cmd \/usr\/bin\/fail2ban-client args stop$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; $fail2banUsername in stoping!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^permit nopass root as $fail2banUsername cmd \/usr\/bin\/fail2ban-client args reload$" /etc/doas.d/daemon.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Doas is misconfigured for; $fail2banUsername in reloading!"; fi

    # Capabilities check
    if [ -z "$(chroot $mountPoint /usr/sbin/getcap /usr/sbin/chronyd | grep cap_sys_time 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Binary /usr/sbin/chronyd has incorrect capabilities set, or is missing"; fi
    if [ -z "$(chroot $mountPoint /usr/sbin/getcap /usr/sbin/sshd | grep cap_net_bind_service 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Binary /usr/sbin/sshd has incorrect capabilities set, or is missing"; fi
    if [ -z "$(chroot $mountPoint /usr/sbin/getcap /usr/sbin/xtables-nft-multi | grep cap_net_admin 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Binary /usr/sbin/xtables-nft-multi has incorrect capabilities set, or is missing"; fi

    # Check sshd_config configuration
    for i in $monitorUsername $previewUsername $serverCommandUsername $backupUsername; do
        if [ -z "$(chroot $mountPoint /bin/grep "^AddressFamily inet" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; AddressFamily!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^RekeyLimit 256M 1h" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; RekeyLimit!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^SyslogFacility AUTH" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; SyslogFacility!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^LogLevel $sshLogging" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; LogLevel!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^LoginGraceTime 15" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; LoginGraceTime!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PermitRootLogin no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PermitRootLogin!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^StrictModes yes" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; StrictModes!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^MaxAuthTries 2" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; MaxAuthTries!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^MaxSessions 2" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; MaxSessions!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PubkeyAuthentication yes" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PubkeyAuthentication!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^HostbasedAuthentication no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; HostbasedAuthentication!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^IgnoreUserKnownHosts no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; IgnoreUserKnownHosts!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^IgnoreRhosts yes" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; IgnoreRhosts!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PasswordAuthentication no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PasswordAuthentication!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PermitEmptyPasswords no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PermitEmptyPasswords!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^UsePAM no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; UsePAM!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^AllowTcpForwarding no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; AllowTcpForwarding!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^GatewayPorts no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; GatewayPorts!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^X11Forwarding no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; X11Forwarding!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PermitTTY yes" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PermitTTY!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PrintMotd yes" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PrintMotd!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^TCPKeepAlive yes" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; TCPKeepAlive!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PermitUserEnvironment no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PermitUserEnvironment!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^Compression yes" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; Compression!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^ClientAliveInterval 150" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; ClientAliveInterval!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^ClientAliveCountMax 2" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; ClientAliveCountMax!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^UseDNS no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; UseDNS!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PermitTunnel no" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PermitTunnel!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^Banner \/etc\/issue" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; Banner!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^DisableForwarding yes" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; DisableForwarding!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^FingerprintHash sha256" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; FingerprintHash!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^ChannelTimeout session=20m" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; ChannelTimeout!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^Ciphers aes256-gcm@openssh.com,aes256-ctr" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; Ciphers!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; KexAlgorithms!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^MACs hmac-sha2-512-etm@openssh.com" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; MACs!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^PubkeyAcceptedKeyTypes ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $i user; PubkeyAcceptedKeyTypes!"; fi
        if [ -z "$(chroot $mountPoint /bin/grep "^AllowUsers $i@$localNetwork\/$localNetmask$" /home/.keys/$i/$i-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for not whitelisting $monitorUsername!"; fi
    done
    if [ -z "$(chroot $mountPoint /bin/grep "^Port $sshPortStatus" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $previewUsername user; Port number!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^Port $sshPortBackup" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $backupUsername user; Port number!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^Port $sshdCommand" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $serverCommandUsername user; Port number!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^Port $sshdLog" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $monitorUsername user; Port number!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^HostKey \/home\/.keys\/$previewUsername\/ssh_host_$previewUsername-key" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $previewUsername user; HostKey!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^HostKey \/home\/.keys\/$backupUsername\/ssh_host_$backupUsername-key" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $backupUsername user; HostKey!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^HostKey \/home\/.keys\/$serverCommandUsername\/ssh_host_$serverCommandUsername-key" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $serverCommandUsername user; HostKey!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^HostKey \/home\/.keys\/$monitorUsername\/ssh_host_$monitorUsername-key" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $monitorUsername user; HostKey!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^AuthorizedKeysFile \/home\/.keys\/$previewUsername\/authorized_keys" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $previewUsername user; AuthorizedKeysFile!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^AuthorizedKeysFile \/home\/.keys\/$backupUsername\/authorized_keys" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $backupUsername user; AuthorizedKeysFile!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^AuthorizedKeysFile \/home\/.keys\/$serverCommandUsername\/authorized_keys" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $serverCommandUsername user; AuthorizedKeysFile!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^AuthorizedKeysFile \/home\/.keys\/$monitorUsername\/authorized_keys" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $monitorUsername user; AuthorizedKeysFile!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^PidFile \/var\/run\/sshdStatus\/sshd.pid" /home/.keys/$previewUsername/$previewUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $previewUsername user; PidFile!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^PidFile \/var\/run\/sshdBackup\/sshd.pid" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $backupUsername user; PidFile!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^PidFile \/var\/run\/sshdCommand\/sshd.pid" /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $serverCommandUsername user; PidFile!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^PidFile \/var\/run\/sshdLog\/sshd.pid" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $monitorUsername user; PidFile!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^Subsystem sftp \/usr\/lib\/ssh\/sftp-server" /home/.keys/$backupUsername/$backupUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $backupUsername user; Port number!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^Subsystem sftp \/usr\/lib\/ssh\/sftp-server" /home/.keys/$monitorUsername/$monitorUsername-sshd.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured for $monitorUsername user; Port number!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_ecdsa_key" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/ssh/ssh_host_ecdsa_key file should not exist!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_ed25519_key" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/ssh/ssh_host_ed25519_key file should not exist!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_rsa_key" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/ssh/ssh_host_rsa_key file should not exist!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_ecdsa_key.pub" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/ssh/ssh_host_ecdsa_key.pub file should not exist!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_ed25519_key.pub" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/ssh/ssh_host_ed25519_key.pub file should not exist!"; fi
    if [ -f "$mountPoint/etc/ssh/ssh_host_rsa_key.pub" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/ssh/ssh_host_rsa_key.pub file should not exist!"; fi
    if [ ! -f "$mountPoint/etc/init.d/sshdStatus" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/init.d/sshdStatus file is missing!"; fi
    if [ ! -f "$mountPoint/etc/init.d/sshdBackup" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/init.d/sshdBackup file is missing!"; fi
    if [ ! -f "$mountPoint/etc/init.d/sshdCommand" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/init.d/sshdCommand file is missing!"; fi
    if [ ! -f "$mountPoint/etc/init.d/sshdLog" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /etc/init.d/sshdLog file is missing!"; fi
    if [ -d "$mountPoint/var/run/sshd" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /var/run/sshd directory should not exist!"; fi
    if [ ! -d "$mountPoint/var/run/sshdStatus" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /var/run/sshdStatus directory does not exist!"; fi
    if [ ! -d "$mountPoint/var/run/sshdBackup" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /var/run/sshd directoryBackup does not exist!"; fi
    if [ ! -d "$mountPoint/var/run/sshdCommand" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /var/run/sshd directoryCommand does not exist!"; fi
    if [ ! -d "$mountPoint/var/run/sshdLog" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /var/run/sshd directoryLog does not exist!"; fi
    if [ ! -d "$mountPoint/home/.keys" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD is misconfigured; /home/.keys directory does not exist!"; fi

    # Check ssh_config configuration
    if [ -z "$(chroot $mountPoint /bin/grep "^    AddressFamily inet" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; AddressFamily!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    BatchMode no" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; BatchMode!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    ChallengeResponseAuthentication yes" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; ChallengeResponseAuthentication!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    CheckHostIP yes" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; CheckHostIP!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    Compression yes" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; Compression!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    CompressionLevel 9" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; CompressionLevel!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    ConnectTimeout 99999" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; ConnectTimeout!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    ForwardAgent no" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; ForwardAgent!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    ForwardX11 no" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; ForwardX11!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    GatewayPorts no" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; GatewayPorts!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    HashKnownHosts yes" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; HashKnownHosts!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    LogLevel $sshLogging" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; LogLevel!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    PasswordAuthentication no" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; PasswordAuthentication!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    PermitLocalCommand no" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; PermitLocalCommand!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    PreferredAuthentications publickey" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; PreferredAuthentications!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    TCPKeepAlive yes" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; TCPKeepAlive!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    Tunnel no" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; Tunnel!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    UsePrivilegedPort no" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; UsePrivilegedPort!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^    PubkeyAuthentication yes" /etc/ssh/ssh_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; PubkeyAuthentication!"; fi

    # Check if sshd moduli file is common moduli file
    if [ "$(chroot $mountPoint /usr/bin/md5sum /etc/ssh/moduli 2>/dev/null)" == "122e215edb179637f7506c53898e8d03" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for moduli; Relying on default moduli file! This will not be solved by the script unless \$sshExpensiveOperation is enabled!"; fi

    # Check if sshd moduli file contains unsafe bits
    if [ ! -z "$(chroot $mountPoint /usr/bin/awk '$5 < 3071' /etc/ssh/moduli)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: There are still unsafe bits in /etc/ssh/moduli!"; fi

    # Default policy and configurations for UFW
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_INPUT_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets that are incoming \(ingress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_OUTPUT_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets that are outgoing \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets meant for routing \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_APPLICATION_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall still accepts application profiles \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "IPV6=no" /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall might accept Ipv6 addresses"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "LOGLEVEL=$ufwLogging" /etc/ufw/ufw.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW has wrong loglevel configured!"; fi

    # Checking for expected open ports via UFW
        # Port 80
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep 80 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port 80"; fi
        # Port 443
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep 443 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port 443"; fi
        # Port 53
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep 53 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port 52"; fi
        # Port 123
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep 123 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port 123"; fi
        # Port 323
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep 323 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port 323"; fi
        # Port ssh
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $sshPortStatus 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $sshPortStatus"; fi
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $sshPortBackup 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $sshPortBackup"; fi
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $sshPortCommand 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $sshPortCommand"; fi
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $sshPortLog 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $sshPortLog"; fi

    # Checking for general logging enablement on UFW
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-after-logging-input -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-after-logging-output -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-after-logging-forward -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-logging-deny -m conntrack --ctstate INVALID -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 4 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-logging-deny -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 5 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-logging-allow -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 6 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-I ufw-before-logging-input -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 7 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-I ufw-before-logging-output -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 8 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-I ufw-before-logging-forward -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 9 for logging"; fi

    # Rate limiting ssh port check
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for rate limiting"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-limit -j REJECT' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for rate limiting"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-limit-accept -j ACCEPT' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for rate limiting"; fi

    # Existance of redundant UFW files?
    if [ -f "$mountPoint/etc/init.d/ufw.apk-new" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: File /etc/init.d/ufw.apk-new should not exist!"; fi
    if [ -f "$mountPoint/etc/ufw/ufw.conf.apk-new" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: File /etc/ufw/ufw.conf.apk-new should not exist!"; fi
    if [ -f "$mountPoint/etc/default/ufw.apk-new" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: File /etc/default/ufw.apk-new should not exist!"; fi

    # UFW root bypass check
    if [ -z "$(chroot $mountPoint /bin/grep "    if 1 == 2 and uid != 0" /usr/lib/python3.12/site-packages/ufw/backend.py 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW still requires root access to be executed!"; fi

    # Fail2ban configuration
    if [ -z "$(chroot $mountPoint /bin/grep "^bantime = 1h" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban bantime does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^findtime = 1h" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban findtime does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^maxretry = 3" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban maxretry does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^bantime.increment = true" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban bantime.increment does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^bantime.maxtime = 6000" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban bantime.maxtime does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^bantime.factor = 2" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban bantime.factor does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^bantime.overalljails = true" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban bantime.overalljails does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^ignorecommand =" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban ignorecommand does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^usedns = warn" /etc/fail2ban/jail.local 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban usedns does not match"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "^loglevel = $fail2banLogging" /etc/fail2ban/fail2ban.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban log level is not set to $fail2banLogging"; fi
    # Remove the bottom test?
    if [ -z "$(chroot $mountPoint /bin/grep "^allowipv6 = no" /etc/fail2ban/fail2ban.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: fail2ban still uses IPv6"; fi

# !!! SYSLOG

# !!! CRON

    # Is $extractUsername properely deleted?
    if [ ! -z "$(chroot $mountPoint /bin/grep $extractUsername /etc/passwd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: User $extractUsername was found, and had no delete script! This user should be deleted"; fi

    # Checking /bin permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/busybox -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/busybox"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/coreutils -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/coreutils"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/rc-status -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/rc-status"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/setpriv -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/setpriv"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/dmesg -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/dmesg"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/kmod -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/kmod"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/bbsuid -perm 4510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/bbsuid"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/ksh -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/ksh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/rksh -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/rksh"; fi

    # Checking /sbin permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/xfs_repair -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/xfs_repair"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/mkfs.xfs -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/mkfs.xfs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/fsck.xfs -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/fsck.xfs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/lvmpersist -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/lvmpersist"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/lvm -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/lvm"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/mke2fs -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/mke2fs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/e2fsck -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/e2fsck"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/ldconfig -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/ldconfig"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/apk -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/apk"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/supervise-daemon -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/supervise-daemon"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/start-stop-daemon -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/start-stop-daemon"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/rc-update -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/rc-update"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/rc-sstat -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/rc-sstat"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/rc-service -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/rc-service"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/openrc-run -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/openrc-run"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/openrc -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/openrc"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/mkmntdirs -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/mkmntdirs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/ifupdown -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/ifupdown"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/nlplug-findfs -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/nlplug-findfs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/mkinitfs -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/mkinitfs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/bootchartd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/bootchartd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/acpid -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin/acpid"; fi

    # Checking /usr/bin permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/xargs -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/xargs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/find -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/find"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/sha512sum -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/sha512sum"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fmt -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/fmt"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/env -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/env"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/econftool -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/econftool"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ssh -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ssh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ssh-pkcs11-helper -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ssh-pkcs11-helper"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ssh-keyscan -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ssh-keyscan"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ssh-copy-id -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ssh-copy-id"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ssh-agent -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ssh-agent"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ssh-add -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ssh-add"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/sftp -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/sftp"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/scp -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/scp"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/findssl.sh -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/findssl.sh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ssh-keygen -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ssh-keygen"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/chronyc -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/chronyc"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/scmp_sys_resolver -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/scmp_sys_resolver"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/p11-kit -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/p11-kit"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/openssl -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/openssl"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ldd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ldd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/iconv -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/iconv"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/getent -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/getent"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/getconf -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/getconf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/scanelf -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/scanelf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/ssl_client -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/ssl_client"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/uniso -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/uniso"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/logger -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/logger"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/lddtree -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/lddtree"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-syslinux2cfg -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-syslinux2cfg"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-script-check -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-script-check"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-render-label -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-render-label"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-mkstandalone -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-mkstandalone"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-mkrescue -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-mkrescue"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-mkrelpath -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-mkrelpath"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-mkpasswd-pbkdf2 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-mkpasswd-pbkdf2"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-mknetdir -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-mknetdir"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-mklayout -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-mklayout"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-mkimage -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-mkimage"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-menulst2cfg -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-menulst2cfg"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-kbdcomp -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-kbdcomp"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-glue-efi -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-glue-efi"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-fstest -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-fstest"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-file -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-file"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/grub-editenv -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/grub-editenv"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/doas -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/doas"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/passwd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/passwd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/gpasswd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/gpasswd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/expiry -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/expiry"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/chsh -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/chsh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/chfn -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/chfn"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/chage -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/chage"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/at -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/at"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/batch -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/batch"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/acpi_listen -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/acpi_listen"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/python3.12 -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/python3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/pydoc3.12 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/pydoc3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/2to3-3.12 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/2to3-3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-server -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/fail2ban-server"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-regex -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/fail2ban-regex"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-client -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/fail2ban-client"; fi

    # Checking /usr/sbin/ permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/partprobe -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/partprobe"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/parted -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/parted"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/sshd -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/sshd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/copy-modloop -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/copy-modloop"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/lbu -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/lbu"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/update-kernel -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/update-kernel"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/update-conf -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/update-conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-xorg-base -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-xorg-base"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-xen-dom0 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-xen-dom0"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-wayland-base -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-wayland-base"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-user -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-user"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-timezone -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-timezone"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-sshd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-sshd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-proxy -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-proxy"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-ntp -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-ntp"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-mta -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-mta"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-lbu -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-lbu"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-keymap -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-keymap"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-interfaces -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-interfaces"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-hostname -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-hostname"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-dns -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-dns"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-disk -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-disk"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-devd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-devd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-desktop -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-desktop"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-bootable -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-bootable"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-apkrepos -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-apkrepos"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-apkcache -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-apkcache"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-alpine -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-alpine"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setup-acf -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setup-acf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/update-grub -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/update-grub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-sparc64-setup -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-sparc64-setup"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-set-default -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-set-default"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-reboot -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-reboot"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-probe -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-probe"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-ofpathname -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-ofpathname"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-mkconfig -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-mkconfig"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-macbless -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-macbless"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-install -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-install"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grub-bios-setup -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grub-bios-setup"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/setcap -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/setcap"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/getcap -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/getcap"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/vipw -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/vipw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/usermod -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/usermod"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/userdel -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/userdel"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/useradd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/useradd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/pwck -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/pwck"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/newusers -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/newusers"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/logoutd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/logoutd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/grpck -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/grpck"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/groupmod -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/groupmod"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/groupmems -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/groupmems"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/groupdel -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/groupdel"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/groupadd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/groupadd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/chpasswd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/chpasswd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/chgpasswd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/chgpasswd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/unix_chkpwd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/unix_chkpwd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/pwhistory_helper -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/pwhistory_helper"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/pam_timestamp_check -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/pam_timestamp_check"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/pam_namespace_helper -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/pam_namespace_helper"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/mkhomedir_helper -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/mkhomedir_helper"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/atd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/atd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/atrun -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/atrun"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/kacpimon -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/kacpimon"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/chronyd -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/chronyd"; fi
#    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/sshd -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/sshd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/ufw -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/faillock -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/faillock"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/xtables-nft-multi -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/xtables-nft-multi"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/iptables-apply -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/iptables-apply"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/nft -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/nft"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/logrotate -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/logrotate"; fi

    # Checking /etc permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/moduli -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ssh/moduli"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/ssh_config -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ssh/ssh_config"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/ssh_config.d -perm 0000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ssh/ssh_config.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/sshd_config.d -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ssh/sshd_config.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/sshd_config -perm 0000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ssh/sshd_config"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ssh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ssh -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d/ssh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/apk -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d/apk"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ntp -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d/ntp"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/dns -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d/dns"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/default/ufw -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/default/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/ufw.conf -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/ufw.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/sysctl.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/sysctl.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after.init -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/after.init"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after.rules -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/after.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after6.rules -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/after6.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before.init -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/before.init"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before.rules -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/before.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before6.rules -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/before6.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/user.rules -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/user.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/user6.rules -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/user6.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ethertypes -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ethertypes"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/nftables.nft -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/nftables.nft"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/iptables -perm 0000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/iptables"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/nftables.d -perm 0000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/nftables.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/ufw -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/nftables -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/nftables"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/iptables -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/iptables"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/ip6tables -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/ip6tables"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/ebtables -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/ebtables"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/jail.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.local -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/jail.local"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/paths-common.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/paths-common.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/paths-debian.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/paths-debian.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/logrotate.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/logrotate.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/fail2ban.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/fail2ban.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/fail2ban.d -perm 0000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/fail2ban.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/action.d -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/action.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/filter.d -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/filter.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.d -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/jail.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.d/alpine-ssh.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/jail.d/alpine-ssh.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/alpine-release -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/alpine-release"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/e2scrub.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/e2scrub.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fstab -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fstab"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/group -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/group"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/group- -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/group-"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/hostname -perm 0404 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/hostname"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/hosts -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/hosts"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/inputrc -perm 0404 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/inputrc"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/issue -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/issue"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/mdev.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/mdev.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/mke2fs.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/mke2fs.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/modules -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/modules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/motd -perm 0404 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/motd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/nsswitch.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/nsswitch.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/passwd -perm 0604 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/passwd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/passwd- -perm 0604 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/passwd-"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/profile -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/profile"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/protocols -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/protocols"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/rc.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/rc.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/resolv.conf -perm 0404 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/resolv.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/services -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/services"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/shadow -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/shadow"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/shadow- -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/shadow-"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/shells -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/shells"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/sysctl.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/sysctl.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/default/grub -perm 400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/default/grub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/PWRF/00000080 -perm 550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/acpi/PWRF/00000080"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/apk/arch -perm 600 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/apk/arch"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/apk/repositories -perm 400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/apk/repositories"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/apk/world -perm 644 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/apk/world"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/busybox-paths.d/busybox -perm 644 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/busybox-paths.d/busybox"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/chrony/chrony.conf -perm 604 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/chrony/chrony.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/crontabs/root -perm 600 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/crontabs/root"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/grub.d/*_* -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/grub.d/*_*"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/keymap/us.bmap.gz -perm 600 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/keymap/us.bmap.gz"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/lvm/lvm.conf -perm 600 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/lvm/lvm.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/lvm/lvmlocal.conf -perm 600 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/lvm/lvmlocal.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network/if-pre-up.d/bridge -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network/if-pre-up.d/bridge"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network/if-up.d/dad -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network/if-up.d/dad"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/secfixes.d/alpine -perm 600 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/secfixes.d/alpine"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/acpid -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/acpid"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/acpid -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/acpid"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/atd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/atd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/binfmt -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/binfmt"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/bootmisc -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/bootmisc"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/cgroups -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/cgroups"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/chronyd -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/chronyd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/chronyd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/chronyd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/consolefont -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/consolefont"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/crond -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/crond"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/devfs -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/devfs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/dmesg -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/dmesg"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/fail2ban -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/fail2ban"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/firstboot -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/firstboot"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/fsck -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/fsck"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/hostname -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/hostname"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/hwclock -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/hwclock"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/hwdrivers -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/hwdrivers"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/killprocs -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/killprocs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/klogd -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/klogd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/loadkmap -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/loadkmap"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/local -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/local"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/localmount -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/localmount"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/loopback -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/loopback"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/lvm -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/lvm"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/machine-id -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/machine-id"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/mdev -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/mdev"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/modloop -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/modloop"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/modules -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/modules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/mount-ro -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/mount-ro"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/mtab -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/mtab"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/net-online -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/net-online"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/netmount -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/netmount"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/networking -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/networking"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/ntpd -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/ntpd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/numlock -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/numlock"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/osclock -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/osclock"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/procfs -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/procfs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/rdate -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/rdate"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/root -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/root"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/runsvdir -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/runsvdir"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/s6-svscan -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/s6-svscan"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/save-keymaps -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/save-keymaps"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/save-termencoding -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/save-termencoding"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/savecache -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/savecache"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/seedrng -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/seedrng"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshd -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/sshd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshdStatus -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/sshdStatus"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshdBackup -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/sshdBackup"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshdCommand -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/sshdCommand"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshdLog -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/sshdLog"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/staticroute -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/staticroute"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/swap -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/swap"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/swclock -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/swclock"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sysctl -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/sysctl"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sysfs -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/sysfs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sysfsconf -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/sysfsconf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/syslog -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/syslog"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/termencoding -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/termencoding"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/ufw -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/user -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/user"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/watchdog -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/watchdog"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/access.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/access.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/faillock.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/faillock.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/group.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/group.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/limits.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/limits.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/namespace.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/namespace.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/namespace.init -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/namespace.init"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/pam_env.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/pam_env.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/pwhistory.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/pwhistory.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/time.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/time.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/pam.d/chsh -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/pam.d/chsh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/pam.d/shadow-utils -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/pam.d/shadow-utils"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/doas.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/doas.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/doas.d/daemon.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/doas.d/daemon.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/doas.d -perm 510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/doas.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/pam.d -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/pam.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/limits.d -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/limits.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/at.allow -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/at.allow"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/security/namespace.d -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/security/namespace.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/events -perm 550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/acpi/events"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/events/anything -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/acpi/events/anything"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi -perm 550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/acpi"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/PWRF -perm 550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/acpi/PWRF"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/apk -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/apk"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/apk/keys -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/apk/keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/apk/protected_paths.d -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/apk/protected_paths.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/busybox-paths.d -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/busybox-paths.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/chrony -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/chrony"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/conf.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/conf.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/crontabs -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/crontabs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/grub.d -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/grub.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/keymap -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/keymap"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/lbu -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/lbu"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/local.d -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/local.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/logrotate.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/logrotate.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/lvm -perm 710 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/lvm"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/lvm/archive -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/lvm/archive"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/lvm/backup -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/lvm/backup"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/lvm/profile -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/lvm/profile"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/mkinitfs -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/mkinitfs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/mkinitfs/features.d -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/mkinitfs/features.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/modprobe.d -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/modprobe.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/modules-load.d -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/modules-load.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network/if-down.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network/if-down.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network/if-post-down.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network/if-post-down.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network/if-post-up.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network/if-post-up.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network/if-pre-down.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network/if-pre-down.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network/if-pre-up.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network/if-pre-up.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/network/if-up.d -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/network/if-up.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/opt -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/opt"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/periodic -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/periodic"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/periodic/15min -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/periodic/15min"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/periodic/daily -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/periodic/daily"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/periodic/hourly -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/periodic/hourly"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/periodic/monthly -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/periodic/monthly"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/periodic/weekly -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/periodic/weekly"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/pkcs11 -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/pkcs11"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/profile.d -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/profile.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/runlevels -perm 705 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/runlevels"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/runlevels/boot -perm 705 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/runlevels/boot"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/runlevels/default -perm 705 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/runlevels/default"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/runlevels/nonetwork -perm 705 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/runlevels/nonetwork"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/runlevels/shutdown -perm 705 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/runlevels/shutdown"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/runlevels/sysinit -perm 705 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/runlevels/sysinit"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/secfixes.d -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/secfixes.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssl -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ssl"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssl1.1 -perm 700 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ssl1.1"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/sysctl.d -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/sysctl.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/a -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/a"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/d -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/g -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/g"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/k -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/k"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/l -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/l"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/p -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/p"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/r -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/r"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/s -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/s"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/t -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/t"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/v -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/v"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/terminfo/x -perm 755 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/terminfo/x"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/udhcpc -perm 000 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/udhcpc"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/zoneinfo -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/zoneinfo"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/default -perm 701 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/default"; fi

    # Checking /usr/lib permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/os-release -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc//usr/lib/os-release for /etc/os-release"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw/ufw-init -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ufw/ufw-init"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw/ufw-init-functions -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ufw/ufw-init-functions"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ufw; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw/ufw-init -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ufw/ufw-init; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw/ufw-init-functions -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ufw/ufw-init-functions; fi

    # Checking /usr/share permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/share/zoneinfo/$timezone -perm 0444 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/share/zoneinfo/$timezone for /etc/localtime"; fi

    # Checking /var/run permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/acpid -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/run/acpid"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/sshdStatus -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/run/sshdStatus"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/sshdBackup -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/run/sshdBackup"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/sshdCommand -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/run/sshdCommand"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/sshdLog -perm 750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/run/sshdLog"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/fail2ban -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/run/fail2ban"; fi

    # /var/lib
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ssh/sftp-server -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ssh/sftp-server"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ssh/ssh-pkcs11-helper -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ssh/ssh-pkcs11-helper"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ssh/sshd-auth -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ssh/sshd-auth"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ssh/sshd-session -perm 0510 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ssh/sshd-session"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/lib/fail2ban/fail2ban.sqlite3 -perm 0460 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/lib/fail2ban/fail2ban.sqlite3"; fi

    # /var/log
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/messages -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/messages"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/acpid.log -perm 0240 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/acpid.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/sshdStatus.log -perm 0240 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/sshdStatus.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/sshdBackup.log -perm 0240 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/sshdBackup.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/sshdCommand.log -perm 0240 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/sshdCommand.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/sshdLog.log -perm 0240 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/sshdLog.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/chronyd.log -perm 0240 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/chronyd.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/fail2ban.log -perm 0240 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/fail2ban.log"; fi

    # Checking /home file permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername -perm 0501 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$monitorUsername"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername -perm 0501 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$previewUsername"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername -perm 0501 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$serverCommandUsername"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername -perm 0501 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$backupUsername"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername/authorized_keys -perm 0404 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$monitorUsername/authorized_keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername/authorized_keys -perm 0404 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$previewUsername/authorized_keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername/authorized_keys -perm 0404 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$serverCommandUsername/authorized_keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername/authorized_keys -perm 0404 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$backupUsername/authorized_keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername/ssh_host_$previewUsername-key -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$previewUsername/ssh_host_$previewUsername-key"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername/ssh_host_$previewUsername-key.pub -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$previewUsername/ssh_host_$previewUsername-key.pub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername/ssh_host_$backupUsername-key -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$backupUsername/ssh_host_$backupUsername-key"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername/ssh_host_$backupUsername-key.pub -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$backupUsername/ssh_host_$backupUsername-key.pub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key.pub -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key.pub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername/ssh_host_$monitorUsername-key -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$monitorUsername/ssh_host_$monitorUsername-key"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername/ssh_host_$monitorUsername-key.pub -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$monitorUsername/ssh_host_$monitorUsername-key.pub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername/$previewUsername-sshd.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$previewUsername/$previewUsername-sshd.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername/$backupUsername-sshd.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$backupUsername/$backupUsername-sshd.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername/$monitorUsername-sshd.conf -perm 0440 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home/.keys/$monitorUsername/$monitorUsername-sshd.conf"; fi

    # Common directories near root permission check
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc -perm 751 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr -perm 701 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var -perm 701 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home -perm 501 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /home"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /root -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /root"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin -perm 701 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin -perm 701 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /sbin"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin -perm 701 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin -perm 701 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin"; fi

    # File ownership checks
    	# Other Files
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/rksh -user root -and -group rshell 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /bin/rksh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/busybox -user root -and -group busybox 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /bin/busybox"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/messages -user root -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/messages"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/env -user root -and -group python 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/bin/env"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/python3.12 -user root -and -group python 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/bin/python3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/xtables-nft-multi -user root -and -group iptables 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/sbin/xtables-nft-multi"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/logrotate -user root -and -group logrotate 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/sbin/logrotate"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/group -user root -and -group readGroup 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/group"; fi

	# Syslogd

	# Acpid
    if [ -z "$(chroot $mountPoint /usr/bin/find /sbin/acpid -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /sbin/acpid"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/acpi_listen -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/bin/acpi_listen"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/kacpimon -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/sbin/kacpimon"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/acpi"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/handler.sh -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/acpi/handler.sh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/events -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/acpi/events"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/events/anything -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/acpi/events/anything"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/PWRF -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/acpi/PWRF"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/acpi/PWRF/00000080 -user root -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/acpi/PWRF/00000080"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/acpid -user $powerUsername -and -group $powerUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/run/acpid"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/acpid.log -user $powerUsername -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/acpid.log"; fi

	# Chronyd
    if [ ! -f "$mountPoint/var/log/chronyd.log" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: File /var/log/chronyd.log does not exist!"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/chronyd -user root -and -group chrony 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/sbin/chronyd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/chronyd.log -user chrony -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/chronyd.log"; fi

	# SSHD
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/sshd -user root -and -group sshexec 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/sbin/sshd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh -user root -and -group sshexec 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ssh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/ssh_config -user root -and -group sshexec 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ssh/ssh_config"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/sshd_config -user root -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ssh/sshd_config"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/sshd_config.d -user root -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ssh/"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshdStatus -user root -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/init.d/sshdStatus"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshdBackup -user root -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/init.d/sshdBackup"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshdCommand -user root -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/init.d/sshdCommand"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/sshdLog -user root -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/init.d/sshdLog"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ssh/moduli -user root -and -group sshexec 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ssh/moduli"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ssh/sftp-server -user root -and -group sshsftp 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ssh/sftp-server"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ssh/ssh-pkcs11-helper -user root -and -group sshexec 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ssh/ssh-pkcs11-helper"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ssh/sshd-auth -user root -and -group sshexec 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ssh/sshd-auth"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ssh/sshd-session -user root -and -group sshexec 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ssh/sshd-session"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/sshdStatus -user $previewUsername -and -group $previewUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/run/sshdStatus"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/sshdBackup -user $backupUsername -and -group $backupUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/run/sshdBackup"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/sshdCommand -user $serverCommandUsername -and -group $serverCommandUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/run/sshdCommand"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/sshdLog -user $monitorUsername -and -group $monitorUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/run/sshdLog"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/sshdStatus.log -user $previewUsername -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/sshdStatus.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/sshdBackup.log -user $backupUsername -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/sshdBackup.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/sshdCommand.log -user $serverCommandUsername -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/sshdCommand.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/sshdLog.log -user $monitorUsername -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/sshdLog.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys -user root -and -group sshpub 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername/$previewUsername-sshd.conf -user root -and -group $previewUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$previewUsername/$previewUsername-sshd.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername/$backupUsername-sshd.conf -user root -and -group $backupUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$backupUsername/$backupUsername-sshd.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf -user root -and -group $serverCommandUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$serverCommandUsername/$serverCommandUsername-sshd.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername/$monitorUsername-sshd.conf -user root -and -group $monitorUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$monitorUsername/$monitorUsername-sshd.conf"; fi

        # Firewall
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ssh -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d/ssh; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/apk -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d/apk; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ntp -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d/ntp; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/dns -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d/dns; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before.init -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/before.init; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before.rules -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/before.rules; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before6.rules -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/before6.rules; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after.init -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/after.init; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after.rules -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/after.rules; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after6.rules -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/after6.rules; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/sysctl.conf -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/sysctl.conf; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/default/ufw -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/default/ufw; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/ufw -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/sbin/ufw; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/ufw.conf -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/ufw.conf; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/user.rules -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/user.rules; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/user6.rules -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/user6.rules; fi

        # Fail2ban
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-client -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/bin/fail2ban-client"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-server -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/bin/fail2ban-server"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-regex -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/bin/fail2ban-regex"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/fail2ban.conf -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/fail2ban.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.conf -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/jail.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.local -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/jail.local"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/paths-common.conf -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/paths-common.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/paths-debian.conf -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/paths-debian.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/fail2ban.d -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/fail2ban.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/action.d -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/action.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/filter.d -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/filter.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.d -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/jail.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.d/alpine-ssh.conf -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/fail2ban/jail.d/alpine-ssh.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/lib/fail2ban/fail2ban.sqlite3 -user root -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/lib/fail2ban/fail2ban.sqlite3"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/fail2ban.log -user $fail2banUsername -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/fail2ban.log"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/run/fail2ban -user $fail2banUsername -and -group $fail2banUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/run/fail2ban"; fi

        # Apk

        # Log gatherer

        # SSH keys
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername -user $monitorUsername -and -group $monitorUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$monitorUsername"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername -user $previewUsername -and -group $previewUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$previewUsername"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername -user $serverCommandUsername -and -group $serverCommandUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$serverCommandUsername"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername -user $backupUsername -and -group $backupUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$backupUsername"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername/authorized_keys -user $monitorUsername -and -group $monitorUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$monitorUsername/authorized_keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername/authorized_keys -user $previewUsername -and -group $previewUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$previewUsername/authorized_keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername/authorized_keys -user $serverCommandUsername -and -group $serverCommandUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$serverCommandUsername/authorized_keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername/authorized_keys -user $backupUsername -and -group $backupUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$backupUsername/authorized_keys"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername/ssh_host_$previewUsername-key -user $previewUsername -and -group $previewUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$previewUsername/ssh_host_$previewUsername-key"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$previewUsername/ssh_host_$previewUsername-key.pub -user $previewUsername -and -group $previewUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$previewUsername/ssh_host_$previewUsername-key.pub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername/ssh_host_$backupUsername-key -user $backupUsername -and -group $backupUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$backupUsername/ssh_host_$backupUsername-key"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$backupUsername/ssh_host_$backupUsername-key.pub -user $backupUsername -and -group $backupUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$backupUsername/ssh_host_$backupUsername-key.pub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key -user $serverCommandUsername -and -group $serverCommandUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key.pub -user $serverCommandUsername -and -group $serverCommandUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$serverCommandUsername/ssh_host_$serverCommandUsername-key.pub"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername/ssh_host_$monitorUsername-key -user $monitorUsername -and -group $monitorUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$monitorUsername/ssh_host_$monitorUsername-key"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /home/.keys/$monitorUsername/ssh_host_$monitorUsername-key.pub -user $monitorUsername -and -group $monitorUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /home/.keys/$monitorUsername/ssh_host_$monitorUsername-key.pub"; fi

    # Service existance check
    if [ ! -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i "^sshd$" 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: sshd should be removed from rc list"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i "^sshdStatus$" 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: sshdStatus is yet to be added to rc list"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i "^sshdBackup$" 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: sshdBackup is yet to be added to rc list"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i "^sshdCommand$" 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: sshdCommand is yet to be added to rc list"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i "^sshdLog$" 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: sshdLog is yet to be added to rc list"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Ufw is yet to be added to rc list"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i fail2ban 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Fail2ban is yet to be added to rc list"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for local installation: $missing"; else echo "INFO: Not a single missed test for local installation!"; fi
}

# !!!
verifyRemoteCapabilities() {
    local missing=0

    log "INFO: One day"
}

# Execution path
main() {
    # Read from environment
    interpretArgs $@
    if [ $(whoami) != "root" ]; then echo "SYSTEM TEST MISMATCH: Required root priviledges"; log "SYSTEM TEST MISMATCH: Insufficient permission to execute alpineVerify.sh"; exit; fi
    printVariables
    
    # Check if no specific tests are set, to enable usage on everything
    if ! $gAlpineSetup && ! $gPartition && ! $gLocal && ! $gRemote; then
        gAlpineSetup=true; gPartition=true; gLocal=true; gRemote=true;
    fi

    # Pre-installation
    if $pre; then
	    log "INFO: Started pre-setup!"
	    if $gAlpineSetup; then setupAlpine; fi
	    if $gPartition; then setupDisks; fi
            log "INFO: Finished pre-setup!"
    fi

    # Optional kernel installation
    if $gKernelSetup; then formatKernel; fi

    # Post installation
    if $post; then
	    log "INFO: Started post-setup!"
            mountAlpine
	    if $gLocal; then configLocalInstallation; fi
	    if $gRemote; then configRemoteCapabilities; fi
	    if $gKernel; then kernelExternalMount; configKernel; fi
            log "INFO: Finished post-setup!"
    fi

    # Verification of installation
    if $verify; then
	    log "INFO: Verifying changes!"
            mountAlpine
	    if $gAlpineSetup || $gPartition; then verifyInstallSetup; fi
	    if $gLocal; then verifyLocalInstallation; fi
	    if $gRemote; then verifyRemoteCapabilities; fi
            log "INFO: Finished verifying changes!"
    fi

    # Mention the following if $extractUsername exists:
	    # Mention important ssh private key files exist in one location, and $tempSshPass reminder

    # Remove alpine installation (yes, even if it was just literally installed)
    if $rmAlpine; then log "INFO: Started execution to remove alpine from mount point"; removeAlpine; fi
    log "INFO: Finished executing script!"
}

main "$@"

# Loose resources that impacted the development of the script overall:
# https://wiki.alpinelinux.org/wiki/Securing_Alpine_Linux
# https://tldp.org/LDP/lame/lame.pdf
# https://alpinelinuxsupport.com/securing-alpine-linux-in-high-security-environments/
# https://github.com/captainzero93/security_harden_linux/blob/main/improved_harden_linux.sh
# https://github.com/peass-ng/PEASS-ng
# https://cisofy.com/lynis
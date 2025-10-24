#!/bin/sh
#Alpine defualt configuration: Missing: 

# Default setup interface
# interface: eth0
# ip: 192.168.0.6x
# netmask: 24
# gateway: 192.168.0.1

# Alpine tested on: 3.22.1, 3.22.2

# Missing features:
#fail2ban: Missing more configuration 
#chkrootkit, 
#Password quality?, 
#revist crontab, 
#restrict busybox, 
#what is busybox-paths.d/busybox?, 
#harden /etc directory, 
#mdev umask settings in /etc/mdev.conf, 
#reimplement umask 037 in /etc/profile.d/ or /etc/profile, 
#carefully set profile's $PATH, 
#set ulimit in sysctl via fs.file and alike, 
#redo filesystem disable, 
#selinux, landlock, lockdown, yama, safesetid, loadpin?, 
#where to install: doas doas-doc doasedit@se, 
#chroot $mountPoint /bin/sed -i 's/# permit/permit/1' /etc/doas.conf, 
#passwd -l root, 
#self kernel upgrading, 
#AIDE, 
#DNS check, 
#debsums regular checks, 
#cron auto-updates, 
#cron auto-purges, 
#apt-show-versions for patch management, 
#automatic apply upgrades, 
#did not create /etc/issue or /etc/issue.net banner, or /etc/motd
#process accounting, 
#sysstat, 
#auditd, 
#file integrity monitor, 
#automation tools, 
#malware scanning, 
#DO NOT OVERWRITE EXISTING PARTITIONS
#Change public incoming facing ports (ssh) to non-standard number
#Skip device check if mountpoint is set to root ("/") directory
#Network monitoring? ARP requests, DHCP requestss
#Awall firewall
#Firewall; Filter arp and other network requests
#Execute certain services as a dedicated limited user in openrc
#Obtain current time without installing anything

# Log meanings in this script:
# INFO: States what is currently happening in the script.
# UNEXPECTED: A command hasn't executed as expected.
# CRITICAL: A command hasn't executed, and may leave a large quantity of UNEXPECTED log messages.
# BAD FORMAT: A verification test found unproper formatting
# SYSTEM TEST MISMATCH: A verification test has not encounter an expected output
# WARNING: Does not belong to this script, but instead belongs from another program that tries to warn about possible errors

# Alpine configuration variables (CHANGE THESE)
export logFile="/tmp/hardeningAlpine.log"
export logIP="127.0.0.1"
export buildUsername="maintain"
export username="entry"
export sshUsernameKey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGI2gky5QxWhi4pNX7dUFhR+VkgurRaZkGrPrt2+E/RN entry@lepotato"
export rootSize="2G"
export homeSize="4M"
export varSize="2G"
export varTmpSize="1G"
export varLogSize="5G"
export localhostName="localhost"
export lvmName="vgcore"
export keyboardLayout="us"
export timezone="US/Pacific"
export dnsList="1.1.1.1 9.9.9.9"
export apkRepoList="https://mirror.math.princeton.edu/pub/alpinelinux/edge https://mirrors.ocf.berkeley.edu/alpine/edge"
export devDevice="mdev"
export rootPass="Core&soul!Beetle=hound"
export mountPoint="/mnt/alpine"
export partitionStart=2 # Leave this as 1 to assume we can make the first partition
export kernelPartitionStart=1 # Leave this as 1 to assume we can make the first partition
export partitionSector="6144" # Leave this as 2048, as it determines which sector on the device to use. Leave it alone, unless you know what you are doing
export kernelPartitionSector="2048" # Leave this as 2048, as it determines which sector on the device to use. Leave it alone, unless you know what you are doing
export kernelVersion="6.12.43" # Could not have this reliable
export gitPackageCommitHash="286b542594d5b89dbe3f49f9faf4ba9e9f34f8d3" # Scroll through original aports git repo to set the desired hash
export localNetwork="192.168.0.0"
export localNetmask="24"

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
gPermissions=false
gLimitedUsers=false
gKernel=false
gExecutable=false
gSSHD=false
gFirewall=false
gFail2Ban=false
gSELinux=false

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
#sshLogging= Cannot find configuration file : /var/log/auth.log

# Log function
log() {
    if [ -z "$logFile" ]; then logFile="/tmp/hardeningAlpine.log"; fi
    if ! $verbose || [ -z "$verbose" ]; then return 0; fi
    local message="$(date '+%Y-%m-%d %H:%M:%S'): $1" 2>/dev/null
    echo "$message" 2>/dev/null | tee -a "$logFile" 2>/dev/null
}

# Display help
printHelp() {
    echo "A script to be run within a fresh alpine environment"
    echo "Usage: ./alpineHarden.sh [ACTIONS] [CONFIGURATIONS]"
    echo "Version: $version"
    echo ""
    echo "Actions: User must specify atleast one action"
    echo "	-h, --help	Display this help message"
    echo "	-v, --verbose	Enable verbose logging or display more help information"
    echo "	--pre		Run pre-setup environment alpine installation in fresh live iso"
    echo "	--post		Run post-setup environment alpine installation, and apply hardening techniques"
    echo "	--verify	Verifies if all configurations have been applied"
    echo "	--formatKernel	Prepare block device to contain a valid alpine kernel to be locally managed. Calls --kernel at the end"
    echo "	--uninstall	Remove alpine installation"
    echo "	--all		Shorthand for --pre, --post and --verify"
    if $verbose; then echo ""; else return 0; fi
    echo "Configuration: If not specified, then assume user wants everything below enabled"
    echo "Found in --pre;"
    echo "	--alpineConfig	Use the existing commands and scripts derived from setup-alpine"
    echo "	--partition	Setup the custom expected partitions for this system"
    echo "Found in --post and --verify;"
    echo "	--kernel	Configure the kernel"
    echo "	--sshd		Configure the sshd service"
    echo "	--firewall	Configure the firewall"
    echo "	--fail2ban	Configure fail2ban"
    echo "	--executable	Configure executables found in /bin /sbin /usr/bin and /usr/sbin"
    echo "	--perm		Configure doas, configuration files found in /etc, and system defaults"
    echo "	--users		Configure and create new users under the principal of least priviledge"
    echo "	--selinux	Configure SELinux"
    echo ""
    echo "Internal variables:"
    echo "version:		Version of the script (required)"
    echo "logFile:		Where to save log messages (required)"
    echo "logIP:			IP address that is a logging server"
    echo "buildUsername:		Username for the account responsible to compile the kernel"
    echo "username:		Username that is the entrypoint of the machine"
    echo "sshUsernameKey:		Public key of trusted username (ssh required)"
    echo "rootSize:		Declare the size of the root partition for lvm"
    echo "homeSize:		Declare the size of the home partition for lvm"
    echo "varSize:		Declare the size of the var partition for lvm"
    echo "varTmpSize:		Declare the size of the tmp partition for lvm"
    echo "varLogSize:		Declare the size of the log partition for lvm"
    echo "localhostName:		Default local host name to be applied on local machine and lvm partitions"
    echo "lvmName:		Name of the lvm group to be used with device"
    echo "keyboardLayout:		Declare the layout keyboard configuration"
    echo "timezone:		Declare the timezone in Country/Origin format"
    echo "dnsList:		Declare the resolv.conf list"
    echo "apkRepoList:		Declare the repository(-ies) to obtain packages for main, community, and testing"
    echo "devDevice:		Declare the udev device type"
    echo "rootPass:		Declare the temporary default root pass"
    echo "mountPoint:		Declare the directory to make a new mount point for a later chroot environment"
    echo "mountDevice:		Declare the block device to install alpine system to"
    echo "packageDevice:		Declare the block device that contains a valid kernel"
    echo "namingJustNum:		Declare that the block device uses a naming scheme that uses only numbers and does not include 'p'"
    echo "packageNamingJustNum:	Declare that the block device uses a naming scheme that uses only numbers and does not include 'p'"
    echo "partitionStart:		Declare the partition from the Alpine stored device to tamper with"
    echo "kernelPartitionStart:	Declare the partition from the Kernel storage device to tamper with"
    echo "partitionSector: 	Declare the beginning sector to use within the Alpine stored device"
    echo "kernelPartitionSector:	Declare the beginning sector to use within the kernel storage device"
    echo "kernelVersion:		Declare which kernel edition we will be using"
    echo "gitPackageCommitHash:	Declare where in the git repository we will interact with based on prior history"
    echo "localNetwork:		Declare the local LAN network this machine is connect to by providing a base IPv4 address"
    echo "localNetmask:		Declare the local LAN network's netmask that will be appeneded to localNetwork"
    echo 'Note: $logFile will be set if the variable is empty upon execution.'
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
        --perm) gPermissions=true;;
        --users) gLimitedUsers=true;;
        --kernel) gKernel=true;;
        --executable) gExecutable=true;;
        --sshd) gSSHD=true;;
        --firewall) gFirewall=true;;
        --fail2ban) gFail2Ban=true;;
        --selinux) gSELinux=true;;
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
    if ! $pre && ! $post && ! $verify && ! $rmAlpine && ! $gKernelSetup; then  # Check if valid ip format
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
    if [ -z "$buildUsername" ]; then echo "BAD FORMAT: Declare username that will be used to build the kernel! Edit: \$buildUsername and include a name!"; exit; fi
    if [ -z "$username" ]; then echo "BAD FORMAT: Declare username that will be seperated from root permissions! Edit: \$username and include a name!"; exit; fi
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
    if [ -z "$rootPass" ]; then echo "BAD FORMAT: Enter a password for the root user. It cannot be empty!"; exit; fi
    if [ -z "$mountPoint" ]; then echo "BAD FORMAT: Missing a path for mounting!"; exit; fi
    if [ -z "$partitionStart" ]; then echo "BAD FORMAT: a!"; exit; fi
    if [ -z "$kernelPartitionStart" ]; then echo "BAD FORMAT: Must indicate boot partition that will be formed or used!"; exit; fi
    if [ -z "$partitionSector" ]; then echo "BAD FORMAT: Must indicate the sector of the block device that indicates where our first partition resides!"; exit; fi
    if [ -z "$kernelPartitionSector" ]; then echo "BAD FORMAT: Must indicate kernel storage partition that will be formed or used!"; exit; fi
    if [ -z "$kernelVersion" ]; then echo "BAD FORMAT: Must indicate the version of the linux kernel that is planned to be used!"; exit; fi
    if [ -z "$gitPackageCommitHash" ]; then echo "BAD FORMAT: Must indicate the git branch hash that is expected to be used!"; exit; fi
    if [ -z "$localNetwork" ]; then echo "BAD FORMAT: Must provide a IPv4 base address for the local network!"; exit; fi
    if [ -z "$localNetmask" ]; then echo "BAD FORMAT: Must provide a IPv4 local network netmask!"; exit; fi

    # Format check
    if ! (echo $logIP | grep -Eq ^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$); then echo "BAD FORMAT: Not a valid IPv4 format IP address for logging capabilities! Edit: logIP"; exit; fi
    if ! (echo $localNetwork | grep -Eq ^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$); then echo "BAD FORMAT: Not a valid IPv4 format IP address for local LAN network! Edit: localNetwork"; exit; fi
    for i in $dnsList; do
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

    # Behavior check
    if [ "$mountPoint" = "/" ] && $pre; then echo "SYSTEM TEST MISMATCH: Cannot have pre-installation declared on / point. Specify elsewhere."; exit; fi

    log "INFO: Finished reading all variables: $*"
}

# Print what this script will apply
printVariables() {
    echo ""
    echo "File related variables:"

    # Mention global variables
    echo "SSH config; kernel_build: $buildUsername | Entrypoint username: $username | SSH public key: $sshUsernameKey"
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
        echo "Device	 	Size	 	Label"
        cat /proc/partitions | grep -ivE ram\|loop\|major\|dm\- | while read -r devDevice; do
            if [ "$devDevice" = '' ]; then continue; fi
            devName=$(echo $devDevice | awk -F ' {1,}' '{print($4)}')
            devBlock=$(echo $devDevice | awk -F ' {1,}' '{print($3)}')
            devSize=$(awk "BEGIN {if ((($devBlock*$blockFormatSize)/1073741824) > 1) {print (($devBlock*$blockFormatSize)/1073741824) \" GB\"} else {print (($devBlock*$blockFormatSize)/1048576) \" MB\"}}")
            devLabel=$(ls -l /dev/disk/by-label/ | grep -w $devName)
            echo "$devName	 $devSize	 $devLabel"
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

# Safely mount expected drives and prepare chroot environment
mountAlpine() {
    # Find where to find mounted devices
    mountFind

    # Check if kernel mounting is warranted, if so then mount
    if [ ! "$packageDevice" = "/dev/skip" ] && [ -z "$(mount | grep -i $packageDevice)" ]; then
        # Check home directory existance, then mount
        if [ -d "$mountPoint/home/maintain" ]; then 
            if $packageNamingJustNum; then chroot $mountPoint /bin/mount -t xfs "$packageDevice$kernelPartitionStart" /home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount kernel partition to $mountPoint/home/maintain"; else chroot $mountPoint /bin/mount -t xfs "$packageDevice$p$kernelPartitionStart" /home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount kernel partition to $mountPoint/home/maintain"; fi
        else log "INFO: Kernel storage device can't mount to $mountPoint/home/maintain"; fi
    else log "INFO: Kernel storage devices skipped, or already mounted!"; fi

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

    # Check if kernel mounting is now possible with everything else mounted
    if [ ! "$packageDevice" = "/dev/skip" ] && [ -z "$(mount | grep -i $packageDevice)" ]; then
        # Check home directory existance, then mount
        if [ -d "$mountPoint/home/maintain" ]; then 
            if $packageNamingJustNum; then chroot $mountPoint /bin/mount -t xfs "$packageDevice$kernelPartitionStart" /home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount kernel partition to $mountPoint/home/maintain"; else chroot $mountPoint /bin/mount -t xfs "$packageDevice$p$kernelPartitionStart" /home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount kernel partition to $mountPoint/home/maintain"; fi
        else log "INFO: Still unable to mount kernel storage device at $mountPoint/home/maintain"; fi
    else log "INFO: Kernel storage devices is stilled skipped, or already mounted!"; fi

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
        if [ -d "$mountPoint/home/maintain" ]; then 
            chroot $mountPoint /bin/umount /home/maintain 2>/dev/null || log "UNEXPECTED: Lacked capabilities to umount kernel partition from $mountPoint/home/maintain"
        else log "INFO: Kernel storage device can't umount to $mountPoint/home/maintain"; fi
    else log "INFO: Kernel storage devices skipped, or already un-mounted!"; fi

    # Check if mountpoint is current filesystem
    if [ "$mountPoint" = "/" ]; then log "INFO: Nothing to mount! Mount point is set to current filesystem root."; return 0; fi

    # Check if drives are already unmounted at mount pount ($mountPoint)
    if [ -z "$(mount | grep -i $mountPoint)" ]; then log "INFO: Drives are already unmounted!"; return 0; fi

    # Unmoount devices from known chroot environment
    log "INFO: Started umount-ing alpine!"
    vgchange -ay 2>/dev/null || log "UNEXPECTED: Could not enable logical partitions"
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

# Date command format: MMDDhhmmCCYY
setupAlpine() {
    log "INFO: Started default alpine installation"
    date -s "10200000"
    setup-hostname "$localhostName" 2>/dev/null || log "UNEXPECTED: Could not declare device's hostname"
    rc-service --quiet networking stop 2>/dev/null || log "UNEXPECTED: Could not stop networking services"
    rc-service --quiet hostname restart 2>/dev/null || log "UNEXPECTED: Could not restart hostname services"
    rc-service --quiet networking start 2>/dev/null || log "UNEXPECTED: Could start networking services"
    setup-devd -C "$devDevice" 2>/dev/null || log "UNEXPECTED: Could not set mdev for devd"
    setup-dns "$dnsList" 2>/dev/null || log "CRITICAL: Could not set up local dns"
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
    apk update
    setup-timezone "$timezone" 2>/dev/null || log "UNEXPECTED: Could not set timezone"
    setup-ntp chrony 2>/dev/null || log "UNEXPECTED: Did not setup chronyd as the default ntp service"
    setup-sshd openssh 2>/dev/null || log "CRITICAL: Did not setup an sshd service"
    setup-keymap "$keyboardLayout" "$keyboardLayout" 2>/dev/null || log "UNEXPECTED: Could not setup device's keyboard keymap"
    rc-update --quiet del loadkmap boot 2>/dev/null || log "UNEXPECTED: Could not remove unncessary service that fails on boot"
    echo "root:$rootPass" | chpasswd || log "UNEXPECTED: Did not change root password"
    apk add parted lvm2 e2fsprogs xfsprogs || log "Unexpected: Could not install all software"
    log "INFO: Almost finished default alpine installation!"
}

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

    # Disable TTY interfaces from inittab to limit root access
    log "INFO: Disabling root login via serial consoles"
    chroot $mountPoint /bin/sed -i 's/^tty/#tty/g' /etc/inittab || log "UNEXPECTED: Could not stop the creation of getty instances"
    chroot $mountPoint /bin/echo > /etc/securetty || log "UNEXPECTED: Could not modify which interfaces a root user can login from"
    chroot $mountPoint /bin/chmod 400 /etc/securetty || log "UNEXPECTED: Could not set to 400 permission on /etc/securetty file"

    # Configure grub
    log "INFO: Modifying grub"
    chroot $mountPoint /bin/sed -i 's/GRUB_TIMEOUT=\(.*\)/GRUB_TIMEOUT=0/g' /etc/default/grub || log "UNEXPECTED: Could not lower timeout for grub configuration"
    chroot $mountPoint /bin/sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="modules=sd=mod,usb-storage,ext4 quiet rootfstype=ext4 hardened_usercopy=1 init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on page_alloc.shuffle=1 slab_nomerge pti=on nosmt hash_pointers=always slub_debug=ZF slub_debug=P page_poison=1 iommu.passthrough=0 iommu.strict=1 mitigations=auto,nosmt kfence.sample_interval=100"/g' /etc/default/grub || log "UNEXPECTED: Could not implement kernel parameters that enforce security"
    chroot $mountPoint /bin/chmod 400 /etc/default/grub || log "UNEXPECTED: Could not set to 400 permission on /etc/default/grub"
    chroot $mountPoint /usr/sbin/update-grub || log "UNEXPECTED: Could not implement changes for grub"

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
    mountAlpine
    
    log 'INFO: Finished preparing kernel storage device. Moving onto automatic configuration from configKernel()'
    configKernel
}

configSSHD() {
    log "INFO: Affecting sshd_config"
    chroot $mountPoint /bin/chmod 600 /etc/ssh/sshd_config 2>/dev/null || log "UNEXPECTED: Could not change /etc/ssh/sshd_config permissions to writable"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}PermitRootLogin\(.*\)/PermitRootLogin no/g' /etc/ssh/sshd_config || log "UNEXPECTED: PermitRootLogin is not properely configured"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}X11Forwarding\(.*\)/X11Forwarding no/g' /etc/ssh/sshd_config || log "UNEXPECTED: X11Forwarding is not properely configured"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}PasswordAuthentication\(.*\)/PasswordAuthentication no/g' /etc/ssh/sshd_config || log "UNEXPECTED: PasswordAuthentication not properely configured"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}PubkeyAuthentication\(.*\)/PubkeyAuthentication yes/g' /etc/ssh/sshd_config || log "UNEXPECTED: PubkeyAuthentication not properely configured"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}IgnoreRhosts \(.*\)/IgnoreRhosts yes/g' /etc/ssh/sshd_config || log "UNEXPECTED: IgnoreRhosts not properely configured"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}PermitEmptyPasswords\(.*\)/PermitEmptyPasswords no/g' /etc/ssh/sshd_config || log "UNEXPECTED: PermitEmptyPasswords not properely configured"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}TCPKeepAlive\(.*\)/TCPKeepAlive yes/g' /etc/ssh/sshd_config || log "UNEXPECTED: TCPKeepAlive not been properely configured"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}ClientAliveInterval\(.*\)/ClientAliveInterval 150/g' /etc/ssh/sshd_config || log "UNEXPECTED: ClientAliveInterval not configured for after 150 in sshd"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}ClientAliveCountMax\(.*\)/ClientAliveCountMax 2/g' /etc/ssh/sshd_config || log "UNEXPECTED: ClientAliveCountMax not configured for a maximum of 2 clients"
    chroot $mountPoint /bin/chmod 400 /etc/ssh/sshd_config 2>/dev/null || log "UNEXPECTED: Could not change /etc/ssh/sshd_config permissions to readable"

    log "INFO: Restarting sshd service"
    chroot $mountPoint /sbin/rc-service sshd restart || log "UNEXPECTED: Could not restart sshd daemon"
}

# Check if /usr/sbin/iptables links to xtables-nft-multi
# Prevent ufw from logging into dmesg via rsyslog
# Resources: https://codelucky.com/ufw-advanced-linux-firewall/
# Awall? Shorewall?
configFirewall() {
    log "INFO: Installing nftables and ufw"
    chroot $mountPoint /sbin/apk add ufw@additional nftables || log "CRITICAL: Could not install all software for firewall"

    log "INFO: Removing default and prior ufw firewall configurations"
    chroot $mountPoint /usr/sbin/ufw --force reset 2>/dev/null || log "CRITICAL: Could not reset firewall properely"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'after.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove after.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'before.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove before.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'user.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove user.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'after6.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove after6.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'before6.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove before6.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/ -name 'user6.rules.*' -delete 2>/dev/null || log "UNEXPECTED: Could not remove user6.rules.* backup(s)"
    chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ -mindepth 1 -delete 2>/dev/null || log "UNEXPECTED: Could not ensure there are no other application rules"

    log "INFO: Logging capabiltities for UFW"
    chroot $mountPoint /usr/sbin/ufw logging "$ufwLogging" 2>/dev/null || log "UNEXPECTED: Logging was not properely enabled";

    log "INFO: Denying all outgoing, incoming, and routed packets by default alongside IPv6 deny"
    chroot $mountPoint /usr/sbin/ufw default deny outgoing 2>/dev/null || log "CRITICAL: Failed to set default deny outgoing to ufw firewall"
    chroot $mountPoint /usr/sbin/ufw default deny incoming 2>/dev/null || log "CRITICAL: Failed to set default deny incoming to ufw firewall"
    chroot $mountPoint /usr/sbin/ufw default deny routed 2>/dev/null || log "CRITICAL: Failed to set default deny routing packets to ufw firewall"
    chroot $mountPoint /bin/chmod 600 /etc/default/ufw 2>/dev/null || log "UNEXPECTED: Could not change /etc/default/ufw permissions to writable"
    chroot $mountPoint /bin/sed -i 's/#\{0,2\}IPV6\(.*\)=\(.*\)yes/IPV6=no/g' /etc/default/ufw 2>/dev/null || log "UNEXPECTED: No pattern to remove IPV6 from UFW has worked"
    chroot $mountPoint /bin/chmod 400 /etc/default/ufw 2>/dev/null || log "UNEXPECTED: Could not change /etc/default/ufw permissions to readable"

    log "INFO: Setting up UFW firewall profiles for ssh, ntp, apk, and dns"
    chroot $mountPoint /usr/sbin/ufw app default allow 2>/dev/null || log "UNEXPECTED: Failed to guarantee ufw firewall accept newly made profiles"
    chroot $mountPoint /bin/echo -e "[SSHServer]\ntitle=SSH network listener\ndescription=For remote management of server via ssh\nports=22/tcp" > $mountPoint/etc/ufw/applications.d/ssh || log "UNEXPECTED: Failed to permit DNS port 22 through firewall"
    chroot $mountPoint /bin/echo -e "[APKUpdate]\ntitle=APK tool\ndescription=When this computer needs to update packages, then this will be enabled\nports=80/tcp|443/tcp" > $mountPoint/etc/ufw/applications.d/apk || log "UNEXPECTED: Failed to permit APK ports 80 and 443 through firewall"
    chroot $mountPoint /bin/echo -e "[NTPListener]\ntitle=Chronyd network listener\ndescription=For chronyd service running in background\nports=123/udp|323/udp" > $mountPoint/etc/ufw/applications.d/ntp || log "UNEXPECTED: Failed to permit NTP ports 123 and 323 through firewall"
    chroot $mountPoint /bin/echo -e "[DNSListener]\ntitle=DNS network listener\ndescription=For a dns service running in background\nports=53" > $mountPoint/etc/ufw/applications.d/dns || log "UNEXPECTED: Failed to permit DNS port 53 through firewall"
    chroot $mountPoint /usr/sbin/ufw app update SSHServer || log "CRITICAL: Could not ensure ufw recognizes the ssh profile"
    chroot $mountPoint /usr/sbin/ufw app update DNSListener || log "UNEXPECTED: Could not ensure ufw recognizes the dns profile"
    chroot $mountPoint /usr/sbin/ufw app update APKUpdate || log "UNEXPECTED: Could not ensure ufw recognizes the apk profile"
    chroot $mountPoint /usr/sbin/ufw app update NTPListener || log "UNEXPECTED: Could not ensure ufw recognizes the ntp profile"
    chroot $mountPoint /usr/sbin/ufw app default deny 2>/dev/null || log "CRITICAL: Failed to set default deny creation and modification of application profiles for ufw firewall"

    log "INFO: Opening ports on the firewall"
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app APKUpdate 2>/dev/null || log "UNEXPECTED: Failed to permit HTTP/HTTPS port 80/443 esgress through firewall"
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app DNSListener 2>/dev/null || log "UNEXPECTED: Failed to permit DNS port 53 esgress through firewall"
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app NTPListener 2>/dev/null || log "UNEXPECTED: Failed to permit NTP port 123 esgress through firewall"

    log "INFO: Opening a rate-limited specific firewall ports"
    chroot $mountPoint /usr/sbin/ufw limit in log from "$localNetwork"/"$localNetmask" to "$localNetwork"/"$localNetmask" app SSHServer 2>/dev/null || log "CRITICAL: Failed to limit port 22 for ingress traffic for ufw firewall"

    log "INFO: Changing file permissions for UFW application profiles created"
    chroot $mountPoint /bin/chmod 400 /etc/ufw/applications.d/ssh 2>/dev/null || log "UNEXPECTED: Could not change ssh profile permissions"
    chroot $mountPoint /bin/chmod 400 /etc/ufw/applications.d/apk 2>/dev/null || log "UNEXPECTED: Could not change apk profile permissions"
    chroot $mountPoint /bin/chmod 400 /etc/ufw/applications.d/ntp 2>/dev/null || log "UNEXPECTED: Could not change ntp profile permissions"
    chroot $mountPoint /bin/chmod 400 /etc/ufw/applications.d/dns 2>/dev/null || log "UNEXPECTED: Could not change dns profile permissions"

    log "INFO: Setting permissions on UFW executables"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/python3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; python3.12"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/pydoc3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; pydoc3.12"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/2to3-3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; 2to3-3.12"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/ufw 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/xtables-nft-multi 2>/dev/null || log "UNEXPECTED: Could not change permissions for; xtables-nft-multi"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/iptables-apply 2>/dev/null || log "UNEXPECTED: Could not change permissions for; iptables-apply"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/nft 2>/dev/null || log "UNEXPECTED: Could not change permissions for; nft"

    log "INFO: Restarting service & Enabling"
    chroot $mountPoint /usr/sbin/ufw enable 2>/dev/null || log "UNEXPECTED: ufw could not be enabled"
    chroot $mountPoint /sbin/rc-update add ufw 2>/dev/null || log "UNEXPECTED: Could not add ufw to launch automatically"
    chroot $mountPoint /sbin/rc-service ufw restart 2>/dev/null || log "UNEXPECTED: Could not restart ufw daemon"

    log "INFO: Simple firewall succesfully configured!"
}

# https://dev.to/caffinecoder54/creating-a-lightweight-linux-firewall-with-ufw-and-fail2ban-35po
# Installs python!
configFail2Ban() {
    log "INFO: Installing fail2ban"
    chroot $mountPoint /sbin/apk add fail2ban || log "CRITICAL: Could not install all software for limiting unwanted connections"

    log "INFO: Defaulting unchanged files to readonly"
    chroot $mountPoint /bin/chmod 400 /etc/fail2ban/jail.conf 2>/dev/null || log "UNEXPECTED: Could not change original jail permissions"
    chroot $mountPoint /bin/chmod 400 /etc/fail2ban/paths-common.conf 2>/dev/null || log "UNEXPECTED: Could not change common-paths permissions"
    chroot $mountPoint /bin/chmod 400 /etc/fail2ban/paths-debian.conf 2>/dev/null || log "UNEXPECTED: Could not change debian-paths permissions"

    log "INFO: Configurating default jail behavior"
    chroot $mountPoint /bin/touch /etc/fail2ban/jail.local || log "CRITICAL: Failed to create configuration file for fail2ban"
    chroot $mountPoint /bin/chmod 600 /etc/fail2ban/jail.local 2>/dev/null || log "UNEXPECTED: Could not guanratee local jail permissions are writable"   
    chroot $mountPoint /bin/echo -e '[INCLUDES]\nbefore = paths-debian.conf\n' > $mountPoint/etc/fail2ban/jail.local || log "UNEXPECTED: Fail to include other relevant standard jail settings"
    chroot $mountPoint /bin/echo -e '[DEFAULT]\nbantime = 1h\nfindtime = 1h\nmaxretry = 3\nbantime.increment = true\nbantime.maxtime = 6000\nbantime.factor = 2\nbantime.overalljails = true\nignorecommand =\nmaxmatches = %(maxretry)s\nbackend = auto\nusedns = warn\nlogencoding = auto\nenabled = false\nmode = normal\nfilter = %(__name__)s[mode=%(mode)s]\n' >> $mountPoint/etc/fail2ban/jail.local || log "UNEXPECTED: Fail to declare default jail settings"
    chroot $mountPoint /bin/echo -e 'destemail=root@localhost\nsender = root@<fq-hostname>\nmta = sendmail\nprotocol = tcp\nchain = <known/chain>\nport = 0:65535\nfail2ban_agent = Fail2Ban%(fail2ban_version)s\nbanaction = iptables-multiport\nbanaction_allports = iptables_allports\naction_ = %(banaction)s[port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]\naction_mw = %(action)s%(mta)s-whois[sender="%(sender)", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]\naction_mwl = %(mta)s-whois-lines[sender="%(sender)", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]\naction_xarf = %(action)sxarf-login-attack[service=%(__name__), logpath="%(logpath)s", port="%(port)s""]\naction_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"] %(mta)s-whois-lines[sender="%(sender)", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]\naction_blocklist_de = blocklist_de[email="%(sender)s", service="%(__name__)s", apikey="%(blocklist_de_apikey)s", agent="%(fail2ban_agent)s"]\naction_abuseipdb = abuseipdb\naction = %(action_)s' >> $mountPoint/etc/fail2ban/jail.local || log "UNEXPECTED: Mostly failed to declare email and management settings for jail"
    chroot $mountPoint /bin/chmod 400 /etc/fail2ban/jail.local 2>/dev/null || log "UNEXPECTED: Could not change local jail permissions to readable"

    log "INFO: Configurations for fail2ban's behavior"
    chroot $mountPoint /bin/chmod 600 /etc/fail2ban/fail2ban.conf 2>/dev/null || log "UNEXPECTED: Could not change fail2ban configuration file permissions to writable"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}allowipv6\(.*\)=\(.*\)/allowipv6 = no/g" /etc/fail2ban/fail2ban.conf || log "UNEXPECTED: Could not disable IPv6 configuration on fail2ban.conf"
    chroot $mountPoint /bin/sed -i "s/^#\{0,2\}loglevel\(.*\)=\(.*\)/loglevel = $fail2banLogging/g" /etc/fail2ban/fail2ban.conf || log "UNEXPECTED: Could not change logging level on fail2ban.conf"
    chroot $mountPoint /bin/chmod 400 /etc/fail2ban/fail2ban.conf 2>/dev/null || log "UNEXPECTED: Could not change fail2ban configuration file permissions to readable"

    log "INFO: Setting permissions on fail2ban executables"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/python3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; python3.12"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/pydoc3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; pydoc3.12"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/2to3-3.12 2>/dev/null || log "UNEXPECTED: Could not change permissions for; 2to3-3.12"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/fail2ban-server 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fail2ban-server"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/fail2ban-regex 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fail2ban-regex"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/fail2ban-client 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fail2ban-client"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/xtables-nft-multi 2>/dev/null || log "UNEXPECTED: Could not change permissions for; xtables-nft-multi"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/iptables-apply 2>/dev/null || log "UNEXPECTED: Could not change permissions for; iptables-apply"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/logrotate 2>/dev/null || log "UNEXPECTED: Could not change permissions for; logrotate"

    log "INFO: Restarting service & Enabling"
    chroot $mountPoint /sbin/rc-update add fail2ban 2>/dev/null || log "INFO: Fail2ban was already added to boot"
    chroot $mountPoint /sbin/rc-service fail2ban restart 2>/dev/null || log "UNEXPECTED: Could not restart fail2ban daemon"

    log "INFO: Succesfully configured fail2ban!"
}

# Check inittab to implace restrict shell
# Check /etc/busybox-paths.d/busybox
# chmod 700 and chown /bin/busybox
# https://wiki.alpinelinux.org/wiki/How_to_get_regular_stuff_working
# Found executables via: find /usr/bin ! -perm 777 -and ! -perm 0500
configExecutables() {
    # Packages included in Util-linux: agetty, blkid, cfdisk & libfdisk & libmount & libsmartcols, dmesg, findmnt & libsmartcols & libmount, flock, fstrim & libmount, hexdump, logger, losetup & libsmartcols, lsblk & libsmartcols & libmount, lscpu & libsmartcols, mcookie, mount & libmount, partx & libsmartcols, runuser & linux-pam, setpriv & libcap-ng, sfdisk & libfdisk & libsmartcols, umount & libmount, uuidgen, util-linux-openrc, util-linux-misc & setarch & & libfdisk & libmount & wipefs & libsmartcols, setarch, wipefs & libsmartcols, linux-pam
    # Other packages and commands of interest: agetty (agetty), lsof & lsfd (util-linux-misc)
    log "INFO: Installing GNU CoreUtils, very small part of Util-Linux, and Findutils"
    chroot $mountPoint /sbin/apk add coreutils findutils || log "UNEXPECTED: Could not install full feature basic tools: Coreutils or Findutils"
    chroot $mountPoint /sbin/apk add dmesg logger setpriv || log "UNEXPECTED: Could not install util-linux related packages"

    #log "Removing unncessary default packages"
    # Why is alpine-conf hooked to alpine-base..., and why does update-kernel and update-conf exist?
    #chroot $mountPoint /sbin/apk del -f alpine-conf || log "UNEXPECTED: Could not remove alpine-conf package"

    log "INFO: Setting permissions on /bin executables"
    chroot $mountPoint /bin/chmod 0500 /bin/busybox 2>/dev/null || log "UNEXPECTED: Could not change permissions for; busybox"
    chroot $mountPoint /bin/chmod 0500 /bin/coreutils 2>/dev/null || log "UNEXPECTED: Could not change permissions for; coreutils"
    chroot $mountPoint /bin/chmod 0500 /bin/rc-status 2>/dev/null || log "UNEXPECTED: Could not change permissions for; rc-status"
    chroot $mountPoint /bin/chmod 0500 /bin/setpriv 2>/dev/null || log "UNEXPECTED: Could not change permissions for; setpriv"
    chroot $mountPoint /bin/chmod 0500 /bin/dmesg 2>/dev/null || log "UNEXPECTED: Could not change permissions for; dmesg"
    chroot $mountPoint /bin/chmod 4500 /bin/bbsuid 2>/dev/null || log "UNEXPECTED: Could not change permissions for; bbsuid"

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

    log "INFO: Setting permissions on /usr/bin executables"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/xargs 2>/dev/null || log "UNEXPECTED: Could not change permissions for; xargs"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/find 2>/dev/null || log "UNEXPECTED: Could not change permissions for; find"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/sha512sum 2>/dev/null || log "UNEXPECTED: Could not change permissions for; sha512sum"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/fmt 2>/dev/null || log "UNEXPECTED: Could not change permissions for; fmt"
    chroot $mountPoint /bin/chmod 0500 /usr/bin/env 2>/dev/null || log "UNEXPECTED: Could not change permissions for; env"
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

    log "INFO: Setting permissions on /usr/sbin executables"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/partprobe 2>/dev/null || log "UNEXPECTED: Could not change permissions for; partprobe"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/parted 2>/dev/null || log "UNEXPECTED: Could not change permissions for; parted"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/sshd 2>/dev/null || log "UNEXPECTED: Could not change permissions for; sshd"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/chronyd 2>/dev/null || log "UNEXPECTED: Could not change permissions for; chronyd"
    chroot $mountPoint /bin/chmod 0500 /usr/sbin/copy-modloop 2>/dev/null || log "UNEXPECTED: Could not change permissions for; copy-modloop"

    log "INFO: Wish I could remove these executables, but they remain in /usr/sbin"
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

    log "INFO: Finished modifying default executables!"
}

# Obtain some commands from setupDisks()
configPermissions() {
    log "INFO: Changing file permissions"
    #chroot $mountPoint /bin/touch /etc/modprobe.d/alpine.conf || log "INFO: File already exists"
    #chroot $mountPoint /bin/chmod 600 /etc/modprobe.d/alpine.conf || log "UNEXPECTED: Could not change permission of alpine.conf for kernel filesystem recognition"
    #chroot $mountPoint /bin/chmod 600 /etc/gshadow || log "UNEXPECTED: Could not change gshadow permission"# Change to /etc/group?
    #chroot $mountPoint /bin/chmod 600 /etc/shadow || log "UNEXPECTED: Could not change shadow permission"
    #chroot $mountPoint /bin/chmod 600 /etc/ssh/sshd_config || log "UNEXPECTED: Could not change sshd_config permission"
    #chroot $mountPoint /bin/chmod 711 /etc/ssh/sshd_config.d || log "UNEXPECTED: Could not change sshd_config.d permission"
    #chroot $mountPoint /bin/chmod 700 -R /etc/periodic/15min || log "UNEXPECTED: Could not change periodic/15min permission"
    #chroot $mountPoint /bin/chmod 700 -R /etc/periodic/daily || log "UNEXPECTED: Could not change periodic/daily permission"
    #chroot $mountPoint /bin/chmod 700 -R /etc/periodic/hourly || log "UNEXPECTED: Could not change periodic/hourly permission"
    #chroot $mountPoint /bin/chmod 700 -R /etc/periodic/monthly || log "UNEXPECTED: Could not change periodic/monthly permission"
    #chroot $mountPoint /bin/chmod 700 -R /etc/periodic/weekly || log "UNEXPECTED: Could not change periodic/weekly permission"
    #chroot $mountPoint /bin/chmod 600 /etc/crontabs/root || log "UNEXPECTED: Could not change crontab permission"
    #chroot $mountPoint /bin/chmod 400 /etc/securetty || log "UNEXPECTED: Could not set to 400 permission on /etc/securetty file"
    #chroot $mountPoint /bin/chmod 400 /etc/default/grub || log "UNEXPECTED: Could not set to 400 permission on /etc/default/grub"
    #chroot $mountPoint /bin/chmod u-s /usr/bin/mount || log "UNEXPECTED: Could not remove SUID bit from mount" # Managed by bbsuid
    #chroot $mountPoint /bin/chmod u-s /usr/bin/umount || log "UNEXPECTED: Could not remove SUID bit from umount" # Managed by bbsuid
    #chroot $mountPoint /bin/chmod 700 /etc/rc.local || log "UNEXPECTED: Could not change permission of rc.local" # Changed to /etc/local.d/

    log "INFO: Restarting service & Enabling"
    chroot $mountPoint /sbin/rc-service sshd restart || log "UNEXPECTED: Could not restart sshd daemon"
    chroot $mountPoint /sbin/rc-service crond restart || log "UNEXPECTED: Could not restart crond daemon"

    log "INFO: Successfully reached end of hardening permissions!"
}

# User accounts to keep: root, daemon, cron, sshd, ntp, nobody, klogd
# User accounts to remove: bin, lp, sync, shutdown, halt, mail, news, uucp, ftp, games, guest
configLimitedUsers() {
    log "INFO: Making things less accessible to $username"
    echo -e "AllowUsers ${username}" >> /etc/ssh/sshd_config || log "UNEXPECTED: Failed to restrict ssh to $username"
    
    log "INFO: Adding public sshkey to current host"
    echo "${sshUsernameKey}" >> /home/"${username}"/.ssh/authorized_keys || log "CRITICAL: Failed to add ssh public key to /.ssh/authorized_keys of $username"

    log "INFO: Restarting service"
    chroot $mountPoint /sbin/rc-service sshd restart 2>/dev/null || log "UNEXPECTED: Could not restart sshd daemon"

}

# Look into /proc/sys, and /etc/sysctl.d
configKernel() {
# Modify kernel with ncurses-dev, chroot /mnt/alpine /usr/bin/make menuconfig -C /home/maintain/aports/main/linux-lts/src/linux-6.12
#chroot $mountPoint /bin/echo "permit nopass root" >> $mountPoint/etc/doas.d/kernelBuild.conf || log "UNEXPECTED: Could not provide doas permissions towards root user"    
# Started with version
    if [ "$choiceAports" = 'skip' ]; then log "BAD FORMAT: Skipping kernel configuration due to lacking a kernel storage device"; return 0; fi

    log "INFO: Installing required tools for this section"
    chroot $mountPoint /sbin/apk add alpine-sdk kernel-hardening-checker@additional 2>/dev/null || log "CRITICAL: Could not install required packages"

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

    log "INFO: Cleaning up"
    chroot $mountPoint /bin/rm /etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Permission doas file has not been deleted to enforce principle of least priviledge"
    if [ -f "$mountPoint/home/maintain/aports/.git/index.lock" ]; then chroot $mountPoint /bin/rm /home/maintain/aports/.git/index.lock 2>/dev/null || log "INFO: Unable to remove git lock"; fi
    chroot $mountPoint /sbin/apk del alpine-sdk kernel-hardening-checker@additional 2>/dev/null || log "UNEXPECTED: Could not remove development build packages"
}

# Packages installed: policycoreutils@se libselinux@additional libsepol@additional libselinux-utils@additional
configSELinux() {
    return 0
    log "INFO: Configurating SELinux"

    log "INFO: Succesfully configured SELinux"
}

verifyInstallSetup() {
    local missing=0
    # Verify setupAlpine()
    if [ ! -f "$mountPoint/etc/keymap/"$keyboardLayout".bmap.gz" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Keyboard layout not found or differs from expected value"; fi
    if [ "$(chroot $mountPoint /bin/date +%z 2>/dev/null)" != '-0700' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Expected timezone is off"; fi
    if [ "$(chroot $mountPoint /bin/hostname 2>/dev/null)" != "localhost" ] && [ "$(hostname 2>/dev/null)" != "$localhostName" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Hostname does not match to expected values"; fi
    if [ "$(chroot $mountPoint /bin/cat /etc/hosts 2>/dev/null | grep 127.0.0.1)" != '127.0.0.1  localhost.localhost localhost' ] && [ "$(chroot $mountPoint /bin/cat /etc/hosts 2>/dev/null | grep 127.0.0.1)" != "127.0.0.1  $localhostName.$localhostName $localhostName" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Hostname is not resolved in local /etc/hosts file"; fi
    if [ ! -f "$mountPoint/sbin/mdev" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Device is not configured with mdev for lightweigth performance"; fi
    for i in $dnsList; do
        if [ "$(chroot $mountPoint /bin/cat /etc/resolv.conf 2>/dev/null | grep $i)" != "nameserver $i" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not find expected dns server in resolv.conf: $i"; fi
    if [ -z "$(chroot $mountPoint /bin/cat /etc/apk/repositories 2>/dev/null | grep https)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Not using a https repository"; fi
    if [ ! -z "$(chroot $mountPoint /bin/cat /etc/shadow 2>/dev/null | grep root:[*!])" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Root account has no password set, or accepts any password"; fi
    done    

    # Verify that the correct services are listed for setupAlpine()
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep networking)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Networking service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep sshd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSHD service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep crond)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: CronD service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep acpid)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: AcpiD service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep chronyd)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: ChronyD service is not managed currently by OpenRC"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l 2>/dev/null | grep seedrng)" ] && [ "$(rc-chroot $mountPoint /sbin/service -l 2>/dev/null | grep urandom)" != 'urandom' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: seedrng or urandom service is not managed currently by OpenRC"; fi

    # Verify mandatory packages for future installations for setupAlpine()
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep lvm)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find lvm package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep e2fsprogs)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find e2fsprogs package"; fi
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep xfsprogs)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find xfsprogs package"; fi
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

    # TTY interfaces for setupDisks()
    if [ ! -z "$(chroot $mountPoint /bin/grep "^tty" /etc/inittab 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: There is atleast one tty interface enabled"; fi
    if [ ! -z "$(chroot $mountPoint /bin/cat /etc/securetty 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: There is atleast a tty interface enabled for login"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/inittab -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/inittab"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/securetty -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/securetty"; fi

    # Grub for setupDisks()
    if [ -z "$(chroot $mountPoint /bin/grep 'GRUB_TIMEOUT=0' /etc/default/grub 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: The grub menu appears when booting! Possibly interactable"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'modules=sd-mod,usb-storage,ext4 quiet rootfstype=ext4 hardened_usercopy=1 init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on page_alloc.shuffle=1 slab_nomerge pti=on nosmt hash_pointers=always slub_debug=ZF slub_debug=P page_poison=1 iommu.passthrough=0 iommu.strict=1 mitigations=auto,nosmt kfence.sample_interval=100' /etc/default/grub | grep 'GRUB_CMDLINE_LINUX_DEFAULT' 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Linux kernel command line has not been properely set in grub"; fi    
   if [ -z "$(chroot $mountPoint /usr/bin/find /etc/default/grub -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/default/grub"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for initial installation: $missing"; else echo "INFO: Not a single missed test for initial installation!"; fi
}

verifySSHD() {
    local missing=0

    # Check the ssh() function
    if [ -z "$(chroot $mountPoint /bin/ls /etc/ssh/ssh_host_* 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Host keys for SSH identification does not exist!"; fi
    if [ "$(chroot $mountPoint /bin/grep '^PermitRootLogin no' /etc/ssh/sshd_config 2>/dev/null)" != "PermitRootLogin no" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; PermitRootLogin!"; fi
    if [ "$(chroot $mountPoint /bin/grep '^X11Forwarding no' /etc/ssh/sshd_config 2>/dev/null)" != "X11Forwarding no" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; X11Forwarding!"; fi
    if [ "$(chroot $mountPoint /bin/grep '^PasswordAuthentication no' /etc/ssh/sshd_config 2>/dev/null)" != "PasswordAuthentication no" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; PasswordAuthentication!"; fi
    if [ "$(chroot $mountPoint /bin/grep '^IgnoreRhosts yes' /etc/ssh/sshd_config 2>/dev/null)" != "IgnoreRhosts yes" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; IgnoreRhosts!"; fi
    if [ "$(chroot $mountPoint /bin/grep '^PermitEmptyPasswords no' /etc/ssh/sshd_config 2>/dev/null)" != "PermitEmptyPasswords no" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; PermitEmptyPasswords!"; fi
    if [ "$(chroot $mountPoint /bin/grep '^PubkeyAuthentication yes' /etc/ssh/sshd_config 2>/dev/null)" != "PubkeyAuthentication yes" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; PubkeyAuthentication!"; fi
    if [ "$(chroot $mountPoint /bin/grep '^TCPKeepAlive yes' /etc/ssh/sshd_config 2>/dev/null)" != "TCPKeepAlive yes" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; TCPKeepAlive!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep '^ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; ClientAliveInterval!"; fi
    if [ -z "$(chroot $mountPoint /bin/grep '^ClientAliveCountMax' /etc/ssh/sshd_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; ClientAliveCountMax!"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for sshd: $missing"; else echo "INFO: Not a single missed test for sshd!"; fi
}

verifyFirewall() {
    local missing=0
    # Default policy and configurations
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_INPUT_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets that are incoming \(ingress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_OUTPUT_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets that are outgoing \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets meant for routing \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_APPLICATION_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall still accepts application profiles \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "IPV6=no" /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall might accept Ipv6 addresses"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "LOGLEVEL=$ufwLogging" /etc/ufw/ufw.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW has wrong loglevel configured!"; fi

    # Checking for expected open ports
        # Port 80
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for port 80"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p tcp --dport 80 -j RETURN' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for port 80"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p tcp --dport 80 -j ufw-user-logging-output' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for port 80"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p tcp --dport 80 -j ACCEPT -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 4 for port 80"; fi
        # Port 443
    if [ -z "$(chroot $mountPoint /bin/grep -- '' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for port 443"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for port 443"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p tcp --dport 443 -j RETURN' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for port 443"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p tcp --dport 443 -j ufw-user-logging-output' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 4 for port 443"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p tcp --dport 443 -j ACCEPT -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for port"; fi
        # Port 53
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p tcp --dport 53 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for port 53"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p tcp --dport 53 -j RETURN' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for port 53"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p tcp --dport 53 -j ufw-user-logging-output' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for port 53"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p tcp --dport 53 -j ACCEPT -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 4 for port 53"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p udp --dport 53 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 5 for port 53"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p udp --dport 53 -j RETURN' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 6 for port"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p udp --dport 53 -j ufw-user-logging-output' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 7 for port 53"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p udp --dport 53 -j ACCEPT -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 8 for port 53"; fi
        # Port 123
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p udp --dport 123 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for port 123"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p udp --dport 123 -j RETURN' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for port 123"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p udp --dport 123 -j ufw-user-logging-output' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for port 123"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p udp --dport 123 -j ACCEPT -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 4 for port 123"; fi
        # Port 323
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p udp --dport 323 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for port 323"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-output -p udp --dport 323 -j RETURN' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for port 323"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p udp --dport 323 -j ufw-user-logging-output' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for port 323"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-output -p udp --dport 323 -j ACCEPT -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 4 for port 323"; fi
        # Port 22
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-input -p tcp -d 192.168.0.0/24 --dport 22 -s 192.168.0.0/24 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for port 22"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-logging-input -p tcp -d 192.168.0.0/24 --dport 22 -s 192.168.0.0/24 -j RETURN' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for port 22"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-input -p tcp -d 192.168.0.0/24 --dport 22 -s 192.168.0.0/24 -j ufw-user-logging-input' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for port 22"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-input -p tcp -d 192.168.0.0/24 --dport 22 -s 192.168.0.0/24 -m conntrack --ctstate NEW -m recent --set -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 4 for port 22"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-input -p tcp -d 192.168.0.0/24 --dport 22 -s 192.168.0.0/24 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 -j ufw-user-limit -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 5 for port 22"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-input -p tcp -d 192.168.0.0/24 --dport 22 -s 192.168.0.0/24 -j ufw-user-limit-accept -m comment --comment' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 6 for port 22"; fi

    # Checking for general logging
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-after-logging-input -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-after-logging-output -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-after-logging-forward -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-logging-deny -m conntrack --ctstate INVALID -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 4 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-logging-deny -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 5 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-logging-allow -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 6 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-I ufw-before-logging-input -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 7 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-I ufw-before-logging-output -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 8 for logging"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-I ufw-before-logging-forward -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 9 for logging"; fi

    # Rate limiting
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 1 for rate limiting"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-limit -j REJECT' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 2 for rate limiting"; fi
    if [ -z "$(chroot $mountPoint /bin/grep -- '-A ufw-user-limit-accept -j ACCEPT' /etc/ufw/user.rules 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall did not have expected output 3 for rate limiting"; fi

    # Checking file permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ssh -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d/ssh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/apk -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d/apk"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ntp -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d/ntp"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/dns -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/applications.d/dns"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/default/ufw -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/default/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/ufw.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/ufw.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/user.rules -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/user.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/user6.rules -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/ufw/user6.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/python3.12 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/python3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/pydoc3.12 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/pydoc3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/2to3-3.12 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/2to3-3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/xtables-nft-multi -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/xtables-nft-multi"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/iptables-apply -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/iptables-apply"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/ufw -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/nft -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/nft"; fi

    # Is ufw enabled on start up?
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Ufw is yet to be added to rc list"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for firewall setup: $missing"; else echo "INFO: Not a single missed test for firewall!"; fi
}

verifyFail2Ban() {
    local missing=0
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

    # Checking file permissions
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/jail.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/paths-common.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/paths-common.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/paths-debian.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/paths-debian.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/jail.local -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/jail.local"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/fail2ban/fail2ban.conf -perm 0400 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/fail2ban/fail2ban.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/python3.12 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/python3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/pydoc3.12 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/pydoc3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/2to3-3.12 -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/2to3-3.12"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-server -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/fail2ban-server"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-regex -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/fail2ban-regex"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fail2ban-client -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/fail2ban-client"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/xtables-nft-multi -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/xtables-nft-multi"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/iptables-apply -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/iptables-apply"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/logrotate -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/logrotate"; fi

    # Is fail2ban enabled on start up?
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i fail2ban 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Fail2ban is yet to be added to rc list"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for fail2ban: $missing"; else echo "INFO: Not a single missed test for fail2ban!"; fi
}

verifyExecutable() {
    local missing=0
    # Checking /bin executables
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/busybox -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/busybox"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/coreutils -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/coreutils"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/rc-status -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/rc-status"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/setpriv -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/setpriv"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/dmesg -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/dmesg"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /bin/bbsuid -perm 4500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /bin/bbsuid"; fi

    # Checking /sbin executables
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

    # Checking /usr/bin executables
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/xargs -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/xargs"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/find -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/find"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/sha512sum -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/sha512sum"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/fmt -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/fmt"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/bin/env -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/bin/env"; fi
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

    # Checking /sbin/executables
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/partprobe -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/partprobe"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/parted -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/parted"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/sshd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/sshd"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/chronyd -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/chronyd"; fi
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
    
    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for common executables: $missing"; else echo "INFO: Not a single missed test for common executables!"; fi
}

verifyPermissions() {
    local missing=0
    #if [ "$(chroot $mountPoint /bin/ls /etc/modprobe.d/alpine.conf -n 2>/dev/null | awk '{print $1}' 2>/dev/null)" != '-rw-r-----' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for alpine.conf"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/gshadow -n 2>/dev/null | awk '{print $1}' 2>/dev/null)" != '-rw-------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for gshadow"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/shadow -n 2>/dev/null | awk '{print $1}' 2>/dev/null)" != '-rw-------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for shadow"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/ssh/sshd_config -n 2>/dev/null | awk '{print $1}' 2>/dev/null)" != '-rw-------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for sshd_config"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/ssh -n 2>/dev/null | grep sshd_config.d 2>/dev/null | awk '{print $1}' 2>/dev/null)" != 'drwx--x--x' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for sshd_config.d directory"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/periodic/15min -dn 2>/dev/null | awk '{print $1}' 2>/dev/null)" != 'drwx------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for periodic/15min"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/periodic/daily -dn 2>/dev/null | awk '{print $1}' 2>/dev/null)" != 'drwx------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for periodic/daily"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/periodic/hourly -dn 2>/dev/null | awk '{print $1}' 2>/dev/null)" != 'drwx------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for periodic/hourly"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/periodic/monthly -dn 2>/dev/null | awk '{print $1}' 2>/dev/null)" != 'drwx------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for periodic/monthly"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/periodic/weekly -dn 2>/dev/null | awk '{print $1}' 2>/dev/null)" != 'drwx------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for periodic/weekly"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/crontabs/root -n 2>/dev/null | awk '{print $1}' 2>/dev/null)" != '-rw-------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/crontabs/root"; fi
    
    #if [ "$(chroot $mountPoint /usr/bin/find /usr/bin/mount -perm /4000 2>/dev/null)" = '/usr/bin/mount' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SUID bit still inside /usr/bin/mount"; fi
    #if [ "$(chroot $mountPoint /usr/bin/find /usr/bin/umount -perm /4000 2>/dev/null)" = '/usr/bin/umount' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SUID bit still inside /usr/bin/umount"; fi
    #if [ "$(chroot $mountPoint /bin/ls /etc/rc.local -n 2>/dev/null | awk '{print $1}' 2>/dev/null)" != '-rwx------' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for rc.local"; fi
    
    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for setting up expected permissions: $missing"; else echo "INFO: Not a single missed test for setting up expected permissions!"; fi
}

verifyLimitedUsers() {
    local missing=0

    # Local ssh tests to see if users are added
    if [ -z "$(chroot $mountPoint /bin/grep "^AllowUsers $username" /etc/ssh/sshd_config 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: SSH is misconfigured for; AllowUsers for $username!"; fi
    if [ "$(chroot $mountPoint /bin/grep "$sshUsernameKey" /home/"${username}"/.ssh/authorized_keys 2>/dev/null)" != "$sshUsernameKey" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Pub SSH key not authorized for $username!"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for limiting users: $missing"; else echo "INFO: Not a single missed test for limiting users!"; fi
}

verifyKernel() {
    local missing=0
    if [ "$(chroot $mountPoint /bin/grep 'unpriviledged_userns_clone = 0' /etc/sysctl.conf 2>/dev/null)" != '#kernel.unpriviledged_userns_clone = 0' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Kernel not restricted /etc/sysctl.conf"; fi
    if [ "$(chroot $mountPoint /bin/grep '^# Disable kernel module loading' /etc/rc.local 2>/dev/null)" != '# Disable kernel module loading' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Kernel modules are not being disabled after boot in rc.local"; fi
    if [ "$(chroot $mountPoint /usr/bin/md5sum /etc/modprobe.d/alpine.conf 2>/dev/null)" != '09c21d6e87416529fcfe8dfca57aa8d8  /etc/modprobe.d/alpine.conf' ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Hash of /etc/modprobe.d/alpine.conf does not match expected hash to disable unused filesystems"; fi

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for kernel: $missing"; else echo "INFO: Not a single missed test for kernel!"; fi
}

verifySELinux() {
    local missing=0

    # Report total missed test, if above 0
    if [ "$missing" != '0' ]; then echo "INFO: Missed tests for setting up SELinux: $missing"; else echo "INFO: Not a single missed test for SELinux!"; fi
}

# Execution path
main() {
    # Read from environment
    interpretArgs $@
    if [ $(whoami) != "root" ]; then echo "SYSTEM TEST MISMATCH: Required root priviledges"; log "SYSTEM TEST MISMATCH: Insufficient permission to execute alpineVerify.sh"; exit; fi
    printVariables
    
    # Check if no specific tests are set, to enable usage on everything
    if ! $gAlpineSetup && ! $gPartition && ! $gPermissions && ! $gLimitedUsers && ! $gKernel && ! $gExecutable && ! $gSSHD && ! $gFirewall && ! $gFail2Ban && ! $gSELinux; then
        gAlpineSetup=true; gPartition=true; gPermissions=true; gLimitedUsers=true; gKernel=true; gExecutable=true; gSSHD=true; gFirewall=true; gFail2Ban=true; gSELinux=true;
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
	    if $gSSHD; then configSSHD; fi
	    if $gKernel; then configKernel; fi
	    if $gFirewall; then configFirewall; fi
	    if $gFail2Ban; then configFail2Ban; fi
            if $gExecutable; then configExecutables; fi
	    if $gPermissions; then configPermissions; fi
	    if $gLimitedUsers; then configLimitedUsers; fi
	    if $gSELinux; then configSELinux; fi
            log "INFO: Finished post-setup!"
    fi

    # Verification of installation
    if $verify; then
	    log "INFO: Verifying changes!"
            mountAlpine
	    if $gAlpineSetup || $gPartition; then verifyInstallSetup; fi
	    if $gSSHD; then verifySSHD; fi
	    if $gKernel; then verifyKernel; fi
	    if $gFirewall; then verifyFirewall; fi
	    if $gFail2Ban; then verifyFail2Ban; fi
            if $gExecutable; then verifyExecutable; fi
	    if $gPermissions; then verifyPermissions; fi
	    if $gLimitedUsers; then verifyLimitedUsers; fi
	    if $gSELinux; then verifySELinux; fi
            log "INFO: Finished verifying changes!"
    fi

    # Remove alpine installation (yes, even if it was just literally installed)
    if $rmAlpine; then log "INFO: Started execution to remove alpine from mount point"; removeAlpine; fi
    log "INFO: Finished executing script!"
}

main "$@"

# Inspiring links:
# - https://github.com/captainzero93/security_harden_linux/blob/main/improved_harden_linux.sh
# - https://github.com/peass-ng/PEASS-ng
# - https://cisofy.com/lynis/
# Cool legacy bash script code
#    if $pre; then log "INFO: Applying script modifications!"; if [ -x alpinePre.sh ]; then . ./alpinePre.sh; else retrieveScripts alpinePre.sh; fi; fi
#    if $post; then log "INFO: Applying script modifications!"; if [ -x alpinePost.sh ]; then . ./alpinePost.sh; else retrieveScripts alpinePost.sh; fi; fi
#    if $verify; then log "INFO: Verifying script modifications..."; if [ -x alpineVerify.sh ]; then . ./alpineVerify.sh; else retrieveScripts alpineVerify.sh; fi; fi
#    # Are we in a live-iso, or somewhere else?
#    if [ -z "$(df ~ | grep -i tmpfs | awk '{print $1}')" ]; then chrootPoint="/"; else chrootPoint=$mountPoint; mountAlpine; fi
# chroot $mountPoint /bin/exec arg 2>/dev/null | grep something
# chroot / /bin/cat /etc/passwd 2>/dev/null | grep root
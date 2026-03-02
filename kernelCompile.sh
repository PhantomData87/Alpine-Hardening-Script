#!/bin/sh

# Setting up kernel configuration on an already mounted kernel storage device


# Modify kernel manually with ncurses-dev; chroot /mnt/alpine /usr/bin/make menuconfig -C /home/$buildUsername/aports/main/linux-lts/src/linux-6.12
# Features; update linuxConfig.config, customize linuxConfig.config, install kernel, update github, repair filesystem, and auto-select latest kernel with specific features

	
	
	
# Variables expected to be configured	
export version="1.0.0"
export logFile="/tmp/customKernel.log"
export kernelPartitionSector="2048" # USED IF IT IS A NEW DISK. Leave this as 2048, as it determines which sector on the device to use. Leave it alone, unless you know what you are doing
export buildUsername="maintain" # Username that can build the linux kernel, and install it
export gitPackageCommitHash="286b542594d5b89dbe3f49f9faf4ba9e9f34f8d3" # Scroll through original aports git repo to set the desired hash

# Variables that will be filled in by the user when script reaches prepareMountEnvironment
export mountPoint=""
export kernelPartition=""

# Variables meant to increase readability
export hardeningPatchUrl="https://github.com/anthraxx/linux-hardened/releases/download/v$kernelVersion-hardened1/linux-hardened-v$kernelVersion-hardened1"
export kernelVersion="$(uname -r | grep -Eo '[0123456789]{1,3}.[0123456789]{1,3}.[0123456789]{1,3}')" # Ensure this remains in the correct format of x.x.x, otherwise leave this alone as "$(uname -r | grep )"	
export systemArch="$(uname -m)" # Leave this as "$(uname -m)" to automatically find system architecture. If building on a different system, then change this into one of the many values: x86_64, x86, arm*, aarch64, riscv64, loongarch64
systemArchFallbackName=""
	# Fallback bootloader name for boot*.efi file in $bootPartition/EFI/boot/
#case $systemArch in
#  	x86_64 ) systemArchFallbackName="x64";;
#   	x86 ) systemArchFallbackName="ia32";;
#   	arm* ) systemArchFallbackName="arm";;
#   	aarch64 ) systemArchFallbackName="aa64";;
#   	riscv64 ) systemArchFallbackName="riscv64";;
#   	loongarch64 ) systemArchFallbackName="loongarch64";;
#esac

# Variables that are flags meant to represent user action
export verbose=false
export gLocal=false
export gKernelPartition=false # Intention to reset or create new partitions of Kernel disk storage
export gNewConfig=false
export gUpdate=false
export gPackageGone=false

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
Usage: ./kernelCompile.sh [ACTIONS]
Version: $version

Actions: User must specify atleast one action
	-h, --help		Display this help message
	-v, --verbose		Enable verbose logging or display more help information
	--stayLocal		Configure services and security on local machine
	--kernelFormat		Configure to install a locally sourced kernel from external device
	--newConfig		Create a brand new linux kernel config
	--updateConfig		Run an interactive process (with ncurses) to adjust & update configuration file for the linux kernel
	--removePackages	Remove linux kernel packages after compiling the kernel"
    if $verbose; then echo ""; else return 0; fi
echo "Internal variables to configure script:
version:			Version of the script
kernelVersion:			Indicate the linux kernel version that is desired in x.x.x format.
logFile:			Where to save log messages
kernelPartition:		Device that contains a github aports repository meant for compiling, configurating, and installing a kernel from
kernelPartitionSector:		Specifies the natural offset of the device's partition to avoid overwriting the superblock of filesystems.
buildUsername:			Alpine uses abuild which required signing keys, and it makes more sense to have these keys not be stored in root (to avoid relying solely on root)
mountPoint:			Facilitate chroot environment
gitPackageCommitHash:		Declare where in the git repository we will interact with based on prior history
hardeningPatchUrl:		The URL to obtain security patches that are recommended from KSSP (Kernel Self Protection Project)
systemArch:			Indicates the target architecture we wish to compile our kernel for
Note: $logFile will be set if the variable is empty upon execution."
    exit;
}

# Interpret args
interpretArgs() {
    local wantHelp=false
    for i in "${@}"; do
      case "$i" in
        -h|--help) wantHelp=true;;
        -v|--verbose) verbose=true;;
        --stayLocal) gLocal=true;;
        --kernelFormat) gKernelPartition=true;;
        --newConfig) gNewConfig=true;;
        --updateConfig) gUpdate=true;;
        --removePackages) gPackageGone=true;;
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

    # Log file existence
    touch $logFile 2>/dev/null || echo "SYSTEM TEST MISMATCH: Cannot create log file!"
    if ! [ -r "$logFile" ] || ! [ -w "$logFile" ]; then echo "CRITICAL: Cannot write and read log file in: $logFile"; exit; fi

    # Null check
    if [ -z "$version" ]; then echo "BAD FORMAT: Provide any number to indicate the version of this script! Fill in \$version"; exit; fi
    if [ -z "$logFile" ]; then echo "BAD FORMAT: Will default to /tmp/hardeningAlpine.log due to \$logFile being empty!"; fi
    if [ -z "$kernelPartitionSector" ]; then echo "BAD FORMAT: Must indicate the starting kernel sector offset for formating the kernel partition. Change \$kernelPartitionSector"; exit; fi
    if [ -z "$buildUsername" ]; then echo "BAD FORMAT: Declare username that will be used to build linux kernel! Edit: \$buildUsername and include a name!"; exit; fi
    if [ -z "$gitPackageCommitHash" ]; then echo "BAD FORMAT: Must provide a legitimate sha256 hash from \$hardeningPatchUrl! Edit: \$gitPackageCommitHash!"; exit; fi
    if [ -z "$hardeningPatchUrl" ]; then echo "BAD FORMAT: Provide a URL to obtain hardening patch from! Edit: \$hardeningPatchUrl!"; exit; fi
    if [ -z "$kernelVersion" ]; then echo "BAD FORMAT: Provide a valid kernel version in x.x.x format! Edit: \$kernelVersion!"; exit; fi
    if [ -z "$systemArch" ]; then echo "BAD FORMAT: Must declare system architecture for var \$systemArch, leave it as default \"\$(uname -m)\""; exit; fi

    # Format check
    if ! (echo $logIP | grep -Eq ^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$); then echo "BAD FORMAT: Not a valid IPv4 format IP address for logging capabilities! Edit: \$logIP"; exit; fi
    if ! (echo $localGateway | grep -Eq ^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$); then echo "BAD FORMAT: Not a valid IPv4 format IP address for local LAN network! Edit: \$localGateway"; exit; fi
    local checkFail=false
    for i in $dnsList; do # Verify valid ipv4 format of dnslist
        if ! (echo $i | grep -Eq ^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$); then echo "BAD FORMAT: Not a valid ip address declared within the \$dnsList: $i" 2>/dev/null; checkFail=true; fi
    done
    if $checkFail; then exit; fi
    for j in $apkRepoList; do
        if ! (echo $j | grep -Eq "^https://[^ ]*[^/]$"); then echo "BAD FORMAT: Invalid format for a URL declared within $apkRepoList: $j" 2>/dev/null; checkFail=true; fi
    done
    if $checkFail; then exit; fi
    if (! echo $rootSize | grep -Eq -e ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$ -e ^[0-9]*[.]\{0,1\}[0-9]+EX$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size type expected in \$rootSize: $rootSize" 2>/dev/null; exit; fi
    if (! echo $homeSize | grep -Eq -e ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$ -e ^[0-9]*[.]\{0,1\}[0-9]+EX$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size type expected in \$homeSize: $homeSize" 2>/dev/null; exit; fi
    if (! echo $varSize | grep -Eq -e ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$ -e ^[0-9]*[.]\{0,1\}[0-9]+EX$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size type expected in \$varSize: $varSize" 2>/dev/null; exit; fi
    if (! echo $varTmpSize | grep -Eq -e ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$ -e ^[0-9]*[.]\{0,1\}[0-9]+EX$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size type expected in \$varTmpSize: $varTmpSize" 2>/dev/null; exit; fi
    if (! echo $varLogSize | grep -Eq -e ^[0-9]*[.]\{0,1\}[0-9]+[kKmMgGtTpPeE]$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTP]B$ -e ^[0-9]*[.]\{0,1\}[0-9]+EX$ -e ^[0-9]*[.]\{0,1\}[0-9]+[KMGTPE]iB$); then echo "BAD FORMAT: Not a valid declaration for the size type expected in \$varLogSize: $varLogSize" 2>/dev/null; exit; fi
    if (! echo $timezone | grep -Eq [A-z]+/[A-z]); then echo "BAD FORMAT: Not a valid timezone declaration in var \$timezone! $timezone" 2>/dev/null; exit; fi
    if (! echo $sshPort | grep -Eq ^[0-9]) && [ $sshPort -le 1023 ] && [ $sshPort -ge 0 ] && [ $sshPort != 22 ]; then echo "BAD FORMAT: Must provide a valid port number for \$sshPort that is in range of 1-1023, and is not 22!"; exit; fi
    if (! echo $umask | grep -Eq ^[0-9][0-9][0-9]); then echo "BAD FORMAT: Must provide a valid umask in 3 digit format in var \$umask; like 022 or 077!"; exit; fi
    if (echo $systemArch | grep -v -e ^x86_64$ -e ^x86$ -e ^arm.*$ -e ^aarch64$ -e ^riscv64$ -e ^loongarch64$); then echo "BAD FORMAT: Invalid system architecture found in var \$systemArch! Please default to \"\$(uname -m)\" or provide the right accepted architecture value for \$systemArch"; exit; fi
    if (echo $kernelVersion | grep -Eo '[0123456789]{1,3}.[0123456789]{1,3}.[0123456789]{1,3}'); then echo "BAD FORMAT: Invalid linux kernel version defined. Leave it as \"\$(uname -r | grep -Eo '[0123456789]{1,3}.[0123456789]{1,3}.[0123456789]{1,3}')\", or insert a valid kernel version"; exit; fi
    
    log "INFO: Finished reading all variables: $*"
}

# Display list of devices, and consider mount & format locations for kernel, before proceeding
prepareMountEnvironment() {
	log "INFO: Finding kernel device"
	local devBlockSize=1024 # /proc/partitions shows size in 1024-byte blocks; https://unix.stackexchange.com/questions/512945/what-units-are-the-values-in-proc-partitions-and-sys-dev-block-block-size
	local devName=""
	local devBlock=""
	local devLabel=""
	local devType=""
	local showAgain=false
	if $gLocal; then mountPoint="/"; fi
	while ! $gLocal; do
		# Show devices list with size and possible label included
		if $showAgain; then
			echo -e "Device     \tSize     \tType\tLabel (if it exists)\n"
			cat /proc/partitions | grep -ivE ram\|loop\|major\|dm\- | while read -r statLine; do
				if [ "$statLine" = '' ]; then continue; fi
            	devName="$(echo $statLine | awk -F ' {1,}' '{print($4)}')"
           		devBlock="$(echo $statLine | awk -F ' {1,}' '{print($3)}')"
            	devBlock="$(awk "BEGIN {if ((($devBlock*$devBlockSize)/1073741824) > 1) {print (($devBlock*$devBlockSize)/1073741824) \" GB\"} else {print (($devBlock*$devBlockSize)/1048576) \" MB\"}}")"
            	devType="$(blkid /dev/$devName | awk -F 'TYPE' 'NF>1{sub(/="/,"",$NF);sub(/".*/,"",$NF);print $NF}')"
            	devLabel="$(ls -l /dev/disk/by-label/ | grep -w $devName)"
            	echo -e "$devName     \t$devBlock \t$devType\t$devLabel"
        	done
        fi
        showAgain=false
        
        # Determine location of kernel sector, and consider requests that are yet to be formatted
        while ! $kernelSectorChosen && ! $showAgain; do
            read -p "From the list above. Specify destination for kernel partition that is xfs [Type 'a' to abort, or 'l' to show list]: " kernelPartition
            kernelPartition="/dev/$(echo $kernelPartition | grep -Eo [^\/]*$)" # Append /dev/
            case $kernelPartition in
                /dev/a ) exit;;
                /dev/A ) exit;;
                /dev/l ) showAgain=true; kernelPartition=""; continue;;
                /dev/L ) showAgain=true; kernelPartition=""; continue;;
                *)
                	# Temporarely pretend the user choose valid options
                	kernelSectorChosen=true
                	kernelExist=true
                	;;
            esac
        done

        # Start beginning of loop check
        	# Emptyness check
        if [ -z "$kernelPartition" ]; then showAgain=true; kernelSectorChosen=false; kernelExist=false; echo "Empty value for kernelPartition"; fi
        if $showAgain; then continue; fi
        
	    	# Valid partition scheme
	    if [ -z "$(echo $kernelPartition | grep -E -o [^1234567890][^p][1234567890]+$\|p[1234567890]+$)" ]; then echo "Partition formatting for $kernelPartition is invalid. Please specify a number correctly [either # or p#] at tail end"; kernelSectorChosen=false; kernelPartition=""; kernelExist=false; fi
		if ! $kernelSectorChosen; then continue; fi # Reset
		
	    	# Formatting acknowledgment, and valid block device check
    	if [ ! -b "$kernelPartition" ] && $gKernelPartition; then echo "kernelPartition at $gKernelPartition partition currently does not exist, but will format due to gKernelPartition being specified as $gKernelPartition"; kernelExist=false; fi
		if [ ! -b "$kernelPartition" ] && $kernelExist; then echo "xfs kernelPartition at $kernelPartition partition currently does not exist, and formatting is currently disabled. Specify a valid existing disk, or enable formatting"; kernelPartition=""; kernelSectorChosen=false; kernelExist=false; fi
		if ! $kernelSectorChosen; then continue; fi # Reset
        
        	# Final sanity check when formatting is disabled: IS kernel xfs?
        if [ "$(blkid $kernelPartition | awk -F 'TYPE' 'NF>1{sub(/="/,"",$NF);sub(/".*/,"",$NF);print $NF}')" != "xfs" ] && ! $gKernelPartition; then echo "Partition at $kernelPartition is not xfs! Enable formatting or pick a different partition"; blockList="\?"; kernelPartition=""; kernelSectorChosen=false; kernelExist=false; fi
		if ! $kernelSectorChosen; then continue; fi # Reset
        
        # Break loop if everything is satisfied
        if $kernelSectorChosen; then break; fi
	done
	log "INFO: Kernel device at; $kernelPartition, Does kernel exist? $kernelExist"
	
		# Ensure $mountPoint is defined in a directory of /mnt
	if ! $gLocal; then
		log "INFO: Ensuring mountPoint is declared in /mnt directory, and exists"
		while [ -z $mountPoint ] || [ "$mountPoint" = "/" ] || [ -z "$(echo $mountPoint | grep -E ^/mnt/.+$)" ]; do
			echo "Directory of /mnt: $(ls -lah /mnt)"
			read -p "Invalid mountpoint is declared at: $mountPoint. Type in an existing or new directory name to select where Alpine installation is currently located within /mnt directory [Type 'a' to abort]: " mountPoint
			mountPoint="/mnt/$(echo $mountPoint | grep -Eo [^\/]*$)" # Append /dev/
			case $mountPoint in
            	/mnt/a ) exit;;
            	/mnt/A ) exit;;
			esac
		done # Create directory
		mkdir -p $mountPoint
	fi
	
	log "INFO: Preparing chroot environment binds (not checking if filesystem has /etc and /home directory!)"
	if [ -z "$(mount | grep "proc on $mountPoint/proc " 2>/dev/null)" ]; then mount -t proc proc "$mountPoint"/proc 2>/dev/null || log log "CRITICAL: Could not make /proc available in chroot environment"; fi
    if [ -z "$(mount | grep "sysfs on $mountPoint/sys " 2>/dev/null)" ]; then mount -o bind /sys "$mountPoint"/sys 2>/dev/null || log "CRITICAL: Could not make /sys available in chroot environment"; fi
    if [ -z "$(mount | grep "devtmpfs on $mountPoint/dev " 2>/dev/null)" ]; then mount -o bind /dev "$mountPoint"/dev 2>/dev/null || log "CRITICAL: Could not make /dev available in chroot environment"; fi
    if [ -z "$(mount | grep "tmpfs on $mountPoint/run " 2>/dev/null)" ]; then mount -o bind /run "$mountPoint"/run 2>/dev/null || log "CRITICAL: Could not make /run available in chroot environment"; fi
	
	log "INFO: Check if $buildUsername username is already created"
	if [ -z "$(chroot $mountPoint /bin/grep $buildUsername /etc/passwd)" ]; then
    	chroot $mountPoint /usr/sbin/adduser -h /home/$buildUsername -S -D -s /sbin/nologin $buildUsername 2>/dev/null || log "CRITICAL: Could not create an account for building the kernel"
    	chroot $mountPoint /usr/sbin/addgroup $buildUsername abuild 2>/dev/null || log "CRITICAL: Could not include $buildUsername into abuild group"
    	chroot $mountPoint /usr/sbin/addgroup $buildUsername wheel 2>/dev/null || log "UNEXPECTED: Could not include $buildUsername into admin group"
    	log "INFO: Finished adding in $buildUsername as limited user to handle kernel installation, updating, and etc"
    fi
	
	log "INFO: Ensuring required packages are being installed"
	chroot $mountPoint /sbin/apk add git alpine-sdk kernel-hardening-checker@additional 2>/dev/null || log "CRITICAL: Could not install required packages for kernel"
	
	if $gKernelPartition; then
		# Kernel formatting
    	local partKernelNumber="$(echo $kernelPartition | grep -Eo [0123456789]*$)"
    	local deviceKernel="$(echo $kernelPartition | sed "s/p\?$partKernelNumber//g")"
    	if ! $kernelExist; then
# !!! parted create?
			parted -a optimal "$deviceKernel" "mkpart primary xfs $kernelPartitionSector 100%" 2>/dev/null || log "CRITICAL: Could not declare kernel block device partition"
    		parted -a optimal "$deviceKernel" "align-check optimal $partKernelNumber" 2>/dev/null || log "UNEXPECTED: Could not optimize placement of kernel block partition"
    		mdev -s 2>/dev/null || log "CRITICAL: Could not restart mdev service to recognize new disks"
			log "INFO: Location: $deviceKernel, Number: $partKernelNumber"
    	fi
    	log "INFO: Passed kernel partitioning stage"

    	# Format drives
		mkfs.xfs -f "$kernelPartition" 2>/dev/null || log "CRITICAL: Could not format kernel block device"
    	log "INFO: Passed kernel formatting stage"
    fi

	log "INFO: Checking health of disk that contains kernel"		
	mount | grep "$kernelPartition" | awk '{print($3)}' | while read -r kerPartition; do
		log "INFO: Found existing partition that contains kernel device mounted! Removing mounting point at: $kerPartition"
		umount kerPartition || log "CRITICAL: Could not ensure safety of kernel device before xfs_repair is executed!"
	done
	xfs_repair "$kernelPartition" || log "UNEXPECTED: Xfs filesystem that stores the kernel could not guarantee it was repaired correctly"

	log "INFO: Mounting kernel device onto $mountPoint/home/$buildUsername AFTER it was potentially repaired"
    chroot $mountPoint /bin/mkdir -p "/home/$buildUsername" 2>/dev/null || log "UNEXPECTED: Lacked capabilities to create mountpoint directory on $mountPoint/home/$buildUsername"
	mount -t xfs "$kernelPartition" "$mountPoint"/home/$buildUsername 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount on $mountPoint/home/$buildUsername"	
    chroot $mountPoint /bin/chmod 760 /home/$buildUsername 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername directory"
    chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername 2>/dev/null || log "UNEXPECTED: Could not ensure home directory of $buildUsername is owner"
	
	
    # !!! TODO; or install github for first time
    log "INFO: Synchronizing aports github with desired kernel version"
#    if [ -f "$mountPointhome/$buildUsername/aports/.git/index.lock" ]; then chroot $mountPoint /bin/rm home/$buildUsername/aports/.git/index.lock 2>/dev/null || log "INFO: Unable to remove git lock"; fi
#    if [ -d "$mountPointhome/$buildUsername/aports/main/linux-lts/src" ]; then chroot $mountPoint /bin/rm -R home/$buildUsername/aports/main/linux-lts/src 2>/dev/null || log "INFO: Unable to remove old kenrel source files"; log "INFO: Finished removing old src directory in aports/main/linux-lts"; fi
#    if [ -d "$mountPointhome/$buildUsername/aports/main/linux-lts/pkg" ]; then chroot $mountPoint /bin/rm -R home/$buildUsername/aports/main/linux-lts/pkg 2>/dev/null || log "INFO: Unable to remove old kenrel built files"; log "INFO: Finished removing old pkg directory in aports/main/linux-lts"; fi
#    chroot $mountPoint /usr/bin/git config --global --add safe.directory home/$buildUsername/aports || log "UNEXPECTED: Could not guanratee that git thinks home/$buildUsername/aports is safe directory"
#    chroot $mountPoint /usr/bin/git -C home/$buildUsername/aports reset --hard "$gitPackageCommitHash" || log "UNEXPECTED: Could not set branch to expected kernel version $kernelVersion"
#    chroot $mountPoint /bin/chown "$buildUsername:root" -R home/$buildUsername 2>/dev/null || log "UNEXPECTED: Could not ensure home directory of $buildUsername is owner"
#    chroot $mountPoint /bin/chmod +x home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "CRITICAL: Could not enable execution to APKBUILD"   
	# Obtain github for the first time
#    log "INFO: Downloading aports Alpine linux github repo for various packages"
#    chroot $mountPoint /usr/bin/git -C /home/$buildUsername clone git://git.alpinelinux.org/aports.git 2>/dev/null || log "CRITICAL: Could not obtain github repo to install kernel"
    	
    # Setup default directories
    log "INFO: Setting up default directories ownership and permissions to permit access for $buildUsername user"
    chroot $mountPoint /bin/chmod 760 /home/$buildUsername/aports 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports directory"
	chroot $mountPoint /bin/chmod 760 /home/$buildUsername/aports/main 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports/main directory"
    chroot $mountPoint /bin/chmod -R 760 /home/$buildUsername/aports/main/linux-lts 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports/main/linux-lts directory"
    chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername/aports 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports directory"
	chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername/aports/main 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports/main directory"
   	chroot $mountPoint /bin/chown -R "$buildUsername:root" /home/$buildUsername/aports/main/linux-lts 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports/main/linux-lts directory"
    
    log "INFO: Finished setting up temporary doas configuration!"
    chroot $mountPoint /bin/echo "permit nopass :wheel as $buildUsername cmd /usr/bin/abuild-keygen args -a -i -n" > $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuilld-keygen permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass :wheel cmd mkdir" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide mkdir permissions to members apart of wheel group"
    chroot $mountPoint /bin/echo "permit nopass :wheel cmd cp" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide cp permissions to members apart of wheel group"
    chroot $mountPoint /bin/echo "permit nopass :wheel as $buildUsername cmd /usr/bin/abuild args -C /home/$buildUsername/aports/main/linux-lts checksum" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuild checksum permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass :wheel as $buildUsername cmd /usr/bin/abuild args -C /home/$buildUsername/aports/main/linux-lts -crK" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuild build permissions to be run as $buildUsername"
    chroot $mountPoint /bin/chmod 0400 /etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/doas.d/kernelBuild.conf file permissions"
    
    log "INFO: Checking if abuild can use $buildUsername keys that should be stored in /etc/apk/keys"
    if [ -z "$(chroot $mountPoint /bin/ls /etc/apk/keys | grep -v alpine-devel)" ]; then
        log "INFO: Generating signing key"
        chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild-keygen -a -i -n || log "UNEXPECTED: Could not generate keys for $buildUsername"
        chroot $mountPoint /bin/chmod a+r /etc/apk/keys/* 2>/dev/null || log "UNEXPECTED: Could not enable keys stored in /etc/apk/keys to be read by $buildUsername"
    fi
    
    log "INFO: Does linux kernel configuration exist in the correct spot?"
    if [ ! -f "$mountPoint/home/$buildUsername/linuxConfig.config" ]; then chroot $mountPoint /bin/touch "/home/$buildUsername/linuxConfig.config" || log "UNEXPECTED: Could not place linuxConfig.config file in /home/$buildUsername"; fi
    if [ "$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/linuxConfig.config)" != "$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config)" ]; then
        # Move the new file
        log "INFO: Moving file linuxConfig.config into lts.$systemArch.config with the following md5sum: $(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/linuxConfig.config) = $(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config)"
        chroot $mountPoint /bin/cp /home/$buildUsername/linuxConfig.config "/home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config" 2>/dev/null || log "CRITICAL: Wrong kernel configuration file is set!"
        chroot $mountPoint /bin/chown "$buildUsername:root" "/home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config" 2>/dev/null || log "UNEXPECTED: Could not ensure kernel config file is owned by $buildUsername"
    fi
    
    log "INFO: The system is ready to compile the linux kernel in a Alpine environment"
}

# Prepare envirnment for ncurses interactive screen; permits manually configurating and updating linux kernel configurations
ncurseSetup() {
	log "INFO: Finished preparing ncurse environemnt for creating or updating linux kernel configuration"
}

# !!!
interactKernelConfig() {
	log "INFO: Finished creating linux configuration script! Lets hope it was configured correctly"
}

# !!!
updateKernelConfig() {
	log "INFO: Finished creating linux configuration script! Lets hope it was updated correctly"
}

compileKernel() {
	if [ ! -f "$mountPointhome/$buildUsername/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" ] || [ ! -f "$mountPointhome/$buildUsername/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" ]; then
        log "INFO: Obtaining kernel patches based on linux hardening alpine guide"
        chroot $mountPoint /usr/bin/wget -O "home/$buildUsername/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" "$hardeningPatchUrl.patch" || log "UNEXPECTED: Could not download patch into kernel"
        chroot $mountPoint /usr/bin/wget -O "home/$buildUsername/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" "$hardeningPatchUrl.patch.sig" || log "UNEXPECTED: Couldd not download patch signature key into kernel"
        chroot $mountPoint /bin/chown "$buildUsername:root" "home/$buildUsername/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" 2>/dev/null || log "UNEXPECTED: Could not ensure kernel patch file is owned by $buildUsername"
        chroot $mountPoint /bin/chown "$buildUsername:root" "home/$buildUsername/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" 2>/dev/null || log "UNEXPECTED: Could not ensure kernel patch signature file is owned by $buildUsername"
    fi
    
    # !!! TODO; make sed more modern and less reliant on gibberish
    log "INFO: Configurating APKBUILD file to include only relevant files"
    chroot $mountPoint /bin/sed -i ':a;N;$!ba;s/lts.aarch64.config\n\tlts.armv7.config\n\tlts.loongarch64.config\n\tlts.ppc64le.config\n\tlts.riscv64.config\n\tlts.s390x.config\n\tlts.x86.config\n\tlts.x86_64.config/REPLACEME.patch1\n\tREPLACEME.patch2\n\tlts.REPLACEME.config/g' home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not prepare APKBUILD's source first configuration"
    chroot $mountPoint /bin/sed -i ':a;N;$!ba;s/virt.aarch64.config\n\tvirt.armv7.config\n\tvirt.ppc64le.config\n\tvirt.x86.config\n\tvirt.x86_64.config/virt.REPLACEME.config/g' home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not prepare APKBUILD's source second configuration"
    chroot $mountPoint /bin/sed -i "s/lts.REPLACEME.config/lts.$systemArch.config/1" home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not finish APKBUILD's source second configuration"
    chroot $mountPoint /bin/sed -i "s/virt.REPLACEME.config/virt.$systemArch.config/1" home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not finish APKBUILD's source third configuration"
    chroot $mountPoint /bin/sed -i "s/REPLACEME.patch1/0098-linux-hardened-v$kernelVersion.patch/1" home/$buildUsername/aports/main/linux-lts/APKBUILD || log "UNEXPECTED: Could not finish APKBUILD's source first configuration" || log "UNEXPECTED: Could not finish APKBUILD's source optinal hardening patch file"
    chroot $mountPoint /bin/sed -i "s/REPLACEME.patch2/0099-linux-hardened-v$kernelVersion.patch.sig/1" home/$buildUsername/aports/main/linux-lts/APKBUILD || log "UNEXPECTED: Could not finish APKBUILD's source first configuration" || log "UNEXPECTED: Could not finish APKBUILD's source optional hardening patch signature file"
    
    log "INFO: Performing checksum on everything"
    chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild -C home/$buildUsername/aports/main/linux-lts checksum || log "UNEXPECTED: Could not compile checksum of everything modified so far"
    
    log "INFO: Compiling kernel at; $(date)"
    time -o /tmp/compileTime chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild -C home/$buildUsername/aports/main/linux-lts -crK 2>&1 | tee /tmp/kernelLog || log "CRITICAL: Could not finish compiling kernel"
    		
    log "INFO: The kernel took to compile: $(cat /tmp/compileTime)"
    rm /tmp/compileTime || log "UNEXPECTED: Could not remove temporary file to keep track the length of time it took the kernel to compile"
    
    log "INFO: Finished compiling kernel at roughly; $(date)"
}
	
# Execution path
main() {
    # Read from environment
    interpretArgs $@
    if [ $(whoami) != "root" ]; then echo "SYSTEM TEST MISMATCH: Required root priviledges"; log "SYSTEM TEST MISMATCH: Insufficient permission to execute alpineVerify.sh"; exit; fi
    
    # Setup environment & format
    prepareMountEnvironment
    
    if $gNewConfig; then interactKernelConfig; fi
    if $gUpdate; then updateKernelConfig; fi
    compileKernel
    
    log "INFO: Cleaning up"
    if [ -f "$mountPoint/etc/doas.d/kernelBuild.conf" ]; then chroot $mountPoint /bin/rm /etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Permission doas file has not been deleted to enforce principle of least priviledge"; fi
	if $gPackageGone; then chroot $mountPoint /sbin/apk del alpine-sdk kernel-hardening-checker@additional 2>/dev/null || log "UNEXPECTED: Could not remove development build packages"; fi
    log "INFO: Finished executing script!"
}

main "$@"

#!/bin/sh

# Setting up kernel configuration on an already mounted kernel storage device

# Features; update linuxConfig.config, customize linuxConfig.config, obtain defualt linuxConfig.config from source, install and compile kernel, update git repo to correct kernel version, filter git repo, and finally repair filesystem

# !!! TODO	install kernel
	
	
# Variables expected to be configured	
export version="1.0.0"
export logFile="/tmp/customKernel.log"
export kernelPartitionSector="2048" # USED IF IT IS A NEW DISK. Leave this as 2048, as it determines which sector on the device to use. Leave it alone, unless you know what you are doing
export buildUsername="maintain" # Username that can build the linux kernel, and install it

# Variables that will be filled in by the user when script reaches prepareMountEnvironment
export mountPoint=""
export kernelPartition=""

# Variables meant to increase readability
export hardeningPatchUrl="https://github.com/anthraxx/linux-hardened/releases/download/v$kernelVersion-hardened1/linux-hardened-v$kernelVersion-hardened1"
export kernelVersion="$(uname -r | grep -Eo '[0123456789]{1,3}.[0123456789]{1,3}.[0123456789]{1,3}')" # Ensure this remains in the correct format of x.x.x, otherwise leave this alone as "$(uname -r | grep )"	
export systemArch="$(uname -m)" # Leave this as "$(uname -m)" to automatically find system architecture. If building on a different system, then change this into one of the many values: x86_64, x86, arm*, aarch64, riscv64, loongarch64
systemArchFallbackName=""
linuxRevision="$(echo $kernelVersion | grep -Eo '[0123456789]{1,3}.[0123456789]{1,3}')" # Just shortens the name of $kernelVersion. Do not edit
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
export gCompile=false

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
	--removePackages	Remove linux kernel packages after compiling the kernel
	--compile		Compiles the linux kernel based on the configuration file provided"
    if $verbose; then echo ""; else return 0; fi
echo "Internal variables to configure script:
version:			Version of the script
kernelVersion:			Indicate the linux kernel version that is desired in x.x.x format.
logFile:			Where to save log messages
kernelPartition:		Device that contains a github aports repository meant for compiling, configurating, and installing a kernel from
kernelPartitionSector:		Specifies the natural offset of the device's partition to avoid overwriting the superblock of filesystems.
buildUsername:			Alpine uses abuild which required signing keys, and it makes more sense to have these keys not be stored in root (to avoid relying solely on root)
mountPoint:			Facilitate chroot environment
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
        --compile) gCompile=true;;
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
    if (! echo $kernelVersion | grep -Eo '[0123456789]{1,3}.[0123456789]{1,3}.[0123456789]{1,3}'); then echo "BAD FORMAT: Invalid linux kernel version defined. Leave it as \"\$(uname -r | grep -Eo '[0123456789]{1,3}.[0123456789]{1,3}.[0123456789]{1,3}')\", or insert a valid kernel version"; exit; fi
    
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
	# TODO: Ensure no password login or shell login!
	if [ -z "$(chroot $mountPoint /bin/grep $buildUsername /etc/passwd)" ]; then
    	chroot $mountPoint /usr/sbin/adduser -h /home/$buildUsername -S -D -s /sbin/nologin $buildUsername 2>/dev/null || log "CRITICAL: Could not create an account for building the kernel"
    	chroot $mountPoint /usr/sbin/addgroup $buildUsername abuild 2>/dev/null || log "CRITICAL: Could not include $buildUsername into abuild group"
    	chroot $mountPoint /usr/sbin/addgroup $buildUsername coreutils 2>/dev/null || log "CRITICAL: Could not include $buildUsername into coreutils group"
    	chroot $mountPoint /usr/sbin/addgroup $buildUsername busybox 2>/dev/null || log "CRITICAL: Could not include $buildUsername into busybox group"
    	chroot $mountPoint /usr/sbin/addgroup $buildUsername apk 2>/dev/null || log "UNEXPECTED: Could not include $buildUsername into apk group"
# TODO !!! Test without this group    	chroot $mountPoint /usr/sbin/addgroup $buildUsername wheel 2>/dev/null || log "UNEXPECTED: Could not include $buildUsername into admin group"
    	log "INFO: Finished adding in $buildUsername as limited user to handle kernel installation, updating, and etc"
    fi
	
	log "INFO: Ensuring required packages are being installed" #kernel-hardening-checker@additional
	chroot $mountPoint /sbin/apk add git alpine-sdk ncurses-dev flex bison 2>/dev/null || log "CRITICAL: Could not install required packages for kernel"
	
	if $gKernelPartition; then
		# Kernel formatting
    	local partKernelNumber="$(echo $kernelPartition | grep -Eo [0123456789]*$)"
    	local deviceKernel="$(echo $kernelPartition | sed "s/p\?$partKernelNumber//g")"
    	if ! $kernelExist; then
# TODO !!! parted create?
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
	
	
    log "INFO: Finished setting up temporary doas configuration!"
    chroot $mountPoint /bin/echo "permit nopass :wheel as $buildUsername cmd /usr/bin/abuild-keygen args -a -i -n" > $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuilld-keygen permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass :wheel cmd mkdir" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide mkdir permissions to members apart of wheel group"
    chroot $mountPoint /bin/echo "permit nopass :wheel cmd cp" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide cp permissions to members apart of wheel group"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/abuild args -C /home/$buildUsername/aports/main/linux-lts checksum" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuild checksum permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/abuild args -C /home/$buildUsername/aports/main/linux-lts -crK" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuild build permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/abuild args -C /home/$buildUsername/aports/main/linux-lts unpack" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide abuild unpack permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/abuild args -C /home/$buildUsername/aports/main/linux-lts clean" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide make clean permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/make args -C /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision menuconfig" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide make menuconfig permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/make args -C /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision oldconfig" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide make oldconfig permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args config --global --add safe.directory /home/$buildUsername/aports" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git config safe.directory permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args -C /home/$buildUsername/aports config core.sparsecheckout true" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git config core.sparsecheckout permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args -C /home/$buildUsername clone git://git.alpinelinux.org/aports.git" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git clone permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args -C /home/$buildUsername/aports pull origin master --quiet" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git pull permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args -C /home/$buildUsername/aports reset --hard $gitCommitHash" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git reset permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args -C /home/$buildUsername/aports restore main/linux-lts/APKBUILD" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git restore main/linux-lts/APKBUILD permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args -C /home/$buildUsername/aports restore main/linux-lts/lts.$systemArch.config" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git restore main/linux-lts/lts.$systemArch.config permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args -C /home/$buildUsername/aports rev-parse HEAD" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git rev-parse permissions to be run as $buildUsername"
    chroot $mountPoint /bin/echo "permit nopass root as $buildUsername cmd /usr/bin/git args -C /home/$buildUsername/aports --no-pager log --grep=\"^main/linux-lts: upgrade to $kernelVersion$\" --pretty=format:\"%H\" -n1" >> $mountPoint/etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not provide git log permissions to be run as $buildUsername"
    chroot $mountPoint /bin/chmod 0400 /etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Could not change /etc/doas.d/kernelBuild.conf file permissions"

	# Reducing massively fetch and object download time by filtering inclusively directories; https://stackoverflow.com/questions/2416815/how-to-git-pull-all-but-one-folder/17075665#17075665
	log "INFO: Focusing on setting up or synchronizing github repo on local storage device"
		# Check if github repo exists
	if [ ! -d "$mountPoint/home/$buildUsername/aports/.git" ]; then 
		log "INFO: Could not find signs of the repo existing, and thus it will be configured"
		chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername" clone git://git.alpinelinux.org/aports.git 2>/dev/null || log "CRITICAL: Could not obtain aports github repo to install kernel"
		chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git config --global --add safe.directory "/home/$buildUsername/aports" 2>/dev/null || log "UNEXPECTED: Could not guarante that git cli will always accept git commands on aports directory"
		chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername/aports" config core.sparsecheckout true 2>/dev/null || log "CRITICAL: Git fetch, pull, and reset commands will take a large amount of unnecesary time"
		chroot $mountPoint /bin/echo "main/linux-lts" > "/home/$buildUsername/aports/.git/info/sparse-checkout" 2>/dev/null || log "UNEXPECTED: Could not declare main/linux-lts package directory as directory of interest"
		chroot $mountPoint /bin/chown "$buildUsername:root" "/home/$buildUsername/aports/.git/info/sparse-checkout" 2>/dev/null || log "UNEXPECTED: Could not ensure git filtering file is owned by $buildUsername"
    	chroot $mountPoint /bin/chmod 440 "/home/$buildUsername/aports/.git/info/sparse-checkout" 2>/dev/null || log "UNEXPECTED: Could not set permission on /home/$buildUsername/aports/.git/info/sparse-checkout"
		chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername/aports" pull origin master --quiet 2>/dev/null || log "CRITICAL: Could not have git delete and acknowledge useless directories"
	fi
	chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git config --global --add safe.directory "/home/$buildUsername/aports" 2>/dev/null || log "UNEXPECTED: Could not guarante that git cli will always accept git commands on aports directory"
		# If it exist, revert prior uncommited files
	if [ -f "$mountPoint/home/$buildUsername/aports/main/linux-lts/APKBUILD" ]; then chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername/aports" restore main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure prior APKBUILD file was reverted back to defualt settings"; fi
	if [ -f "$mountPoint/home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config" ]; then chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername/aports" restore main/linux-lts/lts.$systemArch.config 2>/dev/null || log "UNEXPECTED: Could not ensure prior lts.$systemArch.config file was reverted back to defualt settings"; fi
		# Check if current git repo matches with expected kernel
	local gitCommitHash="$(chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername/aports" --no-pager log --grep="^main/linux-lts: upgrade to $kernelVersion$" --pretty=format:"%H" -n1 2>/dev/null)" # Relies heavely on aport commits having this precise wording: main/linux-lts: upgrade to x.x.x
	if [ "$gitCommitHash" = "$(chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername/aports" rev-parse HEAD 2>/dev/null)" ]; then log "INFO: Current github matches with requested kernel version! No further changes are required"
	else
		if [ -z "$gitCommitHash" ]; then
			log "INFO: Returned hash was empty! Indicating this repo is too outdated to get newer kernel versions! Hard reset of git repo incoming with filtered directories"
			chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername/aports" pull origin master --quiet 2>/dev/null || log "CRITICAL: Could not have git revert to expected kernel version"
		fi
		log "INFO: Git repo does not match with expected kernel version, thus transitioning git repo to older commits to match kernel version"
		chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/git -C "/home/$buildUsername/aports" reset --hard "$gitCommitHash" 2>/dev/null || log "UNEXPECTED: Could not set branch to expected kernel version $kernelVersion"
		# Are prior linux kernel files present? If so, clean since they must have been built on a different version
		if [ ! -d "$mountPoint/home/$buildUsername/aports/main/linux-lts/src" ]; then
			log "INFO: Clearing prior kernel build"
			chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild -C "/home/$buildUsername/aports/main/linux-lts" clean 2>/dev/null || log "CRITICAL: Could not reset src directory to use new $kernelVersion kernel src directory"
		fi
		log "INFO: Finished modifying git repo in preparation for kernel version $kernelVersion"
	fi

# TODO: Test without this properely in place
#	log "INFO: Re-Setting up default directories ownership and permissions to permit access for $buildUsername user"
#	chroot $mountPoint /bin/chmod 760 /home/$buildUsername/aports 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports directory"
#	chroot $mountPoint /bin/chmod 760 /home/$buildUsername/aports/main 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports/main directory"
#	chroot $mountPoint /bin/chmod -R 760 /home/$buildUsername/aports/main/linux-lts 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports/main/linux-lts directory"
#	chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername/aports 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports directory"
#	chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername/aports/main 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports/main directory"
#	chroot $mountPoint /bin/chown -R "$buildUsername:root" /home/$buildUsername/aports/main/linux-lts 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports/main/linux-lts directory"
    
	log "INFO: Temporarely allow certain compiler executables to be used"
    chroot $mountPoint /bin/chmod 501 /usr/bin/ld 2>/dev/null || log "UNEXPECTED: Could not add execute permission on /usr/bin/ld"
    chroot $mountPoint /bin/chmod 501 /usr/bin/as 2>/dev/null || log "UNEXPECTED: Could not add execute permission on /usr/bin/as"
    chroot $mountPoint /bin/chmod 501 /usr/bin/sha512sum 2>/dev/null || log "UNEXPECTED: Could not add execute permission on /usr/bin/sha512sum"
    
    log "INFO: Checking if abuild can use $buildUsername keys that should be stored in /etc/apk/keys"
    if [ -z "$(chroot $mountPoint /bin/ls /etc/apk/keys | grep -v alpine-devel)" ]; then
        log "INFO: Generating signing key"
        chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild-keygen -a -i -n || log "UNEXPECTED: Could not generate keys for $buildUsername"
        chroot $mountPoint /bin/chmod a+r /etc/apk/keys/* 2>/dev/null || log "UNEXPECTED: Could not enable keys stored in /etc/apk/keys to be read by $buildUsername"
    fi
    
    log "INFO: Attempting to install hardening patches from KSSP"
	if [ ! -f "$mountPointhome/$buildUsername/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" ] || [ ! -f "$mountPointhome/$buildUsername/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" ]; then
        log "INFO: Obtaining kernel patches based on linux hardening alpine guide"
        chroot $mountPoint /usr/bin/wget -O "/home/$buildUsername/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" "$hardeningPatchUrl.patch" || log "UNEXPECTED: Could not download patch into kernel"
        chroot $mountPoint /usr/bin/wget -O "/home/$buildUsername/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" "$hardeningPatchUrl.patch.sig" || log "UNEXPECTED: Couldd not download patch signature key into kernel"
        chroot $mountPoint /bin/chown "$buildUsername:root" "/home/$buildUsername/aports/main/linux-lts/0098-linux-hardened-v$kernelVersion.patch" 2>/dev/null || log "UNEXPECTED: Could not ensure kernel patch file is owned by $buildUsername"
        chroot $mountPoint /bin/chown "$buildUsername:root" "/home/$buildUsername/aports/main/linux-lts/0099-linux-hardened-v$kernelVersion.patch.sig" 2>/dev/null || log "UNEXPECTED: Could not ensure kernel patch signature file is owned by $buildUsername"
    fi

	# An idea of all architectures are listed here; https://wiki.debian.org/ArchitectureSpecificsMemo (Unsure if Alpine's cross-compiler supports them all)
    log "INFO: Configurating APKBUILD file to include only relevant files and patches"
    chroot $mountPoint /bin/chmod u+w /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not change /home/$buildUsername/aports/main/linux-lts/APKBUILD file permissions to enable writing"
        # Remove irrelevant architectures from APKBUILD
    if [ -z "$(echo $systemArch | grep aarch64)" ]; then sed -i "s/^#\{0,2\}\tlts.aarch64.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure lts.aarch64.config linux kernel configuration was removed from APKBUILD"; sed -i "s/^#\{0,2\}\tvirt.aarch64.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure virt.aarch64.config linux kernel configuration was removed from APKBUILD"; fi    
    if [ -z "$(echo $systemArch | grep armv7)" ]; then sed -i "s/^#\{0,2\}\tlts.armv7.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure lts.armv7.config linux kernel configuration was removed from APKBUILD"; sed -i "s/^#\{0,2\}\tvirt.armv7.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure virt.armv7.config linux kernel configuration was removed from APKBUILD"; fi    
    if [ -z "$(echo $systemArch | grep loongarch64)" ]; then sed -i "s/^#\{0,2\}\tlts.loongarch64.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure lts.loongarch64.config linux kernel configuration was removed from APKBUILD"; sed -i "s/^#\{0,2\}\tvirt.loongarch64.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure virt.loongarch64.config linux kernel configuration was removed from APKBUILD"; fi    
    if [ -z "$(echo $systemArch | grep ppc64le)" ]; then sed -i "s/^#\{0,2\}\tlts.ppc64le.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure lts.ppc64le.config linux kernel configuration was removed from APKBUILD"; sed -i "s/^#\{0,2\}\tvirt.ppc64le.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure virt.ppc64le.config linux kernel configuration was removed from APKBUILD"; fi    
    if [ -z "$(echo $systemArch | grep riscv64)" ]; then sed -i "s/^#\{0,2\}\tlts.riscv64.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure lts.riscv64.config linux kernel configuration was removed from APKBUILD"; sed -i "s/^#\{0,2\}\tvirt.riscv64.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure virt.riscv64.config linux kernel configuration was removed from APKBUILD"; fi    
    if [ -z "$(echo $systemArch | grep s390x)" ]; then sed -i "s/^#\{0,2\}\tlts.s390x.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure lts.s390x.config linux kernel configuration was removed from APKBUILD"; sed -i "s/^#\{0,2\}\tvirt.s390x.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure virt.s390x.config linux kernel configuration was removed from APKBUILD"; fi     
    if [ -z "$(echo $systemArch | grep x86_64)" ]; then sed -i "s/^#\{0,2\}\tlts.x86_64.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure lts.x86_64.config linux kernel configuration was removed from APKBUILD"; sed -i "s/^#\{0,2\}\tvirt.x86_64.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure virt.x86_64.config linux kernel configuration was removed from APKBUILD"; fi     
    if [ -z "$(echo $systemArch | grep x86)" ]; then sed -i "s/^#\{0,2\}\tlts.x86.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure lts.x86.config linux kernel configuration was removed from APKBUILD"; sed -i "s/^#\{0,2\}\tvirt.x86.config/MARKFORDELETION/g" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not ensure virt.x86.config linux kernel configuration was removed from APKBUILD"; fi 
    sed -i "/MARKFORDELETION/d" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not clean up any prior work on APKBUILD"
    	# If our relevant architecture is not found, then include it (via a very specific point)
	if [ -z "$(grep lts.$systemArch.config $mountPoint/home/$buildUsername/aports/main/linux-lts/APKBUILD)" ] && [ -z "$(grep virt.$systemArch.config $mountPoint/home/$buildUsername/aports/main/linux-lts/APKBUILD)" ]; then sed -i "s/^\t\"$/\tlts.$systemArch.config\n\n\tvirt.$systemArch.config\n\t\"/g" || log "CRITICAL: Could not include our architecture kernel configuration file!"; fi
		# Our additional patches already included?
	if [ -z "$(grep 0098-linux-hardened-v$kernelVersion.patch $mountPoint/home/$buildUsername/aports/main/linux-lts/APKBUILD)" ] && [ -z "$(grep 0099-linux-hardened-v$kernelVersion.patch.sig $mountPoint/home/$buildUsername/aports/main/linux-lts/APKBUILD)" ]; then sed -i "s/^\t\"$/\t0098-linux-hardened-v$kernelVersion.patch\n\t0099-linux-hardened-v$kernelVersion.patch.sig\n\n\tvirt.$systemArch.config/g" || log "UNEXPECTED: Could not include our KSSP kernel patches in compilation APKBUILD file!"; fi
    chroot $mountPoint /bin/chmod 0550 /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not change /home/$buildUsername/aports/main/linux-lts/APKBUILD file permissions to only execute"
    chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername/aports/main/linux-lts/APKBUILD 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports/main/linux-lts/APKBUILD file"
    
    log "INFO: Preparing ncurse's setup by unpacking kernel package"
    if [ ! -d "$mountPoint/home/$buildUsername/aports/main/linux-lts/src" ]; then chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild -C "/home/$buildUsername/aports/main/linux-lts" unpack 2>/dev/null || log "UNEXPECTED: Could not prepare ncurses environment for an interactice kernel configuration"; fi
    
    log "INFO: Does linux kernel configuration exist in the correct spot?"
    if [ ! -f "$mountPoint/home/$buildUsername/linuxConfig.config" ]; then chroot $mountPoint /bin/cp "/home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config" "/home/$buildUsername/linuxConfig.config" || log "UNEXPECTED: Could not place linuxConfig.config file in /home/$buildUsername"; fi
    if [ "$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/linuxConfig.config)" != "$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config)" ]; then
        # Move the new file
        log "INFO: Moving file linuxConfig.config into lts.$systemArch.config with the following md5sum: $(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/linuxConfig.config) != $(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config)"
        chroot $mountPoint /bin/cp "/home/$buildUsername/linuxConfig.config" "/home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config" 2>/dev/null || log "CRITICAL: Wrong kernel configuration file is set!"
    fi
    if [ ! -f "$mountPoint/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config" ] || [ "$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/linuxConfig.config)" != "$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config)" ]; then
        # Move the new file
        log "INFO: Making lts.$systemArch.config as the default .config file in kernel src menuconfig directory with md5sum: $(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/linuxConfig.config) != $(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config)"
        chroot $mountPoint /bin/cp "/home/$buildUsername/linuxConfig.config" "/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config" 2>/dev/null || log "CRITICAL: Wrong kernel configuration file is set!"
    fi
    	# Setting file permissions
	chroot $mountPoint /bin/chown "$buildUsername:root" "/home/$buildUsername/linuxConfig.config" 2>/dev/null || log "UNEXPECTED: Could not ensure user provided build kernel config file is owned by $buildUsername"
	chroot $mountPoint /bin/chown "$buildUsername:root" "/home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config" 2>/dev/null || log "UNEXPECTED: Could not ensure build kernel config file is owned by $buildUsername"
    chroot $mountPoint /bin/chown "$buildUsername:root" "/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config" 2>/dev/null || log "UNEXPECTED: Could not ensure src kernel config file is owned by $buildUsername"
    
    log "INFO: The system is ready to compile the linux kernel in a Alpine environment"
}

interactKernelConfig() {
	log "INFO: Started interacting with file in /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config with ncurses menu to modify!"
	local localChecksum="$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config)"
	chroot /mnt/alpine /usr/bin/doas -u "$buildUsername" /usr/bin/make -C "/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision" menuconfig 2>/dev/null || log "UNEXPECTED: Could not start ncurses menuconfig!"
	
	if [ "$localChecksum" != "$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config)"]; then
		log "INFO: User exited from make oldconfig with changes! Affecting /home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config and /home/$buildUsername/linuxConfig.config"
		chroot $mountPoint /bin/cp "/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config" "/home/$buildUsername/linuxConfig.config" 2>/dev/null || log "CRITICAL: Wrong kernel configuration file is not saved for /home/$buildUsername/linuxConfig.config!"
		chroot $mountPoint /bin/cp "/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config" "/home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config" 2>/dev/null || log "CRITICAL: Wrong kernel configuration file is not saved for /home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config!"
	else
		log "INFO: User exited from make oldconfig without making any changes! Affecting nothing"
	fi
	
	log "INFO: Finished considering .config! Lets hope it was configured correctly"
}

updateKernelConfig() {
	log "INFO: Started interacting with file in /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config with ncurses menu to update!"
	local localChecksum="$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config)"
	chroot /mnt/alpine /usr/bin/doas -u "$buildUsername" /usr/bin/make -C "/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision" oldconfig 2>/dev/null || log "UNEXPECTED: Could not start ncurses menuconfig!"
	
	if [ "$localChecksum" != "$(chroot $mountPoint /usr/bin/md5sum /home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config)"]; then
		log "INFO: User exited from make oldconfig with changes! Affecting /home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config and /home/$buildUsername/linuxConfig.config"
		chroot $mountPoint /bin/cp "/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config" "/home/$buildUsername/linuxConfig.config" 2>/dev/null || log "CRITICAL: Wrong kernel configuration file is not saved for /home/$buildUsername/linuxConfig.config!"
		chroot $mountPoint /bin/cp "/home/$buildUsername/aports/main/linux-lts/src/linux-$linuxRevision/.config" "/home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config" 2>/dev/null || log "CRITICAL: Wrong kernel configuration file is not saved for /home/$buildUsername/aports/main/linux-lts/lts.$systemArch.config!"
	else
		log "INFO: User exited from make oldconfig without making any changes! Affecting nothing"
	fi

	log "INFO: Finished updating .config! Lets hope it was configured correctly"
}

compileKernel() {    
    log "INFO: Performing checksum on everything"
    chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild -C "home/$buildUsername/aports/main/linux-lts" checksum || log "UNEXPECTED: Could not compile checksum of everything modified so far"
    
    log "INFO: Compiling kernel at; $(date)"
    time -o /tmp/compileTime chroot $mountPoint /usr/bin/doas -u "$buildUsername" /usr/bin/abuild -C "home/$buildUsername/aports/main/linux-lts" -crK 2>&1 | tee /tmp/kernelLog || log "CRITICAL: Could not finish compiling kernel"
    		
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
    if $gCompile; then compileKernel; fi
    
    log "INFO: Cleaning up"
    	# File clean up
    if [ -f "$mountPoint/etc/doas.d/kernelBuild.conf" ]; then chroot $mountPoint /bin/rm /etc/doas.d/kernelBuild.conf 2>/dev/null || log "UNEXPECTED: Permission doas file has not been deleted to enforce principle of least priviledge"; fi
	if $gPackageGone; then chroot $mountPoint /sbin/apk del alpine-sdk ncurses-dev 2>/dev/null || log "UNEXPECTED: Could not remove development build packages"; fi
    log "INFO: Finished executing script!"
    	# Permission clean up
    # !!! TODO: Make this permission independent
    chroot $mountPoint /bin/chmod 500 /usr/bin/ld 2>/dev/null || log "UNEXPECTED: Could not remove execute permission on /usr/bin/ld"
    chroot $mountPoint /bin/chmod 500 /usr/bin/as 2>/dev/null || log "UNEXPECTED: Could not remove execute permission on /usr/bin/as"
    chroot $mountPoint /bin/chmod 500 /usr/bin/sha512sum 2>/dev/null || log "UNEXPECTED: Could not remove execute permission on /usr/bin/sha512sum"
}

main "$@"

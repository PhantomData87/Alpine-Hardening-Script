#!/bin/sh

# Setting up kernel configuration on an already mounted kernel storage device


# Modify kernel manually with ncurses-dev; chroot /mnt/alpine /usr/bin/make menuconfig -C /mnt/kernelInstall/aports/main/linux-lts/src/linux-6.12
# Features; update linuxConfig.config, customize linuxConfig.config, install kernel, update github, repair filesystem, and auto-select latest kernel with specific features

    if [ -z "$kernelVersion" ]; then echo "BAD FORMAT: Must indicate the version of the linux kernel that is planned to be used! Fill in \$kernelVersion"; exit; fi
kernelPartition=""
kernelPartitionSector="2048" # USED IF IT IS A NEW DISK. Leave this as 2048, as it determines which sector on the device to use. Leave it alone, unless you know what you are doing
gKernelPartition=false # Intention to reset or create new partitions of Kernel disk storage
mountPoint=""
kernelPoint=""
export buildUsername="maintain" # Username that can build the linux kernel, and install it

export kernelVersion="6.12.43" # Could not have this reliable

	--formatKernel	Setup the custom expected partitions for a seperate kernel installation

kernelVersion:		Declare which kernel edition we will be using
	
	
	# Bootloader fallback name	
export systemArch="$(uname -m)" # Leave this as "$(uname -m)" to automatically find system architecture. If building on a different system, then change this into one of the many values: x86_64, x86, arm*, aarch64, riscv64, loongarch64
systemArchFallbackName=""
	# Fallback bootloader name for boot*.efi file in $bootPartition/EFI/boot/
case $systemArch in
  	x86_64 ) systemArchFallbackName="x64";;
   	x86 ) systemArchFallbackName="ia32";;
   	arm* ) systemArchFallbackName="arm";;
   	aarch64 ) systemArchFallbackName="aa64";;
   	riscv64 ) systemArchFallbackName="riscv64";;
   	loongarch64 ) systemArchFallbackName="loongarch64";;
esac
	
	
	interpretArgs() {
    local wantHelp=false
    for i in "${@}"; do
      case "$i" in
        -h|--help) wantHelp=true;;
        -v|--verbose) verbose=true;;
        --formatSystem) gPartition=true;;
        --formatKernel) gKernelPartition=true;;
        --stayLocal) gLocal=true;;
        --kernelModify) gKernelUnmodified=false;;
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


    if [ -z "$gKernelPartition" ]; then echo "BAD FORMAT: Empty value for \$gKernelPartition implies we are not formatting any devices for installing a seperate compiled kernel"; gKernelPartition=false; fi
    if [ -z "$kernelPartitionSector" ]; then echo "BAD FORMAT: Must indicate the starting kernel sector offset for formating the kernel partition. Change \$kernelPartitionSector"; exit; fi
    }


if $gKernelUnmodified; then gKernelPartition=false; kernelSectorChosen=true; kernelExist=false; kernelPartition="[nowhere]"; fi # If not considering kernel; then skip all kernel functions, formatting, and mounting
	


# Display list of devices, and consider each of the three important mount & format locations: boot, lvm, and kernel.
	local devBlockSize=1024 # /proc/partitions shows size in 1024-byte blocks; https://unix.stackexchange.com/questions/512945/what-units-are-the-values-in-proc-partitions-and-sys-dev-block-block-size
	local devName=""
	local devBlock=""
	local devLabel=""
	local devType=""
	local showAgain=false
	while ! $gLocal || ! $gKernelUnmodified; do
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
        while ! $gKernelUnmodified && ! $kernelSectorChosen && ! $showAgain; do
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
        if ! $gKernelUnmodified && [ -z "$kernelPartition" ]; then showAgain=true; kernelSectorChosen=false; kernelExist=false; echo "Empty value for kernelPartition"; fi
        if $showAgain; then continue; fi
        
	    	# Valid partition scheme
	    if ! $gKernelUnmodified && [ -z "$(echo $kernelPartition | grep -E -o [^1234567890][^p][1234567890]+$\|p[1234567890]+$)" ]; then echo "Partition formatting for $kernelPartition is invalid. Please specify a number correctly [either # or p#] at tail end"; kernelSectorChosen=false; kernelPartition=""; kernelExist=false; fi
		if ! $kernelSectorChosen; then continue; fi # Reset
		
	    	# Formatting acknowledgment, and valid block device check
    	if ! $gKernelUnmodified && [ ! -b "$kernelPartition" ] && $gKernelPartition; then echo "kernelPartition at $gKernelPartition partition currently does not exist, but will format due to gKernelPartition being specified as $gKernelPartition"; kernelExist=false; fi
		if [ ! -b "$kernelPartition" ] && $kernelExist; then echo "xfs kernelPartition at $kernelPartition partition currently does not exist, and formatting is currently disabled. Specify a valid existing disk, or enable formatting"; kernelPartition=""; kernelSectorChosen=false; kernelExist=false; fi
		if ! $kernelSectorChosen; then continue; fi # Reset
        
        	# Final sanity check when formatting is disabled: IS kernel xfs?
        if ! $gKernelUnmodified && [ "$(blkid $kernelPartition | awk -F 'TYPE' 'NF>1{sub(/="/,"",$NF);sub(/".*/,"",$NF);print $NF}')" != "xfs" ] && ! $gKernelPartition; then echo "Partition at $kernelPartition is not xfs! Enable formatting or pick a different partition"; blockList="\?"; kernelPartition=""; kernelSectorChosen=false; kernelExist=false; fi
		if ! $kernelSectorChosen; then continue; fi # Reset
        
        # Break loop if everything is satisfied
        if $kernelSectorChosen; then break; fi
	done




		# Kernel secondary disk installation
	if ! $gKernelUnmodified && $gKernelPartition; then
		# Kernel
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
	
# Modify kernel manually with ncurses-dev; chroot /mnt/alpine /usr/bin/make menuconfig -C /home/$buildUsername/aports/main/linux-lts/src/linux-6.12
# Features; update linuxConfig.config, customize linuxConfig.config, install kernel, update github, repair filesystem, and auto-select latest kernel with specific features
	if ! $gKernelUnmodified; then
		# Installing required packages
		chroot $mountPoint /sbin/apk add git alpine-sdk kernel-hardening-checker@additional 2>/dev/null || log "CRITICAL: Could not install required packages for kernel"
 	
    	# Setup kernel user
		chroot $mountPoint /bin/mkdir -p /home/$buildUsername 2>/dev/null || log "UNEXPECTED: Could not create home directory to mount towards on /home/$buildUsername"
    	if [ -z "$(chroot $mountPoint /bin/grep $buildUsername /etc/passwd)" ]; then
        	chroot $mountPoint /usr/sbin/adduser -h /home/$buildUsername -S -D -s /sbin/nologin $buildUsername 2>/dev/null || log "CRITICAL: Could not create an account for building the kernel"
        	chroot $mountPoint /usr/sbin/addgroup $buildUsername abuild 2>/dev/null || log "CRITICAL: Could not include $buildUsername into abuild group"
        	chroot $mountPoint /usr/sbin/addgroup $buildUsername wheel 2>/dev/null || log "UNEXPECTED: Could not include $buildUsername into admin group"
        	log "INFO: Finished adding in $buildUsername as limited user to handle kernel installation, updating, and etc"
    	fi
    	
		if [ -z "$(mount | grep "$kernelPartition on $mountPoint/home/$buildUsername " 2>/dev/null)" ]; then mount -t xfs "$kernelPartition" "$mountPoint"/home/$buildUsername 2>/dev/null || log "UNEXPECTED: Lacked capabilities to mount on $mountPoint/home/$buildUsername"; fi
		log "INFO: Mounted kernel device onto $mountPoint/home/$buildUsername"
	fi


    if ! $gKernelUnmodified && $gKernelPartition; then
    	# Set up aports github repo on kernel storage device
        chroot $mountPoint /bin/chmod 760 /home/$buildUsername 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername directory"
        chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername 2>/dev/null || log "UNEXPECTED: Could not ensure home directory of $buildUsername is owner"
        chroot $mountPoint /usr/bin/git -C /home/$buildUsername clone git://git.alpinelinux.org/aports.git 2>/dev/null || log "CRITICAL: Could not obtain github repo to install kernel"
        	# Making aports directory accesible to $buildUsername
        chroot $mountPoint /bin/chmod 760 /home/$buildUsername/aports 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports directory"
	    chroot $mountPoint /bin/chmod 760 /home/$buildUsername/aports/main 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports/main directory"
    	chroot $mountPoint /bin/chmod -R 760 /home/$buildUsername/aports/main/linux-lts 2>/dev/null || log "UNEXPECTED: Could not set permissions on /home/$buildUsername/aports/main/linux-lts directory"
        chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername/aports 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports directory"
	    chroot $mountPoint /bin/chown "$buildUsername:root" /home/$buildUsername/aports/main 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports/main directory"
    	chroot $mountPoint /bin/chown -R "$buildUsername:root" /home/$buildUsername/aports/main/linux-lts 2>/dev/null || log "UNEXPECTED: Could not set ownership on /home/$buildUsername/aports/main/linux-lts directory"
        log "INFO: Finished placing github repo to install kernel"
	fi
	
	# !!! linuxConfig.config obtain corner
#	if [ ! -f "$mountPoint/home/$buildUsername/linuxConfig.config" ]; then log "BAD FORMAT: There is no linux configuration file present as linuxConfig.config. Please place one in $mountPoint/home/$buildUsername/"; echo "There is no linux configuration file present as linuxConfig.config. Please place one in $mountPoint/home/$buildUsername/"; return 0; fi

	# !!! Check if github is recent
	if ! $gKernelUnmodified; then
		log "INFO: Checking if kernel is latest version or higher from secondary disk"
		
	fi
	
	
	
	
	
	
	
	
	

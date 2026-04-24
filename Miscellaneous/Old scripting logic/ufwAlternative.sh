#!/bin/sh
# https://codelucky.com/ufw-advanced-linux-firewall/
# https://dev.to/caffinecoder54/creating-a-lightweight-linux-firewall-with-ufw-and-fail2ban-35po

# Old code beloging to alpineHarden.sh when nftables had not been considered properely.

export ufwLogging="full" # "low"="on", "medium", "high", "full" : https://thelinuxcode.com/check-my-ufw-log/

ufwInstallation() {
	chroot $mountPoint /sbin/apk add ufw@
	
		# Creating system user to execute UFW
    if [ -z "$(chroot $mountPoint /bin/grep $firewallUsername /etc/passwd)" ]; then chroot $mountPoint /usr/sbin/adduser -H -h /dev/null -S -D -G $firewallUsername -s /sbin/nologin $firewallUsername 2>/dev/null || log "CRITICAL: Could not create an account for running firewall"; fi
    chroot $mountPoint /usr/sbin/addgroup $firewallUsername iptables 2>/dev/null || log "UNEXPECTED: Could not add iptables group to firewall user" # Required since it relies on iptables
    chroot $mountPoint /usr/sbin/addgroup $firewallUsername python 2>/dev/null || log "UNEXPECTED: Could not add python group to firewall user" # Required since it relies on python to execute code
    chroot $mountPoint /usr/sbin/addgroup $firewallUsername busybox 2>/dev/null || log "UNEXPECTED: Could not add busybox group to firewall user" # Required for disabling firewall (their script executes /bin/sh)
    
    chroot $mountPoint /bin/touch /var/log/daemonUFW.log 2>/dev/null || log "UNEXPECTED: Could not generate a log file meant for capturing UFW daemon"
		# UFW duplicate removal
	if [ -f "$mountPoint/etc/init.d/ufw.apk-new" ]; then chroot $mountPoint /bin/rm /etc/init.d/ufw.apk-new 2>/dev/null || log "UNEXPECTED: Could not remove redundant default file: /etc/init.d/ufw.apk-new"; fi
    if [ -f "$mountPoint/etc/ufw/ufw.conf.apk-new" ]; then chroot $mountPoint /bin/rm /etc/ufw/ufw.conf.apk-new 2>/dev/null || log "UNEXPECTED: Could not remove redundant default file: /etc/ufw/ufw.conf.apk-new"; fi
    if [ -f "$mountPoint/etc/default/ufw.apk-new" ]; then chroot $mountPoint /bin/rm /etc/default/ufw.apk-new 2>/dev/null || log "UNEXPECTED: Could not remove redundant default file: /etc/default/ufw.apk-new"; fi
    
    log "INFO: Permitting root to cause changes to certain files"
    local writablePaths="/etc/default/ufw"
    for enableWrite in $writablePaths; do
    	chroot $mountPoint /bin/chmod u+w $enableWrite 2>/dev/null || log "UNEXPECTED: Could not guarantee that $enableWrite be modified by root"
    done

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
ports=$sshPort/tcp" > $mountPoint/etc/ufw/applications.d/ssh || log "UNEXPECTED: Failed to permit SSH port $sshPort through firewall"
    chroot $mountPoint /bin/echo "[APKUpdate]
title=APK tool
description=When this computer needs to update packages, then this will be enabled
ports=$httpPort/tcp|$httpsPort/tcp" > $mountPoint/etc/ufw/applications.d/apk || log "UNEXPECTED: Failed to permit APK ports $httpPort and $httpsPort through firewall"
    chroot $mountPoint /bin/echo "[NTPListener]
title=Chronyd network listener
description=For chronyd service running in background
ports=$ntpStandardPort/udp|$ntpMonitorPort/udp" > $mountPoint/etc/ufw/applications.d/ntp || log "UNEXPECTED: Failed to permit NTP ports $ntpStandardPort and $ntpMonitorPort through firewall"
    chroot $mountPoint /bin/echo -e "[DNSListener]
title=DNS network listener
description=For a dns service running in background
ports=$dnsPort" > $mountPoint/etc/ufw/applications.d/dns || log "UNEXPECTED: Failed to permit DNS port $dnsPort through firewall"
    chroot $mountPoint /usr/sbin/ufw app update SSHServer || log "CRITICAL: Could not ensure ufw recognizes the ssh profile"
    chroot $mountPoint /usr/sbin/ufw app update DNSListener || log "UNEXPECTED: Could not ensure ufw recognizes the dns profile"
    chroot $mountPoint /usr/sbin/ufw app update APKUpdate || log "UNEXPECTED: Could not ensure ufw recognizes the apk profile"
    chroot $mountPoint /usr/sbin/ufw app update NTPListener || log "UNEXPECTED: Could not ensure ufw recognizes the ntp profile"
    chroot $mountPoint /usr/sbin/ufw app default deny 2>/dev/null || log "CRITICAL: Failed to set default deny creation and modification of application profiles for ufw firewall"
		# Open http, https, dns, and ntp ports
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app APKUpdate 2>/dev/null || log "UNEXPECTED: Failed to permit HTTP/HTTPS port $httpPort/$httpsPort esgress through firewall"
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app DNSListener 2>/dev/null || log "UNEXPECTED: Failed to permit DNS port $dnsPort esgress through firewall"
    chroot $mountPoint /usr/sbin/ufw allow out log from any to any app NTPListener 2>/dev/null || log "UNEXPECTED: Failed to permit NTP port $ntpStandardPort and $ntpMonitorPort esgress through firewall"
		# Add rate limit and open ssh port
    chroot $mountPoint /usr/sbin/ufw limit in log from "$localGateway"/"$localNetmask" to "$localGateway"/"$localNetmask" app SSHServer 2>/dev/null || log "CRITICAL: Failed to limit ports $sshPort for ingress traffic on ufw firewall"
		# Removing UFW code that checks for root access
    chroot $mountPoint /bin/sed -i "s/    if uid != 0/    if 1 == 2 and uid != 0/1" /usr/lib/python$pythonVer/site-packages/ufw/backend.py 2>/dev/null || log "CRITICAL: Could not modify ufw backend python library to bypass root required access"
    chroot $mountPoint /bin/sed -i "s/            if statinfo.st_uid != 0/            if 1 == 2 and statinfo.st_uid != 0/1" /usr/lib/python$pythonVer/site-packages/ufw/backend.py 2>/dev/null || log "UNEXPECTED: Could not turn off warning of certain files owned by non-root account in ufw"

	chroot $mountPoint /bin/sed -i "/#\{0,2\}:msg,contains,\"UFW AUDIT\"\(.*\) # Discard irrelevant UFW Audit messages/{h;s//:msg,contains,\"UFW AUDIT\" stop # Discard irrelevant UFW Audit messages/};\${x;/^\$/{s//:msg,contains,\"UFW AUDIT\" stop # Discard irrelevant UFW Audit messages/;H};x}" /etc/rsyslog.d/10-discardFilters.conf 2>/dev/null || log "UNEXPECTED: Could not add filter to /etc/rsyslog.d/10-discardFilters.conf for discarding unwanted UFW messages"
	chroot $mountPoint /bin/sed -i "/#\{0,2\}if (\$syslogfacility-text == \"kern\")\(.*\) # firewall kernel logging/{h;s//if (\$syslogfacility-text == \"kern\") and (\$msg contains \"[UFW\") then {action(type=\"omfile\" File=\"\/var\/log\/kernFirewall.log\") stop} # firewall kernel logging/};\${x;/^\$/{s//if (\$syslogfacility-text == \"kern\") and (\$msg contains \"[UFW\") then {action(type=\"omfile\" File=\"\/var\/log\/kernFirewall.log\") stop} # firewall kernel logging/;H};x}" /etc/rsyslog.d/40-broadFilters.conf 2>/dev/null || log "UNEXPECTED: Could not add filter to /etc/rsyslog.d/40-broadFilters.conf for firewall kernel logging"
    chroot $mountPoint /bin/sed -i "/#\{0,2\}if (\$programname == \"ufw\")\(.*\) # ufw daemon logging/{h;s//if (\$programname == \"ufw\") then {action(type=\"omfile\" File=\"\/var\/log\/daemonUFW.log\") stop} # ufw daemon logging/};\${x;/^\$/{s//\t# Filters for services on local machine\n\t\t# Daemon activity logging only\nif (\$programname == \"ufw\") then {action(type=\"omfile\" File=\"\/var\/log\/daemonUFW.log\") stop} # ufw daemon logging/;H};x}" /etc/rsyslog.d/50-daemonFilters.conf 2>/dev/null || log "UNEXPECTED: Could not add filter to /etc/rsyslog.d/50-daemonFilters.conf for ufw daemon logging"
    
        # ufw
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/applications.d 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /etc/ufw/applications.d"
    chroot $mountPoint /bin/chown "root:$firewallUsername" /etc/ufw/applications.d/ssh 2>/dev/null || log "UNEXPECTED: Could not change ownership for; ssh profile"
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
    chroot $mountPoint /bin/chown "$loggerUsername:logread" /var/log/daemonUFW.log 2>/dev/null || log "UNEXPECTED: Could not change ownership for; /var/log/daemonUFW.log"
    
    chroot $mountPoint /bin/chmod 0550 /usr/sbin/ufw 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw"
    
    chroot $mountPoint /bin/chmod 0440 /etc/default/ufw 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw in default"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/ssh 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ssh ufw profile"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/apk 2>/dev/null || log "UNEXPECTED: Could not change permissions for; apk ufw profile"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/ntp 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ntp ufw profile"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/applications.d/dns 2>/dev/null || log "UNEXPECTED: Could not change permissions for; dns ufw profile"
    chroot $mountPoint /bin/chmod 0550 /etc/ufw/before.init 2>/dev/null || log "UNEXPECTED: Could not change permissions for; before.init"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/before.rules 2>/dev/null || log "UNEXPECTED: Could not change permissions for; before.rules"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/before6.rules 2>/dev/null || log "UNEXPECTED: Could not change permissions for; before6.rules"
    chroot $mountPoint /bin/chmod 0550 /etc/ufw/after.init 2>/dev/null || log "UNEXPECTED: Could not change permissions for; after.init"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/after.rules 2>/dev/null || log "UNEXPECTED: Could not change permissions for; after.rules"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/after6.rules 2>/dev/null || log "UNEXPECTED: Could not change permissions for; after6.rules"
    chroot $mountPoint /bin/chmod 0640 /etc/ufw/user.rules 2>/dev/null || log "UNEXPECTED: Could not change permissions for; user.rules"
    chroot $mountPoint /bin/chmod 0640 /etc/ufw/user6.rules 2>/dev/null || log "UNEXPECTED: Could not change permissions for; user6.rules"
    chroot $mountPoint /bin/chmod 0640 /etc/ufw/ufw.conf 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw.conf"
    chroot $mountPoint /bin/chmod 0440 /etc/ufw/sysctl.conf 2>/dev/null || log "UNEXPECTED: Could not change permissions for; sysctl.conf"
    chroot $mountPoint /bin/chmod 0500 /etc/init.d/ufw 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw"
    chroot $mountPoint /bin/chmod 00750 /etc/ufw 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw"
    chroot $mountPoint /bin/chmod 00750 /etc/ufw/applications.d 2>/dev/null || log "UNEXPECTED: Could not change permissions for; applications.d"
    chroot $mountPoint /bin/chmod 0750 /usr/lib/ufw/ufw-init 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw-init"
    chroot $mountPoint /bin/chmod 0750 /usr/lib/ufw/ufw-init-functions 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw-init-functions"
    chroot $mountPoint /bin/chmod 00750 /usr/lib/ufw 2>/dev/null || log "UNEXPECTED: Could not change permissions for; ufw"
    chroot $mountPoint /bin/chmod 00701 /etc/default 2>/dev/null || log "UNEXPECTED: Could not change permissions for; default"
    chroot $mountPoint /bin/chmod 0640 /var/log/daemonUFW.log 2>/dev/null || log "UNEXPECTED: Could not change permissions for; /var/log/daemonUFW.log file permissions"
    chroot $mountPoint /usr/sbin/ufw enable 2>/dev/null || log "UNEXPECTED: ufw could not be enabled from itself"
    chroot $mountPoint /sbin/rc-update add ufw default 2>/dev/null || log "UNEXPECTED: Could not add ufw to default with rc-update"
    
    chroot $mountPoint /sbin/rc-service ufw restart 2>/dev/null || log "UNEXPECTED: Could not restart ufw daemon"
}

ufwVerification() {
    if [ -z "$(chroot $mountPoint /sbin/apk list -I 2>/dev/null | grep ufw)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Did not find ufw package"; fi
		# UFW
    if [ ! -f "$mountPoint/etc/ufw/applications.d/ssh" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Missing firewall app profile for ssh connections!"; fi
    if [ ! -f "$mountPoint/etc/ufw/applications.d/apk" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Missing firewall app profile for updating packages!"; fi
    if [ ! -f "$mountPoint/etc/ufw/applications.d/ntp" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Missing firewall app profile for ntp connections!"; fi
    if [ ! -f "$mountPoint/etc/ufw/applications.d/dns" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Missing firewall app profile for dns connections!"; fi
    if [ ! -f "$mountPoint/var/log/daemonUFW.log" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: File /var/log/daemonUFW.log should exist!"; fi
    	# UFW
    if [ -f "$mountPoint/etc/init.d/ufw.apk-new" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: File /etc/init.d/ufw.apk-new should not exist!"; fi
    if [ -f "$mountPoint/etc/ufw/ufw.conf.apk-new" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: File /etc/ufw/ufw.conf.apk-new should not exist!"; fi
    if [ -f "$mountPoint/etc/default/ufw.apk-new" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: File /etc/default/ufw.apk-new should not exist!"; fi

    # Default policy and configurations for UFW
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_INPUT_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets that are incoming \(ingress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_OUTPUT_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets that are outgoing \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall does not drop packets meant for routing \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep 'DEFAULT_APPLICATION_POLICY="DROP"' /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall still accepts application profiles \(egress\)"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "IPV6=no" /etc/default/ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW firewall might accept Ipv6 addresses"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "LOGLEVEL=$ufwLogging" /etc/ufw/ufw.conf 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW has wrong loglevel configured!"; fi
    # Checking for expected open ports via UFW
        # Port http
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $httpPort 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $httpPort"; fi
        # Port https
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $httpsPort 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $httpsPort"; fi
        # Port 53
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $dnsPort 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $dnsPort"; fi
        # Port ntp
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $ntpStandardPort 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $ntpStandardPort"; fi
        # Port ntp monitor
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $ntpMonitorPort 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $ntpMonitorPort"; fi
        # Port ssh
    if [ -z "$(chroot $mountPoint /bin/cat /etc/ufw/user.rules | grep $sshPort 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: NFTables does not contain expected UFW firewall configurations for port $sshPort"; fi

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

    # UFW root bypass check
    if [ -z "$(chroot $mountPoint /bin/grep "    if 1 == 2 and uid != 0" /usr/lib/python$pythonVer/site-packages/ufw/backend.py 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: UFW still requires root access to be executed!"; fi
	
	if [ -z "$(chroot $mountPoint /bin/grep ":msg,contains,\"UFW AUDIT\" stop \# Discard irrelevant UFW Audit messages" /etc/rsyslog.d/10-discardFilters.conf)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not install filter to remove unwanted messages firewall kernel messages"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "if (\$syslogfacility-text == \"kern\") and (\$msg contains \"\[UFW\") then {action(type=\"omfile\" File=\"\/var\/log\/kernFirewall.log\") stop} \# firewall kernel logging" /etc/rsyslog.d/40-broadFilters.conf)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not install filter to redirect kernel firewall messages"; fi
    if [ -z "$(chroot $mountPoint /bin/grep "if (\$programname == \"ufw\") then {action(type=\"omfile\" File=\"\/var\/log\/daemonUFW.log\") stop} \# ufw daemon logging" /etc/rsyslog.d/50-daemonFilters.conf)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Could not install filter to redirect firewall daemon messages"; fi
    
        # Firewall
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ssh -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d/ssh"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/apk -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d/apk"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/ntp -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d/ntp"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/applications.d/dns -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/applications.d/dns"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before.init -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/before.init"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before.rules -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/before.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/before6.rules -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/before6.rules":; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after.init -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/after.init"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after.rules -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/after.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/after6.rules -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/after6.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/sysctl.conf -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/sysctl.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/default/ufw -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/default/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/ufw -user root -and -group $firewallUsername 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/sbin/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/ufw.conf -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/ufw.conf"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/user.rules -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/user.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/ufw/user6.rules -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /etc/ufw/user6.rules"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw/ufw-init -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ufw/ufw-init"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw/ufw-init-functions -user $firewallUsername -and -group root 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /usr/lib/ufw/ufw-init-functions"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/daemonUFW.log -user $loggerUsername -and -group logread 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong file ownership for /var/log/daemonUFW.log"; fi
    
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/sbin/ufw -perm 0550 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/sbin/ufw"; fi
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
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/default -perm 701 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/default"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/ufw -perm 500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /etc/init.d/ufw -perm 0500 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /etc/init.d/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ufw"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw/ufw-init -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ufw/ufw-init"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /usr/lib/ufw/ufw-init-functions -perm 0750 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /usr/lib/ufw/ufw-init-functions"; fi
    if [ -z "$(chroot $mountPoint /usr/bin/find /var/log/daemonUFW.log -perm 0640 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Wrong permissions for /var/log/daemonUFW.log"; fi
    if [ -z "$(chroot $mountPoint /sbin/rc-service -l | grep -i ufw 2>/dev/null)" ]; then missing=$((missing+1)); log "SYSTEM TEST MISMATCH: Ufw is yet to be added to rc list"; fi
}

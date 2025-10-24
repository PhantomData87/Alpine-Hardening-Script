#Consider:
#/bin:
#setpriv; setpriv
#wdctl; util-linux-misc
#lsfd; util-linux-misc
#dmesg; dmesg

#Unnecessary:
#/bin:
#rev; util-linux-misc
#pipesz; util-linux-misc
#mountpoint; util-linux-misc
#ionice; util-linux-misc
#getopt; util-linux-misc
#more; util-linux-misc
#findmnt; findmnt
#lsblk; lsblk
#umount; umount
#mount; mount

#Consider:
#/sbin
#agetty; agetty
#blkid; blkid
#losetup; losetup
#hwclock; util-linux-misc
#fsfreeze; util-linux-misc
#mkfs; util-linux-misc
#fsck; util-linux-misc
#blockdev; util-linux-misc
#blkzone; util-linux-misc

#Unnecessary
#/sbin
#fstrim; fstrim
#cfdisk; cfdisk
#wipefs; wipefs
#sfdisk; sfdisk
#runuser; runuser
#zramctl; util-linux-misc
#switch_root; util-linux-misc
#swapon; util-linux-misc
#swapoff; util-linux-misc
#swapplabel; util-linux-misc
#pivot_root; util-linux-misc
#mkswap; util-linux-misc
#mkfs.min; util-linux-miscix
#mkfs.cramfs; util-linux-misc
#mkfs.bfs; util-linux-misc
#fsck.minix; util-linux-misc
#fsck.cramfs; util-linux-misc
#findfs; util-linux-misc
#fdisk; util-linux-misc
#ctraltdelete; util-linux-misc
#chcpu; util-linux-misc
#blkpr; util-linux-misc
#blkdiscard; util-linux-misc

#Consider:
#/usr/bin
#logger; logger
#lscpu; lscpu
#flock; flock
#hexdump; hexdump
#whereis; util-linux-misc
#waitpid; util-linux-misc
#utmpdump; util-linux-misc
#unshare; util-linux-misc
#uclampset; util-linux-misc
#taskset; util-linux-misc
#renice; util-linux-misc
#prlimit; util-linux-misc
#lsns; util-linux-misc
#lsmem; util-linux-misc
#lslocks; util-linux-misc
#lsirq; util-linux-misc
#lsipc; util-linux-misc
#lsclocks; util-linux-misc
#irqtop; util-linux-misc
#ipcsl util-linux-misc
#ipcrm; util-linux-misc
#ipcmk; util-linux-misc
#hardlink; util-linux-misc
#fincore; util-linux-misc
#fallocate; util-linux-misc
#fadvice; util-linux-misc
#exch; util-linux-misc
#enosys; util-linux-misc
#column; util-linux-misc
#colrm; util-linux-misc
#colcrt; util-linux-misc
#chrt; util-linux-misc

#Unnecessary
#/usr/bin
#mcookie; mcookie
#uuidgen; uuidgen
#wall; util-linux-misc
#uuidparse; util-linux-misc
#ul; util-linux-misc
#setterm; util-linux-misc
#setsid; util-linux-misc
#setpgid; util-linux-misc
#scriptreplay; util-linux-misc
#scriptlive; util-linux-misc
#script; util-linux-misc
#rename; util-linux-misc
#nsenter; util-linux-misc
#namei; util-linux-misc
#mesg; util-linux-misc
#look; util-linux-misc
#isosize; util-linux-misc
#eject; util-linux-misc
#coresched; util-linux-misc
#choom; util-linux-misc
#chmem; util-linux-misc
#cal; util-linux-misc
#bits; util-linux-misc
#setarch; setarch, util-linux-misc

#Consider:
#/usr/sbin:
#rtcwake; util-linux-misc

#Unnecessary:
#/usr/sbin:
#partx; partx
#unix_chkpwd; linux-pam runuser
#pwhistory_helper; linux-pam runuser
#pam_timestamp_chec; linux-pamk runuser
#pam_namespace_helper; linux-pam runuser
#mkhomedir_helper; linux-pam runuser
#faillock; linux-pam runuser
#rfkill; util-linux-misc
#resizepart; util-linux-misc
#readprofile; util-linux-misc
#ldattach; util-linux-misc
#delpart; util-linux-misc
#addpart; util-linux-misc
#!/bin/bash




#############################################################################
#############################################################################
#Section 1: Initial Setup
#Section 1.1: Disable unused filesystems
echo "Disabling unused filesystems"

#Function that checks to see if a filesystem is disabled and if not, disables it. Receives the name of the filesystem as an argument.
disable() {
        CORRECT="install /bin/true "
        AUDIT=$(modprobe -n -v $1 | grep "install /bin/true")
        CHECK=$(cat /etc/modprobe.d/CIS.conf | grep -ow "$1")
        if [[ "$AUDIT" != "$CORRECT" && "$1" != "$CHECK" ]];
        then
                echo "Writing $1 to CIS.conf"
                echo "install $1 /bin/true" >> /etc/modprobe.d/CIS.conf
        fi
} #End of function "disable"

touch /etc/modprobe.d/CIS.conf

disable cramfs
disable freevxfs
disable jffs2
disable hfs
disable hfsplus
disable squashfs
disable udf
#disable vfat


#Section 1.1.2 - 1.1.16
#This function checks to see if file system is on a separate partition.
#If it is, it will ensure each one is met with the proper mounting
#options according to CIS standards.
#The function receives 2 inputs "ensureOptions <1> <2>
#<1> = Desired file system to check 		i.e. "/tmp"
#<2> = Desired mounting option to check 	i.i. "nosud"
 
ensureOptions() {
FS=$1           #Receives the filesystem we wish to check
OPT=$2          #Receives the option we wish to check
LINE=$(awk -v pat="$FS" '(/UUID/ && $0~pat){print NR}' /etc/fstab)
CHECK=$(mount | grep $FS | grep -ow $OPT)

if [ "$CHECK" == "" ]
then
        if [ "$(awk -v pat="$LINE" 'NR==pat {print $4}' /etc/fstab)" == "defaults" ]
        then
                sed -i "$LINE s/defaults/$OPT/" /etc/fstab
                mount -o remount,$OPT $FS
        elif [ "$(mount | grep $FS | grep -ow noexec)" == "noexec" ]
        then
                sed -i "$LINE s/noexec/&,$OPT/" /etc/fstab
                mount -o remount,$OPT $FS
        elif [ "$(mount | grep $FS | grep -ow nodev)" == "nodev" ]
        then
                sed -i "$LINE s/nodev/&,$OPT/" /etc/fstab
                mount -o remount,$OPT $FS       
        elif [ "$(mount | grep $FS | grep -ow nosuid)" == "nosuid" ]
        then
                sed -i "$LINE s/nosuid/&,$OPT/" /etc/fstab
                mount -o remount,$OPT $FS
        else
                echo "The $FS filesystem does not have a seperate partition"
        fi
fi
}


 ensureOptions /tmp nosuid
 ensureOptions /tmp nodev
# ensureOptions /tmp noexec

# ensureOptions /var nosuid
# ensureOptions /var nodev
# ensureOptions /var noexec

 ensureOptions /var/tmp nosuid
 ensureOptions /var/tmp nodev
 ensureOptions /var/tmp noexec

# ensureOptions /var/log nosuid
# ensureOptions /var/log nodev
# ensureOptions /var/log noexec

# ensureOptions /var/log/audit nosuid
# ensureOptions /var/log/audit nodev
# ensureOptions /var/log/audit noexec

# ensureOptions /home nosuid
 ensureOptions /home nodev
# ensureOptions /home noexec

# ensureOptions /dev/shm nosuid
# ensureOptions /dev/shm nodev
# ensureOptions /dev/shm noexec



#############################################################################
#############################################################################
#section 1.3.1

echo "Installing and initiating Aide"
apt install aide -y
aideinit

echo "Adding crontab for Aide"
echo -e "$(crontab -u root -l)\n0 5 * * * /usr/bin/aide --check" | crontab -u root -

#############################################################################
#############################################################################
#section 1.4.1
echo "Securing bootloader permissions"
chown root:root /boot/grub/grub.cfg
chmod 600 /boot/grub/grub.cfg

#############################################################################
#############################################################################
#section 1.5.1
echo "Restricting core dumps"
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0


#section 1.5.3
RESULT=$(sysctl kernel.randomize_va_space | awk '{ print $2 }')
if [ $RESULT != 2 ]
then
        echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
        sysctl -w kernel.randomize_va_space=2
fi

#section 1.5.4
prelink -ua			#restores binaries
apt purge prelink		#removes prelink

#############################################################################
#############################################################################
#section 1.7
echo "Configuring banners"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

#Configure permissions
chown root:root /etc/motd
chmod 644 /etc/motd

chown root:root /etc/issue
chmod 644 /etc/issue

chown root:root /etc/issue.net
chmod 644 /etc/issue.net

#1.7.2: Ensure GDM Banner is configured
#Ensure file exists
touch /etc/dconf/profile/gdm
mkdir /etc/dconf/db/gdm.d
touch /etc/dconf/db/gdm.d/01-banner-message

#Ensures proper contents are in the file
if [ ! $(grep "user-db:user" /etc/dconf/profile/gdm) ]
then
        echo "user-db:user" >> /etc/dconf/profile/gdm
fi
if [ ! $(grep "system-db:gdm" /etc/dconf/profile/gdm) ]
then
        echo "system-db:gdm" >> /etc/dconf/profile/gdm
fi
if [ ! $(grep "file-db:/usr/share/gdm/greeter-dconf-defaults" /etc/dconf/profile/gdm) ]
then
        echo "file-db:/usr/share/gdm/greeter-dconf-defaults" >> /etc/dconf/profile/gdm
fi
if [ ! $(grep -ow "\[org/gnome/login-screen\]" /etc/dconf/db/gdm.d/01-banner-message) ]
then
        echo "[org/gnome/login-screen]" >> /etc/dconf/db/gdm.d/01-banner-message
fi
if [ ! $(grep -ow "banner-message-enable=true" /etc/dconf/db/gdm.d/01-banner-message) ]
then
        echo "banner-message-enable=true" >> /etc/dconf/db/gdm.d/01-banner-message
fi
if [ ! $(grep -ow "banner-message-text=" /etc/dconf/db/gdm.d/01-banner-message) ]
then
        echo "banner-message-text='Authorized uses only. All activity may be monitored and reported.'" >> /etc/dconf/db/gdm.d/01-banner-message
fi

dconf update

#section 1.8: Apply automatic security updates
PATH="/etc/cron.weekly/apt-security-updates"
PATH2="/etc/logrotate.d/apt-security-updates"
if [ -e $PATH ]
then
        #Configure automatic security updates
        touch $PATH
        echo "echo \"**************\" >> /var/log/apt-security-updates" >> $PATH
        echo "date >> /var/log/apt-security-updates" >> $PATH
        echo "aptitude update >> /var/log/apt-security-updates" >> $PATH
        echo "aptitude safe-upgrade -o Aptitude::Delete-Unused=false --assume-yes --target-release \`lsb_release -cs\` -security >> /var/log/apt-security-updates" >> $PATH
        echo "echo \"security updates (if any) installed\"" >> $PATH
        chmod +x $PATH

        #Enable rotating of the logs
        echo "/var/log/apt-security-updates {" >> $PATH2
        echo "  rotate 2" >> $PATH2
        echo "  weekly" >> $PATH2
        echo "  size 250k" >> $PATH2
        echo "  compress" >> $PATH2
        echo "  notifempty" >> $PATH2
        echo "}" >> $PATH2

fi


#############################################################################
#############################################################################
#section 2.2.3
echo "Disabling Avahi Server"
systemctl disable avahi-daemon

#############################################################################
#############################################################################
#section 2.2.15
echo "Configuring mail transfer agent for local-only mode"
sed -i '/^inet_interfaces =/s/=.*/= localhost/' /etc/postfix/main.cf
services postfix restart

#############################################################################
#############################################################################
#section 2.3
echo "Removing service clients"
apt remove telnet -y

#############################################################################
#############################################################################
#section 3.1
echo "Securing network parameters"

#ipv4
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.tcp_syncookies=1

sysctl -w net.ipv4.route.flush=1

#ipv6
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf

sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0

sysctl -w net.ipv6.route.flush=1

#Disable IPv6
sed -i '/^GRUB_CMDLINE_LINUX=/s/=.*/="ipv6.disable=1"/' /etc/default/grub
update-grub

#############################################################################
#############################################################################
#section 3.4
echo "Hardening TCP Wrappers"
#Add Hosts allowed to access this machine
#echo "ALL: <net>/<mask>, <net>/<mask>, ..." > /etc/hosts.allow
#
#Deny all hosts except for previously specified
#echo "ALL: ALL" >> /etc/hosts.deny

#############################################################################
#############################################################################
#section 3.5
echo "Hardening uncommon network protocols"

echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf 
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf 
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

#############################################################################
#############################################################################
#section 3.6
apt install ufw -y
ufw enable

#############################################################################
#############################################################################
#section 4.2.1
echo "Configuring logging"

apt install rsyslog -y
systemctl enable rsyslog

chmod -R g-wx,o-rwx /var/log/*

#############################################################################
#############################################################################
#section 5.1
echo "Configuring cron daemon"

chown root:root /etc/crontab
chmod 600 /etc/crontab
chown root:root /etc/cron.hourly
chmod 600 /etc/cron.hourly
chown root:root /etc/cron.daily
chmod 600 /etc/cron.daily
chown root:root /etc/cron.weekly
chmod 600 /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod 600 /etc/cron.monthly
chown root:root /etc/cron.d
chmod 600 /etc/cron.d

rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod 600 /etc/cron.allow
chmod 600 /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

#############################################################################
#############################################################################
#section 5.2
echo "Configuring SSH"
chown root:root /etc/ssh/ssh_config
chmod 600 /etc/ssh/ssh_config

#sed -i '/Protocol /s/^#//g' /etc/ssh/ssh_config
#sed -i '/LogLevel  /s/^#//g' /etc/ssh/ssh_config
#sed -i '/X11Forwarding  /s/^#//g' /etc/ssh/ssh_config
#sed -i '/IgnoreRhosts /s/^#//g' /etc/ssh/ssh_config
#sed -i '/HostbasedAuthentication /s/^#//g' /etc/ssh/ssh_config
#sed -i '/PermitRootLogin /s/^#//g' /etc/ssh/ssh_config
#sed -i '/PermitEmptyPasswords /s/^#//g' /etc/ssh/ssh_config
#sed -i '/PermitUserEnvironment /s/^#//g' /etc/ssh/ssh_config
#sed -i '/MACs /s/^#//g' /etc/ssh/ssh_config


echo "Protocol 2" >> /etc/ssh/ssh_config
echo "LogLevel INFO" >> /etc/ssh/ssh_config
echo "X11Forwarding no" >> /etc/ssh/ssh_config
echo "MaxAuthTries 4" >> /etc/ssh/ssh_config
echo "IgnoreRhosts yes" >> /etc/ssh/ssh_config
echo "HostbasedAuthentication no" >> /etc/ssh/ssh_config
echo "PermitRootLogin no" >> /etc/ssh/ssh_config
echo "PermitEmptyPasswords no" >> /etc/ssh/ssh_config
echo "PermitUserEnvironment no" >> /etc/ssh/ssh_config
echo "MACS hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/ssh_config
echo "ClientAliveInterval 300" >> /etc/ssh/ssh_config
echo "ClientAliveCountMax 0" >> /etc/ssh/ssh_config
echo "LoginGraceTime 60" >> /etc/ssh/ssh_config
echo "Banner /etc/issue.net" >> /etc/ssh/ssh_config

#############################################################################
#############################################################################
#section 5.3
echo "Configuring PAM"

apt install libpam-pwquality -y

#############################################################################
#############################################################################
#section 5.4
echo "Configuring user accounts and environment"
echo "umask 027" >> /etc/bash.bashrc
echo "umask 027" >> /etc/profile 

#############################################################################
#############################################################################
#section 5.6
echo "Restricting access to su"
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
echo "wheel:x:10:root,icisi-admin" >> /etc/group

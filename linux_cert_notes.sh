Cert GUIDE

# CHAPTER 1

grep S[ek] file_example 	> "will show words starting with S and with 2nd letter e or k"
grep [0-9] file_example		> "print lines with numbers 0-9"
grep ^S file_example		> "beginning with S"
grep me$ file_example 		> "ending me"
grep -v ^#					> "-v invert match ; will skip lines with # in the beginning "
find / -user stembedu -exec cp {} /tmp/stembedu/ \; >"find everything from stembedu and copy to /tmp/stembedu"
sed -i 's/vg_cent02/vg_cent03/g' /boot/grub/grub.conf 	 > "replace a for b "

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 2 (bootloader, runlevels, services/jobs)

GRUB

grub> find /grub/grub.conf	> "find partition that contain the grub.conf"
grub> root
grub> setup (hd0) 			> "reinstall GRUB"

	GRUB CORRUPTED
		linux rescue
		chroot /mnt/sysimage
		grub-install /dev/sd*
		exit  

runlevel > "current runlevel"
chkconfig --list sshd 			> "check status of sshd service"
chkconfig --level 4 sshd off 	> "turn off sshd service for runlevel 4"
ntsysv --level 2 	> "service management utility - for level 2" 
service sshd status > "check service status"
initctl list 		> "currently running jobs"

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 3 (standard partitioning, LVM, RAID)

cat /etc/partitions > "current partition layout"
parted -l 			> "equiv. to fdisk -l"
fdisk /dev/sdb    	> "equiv. parted /dev/sdb"
	1st primary
	2nd primary 
		>> partprobe /dev/sdb

pvcreate /dev/sdb
vgcreate vg_group01 /dev/sdb
lvcreate -L 256 vg_group01 		> "256MB logical volume"
lvrename /dev/vg_group01/lvol0 /dev/vg_group01/SecretData > "lv rename"
lvextend -L +200 /dev/vg_group01/... 	"add 200 MB from vg to lv"
lvextend -L 5000 /dev/... 		> "extend to 5GB"
lvresize -L 6000 /dev/...		> "extend to 6GB - same as lvextend"
vgextend vg_group01 /dev/sdc 	> "extend existing vg with new physical volume"
lvreduce -L 200 /dev/vg_group01/SecretData > "reduce lv 'SecretData' to 200M"
vgreduce vg_group01 /dev/sdc	>	""
pvmove /dev/sdb /dev/sdc 		> "migrate the data from the 'dying' drive"
lvremove /dev/vg_group01/SecretData > "removing useless lv"
vgremove VolGroup22 			> "remove specific vg"
pvremove /dev/sdd
vgscan 						> 'scan disk for LVM'
vgreduce uavg /dev/sde		> 'remove disk from VG' 

mdadm -Cv /dev/md0 --level=5 -n3 /dev/sdb1 /dev/sdc1 /dev/sdd1 > "RAID 5 with 3 partitions /dev/md0 "
mdadm -D /dev/md0 	> "detail about the RAID array"
cat /proc/mdstat 	> "status of RAID"
mdadm /dev/md0 -f /dev/sdd1 > "to fail a disk in the array"
mdadm /dev/md0 -r /dev/sdd1 > "remove from array"
mdadm /dev/md0 -a /dev/sdd1 > "add new on - must be partitioned"

mdadm -vS /dev/md0 	> "take the RAID array offline"
mdadm --remove /dev/md0 > "remove array - must be stopped before"
mdadm --examine --scan > "simple raid scan"
	# check why UUID from mdadm and blkid is different " FSTAB mount from BLKID is working"
	# REASON blkid - reports UUID from ext4 fs ; mdadm of RAID device !!! USE BLKID in fstab

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 4 (fs setup, LUKS encryption, fs quotas, fs security, AutoFS)

mkfs.ext2 /dev/sdc1										> "create ext2 fs"
tune2fs -j /dev/sdc1 									> "upgrade to ext3"
swapon -s 												> "check any current swap spaces"
dd if=/dev/zero of=/mnt/file_swap bs=1024 count=50000 	> "file as swap 50MB"
mkswap /mnt/file_swap && swapon /mnt/file_swap
fuser -cu /dev/sdc1 									> "check what users are currently using file system"
lsof /dev/sdc1											> "view all open files"
/etc/mtab 												> "contains a list of all currently mounted file systems"
blkid (block device attributes) ; e2label (modifies the label on an ext fs) ; findfs (locate specific fs)
e2label /dev/sdb1 CData && findfs LABEL=CData
mount LABEL=CData /opt/company_data
e2fsck -f /dev/vg_group01/lvol0 						> "check the filesystem"
lvextend -L +24 /dev/vg_group01/lvol0 && resize2fs -p /dev/vg_group01/lvol0 "extending logical volume + extending file system"

dd if=/dev/urandom of=/dev/sdb1 								> "fill partition with random data"
cryptsetup --verbose --verify-passphrase luksFormat /dev/sdb1 	> "partition initialization"
cryptsetup luksOpen /dev/sdb1 opt_data 							> "name for encrypted device"
mount /dev/mapper/opt_data /opt/opt_data 
vim /etc/crypttab 												> "opt_data /dev/sdb1 none"	encrypted partition has to be added
/sbin/restorecon -v -R /opt/opt_data							> "restore of SELinux security contexts"
cryptsetup luksDump /dev/sdb1 									> "verify encrypted partition"
cryptsetup luksUUID /dev/sdb1									> "check UUID"

> remove 
	cryptsetup status opt_data
	cryptsetup luksRemoveKey /dev/sdb1
	cryptsetup remove /dev/mapper/opt_data /dev/sdb1

vim /etc/fstab > /dev/sdb1	/opt/company_data	ext4	defaults,usrquota,grpquota	1 2
quotacheck -ugm /opt/company_data 		>"create quota files"
quotaon -v /opt/company_data 			>""
edquota -u user01 						>"edit quota for user01"
edquota -t 								>"edit grace period"
edquota -up user01 user02 user02 		>"quota rules for other users will be configured according to user01 "
repquota -uv /opt/company_data/			>"report quotas information"

getfacl file1 								>"grab ACL info, fs has to be mounted with ACL option"
setfacl -m u:user01:rwx /opt/backup/file1 	>"add rwx for user01"
setfacl -x u:stembedu /opt/backup/file1	>"remove for user stembedu "

superblock is structure that contains metadata of the file system

dumpe2fs -h /dev/hda1 > check the state of the file system 

iscsiadm -m discovery -t st -p 10.0.0.96 			> "check for iscsi target"
iscsiadm -m node -T iqn.1994-05.com.redhat:9c7745dafe68:mhvtl:stgt:1 -p 10.0.0.96 -l  >"recod iscsi target"
service iscsi status
iscsiadm -m session 			>"display connected targets "

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 5 (networking)

system-config-network-tui  > "network utility"
ifdown / ifup eth1
ifconfig eth0 172.168.1.1 netmask 255.255.255.0
route add default gw 192.168.1.1 eth0
/etc/sysconfig/network-scripts-route<interface> 
tcpdump -i eth0 -w pkt_capture 	> "capturing traffic on eth0"   > dhclient on other console
tcpdump -r pkt_capture | less > "review result"

	# bonding 	> vim /etc/modprobe.d/bond.conf
	#			> alias bond0 bonding
    #			> eth1/2 has to be modified > MASTER=bond0 ; SLAVE=yes ; USERCTL=no

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 6 (rpm & red hat network)

rpm -qi nano 	> "info about nano package"
rpm -qf /etc/rsyslog.conf > "query the package that the file belongs to"
rpm -qc rsyslog 	> "find all config files"
rpm -qd rsyslog 	> "find the documentation files"
rpm -ql rsyslog 	> "all files which belongs to rsyslog"
yum grouplist 		> "set of packages"
yum groupinstall "Backup Server"
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS,tmp} > "create multiple directories"
yum provides /usr/sbin/semanage  		> "which package provides semanage"
yum whatprovides /usr/sbin/semanage		> "which package provides semanage"

	!!!!!!!!!!!!
	#USEFUL HINT how to INSTALL via YUM without Red Hat subscription
		
		mount -t iso9660 /dev/sr0 /mnt/dvd

		cd /etc/yum.repos.d
		mv rhel-source.repo rhel-source.bck 
		vim dvd.repo
			
			[dvd-source]
			name=RHEL 6.4 dvd repo
			baseurl=file:///mnt/dvd
			enabled=1
			gpgcheck=0
		yum repolist
		yum install ...... :)


-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 7 (user administration)

find / -user user02  	> "search all files belongs to user02"
chage -l user02 		> "info about user02 password"
chage -E 2014-12-30 user02 > "expiration for user02"
id -Gn user02 			> "check out the groups to which user02 belongs"
grep -v ^# /etc/login.defs > "this file controls specifis relating to system-wide user logins and passwords"

setuid u SPUSTITELNYCH SOUBORU >"povoli docasne spustit soubor,ktery bezne potrebuje root prava , napr passwd" chmod u+s
setgid u adresaru >"způsobí, že nové soubory a podadresáře v něm vytvořené zdědí jeho groupID místo primárního groupID uživatele, který adresář nebo soubor vytvořil"chmod g+s
sticky bit >"Pokud je na nějakém nastaven, pouze vlastník objektu, vlastník adresáře, nebo správce počítače může přejmenovávat či mazat položky v tomto adresáři."

authconfig-tui > "menu based configuration utility for network authentication clients"

NIS > "je protokol typu klient-server pro distribuci systémových konfiguračních dat, jako jsou uživatelská jména mezi počítači v počítačové síti.příkazy začínají na "yp"."
	> "nastupce LDAP "
vim /etc/nsswitch.conf > passwd:	nis files ""
yum install -u openldap nss_ldap  "same but for LDAP"
/etc/skel >

4=SUID
2=SGID
1=sticky

3=SGID && sticky
5=SUID && sticky
6=SGID && SUID
7=sticky, SUID && SGID

-----------------------------------------------------------------------------------------------------------------------------------------------------------

#CHAPTER 8 (kickstart etc.)

iptables -I INPUT 5 -p tcp -m tcp --dport 80 -j ACCEPT  (prida na 5radek INPUT retezu ACCEPT rule pro port 80 http)
service iptables save ; service iptables restart
touch /var/www/pub/kickstart/redhat-base.cfg 
# from boot # linux ks=http://10.0.0.98/pub/kickstart/redhat-base.cfg append ip=10.0.0.99 netmask=255.255.255.0

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 9 (system logging, monitoring and automation)

rsyslog > /etc/rsyslog.conf
logrotate > /etc/logrotate.conf ; /etc/logrotate.d/
		# the standard is to use the UDP protocol on port 514 >to become the centralized server for the network
			ON SERVER SIDE 
			> uncomment UDP section
			> service rsyslog restart
			> iptables -I INPUT 5 -p udp -m udp --dport 514 -j ACCEPT
			> service iptables save ; service iptables restart
			ON CLIENT SIDE
			>rsyslong.conf  > authpriv.*	@serverIP

lastlog > "list login records"
faillog > "lists failed login attempts"

pidof sshd , pgrep sshd  > "will show PID(s) belonging to SSH service"
		# first priority -20 to 20 (dead last priority)
renice -2 3874 	> "change priority for pid 3874"
crond > /etc/cron.allow /etc/cron.deny
grep ^# /etc/crontab
crontab -u eddie -e > "edit cron for user eddie"
run-parts 	>
/etc/ancrontab 		> "if system is turned off during the time that a cron job should have run,when the system boots again, the cron service will call /etc/anacrontab to make sure that all missed cron jobs are run"
at (atd service) 	> "executes command at specified time" "one time job only"
at -f /tmp/hello 11am > "execute file hello at 11am"
atq 				> "check queue"
/etc/services 		> "file with services"

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 10 (kernel)

lsmod 		> "list currently loaded modules"
modinfo		> "display info about a kernel module"
/proc/sys 	> "virtual file system - allows to tune the kernel while the system is running"
		# example - allow system to temporarily forward packets
			> echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -a 	> "list all the available options"
sysctl -a |grep ip_forward > "query parameter"
sysctl -w net.ipv4.ip_forward=1
		# NEVER use rpm -U option when updating kernel - it erases the prior kernel
sysctl.conf > "maintain custom parameters for the kernel during system boot"
rpm -qa | grep 'php' | xargs rpm -e

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 11 (SELinux)

sestatus ; getenforce ; setenforce ; getsebool ; setsebool ; chcon ; restorecon

setenforce enforcing 	> "eg. change from permissive to enforcing"
	# SELinux uses 3 different context to enforce security : user, role and domain
	# USER : unconfined_u ; system_u ; user_u  ROLE : object_r (FILE) system_r (USER& PROCESSES) ; DOMAIN unconfined_r 
ps -ZC sshd 			> "check SELinux labelsaccociated with SSH"

	touch myfile && ls -Z myfile  >>> (unconfined_u   >>> unprotected user)
	# change contect to system user 
		chcon -vu system_u myfile 
	# reset context of file back
	restorecon -F myfile

getsebool -a |grep ftp > "query all values for ftp service"
semanage boolean -l |grep ftp > "same as getsebool but with description"
setsebool -P httpd_enable_homedirs=1 > "disable protection to access home dirs on web server , PERSISTENT "
grep "SELinux is preventing" /var/log/messages
grep "denied" /var/log/audit/audit.log
/selinux/booleans 		> "list of all available booleans"

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 12 (System security)

	# TCP Wrappers is a host service that can be used to limit or control access from remote hosts , eg. /etc/hosts.allow /deny

/etc/hosts.allow   > 	sshd : 172.168.1. EXCEPT 172.168.1.100   > allow  172.168.1.0/24 subnet except 172.168.1.100 ''
						sshd : .example.com

iptables  /etc/sysconfig/iptables
iptables -I INPUT 6 -s 172.168.1.1/24 -p tcp --dport 22 -j ACCEPT && service iptables save

	# NAT (network address translation) allows you to use a server as a gateway to a subnet, essentially controlling what goes in and out of your network
	# NAT maintains a table that allow the use of multiple internal IP addressess to multiple public IP address
	ipltabes t nat -I POSTROUTING -o eth0 -s 172.168.1.0/24 -j MASQUERADE

cp /etc/sysconfig/iptables /etc/sysconfig/iptables.bak 
echo "mv /etc/sysconfig/iptables.bak /etc/sysconfig/iptables && service iptables restart" | at now+20min

	# PAM (Pluggable Authentication Module - includes a set of dinamically loadable librabry modules)
/lib/security/	> "contains available library modules"
/etc/pam.d/		> "containts config file for services using PAM"
/varl/log/secure	> "provides information relating to PAM events"

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 13 (Remote access)

ssh-keygen -t rsa > "will generate public/private keys under .ssh"
ssh-copy-id pidora@pidora > "authorized_keys on @pidora was updated and login to pidora is passwordless"
cat .ssh/id_rsa.pub | ssh eddie@cent01 'cat >> ~/.ssh/authorized_keys'  # from MAC to linux machine without ssh-copy-id

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 14 (Web services)

service httpd configtest 	> "will check httpd.conf file - same as httpd -t"
service httpd graceful 		> "it restarts the web server, without disconnecting any currently connected clients"

mkdir /var/www/site1 ; chcon -Rvu system_u site1

	#password protected site
	<Directory "/var/www/html">
	AuthType Basic
    AuthName "Password Restricted Area"
    AuthUserFile /etc/httpd/userfile
    Require user eddie

    htpasswd -cm /etc/httpd/userfile eddie  "(create with MD5 protection)"

    AllowOverride authconfig 	

    cd /var/www/html ; mkdir hr 
    cd hr ; vim .htaccess 			# AllowOverride authconfig
    	AuthType Basic
    	AuthName	"Password Restricted Area"
    	AuthGroupFile /etc/httpd/groupfile 
    	Require group hr_users

    htpasswd -m /etc/httpd/userfile hr01   ("don't use -c parameter ; it will destroy previous user")
    echo "hr_users: hr01 hr02" > /etc/groupfile


  	#SSL (https port 443)

    /etc/httpd/conf.d/ssl.conf
    <VirtualHost _default_:443> </VirtualHost>

    SSLCertificateFile /etc/pki/tls/certs/localhost.crt 
    SSLCertificateKeyFile /etc/pki/tls/private/localhost.key

    # CGI Applications

cp app.py /var/www/web-app-01
vim /etc/httpd/conf/httpd.conf
>>>	ScriptAlias /webapp "/var/www/web-app-01"
	<Directory "/var/www/web-app-01"/>
	Options ExecCGI FollowSymlinks
	....

chmod 755 -R /var/www/web-app-01

	# Virtual Hosts
		# multiple websites on a single host

in /etc/hosts

10.0.0.96       example.com
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
10.0.0.96       CENT02


<VirtualHost *:80>
    ServerAdmin stembedu@example.com
    DocumentRoot /var/www/site1
    ServerName example.com
    ErrorLog logs/site1_error_log
    CustomLog logs/site1_access_log common
</VirtualHost>

	httpd -S "verify syntax with VirtualHost config"
	httpd -D DUMP_VHOSTS "for multiple virtual host sites "

	# SQUID Web Proxy

   acl intranet src 192.168.1.0/24   > "nastaveno acl pro intranet"
    acl intranet2 src 192.168.2.0/24
    acl faceb dstdomain .facebook.com

    http_access allow intranet        > povoleno
    http_access deny intranet2        > zamitnuto
    http_access deny faceb

 		#for elinks.conf activate squid with
 		set protocol.http.proxy.host = "127.0.0.1:8080"

-----------------------------------------------------------------------------------------------------------------------------------------------------------

#CHAPTER 15 ( NFS   port 2049)

#RPC, vzdálené volání procedur > rpcinfo -p  (port 111)

/etc/sysconfig/nfs 
	# Define which protocol versions mountd will advertise.
	MOUNTD_NFS_V2="no"
	MOUNTD_NFS_V3="no"
exportfs -rav - "export any new resources"

/var/lib/nfs/etab	> "list of currently exported resources"
/var/lib/nfs/rmtab	> "list of remotely mounted resources"
nfstat -m 	> "exported resources from client"

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 16 (SAMBA 137 , 138-139 , 445 port)

testparm 		> "check smb.conf file and print output"
smbpasswd -a stembedu > "will create user stembedu"
pdbedit -w -L > "verify that user was created"
getsebool -a | egrep '(samba)|(smb)|(nmb)|(win)' > "check all SELinux values with egrep"
chcon -Rt samba_share_t /opt/company_data "change context type"
smbclient -L CENT02 -U stembedu%password > "to see shares on CENT02"
mount -t cifs //pidora/Share /opt/test -o username=pidora,password=password > "mount samba Share"

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 17 (FTP 20-21 port)

grep -v ^# vsftpd.conf

-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 18 (DNS  port 53)

yum install -y bind bind-utils bind-libs

/etc/named.conf 	>"Main config file"
/etc/rndc.key 		>"Key file"
/etc/rndc.conf 		>"Key config file"

	# example of zone in named.conf
	zone "example.com" {
        type master;
        file "example.com.zone";
        allow-update { none; };
		};


-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 19 (Network services)

	Xinetd
	# Xinetd is master service that can run multiple services at the same time  , port 69 UDP
	# eg. chkconfig tftp on >  cat /etx/xinetd.d/tftp |grep disable > disable = no

	DHCP  # (port 67)

	/etc/sysconfig/dhcpcd	> "for multiple interfaces change DHCPDARGS="eth0 eth1" "  	

# A slightly different configuration for an internal subnet.  /etc/dhcp/dhcpd.conf
subnet 172.168.1.0 netmask 255.255.255.0 {
  range 172.168.1.20 172.168.1.30;
  option domain-name-servers 172.168.1.1;		#dns for the subnet
  option domain-name "example.org";
  option routers 172.168.1.1;					#default gateway for the subnet
  option broadcast-address 172.168.1.31;
  default-lease-time 600;						#how long each client keeps its lease until a renewal is requested (in seconds)
  max-lease-time 7200;
}

# DHCP reservations for example for printers (change in dhcpd.conf)

	host centos01	{

	option host-name "centos01.example.com"
	hardware ethernet	MACaddress
	fixed-address		172.168.1.25
	}

/var/lib/dhcpd/dhcpd.leases 		> info about IPs 

#NTP (port 123)

	zapsat INFO



-----------------------------------------------------------------------------------------------------------------------------------------------------------

# CHAPTER 20 (Email services) SMTP = port 25

alternatives --config mta 		> "change the default mail program"

[root@CENT02 ~]# alternatives --display mta |grep current 	> "show current default"
 link currently points to /usr/sbin/sendmail.postfix

 	# IMPORTANT values in main.cf
 	myhostname = cent02.example.com    (/etc/hosts has to be updated)
 	mydomain = example.com
 	myorigin = $mydomain
 	inet_interfaces = all 	
 	mydestination = $myhostname, localhost.$mydomain, localhost
 	mynetworks = 172.168.1.0/24, 127.0.0.0/8 		"in my case allowed only for internal ethernet and localhost"

 	> postfix check 	"check cfg syntax"

 	#post configuration
 	postconf -e mynetworks="127.0.0.1 /8 192.168.1.0 /24" 	"check configuration"
 	postconf -n |grep mynet 	> "just print"

 /etc/postfix/access 	> "allow or disallow relay mail via outgoing server"
 eg. 	172.168.1.2 	RELAY
 		172.168.1.10 	REJECT
 		client02		REJECT

 		# SASL connection
 	/etc/postfix/main.cf
 	relayhost = mail.example-a.com
 	smtp_use_tls = yes
 	smtp_sasl_auth_enable = yes
 	smtp_sasl_password_maps = hash:/etc/postfix/smtp_auth 
 	smtp_sasl_security_options = noanonymous

 		> vim /etc/postfix/smtp_auth
 			mail.example-a.com 		<account_number | account_info>:<password>
 		postmap /etc/postfix/smtp_auth > "update postfix lookup tables"

	# Aliases (useful to create distribution groups eg.)
	/etc/aliases
	helpdesk:	stembedu	user01	user02
	newaliases "update changes"    > helpdesk@example.com will work 

#   DOVECOT  (incoming mail server) imap TCP 143  , POP3 TCP 110 ,  993,995 for SSL

	"COMMON SETTINGS"

	/etc/dovecot/dovecot.conf
	/etc/pki/dovecot/dovecot-openssl.cnf 	"SSL certificate file"
	
	listen = 172.168.1.1
	ssl_disable = yes
	mail_location = maildir:~/Maildir 


		#local mail test
		echo "Hello stembedu" | mail -s "Local test" stembedu
		echo "Hello stembedu" | mail -s "Remote test" stembedu@example.com

	mutt > command to read mail from commandline 
	mailq > "display current mail in the queue"
	pstsuper -d 000F333 > "delete stuck message"


# ALLOW telnet to all connection not only localhost
# vi /etc/mail/sendmail.mc

DAEMON_OPTIONS(Port=smtp,Addr=127.0.0.1, Name=MTA')dnl
DAEMON_OPTIONS(`Port=smtp,Name=MTA')dnl 

m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf  	"will regenerate sendmail config file"

-----------------------------------------------------------------------------------------------------------------------------------------------------------

#CHAPTER 21 (Troubleshooting)

Single-user mode 	> "when ROOT password can't be changed "
					> ls /etc |grep shadow
					> pwconv  "will recreate /etc/shadow file"


MBR is corrupt 		> "boot into rescue mode, eg. RHEL DVD"
					> "enter grub shell"
					> grub> root  			"locate root drive"
					> grub> setup (hd0)		"reinstall MBR"
					> reboot

Partition or Root file system not found	> 1st option > fix grub.conf through GRUB menu , boot and make pernament changes in grub.cfg (NEED TO KNOW CORRECT info)
										> 2nd option > boot rescue DVD > go into root partition cd /mnt/sysimage/ ...
										> ... make it writable >> eg. mount -o remount,rw /dev/mapper/vg_rhel1-lv_root /mnt/sysimage
										> edit grub.conf 
										> reboot and pray 

The Superblock has become corrupt 	# root partition only in single user or recovery mode
									> dumpe2fs -h /dev/mapper/vg_cent02-lv_root "check state of filesystem"
									> dumpe2fs /dev/mapper/vg_cent02-lv_root |grep -i superblock "find a valid backup superblock"
									> e2fsck -f -b 8193 /dev/mapper/vg_cent02-lv_root > "repair the filesystem with a backup superblock"

Users cant create files in home dir 	> df -h 	>"verify partition isn't full"
										> quota 	>"if the partition isn't full check quota"


When service tells "Cannot Bind to address" 	> ifconfig	"verify current IP"
												> netstat -tuape "look at the current list of ports being used by the system"
												> tail /var/log/messages "find out which port is in conflict"



-----------------------------------------------------------------------------------------------------------------------------------------------------------

#CHAPTER 22 (Virtualization with KVM)

virt-install --name Client03 --ram 512 --disk path=/var/lib/libvirt/images/client03.img,size=2 --network network=default --cdrom /dev/cdrom
	# Client03 , 512 RAM , 2GB of storage , DVD mounted on /dev/cdrom

virsh connecto RHEL03 	> "will connect to HyperVisor"
virsh list --all 		> "display all available virtual guests"







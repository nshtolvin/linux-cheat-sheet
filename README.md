# Linux cheatsheet and routine operations

## Content <!-- omit in toc -->
- [Basics](#basics)
  - [Users](#users)
  - [Groups](#groups)
  - [NTP](#ntp)
  - [Networks](#networks)
  - [Archives](#archives)
  - [Proxy](#proxy)
- [Statistics](#statistics)
- [iptables](#iptables)
  - [Add rule](#add-rule)
  - [Save changes](#save-changes)
- [File Systems](#file-systems)
  - [Classical approach](#classical-approach)
  - [Logical partitions](#logical-partitions)
  - [RAID storage](#raid-storage)
  - [LVM](#lvm)
- [Certificates](#certificates)
- [Troubleshooting](#troubleshooting)
- [VMWare tools](#vmware-tools)
  - [Install VMWare tools](#install-vmware-tools)
  - [Enable shared folder](#enable-shared-folder)
  - [Auto-mounting shared folder](#auto-mounting-shared-folder)
- [Docker](#docker)
  - [Docker auto installation](#docker-auto-installation)
  - [Docker installation](#docker-installation)
  - [Run docker by nonroot user](#run-docker-by-nonroot-user)
  - [Image offline migration](#image-offline-migration)
- [Minikube](#minikube)
  - [Minikube installation](#minikube-installation)
  - [kubectl installation](#kubectl-installation)
- [PowerShell AD Commands](#powerShell-ad-commands)
  - [Networks](#networks)
- [LDAP authentication](#ldap-authentication)


## Links
- [GIT CHEAT SHEET](https://education.github.com/git-cheat-sheet-education.pdf)
- [khazeamo/linux-cheatsheet.md](https://gist.github.com/khazeamo/f762f532bfbc17d5bf396e9d4c2a9586)
- [RehanSaeed/Bash-Cheat-Sheet](https://github.com/RehanSaeed/Bash-Cheat-Sheet#command-history)
- [sudheerj/Linux-cheat-shee](https://github.com/sudheerj/Linux-cheat-sheet)
- [Linux Command Line](https://cheatography.com/davechild/cheat-sheets/linux-command-line/)
- [Linux Commands](https://www.pcwdld.com/linux-commands-cheat-sheet)

---

- [bregman-arie/devops-exercises](https://github.com/bregman-arie/devops-exercises)
- [wagoodman/dive](https://github.com/wagoodman/dive)
- [awesome-selfhosted/awesome-selfhosted](https://github.com/awesome-selfhosted/awesome-selfhosted)
- [HariSekhon/DevOps-Bash-tools](https://github.com/HariSekhon/DevOps-Bash-tools)
- [HariSekhon/Kubernetes-configs](https://github.com/HariSekhon/Kubernetes-configs)
- [jlord/git-it-electron](https://github.com/jlord/git-it-electron)
- [Lifailon/PS-Commands](https://github.com/Lifailon/PS-Commands)
- [sadservers.com](https://sadservers.com/)


## Basics

### Users
`useradd -m <username> -G <group> -s /bin/bash -p <password> -d /home/<dir> -g <group>` - create user

User info without passwords is stored in `/etc/passwd`. User passwords is stored in `/etc/shadow`.

`passwd <username>` - change password


### Groups
`groupadd <group_name>` - create groupe

`groups <username>` - show user groups

`cat /etc/group` - show all groups

### NTP
- [Simple tutorial](https://www.server-world.info/en/note?os=Ubuntu_20.04&p=ntp&f=3)

### Networks
To configure network parameters you can use `ifconfig`, `ip` or `nmtui` (`apt install network-manager`)

### Archives
Create _.tar.gz_ archive:
```bash
tar -cvf <archive_name>.tar <path>
tar -czvf <archive_name>.tar.gz <path>
```
where
- с - create: create archive
- v - verbose: display information
- f - file: use the archive specified file name (after the keys)
- z - gzip: zip file using gzip

To unpack the packaged _.tar.gz_ archive:
```bash
tar -xvf <archive_name>.tar.gz
```
where
- x - eXtract: extract files
- v - verbose: display information
- f - file : use the archive file name for unpacking specified after the keys

### Proxy
#### /etc/apt/apt.conf
```bash
Acquire::http::proxy "http://<username>:<password>@<proxy_ip>:<proxy_iport>/";
Acquire::https::proxy "http://<username>:<password>@<proxy_ip>:<proxy_iport>";
Acquire::ftp::proxy "http://<username>:<password>@<proxy_ip>:<proxy_iport>";
Acquire::socks::proxy "http://<username>:<password>@<proxy_ip>:<proxy_iport>";
Acquire::::Proxy "true";
```

#### /etc/environment
```bash
https_proxy="https://<username>:<password>@<proxy_ip>:<proxy_iport>/" 
http_proxy="http://<username>:<password>@<proxy_ip>:<proxy_iport>/"
ftp_proxy="ftp://<username>:<password>@<proxy_ip>:<proxy_iport>/"
socks_proxy="socks://<username>:<password>@<proxy_ip>:<proxy_iport>/"
```

#### /etc/wgetrc
```bash
proxy-user = <username>
proxy-password = <password>
http_proxy = http://<proxy_ip>:<proxy_iport>/
ftp_proxy = http://<proxy_ip>:<proxy_iport>/
use_proxy = on
```
#### /etc/bash.bashrc
```bash
export https_proxy="https://<username>:<password>@<proxy_ip>:<proxy_iport>/"
export http_proxy="https://<username>:<password>@<proxy_ip>:<proxy_iport>/"
export ftp_proxy="https://<username>:<password>@<proxy_ip>:<proxy_iport>/"
export socks_proxy="https://<username>:<password>@<proxy_ip>:<proxy_iport>/"
```

#### Proxy for docker:
```bash
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo vi /etc/systemd/system/docker.service.d/http-proxy.conf

# append text:
[Service]
Environment="HTTP_PROXY=http://myproxy.hostname:8080/"
Environment="HTTPS_PROXY=https://myproxy.hostname:8080/"
Environment="NO_PROXY=localhost,127.0.0.1,::1"

# restart docker
sudo systemctl daemon-reload
sudo systemctl restart docker.service
sudo systemctl show --property=Environment docker
```
## Units systemd (systemctl)
`/etc/systemd/system` - users units

`/usr/lib/systemd/system` - deb-packages

`/run/systemd/system` - runtime units


## Statistics
Processes:
```bash
top 
# or
htop
# or
atop
```

Disk:
```bash
iotop
# or
iostat
```

`df -hT` - show free disk space

`df -hTi` - show free disk inodes (metadata about files)

How to see the space occupied by the folder:
```bash
df -h ./<folder>
# or
du -hs ./<folder>
# or
echo size ./<folder>
```


## iptables
Read tutorials:
- [Iptables Tutorial](https://linuxhint.com/iptables-tutorial/)
- [iptables and connection tracking](http://rhd.ru/docs/manuals/enterprise/RHEL-4-Manual/security-guide/s1-firewall-state.html)
- [How to make iptables persistent after reboot on Linux](https://linuxconfig.org/how-to-make-iptables-rules-persistent-after-reboot-on-linux)

### Add rule
```bash
iptables -t <table> <command> <chain> [num] <condition> <action>
```
where
- \<table> - default ___filter___ (there are 4 tables in total)
- \<chain> - INPUT/OUTPUT/FORWARD
- \<action> - ACCEPT/REJECT/DROP

Example - enable ssh on specific port:
```bash
iptables -t filter -A INPUT 10 -s 10.10.10.0/255.255.255.0 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -P INPUT DROP
```

### Save changes
If you want to save your custom iptables rules you need `iptables-persistent` and `iptables-save`:
```bash
sudo apt install iptables-persistent
```

IPv4 and IPv6 rules in files `/etc/iptables/rules.v4` and `/etc/iptables/rules.v6`

To update persistent iptables with new rules:
```bash
sudo -i
sudo iptables-save > /etc/iptables/rules.v4
# or
$ sudo ip6tables-save > /etc/iptables/rules.v6
```


## File systems

### Classical approach
The classic approach involves working with __storage media__, __logical partitions__ and __file systems__.
```bash
# show info only about mounted file systems, including those that are not disk partitions
df -h
# show info about disks and partitions created on them, their sizes, mount point
lsblk

# crate file system on disk or logical partition
mkfs.<file_system_name> /dev/<disk>
# example
mkfs.ext4 /dev/sdb

# mount file system to folder каталог
mount /dev/<disk> </mount/point/path/to/folder>
# example
mount /dev/sdb /mmt/testfolder

# mount mount everything listed in /etc/fstab file
mount -a

# unmount file system
umount </mount/point/path/to/folder>

# show UUID of file systems
blkid

# resize existing file system
resize2fs /dev/<disk>
```

To automatically mount the file system when the OS boots, add the line to the `/etc/fstab`:
```
UUID=<UUID> /mount/point/path/to/folder/ ext4  defaults   0 0
```

### Logical partitions
Work with:
```bash
fdisk /dev/<disk>

# then in the fsdisk utility
n # create new partition
p # create new primary partition
# partition number and value first sector can be left as default
+<size>{K,M,G,T,P} # partition size in kilobytes, megabytes...
p # show created partitions
w # write changes to disk
d # delete partition
```
Next, you need to create a file system via `mkfs.<file_system_name> /dev/<disk>`, mount the directory and add it to `/etc/fstab` if necessary.

It is not possible to increase the size of the current partition just like that, since it is logical: it starts and ends on certain sectors of the physical medium, and it is the starting sector that is important, since increasing the size of the logical disk is associated with deleting the current logical disk and creating a larger volume on a new partition.

__Before increasing the logical partition, it is necessary to fill in the number of its first sector at the current moment in time.__

```bash
fdisk /dev/<disk>

d # delete partition that needs to be enlarged
# then create a new section using the algorithm above
# it is important that the enlarged partition starts from the same sector as the partition before it was enlarged and deleted
```

The partition size has been increased, but the file system has not actually increased the partition, since the OS operates with the file system size in blocks - this is reflected in the `/proc/partitions` file. This file cannot be changed even under _root_. Therefore, it is necessary to recalculate the partition table via `partprobe`. Then you can increase the FS itself via `resize2fs /dev/<disk>`.

If you create another logical partition on the same disk, problems will arise with increasing the first partition, since the second one starts right after it and increasing the first partition will climb onto the beginning of the second one. In this case, you need to backup the second partition, delete it, increase the first partition, create the second partition of the required partition anew, mount the directories. That is, you can only increase the last logical partition painlessly.
Usually, there is no reserve on the disk and when creating logical partitions, they are made larger than is actually required.

### RAID storage
Working with RAID storages without logical partitions on them:
```bash
# check the presence of disks (block devices) and their names
lsblk

# create a software RAID storage
mdadm --create /dev/<raid_name> --level <level> --raid-devices <disk_count> /dev/<disk_1> /dev/<disk_2>
# or
mdadm --create /dev/<raid_name> -l <level> -n <disk_count> /dev/<disk_1> /dev/<disk_2>

# example: creating RAID1 from 2 disks
mdadm --create /dev/md123 -l 1 -n 2 /dev/sdb /dev/sdc
```
The disk space is ready. Next, you need to format it for the required file system and mount the directory.

Increasing the RAID size:
1. Prepare disks with increased capacity
2. Remove one of the drives from the RAID storage
```bash
mdadm --manage /dev/<raid_name> --fail /dev/<old_disk_1> # mark the disk as bad
mdadm --manage /dev/<raid_name> --remove /dev/<old_disk_1> # remove the disk from the RAID storage
mdadm --manage /dev/<raid_name> --add /dev/<new_disk_1> # add a new disk with a larger capacity; the disk is prepared and the data on it is synchronized with other disks
```
3. Repeat steps 1-2 for the second disk in the storage
4. Increase the maximum size of disks in the storage (that is, we update/increase the size of the RAID storage)
```bash
mdadm --grow /dev/<raid_name> --size=max
```
5. Update the file system size to the new RAID storage size using `resize2fs /dev/<raid_name>`

When working with RAID storage with logical partitions, the procedure is similar, but initially you need to change the logical partitions, and then make changes to the storage media themselves.
In general, this creates additional problems, so for disks that are used only for data storage, it is best not to use logical partitions at all. That is, use the entire disk or RAID storage to store data.

### LVM
Up to this point, the example concerned the ligaments
- block device (RAID storage) - file system
- block device (RAID storage) - logical partition - file system

Now let's add a layer in the form of LVM. It consists of __physical volume__, __volume group__ and __logical volume__.

Read tutorials:
- [List of commands for working with LVM](https://hostadmina.ru/zametki/linux/lvm/spisok-komand-dlya-rabotyi-s-lvm.html)
- [How to work with LVM](https://www.dmosk.ru/instruktions.php?object=lvm)

```bash
pvcrate /dev/<disk>
vgcreate <volume_group_name> /dev/<disk>
lvcreate <volume_group_name> -n <logical_volume_name> -l <logical_volume_size>
```
Next, you need to format it for the required file system via `mkfs.ext4 /dev/mapper/<volume_group_name>-<logical_volume_name>` and mount the directory.

After this, you can expand any logical volume without taking into account its placement, order, etc.
```bash
# expand logical volume and immediately increase the size of the file system (flag -r)
lvextend /dev/mapper/<volume_group_name>-<logical_volume_name> -L +<size> -r
# or
lvextend /dev/mapper/<volume_group_name>-<logical_volume_name> -l +<percentage>%FREE -r
```

Show real allocation of LVM partitions on media:
```bash
pvs -a -o +lv_name -o +seg_size -o +seg_size_pe -o +seg_pe_ranges
```

Transferring a logical volume from one disk to a RAID storage:
1. Created RAID storage with status ___Degraded___
```bash
mdadm --create /dev/<raid_name> --level <level> --raid-devices <disk_count> /dev/<new_disk> missing
```
2. Add a RAID storage to volume group
```bash
vgextend <volume_group_name> /dev/<raid_name>
```
3. Move an existing disk from volume group to RAID storage
```bash
pvmove /dev/<existing_lvm_disk>
vgreduce <volume_group_name> /dev/<existing_lvm_disk>
pvremove /dev/<existing_lvm_disk>
mdadm --manage /dev/<raid_name> -add /dev/<existing_lvm_disk>

# проверить результат
mdadm -D /dev/<raid_name>
```


## Certificates
Install `openssl`:
```bash
sudo apt-get update
sudo apt-get install openssl
```

Extract _.crt_ and _.key_ files from _.pfx_ file:
1. Start OpenSSL from the _OpenSSL\bin_ folder
2. Open the command prompt and go to the folder that contains your _.pfx_ file
3. Run the following command to extract the private key:
```bash
openssl pkcs12 -in <yourfile.pfx> -nocerts -out <drlive.key>
```
You will be prompted to type the import password. Type the password that you used to protect your keypair when you created the .pfx file. You will be prompted again to provide a new password to protect the .key file that you are creating. Store the password to your key file in a secure place to avoid misuse.

4. Run the following command to extract the certificate:
```bash
openssl pkcs12 -in <yourfile.pfx> -clcerts -nokeys -out <drlive.crt>
```
5. Run the following command to decrypt the private key:
```bash
openssl rsa -in <drlive.key> -out <drlive-decrypted.key>
```
Type the password that you created to protect the private key file in the previous step.
The _.crt_ file and the decrypted and encrypted _.key_ files are available in the path, where you started OpenSSL.

### Convert _.pfx_ file to .pem format
There might be instances where you might have to convert the _.pfx_ file into _.pem_ format. Run the following command to convert it into PEM format.
```bash
openssl rsa -in <keyfile-encrypted.key> -outform PEM -out <keyfile-encrypted-pem.key>
```


## Troubleshooting
```bash
# checking free disk space
df -h
# checking directory size
du -sh <path_to_dir>
# inodes check
df -i
# checking disk status through smart reports
smartctl -a /dev/<disk>
# checking the software raid array
cat /proc/mdstat
# load on the disk subsystem
iostat
# processes working with the disk subsystem
iotop


# cpu - top / htop
# us - user processes, sy - system processes and system kernel, ni - operations with changed priority, id - idle, wa - i/o waiting (disk, user, network), hi - hardware interrupts, si - software interrupts, st - downtime due to the inability to allocate resources by the hypervisor

# RAM info
vmstat
# or
free -m
# or
cat /proc/meminfo

# show processes
ps aux
# kill process
kill <PID>
# debugging processes in real time
strace [ls] -p <PID>


# output of processes that listen on some ports
netstat -tunlp
# or
ss -lntu

# routing (~ ip route)
netstat -rn

# real-time tracing (~ traceroute)
mtr <dst_ip>

# dns lookup (~ nslookup)
dig @<dns_server_ip> <FQDN>
# request dns server record
dig -t [type] <FQDN>

# checking an open port on a remote server via the telnet protocol, but without using the telnet utility
curl -v telnet://<dst_ip>:<dst_port>
# requests to unix socket
curl --unix-socket <path_to_socket> <URL>


# user logins and privilege escalation
/var/log/auth.log
# messages from the system kernel
/var/log/kern.log
dmesg -T

# show srvice logs
journalctl -xeu <service_name>
```


## VMWare tools
### Install VMWare tools
```bash
sudo apt update
sudo apt install open-vm-tools open-vm-tools-desktop
```
### Enable shared folder
Enable shared folder in settings of VM and then:
```bash
sudo mkdir -p /mnt/hgfs
sudo mount -t fuse.vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other
```

On Windows open the directory in Explorer:
```
\\vmware-host\Shared Folders\<shared_folder_name>
```

### Auto-mounting shared folder:
Add the following line to `/etc/fstab`:
```
.host:/	/mnt/hgfs	fuse.vmhgfs-fuse	auto,allow_other	0	0
```
__Update:__ based on extensive testing, the _'auto'_ keyword seems to work fine. Prior versions suggested _'noauto'_. If you have trouble with _'auto'_, change to _'noauto'_ and see below


## Docker
### Docker auto installation
Project - https://github.com/docker/docker-install
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
DRY_RUN=1 sh ./get-docker.sh
```

### Docker installation
[Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

or

```bash
sudo apt-get update
sudo apt-get dist-upgrade

sudo apt-get install apt-transport-https ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

sudo touch /etc/apt/sources.list.d/docker.list
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" | sudo tee /etc/apt/sources.list.d/docker.list

sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

__If the installation fails, use [Install from a package](https://docs.docker.com/engine/install/ubuntu/#install-from-a-package)__

Tutorials:
- [Install docker on Ubuntu 20.04 (ru)](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-20-04-ru)
- [Install docker on Ubuntu 22.04](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-22-04)

### Run docker by nonroot user
Add current user to _docker_ group
```bash
sudo usermod -aG docker ${USER}
newgrp docker
```

Add user by username to _docker_ group
```bash
sudo usermod -aG docker <username>
newgrp docker
```

Check membership of _docker_ group
```bash
su - ${USER}
groups
`````

#### Example
Run docker for [Focalboard](https://www.focalboard.com/):
```bash
docker pull mattermost/focalboard
docker run -d -it -p 8000:8000 --name focalboard --restart=always mattermost/focalboard
```

### Image offline migration
```bash
docker save -o <path for generated tar file> <image name>
docker load -i <path to image tar file>
```


## Minikube
### Minikube installation
```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
sudo chmod +x /usr/local/bin/minikube
```

and check installation using `minikube version`

### kubectl installation
```bash
curl -LO https://dl.k8s.io/release/`curl -LS https://dl.k8s.io/release/stable.txt`/bin/linux/amd64/kubectl
chmod +x ./kubectl
sudo mv kubectl /usr/local/bin/
```
and check installation using `kubectl version -o yaml или kubectl version --client`


## PowerShell AD Commands
```powershell
# user search
Get-ADUser -Filter "Name -like '*<search>*'"
Get-ADUser -Filter "Name -like '*<search>*'" -Properties EmailAddress, DisplayName, SamAccountName | select EmailAddress, DisplayName, SamAccountName

# filter using
-Filter {(<attr> <operator> "*<search>*") <join_operator> (<attr> <operator> "*<search>*")}
Get-ADUser -Filter {Name -like "*<search>*"}
Get-ADUser -Filter {Name -like "*<search>*"} -Properties EmailAddress, DisplayName, SamAccountName | select EmailAddress, DisplayName, SamAccountName

Get-ADUser -Filter * -SearchBase "OU=<>,OU=<>,...,DC=<>" -Properties "LastLogonDate" | select name, LastLogonDate | sort LastLogonDate

Get-ADUser -Filter {Enabled -eq "false"} -SearchBase "OU=<>,OU=<>,...,DC=<>" -Properties "LastLogonDate" | select name, LastLogonDate | sort LastLogonDate

Get-ADUser -Filter {Enabled -eq "true"} -SearchBase "OU=<>,OU=<>,...,DC=<>" -Properties SamAccountName, Manager | select SamAccountName, Manager

Get-ADUser -Filter * -Properties EmailAddress, DisplayName, SamAccountName | select EmailAddress, DisplayName, SamAccountName, [Enabled|Disabled]

Get-ADUser -Identity <SamAccountName>

# PC search
Get-ADComputer -Identity "<CN>" -Properties *

Get-ADComputer -Filter "Name -like '*<search>*'" -Properties *
Get-ADComputer -Filter "Name -like '*<search>*'" -Properties Description

Get-ADComputer -Filter {Name -like "*<search>*"} -Properties *
Get-ADComputer -Filter {Name -like "*<search>*"} -Properties Description

Get-ADComputer -Filter {Description -like "*<search>*"} -Properties Description

# groups
Get-ADGroupMember -Identity <gr_name>
Get-ADGroup -Filter {Name -like "*<search>*"}
Get-ADGroup {-Identity <gr_name> | -Filter {Name -like "*<search>*"}} -Properties *
Get-ADGroup {-Identity <gr_name> | -Filter {Name -like "*<search>*"}} -Properties * | Get-Member
Get-ADGroupMember -Identity <gr_name> | Measure-Object | select count
(Get-ADGroup GR_devstorage_editors -Properties *).Members.Count
```

`gpupdate /force` - update group policies for a user and/or computer


### Networks
`nbtstat` - displays NetBIOS protocol statistics, NetBIOS name tables for local and remote computers, and the NetBIOS name cache

`ipconfig {/release | /release6}` - reset network ipv4/ipv6 parameters received via DHCP
`ipconfig {/renew | /renew6}` /renew - update the ipv4/ipv6 address for the specified adapter


## LDAP authentication
An example of setting up user authentication using ldap for the _wiki.js_ service. You must first configure a domain controller with the Active Directory Domain Services role.<br>
It is also necessary to allow self-registration of users and designate a group that will be assigned to them by default (preferably a group with the least number of privileges); then the user group can be changed. Otherwise, you will have to manually add users and only after that they will be able to log in to the system.

LDAP URL
```
ldap://<server_host_or_server_ip>:389
or
ldaps://<server_host_or_server_ip>:636
```
​
Admin Bind DN - The distinguished name (dn) of the account used for binding.
```
CN=<srv_account>,OU=...,...,DC=<local>,DC=<com>
```
​
Admin Bind Credentials - The password of the account used above for binding.
​
Search Base - The base DN from which to search for users.
```
DC=<local>,DC=<com>
```
​
Search Filter - The query to use to match username. {{username}} must be present and will be interpolated with the user provided username when performing the LDAP search.
```
(sAMAccountName={{username}})
or
(|(sAMAccountName={{username}})(userPrincipalName={{username}}))
or
(&(sAMAccountName={{username}})(memberOf=CN=<>,OU=...,..,DC=<local>,DC=<com>))
```
​
Configure TLS if necessary<br>
TLS Certificate Path - Absolute path to the TLS certificate on the server.

Unique ID Field Mapping - The field storing the user unique identifier. Usually "uid" or "sAMAccountName".
```
sAMAccountName
```
​
Email Field Mapping - The field storing the user email. Usually "mail".
```
userPrincipalName
```
​
Display Name Field Mapping - The field storing the user display name. Usually "displayName" or "cn".
```
displayName
```
​
Avatar Picture Field Mapping
```
jpegPhoto
```

Map Groups if necessary<br>
Map groups matching names from the users LDAP/Active Directory groups. Group Search Base must also be defined for this to work. Note this will remove any groups the user has that doesn't match an LDAP/Active Directory group.<br>
Group Search Base - The base DN from which to search for groups.<br>
​Group Search Filter - LDAP search filter for groups. (member={{dn}}) will use the distinguished name of the user and will work in most cases.<br>
​Group Search Scope - How far from the Group Search Base to search for groups. sub (default) will search the entire subtree. base, will only search the Group Search Base dn. one, will search the Group Search Base dn and one additional level.<br>
​Group DN Property - The property of user object to use in {{dn}} interpolation of Group Search Filter.
​Group Name Field - The field that contains the name of the LDAP group to match on, usually "name" or "cn".

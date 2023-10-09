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
- [Certificates](#certificates)
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


## Links
- [GIT CHEAT SHEET](https://education.github.com/git-cheat-sheet-education.pdf)
- [khazeamo/linux-cheatsheet.md](https://gist.github.com/khazeamo/f762f532bfbc17d5bf396e9d4c2a9586)
- [RehanSaeed/Bash-Cheat-Sheet](https://github.com/RehanSaeed/Bash-Cheat-Sheet#command-history)
- [sudheerj/Linux-cheat-shee](https://github.com/sudheerj/Linux-cheat-sheet)
- [Linux Command Line](https://cheatography.com/davechild/cheat-sheets/linux-command-line/)
- [Linux Commands](https://www.pcwdld.com/linux-commands-cheat-sheet)


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
```
iptables -t <table> <command> <chain> [num] <condition> <action>
```
where
- \<table> - default ___filter___ (there are 4 tables in total)
- \<chain> - INPUT/OUTPUT/FORWARD
- \<action> - ACCEPT/REJECT/DROP

Example - enable ssh on specific port:
```
iptables -t filter -A INPUT 10 -s 10.10.10.0/255.255.255.0 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -P INPUT DROP
```

### Save changes
If you want to save your custom iptables rules you need `iptables-persistent` and `iptables-save`:
```
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


## Certificates
Install `openssl`:
```
sudo apt-get update
sudo apt-get install openssl
```

Extract _.crt_ and _.key_ files from _.pfx_ file:
1. Start OpenSSL from the _OpenSSL\bin_ folder
2. Open the command prompt and go to the folder that contains your _.pfx_ file
3. Run the following command to extract the private key:
```
openssl pkcs12 -in <yourfile.pfx> -nocerts -out <drlive.key>
```
You will be prompted to type the import password. Type the password that you used to protect your keypair when you created the .pfx file. You will be prompted again to provide a new password to protect the .key file that you are creating. Store the password to your key file in a secure place to avoid misuse.

4. Run the following command to extract the certificate:
```
openssl pkcs12 -in <yourfile.pfx> -clcerts -nokeys -out <drlive.crt>
```
5. Run the following command to decrypt the private key:
```
openssl rsa -in <drlive.key> -out <drlive-decrypted.key>
```
Type the password that you created to protect the private key file in the previous step.
The _.crt_ file and the decrypted and encrypted _.key_ files are available in the path, where you started OpenSSL.

### Convert _.pfx_ file to .pem format
There might be instances where you might have to convert the _.pfx_ file into _.pem_ format. Run the following command to convert it into PEM format.
```
openssl rsa -in <keyfile-encrypted.key> -outform PEM -out <keyfile-encrypted-pem.key>
```


## VMWare tools
### Install VMWare tools
```
sudo apt update
sudo apt install open-vm-tools open-vm-tools-desktop
```
### Enable shared folder
Enable shared folder in settings of VM and then:
```
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
```
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

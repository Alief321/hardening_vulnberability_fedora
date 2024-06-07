# hardening_vulnberability_fedora

## Make container

```markdown
toolbox create f35-base
toolbox enter f35-base
toolbox list
```

## Securing Accounts and Authentication

### Accounts

make a group

```
groups alief wheel
```

```
groups
```

```
sudo visudo
```

![alt text](VirtualBox_fedora_06_06_2024_21_39_50.png)

add user

```
sudo useradd -G wheel himawan
```

Give sudo permission to account

```
sudo visudo
```

give sudo privileges to user

```
alief ALL=(ALL:ALL) ALL
```

check it

```
su -alief
sudo whoami
```

disable root account

```
sudo passwd -l root
```

check list user account

```
awk -F':' '{ print $1}' /etc/passwd
```

to delete user

```
sudo userdel -r username
```

### Password Policies

```
sudo nano /etc/pam.d/common-password
```

add it

```
password requisite pam_pwquality.so retry=5 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
```

```
sudo pwck
```

### configure password hashing

```
sudo nano /etc/login.defs
```

```
ENCRYPT_METHOD SHA512
```

add it in `/etc/pam.d/system-auth` and `/etc/pam.d/password-auth`

```
password required pam_pwquality.so retry=3
password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok
```

### Configure Minimum and Maximum Password Age

`add in /etc/login.defs`

```
PASS_MIN_DAYS 7
PASS_MAX_DAYS 90
PASS MIN_LEN 12
PASS_WARN_AGE   14
```

```
UMASK 027
```

### Lockout Policy

```
sudo nano /etc/pam.d/common-auth
```

add it

```
auth required pam_tally2.so deny=5 unlock_time=900
```

### Iddle session

edit bash configuration on `/etc/profile` and `/etc/bashrc` `/etc/csh.cshrc`

```
TMOUT=600
readonly TMOUT
export TMOUT
```

## Services

### Disable Unnecessary Services

check hardening system services

```
for service in $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'); do
    systemd-analyze security $service;
done
```

check all running services

```
systemctl --type=service --state=running
```

check spesific service

```
sudo systemd-analyze security sshd
```

stop avahi daemon`

```
sudo systemctl stop avahi-daemon.service
sudo systemctl disable avahi-daemon.service
```

### Secure Necessary Services (SSH)

misal ssh

```
sudo nano /etc/ssh/sshd_config
```

add this line

```
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
AllowUsers alief
```

restart

```
sudo systemctl restart sshd
```

### Limit Capabilities:

```
sudo systemctl edit NetworkManager.service
```

tambahkan line ini

```
[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
```

### Restrict File System Access:

```
sudo systemctl edit NetworkManager.service
```

```
[Service]
ProtectSystem=full
ProtectHome=yes
```

### Reload and Restart the Service:

```
sudo systemctl daemon-reload
sudo systemctl restart NetworkManager.service
```

## Network

### check DNS

```
cat /etc/resolv.conf
```

### Add IP name and FQDN to /etc/hosts

```
sudo nano /etc/hosts
```

```
127.0.0.1   localhost
::1         localhost
{IP linux} myhostname myhostname.mydomain
```

### Disable Unnecessary Protocols

```
sudo nano /etc/modprobe.d/blacklist.conf
```

```
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
```

### Firewall configuration

```markdown
sudo systemctl enable firewalld
sudo systemctl start firewalld
sudo firewall-cmd --add-service=ssh --permanent
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### Disable IPV6

```
sudo nano /etc/sysctl.conf
```

```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

```
sudo sysctl -p
```

### Enable systat

```
sudo rpm-ostree install sysstat
sudo systemctl enable --now sysstat
```

### Configure auditd

```
sudo rpm-ostree install audit
sudo systemctl enable --now auditd
```

```
sudo nano /etc/audit/auditd.conf
```

ADD IT

```
max_log_file = 50
max_log_file_action = KEEP_LOGS
space_left_action = SYSLOG
admin_space_left_action = SYSLOG
```

RESTART

```
sudo systemctl restart auditd
```

OR

```
sudo systemctl disable  auditd
sudo systemctl enable --now  auditd
```

## Logging & Auditing

### Check logging

```
sudo rpm-ostree install rsyslog
sudo systemctl reboot

sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

### Configure Log Rotation

```
sudo nano /etc/logrotate.conf

```

```
/var/log/wtmp {
    monthly
    create 0664 root utmp
    minsize 1M
    rotate 1
}

/var/log/messages {
    rotate 4
    weekly
    postrotate
        /usr/bin/systemctl reload rsyslog > /dev/null 2>/dev/null || true
    endscript
}
```

### Check deleted file in Use

```
sudo lsof | grep deleted
```

### Add Legal Banner to /etc/issue and /etc/issue.net

```
echo "Authorized users only. All activity may be monitored and reported." | sudo tee /etc/issue
echo "Authorized users only. All activity may be monitored and reported." | sudo tee /etc/issue.net
```

## File Permission and integrity

### Edit /etc/fstab

```
sudo nano /etc/fstab
```

add it

```
tmpfs   /tmp    tmpfs   defaults,noexec,nosuid,nodev    0 0
/dev/sda1  /var   ext4    defaults,noexec,nosuid,nodev    0 0
```

### Remount file system

```
sudo mount -o remount /tmp
sudo mount -o remount /var
```

### Check Symlinked Mount Points

```
ls -l /home
```

### Set Appropriate File Permissions:

```
sudo chmod 600 /etc/ssh/sshd_config
sudo chown root:root /etc/ssh/sshd_config
```

### configure aide

```
sudo rpm-ostree install aide
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

```
sudo crontab -e
```

### disable unwanted file system

add file `/etc/modprobe.d/blacklist-filesystems.conf` and add this line

```
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
```

### Kernel Hardening

```
rpm-ostree upgrade
```

```
sudo nano /etc/sysctl.conf
```

```
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable packet redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

```

## USB and Storage Drivers

```
sudo nano /etc/modprobe.d/blacklist.conf
```

```
blacklist usb_storage
blacklist firewire_ohci
```

## Check and Tweak Sysctl Values

```
sudo nano /etc/sysctl.conf
```

add this line

```
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
```

```
sudo sysctl -p
```

### Malware Scanner

```
sudo rpm-ostree install rkhunter
sudo rkhunter --update
sudo rkhunter --checkall
```

### SELINUX

make sure selinux in enforcing

```
sudo setenforce 1
sudo nano /etc/selinux/config
```

## Check For Unattended Upgrades

```
sudo rpm-ostree install dnf-automatic
```

edit `/etc/dnf/automatic.conf`

```
[commands]
upgrade_type = default
random_sleep = 360

[emitters]
system_name = yes
emit_via = motd

[base]
debuglevel = 1
mdpolicy = group:main

[download]
check_only = yes
download_updates = yes
```

## Run Audit Security using Lynis

```
 cd lynis && ./lynis audit system
```

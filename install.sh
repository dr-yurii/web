#!/bin/bash
#installation of opencanary to Ubuntu 20.04
#checking google resolvers
R_TOK="Z2hwX3BWQzA2bFFtRFZiNmRMMHVKcnNjYWVYbHkxT0F2MzFseXJUZkA="
READ_TOKEN=$(echo $R_TOK | base64 --decode)
if [[ ! $(grep -e "^nameserver 8.8.8.8" /etc/resolv.conf) && ! $(grep -e "^nameserver 8.8.4.4" /etc/resolv.conf) ]]; then
        if [[ ! $(grep -e "^nameserver 8.8.8.8" /etc/resolv.conf) ]]; then
        echo "nameserver 8.8.8.8" >>/etc/resolv.conf
        fi
        if [[ ! $(grep -e "^nameserver 8.8.4.4" /etc/resolv.conf) ]]; then
        echo "nameserver 8.8.4.4" >>/etc/resolv.conf
        fi
else
                echo "google resolvers exists"
fi
#update and upgrade OS packets
DEBIAN_FRONTEND=noninteractive apt update -y 2>/dev/null | grep packages | cut -d '.' -f 1 && DEBIAN_FRONTEND=noninteractive apt upgrade -y 2>/dev/null | grep upgraded | cut -d '.' -f 1 &
wait $!
echo "Upgrade finished, Exit status: $?"
#installing tools
apt install git net-tools sudo vim nano wget iptables rsyslog psmisc resolvconf mawk netplan.io curl cron netcat locales -y 2>/dev/null | grep upgraded | cut -d '.' -f 1 &
wait $!
echo "Tools installation finished, Exit status: $?"
#self-updation of script
sync; echo 1 > /proc/sys/vm/drop_caches && sync; echo 2 > /proc/sys/vm/drop_caches && sync; echo 3 > /proc/sys/vm/drop_caches
string_to_int() {
  local _convert
  _convert="${1:?No version number supplied}"
  _convert="${_convert//[^0-9.]/}"
  set -- ${_convert//./ }
  printf -- '%d%02d%02d' "${1}" "${2:-0}" "${3:-0}"
}
VERSION="4.3.6"
GIT_URL=https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/install.sh
SCRIPT_LOCATION="${BASH_SOURCE[@]}"
ABS_SCRIPT_PATH=$(readlink -f "$SCRIPT_LOCATION")
TMP_FILE=$(mktemp -p "" "XXXXX.sh")
curl -s -L "$GIT_URL" > "$TMP_FILE"
NEW_VERSION=$(grep "^VERSION" "$TMP_FILE" | awk -F'[="]' '{print $3}')
if [[ "$(string_to_int $VERSION)" < "$(string_to_int $NEW_VERSION)" ]]; then
    printf "Updating "$ABS_SCRIPT_PATH" script \e[31;1m%s\e[0m -> \e[32;1m%s\e[0m\n" "$VERSION" "$NEW_VERSION"
    cp -f "$TMP_FILE" "$ABS_SCRIPT_PATH" || printf "Unable to update the script\n"
else
     printf "Already the latest version.\n"
fi
rm -f /tmp/*.sh
#installing and checking resolvconf service
if [[ $(systemctl is-enabled resolvconf) != "enabled" ]]; then
                systemctl enable resolvconf
                echo "resolvconf was enabled"
        else
                echo "resolvconf is already enabled"
        fi
        if [[ $(systemctl is-active resolvconf) != "active" ]]; then
                systemctl start resolvconf.service
                echo "resolvconf was started, Exit status: $?"
        else
                echo "resolvconf is already active"
        fi
if [[ ! $(grep -e "^nameserver 8.8.8.8" /etc/resolvconf/resolv.conf.d/head) && ! $(grep -e "^nameserver 8.8.4.4" /etc/resolvconf/resolv.conf.d/head) && ! $(grep -e "^nameserver 1.1.1.1" /etc/resolvconf/resolv.conf.d/head) ]]; then
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n" >> /etc/resolvconf/resolv.conf.d/head
systemctl restart resolvconf.service
systemctl restart systemd-resolved.service
echo "/etc/resolvconf/resolv.conf.d/head was updated"
fi
if [ $(id -u) -eq 0 ]; then
        if [[ $(grep -e "^glsh" /etc/passwd) ]]; then
                echo "user glsh exists!"
        else
                adduser --disabled-password --gecos "" glsh >/dev/null
                usermod -aG sudo glsh >/dev/null
                echo "User glsh added, Exit status: $?"
                if [[ $(grep -e "^glsh" /etc/sudoers) ]]; then
                        echo "user glsh already is sudouser"
                else
                        echo "glsh ALL=(ALL:ALL) NOPASSWD: ALL" >>/etc/sudoers
                fi
        fi
else
        echo "Only root may add a user to the system. Installation was stopped"
        exit 1
fi
#checking ssh port and configurations of ssh service
if [[ $(grep -e "^Port 65221" /etc/ssh/sshd_config) && $(grep -e "^PermitRootLogin yes" /etc/ssh/sshd_config) && $(netstat -ntplau | grep ssh | grep :65221) && $(grep -e "^PasswordAuthentication no" /etc/ssh/sshd_config) ]]; then
        echo "SSH port is 65221 and RootLogin already enabled"
else
        curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/configs/sshd_config -o /etc/ssh/sshd_config    
        systemctl restart ssh
                echo "SSH configurations was updated, service was restarted"
fi
if [[ -f /root/.ssh/authorized_keys && $(grep "T8X5OF6kNv7Q9pz1CFFnppUYT" /root/.ssh/authorized_keys) ]]; then
echo "authorized key exists"
else
if [ ! -d /root/.ssh ]; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
fi
        curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/configs/authorized_keys -o /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
		echo "authorized key was updated"
fi
if [[ $(systemctl is-enabled ssh) != "enabled" ]]; then
        systemctl enable ssh
        echo "ssh was enabled"
else
        echo "ssh is already enabled"
fi
#installing Python
apt install python3-dev python3-pip python3-virtualenv python3-venv python3-scapy libssl-dev libpcap-dev libffi-dev build-essential redis-server python python-dev virtualenv -y 2>/dev/null | grep upgraded | cut -d '.' -f 1 &
wait $!
#checking if python installed correctly
python2 --version >/dev/null
if [ $? != 0 ]; then
        echo "Python2 isn't available, please check if Python2 was installed, Exit status: $?"
        exit 1
fi
python3 --version >/dev/null
if [ $? != 0 ]; then
        echo "Python3 isn't available, please check if Python3 was installed, Exit status: $?"
        exit 1
fi
#requirments for Debian 10
if [[ $(cat /etc/*release | grep -i buster) ]]; then
if [[ $(pip3 list | grep 0.32.3) && $(pip3 list | grep 45.2.0) && $(pip3 list | grep 20.0.17) ]]; then
echo "pip3 requirments are already installed for Debian 10"
else
pip3 install wheel==0.32.3 >/dev/null
pip3 install setuptools==45.2.0 >/dev/null
pip3 install virtualenv==20.0.17 >/dev/null
fi
fi
#installing opencanary to user glsh
if [ ! -d /home/glsh/env ]; then
sudo -i -u glsh bash <<EOF
cd ~
virtualenv -p /usr/bin/python3 env
. env/bin/activate
pip install opencanary >/dev/null
pip install scapy pcapy >/dev/null
pip install MarkupSafe==2.0.1 >/dev/null
opencanaryd --copyconfig
pip list | grep -e opencanary -e scapy -e pcapy -e MarkupSafe -e setuptools
EOF
echo "Opencanary installation finished, Exit status: $?"
else
        echo "Directory /home/glsh/env exists, opencanary may be already installed"
fi
#installing and checking opencanary correlator work
MAIL_PA="cXhjY2x0eGdhcWtmZnJubA=="
MAIL_P=$(echo $MAIL_PA | base64 --decode)
if [ ! -d /home/glsh/envc ]; then
sudo -i -u glsh bash <<EOF
cd ~
virtualenv -p /usr/bin/python2 envc
. envc/bin/activate
pip install opencanary-correlator >/dev/null
curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/configs/opencanary_correlator.conf -o /home/glsh/opencanary_correlator.conf
sed -i "s/password/$MAIL_P/g" /home/glsh/opencanary_correlator.conf
opencanary-correlator --config=/home/glsh/opencanary_correlator.conf &
EOF
echo "opencanary-correlator installation finished, Exit status: $?"
else
echo "Directory /home/glsh/envc exist, checking opencanary-correlator work"
if [[ ! $(grep -e "kffrnl" /home/glsh/opencanary_correlator.conf ) ]]; then
ps auxfS | grep -v grep | grep opencanary-correlator | awk '{print $2}' | xargs kill -9
curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/configs/opencanary_correlator.conf -o /home/glsh/opencanary_correlator.conf
chown glsh:glsh /home/glsh/opencanary_correlator.conf
sed -i "s/password/$MAIL_P/g" /home/glsh/opencanary_correlator.conf
echo "/home/glsh/opencanary_correlator.conf was updated"
fi
if [[ $(ps -aux | grep -v grep | grep opencanary-correlator) ]]; then
echo "opencanary-correlator process is exist"
else
sudo -i -u glsh bash <<EOF
cd ~
virtualenv -p /usr/bin/python2 envc
. envc/bin/activate
opencanary-correlator --config=/home/glsh/opencanary_correlator.conf &
EOF
echo "/home/glsh/opencanary_correlator.conf was started"
fi
fi
#installing canary_log_forwarder
if [[ ! $(ps -aux | grep -v grep | grep canary_log_forwarder.py) ]]; then
       if [ ! -f /home/glsh/canary_log_forwarder.py ]; then
        curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/other/canary_log_forwarder.py -o /home/glsh/canary_log_forwarder.py
        chown glsh:glsh /home/glsh/canary_log_forwarder.py
        else
        echo "/home/glsh/canary_log_forwarder.py is exist"
       fi
sudo -i -u glsh bash <<EOF
cd ~
virtualenv -p /usr/bin/python3 env
. env/bin/activate
/home/glsh/env/bin/python3 /home/glsh/canary_log_forwarder.py &
EOF
echo "/home/glsh/canary_log_forwarder.py was started"
else
echo "/home/glsh/canary_log_forwarder.py process is exist"
fi
#checking redis server
        if [[ $(systemctl is-enabled redis) != "enabled" ]]; then
                systemctl enable redis
                echo "redis was enabled"
        else
                echo "redis is already enabled"
        fi
        if [[ $(systemctl is-active redis) != "active" ]]; then
                systemctl start redis.service
                echo "redis was started, Exit status: $?"
        else
                echo "redis is already active"
        fi
#checking cron service
        if [[ $(systemctl is-enabled cron) != "enabled" ]]; then
                systemctl enable cron
                echo "cron was enabled"
        else
                echo "cron is already enabled"
        fi
        if [[ $(systemctl is-active cron) != "active" ]]; then
                systemctl start cron.service
                echo "cron was started, Exit status: $?"
        else
                echo "cron is already active"
        fi
#checking configurations and opencanary service status
if [[ -f /etc/opencanaryd/opencanary.conf && $(grep -e "1514" /etc/opencanaryd/opencanary.conf) ]]; then
        echo "/etc/opencanaryd/opencanary.conf exists"
else
        mv -f /etc/opencanaryd/opencanary.conf /etc/opencanaryd/opencanary.conf_old
        curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/configs/opencanary.conf -o /etc/opencanaryd/opencanary.conf
        systemctl restart opencanary
        echo "/etc/opencanaryd/opencanary.conf was updated"
fi
if [ ! -f /etc/systemd/system/opencanary.service ]; then
        curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/configs/opencanary.service -o /etc/systemd/system/opencanary.service
        systemctl enable opencanary
        systemctl start opencanary.service
        echo "opencanary service was enabled and started, Exit status: $?"
else
        if [[ $(systemctl is-enabled opencanary) != "enabled" ]]; then
                systemctl enable opencanary
                echo "opencanary was enabled"
        else
                echo "opencanary is already enabled"
        fi
        if [[ $(systemctl is-active opencanary) != "active" ]]; then
if [ -f /home/glsh/env/bin/opencanaryd.pid ]; then
rm -f /home/glsh/env/bin/opencanaryd.pid
fi
                systemctl start opencanary.service
                echo "opencanary was started, Exit status: $?"
        else
                echo "opencanary is already active"
        fi
fi
if [[ $(systemctl is-active opencanary) != "active" ]]; then
        echo "Opencanary wasn't started correctly, Script was stopped, please check status of service opencanary, Exit status: $?"
        exit 1
fi
#installing Samba
DEBIAN_FRONTEND=noninteractive apt install samba -y 2>/dev/null | grep upgraded | cut -d '.' -f 1 &
wait $!
samba --version >/dev/null
if [ $? != 0 ]; then
        echo "Samba wasn't installed, please check status of service samba, Exit status: $?"
else
        echo "Samba $(samba --version) already installed"
fi
#creating Samba test files
if [ ! -d /home/glsh/samba ]; then
        mkdir /home/glsh/samba
        touch /home/glsh/samba/testing.txt
        chown -R glsh:glsh /home/glsh/samba
else
        echo "Directory /home/glsh/samba exists"
fi
#checking samba configurations and service status
if [[ -f /etc/samba/smb.conf && $(grep -e "server string = NBDocs" /etc/samba/smb.conf) ]]; then
        echo "/etc/samba/smb.conf exists"
        if [[ $(systemctl is-active smbd) != "active" ]]; then
                systemctl start smbd.service
                echo "smbd was started, Exit status: $?"
        else
                echo "smbd is already active"
        fi
        if [[ $(systemctl is-active nmbd) != "active" ]]; then
                systemctl start nmbd.service
                echo "nmbd was started, Exit status: $?"
        else
                echo "nmbd is already active"
        fi
else
        mv -f /etc/samba/smb.conf /etc/samba/smb.conf_old
        curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/configs/samba.conf -o /etc/samba/smb.conf
        echo "/etc/samba/smb.conf was updated"
        smbcontrol all reload-config
        systemctl restart smbd
        systemctl restart nmbd
fi
#checking rsyslog and syslog status and configurations
if [[ -f /etc/rsyslog.conf && ! -f /etc/rsyslog.d/50-default.conf ]]; then
        if [[ $(grep -e "^local7" /etc/rsyslog.conf) ]]; then
                echo "record in /etc/rsyslog.conf exists"
                if [[ $(systemctl is-active rsyslog) != "active" ]]; then
                        systemctl start rsyslog.service
                        echo "rsyslog was started, Exit status: $?"
                else
                        echo "rsyslog is already active"
                fi
                if [[ $(systemctl is-active syslog) != "active" ]]; then
                        systemctl start syslog.service
                        echo "syslog was started, Exit status: $?"
                else
                        echo "syslog is already active"
                fi
        else
                echo "local7.*  /var/log/samba-audit.log" >>/etc/rsyslog.conf
                echo "record was added to /etc/rsyslog.conf"
                systemctl restart rsyslog
                systemctl restart syslog
        fi
else
        echo "/etc/rsyslog.d/50-default.conf exist"
fi
if [[ -f /etc/rsyslog.conf && -f /etc/rsyslog.d/50-default.conf ]]; then
        if [[ $(grep -e "^local7" /etc/rsyslog.d/50-default.conf) || $(grep -e "^local7" /etc/rsyslog.conf) ]]; then
                echo "record in /etc/rsyslog.conf or /etc/rsyslog.d/50-default.conf exists"
        else
                mv -f /etc/rsyslog.d/50-default.conf /etc/rsyslog.d/50-default.conf_old
                curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/configs/50-default.conf -o /etc/rsyslog.d/50-default.conf
                echo "/etc/rsyslog.d/50-default.conf was updated"
                systemctl restart rsyslog
                systemctl restart syslog
        fi
fi
#checking samba audit logs
if [ ! -f /var/log/samba-audit.log ]; then
        touch /var/log/samba-audit.log
else
        echo "/var/log/samba-audit.log exists"
fi
chown --reference=/var/log/syslog /var/log/samba-audit.log
#update opencanary from https://github.com/msphoneypot/msphp
GIT_CANARY=https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/opencanary/__init__.py
LOCAL_CANARY=$(ls /home/glsh/env/lib/python*/site-packages/opencanary/__init__.py)
TMP_FILE=$(mktemp -p "" "XXXXX.py")
curl -s -L "$GIT_CANARY" > "$TMP_FILE"
GIT_VERS=$(grep "^__" "$TMP_FILE" | awk -F'[="]' '{print $3}')
LOC_VERS=$(grep "^__" "$LOCAL_CANARY" | awk -F'[="]' '{print $3}')
if [[ "$(string_to_int $LOC_VERS)" < "$(string_to_int $GIT_VERS)" ]]; then
printf "Updating OpenCanary \e[31;1m%s\e[0m -> \e[32;1m%s\e[0m\n" "$LOC_VERS" "$GIT_VERS"
cd ~
rm -rf ~/msphp
git clone https://"$READ_TOKEN"github.com/msphoneypot/msphp.git
rm -rf /home/glsh/env/lib/python*/site-packages/opencanary
cp -a ~/msphp/opencanary /home/glsh/env/lib/python*/site-packages
chown -R glsh:glsh /home/glsh/env/lib/python*/site-packages/opencanary
rm -rf ~/msphp
systemctl restart opencanary
else
     printf "OpenCanary is already the latest version.\n"
fi
#update opencanary_correlator from https://github.com/msphoneypot/msphp
GIT_CANARY_C=https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/opencanary_correlator/__init__.py
LOCAL_CANARY_C=$(ls /home/glsh/envc/lib/python*/site-packages/opencanary_correlator/__init__.py)
TMP_FILE_C=$(mktemp -p "" "XXXXX.py")
curl -s -L "$GIT_CANARY_C" > "$TMP_FILE_C"
GIT_VERS_C=$(grep "^__" "$TMP_FILE_C" | awk -F'[="]' '{print $3}')
LOC_VERS_C=$(grep "^__" "$LOCAL_CANARY_C" | awk -F'[="]' '{print $3}')
if [[ "$(string_to_int $LOC_VERS_C)" < "$(string_to_int $GIT_VERS_C)" ]]; then
printf "Updating OpenCanary Correlator \e[31;1m%s\e[0m -> \e[32;1m%s\e[0m\n" "$LOC_VERS_C" "$GIT_VERS_C"
cd ~
rm -rf ~/msphp
git clone https://"$READ_TOKEN"github.com/msphoneypot/msphp.git
rm -rf /home/glsh/envc/lib/python*/site-packages/opencanary_correlator
cp -a ~/msphp/opencanary_correlator /home/glsh/envc/lib/python*/site-packages
chown -R glsh:glsh /home/glsh/envc/lib/python*/site-packages/opencanary_correlator
rm -rf ~/msphp
ps auxfS | grep -v grep | grep opencanary-correlator | awk '{print $2}' | xargs kill -9
sudo -i -u glsh bash <<EOF
cd ~
virtualenv -p /usr/bin/python2 envc
. envc/bin/activate
opencanary-correlator --config=/home/glsh/opencanary_correlator.conf &
EOF
echo "/home/glsh/opencanary_correlator.conf was started"
else
     printf "OpenCanary Correlator is already the latest version.\n"
fi
rm -f /tmp/*.py 
#changing hostname to random
function change_hostname() {
FirstW=("office" "suite" "floor" "hall" "cube" "desk" "head" "place" "room" "center" "main" "firm" "company")
SecondW=("comp" "system" "desktop" "server" "host" "network" "portal" "pc" "master" "linux")
RandA=$(( RANDOM % 13 ))
RandB=$(( RANDOM % 9 ))
NewHostName=${FirstW[$RandA]}${SecondW[$RandB]}
echo "hostname changed to $NewHostName"
hostnamectl set-hostname $NewHostName
sed -i '/127.0.0.1/d' /etc/hosts
echo "127.0.0.1 $NewHostName localhost" >>/etc/hosts
}
if [[ ! $(grep "office\|suite\|floor\|hall\|cube\|desk\|head\|place\|room\|center\|main\|firm\|company" /etc/hostname) ]] ; then
change_hostname
else
echo "hostname already changed"
fi
#add crontab rules
if [[ ! $(crontab -l | grep -e "*/5*\s\*\s\*\s\*\s\*\s/usr/bin/bash\s/root/check_updates.sh") ]] ; then
(crontab -l 2>/dev/null || true; echo "*/5 * * * * /usr/bin/bash /root/check_updates.sh >/dev/null 2>&1") | crontab -
systemctl restart cron
echo "crontab check_updates rule was added"
fi
if [[ ! $(crontab -l | grep -e "^0\s\*\s\*\s\*\s\*\s/usr/bin/bash\s/root/install.sh") ]] ; then
(crontab -l 2>/dev/null || true; echo "0 * * * * /usr/bin/bash /root/install.sh >/dev/null 2>&1") | crontab -
systemctl restart cron
echo "crontab 1h rule was added"
fi
if [[ ! $(crontab -l | grep "^@reboot /usr/bin/bash /root/install.sh") ]] ; then
(crontab -l 2>/dev/null || true; echo "@reboot /usr/bin/bash /root/install.sh >/dev/null 2>&1") | crontab -
systemctl restart cron
echo "crontab reboot rule was added"
fi
if [[ ! -f /root/check_updates.sh || ! $(grep -e "base64" /root/check_updates.sh) ]]; then
curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/check_updates.sh -o /root/check_updates.sh
chmod +x /root/check_updates.sh
echo "/root/check_updates.sh was updated"
fi
#changing mac address to random 90:09:D0:XX:XX:XX
m_interface=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
m_mac=$(echo '90:09:d0'$(od -An -N3 -txC /dev/random) | sed -e 's/ /:/g')
if [[ ! $(cat /sys/class/net/$m_interface/address | grep -i 90:09:D0:) ]] ; then
rm -rf /etc/netplan/*
cat > /etc/netplan/00-installer-config.yaml <<EOF
# This is the network config of netplan
network:
    version: 2
    renderer: networkd
    ethernets:
        $m_interface:
            dhcp4: yes
            macaddress: $m_mac
EOF
netplan apply
systemctl start NetworkManager.service >/dev/null
systemctl restart NetworkManager.service >/dev/null
echo "OS will be rebooted. Installation will be finished after reboot."
reboot
fi
mac1=$(cat /sys/class/net/$m_interface/address)
mac2=$(cat /etc/netplan/00-installer-config.yaml | grep macaddress |  awk '{print $2}')
if [[ $mac1 != $mac2 ]] ; then
netplan apply
echo "OS will be rebooted. Installation will be finished after reboot."
reboot
else
        if [[ -f /etc/opencanaryd/opencanary.conf && $(ifconfig $m_interface | grep $mac2 ) ]] ; then
        if [[ ! $(grep -i "90:09:d0:" /etc/opencanaryd/opencanary.conf) ]] ; then
        echo '$mac1' | sed -i "s/opencanary-1/$mac1/g" /etc/opencanaryd/opencanary.conf
        systemctl restart opencanary
        echo "node_id in /etc/opencanaryd/opencanary.conf was changed to $mac1"
else
        echo "node_id in /etc/opencanaryd/opencanary.conf already changed to 90:09:d0:XX:XX:XX"
        fi
        fi
fi
#fix for Debian10
if [[ $(cat /etc/*release | grep -i buster) ]]; then
if [[ -L /etc/systemd/network/99-default.link || -f /etc/systemd/network/99-default.link ]]; then
rm -f /etc/systemd/network/99-default.link
netplan apply
systemctl restart systemd-networkd
fi
fi
#disabling ipv6
function disable_ipv6() {
if [[ $(grep -e "^net.ipv6.conf.all.disable_ipv6" /etc/sysctl.conf) && $(grep -e "^net.ipv6.conf.default.disable_ipv6" /etc/sysctl.conf) && $(grep -e "^net.ipv6.conf.lo.disable_ipv6" /etc/sysctl.conf) && $(grep -e "^net.ipv6.conf.$m_interface.disable_ipv6" /etc/sysctl.conf) ]]; then
    echo "ipv6 already disabled"
    /usr/sbin/sysctl -p /etc/sysctl.conf >/dev/null
else
        echo -e "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1 \nnet.ipv6.conf.$m_interface.disable_ipv6 = 1" >>/etc/sysctl.conf
        sysctl -p >/dev/null
        echo "ipv6 was disabled"
fi
}
if [[ -n $m_interface && $(ip a | grep inet6) ]]; then
disable_ipv6
else
echo "ipv6 already disabled"
fi
#changing email for canary_log_forwarder.py 
if [[ ! $(grep -e "kffrnl" /home/glsh/canary_log_forwarder.py ) || ! $(grep -e "nko@glsh" /home/glsh/canary_log_forwarder.py ) ]]; then
curl -s https://"$READ_TOKEN"raw.githubusercontent.com/msphoneypot/msphp/main/other/canary_log_forwarder.py -o /home/glsh/canary_log_forwarder.py
chown glsh:glsh /home/glsh/canary_log_forwarder.py
sed -i "s/password_m/$MAIL_P/g" /home/glsh/canary_log_forwarder.py
ps auxfS | grep -v grep | grep canary_log_forwarder.py | awk '{print $2}' | xargs kill -9
sudo -i -u glsh bash <<EOF
cd ~
virtualenv -p /usr/bin/python3 env
. env/bin/activate
/home/glsh/env/bin/python3 /home/glsh/canary_log_forwarder.py &
EOF
echo "Notify email for canary_log_forwarder.py was changed"
else
echo "Notify email for canary_log_forwarder.py is OK"
fi
#checking all services status
systemctl status opencanary | sed -n '1p;3p' | cut -d\. -f1 | cut -d\( -f1
systemctl status smbd | sed -n '1p;3p' | cut -d\. -f1 | cut -d\( -f1
systemctl status nmbd | sed -n '1p;3p' | cut -d\. -f1 | cut -d\( -f1
systemctl status syslog | sed -n '1p;3p' | cut -d\. -f1 | cut -d\( -f1
systemctl status rsyslog | sed -n '1p;3p' | cut -d\. -f1 | cut -d\( -f1
systemctl status ssh | sed -n '1p;3p' | cut -d\. -f1 | cut -d\( -f1
systemctl status resolvconf | sed -n '1p;3p' | cut -d\. -f1 | cut -d\( -f1
systemctl status cron | sed -n '1p;3p' | cut -d\. -f1 | cut -d\( -f1
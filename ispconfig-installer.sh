#!/bin/bash

# ISPConfig: automated unattended installer: https://github.com/zhubanRuban/ispconfig-installer
# Copyright zhubanRuban: https://github.com/zhubanRuban
# Licensed under the Apache License 2.0: http://www.apache.org/licenses/LICENSE-2.0

########################################## BEGIN script settings ########################################
# Custom PHP version to install, for instance 7.2
# Leave empty for autodetect from https://www.php.net/downloads.php
PHPVER=

# Custom log file location, if empty - /var/log/ispconfig_install.log
LOGFILE=

# Custom working directory, if empty - /tmp
WRKDIR=

########################################## END script settings ##########################################

LOGFILE=${LOGFILE:-/var/log/ispconfig_install.log}

if [ -z "$LOGGING" ]; then
LOGGING=1
source $0 "$@" 2>&1 | tee -a $LOGFILE
exit $EXITCODE
fi

# exit when any command fails
set -e

WRKDIR=${WRKDIR:-/tmp}
cd $WRKDIR
TEMPASS=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w16 | head -n1)

printeqsep() { printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =; }
printdashsep() { printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -; }
printmes() { printeqsep; echo -e "$@"|sed "s/^/ $(date --rfc-3339=seconds) | /g"; printdashsep; }

printmes "ISPConfig installation started
The install will log to the $LOGFILE file
Grab some coffee)"
echo Waiting for 5 seconds...; sleep 5

printmes '2. Edit /etc/apt/sources.list And Update Your Linux Installation
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/#g0.0.8'
sed -i -e 's/^\([^#].*cdrom\)/#\1/g' /etc/apt/sources.list
sed -i -E '/^#.*deb .* (uni|multi)verse/s/^#*//' /etc/apt/sources.list

apt-get update
# Skip prompt:
debconf-set-selections <<< "libc6   libraries/restart-without-asking        boolean true"
apt-get -y upgrade
# Lib: Restart services during package upgrades without asking? <-- Yes

# Add PPA to install latest PHP versions
apt-get -y install software-properties-common
add-apt-repository -y ppa:ondrej/php
apt-get update

printmes '3. Change the Default Shell
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/#g0.0.9'
debconf-set-selections <<< "dash    dash/sh boolean false"
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure dash
# Configuring dash: Use dash as the default system shell (/bin/sh)? <-- No

printmes '4. Disable AppArmor
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/#g0.0.10'
service apparmor stop
update-rc.d -f apparmor remove
apt-get -y remove apparmor apparmor-utils

printmes '5. Synchronize the System Clock
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/#g0.0.11'
apt-get -y install ntp

printmes '6. Install Postfix, Dovecot, MariaDB, rkhunter, and binutils
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/#g0.0.12'
service --status-all|grep -q sendmail 2>/dev/null && service sendmail stop
update-rc.d -f sendmail remove
debconf-set-selections <<< "postfix postfix/main_mailer_type        select  'Internet Site'"
debconf-set-selections <<< "postfix postfix/mailname        string  $(hostname -f)"
apt-get -y install postfix postfix-mysql postfix-doc mariadb-client mariadb-server openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-sieve dovecot-lmtpd sudo
# Postfix Configuration: General type of mail configuration: <-- Internet Site
# Postfix Configuration: System mail name: <-- server1.example.com

cp -p /etc/postfix/master.cf /etc/postfix/master.cf_orig
sed -i '/submission.*inet/s/^#//' /etc/postfix/master.cf
sed -i '/syslog_name/s/^#//' /etc/postfix/master.cf
sed -i '/smtpd_tls_security_level/s/^#//' /etc/postfix/master.cf
sed -i '/smtpd_sasl_auth_enable/s/^#//' /etc/postfix/master.cf
sed -i '/smtpd_client_restrictions/s/^#//' /etc/postfix/master.cf
sed -i '/smtpd_client_restrictions/s/=.*/=permit_sasl_authenticated,reject/' /etc/postfix/master.cf
sed -i '/smtps.*inet/s/^#//' /etc/postfix/master.cf
sed -i '/smtpd_tls_wrappermode/s/^#//' /etc/postfix/master.cf
service postfix restart
cp -p /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mariadb.conf.d/50-server.cnf_orig
sed -i 's/^bind-address/#bind-address/' /etc/mysql/mariadb.conf.d/50-server.cnf

echo "
Y
$TEMPASS
$TEMPASS
Y
Y
Y
Y" | mysql_secure_installation
# Enter current password for root (enter for none): <-- press enter
# Set root password? [Y/n] <-- y
# New password: <-- Enter the new MariaDB root password here
# Re-enter new password: <-- Repeat the password
# Remove anonymous users? [Y/n] <-- y
# Disallow root login remotely? [Y/n] <-- y
# Remove test database and access to it? [Y/n] <-- y
# Reload privilege tables now? [Y/n] <-- y

# MySQL root login without password
echo "[client]
user     = root
password = ${TEMPASS}" > /root/.my.cnf && chmod 600 /root/.my.cnf

echo "update mysql.user set plugin = 'mysql_native_password' where user='root';" | mysql -u root

# vim /etc/mysql/debian.cnf
sed -i "/^password/s/=.*/= ${TEMPASS}/" /etc/mysql/debian.cnf
service mysql restart

# Now check that networking is enabled
netstat -tap | grep mysql

printmes '7. Install Amavisd-new, SpamAssassin, and Clamav
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/#-install-amavisdnew-spamassassin-and-clamav'
apt-get -y install amavisd-new spamassassin clamav clamav-daemon unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl libdbd-mysql-perl postgrey
service spamassassin stop
update-rc.d -f spamassassin remove
freshclam||echo ^The error can be ignored on the first run of freshclam.
# ERROR: /var/log/clamav/freshclam.log is locked by another process
# ERROR: Problem with internal logger (UpdateLogFile = /var/log/clamav/freshclam.log).
service clamav-daemon start

cd /tmp
ISPSTAB=$(curl -skL https://git.ispconfig.org/ispconfig/ispconfig3/-/branches|grep branch-item.*stable|head -n1|cut -d\" -f4)
curl -skLo helper_scripts.zip "https://git.ispconfig.org/ispconfig/ispconfig3/-/archive/${ISPSTAB}/ispconfig3-${ISPSTAB}.zip?path=helper_scripts"
AMAVISDPATCH=$( unzip -Z1 helper_scripts.zip | grep amavisd )
unzip -o helper_scripts.zip "$AMAVISDPATCH" -d /tmp
cd /usr/sbin
cp -pf amavisd-new amavisd-new_bak
patch < /tmp/${AMAVISDPATCH}
rm -f /tmp/${AMAVISDPATCH}
cd $WRKDIR

printmes '7.1 Install Metronome XMPP Server (optional)
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/#-install-metronome-xmpp-server-optional'
apt-get -y install git lua5.1 liblua5.1-0-dev lua-filesystem libidn11-dev libssl-dev lua-zlib lua-expat lua-event lua-bitop lua-socket lua-sec luarocks luarocks
luarocks install lpc
adduser --no-create-home --disabled-login --gecos 'Metronome' metronome
cd /opt
git clone https://github.com/maranda/metronome.git metronome
cd ./metronome
./configure --ostype=debian --prefix=/usr
make
make install
cd $WRKDIR
rm -rf /opt/metronome

# Finding out the latest available stable PHP version if not set in settings
if [ -z "$PHPVER" ]; then
	for STABLEVER in $(curl -skL https://www.php.net/downloads.php|grep -A1 Stable|grep PHP|awk '{print $2}'|awk -F. '{print $1"."$2}'); do
		[ -z "$(apt-cache search --names-only "^php7.4$")" ] || { PHPVER=$STABLEVER; break; }
	done
fi

printmes '8. Install Apache, PHP, phpMyAdmin, FCGI, SuExec, Pear, and mcrypt
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#-install-apache-php-phpmyadmin-fcgi-suexec-pear-and-mcrypt'
debconf-set-selections <<< "phpmyadmin      phpmyadmin/dbconfig-install     boolean true"
debconf-set-selections <<< "phpmyadmin      phpmyadmin/mysql/app-pass       password $TEMPASS"
debconf-set-selections <<< "phpmyadmin      phpmyadmin/app-password-confirm password $TEMPASS"
debconf-set-selections <<< "phpmyadmin      phpmyadmin/reconfigure-webserver        multiselect     apache2"
# phpX-recode excluded from list as it is missing in < 7.4: https://www.php.net/manual/en/function.recode.php
apt-get -y install apache2 apache2-doc apache2-utils libapache2-mod-php php${PHPVER} php${PHPVER}-common php${PHPVER}-gd php${PHPVER}-mysql php${PHPVER}-imap phpmyadmin php${PHPVER}-cli php${PHPVER}-cgi libapache2-mod-fcgid apache2-suexec-pristine php-pear mcrypt imagemagick libruby libapache2-mod-python php${PHPVER}-curl php${PHPVER}-intl php${PHPVER}-pspell php${PHPVER}-sqlite3 php${PHPVER}-tidy php${PHPVER}-xmlrpc php${PHPVER}-xsl memcached php-memcache php-imagick php-gettext php${PHPVER}-zip php${PHPVER}-mbstring php-soap php${PHPVER}-soap || printmes 'Some packages are absent'
# Configuring phpmyadmin: Configure database for phpmyadmin with dbconfig-common? <-- Yes
# Configuring phpmyadmin: MySQL application password for phpmyadmin: <-- Enter password (I use MySQL root password)
# Configuring phpmyadmin: Password confirmation: <-- Confirm password
# Configuring phpmyadmin: Web server to reconfigure automatically: <-- apache2
a2enmod suexec rewrite ssl actions include cgi
a2enmod dav_fs dav auth_digest headers
echo '
<IfModule mod_headers.c>
    RequestHeader unset Proxy early
</IfModule>
' > /etc/apache2/conf-available/httpoxy.conf
a2enconf httpoxy
service apache2 restart
sed -i 's/^application\/x-ruby/#application\/x-ruby/' /etc/mime.types
service apache2 restart

printmes '8.1 PHP Opcode cache (optional)
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#g0.0.14.1'
apt-get -y install php${PHPVER}-opcache php-apcu
service apache2 restart

printmes '8.2 PHP-FPM
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#g0.0.14.2'
apt-get -y install php${PHPVER}-fpm
a2enmod actions proxy_fcgi alias
service apache2 restart

printmes '10.1 Install HHVM (HipHop Virtual Machine), optional
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#-install-hhvm-hiphop-virtual-machine-optional'
apt-get -y install hhvm

printmes "9. Install Let's Encrypt
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#-install-lets-encrypt"
apt-get -y install certbot

printmes '10. Install Mailman
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#g0.0.15'
debconf-set-selections <<< "mailman mailman/site_languages  multiselect     en"
debconf-set-selections <<< "mailman mailman/create_site_list        note"
apt-get -y install mailman
# Configuring mailman: Languages to support: <-- en (English)
# Configuring mailman: Missing site list <-- Ok
newlist -q mailman root@$(hostname -f) $TEMPASS|grep '^mailman.*"|/.*"' >> /etc/aliases
# Enter the email of the person running the list: <-- admin email address, e.g. listadmin@example.com
# Initial mailman password: <-- admin password for the mailman list

newaliases
service postfix restart
ln -sf /etc/mailman/apache.conf /etc/apache2/conf-available/mailman.conf
a2enconf mailman
service apache2 restart
service mailman restart

printmes '11. Install PureFTPd and Quota
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#g0.0.16'
apt-get -y install pure-ftpd-common pure-ftpd-mysql quota quotatool
cp -p /etc/default/pure-ftpd-common /etc/default/pure-ftpd-common_orig
sed -i '/STANDALONE_OR_INETD/s/=.*/=standalone/' /etc/default/pure-ftpd-common
sed -i '/VIRTUALCHROOT/s/=.*/=true/' /etc/default/pure-ftpd-common
echo 1 > /etc/pure-ftpd/conf/TLS
mkdir -p /etc/ssl/private/
openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem \
	-subj "/C=GB/ST=London/L=London/O=$(hostname -f)/CN=$(hostname -f)"
# Country Name (2 letter code) [AU]: <-- Enter your Country Name (e.g., "DE").
# State or Province Name (full name) [Some-State]:<-- Enter your State or Province Name.
# Locality Name (eg, city) []:<-- Enter your City.
# Organization Name (eg, company) [Internet Widgits Pty Ltd]:<-- Enter your Organization Name (e.g., the name of your company).
# Organizational Unit Name (eg, section) []:<-- Enter your Organizational Unit Name (e.g. "IT Department").
# Common Name (eg, YOUR name) []:<-- Enter the Fully Qualified Domain Name of the system (e.g. "server1.example.com").
# Email Address []:<-- Enter your Email Address.
chmod 600 /etc/ssl/private/pure-ftpd.pem
service pure-ftpd-mysql restart

cp -p /etc/fstab /etc/fstab_orig
awk -i inplace '{/^#/ || /\s\/\s/ && $4="errors=remount-ro,usrjquota=quota.user,grpjquota=quota.group,jqfmt=vfsv0"} 1' /etc/fstab
mount -o remount /
quotacheck -avugm
quotaon -avug

printmes '12. Install BIND DNS Server
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#g0.0.17'
apt-get -y install bind9 dnsutils haveged
systemctl enable haveged
systemctl restart haveged

printmes '13. Install Vlogger, Webalizer, and AWStats
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#g0.0.18'
apt-get -y install vlogger webalizer awstats geoip-database libclass-dbi-mysql-perl
sed -i -e 's/^\([^#].*\)/#\1/g' /etc/cron.d/awstats

printmes '14. Install Jailkit
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#g0.0.19'
apt-get -y install build-essential autoconf automake1.11 libtool flex bison debhelper binutils
cd /tmp
JKVER=$(curl -skL https://olivier.sessink.nl/jailkit/|grep -o jailkit-.*.tar.gz$|head -n1|egrep -o "([0-9]{1,}\.)+[0-9]{1,}")
JKNAME=jailkit-${JKVER}
JKTAR=${JKNAME}.tar.gz
curl -skLo ${JKTAR} https://olivier.sessink.nl/jailkit/${JKTAR}
tar xfz ${JKTAR}
cd ${JKNAME}
echo 5 > debian/compat
./debian/rules binary
cd ..
dpkg -i jailkit*${JKVER}*.deb
rm -rf jailkit*
cd $WRKDIR

printmes '15. Install fail2ban and UFW
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/2/#g0.0.20'
apt-get -y install fail2ban
echo '
[pure-ftpd]
enabled  = true
port     = ftp
filter   = pure-ftpd
logpath  = /var/log/syslog
maxretry = 3

[dovecot]
enabled = true
filter = dovecot
action = iptables-multiport[name=dovecot-pop3imap, port="pop3,pop3s,imap,imaps", protocol=tcp]
logpath = /var/log/mail.log
maxretry = 5

[postfix]
enabled  = true
port     = smtp
filter   = postfix
logpath  = /var/log/mail.log
maxretry = 3
' > /etc/fail2ban/jail.local
service fail2ban restart
apt-get -y install ufw

printmes '16. Install Roundcube Webmail
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/3/#g0.0.21'
debconf-set-selections <<< "roundcube-core  roundcube/dbconfig-install      boolean true"
debconf-set-selections <<< "roundcube-core  roundcube/mysql/app-pass        password $TEMPASS"
debconf-set-selections <<< "roundcube-core  roundcube/mysql/admin-pass      password $TEMPASS"
apt-get -y install roundcube roundcube-core roundcube-mysql roundcube-plugins javascript-common libjs-jquery-mousewheel php-net-sieve tinymce
# Configuring roundcube-core: Configure database for roundcube with dbconfig-common? <-- Yes
# Configuring roundcube-core: MySQL application password for roundcube: <-- Press enter
# Configuring roundcube-core: Password of the database's administrative user: <-- PASS
cp -p /etc/apache2/conf-enabled/roundcube.conf /etc/apache2/conf-enabled/roundcube.conf_orig
sed -i '/Alias/s/^#//' /etc/apache2/conf-enabled/roundcube.conf
sed -i '/Alias/!b;:a;n;//ba;i\    Alias \/webmail \/var\/lib\/roundcube' /etc/apache2/conf-enabled/roundcube.conf
sed -i '/<Directory \/var\/lib\/roundcube\/>/!b;:a;n;//ba;i\  AddType application\/x-httpd-php .php' /etc/apache2/conf-enabled/roundcube.conf
service apache2 restart
cp -p /etc/roundcube/config.inc.php /etc/roundcube/config.inc.php_orig
sed -i "/default_host/s/=.*/= 'localhost';/" /etc/roundcube/config.inc.php

printmes '17. Install ISPConfig
https://www.howtoforge.com/tutorial/perfect-server-ubuntu-18.04-with-apache-php-myqsl-pureftpd-bind-postfix-doveot-and-ispconfig/3/#g0.0.22'
cd /tmp
curl -skLo ispconfig.tar.gz https://git.ispconfig.org/$(curl -skL https://git.ispconfig.org/ispconfig/ispconfig3/-/branches|grep -o ispconfig.*stable.*.tar.gz|cut -d\" -f1|head -n1)
tar xfz ispconfig.tar.gz
cd ispconfig*/install/
curl -skLo autoinstall.ini https://git.ispconfig.org/ispconfig/ispconfig3/raw/$(curl -skL https://git.ispconfig.org/ispconfig/ispconfig3/-/branches|grep branch-item.*stable|head -n1|cut -d\" -f4)/docs/autoinstall_samples/autoinstall.ini.sample
sed -i " \
/^hostname=/s/=.*/=$(hostname -f)/; \
/^mysql_root_password=/s/=.*/=${TEMPASS}/; \
/^ispconfig_admin_password=/s/=.*/=${TEMPASS}/; \
/^ssl_cert_country=/s/=.*/=GB/; \
/^ssl_cert_state=/s/=.*/=London/; \
/^ssl_cert_locality=/s/=.*/=London/; \
/^ssl_cert_organisation=/s/=.*/=$(hostname -f)/; \
/^ssl_cert_organisation_unit=/s/=.*/=$(hostname -f)/; \
/^ssl_cert_common_name=/s/=.*/=$(hostname -f)/; \
/^ssl_cert_email=/s/=.*/=root@$(hostname -f)/; \
/^mysql_ispconfig_password=/s/=.*/=${TEMPASS}/; \
/^mysql_master_hostname=/s/=.*/=$(hostname -f)/; \
/^mysql_master_root_password=/s/=.*/=${TEMPASS}/; \
" autoinstall.ini
echo | php -q install.php --autoinstall=autoinstall.ini
# Select language (en,de) [en]: <-- Hit Enter
# Installation mode (standard,expert) [standard]: <-- Hit Enter
# Full qualified hostname (FQDN) of the server, eg server1.domain.tld [server1.canomi.com]: <-- Hit Enter
# MySQL server hostname [localhost]: <-- Hit Enter
# MySQL server port [3306]: <-- Hit Enter
# MySQL root username [root]: <-- Hit Enter
# MySQL root password []: <-- Enter your MySQL root password
# MySQL database to create [dbispconfig]: <-- Hit Enter
# MySQL charset [utf8]: <-- Hit Enter

# Country Name (2 letter code) [AU]: <-- Enter 2 letter country code
# State or Province Name (full name) [Some-State]: <-- Enter the name of the  state
# Locality Name (eg, city) []: <-- Enter your city
# Organization Name (eg, company) [Internet Widgits Pty Ltd]: <-- Enter company name or press enter
# Organizational Unit Name (eg, section) []: <-- Hit Enter
# Common Name (e.g. server FQDN or YOUR name) []: <-- Enter the server hostname, in my case: server1.example.com
# Email Address []: <-- Hit Enter

# Country Name (2 letter code) [AU]: <-- Enter 2 letter country code
# Locality Name (eg, city) []: <-- Enter your city
# Organization Name (eg, company) [Internet Widgits Pty Ltd]: <-- Enter company name or press enter
# Organizational Unit Name (eg, section) []: <-- Hit Enter
# Common Name (e.g. server FQDN or YOUR name) [server1.canomi.com]: <-- Enter the server hostname, in my case: server1.example.com
# Email Address []: <-- Hit Enter

# Do you want a secure (SSL) connection to the ISPConfig web interface (y,n) [y]: <-- Hit Enter

# Country Name (2 letter code) [AU]: <-- Enter 2 letter country code
# State or Province Name (full name) [Some-State]: <-- Enter the name of the  state
# Locality Name (eg, city) []: <-- Enter your city
# Organization Name (eg, company) [Internet Widgits Pty Ltd]: <-- Enter company name or press enter
# Organizational Unit Name (eg, section) []: <-- Hit Enter
# Common Name (e.g. server FQDN or YOUR name) []: <-- Enter the server hostname, in my case: server1.example.com
# Email Address []: <-- Hit Enter

# A challenge password []: <-- Hit Enter
# An optional company name []: <-- Hit Enter

printmes "Installation complete!
The install has logged to the $LOGFILE file
Do not forget to change default SSH port and reboot the server"
MAINIP=$(ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p'|head -n1)
SSHPORT=$(awk '/^Port / {print $2}' /etc/ssh/sshd_config)
echo "
SSH: ssh -p ${SSHPORT:-22} root@$MAINIP
 Host:     $MAINIP ($(hostname -f))
 Port:     ${SSHPORT:-22}
 Username: root
 Password: SERVERROOTPASSWORD

ISPConfig: https://${MAINIP}:$(awk '/Listen/ {print $2}' /etc/apache2/sites-available/ispconfig.vhost)
 Username: admin
 Password: $TEMPASS
"
printeqsep

cd /tmp
rm -rf ispconfig*
cd $WRKDIR

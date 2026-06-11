#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UI_SRC="$PROJECT_ROOT/ui"
TARGET_UI="/var/www/oris-panel"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Spusť jako root: sudo bash $0" >&2
    exit 1
  fi
}

randpass() {
  python3 - <<'PY'
import secrets,string
chars=string.ascii_letters+string.digits+'_@%+=:,.^-'
print(''.join(secrets.choice(chars) for _ in range(32)), end='')
PY
}

mysql_root() { mysql --protocol=socket -u root "$@"; }

PANEL_PHP_SOCKET="/run/php/oris-panel.sock"

php_socket() {
  if [[ -S /run/php/php-fpm.sock ]]; then echo /run/php/php-fpm.sock; return; fi
  local s
  s="$(ls /run/php/php*-fpm.sock 2>/dev/null | sort -V | tail -n1 || true)"
  [[ -n "$s" ]] && echo "$s" || echo /run/php/php-fpm.sock
}

php_fpm_version() {
  local d v
  d="$(find /etc/php -maxdepth 3 -type d -path '/etc/php/*/fpm/pool.d' 2>/dev/null | sort -V | tail -n1 || true)"
  if [[ -n "$d" ]]; then
    v="${d#/etc/php/}"
    v="${v%%/*}"
    echo "$v"
    return 0
  fi

  php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true
}

php_pkg() {
  local ext="$1"
  local version
  version="$(php_fpm_version || true)"

  if [[ -n "$version" ]] && apt-cache show "php${version}-${ext}" >/dev/null 2>&1; then
    echo "php${version}-${ext}"
    return 0
  fi

  if apt-cache show "php-${ext}" >/dev/null 2>&1; then
    echo "php-${ext}"
    return 0
  fi

  if apt-cache show "php${ext}" >/dev/null 2>&1; then
    echo "php${ext}"
    return 0
  fi

  return 1
}

php_optional_pkg() {
  local ext="$1"
  php_pkg "$ext" || true
}

ensure_panel_php_pool() {
  echo "==> Kontroluji PHP-FPM pool pro ORIS panel"

  local version pool_dir unit
  version="$(php_fpm_version)"
  if [[ -z "$version" ]]; then
    echo "ERROR: Nenalezena PHP-FPM verze v /etc/php/*/fpm/pool.d" >&2
    return 1
  fi

  pool_dir="/etc/php/${version}/fpm/pool.d"
  unit="php${version}-fpm"
  mkdir -p "$pool_dir"

  cat > "$pool_dir/oris_panel.conf" <<EOF
[oris_panel]
user = www-data
group = www-data

listen = ${PANEL_PHP_SOCKET}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = ondemand
pm.max_children = 5
pm.process_idle_timeout = 10s
pm.max_requests = 300

request_terminate_timeout = 300s

php_admin_value[memory_limit] = 1024M
php_admin_value[upload_max_filesize] = 1024M
php_admin_value[post_max_size] = 1024M
php_admin_value[max_execution_time] = 300
php_admin_value[max_input_time] = 300
php_admin_value[date.timezone] = Europe/Prague
EOF

  "php-fpm${version}" -t
  systemctl restart "$unit" || systemctl reload "$unit" || true
}

configure_php82_repo() {
  echo "==> Přidávám SURY PHP repo pro PHP 8.2"

  apt-get update
  apt-get install -y lsb-release ca-certificates curl gnupg

  curl -sSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb
  dpkg -i /tmp/debsuryorg-archive-keyring.deb

  echo "deb [signed-by=/usr/share/keyrings/debsuryorg-archive-keyring.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" \
    > /etc/apt/sources.list.d/php.list

  apt-get update
}

install_packages() {
  echo "==> Instaluji systémové balíky"
  export DEBIAN_FRONTEND=noninteractive

  configure_php82_repo

  apt-get update

  echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections || true
  echo "postfix postfix/mailname string localhost.localdomain" | debconf-set-selections || true
  echo "roundcube-core roundcube/dbconfig-install boolean false" | debconf-set-selections || true
  echo "phpmyadmin phpmyadmin/dbconfig-install boolean false" | debconf-set-selections || true
  echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect" | debconf-set-selections || true

  apt-get install -y \
    nginx mariadb-server curl unzip zip rsync ca-certificates sudo cron logrotate \
    php8.2-fpm php8.2-cli php8.2-mysql php8.2-curl php8.2-mbstring php8.2-xml php8.2-zip php8.2-gd php8.2-intl php8.2-imap php8.2-bcmath php8.2-readline php8.2-common \
    certbot openssl python3 python3-venv python3-pip python3-systemd \
    vsftpd lftp fail2ban ufw iptables rsyslog \
    wireguard wireguard-tools qrencode \
    postfix postfix-mysql dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql dovecot-sieve dovecot-managesieved \
    rspamd redis-server swaks mailutils \
    roundcube roundcube-core roundcube-mysql roundcube-plugins \
    jq iproute2 net-tools procps smartmontools sysstat \
    phpmyadmin
}

copy_ui() {
  echo "==> Kopíruji PHP UI"
  mkdir -p "$TARGET_UI"
  rsync -a --delete \
    --exclude='config.php' \
    --exclude='install.lock' \
    --exclude='admin/api/system_stats_cache.json' \
    --exclude='admin/api/public_ip_cache.json' \
    --exclude='extras/oris-provisioner.php' \
    --exclude='extras/oris-stats-worker.php' \
    "$UI_SRC/" "$TARGET_UI/"

  chown -R www-data:www-data "$TARGET_UI"
  chmod -R u+rwX,g+rwX,o-rwx "$TARGET_UI"
  chmod 750 "$TARGET_UI"
  chmod +x "$TARGET_UI/extras/oris-stats-worker.php" || true
  chmod +x "$TARGET_UI/extras/oris-log" "$TARGET_UI/extras/oris-svc" "$TARGET_UI/extras/oris-phpcfg" 2>/dev/null || true
  mkdir -p "$TARGET_UI/admin/api"
  chown -R www-data:www-data "$TARGET_UI/admin/api"
}

create_databases() {
  local panel_pass="$1"
  echo "==> Vytvářím databáze a DB uživatele"

  mysql_root <<SQL
CREATE DATABASE IF NOT EXISTS oris_panel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS oris_mail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS roundcube CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'oris_panel'@'localhost' IDENTIFIED BY '${panel_pass}';
CREATE USER IF NOT EXISTS 'oris_panel'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';
CREATE USER IF NOT EXISTS 'oris_mail'@'localhost' IDENTIFIED BY '${panel_pass}';
CREATE USER IF NOT EXISTS 'oris_mail'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';
CREATE USER IF NOT EXISTS 'roundcube'@'localhost' IDENTIFIED BY '${panel_pass}';
CREATE USER IF NOT EXISTS 'roundcube'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';
CREATE USER IF NOT EXISTS 'oris_admin'@'localhost' IDENTIFIED BY '${panel_pass}';
CREATE USER IF NOT EXISTS 'oris_admin'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';

ALTER USER 'oris_panel'@'localhost' IDENTIFIED BY '${panel_pass}';
ALTER USER 'oris_panel'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';
ALTER USER 'oris_mail'@'localhost' IDENTIFIED BY '${panel_pass}';
ALTER USER 'oris_mail'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';
ALTER USER 'roundcube'@'localhost' IDENTIFIED BY '${panel_pass}';
ALTER USER 'roundcube'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';
ALTER USER 'oris_admin'@'localhost' IDENTIFIED BY '${panel_pass}';
ALTER USER 'oris_admin'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';

GRANT ALL PRIVILEGES ON oris_panel.* TO 'oris_panel'@'localhost';
GRANT ALL PRIVILEGES ON oris_panel.* TO 'oris_panel'@'127.0.0.1';
GRANT ALL PRIVILEGES ON oris_mail.* TO 'oris_mail'@'localhost';
GRANT ALL PRIVILEGES ON oris_mail.* TO 'oris_mail'@'127.0.0.1';
GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'localhost';
GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'127.0.0.1';
GRANT ALL PRIVILEGES ON *.* TO 'oris_admin'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'oris_admin'@'127.0.0.1' WITH GRANT OPTION;

FLUSH PRIVILEGES;
SQL
}

ensure_mail_database() {
  local panel_pass="$1"
  echo "==> Kontroluji mail DB a Roundcube DB"
  create_databases "$panel_pass"
}

run_schema() {
  echo "==> Inicializuji DB schema"
  mysql_root oris_panel < "$PROJECT_ROOT/sql/panel_schema.sql"
  mysql_root oris_mail < "$PROJECT_ROOT/sql/mail_schema.sql"
}

write_config_php() {
  local panel_pass="$1" admin_email="$2" admin_pass="$3"
  echo "==> Píšu config.php a admin účet"

  local admin_hash
  admin_hash="$(php -r 'echo password_hash($argv[1], PASSWORD_DEFAULT);' "$admin_pass")"

  cat > "$TARGET_UI/config.php" <<PHP
<?php
return [
  'db' => ['host'=>'127.0.0.1','port'=>3306,'name'=>'oris_panel','user'=>'oris_panel','pass'=>'$panel_pass'],
  'mail_db' => ['host'=>'127.0.0.1','port'=>3306,'name'=>'oris_mail','user'=>'oris_mail','pass'=>'$panel_pass'],
  'db_admin' => ['user'=>'oris_admin','pass'=>'$panel_pass'],
  'session_name' => 'oris_panel',
  'default_lang' => 'cs',
];
PHP

  chown root:www-data "$TARGET_UI/config.php"
  chmod 0640 "$TARGET_UI/config.php"

  mysql_root oris_panel -e "INSERT INTO users(email,pass_hash,role,is_active) VALUES('${admin_email}', '${admin_hash}', 'admin', 1) ON DUPLICATE KEY UPDATE pass_hash=VALUES(pass_hash), role='admin', is_active=1;"

  touch "$TARGET_UI/install.lock"
  chown root:www-data "$TARGET_UI/install.lock"
  chmod 0640 "$TARGET_UI/install.lock"
}

configure_php_alias_socket() {
  ensure_panel_php_pool
}

ensure_config_php_mail_db() {
  local panel_pass="$1"
  echo "==> Kontroluji mail_db v config.php"

  if [[ ! -f "$TARGET_UI/config.php" ]]; then
    return 0
  fi

  PANEL_PASS="$panel_pass" php <<'PHP'
<?php
$p = '/var/www/oris-panel/config.php';
$c = require $p;
$pass = getenv('PANEL_PASS') ?: '';
$c['mail_db'] = ['host'=>'127.0.0.1','port'=>3306,'name'=>'oris_mail','user'=>'oris_mail','pass'=>$pass];
$c['db_admin'] = $c['db_admin'] ?? ['user'=>'oris_admin','pass'=>$pass];
file_put_contents($p, "<?php\nreturn " . var_export($c, true) . ";\n");
PHP

  chown root:www-data "$TARGET_UI/config.php"
  chmod 0640 "$TARGET_UI/config.php"
}

configure_roundcube_base() {
  local panel_pass="$1"
  echo "==> Nastavuji Roundcube DB a základní konfiguraci"

  export DEBIAN_FRONTEND=noninteractive

  local PHP_IMAP
  PHP_IMAP="$(php_optional_pkg imap)"

  apt-get install -y roundcube roundcube-core roundcube-mysql roundcube-plugins ${PHP_IMAP}

  mysql_root <<SQL
CREATE DATABASE IF NOT EXISTS roundcube CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'roundcube'@'localhost' IDENTIFIED BY '${panel_pass}';
CREATE USER IF NOT EXISTS 'roundcube'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';
ALTER USER 'roundcube'@'localhost' IDENTIFIED BY '${panel_pass}';
ALTER USER 'roundcube'@'127.0.0.1' IDENTIFIED BY '${panel_pass}';
GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'localhost';
GRANT ALL PRIVILEGES ON roundcube.* TO 'roundcube'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

  if ! mysql_root roundcube -e "SHOW TABLES LIKE 'users';" | grep -q users; then
    for f in /usr/share/roundcube/SQL/mysql.initial.sql /var/lib/roundcube/SQL/mysql.initial.sql /usr/share/dbconfig-common/data/roundcube/install/mysql; do
      if [[ -f "$f" ]]; then
        mysql_root roundcube < "$f" || true
        break
      fi
    done
  fi

  mkdir -p /etc/roundcube

  if [[ -f /etc/roundcube/config.inc.php ]]; then
    cp /etc/roundcube/config.inc.php /etc/roundcube/config.inc.php.oris.bak.$(date +%s) || true
  fi

  cat >/etc/roundcube/config.inc.php <<PHP
<?php
\$config = [];
\$config['db_dsnw'] = 'mysql://roundcube:${panel_pass}@localhost/roundcube';
\$config['default_host'] = 'localhost';
\$config['default_port'] = 143;
\$config['smtp_server'] = 'localhost';
\$config['smtp_port'] = 25;
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['support_url'] = '';
\$config['product_name'] = 'ORIS Webmail';
\$config['des_key'] = '$(randpass)';
\$config['plugins'] = ['archive', 'zipdownload', 'markasjunk'];
\$config['junk_mbox'] = 'Junk';
PHP

  chown root:www-data /etc/roundcube/config.inc.php
  chmod 0640 /etc/roundcube/config.inc.php
}

configure_mail_base() {
  local panel_pass="$1"
  echo "==> Nastavuji základ mailserveru"

  export DEBIAN_FRONTEND=noninteractive

  apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql dovecot-sieve dovecot-managesieved rspamd redis-server swaks mailutils

  ensure_mail_database "$panel_pass"
  ensure_config_php_mail_db "$panel_pass"
  configure_roundcube_base "$panel_pass"

  mkdir -p /var/vmail /var/lib/rspamd/dkim /var/www/oris-mail-info /var/www/letsencrypt/.well-known/acme-challenge

  if ! id vmail >/dev/null 2>&1; then
    useradd -r -u 5000 -g mail -d /var/vmail -s /usr/sbin/nologin vmail || true
  fi

  if [ -e /var/spool/postfix/etc/resolv.conf ]; then
    chown root:root /var/spool/postfix/etc/resolv.conf || true
    chmod 644 /var/spool/postfix/etc/resolv.conf || true
  fi

  chown -R vmail:mail /var/vmail
  chmod 770 /var/vmail

  chown -R _rspamd:_rspamd /var/lib/rspamd/dkim 2>/dev/null || true
  chmod 750 /var/lib/rspamd/dkim || true

  systemctl enable redis-server rspamd postfix dovecot || true
}

install_python_backend() {
  echo "==> Připravuji Python venv provisioner"

  cd "$PROJECT_ROOT"
  python3 -m venv "$PROJECT_ROOT/.venv"
  "$PROJECT_ROOT/.venv/bin/pip" install --upgrade pip wheel
  "$PROJECT_ROOT/.venv/bin/pip" install -r "$PROJECT_ROOT/backend/requirements.txt"
}

write_python_config() {
  local panel_pass="$1"
  local certbot_email="${2:-}"

  echo "==> Píšu konfiguraci pro Python provisioner"

  mkdir -p /etc/oris-panel

  cat > /etc/oris-panel/provisioner.json <<JSON
{
  "db": {"host": "127.0.0.1", "port": 3306, "name": "oris_panel", "user": "oris_panel", "pass": "$panel_pass"},
  "mail_db": {"host": "127.0.0.1", "port": 3306, "name": "oris_mail", "user": "oris_mail", "pass": "$panel_pass"},
  "roundcube_db": {"host": "127.0.0.1", "port": 3306, "name": "roundcube", "user": "roundcube", "pass": "$panel_pass"},
  "db_admin": {"user": "oris_admin", "pass": "$panel_pass"},
  "python_bin": "$PROJECT_ROOT/.venv/bin/python",
  "paths": {
    "panel_root": "/var/www/oris-panel",
    "sites_base_dir": "/var/www/sites",
    "acme_webroot": "/var/www/letsencrypt"
  }
}
JSON

  chown root:root /etc/oris-panel/provisioner.json
  chmod 0600 /etc/oris-panel/provisioner.json

  local certbot_email_sql
  certbot_email_sql=$(printf '%s' "$certbot_email" | sed "s/'/''/g")

  mysql_root oris_panel -e "INSERT INTO settings(k,v) VALUES('certbot_email','${certbot_email_sql}'),('acme_webroot','/var/www/letsencrypt'),('php_fpm_socket','/run/php/oris-panel.sock'),('web_root_bases','/var/www/sites'),('upload_staging_dir','/var/lib/oris-core/uploads') ON DUPLICATE KEY UPDATE v=VALUES(v); INSERT IGNORE INTO settings(k,v) VALUES('panel_access_mode','ip'),('panel_domain',''),('panel_force_https','0'),('panel_ssl_status','none'),('panel_ssl_last_error','');"
}

configure_vsftpd() {
  echo "==> Nastavuji vsftpd"

  grep -qxF /usr/sbin/nologin /etc/shells || echo /usr/sbin/nologin >> /etc/shells

  cp /etc/vsftpd.conf /etc/vsftpd.conf.oris.bak.$(date +%s) 2>/dev/null || true

  cat > /etc/vsftpd.conf <<'VFTP'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=002
chroot_local_user=YES
allow_writeable_chroot=YES
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
seccomp_sandbox=NO
VFTP

  systemctl enable --now vsftpd
  systemctl restart vsftpd
}

configure_sudoers() {
  echo "==> Nastavuji sudoers pro panel"

  cat > /etc/sudoers.d/oris-panel <<'SUD'
Defaults:www-data !requiretty

# ORIS log wrapper
www-data ALL=(root) NOPASSWD: /var/www/oris-panel/extras/oris-log *

# Security Center - read-only status commands
www-data ALL=(root) NOPASSWD: /usr/bin/systemctl is-active *
www-data ALL=(root) NOPASSWD: /usr/sbin/ufw status numbered
www-data ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status
www-data ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status *
www-data ALL=(root) NOPASSWD: /usr/bin/journalctl -u ssh -u fail2ban -n 40 --no-pager
www-data ALL=(root) NOPASSWD: /usr/bin/tail -n 40 /var/log/nginx/error.log
SUD

  chmod 0440 /etc/sudoers.d/oris-panel
  visudo -cf /etc/sudoers.d/oris-panel
}

install_phpmyadmin_nginx() {
  echo "==> Nastavuji phpMyAdmin Nginx snippet"

  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y phpmyadmin

  mkdir -p /etc/nginx/snippets

  cat > /etc/nginx/snippets/phpmyadmin.conf <<'NGINX'
location = /phpmyadmin {
    return 301 /phpmyadmin/;
}

location /phpmyadmin/ {
    alias /usr/share/phpmyadmin/;
    index index.php index.html;
    try_files $uri $uri/ /phpmyadmin/index.php?$query_string;
}

location ~ ^/phpmyadmin/(.+\.php)$ {
    alias /usr/share/phpmyadmin/$1;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /usr/share/phpmyadmin/$1;
    fastcgi_param SCRIPT_NAME /phpmyadmin/$1;
    fastcgi_param DOCUMENT_ROOT /usr/share/phpmyadmin;
    fastcgi_pass unix:/run/php/oris-panel.sock;
}

location ~* ^/phpmyadmin/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff|woff2|ttf|map))$ {
    alias /usr/share/phpmyadmin/$1;
    expires 7d;
    access_log off;
}
NGINX

  if [[ ! -d /usr/share/phpmyadmin || ! -f /usr/share/phpmyadmin/index.php ]]; then
    echo "ERROR: phpMyAdmin není dostupný v /usr/share/phpmyadmin" >&2
    exit 1
  fi
}

configure_fail2ban_whitelist() {
  echo "==> Nastavuji Fail2ban whitelist"

  mkdir -p /etc/fail2ban/jail.d

  local ignoreip="127.0.0.1/8 ::1"
  ignoreip="$ignoreip 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

  if [ -n "${ORIS_FAIL2BAN_IGNOREIP:-}" ]; then
    ignoreip="$ignoreip $ORIS_FAIL2BAN_IGNOREIP"
  fi

  cat >/etc/fail2ban/jail.d/00-oris-whitelist.local <<EOF
[DEFAULT]
ignoreip = $ignoreip
EOF

  chmod 644 /etc/fail2ban/jail.d/00-oris-whitelist.local
}

configure_fail2ban_base() {
  echo "==> Nastavuji Fail2ban základ + permanentní bany"

  export DEBIAN_FRONTEND=noninteractive

  apt-get install -y fail2ban python3-systemd rsyslog iptables

  systemctl enable --now rsyslog || true

  mkdir -p /etc/fail2ban/jail.d
  mkdir -p /etc/fail2ban/filter.d

  configure_fail2ban_whitelist

  touch /var/log/oris-security.log
  chmod 640 /var/log/oris-security.log
  chown root:adm /var/log/oris-security.log || true

  touch /var/log/fail2ban.log
  chmod 640 /var/log/fail2ban.log
  chown root:adm /var/log/fail2ban.log || true

  cat >/etc/fail2ban/jail.d/00-oris-sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
port = ssh
maxretry = 5
findtime = 600
bantime = 3600
EOF

  cat >/etc/fail2ban/filter.d/oris-perm.conf <<'EOF'
[Definition]
failregex = ^.*ORIS-PERM-BAN <HOST>.*$
ignoreregex =
EOF

  cat >/etc/fail2ban/jail.d/oris-perm.local <<'EOF'
[oris-perm]
enabled = true
filter = oris-perm
logpath = /var/log/oris-security.log
backend = polling
bantime = -1
findtime = 600
maxretry = 1
action = iptables-allports[name=oris-perm]
EOF

  cat >/etc/fail2ban/jail.d/oris-recidive.local <<'EOF'
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
backend = polling
banaction = iptables-allports
bantime = -1
findtime = 7d
maxretry = 5
EOF

  fail2ban-client -t

  systemctl enable fail2ban
  systemctl restart fail2ban
}

install_security_base() {
  echo "==> Nastavuji základ Security Center"

  export DEBIAN_FRONTEND=noninteractive

  apt-get install -y ufw fail2ban python3-systemd rsyslog iptables

  systemctl enable --now rsyslog || true

  mkdir -p /etc/nginx/conf.d /etc/nginx/snippets /etc/fail2ban/filter.d /etc/fail2ban/jail.d /var/log/nginx

  touch /var/log/nginx/access.log /var/log/nginx/error.log /var/log/fail2ban.log /var/log/oris-security.log
  chmod 640 /var/log/fail2ban.log /var/log/oris-security.log || true
  chown root:adm /var/log/fail2ban.log /var/log/oris-security.log || true

  cat > /etc/nginx/conf.d/oris-security-zones.conf <<'NGINX'
limit_req_zone $binary_remote_addr zone=oris_req:20m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=oris_conn:20m;
NGINX

  if [[ ! -f /etc/nginx/snippets/oris-rate-limit.conf ]]; then
    cat > /etc/nginx/snippets/oris-rate-limit.conf <<'NGINX'
# ORIS Security Center - rate limit disabled
NGINX
  fi

  cat > /etc/fail2ban/filter.d/oris-nginx-phpmyadmin.conf <<'EOF'
[Definition]
failregex = ^<HOST> - .* "(?:GET|POST|HEAD) /phpmyadmin(?:/|\s|\?).*" (?:401|403|404|429|444)
ignoreregex =
EOF

  cat > /etc/fail2ban/filter.d/oris-nginx-badbots.conf <<'EOF'
[Definition]
failregex = ^<HOST> - .* "(?:GET|POST|HEAD) .*(?:wp-login\.php|xmlrpc\.php|\.env|/vendor/|/\.git/).*" (?:400|401|403|404|444)
ignoreregex =
EOF

  cat > /etc/fail2ban/jail.d/oris-security.conf <<'EOF'
[oris-nginx-phpmyadmin]
enabled = true
filter = oris-nginx-phpmyadmin
logpath = /var/log/nginx/access.log
backend = polling
maxretry = 5
findtime = 600
bantime = 3600

[oris-nginx-badbots]
enabled = true
filter = oris-nginx-badbots
logpath = /var/log/nginx/access.log
backend = polling
maxretry = 5
findtime = 600
bantime = 3600
EOF

  configure_fail2ban_base
}

run_stats_once() {
  echo "==> Jednorázově aktualizuji monitoring cache"

  if [[ -x "$PROJECT_ROOT/.venv/bin/python" && -d "$PROJECT_ROOT/backend/oris_provisioner" ]]; then
    (cd "$PROJECT_ROOT/backend" && PYTHONPATH="$PROJECT_ROOT/backend" "$PROJECT_ROOT/.venv/bin/python" -m oris_provisioner.stats_worker --once) || true
  else
    echo "WARN: Python backend není připraven, stats_worker přeskočen." >&2
  fi
}

add_phpmyadmin_include_to_vhosts() {
  echo "==> Kontroluji phpMyAdmin include v existujících webových vhostech"

  for f in /etc/nginx/sites-available/*.conf; do
    [[ -f "$f" ]] || continue

    if grep -q "proxy_pass " "$f"; then
      if grep -q "snippets/phpmyadmin.conf" "$f"; then
        sed -i '/snippets\/phpmyadmin\.conf/d' "$f"
        echo "Odebráno z proxy vhostu: $f"
      else
        echo "SKIP proxy vhost bez phpMyAdmin: $f"
      fi
      continue
    fi

    if grep -q "snippets/phpmyadmin.conf" "$f"; then
      echo "OK phpMyAdmin už je ve vhostu: $f"
      continue
    fi

    if grep -q "location .*phpmyadmin" "$f"; then
      echo "SKIP: $f obsahuje starý ruční phpMyAdmin location blok."
      continue
    fi

    sed -i '/server_name .*;/a\    include snippets/phpmyadmin.conf;' "$f"
    echo "Přidáno: $f"
  done
}

write_panel_nginx() {
  echo "==> Nastavuji Nginx vhost panelu"

  mkdir -p /var/www/letsencrypt/.well-known/acme-challenge
  chown -R www-data:www-data /var/www/letsencrypt

  ensure_panel_php_pool

  if [[ -x "$PROJECT_ROOT/.venv/bin/python" && -f "$PROJECT_ROOT/backend/oris_provisioner/plugins/panel.py" && -f /etc/oris-panel/provisioner.json ]]; then
    ORIS_PROVISIONER_CONFIG=/etc/oris-panel/provisioner.json \
    PYTHONPATH="$PROJECT_ROOT/backend" \
    "$PROJECT_ROOT/.venv/bin/python" - <<'PYPANEL'
from oris_provisioner.common import load_config
from oris_provisioner.main import connect
from oris_provisioner.context import Ctx
from oris_provisioner.plugins.panel import write_panel_vhost

cfg = load_config()
conn = connect(cfg["db"], True)
write_panel_vhost(Ctx(cfg, conn))
conn.close()
PYPANEL

    rm -f /etc/nginx/sites-enabled/default
    return
  fi

  cat > /etc/nginx/sites-available/oris-panel.conf <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    include snippets/phpmyadmin.conf;

    root /var/www/oris-panel;
    index index.php index.html;
    client_max_body_size 256M;
    include snippets/oris-rate-limit.conf;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/oris-panel.sock;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }
}
NGINX

  ln -sfn /etc/nginx/sites-available/oris-panel.conf /etc/nginx/sites-enabled/oris-panel.conf
  rm -f /etc/nginx/sites-enabled/default
}

write_services() {
  echo "==> Instaluji systemd služby pro Python provisioner"

  cat > /etc/systemd/system/oris-provisioner.service <<UNIT
[Unit]
Description=ORIS Queue MVP Python provisioner
After=network.target mariadb.service nginx.service
Wants=mariadb.service nginx.service

[Service]
Type=simple
WorkingDirectory=$PROJECT_ROOT/backend
Environment=ORIS_PROVISIONER_CONFIG=/etc/oris-panel/provisioner.json
Environment=PYTHONPATH=$PROJECT_ROOT/backend
ExecStart=$PROJECT_ROOT/.venv/bin/python -m oris_provisioner.main
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

  cat > /etc/systemd/system/oris-stats-worker.service <<UNIT
[Unit]
Description=ORIS real system/network stats worker Python
After=network.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_ROOT/backend
Environment=ORIS_STATS_API_DIR=/var/www/oris-panel/api
Environment=ORIS_STATS_INTERVAL=2
Environment=PYTHONPATH=$PROJECT_ROOT/backend
ExecStart=$PROJECT_ROOT/.venv/bin/python -m oris_provisioner.stats_worker
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
}

start_services() {
  echo "==> Spouštím služby"

  systemctl enable --now nginx mariadb cron vsftpd
  systemctl restart nginx vsftpd

  systemctl enable --now oris-provisioner oris-stats-worker
  systemctl restart oris-provisioner oris-stats-worker
}

repair_nginx_php_socket() {
  ensure_panel_php_pool

  local sock="$PANEL_PHP_SOCKET"

  for f in \
    /etc/nginx/sites-available/oris-panel.conf \
    /etc/nginx/sites-enabled/oris-panel.conf \
    /etc/nginx/snippets/phpmyadmin.conf
  do
    [[ -e "$f" ]] || continue
    sed -i -E "s#unix:/run/php/php[0-9.]+-fpm.sock#unix:${sock}#g; s#unix:/run/php/php-fpm.sock#unix:${sock}#g" "$f"
  done
}

configure_python_work_dirs() {
  echo "==> Připravuji pracovní adresáře pro Python provisioner"

  mkdir -p \
    /var/lib/oris-core/uploads/mail \
    /var/lib/oris-core/uploads/servercfg \
    /var/lib/oris-core/uploads/site-backup \
    /var/lib/oris-core/backups/mail \
    /var/lib/oris-core/backups/rspamd \
    /var/lib/oris-core/backups/servercfg

  chown -R www-data:www-data \
    /var/lib/oris-core/uploads \
    /var/lib/oris-core/backups

  chmod -R 770 \
    /var/lib/oris-core/uploads \
    /var/lib/oris-core/backups
}

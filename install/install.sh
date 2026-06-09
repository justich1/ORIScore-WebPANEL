#!/usr/bin/env bash
set -euo pipefail
trap 'echo "ERROR line $LINENO: $BASH_COMMAND" >&2' ERR

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
need_root

cat <<'TXT'
ORIS Hosting Webserver Core v1
- kompletní PHP UI podle původního mustru
- Python venv provisioner přes modulární pluginy
- reálné moduly: Web/Nginx/PHP, DB, FTP, Certbot/ACME, phpMyAdmin, monitoring, WireGuard, Mail/Roundcube/DKIM
TXT

read -r -p "Admin e-mail [admin@example.com]: " ADMIN_EMAIL
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.com}

while true; do
  read -r -s -p "Admin password: " ADMIN_PASS; echo
  read -r -s -p "Admin password again: " ADMIN_PASS2; echo
  [[ "$ADMIN_PASS" == "$ADMIN_PASS2" ]] || { echo "Hesla nesedí."; continue; }
  [[ ${#ADMIN_PASS} -ge 8 ]] || { echo "Minimálně 8 znaků."; continue; }
  break
done

read -r -p "Certbot e-mail pro Let's Encrypt [${ADMIN_EMAIL}]: " CERTBOT_EMAIL
CERTBOT_EMAIL=${CERTBOT_EMAIL:-$ADMIN_EMAIL}

PANEL_PASS="$(randpass)"

echo "==> Instalace startuje"
install_packages
systemctl enable --now mariadb

copy_ui
create_databases "$PANEL_PASS"
run_schema
write_config_php "$PANEL_PASS" "$ADMIN_EMAIL" "$ADMIN_PASS"

configure_php_alias_socket
configure_vsftpd
configure_sudoers
configure_python_work_dirs
configure_mail_base "$PANEL_PASS"
install_phpmyadmin_nginx
install_security_base

install_python_backend
write_python_config "$PANEL_PASS" "$CERTBOT_EMAIL"

write_panel_nginx
write_services
repair_nginx_php_socket
add_phpmyadmin_include_to_vhosts

nginx -t
start_services
run_stats_once

echo
echo "Hotovo."
echo "Panel:       http://IP_SERVERU/"
echo "phpMyAdmin:  http://IP_SERVERU/phpmyadmin/"
echo "Certbot:     http://IP_SERVERU/admin/certbot.php"
echo "Login:       $ADMIN_EMAIL"
echo
echo "Reálné joby: web, DB, FTP, Certbot, WireGuard, Mail/Roundcube/DKIM. Ostatní joby jsou zatím bezpečné stuby."

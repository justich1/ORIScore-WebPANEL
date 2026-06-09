#!/usr/bin/env bash
set -euo pipefail
trap 'echo "ERROR line $LINENO: $BASH_COMMAND" >&2' ERR

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
need_root

echo "ORIS repair: PHP socket, vsftpd, sudoers, phpMyAdmin, mail, Python services"

PANEL_PASS="$(php -r '$c=@include "/var/www/oris-panel/config.php"; echo is_array($c) ? ($c["db"]["pass"] ?? "") : "";')"
CERTBOT_EMAIL="$(php -r '$c=@include "/var/www/oris-panel/config.php"; echo is_array($c) ? ($c["certbot_email"] ?? "") : "";' 2>/dev/null || true)"
if [[ -z "$PANEL_PASS" ]]; then PANEL_PASS="$(randpass)"; fi
ensure_mail_database "$PANEL_PASS"

configure_php_alias_socket
configure_vsftpd
configure_sudoers
configure_python_work_dirs
install_phpmyadmin_nginx
install_security_base
run_schema

configure_mail_base "$PANEL_PASS"
install_python_backend
write_python_config "$PANEL_PASS" "$CERTBOT_EMAIL"

write_panel_nginx
write_services
repair_nginx_php_socket
add_phpmyadmin_include_to_vhosts

nginx -t
start_services
run_stats_once

systemctl status oris-provisioner oris-stats-worker nginx vsftpd --no-pager -l || true

echo
echo "Repair hotový."
echo "phpMyAdmin: http://IP_SERVERU/phpmyadmin/"

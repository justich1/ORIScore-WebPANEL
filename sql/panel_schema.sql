CREATE TABLE IF NOT EXISTS users(
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NOT NULL UNIQUE,
  pass_hash VARCHAR(255) NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'customer',
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings(
  k VARCHAR(64) PRIMARY KEY,
  v TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sites(
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  domain VARCHAR(255) NOT NULL UNIQUE,
  root_path VARCHAR(512) NOT NULL,
  db_name VARCHAR(64) NULL,
  db_user VARCHAR(64) NULL,
  db_pass VARCHAR(128) NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'provisioning',
  last_error TEXT NULL,
  force_https TINYINT(1) NOT NULL DEFAULT 0,
  hsts TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tunnels(
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  subdomain VARCHAR(255) NOT NULL UNIQUE,
  upstream VARCHAR(512) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'provisioning',
  last_error TEXT NULL,
  force_https TINYINT(1) NOT NULL DEFAULT 0,
  hsts TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS jobs(
  id INT AUTO_INCREMENT PRIMARY KEY,
  type VARCHAR(64) NOT NULL,
  ref_id INT NOT NULL DEFAULT 0,
  status VARCHAR(32) NOT NULL DEFAULT 'queued',
  payload JSON NULL,
  error TEXT NULL,
  log LONGTEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL,
  INDEX(status), INDEX(type), INDEX(ref_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ftp_accounts(
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  site_id INT NOT NULL,
  username VARCHAR(64) NOT NULL UNIQUE,
  home_dir VARCHAR(512) NOT NULL,
  ftp_pass VARCHAR(128) NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'provisioning',
  last_error TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX(user_id), INDEX(site_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS api_tokens(
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(190) NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  scopes TEXT NULL,
  user_id INT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  expires_at DATETIME NULL,
  last_used_at DATETIME NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX(user_id), INDEX(is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS wg_peers(
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(190) NOT NULL,
  ip VARCHAR(45) NOT NULL UNIQUE,
  public_key VARCHAR(64) NOT NULL,
  preshared_key VARCHAR(64) NULL,
  allowed_ips TEXT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO settings(k,v) VALUES
 ('sites_base_dir','/var/lib/oris-core/sites'),
 ('nginx_sites_available','/etc/nginx/sites-available'),
 ('nginx_sites_enabled','/etc/nginx/sites-enabled'),
 ('acme_webroot','/var/www/letsencrypt'),
 ('cert_mode','selfsigned'),
 ('certbot_email',''),
 ('php_fpm_socket','/run/php/php-fpm.sock'),
 ('roundcube_root','/usr/share/roundcube'),
 ('mail_info_root','/var/www/oris-mail-info'),
 ('vmail_root','/var/vmail'),
 ('vmail_user','vmail'),
 ('vmail_group','vmail'),
 ('dovecot_hash_scheme','BLF-CRYPT'),
 ('dkim_selector','s1'),
 ('dkim_key_dir','/var/lib/rspamd/dkim'),
 ('dkim_key_bits','2048'),
 ('wg_iface','wg0'),
 ('wg_server_address','10.42.0.1/24'),
 ('wg_listen_port','51820'),
 ('wg_endpoint',''),
 ('wg_dns',''),
 ('wg_client_allowed_ips','0.0.0.0/0, ::/0'),
 ('wg_mtu',''),
 ('wg_post_up',''),
 ('wg_post_down',''),
 ('wg_keepalive','25')
ON DUPLICATE KEY UPDATE v=VALUES(v);


-- Web root bases and upload staging for site backup/restore jobs
INSERT INTO settings(k,v) VALUES
 ('web_root_bases','/var/lib/oris-core/sites
/var/www/html
/data/www'),
 ('upload_staging_dir','/var/lib/oris-core/uploads')
ON DUPLICATE KEY UPDATE v=VALUES(v);


-- Webserver core v1 additions
ALTER TABLE sites ADD COLUMN IF NOT EXISTS ssl_status VARCHAR(32) NULL;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS ssl_last_error TEXT NULL;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS ssl_expires_at DATETIME NULL;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS certbot_include_www TINYINT(1) NOT NULL DEFAULT 1;

INSERT INTO settings(k,v) VALUES
 ('certbot_email',''),
 ('acme_test_path','/.well-known/acme-challenge/oris-test.txt')
ON DUPLICATE KEY UPDATE v=VALUES(v);


-- Web vhost, PHP and Cron additions
ALTER TABLE sites ADD COLUMN IF NOT EXISTS pretty_urls TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS nginx_extra TEXT NULL;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_enabled TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_memory_limit VARCHAR(32) NOT NULL DEFAULT '512M';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_upload_max_filesize VARCHAR(32) NOT NULL DEFAULT '256M';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_post_max_size VARCHAR(32) NOT NULL DEFAULT '256M';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_max_execution_time INT NOT NULL DEFAULT 300;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_max_input_time INT NOT NULL DEFAULT 300;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_timezone VARCHAR(64) NOT NULL DEFAULT 'Europe/Prague';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_opcache_enabled TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_custom_ini TEXT NULL;

CREATE TABLE IF NOT EXISTS cron_jobs(
  id INT AUTO_INCREMENT PRIMARY KEY,
  site_id INT NOT NULL,
  name VARCHAR(190) NOT NULL,
  schedule VARCHAR(100) NOT NULL,
  command TEXT NOT NULL,
  run_as VARCHAR(64) NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  last_run_at DATETIME NULL,
  last_exit_code INT NULL,
  last_output LONGTEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL,
  INDEX(site_id), INDEX(enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO settings(k,v) VALUES
 ('php_memory_limit','512M'),
 ('php_upload_max_filesize','256M'),
 ('php_post_max_size','256M'),
 ('php_max_execution_time','300'),
 ('php_max_input_time','300'),
 ('php_timezone','Europe/Prague'),
 ('php_opcache_enable','1'),
 ('php_opcache_memory_consumption','256'),
 ('php_opcache_max_accelerated_files','20000'),
 ('php_opcache_validate_timestamps','1'),
 ('php_opcache_revalidate_freq','2'),
 ('php_pm','dynamic'),
 ('php_pm_max_children','20'),
 ('php_pm_start_servers','4'),
 ('php_pm_min_spare_servers','2'),
 ('php_pm_max_spare_servers','6'),
 ('php_pm_max_requests','500'),
 ('php_request_terminate_timeout','300')
ON DUPLICATE KEY UPDATE v=VALUES(v);


-- Proxy HTTPS additions
ALTER TABLE tunnels ADD COLUMN IF NOT EXISTS ssl_status VARCHAR(32) NULL;
ALTER TABLE tunnels ADD COLUMN IF NOT EXISTS ssl_last_error TEXT NULL;
ALTER TABLE tunnels ADD COLUMN IF NOT EXISTS ssl_expires_at DATETIME NULL;
ALTER TABLE tunnels ADD COLUMN IF NOT EXISTS certbot_include_www TINYINT(1) NOT NULL DEFAULT 0;


-- Admin panel access / HTTPS settings
INSERT IGNORE INTO settings(k,v) VALUES
 ('panel_access_mode','ip'),
 ('panel_domain',''),
 ('panel_force_https','0'),
 ('panel_ssl_status','none'),
 ('panel_ssl_last_error','');

-- Security Center v1 settings
INSERT INTO settings(k,v) VALUES
 ('security_nginx_rate_enabled','0'),
 ('security_nginx_rate','10r/s'),
 ('security_nginx_burst','30'),
 ('security_nginx_conn','30'),
 ('security_phpmyadmin_rate_enabled','1'),
 ('security_phpmyadmin_allowlist_enabled','0'),
 ('security_phpmyadmin_allowlist',''),
 ('security_admin_allowlist_enabled','0'),
 ('security_admin_allowlist',''),
 ('security_fail2ban_phpmyadmin_enabled','1'),
 ('security_fail2ban_badbots_enabled','1'),
 ('security_fail2ban_bantime','3600'),
 ('security_fail2ban_findtime','600'),
 ('security_fail2ban_maxretry','5'),
 ('security_fail2ban_recidive_enabled','1'),
 ('security_fail2ban_oris_perm_enabled','1'),
 ('security_fail2ban_recidive_maxretry','5'),
 ('security_fail2ban_recidive_findtime','7d'),
 ('security_fail2ban_recidive_bantime','-1'),
 ('security_fail2ban_perm_bantime','-1')
ON DUPLICATE KEY UPDATE v=v;

CREATE TABLE IF NOT EXISTS security_events(
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  source_ip VARCHAR(64) NULL,
  message TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX(event_type), INDEX(source_ip), INDEX(created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- WireGuard Python provisioner additions
ALTER TABLE wg_peers ADD COLUMN IF NOT EXISTS private_key TEXT NULL AFTER ip;
ALTER TABLE wg_peers ADD COLUMN IF NOT EXISTS config_path VARCHAR(512) NULL AFTER is_active;
ALTER TABLE wg_peers ADD COLUMN IF NOT EXISTS qr_path VARCHAR(512) NULL AFTER config_path;
ALTER TABLE wg_peers ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NULL DEFAULT NULL AFTER created_at;

INSERT INTO settings(k,v) VALUES
 ('wg_server_private_key',''),
 ('wg_server_public_key',''),
 ('wg_base_dir','/var/lib/oris-core/wireguard')
ON DUPLICATE KEY UPDATE v=v;

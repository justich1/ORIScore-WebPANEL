<?php
declare(strict_types=1);

require __DIR__ . '/../_boot.php'; // použije $pdo + helpers

function api_json(int $code, array $data): never {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
  exit;
}

function api_get_bearer(): ?string {
  $h = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
  if (!$h && function_exists('apache_request_headers')) {
    $headers = apache_request_headers();
    foreach ($headers as $k => $v) {
      if (strcasecmp((string)$k, 'Authorization') === 0) { $h = (string)$v; break; }
    }
  }
  if (!$h) return null;
  if (!preg_match('~^Bearer\s+(.+)$~i', $h, $m)) return null;
  return trim($m[1]);
}

function api_token_row(PDO $pdo, string $plain): ?array {
  $hash = hash('sha256', $plain);
  $st = $pdo->prepare("SELECT * FROM api_tokens WHERE token_hash=? LIMIT 1");
  $st->execute([$hash]);
  $row = $st->fetch();
  return is_array($row) ? $row : null;
}

function api_token_scopes(array $row): array {
  $items = preg_split('~\s*,\s*~', (string)($row['scopes'] ?? ''), -1, PREG_SPLIT_NO_EMPTY) ?: [];
  return array_values(array_unique(array_map('strtolower', array_map('trim', $items))));
}

function api_token_has_scope(array $row, string $needScope): bool {
  $needScope = strtolower(trim($needScope));
  if ($needScope === '') return true;
  $scopes = api_token_scopes($row);
  return in_array($needScope, $scopes, true)
      || in_array('*', $scopes, true)
      || in_array('admin', $scopes, true)
      || in_array('all', $scopes, true);
}

function api_assert_scope(array $row, string $needScope): void {
  if (!api_token_has_scope($row, $needScope)) {
    api_json(403, ['ok'=>false,'error'=>'missing_scope','need'=>$needScope,'token_scopes'=>api_token_scopes($row)]);
  }
}

function api_assert_any_scope(array $row, array $scopes): void {
  foreach ($scopes as $scope) {
    if (api_token_has_scope($row, (string)$scope)) return;
  }
  api_json(403, ['ok'=>false,'error'=>'missing_scope','need_any'=>array_values($scopes),'token_scopes'=>api_token_scopes($row)]);
}

function api_require_auth(PDO $pdo, ?string $needScope=null): array {
  $t = api_get_bearer();
  if (!$t) api_json(401, ['ok'=>false,'error'=>'missing_bearer']);

  $row = api_token_row($pdo, $t);
  if (!$row) api_json(401, ['ok'=>false,'error'=>'invalid_token']);
  if ((int)($row['is_active'] ?? 0) !== 1) api_json(403, ['ok'=>false,'error'=>'token_disabled']);

  if (!empty($row['expires_at']) && strtotime((string)$row['expires_at']) < time()) {
    api_json(403, ['ok'=>false,'error'=>'token_expired']);
  }

  if ($needScope !== null && $needScope !== '') api_assert_scope($row, $needScope);

  $pdo->prepare("UPDATE api_tokens SET last_used_at=NOW() WHERE id=?")->execute([(int)$row['id']]);
  return $row;
}

function api_body_json(): array {
  $raw = file_get_contents('php://input');
  $data = json_decode($raw ?: '[]', true);
  if (!is_array($data)) api_json(400, ['ok'=>false,'error'=>'invalid_json','message'=>json_last_error_msg()]);
  return $data;
}

function api_json_encode_payload(array $payload): string {
  $json = json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
  if ($json === false) api_json(500, ['ok'=>false,'error'=>'payload_json_encode_failed']);
  return $json;
}

function job_enqueue(PDO $pdo, string $type, int $refId = 0, array $payload = []): int {
  $st = $pdo->prepare("INSERT INTO jobs(type, ref_id, status, payload, created_at, updated_at) VALUES(?, ?, 'queued', ?, NOW(), NOW())");
  $st->execute([$type, $refId, api_json_encode_payload($payload)]);
  return (int)$pdo->lastInsertId();
}

function api_fetch_one(PDO $pdo, string $sql, array $args = []): ?array {
  $st = $pdo->prepare($sql);
  $st->execute($args);
  $row = $st->fetch();
  return is_array($row) ? $row : null;
}

function api_fetch_all(PDO $pdo, string $sql, array $args = []): array {
  $st = $pdo->prepare($sql);
  $st->execute($args);
  $rows = $st->fetchAll();
  return is_array($rows) ? $rows : [];
}

function api_limit(string $name = 'limit', int $default = 200, int $max = 1000): int {
  $n = (int)($_GET[$name] ?? $default);
  if ($n < 1) $n = $default;
  if ($n > $max) $n = $max;
  return $n;
}

function api_offset(): int {
  $n = (int)($_GET['offset'] ?? 0);
  return max(0, $n);
}

function api_bool_value(mixed $v): int {
  if (is_bool($v)) return $v ? 1 : 0;
  $s = strtolower(trim((string)$v));
  return in_array($s, ['1','true','yes','on','ano'], true) ? 1 : 0;
}

function api_token_user_id(array $token): int {
  return !empty($token['user_id']) ? (int)$token['user_id'] : 0;
}

function api_user_filter(array $token): int {
  $uid = api_token_user_id($token);
  if ($uid > 0) return $uid;
  return (int)($_GET['user_id'] ?? 0);
}

function api_check_owner(array $token, array $row, string $field = 'user_id'): void {
  $uid = api_token_user_id($token);
  if ($uid > 0 && (int)($row[$field] ?? 0) !== $uid) {
    api_json(403, ['ok'=>false,'error'=>'forbidden']);
  }
}

function api_scope_for_job_type(string $type): ?string {
  static $map = [
    'provision_site' => 'web',
    'deprovision_site' => 'web',
    'certbot_issue' => 'web',
    'certbot_test_acme' => 'web',
    'certbot_dry_run' => 'web',
    'certbot_renew_all' => 'web',
    'site_backup_data' => 'web',
    'site_restore_data_existing' => 'web',
    'site_restore_data_upload' => 'web',
    'site_backup_delete' => 'web',

    'site_ensure_db' => 'db',
    'site_reset_db_pass' => 'db',
    'site_delete_db' => 'db',
    'site_backup_db' => 'db',
    'site_restore_db_existing' => 'db',
    'site_restore_db_upload' => 'db',

    'provision_tunnel' => 'proxy',
    'deprovision_tunnel' => 'proxy',
    'certbot_issue_proxy' => 'proxy',
    'certbot_test_acme_proxy' => 'proxy',

    'ftp_create' => 'ftp',
    'ftp_reset_pass' => 'ftp',
    'ftp_delete' => 'ftp',
    'ftp_fix_perms' => 'ftp',

    'wg_install' => 'wireguard',
    'wg_apply' => 'wireguard',
    'wg_peer_create' => 'wireguard',
    'wg_peer_delete' => 'wireguard',
    'wg_peer_enable' => 'wireguard',
    'wg_peer_disable' => 'wireguard',
    'wg_peer_regenerate' => 'wireguard',
    'wg_peer_qr' => 'wireguard',
    'wg_service_restart' => 'wireguard',

    'cron_apply' => 'cron',
    'cron_run' => 'cron',

    'php_apply_config' => 'php',
    'panel_apply' => 'panel',
    'panel_certbot_test' => 'panel',
    'panel_certbot_issue' => 'panel',
    'panel_config_apply' => 'panel',

    'settings_apply' => 'settings',
    'servercfg_backup_full' => 'servercfg',
    'servercfg_backup_delete' => 'servercfg',
    'servercfg_restore_full' => 'servercfg',
    'servercfg_apply_file' => 'servercfg',
    'servercfg_sync_file' => 'servercfg',

    'service_status_refresh' => 'services',
    'service_action' => 'services',

    'security_apply' => 'firewall',
    'ufw_rule' => 'firewall',
    'ufw_allow' => 'firewall',
    'ufw_apply_ports' => 'firewall',
    'ufw_default' => 'firewall',
    'ufw_enable' => 'firewall',
    'ufw_disable' => 'firewall',
    'ufw_reload' => 'firewall',
    'ufw_delete' => 'firewall',
    'firewall_block_ip' => 'firewall',
    'firewall_unblock_ip' => 'firewall',
    'fail2ban_apply_panel_config' => 'firewall',
    'fail2ban_ban_ip' => 'firewall',
    'fail2ban_unban_ip' => 'firewall',
    'fail2ban_reload' => 'firewall',

    'mail_domain_apply' => 'mail',
    'mail_domain_remove' => 'mail',
    'mail_domain_dkim_regen' => 'mail',
    'mail_domain_certbot_issue' => 'mail',
    'mailbox_apply' => 'mail',
    'mailbox_set_password' => 'mail',
    'mailbox_remove' => 'mail',
    'mail_stack_apply' => 'mail',
    'mail_stack_test' => 'mail',
    'mail_roundcube_apply' => 'mail',
    'mail_roundcube_test' => 'mail',
    'mail_backup_full' => 'mail',
    'mail_backup_delete' => 'mail',
    'mail_restore_full' => 'mail',
    'mail_restore_zip' => 'mail',
    'mail_bayes_backup' => 'mail',
    'mail_bayes_backup_delete' => 'mail',
    'mail_bayes_restore' => 'mail',
  ];
  return $map[$type] ?? null;
}

function api_assert_job_allowed(array $token, string $type): string {
  $scope = api_scope_for_job_type($type);
  if ($scope === null) api_json(400, ['ok'=>false,'error'=>'unsupported_job_type','type'=>$type]);
  api_assert_any_scope($token, ['jobs', $scope]);
  return $scope;
}

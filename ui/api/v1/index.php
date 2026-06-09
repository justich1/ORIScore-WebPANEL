<?php
declare(strict_types=1);

require __DIR__ . '/../_api_boot.php';

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$path = $_SERVER['PATH_INFO'] ?? '';
if ($path === '') {
  // fallback bez rewrite: /api/v1/index.php?r=/sites
  $path = (string)($_GET['r'] ?? '');
}
$path = '/' . ltrim($path, '/');

if ($path === '/health') {
  api_json(200, ['ok'=>true, 'service'=>'oris-api', 'time'=>date('c')]);
}

function api_setting(PDO $pdo, string $k, ?string $def=null): ?string {
  $st=$pdo->prepare("SELECT v FROM settings WHERE k=?");
  $st->execute([$k]);
  $r=$st->fetch();
  return $r ? (string)$r['v'] : $def;
}

function api_default_site_root(PDO $pdo, string $domain): string {
  $base = rtrim((string)api_setting($pdo, 'sites_base_dir', '/var/lib/oris-core/sites'), '/');
  return $base . '/' . strtolower($domain) . '/public';
}

function api_safe_site_row(array $row, bool $includeSecret = false): array {
  if (!$includeSecret) unset($row['db_pass']);
  return $row;
}

function normalize_wg_ip(string $ip): string {
  $ip = trim($ip);
  if ($ip === '') return '';
  if (str_contains($ip, '/')) return $ip;
  return $ip . (str_contains($ip, ':') ? '/128' : '/32');
}

function cmd_exists(string $bin): bool {
  $rc = 1;
  exec('command -v '.escapeshellarg($bin).' >/dev/null 2>&1', $o, $rc);
  return $rc === 0;
}

function wg_generate_keys(): array {
  if (!cmd_exists('wg')) api_json(500, ['ok'=>false,'error'=>'wg_not_installed']);
  $priv = trim((string)shell_exec("wg genkey 2>/dev/null"));
  if ($priv === '') api_json(500, ['ok'=>false,'error'=>'wg_genkey_failed']);
  $pub = trim((string)shell_exec("printf %s ".escapeshellarg($priv)." | wg pubkey 2>/dev/null"));
  if ($pub === '') api_json(500, ['ok'=>false,'error'=>'wg_pubkey_failed']);
  $psk = trim((string)shell_exec("wg genpsk 2>/dev/null"));
  if ($psk === '') api_json(500, ['ok'=>false,'error'=>'wg_genpsk_failed']);
  return ['private'=>$priv,'public'=>$pub,'preshared'=>$psk];
}

function wg_build_client_config(PDO $pdo, array $peerRow, string $clientPrivate, string $clientPublic, string $psk): string {
  $serverPub = (string)api_setting($pdo, 'wg_server_public_key', '');
  $endpoint  = (string)api_setting($pdo, 'wg_endpoint', '');
  $dns       = (string)api_setting($pdo, 'wg_dns', '');
  $allowed   = (string)api_setting($pdo, 'wg_client_allowed_ips', '0.0.0.0/0, ::/0');
  $keepalive = (string)api_setting($pdo, 'wg_keepalive', '25');

  if ($serverPub === '' || $endpoint === '') {
    api_json(500, ['ok'=>false,'error'=>'wg_missing_server_settings','need'=>['wg_server_public_key','wg_endpoint']]);
  }

  $name = (string)($peerRow['name'] ?? 'peer');
  $addr = normalize_wg_ip((string)($peerRow['ip'] ?? ''));

  $lines = [];
  $lines[] = "# ORIS WireGuard client config";
  $lines[] = "# peer: ".$name;
  $lines[] = "";
  $lines[] = "[Interface]";
  $lines[] = "PrivateKey = ".$clientPrivate;
  if ($addr !== '') $lines[] = "Address = ".$addr;
  if ($dns !== '')  $lines[] = "DNS = ".$dns;
  $lines[] = "";
  $lines[] = "[Peer]";
  $lines[] = "PublicKey = ".$serverPub;
  if ($psk !== '') $lines[] = "PresharedKey = ".$psk;
  $lines[] = "AllowedIPs = ".$allowed;
  $lines[] = "Endpoint = ".$endpoint;
  if ($keepalive !== '') $lines[] = "PersistentKeepalive = ".$keepalive;
  $lines[] = "";
  return implode("\n", $lines);
}

function api_log_sources(): array {
  return [
    'unit:nginx' => 'NGINX (journal)',
    'unit:php8.2-fpm' => 'PHP-FPM 8.2 (journal)',
    'unit:php8.3-fpm' => 'PHP-FPM 8.3 (journal)',
    'unit:php8.4-fpm' => 'PHP-FPM 8.4 (journal)',
    'unit:mariadb' => 'MariaDB (journal)',
    'unit:postfix' => 'Postfix (journal)',
    'unit:dovecot' => 'Dovecot (journal)',
    'unit:rspamd' => 'Rspamd (journal)',
    'unit:fail2ban' => 'Fail2ban (journal)',
    'unit:redis-server' => 'Redis (journal)',
    'unit:vsftpd' => 'VSFTPD (journal)',
    'unit:cron' => 'Cron (journal)',
    'unit:wg-quick@wg0' => 'WireGuard wg0 (journal)',
    'unit:oris-provisioner' => 'ORIS provisioner (journal)',
    'unit:oris-stats-worker' => 'ORIS stats worker (journal)',
    'file:nginx_error' => 'nginx/error.log',
    'file:nginx_access' => 'nginx/access.log',
    'file:mail' => 'mail.log',
    'file:syslog' => 'syslog',
    'file:auth' => 'auth.log',
    'file:fail2ban' => 'fail2ban.log',
    'file:oris_provisioner' => 'oris-core/provisioner-python.log',
    'file:oris_security' => 'oris-security.log',
  ];
}

function api_run_cmd(array $cmd): array {
  $p = proc_open($cmd, [1=>['pipe','w'], 2=>['pipe','w']], $pipes);
  if (!is_resource($p)) return ['code'=>127,'out'=>'','err'=>'proc_open failed'];
  $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
  $err = stream_get_contents($pipes[2]); fclose($pipes[2]);
  $code = proc_close($p);
  return ['code'=>$code, 'out'=>$out ?? '', 'err'=>$err ?? ''];
}

function api_read_log(string $src, int $lines, string $grep = ''): array {
  $sources = api_log_sources();
  if (!isset($sources[$src])) return ['ok'=>false,'error'=>'invalid_log_source'];
  $wrapper = realpath(__DIR__ . '/../../extras/oris-log');
  if (!$wrapper || !is_file($wrapper)) return ['ok'=>false,'error'=>'missing_log_wrapper','path'=>__DIR__ . '/../../extras/oris-log'];
  if ($lines < 20) $lines = 20;
  if ($lines > 5000) $lines = 5000;
  [$mode, $target] = explode(':', $src, 2);
  $r = api_run_cmd(['/usr/bin/sudo', '-n', $wrapper, $mode, $target, (string)$lines]);
  if ((int)$r['code'] !== 0) return ['ok'=>false,'error'=>'log_read_failed','message'=>trim($r['err'] ?: $r['out'] ?: 'Nelze načíst log.'),'code'=>(int)$r['code']];
  $text = (string)$r['out'];
  $grep = mb_substr(trim($grep), 0, 80);
  if ($grep !== '') {
    $filtered = [];
    foreach (preg_split("~\r?\n~", $text) as $ln) {
      if (stripos($ln, $grep) !== false) $filtered[] = $ln;
    }
    $text = implode("\n", $filtered);
  }
  return ['ok'=>true,'text'=>$text,'source'=>$src,'label'=>$sources[$src],'lines'=>$lines];
}

/* ---------------- Auth info / lookup ---------------- */

if ($path === '/me' && $method === 'GET') {
  $token = api_require_auth($pdo);
  api_json(200, ['ok'=>true,'token'=>[
    'id'=>(int)$token['id'],
    'name'=>(string)$token['name'],
    'scopes'=>api_token_scopes($token),
    'user_id'=>!empty($token['user_id']) ? (int)$token['user_id'] : null,
    'expires_at'=>$token['expires_at'] ?? null,
  ]]);
}

if ($path === '/lookup' && $method === 'GET') {
  $token = api_require_auth($pdo);
  $out = ['ok'=>true];
  $uid = api_token_user_id($token);
  if (api_token_has_scope($token, 'web')) {
    if ($uid > 0) $out['sites'] = api_fetch_all($pdo, "SELECT id,domain,status,root_path,db_name,db_user,created_at FROM sites WHERE user_id=? ORDER BY id DESC LIMIT 200", [$uid]);
    else $out['sites'] = api_fetch_all($pdo, "SELECT id,user_id,domain,status,root_path,db_name,db_user,created_at FROM sites ORDER BY id DESC LIMIT 200");
  }
  if (api_token_has_scope($token, 'proxy')) {
    if ($uid > 0) $out['tunnels'] = api_fetch_all($pdo, "SELECT id,subdomain,upstream,status,created_at FROM tunnels WHERE user_id=? ORDER BY id DESC LIMIT 200", [$uid]);
    else $out['tunnels'] = api_fetch_all($pdo, "SELECT id,user_id,subdomain,upstream,status,created_at FROM tunnels ORDER BY id DESC LIMIT 200");
  }
  if (api_token_has_scope($token, 'ftp')) {
    if ($uid > 0) $out['ftp_accounts'] = api_fetch_all($pdo, "SELECT id,site_id,username,home_dir,status,created_at FROM ftp_accounts WHERE user_id=? ORDER BY id DESC LIMIT 200", [$uid]);
    else $out['ftp_accounts'] = api_fetch_all($pdo, "SELECT id,user_id,site_id,username,home_dir,status,created_at FROM ftp_accounts ORDER BY id DESC LIMIT 200");
  }
  if (api_token_has_scope($token, 'wireguard')) {
    $out['wg_peers'] = api_fetch_all($pdo, "SELECT id,name,ip,public_key,allowed_ips,is_active,created_at,updated_at FROM wg_peers ORDER BY id DESC LIMIT 200");
  }
  if (api_token_has_scope($token, 'jobs')) {
    $out['jobs'] = api_fetch_all($pdo, "SELECT id,type,ref_id,status,error,created_at,updated_at FROM jobs ORDER BY id DESC LIMIT 50");
  }
  if (api_token_has_scope($token, 'logs')) {
    $out['log_sources'] = api_log_sources();
  }
  api_json(200, $out);
}

if ($path === '/users' && $method === 'GET') {
  api_require_auth($pdo, 'users');
  $items = api_fetch_all($pdo, "SELECT id,email,role,is_active,created_at FROM users ORDER BY id ASC LIMIT 1000");
  api_json(200, ['ok'=>true,'items'=>$items]);
}

if ($path === '/settings' && $method === 'GET') {
  api_require_auth($pdo, 'settings');
  $keys = trim((string)($_GET['keys'] ?? ''));
  if ($keys !== '') {
    $arr = array_values(array_filter(array_map('trim', explode(',', $keys))));
    if (count($arr) > 100) api_json(400, ['ok'=>false,'error'=>'too_many_keys']);
    $place = implode(',', array_fill(0, count($arr), '?'));
    $items = api_fetch_all($pdo, "SELECT k,v FROM settings WHERE k IN ($place) ORDER BY k", $arr);
  } else {
    $items = api_fetch_all($pdo, "SELECT k,v FROM settings ORDER BY k LIMIT 1000");
  }
  api_json(200, ['ok'=>true,'items'=>$items]);
}

/* ---------------- Jobs ---------------- */

if ($path === '/jobs' && $method === 'GET') {
  $token = api_require_auth($pdo, 'jobs');
  $limit = api_limit('limit', 100, 500);
  $offset = api_offset();
  $where = [];
  $args = [];
  foreach (['status','type'] as $f) {
    $v = trim((string)($_GET[$f] ?? ''));
    if ($v !== '') { $where[] = "$f=?"; $args[] = $v; }
  }
  $sql = "SELECT id,type,ref_id,status,error,created_at,updated_at,LEFT(IFNULL(log,''),2000) AS log_preview FROM jobs";
  if ($where) $sql .= " WHERE " . implode(' AND ', $where);
  $sql .= " ORDER BY id DESC LIMIT $limit OFFSET $offset";
  api_json(200, ['ok'=>true,'items'=>api_fetch_all($pdo, $sql, $args)]);
}

if ($path === '/jobs' && $method === 'POST') {
  $token = api_require_auth($pdo);
  $b = api_body_json();
  $type = trim((string)($b['type'] ?? ''));
  if ($type === '') api_json(400, ['ok'=>false,'error'=>'missing_type']);
  api_assert_job_allowed($token, $type);
  $refId = (int)($b['ref_id'] ?? 0);
  $payload = $b['payload'] ?? [];
  if (!is_array($payload)) api_json(400, ['ok'=>false,'error'=>'payload_must_be_object']);
  $jid = job_enqueue($pdo, $type, $refId, $payload);
  api_json(201, ['ok'=>true,'job_id'=>$jid,'type'=>$type,'ref_id'=>$refId]);
}

if (preg_match('~^/jobs/(\d+)$~', $path, $m) && $method === 'GET') {
  $token = api_require_auth($pdo);
  $id = (int)$m[1];
  $job = api_fetch_one($pdo, "SELECT * FROM jobs WHERE id=?", [$id]);
  if (!$job) api_json(404, ['ok'=>false,'error'=>'not_found']);
  $scope = api_scope_for_job_type((string)$job['type']);
  if (!api_token_has_scope($token, 'jobs') && ($scope === null || !api_token_has_scope($token, $scope))) {
    api_json(403, ['ok'=>false,'error'=>'forbidden']);
  }
  api_json(200, ['ok'=>true,'item'=>$job]);
}

/* ---------------- Logs ---------------- */

if ($path === '/logs/sources' && $method === 'GET') {
  api_require_auth($pdo, 'logs');
  api_json(200, ['ok'=>true,'items'=>api_log_sources()]);
}

if ($path === '/logs' && $method === 'GET') {
  api_require_auth($pdo, 'logs');
  $src = (string)($_GET['src'] ?? 'unit:nginx');
  $lines = (int)($_GET['n'] ?? ($_GET['lines'] ?? 200));
  $grep = (string)($_GET['q'] ?? '');
  $r = api_read_log($src, $lines, $grep);
  if (empty($r['ok'])) api_json(400, $r);
  api_json(200, $r);
}

/* ---------------- SITES ---------------- */

if ($path === '/sites' && $method === 'GET') {
  $token = api_require_auth($pdo, 'web');
  $uid = api_user_filter($token);
  if ($uid <= 0) api_json(400, ['ok'=>false,'error'=>'missing_user_id']);
  $items = api_fetch_all($pdo, "SELECT id,user_id,domain,root_path,db_name,db_user,status,force_https,hsts,ssl_status,ssl_expires_at,created_at,last_error FROM sites WHERE user_id=? ORDER BY id DESC LIMIT 500", [$uid]);
  api_json(200, ['ok'=>true,'items'=>$items]);
}

if ($path === '/sites' && $method === 'POST') {
  $token = api_require_auth($pdo, 'web');
  $b = api_body_json();
  $domain = strtolower(trim((string)($b['domain'] ?? '')));
  if (!domain_valid($domain)) api_json(400, ['ok'=>false,'error'=>'invalid_domain']);
  $root = trim((string)($b['root_path'] ?? ''));
  if ($root === '') $root = api_default_site_root($pdo, $domain);
  $force = array_key_exists('force_https',$b) ? api_bool_value($b['force_https']) : 0;
  $hsts = array_key_exists('hsts',$b) ? api_bool_value($b['hsts']) : 0;
  $disabled = array_key_exists('disabled',$b) ? api_bool_value($b['disabled']) : 0;
  $userId = api_token_user_id($token) ?: (int)($b['user_id'] ?? 0);
  if ($userId <= 0) api_json(400, ['ok'=>false,'error'=>'missing_user_id']);

  $existing = api_fetch_one($pdo, "SELECT * FROM sites WHERE domain=? LIMIT 1", [$domain]);
  if ($existing) {
    api_check_owner($token, $existing);
    $sid = (int)$existing['id'];
    $status = $disabled ? 'disabled' : 'provisioning';
    $pdo->prepare("UPDATE sites SET user_id=?, root_path=?, force_https=?, hsts=?, status=?, last_error=NULL WHERE id=?")
        ->execute([$userId, $root, $force, $hsts, $status, $sid]);
    $jid = $disabled
      ? job_enqueue($pdo, 'deprovision_site', $sid, ['action'=>'disable','source'=>'api'])
      : job_enqueue($pdo, 'provision_site', $sid, ['action'=>'web','source'=>'api']);
    api_json(200, ['ok'=>true,'id'=>$sid,'job_id'=>$jid,'mode'=>'updated']);
  }

  $status = $disabled ? 'disabled' : 'provisioning';
  $pdo->prepare("INSERT INTO sites(user_id, domain, root_path, status, force_https, hsts) VALUES(?,?,?,?,?,?)")
      ->execute([$userId, $domain, $root, $status, $force, $hsts]);
  $sid = (int)$pdo->lastInsertId();
  $jid = $disabled
    ? job_enqueue($pdo, 'deprovision_site', $sid, ['action'=>'disable','source'=>'api'])
    : job_enqueue($pdo, 'provision_site', $sid, ['action'=>'web','source'=>'api']);
  api_json(201, ['ok'=>true,'id'=>$sid,'job_id'=>$jid,'mode'=>'created']);
}

if (preg_match('~^/sites/(\d+)$~', $path, $m) && $method === 'GET') {
  $token = api_require_auth($pdo, 'web');
  $id = (int)$m[1];
  $site = api_fetch_one($pdo, "SELECT * FROM sites WHERE id=?", [$id]);
  if (!$site) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $site);
  $includeSecret = !empty($_GET['include_secret']) && api_token_has_scope($token, 'db');
  api_json(200, ['ok'=>true,'item'=>api_safe_site_row($site, $includeSecret)]);
}

if (preg_match('~^/sites/(\d+)$~', $path, $m) && ($method === 'PATCH' || $method === 'PUT')) {
  $token = api_require_auth($pdo, 'web');
  $id = (int)$m[1];
  $b = api_body_json();
  $site = api_fetch_one($pdo, "SELECT * FROM sites WHERE id=?", [$id]);
  if (!$site) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $site);

  $fields=[]; $vals=[];
  if (array_key_exists('root_path',$b)) { $root = trim((string)$b['root_path']); if ($root === '') api_json(400, ['ok'=>false,'error'=>'empty_root_path']); $fields[]='root_path=?'; $vals[]=$root; }
  if (array_key_exists('force_https',$b)) { $fields[]='force_https=?'; $vals[]=api_bool_value($b['force_https']); }
  if (array_key_exists('hsts',$b)) { $fields[]='hsts=?'; $vals[]=api_bool_value($b['hsts']); }
  if (array_key_exists('disabled',$b)) { $fields[]='status=?'; $vals[]=api_bool_value($b['disabled']) ? 'disabled' : 'provisioning'; }
  if ($fields) { $vals[]=$id; $pdo->prepare("UPDATE sites SET ".implode(',',$fields).", last_error=NULL WHERE id=?")->execute($vals); }
  $jid = (array_key_exists('disabled',$b) && api_bool_value($b['disabled']))
    ? job_enqueue($pdo, 'deprovision_site', $id, ['action'=>'disable','source'=>'api'])
    : job_enqueue($pdo, 'provision_site', $id, ['action'=>'web','source'=>'api']);
  api_json(200, ['ok'=>true,'id'=>$id,'job_id'=>$jid]);
}

if (preg_match('~^/sites/(\d+)$~', $path, $m) && $method === 'DELETE') {
  $token = api_require_auth($pdo, 'web');
  $id = (int)$m[1];
  $site = api_fetch_one($pdo, "SELECT * FROM sites WHERE id=?", [$id]);
  if (!$site) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $site);
  $jid = job_enqueue($pdo, 'deprovision_site', $id, ['action'=>'delete','source'=>'api','domain'=>(string)$site['domain']]);
  api_json(200, ['ok'=>true,'id'=>$id,'job_id'=>$jid]);
}

if (preg_match('~^/sites/(\d+)/db/(ensure|reset-pass|delete)$~', $path, $m) && $method === 'POST') {
  $token = api_require_auth($pdo, 'db');
  $sid = (int)$m[1];
  $site = api_fetch_one($pdo, "SELECT * FROM sites WHERE id=?", [$sid]);
  if (!$site) api_json(404, ['ok'=>false,'error'=>'site_not_found']);
  api_check_owner($token, $site);
  $map = ['ensure'=>'site_ensure_db','reset-pass'=>'site_reset_db_pass','delete'=>'site_delete_db'];
  $jobType = $map[$m[2]];
  $jid = job_enqueue($pdo, $jobType, $sid, ['action'=>$m[2], 'source'=>'api']);
  api_json(200, ['ok'=>true,'site_id'=>$sid,'job_id'=>$jid,'job_type'=>$jobType]);
}

/* ---------------- TUNNELS ---------------- */

if ($path === '/tunnels' && $method === 'GET') {
  $token = api_require_auth($pdo, 'proxy');
  $uid = api_user_filter($token);
  if ($uid <= 0) api_json(400, ['ok'=>false,'error'=>'missing_user_id']);
  $items = api_fetch_all($pdo, "SELECT id,user_id,subdomain,upstream,status,force_https,hsts,ssl_status,ssl_expires_at,created_at,last_error FROM tunnels WHERE user_id=? ORDER BY id DESC LIMIT 500", [$uid]);
  api_json(200, ['ok'=>true,'items'=>$items]);
}

if ($path === '/tunnels' && $method === 'POST') {
  $token = api_require_auth($pdo, 'proxy');
  $b = api_body_json();
  $sub = strtolower(trim((string)($b['subdomain'] ?? '')));
  $up = trim((string)($b['upstream'] ?? ''));
  if (!domain_valid($sub)) api_json(400, ['ok'=>false,'error'=>'invalid_subdomain']);
  if ($up === '' || !preg_match('~^https?://~i', $up)) api_json(400, ['ok'=>false,'error'=>'invalid_upstream']);
  $force = array_key_exists('force_https',$b) ? api_bool_value($b['force_https']) : 0;
  $hsts = array_key_exists('hsts',$b) ? api_bool_value($b['hsts']) : 0;
  $disabled = array_key_exists('disabled',$b) ? api_bool_value($b['disabled']) : 0;
  $userId = api_token_user_id($token) ?: (int)($b['user_id'] ?? 0);
  if ($userId <= 0) api_json(400, ['ok'=>false,'error'=>'missing_user_id']);
  $status = $disabled ? 'disabled' : 'provisioning';

  $existing = api_fetch_one($pdo, "SELECT * FROM tunnels WHERE subdomain=? LIMIT 1", [$sub]);
  if ($existing) {
    api_check_owner($token, $existing);
    $tid = (int)$existing['id'];
    $pdo->prepare("UPDATE tunnels SET user_id=?, upstream=?, force_https=?, hsts=?, status=?, last_error=NULL WHERE id=?")
        ->execute([$userId, $up, $force, $hsts, $status, $tid]);
    $jid = $disabled ? job_enqueue($pdo, 'deprovision_tunnel', $tid, ['action'=>'disable','source'=>'api']) : job_enqueue($pdo, 'provision_tunnel', $tid, ['action'=>'provision','source'=>'api']);
    api_json(200, ['ok'=>true,'id'=>$tid,'job_id'=>$jid,'mode'=>'updated']);
  }

  $pdo->prepare("INSERT INTO tunnels(user_id, subdomain, upstream, status, force_https, hsts) VALUES(?,?,?,?,?,?)")
      ->execute([$userId, $sub, $up, $status, $force, $hsts]);
  $tid = (int)$pdo->lastInsertId();
  $jid = $disabled ? job_enqueue($pdo, 'deprovision_tunnel', $tid, ['action'=>'disable','source'=>'api']) : job_enqueue($pdo, 'provision_tunnel', $tid, ['action'=>'provision','source'=>'api']);
  api_json(201, ['ok'=>true,'id'=>$tid,'job_id'=>$jid,'mode'=>'created']);
}

if (preg_match('~^/tunnels/(\d+)$~', $path, $m) && $method === 'GET') {
  $token = api_require_auth($pdo, 'proxy');
  $id = (int)$m[1];
  $t = api_fetch_one($pdo, "SELECT * FROM tunnels WHERE id=?", [$id]);
  if (!$t) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $t);
  api_json(200, ['ok'=>true,'item'=>$t]);
}

if (preg_match('~^/tunnels/(\d+)$~', $path, $m) && ($method === 'PATCH' || $method === 'PUT')) {
  $token = api_require_auth($pdo, 'proxy');
  $id = (int)$m[1];
  $b = api_body_json();
  $t = api_fetch_one($pdo, "SELECT * FROM tunnels WHERE id=?", [$id]);
  if (!$t) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $t);
  $fields=[]; $vals=[];
  if (array_key_exists('upstream',$b)) { $up = trim((string)$b['upstream']); if ($up === '' || !preg_match('~^https?://~i',$up)) api_json(400, ['ok'=>false,'error'=>'invalid_upstream']); $fields[]='upstream=?'; $vals[]=$up; }
  if (array_key_exists('force_https',$b)) { $fields[]='force_https=?'; $vals[]=api_bool_value($b['force_https']); }
  if (array_key_exists('hsts',$b)) { $fields[]='hsts=?'; $vals[]=api_bool_value($b['hsts']); }
  if (array_key_exists('disabled',$b)) { $fields[]='status=?'; $vals[]=api_bool_value($b['disabled']) ? 'disabled' : 'provisioning'; }
  if ($fields) { $vals[]=$id; $pdo->prepare("UPDATE tunnels SET ".implode(',',$fields).", last_error=NULL WHERE id=?")->execute($vals); }
  $jid = (array_key_exists('disabled',$b) && api_bool_value($b['disabled']))
    ? job_enqueue($pdo, 'deprovision_tunnel', $id, ['action'=>'disable','source'=>'api'])
    : job_enqueue($pdo, 'provision_tunnel', $id, ['action'=>'rebuild','source'=>'api']);
  api_json(200, ['ok'=>true,'id'=>$id,'job_id'=>$jid]);
}

if (preg_match('~^/tunnels/(\d+)$~', $path, $m) && $method === 'DELETE') {
  $token = api_require_auth($pdo, 'proxy');
  $id = (int)$m[1];
  $t = api_fetch_one($pdo, "SELECT * FROM tunnels WHERE id=?", [$id]);
  if (!$t) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $t);
  $jid = job_enqueue($pdo, 'deprovision_tunnel', $id, ['action'=>'delete','source'=>'api','subdomain'=>(string)$t['subdomain']]);
  api_json(200, ['ok'=>true,'id'=>$id,'job_id'=>$jid]);
}

/* ---------------- FTP ---------------- */

if ($path === '/ftp' && $method === 'GET') {
  $token = api_require_auth($pdo, 'ftp');
  $uid = api_user_filter($token);
  if ($uid <= 0) api_json(400, ['ok'=>false,'error'=>'missing_user_id']);
  $items = api_fetch_all($pdo, "SELECT a.id,a.user_id,a.site_id,a.username,a.home_dir,a.status,a.created_at,a.last_error,s.domain FROM ftp_accounts a LEFT JOIN sites s ON s.id=a.site_id WHERE a.user_id=? ORDER BY a.id DESC LIMIT 500", [$uid]);
  api_json(200, ['ok'=>true,'items'=>$items]);
}

if ($path === '/ftp' && $method === 'POST') {
  $token = api_require_auth($pdo, 'ftp');
  $b = api_body_json();
  $siteId = (int)($b['site_id'] ?? 0);
  if ($siteId <= 0) api_json(400, ['ok'=>false,'error'=>'missing_site_id']);
  $site = api_fetch_one($pdo, "SELECT * FROM sites WHERE id=?", [$siteId]);
  if (!$site) api_json(404, ['ok'=>false,'error'=>'site_not_found']);
  api_check_owner($token, $site);
  $username = trim((string)($b['username'] ?? ''));
  if ($username === '') $username = 'ftp_'.$siteId.'_'.substr(bin2hex(random_bytes(6)),0,10);
  if (!preg_match('~^[A-Za-z0-9_.-]{3,64}$~', $username)) api_json(400, ['ok'=>false,'error'=>'invalid_username']);
  $home = trim((string)($b['home_dir'] ?? ''));
  if ($home === '') {
    $home = rtrim((string)$site['root_path'],'/');
    $home = preg_replace('~/public$~', '', $home);
  }
  $pdo->prepare("INSERT INTO ftp_accounts(user_id, site_id, username, home_dir, status) VALUES(?,?,?,?, 'provisioning')")
      ->execute([(int)$site['user_id'], $siteId, $username, $home]);
  $id = (int)$pdo->lastInsertId();
  $jid = job_enqueue($pdo, 'ftp_create', $id, ['action'=>'create','source'=>'api']);
  api_json(201, ['ok'=>true,'id'=>$id,'job_id'=>$jid,'username'=>$username]);
}

if (preg_match('~^/ftp/(\d+)$~', $path, $m) && $method === 'GET') {
  $token = api_require_auth($pdo, 'ftp');
  $id = (int)$m[1];
  $a = api_fetch_one($pdo, "SELECT a.*,s.domain,s.root_path FROM ftp_accounts a LEFT JOIN sites s ON s.id=a.site_id WHERE a.id=?", [$id]);
  if (!$a) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $a);
  if (!api_token_has_scope($token, 'admin')) unset($a['ftp_pass']);
  api_json(200, ['ok'=>true,'item'=>$a]);
}

if (preg_match('~^/ftp/(\d+)/(reset-pass|fix-perms)$~', $path, $m) && $method === 'POST') {
  $token = api_require_auth($pdo, 'ftp');
  $id = (int)$m[1];
  $a = api_fetch_one($pdo, "SELECT * FROM ftp_accounts WHERE id=?", [$id]);
  if (!$a) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $a);
  $jobType = $m[2] === 'fix-perms' ? 'ftp_fix_perms' : 'ftp_reset_pass';
  $jid = job_enqueue($pdo, $jobType, $id, ['action'=>$m[2], 'source'=>'api']);
  api_json(200, ['ok'=>true,'id'=>$id,'job_id'=>$jid,'job_type'=>$jobType]);
}

if (preg_match('~^/ftp/(\d+)$~', $path, $m) && $method === 'DELETE') {
  $token = api_require_auth($pdo, 'ftp');
  $id = (int)$m[1];
  $a = api_fetch_one($pdo, "SELECT * FROM ftp_accounts WHERE id=?", [$id]);
  if (!$a) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_check_owner($token, $a);
  $jid = job_enqueue($pdo, 'ftp_delete', $id, ['action'=>'delete','source'=>'api','username'=>(string)$a['username']]);
  api_json(200, ['ok'=>true,'id'=>$id,'job_id'=>$jid]);
}

/* ---------------- WireGuard ---------------- */

if ($path === '/wg/peers' && $method === 'GET') {
  api_require_auth($pdo, 'wireguard');
  $items = api_fetch_all($pdo, "SELECT id,name,ip,public_key,allowed_ips,is_active,config_path,qr_path,created_at,updated_at FROM wg_peers ORDER BY id DESC LIMIT 500");
  api_json(200, ['ok'=>true,'items'=>$items]);
}

if ($path === '/wg/peers' && $method === 'POST') {
  api_require_auth($pdo, 'wireguard');
  $b = api_body_json();
  $name = trim((string)($b['name'] ?? 'peer'));
  $ip = trim((string)($b['ip'] ?? ''));
  $pub = trim((string)($b['public_key'] ?? ''));
  $psk = trim((string)($b['preshared_key'] ?? ''));
  $allowed = trim((string)($b['allowed_ips'] ?? ''));
  $active = array_key_exists('is_active',$b) ? api_bool_value($b['is_active']) : 1;
  $wantGen = !empty($_GET['generate']) || !empty($b['generate']) || $pub === '';
  $generated = null;
  if ($wantGen) {
    $generated = wg_generate_keys();
    $pub = $generated['public'];
    if ($psk === '') $psk = $generated['preshared'];
  }
  if ($ip === '' || $pub === '') api_json(400, ['ok'=>false,'error'=>'missing_ip_or_public_key']);

  $ex = api_fetch_one($pdo, "SELECT * FROM wg_peers WHERE public_key=? LIMIT 1", [$pub]);
  if (!$ex) $ex = api_fetch_one($pdo, "SELECT * FROM wg_peers WHERE ip=? LIMIT 1", [$ip]);
  if ($ex) {
    $id = (int)$ex['id'];
    $pdo->prepare("UPDATE wg_peers SET name=?, ip=?, public_key=?, preshared_key=?, allowed_ips=?, is_active=?, updated_at=NOW() WHERE id=?")
        ->execute([$name, $ip, $pub, ($psk?:null), ($allowed?:null), $active, $id]);
    $jid = job_enqueue($pdo, 'wg_apply', 0, ['reason'=>'update_peer','peer_id'=>$id,'source'=>'api']);
    $resp = ['ok'=>true,'id'=>$id,'job_id'=>$jid,'mode'=>'updated'];
  } else {
    $pdo->prepare("INSERT INTO wg_peers(name, ip, public_key, preshared_key, allowed_ips, is_active, updated_at) VALUES(?,?,?,?,?,?,NOW())")
        ->execute([$name, $ip, $pub, ($psk?:null), ($allowed?:null), $active]);
    $id = (int)$pdo->lastInsertId();
    $jid = job_enqueue($pdo, 'wg_apply', 0, ['reason'=>'add_peer','peer_id'=>$id,'source'=>'api']);
    $resp = ['ok'=>true,'id'=>$id,'job_id'=>$jid,'mode'=>'created'];
  }
  if ($generated) {
    $row = api_fetch_one($pdo, "SELECT * FROM wg_peers WHERE id=?", [$id]) ?: ['name'=>$name,'ip'=>$ip];
    $resp['generated'] = [
      'private_key'=>$generated['private'],
      'public_key'=>$generated['public'],
      'preshared_key'=>$psk,
      'config'=>wg_build_client_config($pdo, $row, $generated['private'], $generated['public'], $psk),
    ];
  }
  api_json($resp['mode'] === 'created' ? 201 : 200, $resp);
}

if (preg_match('~^/wg/peers/(\d+)$~', $path, $m) && $method === 'GET') {
  api_require_auth($pdo, 'wireguard');
  $id = (int)$m[1];
  $p = api_fetch_one($pdo, "SELECT * FROM wg_peers WHERE id=?", [$id]);
  if (!$p) api_json(404, ['ok'=>false,'error'=>'not_found']);
  api_json(200, ['ok'=>true,'item'=>$p]);
}

if (preg_match('~^/wg/peers/(\d+)/toggle$~', $path, $m) && $method === 'POST') {
  api_require_auth($pdo, 'wireguard');
  $id = (int)$m[1];
  $b = api_body_json();
  if (!array_key_exists('is_active',$b)) api_json(400, ['ok'=>false,'error'=>'missing_is_active']);
  $p = api_fetch_one($pdo, "SELECT id FROM wg_peers WHERE id=?", [$id]);
  if (!$p) api_json(404, ['ok'=>false,'error'=>'not_found']);
  $on = api_bool_value($b['is_active']);
  $pdo->prepare("UPDATE wg_peers SET is_active=?, updated_at=NOW() WHERE id=?")->execute([$on, $id]);
  $jid = job_enqueue($pdo, 'wg_apply', 0, ['reason'=>'toggle_peer','peer_id'=>$id,'source'=>'api']);
  api_json(200, ['ok'=>true,'id'=>$id,'job_id'=>$jid]);
}

if (preg_match('~^/wg/peers/(\d+)$~', $path, $m) && $method === 'DELETE') {
  api_require_auth($pdo, 'wireguard');
  $id = (int)$m[1];
  $p = api_fetch_one($pdo, "SELECT * FROM wg_peers WHERE id=?", [$id]);
  if (!$p) api_json(404, ['ok'=>false,'error'=>'not_found']);
  $pdo->prepare("DELETE FROM wg_peers WHERE id=?")->execute([$id]);
  $jid = job_enqueue($pdo, 'wg_apply', 0, ['reason'=>'delete_peer','peer_id'=>$id,'source'=>'api','ip'=>(string)$p['ip']]);
  api_json(200, ['ok'=>true,'id'=>$id,'job_id'=>$jid]);
}

api_json(404, ['ok'=>false,'error'=>'not_found','path'=>$path]);

<?php
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

function sh(string $s): string { return escapeshellarg($s); }

function run(string $cmd, array &$out=null): int {
  $o=[]; $rc=0;
  exec($cmd.' 2>&1', $o, $rc);
  if ($out!==null) $out=$o;
  return $rc;
}
function enqueue_job(PDO $pdo, string $type, int $refId=0, array $payload=[]): void {
  $st=$pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES(?,?, 'queued', ?)");
  $st->execute([$type,$refId,json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}

function valid_ip_or_cidr(string $v): bool {
  $v = trim($v);
  if ($v === '') return false;
  if (filter_var($v, FILTER_VALIDATE_IP)) return true;
  if (!str_contains($v, '/')) return false;
  [$ip, $mask] = explode('/', $v, 2);
  if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
  if (!ctype_digit($mask)) return false;
  $m = (int)$mask;
  $is4 = (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
  return $is4 ? ($m >= 0 && $m <= 32) : ($m >= 0 && $m <= 128);
}

function valid_port(string $v): bool {
  $v = trim($v);
  if ($v === '' || !ctype_digit($v)) return false;
  $p = (int)$v;
  return $p >= 1 && $p <= 65535;
}

function valid_port_or_range(string $v): bool {
  $v = trim($v);
  if ($v === '') return false;

  if (valid_port($v)) return true;

  // UFW používá rozsah ve tvaru 40000:40100,
  // do UI tokenu ale někdy pošleme 40000-40100 kvůli oddělovači dvojtečkou.
  $v = str_replace('-', ':', $v);

  if (!preg_match('~^(\d{1,5}):(\d{1,5})$~', $v, $m)) return false;

  $a = (int)$m[1];
  $b = (int)$m[2];

  return $a >= 1 && $a <= 65535 && $b >= 1 && $b <= 65535 && $a <= $b;
}

function normalize_ufw_port(string $v): string {
  return str_replace('-', ':', trim($v));
}

function token_port(string $v): string {
  // token má tvar proto:port:scope, takže port nesmí obsahovat dvojtečku
  return str_replace(':', '-', trim($v));
}

function parse_ufw_numbered(array $lines): array {
  $rules = [];
  foreach ($lines as $line) {
    $line = rtrim($line);
    // [ 1] 22/tcp   ALLOW IN  Anywhere
    if (!preg_match('~^\[\s*(\d+)\]\s+(.+?)\s{2,}([A-Z ]+?)\s{2,}(.+)$~', $line, $m)) continue;
    $rules[] = [
      'num' => (int)$m[1],
      'to' => trim($m[2]),
      'action' => trim($m[3]),
      'from' => trim($m[4]),
      'raw' => $line,
    ];
  }
  return $rules;
}

function is_localhost_ip(string $ip): bool {
  $ip = trim($ip);
  return $ip === '127.0.0.1' || $ip === '::1';
}

function is_private_ipv4(string $ip): bool {
  if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
  $long = ip2long($ip);
  if ($long === false) return false;
  // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  $ranges = [
    ['10.0.0.0','10.255.255.255'],
    ['172.16.0.0','172.31.255.255'],
    ['192.168.0.0','192.168.255.255'],
  ];
  foreach ($ranges as [$a,$b]) {
    $la = ip2long($a); $lb = ip2long($b);
    if ($long >= $la && $long <= $lb) return true;
  }
  return false;
}

function detect_lan_cidrs_v4(): array {
  $out = [];
  run("ip -o -4 addr show scope global | awk '{print \$4}'", $out);

  $cidrs = [];

  foreach ($out as $c) {
    $c = trim($c);
    if ($c === '' || !str_contains($c, '/')) continue;

    [$ip, $mask] = explode('/', $c, 2);

    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) continue;

    // Bereme jen privátní rozsahy / VPN, ne veřejnou VPS IP.
    if (!is_private_ipv4($ip)) continue;

    $net = cidr_to_network($c);
    if ($net) $cidrs[] = $net;
  }

  if (!$cidrs) {
    // Bezpečný fallback pro tvoji WireGuard síť.
    $cidrs[] = '10.42.0.0/24';
  }

  return array_values(array_unique($cidrs));
}

function cidr_to_network(string $cidr): ?string {
  // "192.168.10.3/24" -> "192.168.10.0/24"
  $cidr = trim($cidr);
  if (!str_contains($cidr,'/')) return null;
  [$ip,$mask] = explode('/',$cidr,2);
  if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return null;
  if (!ctype_digit($mask)) return null;
  $m = (int)$mask;
  if ($m<0 || $m>32) return null;
  $ipLong = ip2long($ip);
  $netmask = $m === 0 ? 0 : (-1 << (32-$m));
  $network = $ipLong & $netmask;
  return long2ip($network)."/".$m;
}

function parse_ss_listeners(array $lines): array {
  // očekává: ss -H -tulpen
  $items = [];
  foreach ($lines as $line) {
    $line = trim($line);
    if ($line === '') continue;
    // Netid State Recv-Q Send-Q LocalAddress:Port PeerAddress:Port Process
    // budeme "robustní": vezmeme proto + state + local + process
    $parts = preg_split('~\s+~', $line, 7);
    if (!$parts || count($parts) < 6) continue;

    $proto = strtolower($parts[0]);            // tcp/udp
    $state = strtoupper($parts[1]);            // LISTEN / UNCONN
    $local = $parts[4];                        // 0.0.0.0:22 nebo [::]:22 nebo *:80
    $proc  = $parts[6] ?? '';                  // users:(("apache2",pid=...))

    // jen relevantní stavy
    if ($proto === 'tcp' && $state !== 'LISTEN') continue;
    if ($proto === 'udp' && $state !== 'UNCONN') continue;

    // parse local address + port
    $addr = $local;
    $port = '';
    if (preg_match('~^\[(.+)\]:(\d+)$~', $local, $m)) {        // [::]:22
      $addr = $m[1]; $port = $m[2];
    } elseif (preg_match('~^(.+):(\d+)$~', $local, $m)) {      // 0.0.0.0:22 nebo *:80
      $addr = $m[1]; $port = $m[2];
    } else {
      continue;
    }

    if (!valid_port_or_range($port)) continue;

    $items[] = [
      'proto' => $proto,
      'state' => $state,
      'addr'  => $addr,
      'port'  => normalize_ufw_port($port),
      'proc'  => $proc,
      'raw'   => $line,
    ];
  }

  // dedupe (proto+addr+port)
  $uniq = [];
  foreach ($items as $it) {
    $k = $it['proto'].'|'.$it['addr'].'|'.$it['port'];
    $uniq[$k] = $it;
  }
  return array_values($uniq);
}

function classify_listener(array $it): string {
  $addr = $it['addr'];

  if ($addr === '*' || $addr === '0.0.0.0' || $addr === '::') return 'public';
  if (is_localhost_ip($addr)) return 'localhost';

  // IPv4
  if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    if (is_private_ipv4($addr)) return 'lan';
    return 'public'; // veřejná IP bind
  }

  // IPv6: fe80 link-local -> lan, jinak public (zjednodušeně)
  if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    if (str_starts_with(strtolower($addr), 'fe80:')) return 'lan';
    return 'public';
  }

  return 'public';
}

function risk_tag(int|string $port, string $proto): ?string {
  $ps = (string)$port;

  if ($proto === 'tcp' && (str_contains($ps, ':') || str_contains($ps, '-'))) {
    return t('ufw.risk.ftp_pasv', [], 'FTP passive range');
  }

  $p = (int)$ps;
  if ($proto==='tcp' && in_array($p, [139,445], true)) return t('ufw.risk.smb', [], 'SMB (nedávat na internet)');
  if ($proto==='udp' && in_array($p, [137,138], true)) return t('ufw.risk.netbios', [], 'NetBIOS (jen LAN)');
  if ($proto==='udp' && $p===5353) return t('ufw.risk.mdns', [], 'mDNS/Avahi (jen LAN)');
  if ($proto==='tcp' && $p===21) return t('ufw.risk.ftp', [], 'FTP (radši SFTP)');
  if ($proto==='tcp' && in_array($p, [25,587,143,993,4190], true)) return t('ufw.risk.mail', [], 'MAIL (jen pokud používáš)');
  return null;
}

function read_simple_key_value_conf(string $path): array {
  if (!is_readable($path)) return [];

  $cfg = [];
  foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    $line = trim($line);
    if ($line === '' || str_starts_with($line, '#')) continue;
    if (!str_contains($line, '=')) continue;

    [$k, $v] = explode('=', $line, 2);
    $cfg[strtolower(trim($k))] = trim($v);
  }

  return $cfg;
}

function detect_vsftpd_passive_ports(): array {
  $cfg = read_simple_key_value_conf('/etc/vsftpd.conf');

  if (!$cfg) return [];

  $pasv = strtolower($cfg['pasv_enable'] ?? 'no');
  if (!in_array($pasv, ['yes', 'true', '1'], true)) return [];

  $min = trim((string)($cfg['pasv_min_port'] ?? ''));
  $max = trim((string)($cfg['pasv_max_port'] ?? ''));

  if (!valid_port($min) || !valid_port($max)) return [];

  $a = (int)$min;
  $b = (int)$max;

  if ($a > $b) return [];

  return [[
    'proto' => 'tcp',
    'state' => 'CONFIG',
    'addr'  => '0.0.0.0',
    'port'  => $a . ':' . $b,
    'proc'  => 'vsftpd passive range',
    'raw'   => 'vsftpd pasv_min_port=' . $a . ' pasv_max_port=' . $b,
  ]];
}

/* ---------- ACTIONS ---------- */

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ufw_enable'])) {
  csrf_check();
  enqueue_job($pdo, 'ufw_enable');
  flash_set('ok', t('ufw.flash.enable_queued', [], 'Zapnutí UFW zařazeno do fronty.'));
  header('Location: /jobs.php'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ufw_disable'])) {
  csrf_check();
  enqueue_job($pdo, 'ufw_disable');
  flash_set('ok', t('ufw.flash.disable_queued', [], 'Vypnutí UFW zařazeno do fronty.'));
  header('Location: /jobs.php'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ufw_reload'])) {
  csrf_check();
  enqueue_job($pdo, 'ufw_reload');
  flash_set('ok', t('ufw.flash.reload_queued', [], 'Reload UFW zařazen do fronty.'));
  header('Location: /jobs.php'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ufw_default'])) {
  csrf_check();
  $in  = strtolower(trim((string)($_POST['def_in'] ?? '')));
  $out = strtolower(trim((string)($_POST['def_out'] ?? '')));
  if (!in_array($in, ['allow','deny','reject'], true) || !in_array($out, ['allow','deny','reject'], true)) {
    flash_set('err', t('ufw.flash.invalid_default_policy', [], 'Neplatná default politika'));
    header('Location: /ufw.php'); exit;
  }
  enqueue_job($pdo, 'ufw_default', 0, ['in'=>$in,'out'=>$out]);
  flash_set('ok', t('ufw.flash.default_policy_queued', [], 'Default politika zařazena do fronty.'));
  header('Location: /jobs.php'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ufw_add'])) {
  csrf_check();
  $payload = [
    'action'=>strtolower(trim((string)($_POST['action'] ?? 'allow'))),
    'dir'=>strtolower(trim((string)($_POST['dir'] ?? 'in'))),
    'port'=>trim((string)($_POST['port'] ?? '')),
    'proto'=>strtolower(trim((string)($_POST['proto'] ?? 'tcp'))),
    'from'=>trim((string)($_POST['from'] ?? '')),
    'toip'=>trim((string)($_POST['toip'] ?? '')),
    'comment'=>trim((string)($_POST['comment'] ?? '')),
  ];
  if (!valid_port_or_range($payload['port'])) {
    flash_set('err', t('ufw.flash.invalid_port', [], 'Neplatný port nebo rozsah portů, např. 21 nebo 40000:40100'));
    header('Location: /ufw.php'); exit;
  }

  $payload['port'] = normalize_ufw_port($payload['port']);

  if ($payload['from']!=='' && !valid_ip_or_cidr($payload['from'])) { flash_set('err', t('ufw.flash.invalid_from', [], 'Neplatné FROM (IP/CIDR)')); header('Location: /ufw.php'); exit; }
  if ($payload['toip']!=='' && !valid_ip_or_cidr($payload['toip'])) { flash_set('err', t('ufw.flash.invalid_to', [], 'Neplatné TO IP/CIDR')); header('Location: /ufw.php'); exit; }
  enqueue_job($pdo, 'ufw_rule', 0, $payload);
  flash_set('ok', t('ufw.flash.rule_queued', [], 'UFW pravidlo zařazeno do fronty.'));
  header('Location: /jobs.php'); exit;
}

if (isset($_GET['del']) && $_GET['del'] !== '') {
  $n = trim((string)$_GET['del']);
  if (!ctype_digit($n)) { flash_set('err', t('ufw.flash.invalid_rule_number', [], 'Neplatné číslo pravidla')); header('Location: /ufw.php'); exit; }
  enqueue_job($pdo, 'ufw_delete', 0, ['num'=>(int)$n]);
  flash_set('ok', t('ufw.flash.delete_rule_queued', ['num'=>$n], 'Smazání pravidla #{num} zařazeno do fronty.'));
  header('Location: /jobs.php'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ufw_scan_ports'])) {
  csrf_check();

  $ss = [];
  $rc = run('sudo -n /usr/bin/ss -H -tulpen', $ss);

  if ($rc !== 0) {
    unset($_SESSION['ufw_scan']);
    flash_set('err', 'Sken portů selhal: ' . trim(implode("\n", $ss)));
    header('Location: /ufw.php'); exit;
  }

  $_SESSION['ufw_scan'] = $ss;
  flash_set('ok', t('ufw.flash.scan_done', [], 'Sken portů hotový'));
  header('Location: /ufw.php'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ufw_apply_ports'])) {
  csrf_check();
  $selected = $_POST['ports'] ?? [];
  if (!is_array($selected) || !$selected) { flash_set('err', t('ufw.flash.nothing_selected', [], 'Nic nebylo vybráno')); header('Location: /ufw.php'); exit; }
  $lanCidrs = detect_lan_cidrs_v4();
  $lanNet = cidr_to_network($lanCidrs[0] ?? '192.168.0.0/16') ?? '192.168.0.0/16';
  $scope = (string)($_POST['scope'] ?? 'auto');
  if (!in_array($scope, ['auto','public','lan'], true)) $scope = 'auto';
  enqueue_job($pdo, 'ufw_apply_ports', 0, ['ports'=>array_values($selected), 'lan_net'=>$lanNet, 'scope'=>$scope]);
  flash_set('ok', t('ufw.flash.selected_ports_queued', [], 'Přidání vybraných portů zařazeno do fronty.'));
  header('Location: /jobs.php'); exit;
}

/* ---------- LOAD ---------- */

$statusOut=[]; run('sudo /usr/sbin/ufw status', $statusOut);
$isActive = (bool)preg_match('~Status:\s+active~i', implode("\n",$statusOut));

$verboseOut=[]; run('sudo /usr/sbin/ufw status verbose', $verboseOut);
$numberedOut=[]; run('sudo /usr/sbin/ufw status numbered', $numberedOut);
$rules = parse_ufw_numbered($numberedOut);
$lanCidrs = detect_lan_cidrs_v4();
$lanNet   = cidr_to_network($lanCidrs[0] ?? '192.168.0.0/16') ?? '192.168.0.0/16';

$scanRaw = $_SESSION['ufw_scan'] ?? null;
$scanItems = [];

if (is_array($scanRaw)) {
  $scanItems = parse_ss_listeners($scanRaw);
}

// Přidat konfigurované porty, které se přes ss běžně neukážou.
$scanItems = array_merge($scanItems, detect_vsftpd_passive_ports());

// Dedupe podle proto + port + bind.
$dedupe = [];
foreach ($scanItems as $it) {
  $k = $it['proto'] . '|' . $it['addr'] . '|' . $it['port'];
  $dedupe[$k] = $it;
}
$scanItems = array_values($dedupe);

render($pdo, t('page.ufw.title', [], 'UFW'), function() use ($isActive, $verboseOut, $rules, $numberedOut, $scanItems, $lanNet, $lanCidrs) { ?>
  <div class="card">
    <h2><?=h(t('page.ufw.title', [], 'UFW'))?></h2>
    <p><?=h(t('common.status', [], 'Stav'))?>:
      <?php if ($isActive): ?><span class="pill ok"><?=h(t('status.active', [], 'active'))?></span>
      <?php else: ?><span class="pill err"><?=h(t('status.inactive', [], 'inactive'))?></span>
      <?php endif; ?>
    </p>

    <div class="row">
      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <button class="btn" name="ufw_enable" value="1" type="submit"><?=h(t('ufw.action.enable', [], 'Enable'))?></button>
      </form>

      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <button class="btn-danger" name="ufw_disable" value="1" type="submit"><?=h(t('ufw.action.disable', [], 'Disable'))?></button>
      </form>

      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <button class="btn2" name="ufw_reload" value="1" type="submit"><?=h(t('ufw.action.reload', [], 'Reload'))?></button>
      </form>
    </div>

    <details style="margin-top:10px">
      <summary><span class="pill run"><?=h(t('ufw.status_verbose', [], 'Status verbose'))?></span></summary>
      <pre><?=h(implode("\n",$verboseOut))?></pre>
    </details>
  </div>

  <div class="card">
    <h2><?=h(t('ufw.default_policy.heading', [], 'Default policy'))?></h2>
    <form method="post" class="row3">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div>
        <label><?=h(t('ufw.field.incoming', [], 'Incoming'))?></label>
        <select name="def_in">
          <option value="deny"><?=h(t('ufw.policy.deny', [], 'deny'))?></option>
          <option value="allow"><?=h(t('ufw.policy.allow', [], 'allow'))?></option>
          <option value="reject"><?=h(t('ufw.policy.reject', [], 'reject'))?></option>
        </select>
      </div>
      <div>
        <label><?=h(t('ufw.field.outgoing', [], 'Outgoing'))?></label>
        <select name="def_out">
          <option value="allow"><?=h(t('ufw.policy.allow', [], 'allow'))?></option>
          <option value="deny"><?=h(t('ufw.policy.deny', [], 'deny'))?></option>
          <option value="reject"><?=h(t('ufw.policy.reject', [], 'reject'))?></option>
        </select>
      </div>
      <div style="display:flex; align-items:end">
        <button class="btn" name="ufw_default" value="1" type="submit"><?=h(t('common.save', [], 'Uložit'))?></button>
      </div>
    </form>
  </div>

  <div class="card">
    <h2><?=h(t('ufw.auto_ports.heading', [], 'Auto detekce portů'))?></h2>
    <p><small><?=t('ufw.auto_ports.help', [], 'Načte naslouchající porty přes <code>ss -tulpen</code>, rozdělí je na public/LAN/localhost a dovolí je jedním klikem přidat do UFW.')?></small></p>

    <div class="row">
      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <button class="btn2" name="ufw_scan_ports" value="1" type="submit"><?=h(t('ufw.action.scan_ports', [], 'Skenovat porty'))?></button>
      </form>
      <div>
        <small><?=h(t('ufw.lan_detected', [], 'LAN detekováno'))?>: <code><?=h(implode(', ', $lanCidrs))?></code></small><br>
        <small><?=h(t('ufw.lan_rules_use', [], 'LAN pravidla použijí'))?>: <code><?=h($lanNet)?></code></small>
      </div>
    </div>

    <?php if ($scanItems): ?>
      <?php
        $groups = ['public'=>[], 'lan'=>[], 'localhost'=>[]];
        foreach ($scanItems as $it) {
          $c = classify_listener($it);
          $groups[$c][] = $it;
        }
        $labels = ['public'=>t('ufw.group.public', [], 'Veřejné (internet)'), 'lan'=>t('ufw.group.lan', [], 'LAN (privátní rozsahy)'), 'localhost'=>t('ufw.group.localhost', [], 'Localhost (jen na serveru)')];
      ?>

      <form method="post" style="margin-top:12px">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">

        <div class="row">
          <div>
            <label><?=h(t('ufw.field.scope', [], 'Jak aplikovat scope?'))?></label>
            <select name="scope">
              <option value="auto"><?=h(t('ufw.scope.auto', [], 'auto (public→public, lan→LAN)'))?></option>
              <option value="public"><?=h(t('ufw.scope.public', [], 'vše jako public (allow port/proto)'))?></option>
              <option value="lan"><?=h(t('ufw.scope.lan', ['lan'=>$lanNet], 'vše jen LAN (allow from {lan})'))?></option>
            </select>
          </div>
          <div style="display:flex; align-items:end">
            <button class="btn" name="ufw_apply_ports" value="1" type="submit"
              onclick="return confirm(<?=json_encode(t('ufw.confirm.apply_ports', [], 'Opravdu přidat vybrané porty do UFW?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('ufw.action.apply_to_ufw', [], 'Aplikovat do UFW'))?></button>
          </div>
        </div>

        <?php foreach (['public','lan','localhost'] as $g): ?>
          <details style="margin-top:10px" <?= $g==='public' ? 'open' : '' ?>>
            <summary><span class="pill <?= $g==='public' ? 'err' : ($g==='lan' ? 'run' : 'ok') ?>"><?=h($labels[$g])?></span></summary>

            <div class="table-scroll" style="margin-top:10px">
              <table>
                <thead>
                  <tr>
                    <th></th>
                    <th><?=h(t('ufw.col.proto', [], 'Proto'))?></th>
                    <th><?=h(t('ufw.col.port', [], 'Port'))?></th>
                    <th><?=h(t('ufw.col.bind', [], 'Bind'))?></th>
                    <th><?=h(t('ufw.col.process', [], 'Proces'))?></th>
                    <th><?=h(t('ufw.col.note', [], 'Pozn.'))?></th>
                  </tr>
                </thead>
                <tbody>
                  <?php if (!$groups[$g]): ?>
                    <tr><td colspan="6"><small><?=h(t('common.none', [], 'Nic'))?></small></td></tr>
                  <?php endif; ?>

                  <?php foreach ($groups[$g] as $it): ?>
                    <?php
                      $tag = risk_tag((int)$it['port'], (string)$it['proto']);
                      $token = $it['proto'].':'.token_port((string)$it['port']).':'.$g;
                    ?>
                    <tr>
                      <td>
                        <?php if ($g !== 'localhost'): ?>
                          <input type="checkbox" name="ports[]" value="<?=h($token)?>">
                        <?php else: ?>
                          <small>—</small>
                        <?php endif; ?>
                      </td>
                      <td><code><?=h($it['proto'])?></code></td>
                      <td><code><?= h((string)$it['port']) ?></code></td>
                      <td><?=h($it['addr'])?></td>
                      <td><small><?=h($it['proc'])?></small></td>
                      <td>
                        <?php if ($tag): ?>
                          <span class="pill err"><?=h($tag)?></span>
                        <?php else: ?>
                          <small> </small>
                        <?php endif; ?>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          </details>
        <?php endforeach; ?>

        <details style="margin-top:10px">
          <summary><span class="pill run"><?=h(t('common.tip', [], 'Tip'))?></span></summary>
          <pre><?=h(t('ufw.auto_ports.tip', [], "• localhost porty se do UFW nepřidávají (nemají smysl).
• SMB 139/445 a NetBIOS 137/138 nechávej jen pro LAN nebo přes VPN."))?></pre>
        </details>

      </form>
    <?php else: ?>
      <small><?=t('ufw.auto_ports.empty', [], 'Ještě nebyl proveden sken. Klikni na <b>Skenovat porty</b>.')?></small>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2><?=h(t('ufw.add_rule.heading', [], 'Přidat pravidlo'))?></h2>

    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">

      <div class="row3">
        <div>
          <label><?=h(t('common.action', [], 'Akce'))?></label>
          <select name="action">
            <option value="allow"><?=h(t('ufw.policy.allow', [], 'allow'))?></option>
            <option value="deny"><?=h(t('ufw.policy.deny', [], 'deny'))?></option>
            <option value="reject"><?=h(t('ufw.policy.reject', [], 'reject'))?></option>
            <option value="limit"><?=h(t('ufw.policy.limit', [], 'limit'))?></option>
          </select>
        </div>

        <div>
          <label><?=h(t('ufw.field.direction', [], 'Směr'))?></label>
          <select name="dir">
            <option value="in"><?=h(t('ufw.direction.in', [], 'in'))?></option>
            <option value="out"><?=h(t('ufw.direction.out', [], 'out'))?></option>
          </select>
        </div>

        <div>
          <label><?=h(t('ufw.field.proto', [], 'Proto'))?></label>
          <select name="proto">
            <option value="tcp"><?=h(t('ufw.proto.tcp', [], 'tcp'))?></option>
            <option value="udp"><?=h(t('ufw.proto.udp', [], 'udp'))?></option>
            <option value="any"><?=h(t('ufw.proto.any', [], 'any'))?></option>
          </select>
        </div>
      </div>

      <div class="row">
        <div>
          <label><?=h(t('ufw.field.port', [], 'Port'))?></label>
          <input name="port" placeholder="22" required>
        </div>
        <div>
          <label><?=h(t('ufw.field.comment', [], 'Komentář'))?></label>
          <input name="comment" placeholder="<?=h(t('ufw.placeholder.comment', [], 'SSH / Web / ...'))?>">
        </div>
      </div>

      <div class="row">
        <div>
          <label><?=h(t('ufw.field.from', [], 'FROM (jen pro IN)'))?></label>
          <input name="from" placeholder="<?=h(t('ufw.placeholder.from', [], '1.2.3.4 nebo 1.2.3.0/24'))?>">
        </div>
        <div>
          <label><?=h(t('ufw.field.to_ip', [], 'TO IP (jen pro OUT)'))?></label>
          <input name="toip" placeholder="<?=h(t('ufw.placeholder.to_ip', [], '8.8.8.8 nebo 2001:db8::/64'))?>">
        </div>
      </div>

      <button class="btn" name="ufw_add" value="1" type="submit"><?=h(t('common.add', [], 'Přidat'))?></button>
    </form>
  </div>

  <div class="card">
    <h2><?=h(t('ufw.rules.heading', [], 'Pravidla'))?></h2>

    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>#</th><th><?=h(t('ufw.col.to', [], 'To'))?></th><th><?=h(t('common.action', [], 'Akce'))?></th><th><?=h(t('ufw.col.from', [], 'From'))?></th><th></th>
          </tr>
        </thead>
        <tbody>
        <?php if (!$rules): ?>
          <tr><td colspan="5"><small><?=h(t('ufw.rules.empty', [], 'Žádná pravidla / nebo neparsovatelný výstup.'))?></small></td></tr>
        <?php endif; ?>

        <?php foreach ($rules as $r): ?>
          <tr>
            <td><code><?= (int)$r['num'] ?></code></td>
            <td><?= h($r['to']) ?></td>
            <td><?= h($r['action']) ?></td>
            <td><?= h($r['from']) ?></td>
            <td style="text-align:right">
              <a class="btn-danger" style="padding:6px 10px; border-radius:10px; display:inline-block"
                 href="/ufw.php?del=<?= (int)$r['num'] ?>"
                 onclick="return confirm(<?=json_encode(t('ufw.confirm.delete_rule', ['num'=>(int)$r['num']], 'Smazat pravidlo #{num}?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('common.delete', [], 'Smazat'))?></a>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <details style="margin-top:10px">
      <summary><span class="pill run"><?=h(t('common.raw', [], 'Raw'))?></span></summary>
      <pre><?=h(implode("\n",$numberedOut))?></pre>
    </details>
  </div>
<?php });

<?php
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

$chain = 'ORISBLOCK';

function sh(string $s): string { return escapeshellarg($s); }
function run(string $cmd, array &$out=null): int { $o=[]; $rc=0; exec($cmd.' 2>&1', $o, $rc); if ($out!==null) $out=$o; return $rc; }
function enqueue_job(PDO $pdo, string $type, int $refId=0, array $payload=[]): void {
  $st=$pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES(?,?, 'queued', ?)");
  $st->execute([$type,$refId,json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}
function valid_ip_or_cidr(string $v): bool {
  $v = trim($v); if ($v === '') return false;
  if (filter_var($v, FILTER_VALIDATE_IP)) return true;
  if (!str_contains($v, '/')) return false;
  [$ip, $mask] = explode('/', $v, 2);
  if (!filter_var($ip, FILTER_VALIDATE_IP) || !ctype_digit($mask)) return false;
  $m = (int)$mask; $is4 = (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
  return $is4 ? ($m >= 0 && $m <= 32) : ($m >= 0 && $m <= 128);
}
function f2b_status_jail(string $jail): array {
  $out = []; $rc = run('sudo /usr/bin/fail2ban-client status ' . sh($jail), $out);
  if ($rc !== 0) return ['ok'=>false, 'text'=>implode("\n",$out), 'banned'=>[]];
  $banned = [];
  foreach ($out as $line) {
    if (stripos($line, 'Banned IP list') !== false) {
      $parts = explode(':', $line, 2);
      if (isset($parts[1])) $banned = array_values(array_filter(preg_split('/\s+/', trim($parts[1])), fn($x)=>$x!==''));
    }
  }
  return ['ok'=>true, 'text'=>implode("\n",$out), 'banned'=>$banned];
}
function parse_jails(array $statusLines): array {
  $txt = implode("\n", $statusLines);
  if (preg_match('~Jail list:\s*(.+)$~m', $txt, $m)) return array_values(array_filter(array_map('trim', explode(',', $m[1]))));
  return [];
}
function setting_bool(PDO $pdo, string $k, string $def='0'): bool { return (setting($pdo,$k,$def) ?: $def) === '1'; }
function setting_int(PDO $pdo, string $k, string $def): int { return (int)(setting($pdo,$k,$def) ?: $def); }

function fw_confirm(string $key, array $vars, string $fallback): string {
  return h(json_encode(t($key, $vars, $fallback), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}

function normalize_ip_list(string $text): array {
  $items = [];

  foreach (preg_split('/\R/', $text) ?: [] as $line) {
    $line = preg_replace('~#.*$~', '', (string)$line);
    foreach (preg_split('/[\s,;]+/', trim((string)$line)) ?: [] as $part) {
      $part = trim((string)$part);
      if ($part !== '') $items[] = $part;
    }
  }

  $valid = [];
  $invalid = [];

  foreach ($items as $item) {
    if (!valid_ip_or_cidr($item)) {
      $invalid[] = $item;
      continue;
    }

    if (!in_array($item, $valid, true)) {
      $valid[] = $item;
    }
  }

  return [$valid, $invalid];
}

function ip_list_text(array $items): string {
  return implode("\n", array_values(array_filter(array_map('strval', $items), fn($x) => trim($x) !== '')));
}

function fail2ban_jails_from_settings(PDO $pdo, array $jailDefaults): array {
  $jails = $jailDefaults;
  $jails['oris-nginx-phpmyadmin'] = setting_bool($pdo,'security_fail2ban_phpmyadmin_enabled','1');
  $jails['oris-nginx-badbots'] = setting_bool($pdo,'security_fail2ban_badbots_enabled','1');
  $jails['recidive'] = setting_bool($pdo,'security_fail2ban_recidive_enabled','1');
  $jails['oris-perm'] = setting_bool($pdo,'security_fail2ban_oris_perm_enabled','1');
  return $jails;
}

function fail2ban_payload_from_settings(PDO $pdo, array $jailDefaults, ?array $overrideIgnoreip=null): array {
  $ignoreDefault = '127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16';
  if ($overrideIgnoreip === null) {
    [$ignoreip, $invalid] = normalize_ip_list((string)(setting($pdo,'security_fail2ban_ignoreip',$ignoreDefault) ?: $ignoreDefault));
    if ($invalid) $ignoreip = ['127.0.0.1/8', '::1'];
  } else {
    $ignoreip = $overrideIgnoreip;
  }

  return [
    'maxretry'=>setting_int($pdo,'security_fail2ban_maxretry','5'),
    'findtime'=>setting_int($pdo,'security_fail2ban_findtime','600'),
    'bantime'=>setting_int($pdo,'security_fail2ban_bantime','3600'),
    'recidive_maxretry'=>setting_int($pdo,'security_fail2ban_recidive_maxretry','5'),
    'recidive_findtime'=>setting($pdo,'security_fail2ban_recidive_findtime','7d') ?: '7d',
    'recidive_bantime'=>setting($pdo,'security_fail2ban_recidive_bantime','-1') ?: '-1',
    'perm_bantime'=>setting($pdo,'security_fail2ban_perm_bantime','-1') ?: '-1',
    'ignoreip'=>$ignoreip,
    'jails'=>fail2ban_jails_from_settings($pdo, $jailDefaults),
  ];
}

$jailDefaults = [
  'sshd' => true,
  'oris-nginx-phpmyadmin' => true,
  'oris-nginx-badbots' => true,
  'postfix' => false,
  'postfix-sasl' => false,
  'dovecot' => false,
  'recidive' => true,
  'oris-perm' => true,
];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['fw_add'])) {
  csrf_check(); $ip = trim((string)($_POST['fw_ip'] ?? ''));
  if (!valid_ip_or_cidr($ip)) { flash_set('err', t('firewall.flash.invalid_ip_cidr', [], 'Neplatná IP/CIDR')); header('Location: /firewall.php'); exit; }
  enqueue_job($pdo, 'firewall_block_ip', 0, ['ip'=>$ip]);
  flash_set('ok', t('firewall.flash.block_queued', [], 'Blokace IP zařazena do fronty.')); header('Location: /jobs.php'); exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['f2b_apply'])) {
  csrf_check();
  $jails=[]; foreach (array_keys($jailDefaults) as $j) $jails[$j] = !empty($_POST['j_'.$j]);

  [$ignoreip, $invalidIgnoreip] = normalize_ip_list((string)($_POST['ignoreip'] ?? ''));
  if ($invalidIgnoreip) {
    flash_set('err', t('firewall.flash.invalid_whitelist_item', ['items' => implode(', ', $invalidIgnoreip)], 'Neplatná položka v bílé listině: {items}'));
    header('Location:/firewall.php'); exit;
  }

  $payload = [
    'maxretry'=>(int)($_POST['maxretry'] ?? 5),
    'findtime'=>(int)($_POST['findtime'] ?? 600),
    'bantime'=>(int)($_POST['bantime'] ?? 3600),
    'recidive_maxretry'=>(int)($_POST['recidive_maxretry'] ?? 5),
    'recidive_findtime'=>trim((string)($_POST['recidive_findtime'] ?? '7d')),
    'recidive_bantime'=>trim((string)($_POST['recidive_bantime'] ?? '-1')),
    'perm_bantime'=>trim((string)($_POST['perm_bantime'] ?? '-1')),
    'ignoreip'=>$ignoreip,
    'jails'=>$jails,
  ];
  set_setting($pdo,'security_fail2ban_maxretry',(string)$payload['maxretry']);
  set_setting($pdo,'security_fail2ban_findtime',(string)$payload['findtime']);
  set_setting($pdo,'security_fail2ban_bantime',(string)$payload['bantime']);
  set_setting($pdo,'security_fail2ban_recidive_maxretry',(string)$payload['recidive_maxretry']);
  set_setting($pdo,'security_fail2ban_recidive_findtime',(string)$payload['recidive_findtime']);
  set_setting($pdo,'security_fail2ban_recidive_bantime',(string)$payload['recidive_bantime']);
  set_setting($pdo,'security_fail2ban_perm_bantime',(string)$payload['perm_bantime']);
  set_setting($pdo,'security_fail2ban_ignoreip',implode(' ', $ignoreip));
  set_setting($pdo,'security_fail2ban_recidive_enabled',!empty($jails['recidive'])?'1':'0');
  set_setting($pdo,'security_fail2ban_oris_perm_enabled',!empty($jails['oris-perm'])?'1':'0');
  set_setting($pdo,'security_fail2ban_phpmyadmin_enabled',!empty($jails['oris-nginx-phpmyadmin'])?'1':'0');
  set_setting($pdo,'security_fail2ban_badbots_enabled',!empty($jails['oris-nginx-badbots'])?'1':'0');
  enqueue_job($pdo, 'fail2ban_apply_panel_config', 0, $payload);
  flash_set('ok', t('firewall.flash.fail2ban_apply_queued', [], 'Fail2ban konfigurace zařazena do fronty.')); header('Location: /jobs.php'); exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['f2b_whitelist_apply'])) {
  csrf_check();

  [$ignoreip, $invalidIgnoreip] = normalize_ip_list((string)($_POST['ignoreip'] ?? ''));
  if ($invalidIgnoreip) {
    flash_set('err', t('firewall.flash.invalid_whitelist_item', ['items' => implode(', ', $invalidIgnoreip)], 'Neplatná položka v bílé listině: {items}'));
    header('Location:/firewall.php'); exit;
  }

  set_setting($pdo,'security_fail2ban_ignoreip',implode(' ', $ignoreip));
  enqueue_job($pdo, 'fail2ban_apply_panel_config', 0, fail2ban_payload_from_settings($pdo, $jailDefaults, $ignoreip));
  flash_set('ok', t('firewall.flash.whitelist_apply_queued', [], 'Bílá listina Fail2ban zařazena do fronty.')); header('Location:/jobs.php'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['f2b_whitelist_ip'])) {
  csrf_check();
  $ip = trim((string)($_POST['ip'] ?? ''));
  $jail = trim((string)($_POST['jail'] ?? ''));

  if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    flash_set('err', t('firewall.flash.invalid_whitelist_ip', [], 'Neplatná IP pro bílou listinu')); header('Location:/firewall.php'); exit;
  }
  if ($jail !== '' && !preg_match('~^[A-Za-z0-9_.:-]+$~',$jail)) {
    flash_set('err', t('firewall.flash.invalid_jail', [], 'Neplatný jail')); header('Location:/firewall.php'); exit;
  }

  $ignoreDefault = '127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16';
  [$ignoreip, $invalidIgnoreip] = normalize_ip_list((string)(setting($pdo,'security_fail2ban_ignoreip',$ignoreDefault) ?: $ignoreDefault));
  if (!in_array($ip, $ignoreip, true)) $ignoreip[] = $ip;

  set_setting($pdo,'security_fail2ban_ignoreip',implode(' ', $ignoreip));
  enqueue_job($pdo, 'fail2ban_apply_panel_config', 0, fail2ban_payload_from_settings($pdo, $jailDefaults, $ignoreip));
  if ($jail !== '') {
    enqueue_job($pdo, 'fail2ban_unban_ip', 0, ['jail'=>$jail,'ip'=>$ip]);
  }

  flash_set('ok', t('firewall.flash.ip_whitelisted_queued', [], 'IP přidána na bílou listinu a změna zařazena do fronty.')); header('Location:/jobs.php'); exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['f2b_unban'])) {
  csrf_check(); $jail=(string)($_POST['jail'] ?? ''); $ip=(string)($_POST['ip'] ?? '');
  if (!preg_match('~^[A-Za-z0-9_.:-]+$~',$jail) || !filter_var($ip, FILTER_VALIDATE_IP)) { flash_set('err', t('firewall.flash.invalid_unban', [], 'Neplatný unban')); header('Location:/firewall.php'); exit; }
  enqueue_job($pdo, 'fail2ban_unban_ip', 0, ['jail'=>$jail,'ip'=>$ip]);
  flash_set('ok', t('firewall.flash.unban_queued', [], 'Unban zařazen do fronty.')); header('Location:/jobs.php'); exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['f2b_perm_ban'])) {
  csrf_check(); $ip=trim((string)($_POST['perm_ip'] ?? ''));
  if (!filter_var($ip, FILTER_VALIDATE_IP)) { flash_set('err', t('firewall.flash.invalid_perm_ip', [], 'Neplatná IP pro permanentní ban')); header('Location:/firewall.php'); exit; }
  enqueue_job($pdo, 'fail2ban_ban_ip', 0, ['jail'=>'oris-perm','ip'=>$ip]);
  flash_set('ok', t('firewall.flash.perm_ban_queued', [], 'Permanentní ban zařazen do fronty.')); header('Location:/jobs.php'); exit;
}
if (isset($_GET['del']) && $_GET['del'] !== '') {
  $ip = (string)$_GET['del'];
  if (valid_ip_or_cidr($ip)) { enqueue_job($pdo, 'firewall_unblock_ip', 0, ['ip'=>$ip]); flash_set('ok', t('firewall.flash.unblock_queued', [], 'Odebrání IP zařazeno do fronty.')); header('Location:/jobs.php'); exit; }
  flash_set('err', t('firewall.flash.invalid_ip', [], 'Neplatná IP')); header('Location:/firewall.php'); exit;
}

$blocked=[]; $out=[];
if (run('sudo /usr/sbin/iptables -S ' . $chain, $out) !== 0) run('sudo /sbin/iptables -S ' . $chain, $out);
foreach ($out as $line) if (preg_match('~-s\s+([0-9a-fA-F\.:/]+)~', $line, $m)) $blocked[]=$m[1];
$out6=[]; if (run('sudo /usr/sbin/ip6tables -S ' . $chain, $out6) !== 0) run('sudo /sbin/ip6tables -S ' . $chain, $out6);
foreach ($out6 as $line) if (preg_match('~-s\s+([0-9a-fA-F\.:/]+)~', $line, $m)) $blocked[]=$m[1];
$blocked=array_values(array_unique($blocked));

$st_main=[]; run('sudo /usr/bin/fail2ban-client status', $st_main);
$activeJails = parse_jails($st_main);
$jails_for_tables = array_values(array_unique(array_merge(['sshd','oris-nginx-phpmyadmin','oris-nginx-badbots','oris-perm'], $activeJails)));
$st=[]; foreach($jails_for_tables as $jn) $st[$jn]=f2b_status_jail($jn);

$cfg = [
  'maxretry'=>setting_int($pdo,'security_fail2ban_maxretry','5'),
  'findtime'=>setting_int($pdo,'security_fail2ban_findtime','600'),
  'bantime'=>setting_int($pdo,'security_fail2ban_bantime','3600'),
  'recidive_maxretry'=>setting_int($pdo,'security_fail2ban_recidive_maxretry','5'),
  'recidive_findtime'=>setting($pdo,'security_fail2ban_recidive_findtime','7d') ?: '7d',
  'recidive_bantime'=>setting($pdo,'security_fail2ban_recidive_bantime','-1') ?: '-1',
  'perm_bantime'=>setting($pdo,'security_fail2ban_perm_bantime','-1') ?: '-1',
  'ignoreip'=>[],
  'jails'=>$jailDefaults,
];
$cfg['jails']['oris-nginx-phpmyadmin'] = setting_bool($pdo,'security_fail2ban_phpmyadmin_enabled','1');
$cfg['jails']['oris-nginx-badbots'] = setting_bool($pdo,'security_fail2ban_badbots_enabled','1');
$cfg['jails']['recidive'] = setting_bool($pdo,'security_fail2ban_recidive_enabled','1');
$cfg['jails']['oris-perm'] = setting_bool($pdo,'security_fail2ban_oris_perm_enabled','1');
[$cfg['ignoreip'], $cfgIgnoreInvalid] = normalize_ip_list((string)(setting($pdo,'security_fail2ban_ignoreip','127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16') ?: ''));

render($pdo, t('page.firewall.title', [], 'Firewall / Fail2ban'), function() use ($blocked,$cfg,$st_main,$st,$jails_for_tables) { ?>
  <div class="card">
    <h2><?=h(t('page.firewall.title', [], 'Firewall / Fail2ban'))?></h2>
    <small><?=h(t('firewall.intro', [], 'Detailní stránka z původního panelu. Změny se už nepouští přímo z PHP, ale přes Python provisioner/job frontu.'))?></small>
  </div>

  <div class="card">
    <h3><?=h(t('firewall.manual_block.heading', [], 'Ruční blokace IP (iptables ORISBLOCK)'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row3">
        <div style="grid-column:span 2">
          <label><?=h(t('firewall.ip_cidr', [], 'IP / CIDR'))?></label>
          <input name="fw_ip" placeholder="<?=h(t('firewall.ip_cidr.placeholder', [], '1.2.3.4 nebo 1.2.3.0/24'))?>" required>
        </div>
        <div style="display:flex;align-items:flex-end">
          <button class="btn" name="fw_add" value="1"><?=h(t('common.add', [], 'Přidat'))?></button>
        </div>
      </div>
    </form>
    <table>
      <tr><th><?=h(t('common.ip', [], 'IP'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
      <?php if(!$blocked): ?>
        <tr><td colspan="2"><?=h(t('firewall.no_blocked_ips', [], 'Žádné blokované IP'))?></td></tr>
      <?php else: foreach($blocked as $ip): ?>
        <tr>
          <td><?=h($ip)?></td>
          <td><a class="btn-danger" href="?del=<?=urlencode($ip)?>" onclick="return confirm(<?=fw_confirm('firewall.confirm.remove_ip', ['ip' => $ip], 'Odebrat {ip}?')?>)"><?=h(t('common.delete', [], 'Smazat'))?></a></td>
        </tr>
      <?php endforeach; endif; ?>
    </table>
  </div>

  <div class="card">
    <h3><?=h(t('firewall.fail2ban_settings.heading', [], 'Fail2ban nastavení'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row3">
        <div><label><?=h(t('firewall.maxretry', [], 'maxretry'))?></label><input type="number" min="1" name="maxretry" value="<?=h((string)$cfg['maxretry'])?>"></div>
        <div><label><?=h(t('firewall.findtime_seconds', [], 'findtime (s)'))?></label><input type="number" min="1" name="findtime" value="<?=h((string)$cfg['findtime'])?>"></div>
        <div><label><?=h(t('firewall.bantime_seconds', [], 'bantime (s)'))?></label><input type="number" min="1" name="bantime" value="<?=h((string)$cfg['bantime'])?>"></div>
      </div>
      <div class="row" style="margin-top:12px">
        <div>
          <strong><?=h(t('firewall.section.web_nginx', [], 'Web/Nginx'))?></strong><br>
          <label><input type="checkbox" name="j_oris-nginx-phpmyadmin" <?=!empty($cfg['jails']['oris-nginx-phpmyadmin'])?'checked':''?>> <?=h(t('firewall.jail.phpmyadmin', [], 'phpMyAdmin'))?></label><br>
          <label><input type="checkbox" name="j_oris-nginx-badbots" <?=!empty($cfg['jails']['oris-nginx-badbots'])?'checked':''?>> <?=h(t('firewall.jail.badbots', [], 'badbots/scannery'))?></label>
        </div>
        <div>
          <strong><?=h(t('firewall.section.services', [], 'Služby'))?></strong><br>
          <label><input type="checkbox" name="j_sshd" <?=!empty($cfg['jails']['sshd'])?'checked':''?>> sshd</label><br>
          <label><input type="checkbox" name="j_postfix" <?=!empty($cfg['jails']['postfix'])?'checked':''?>> postfix</label><br>
          <label><input type="checkbox" name="j_postfix-sasl" <?=!empty($cfg['jails']['postfix-sasl'])?'checked':''?>> postfix-sasl</label><br>
          <label><input type="checkbox" name="j_dovecot" <?=!empty($cfg['jails']['dovecot'])?'checked':''?>> dovecot</label>
        </div>
        <div>
          <strong><?=h(t('firewall.section.escalation', [], 'Escalace'))?></strong><br>
          <label><input type="checkbox" name="j_recidive" <?=!empty($cfg['jails']['recidive'])?'checked':''?>> <?=h(t('firewall.jail.recidive_auto_perm', [], 'recidive auto permanent'))?></label><br>
          <label><input type="checkbox" name="j_oris-perm" <?=!empty($cfg['jails']['oris-perm'])?'checked':''?>> <?=h(t('firewall.jail.oris_perm_manual', [], 'oris-perm ruční permanent'))?></label>
        </div>
      </div>
      <h4 style="margin-top:14px"><?=h(t('firewall.permanent_settings.heading', [], 'Nastavení permanentních blokací'))?></h4>
      <div class="row3">
        <div><label><?=h(t('firewall.recidive_maxretry', [], 'Recidive počet banů'))?></label><input type="number" min="1" name="recidive_maxretry" value="<?=h((string)$cfg['recidive_maxretry'])?>"><small><?=h(t('firewall.recidive_maxretry.help', [], 'Po kolika banech se IP přesune do permanentního banu.'))?></small></div>
        <div><label><?=h(t('firewall.recidive_findtime', [], 'Recidive období'))?></label><input name="recidive_findtime" value="<?=h((string)$cfg['recidive_findtime'])?>"><small><?=h(t('firewall.recidive_findtime.help', [], 'Např. 7d, 24h, 604800.'))?></small></div>
        <div><label><?=h(t('firewall.recidive_bantime', [], 'Recidive ban'))?></label><input name="recidive_bantime" value="<?=h((string)$cfg['recidive_bantime'])?>"><small><?=h(t('firewall.permanent_help', [], '-1 = permanentně.'))?></small></div>
      </div>
      <div class="row3" style="margin-top:10px">
        <div><label><?=h(t('firewall.manual_perm_bantime', [], 'Ruční permanentní ban'))?></label><input name="perm_bantime" value="<?=h((string)$cfg['perm_bantime'])?>"><small><?=h(t('firewall.permanent_help', [], '-1 = permanentně.'))?></small></div>
      </div>

      <h4 style="margin-top:14px"><?=h(t('firewall.whitelist.heading', [], 'Bílá listina Fail2ban'))?></h4>
      <label><?=h(t('firewall.ignoreip', [], 'ignoreip'))?></label>
      <textarea name="ignoreip" rows="6" placeholder="127.0.0.1/8&#10;::1&#10;89.221.216.232&#10;10.42.0.0/24"><?=h(ip_list_text($cfg['ignoreip']))?></textarea>
      <small><?=h(t('firewall.ignoreip.help', [], 'Zadej jednu IP/CIDR na řádek, případně oddělené mezerou nebo čárkou. Tyto IP nebude Fail2ban banovat v žádném jailu.'))?></small>

      <p style="margin-top:12px"><button class="btn" name="f2b_apply" value="1"><?=h(t('firewall.apply_via_provisioner', [], 'Aplikovat přes provisioner'))?></button></p>
    </form>
    <form method="post" style="margin-top:10px">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="ignoreip" value="<?=h(ip_list_text($cfg['ignoreip']))?>">
      <button class="btn2" name="f2b_whitelist_apply" value="1"><?=h(t('firewall.save_apply_whitelist_only', [], 'Pouze uložit/aplikovat bílou listinu'))?></button>
    </form>

    <h4><?=h(t('firewall.perm_ban.heading', [], 'Permanentní ban (oris-perm)'))?></h4>
    <form method="post" class="row">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div><label><?=h(t('common.ip', [], 'IP'))?></label><input name="perm_ip" placeholder="1.2.3.4"></div>
      <div style="align-self:end"><button class="btn-danger" name="f2b_perm_ban" value="1"><?=h(t('firewall.permanent_ban_button', [], 'Permanentní ban'))?></button></div>
    </form>
    <h4 style="margin-top:14px"><?=h(t('firewall.fail2ban_status.heading', [], 'Fail2ban status'))?></h4>
    <pre style="white-space:pre-wrap"><?=h(implode("\n",$st_main))?></pre>
    <?php foreach($jails_for_tables as $jn): $stj=$st[$jn]??['ok'=>false,'text'=>'','banned'=>[]]; ?>
      <h4 style="margin-top:14px"><?=h(t('firewall.banned_ip_title', ['jail' => $jn], '{jail} banned IP'))?></h4>
      <?php if(!$stj['ok']): ?>
        <pre style="white-space:pre-wrap"><?=h($stj['text'])?></pre>
      <?php else: ?>
        <table>
          <tr><th><?=h(t('common.ip', [], 'IP'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
          <?php if(!$stj['banned']): ?>
            <tr><td colspan="2"><?=h(t('common.none', [], 'Žádné'))?></td></tr>
          <?php else: foreach($stj['banned'] as $ip): ?>
            <tr>
              <td><?=h($ip)?></td>
              <td>
                <form method="post" style="display:inline">
                  <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                  <input type="hidden" name="jail" value="<?=h($jn)?>">
                  <input type="hidden" name="ip" value="<?=h($ip)?>">
                  <button class="btn2" name="f2b_unban" value="1"><?=h(t('firewall.unban_button', [], 'Unban'))?></button>
                </form>
                <form method="post" style="display:inline" onsubmit="return confirm(<?=fw_confirm('firewall.confirm.whitelist_and_unban', ['ip' => $ip], 'Přidat {ip} na bílou listinu a odblokovat?')?>)">
                  <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                  <input type="hidden" name="jail" value="<?=h($jn)?>">
                  <input type="hidden" name="ip" value="<?=h($ip)?>">
                  <button class="btn2" name="f2b_whitelist_ip" value="1"><?=h(t('firewall.whitelist_unban_button', [], 'Bílá + unban'))?></button>
                </form>
                <?php if($jn !== 'oris-perm'): ?>
                  <form method="post" style="display:inline" onsubmit="return confirm(<?=fw_confirm('firewall.confirm.permanent_ban', ['ip' => $ip], 'Dát {ip} na permanentní ban?')?>)">
                    <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                    <input type="hidden" name="perm_ip" value="<?=h($ip)?>">
                    <button class="btn-danger" name="f2b_perm_ban" value="1"><?=h(t('firewall.permanently_button', [], 'Permanentně'))?></button>
                  </form>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; endif; ?>
        </table>
      <?php endif; ?>
    <?php endforeach; ?>
  </div>
<?php });

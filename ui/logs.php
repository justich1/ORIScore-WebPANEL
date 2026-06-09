<?php
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

/** @var PDO $pdo */

$logWrapper = realpath(__DIR__ . '/extras/oris-log') ?: (__DIR__ . '/extras/oris-log');

// Zdroje logů (musí odpovídat whitelistu v oris-log)
$sources = [
  // systemd units
  'unit:nginx'        => ['key' => 'logs.source.unit_nginx', 'label' => 'NGINX (journal)'],
  'unit:php8.2-fpm'   => ['key' => 'logs.source.unit_php82', 'label' => 'PHP-FPM 8.2 (journal)'],
  'unit:php8.3-fpm'   => ['key' => 'logs.source.unit_php83', 'label' => 'PHP-FPM 8.3 (journal)'],
  'unit:php8.4-fpm'   => ['key' => 'logs.source.unit_php84', 'label' => 'PHP-FPM 8.4 (journal)'],
  'unit:mariadb'      => ['key' => 'logs.source.unit_mariadb', 'label' => 'MariaDB (journal)'],
  'unit:postfix'      => ['key' => 'logs.source.unit_postfix', 'label' => 'Postfix (journal)'],
  'unit:dovecot'      => ['key' => 'logs.source.unit_dovecot', 'label' => 'Dovecot (journal)'],
  'unit:rspamd'       => ['key' => 'logs.source.unit_rspamd', 'label' => 'Rspamd (journal)'],
  'unit:fail2ban'     => ['key' => 'logs.source.unit_fail2ban', 'label' => 'Fail2ban (journal)'],
  'unit:redis-server' => ['key' => 'logs.source.unit_redis', 'label' => 'Redis (journal)'],
  'unit:vsftpd'       => ['key' => 'logs.source.unit_vsftpd', 'label' => 'VSFTPD (journal)'],
  'unit:cron'         => ['key' => 'logs.source.unit_cron', 'label' => 'Cron (journal)'],
  'unit:wg-quick@wg0' => ['key' => 'logs.source.unit_wireguard', 'label' => 'WireGuard wg0 (journal)'],
  'unit:oris-provisioner'  => ['key' => 'logs.source.unit_oris_provisioner', 'label' => 'ORIS provisioner (journal)'],
  'unit:oris-stats-worker' => ['key' => 'logs.source.unit_oris_stats_worker', 'label' => 'ORIS stats worker (journal)'],

  // files
  'file:nginx_error'      => ['key' => 'logs.source.file_nginx_error', 'label' => 'nginx/error.log'],
  'file:nginx_access'     => ['key' => 'logs.source.file_nginx_access', 'label' => 'nginx/access.log'],
  'file:mail'             => ['key' => 'logs.source.file_mail', 'label' => 'mail.log'],
  'file:syslog'           => ['key' => 'logs.source.file_syslog', 'label' => 'syslog'],
  'file:auth'             => ['key' => 'logs.source.file_auth', 'label' => 'auth.log'],
  'file:fail2ban'         => ['key' => 'logs.source.file_fail2ban', 'label' => 'fail2ban.log'],
  'file:oris_provisioner' => ['key' => 'logs.source.file_oris_provisioner', 'label' => 'oris-core/provisioner-python.log'],
  'file:oris_security'    => ['key' => 'logs.source.file_oris_security', 'label' => 'oris-security.log'],
];

function run_cmd(array $cmd): array {
  $p = proc_open($cmd, [1=>['pipe','w'], 2=>['pipe','w']], $pipes);
  if (!is_resource($p)) return ['code'=>127,'out'=>'','err'=>'proc_open failed'];
  $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
  $err = stream_get_contents($pipes[2]); fclose($pipes[2]);
  $code = proc_close($p);
  return ['code'=>$code, 'out'=>$out ?? '', 'err'=>$err ?? ''];
}

function logs_source_label(array $meta): string {
  return t((string)$meta['key'], [], (string)$meta['label']);
}

$src = (string)($_GET['src'] ?? 'unit:nginx');
$lines = (int)($_GET['n'] ?? 200);
if ($lines < 20) $lines = 20;
if ($lines > 5000) $lines = 5000;

$grep = trim((string)($_GET['q'] ?? ''));
$grep = mb_substr($grep, 0, 80); // limit

$refresh = (int)($_GET['r'] ?? 0); // seconds
if ($refresh < 0) $refresh = 0;
if ($refresh > 60) $refresh = 60;

$logText = '';
$errText = '';

if (!isset($sources[$src])) {
  $errText = t('logs.err.invalid_source', [], 'Neplatný zdroj logu.');
} else {
  if (!is_file($logWrapper)) {
    $errText = t('logs.err.missing_wrapper', ['path' => $logWrapper], 'Chybí wrapper: {path}');
  } else {
    [$mode, $target] = explode(':', $src, 2);
    $cmd = ['/usr/bin/sudo', '-n', $logWrapper, $mode, $target, (string)$lines];
    $r = run_cmd($cmd);

    if ($r['code'] !== 0) {
      $errText = trim($r['err'] ?: $r['out']);
      if ($errText === '') $errText = t('logs.err.cannot_read', [], 'Nelze načíst log.');
    } else {
      $logText = $r['out'];
      if ($grep !== '') {
        $filtered = [];
        foreach (preg_split("~\r?\n~", $logText) as $ln) {
          if (stripos($ln, $grep) !== false) $filtered[] = $ln;
        }
        $logText = implode("\n", $filtered);
      }
    }
  }
}

render($pdo, t('page.logs.title', [], 'Logy'), function() use ($sources, $src, $lines, $grep, $refresh, $logText, $errText) { ?>
  <?php if ($refresh > 0): ?>
    <script>
      setTimeout(() => { window.location.reload(); }, <?= (int)$refresh * 1000 ?>);
    </script>
  <?php endif; ?>

  <div class="card">
    <h2><?=h(t('page.logs.title', [], 'Logy'))?></h2>
    <small><?=h(t('logs.help', [], 'Čtení přes whitelist wrapper'))?> <code>oris-log</code>. <?=h(t('logs.help2', [], 'Podporuje journal (systemd) i vybrané soubory v /var/log.'))?></small>
  </div>

  <div class="card">
    <form method="get" style="display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end">
      <label><?=h(t('logs.field.source', [], 'Zdroj'))?><br>
        <select name="src">
          <?php foreach($sources as $k=>$meta): ?>
            <option value="<?=h($k)?>" <?= $k===$src?'selected':'' ?>><?=h(logs_source_label($meta))?></option>
          <?php endforeach; ?>
        </select>
      </label>

      <label><?=h(t('logs.field.lines', [], 'Řádků'))?><br>
        <select name="n">
          <?php foreach([50,100,200,500,1000,2000,5000] as $n): ?>
            <option value="<?=$n?>" <?= $n===$lines?'selected':'' ?>><?=$n?></option>
          <?php endforeach; ?>
        </select>
      </label>

      <label><?=h(t('logs.field.filter', [], 'Filtr (contains)'))?><br>
        <input name="q" value="<?=h($grep)?>" placeholder="<?=h(t('logs.placeholder.filter', [], 'např. error, login, denied'))?>">
      </label>

      <label><?=h(t('logs.field.auto_refresh', [], 'Auto-refresh (s)'))?><br>
        <select name="r">
          <?php foreach([0,2,5,10,15,30,60] as $s): ?>
            <option value="<?=$s?>" <?= $s===$refresh?'selected':'' ?>><?=$s?></option>
          <?php endforeach; ?>
        </select>
      </label>

      <button class="btn" type="submit"><?=h(t('common.load', [], 'Načíst'))?></button>
      <a class="btn" href="logs.php"><?=h(t('common.reset', [], 'Reset'))?></a>
    </form>
  </div>

  <div class="card">
    <?php if($errText): ?>
      <p class="pill err"><?=h($errText)?></p>
    <?php else: ?>
      <pre style="max-height:70vh; overflow:auto; white-space:pre;"><?=h($logText !== '' ? $logText : t('logs.empty', [], '(žádné řádky)'))?></pre>
    <?php endif; ?>
  </div>
<?php });

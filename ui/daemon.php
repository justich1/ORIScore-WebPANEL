<?php

declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

/** @var PDO $pdo */

function enqueue_job(PDO $pdo, string $type, int $refId = 0, array $payload = []): void {
  $st = $pdo->prepare("INSERT INTO jobs(type, ref_id, status, payload) VALUES(?, ?, 'queued', ?)");
  $st->execute([$type, $refId, json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}

function daemon_action_label(string $action): string {
  return t('daemon.action.' . $action, [], ucfirst($action));
}

function daemon_state_label(string $state): string {
  return t('daemon.state.' . $state, [], $state);
}

function daemon_confirm(string $action, string $unit): string {
  return h(json_encode(
    t('daemon.confirm.service_action', ['action' => daemon_action_label($action), 'unit' => $unit], 'Provést akci {action} pro unit {unit}?'),
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
  ));
}

$services = [
  ['key' => 'nginx',        'label' => 'NGINX',          'hint' => 'nginx'],
  ['key' => 'php-fpm',      'label' => 'PHP-FPM',        'hint' => 'auto php*-fpm'],
  ['key' => 'mariadb',      'label' => 'MariaDB',        'hint' => 'mariadb'],
  ['key' => 'postfix',      'label' => 'Postfix',        'hint' => 'postfix'],
  ['key' => 'dovecot',      'label' => 'Dovecot',        'hint' => 'dovecot'],
  ['key' => 'rspamd',       'label' => 'Rspamd',         'hint' => 'rspamd'],
  ['key' => 'redis',        'label' => 'Redis',          'hint' => 'redis-server'],
  ['key' => 'fail2ban',     'label' => 'Fail2ban',       'hint' => 'fail2ban'],
  ['key' => 'ufw',          'label' => 'UFW',            'hint' => 'ufw'],
  ['key' => 'vsftpd',       'label' => 'VSFTPD',         'hint' => 'vsftpd'],
  ['key' => 'cron',         'label' => 'Cron',           'hint' => 'cron'],
  ['key' => 'wireguard',    'label' => 'WireGuard wg0',  'hint' => 'wg-quick@wg0'],
  ['key' => 'provisioner',  'label' => 'ORIS Provisioner', 'hint' => 'oris-provisioner'],
  ['key' => 'stats-worker', 'label' => 'ORIS Stats Worker', 'hint' => 'oris-stats-worker'],
];

$allowedKeys = array_flip(array_map(fn($s) => $s['key'], $services));
$allowedActions = array_flip(['start', 'stop', 'restart', 'reload']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();
  $action = (string)($_POST['action'] ?? '');

  if ($action === 'refresh') {
    enqueue_job($pdo, 'service_status_refresh');
    flash_set('ok', t('daemon.flash.refresh_queued', [], 'Aktualizace stavů služeb zařazena do fronty.'));
    header('Location: /jobs.php');
    exit;
  }

  if ($action === 'service_do') {
    $key = (string)($_POST['service_key'] ?? '');
    $do = (string)($_POST['do'] ?? '');

    if ($key === '' || !isset($allowedKeys[$key])) {
      flash_set('err', t('daemon.flash.invalid_service', [], 'Neplatná služba.'));
      header('Location: /daemon.php');
      exit;
    }
    if ($do === '' || !isset($allowedActions[$do])) {
      flash_set('err', t('daemon.flash.invalid_action', [], 'Neplatná akce.'));
      header('Location: /daemon.php');
      exit;
    }

    // Provisioner si unit znovu zvaliduje a přeloží. PHP neposílá raw systemctl příkaz.
    enqueue_job($pdo, 'service_action', 0, ['service_key' => $key, 'action' => $do]);
    flash_set('ok', t('daemon.flash.action_queued', ['service' => $key, 'action' => daemon_action_label($do)], 'Akce služby zařazena do fronty: {service} {action}'));
    header('Location: /jobs.php');
    exit;
  }

  flash_set('err', t('daemon.flash.unknown_action', [], 'Neznámá akce.'));
  header('Location: /daemon.php');
  exit;
}

$statusRaw = setting($pdo, 'service_status_json', '');
$status = [];
if ($statusRaw !== '') {
  $tmp = json_decode($statusRaw, true);
  if (is_array($tmp)) $status = $tmp;
}
$serviceState = [];
foreach (($status['services'] ?? []) as $row) {
  if (is_array($row) && isset($row['key'])) $serviceState[(string)$row['key']] = $row;
}
$updatedAt = (string)($status['updated_at'] ?? '');

render($pdo, t('page.daemon.title', [], 'Systém'), function() use ($services, $serviceState, $updatedAt) { ?>
  <div class="card">
    <h2><?=h(t('page.daemon.title', [], 'Systém'))?></h2>
    <small><?=h(t('daemon.intro', [], 'Stavy služeb + základní akce. PHP pouze zakládá joby, systémové akce provádí Python provisioner.'))?></small>
  </div>

  <div class="card">
    <div class="row space">
      <div>
        <h3><?=h(t('daemon.services.heading', [], 'Služby'))?></h3>
        <small><?=h(t('daemon.last_loaded', ['time' => ($updatedAt ?: t('daemon.not_loaded_yet', [], 'zatím nenačteno'))], 'Poslední načtení: {time}'))?></small>
      </div>
      <form method="post" style="margin:0">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <button class="btn" name="action" value="refresh"><?=h(t('daemon.refresh_button', [], 'Aktualizovat stavy přes provisioner'))?></button>
      </form>
    </div>

    <div class="table-scroll">
      <table style="margin-top:12px">
        <tr>
          <th><?=h(t('daemon.table.service', [], 'Služba'))?></th>
          <th><?=h(t('daemon.table.unit', [], 'Unit'))?></th>
          <th><?=h(t('daemon.table.status', [], 'Stav'))?></th>
          <th><?=h(t('daemon.table.enabled', [], 'Enabled'))?></th>
          <th><?=h(t('daemon.table.uptime', [], 'Uptime'))?></th>
          <th><?=h(t('daemon.table.error', [], 'Chyba'))?></th>
          <th><?=h(t('common.actions', [], 'Akce'))?></th>
        </tr>
        <?php foreach ($services as $svc):
          $key = $svc['key'];
          $r = $serviceState[$key] ?? [];
          $active = (string)($r['active'] ?? 'unknown');
          $enabled = (string)($r['enabled'] ?? 'unknown');
          $unit = (string)($r['unit'] ?? $svc['hint']);
          $uptime = (string)($r['active_enter_timestamp'] ?? '-');
          $error = (string)($r['error'] ?? '');
          $activeLabel = daemon_state_label($active);
          $enabledLabel = daemon_state_label($enabled);
          $pill = '<span class="pill">'.h($activeLabel).'</span>';
          if ($active === 'active') $pill = '<span class="pill ok">'.h($activeLabel).'</span>';
          if ($active === 'failed') $pill = '<span class="pill err">'.h($activeLabel).'</span>';
          if ($active === 'inactive') $pill = '<span class="pill warn">'.h($activeLabel).'</span>';
        ?>
          <tr>
            <td><?=h($svc['label'])?></td>
            <td><code><?=h($unit)?></code></td>
            <td><?=$pill?></td>
            <td><?=h($enabledLabel)?></td>
            <td><small><?=h($uptime ?: '-')?></small></td>
            <td><small style="color:#ffb3b3"><?=h($error)?></small></td>
            <td style="white-space:nowrap">
              <?php foreach (['start','stop','restart','reload'] as $do): ?>
                <form method="post" style="display:inline" onsubmit="return confirm(<?=daemon_confirm($do, $unit)?>);">
                  <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                  <input type="hidden" name="service_key" value="<?=h($key)?>">
                  <input type="hidden" name="do" value="<?=h($do)?>">
                  <button class="btn2" name="action" value="service_do"><?=h(daemon_action_label($do))?></button>
                </form>
              <?php endforeach; ?>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </div>
<?php });

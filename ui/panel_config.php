<?php
declare(strict_types=1);
require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

$defaults = [
  'panel_php_version' => '8.2',
  'panel_php_memory_limit' => '1024M',
  'panel_php_upload_max_filesize' => '1024M',
  'panel_php_post_max_size' => '1024M',
  'panel_php_max_execution_time' => '300',
  'panel_php_max_input_time' => '300',
  'panel_php_max_file_uploads' => '20',
  'panel_php_timezone' => 'Europe/Prague',
  'panel_nginx_client_max_body_size' => '2048M',
  'panel_nginx_extra' => '',
];

function panel_size_ok(string $v): bool { return (bool)preg_match('~^\d+[KMG]?$~i', trim($v)); }
function panel_int_ok(string $v): bool { return (bool)preg_match('~^\d+$~', trim($v)); }
function panel_php_version_ok(string $v): bool { return (bool)preg_match('~^\d+\.\d+$~', trim($v)); }
function panel_nginx_extra_ok(string $v): bool {
  if (strlen($v) > 12000) return false;
  foreach ([
    '~\bserver\s*\{~i',
    '~\blisten\b~i',
    '~\broot\b~i',
    '~\binclude\b~i',
    '~\bssl_certificate\b~i',
    '~\bssl_certificate_key\b~i',
  ] as $rx) {
    if (preg_match($rx, $v)) return false;
  }
  return true;
}

function enqueue_panel_job(PDO $pdo): int {
  $st = $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('panel_config_apply',0,'queued',JSON_OBJECT('action','apply'))");
  $st->execute();
  return (int)$pdo->lastInsertId();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  try {
    $new = [];
    foreach ($defaults as $k => $def) {
      $new[$k] = trim((string)($_POST[$k] ?? $def));
    }

    if (!panel_php_version_ok($new['panel_php_version'])) {
      throw new RuntimeException(t('panel_config.err.invalid_php_version', [], 'Neplatná verze PHP. Použij např. 8.2.'));
    }

    foreach (['panel_php_memory_limit','panel_php_upload_max_filesize','panel_php_post_max_size','panel_nginx_client_max_body_size'] as $k) {
      if (!panel_size_ok($new[$k])) throw new RuntimeException(t('panel_config.err.invalid_size', ['key' => $k], 'Neplatná velikost u {key}. Použij např. 1024M.'));
    }

    foreach (['panel_php_max_execution_time','panel_php_max_input_time','panel_php_max_file_uploads'] as $k) {
      if (!panel_int_ok($new[$k])) throw new RuntimeException(t('panel_config.err.invalid_number', ['key' => $k], 'Neplatné číslo u {key}.'));
    }

    if ($new['panel_php_timezone'] === '' || !preg_match('~^[A-Za-z0-9_./+-]+$~', $new['panel_php_timezone'])) {
      throw new RuntimeException(t('panel_config.err.invalid_timezone', [], 'Neplatná timezone.'));
    }

    if (!panel_nginx_extra_ok($new['panel_nginx_extra'])) {
      throw new RuntimeException(t('panel_config.err.nginx_forbidden_directive', [], 'Extra nginx konfigurace obsahuje zakázanou direktivu.'));
    }

    $pdo->beginTransaction();
    foreach ($new as $k => $v) set_setting($pdo, $k, $v);
    $jobId = enqueue_panel_job($pdo);
    $pdo->commit();

    flash_set('ok', t('panel_config.flash.saved_queued', ['id' => $jobId], 'Nastavení admin panelu uloženo a zařazeno do provisioneru jako job #{id}.'));
    header('Location:/jobs.php'); exit;
  } catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    flash_set('err', $e->getMessage());
    header('Location:/panel_config.php'); exit;
  }
}

$vals = [];
foreach ($defaults as $k => $def) $vals[$k] = (string)setting($pdo, $k, $def);
$last = $pdo->query("SELECT * FROM jobs WHERE type='panel_config_apply' ORDER BY id DESC LIMIT 1")->fetch();

$effective = [
  'enable_post_data_reading' => ini_get('enable_post_data_reading'),
  'memory_limit' => ini_get('memory_limit'),
  'upload_max_filesize' => ini_get('upload_max_filesize'),
  'post_max_size' => ini_get('post_max_size'),
  'max_execution_time' => ini_get('max_execution_time'),
  'max_input_time' => ini_get('max_input_time'),
  'max_file_uploads' => ini_get('max_file_uploads'),
];

render($pdo, t('page.panel_config.title', [], 'Admin panel PHP / vhost'), function() use ($vals, $last, $effective) { ?>
  <div class="card">
    <h2><?=h(t('page.panel_config.title', [], 'Admin panel PHP / vhost'))?></h2>
    <small>
      <?=h(t('panel_config.help', [], 'Tohle nastavuje PHP-FPM a nginx pro samotný ORIS admin panel. Netýká se PHP poolů jednotlivých webů.'))?>
    </small>
    <?php if ($last): ?>
      <br><small><?=h(t('common.last_job', ['id' => $last['id']], 'Poslední job #{id}:'))?> <span class="pill <?= $last['status']==='done'?'ok':($last['status']==='error'?'err':'run') ?>"><?=h($last['status'])?></span></small>
    <?php endif; ?>
  </div>

  <div class="card">
    <h3><?=h(t('panel_config.effective.heading', [], 'Aktuální hodnoty, které teď vidí panelové PHP'))?></h3>
    <div class="table-scroll"><table>
      <tr><th><?=h(t('panel_config.col.directive', [], 'Direktiva'))?></th><th><?=h(t('panel_config.col.current', [], 'Aktuálně'))?></th></tr>
      <?php foreach ($effective as $k => $v): ?>
        <tr><td><code><?=h($k)?></code></td><td><code><?=h((string)$v)?></code></td></tr>
      <?php endforeach; ?>
    </table></div>
    <small><?=h(t('panel_config.effective.help', [], 'Po aplikaci provisionerem a restartu PHP-FPM stránku znovu otevři, aby se načetly nové hodnoty.'))?></small>
  </div>

  <div class="card">
    <h3><?=h(t('common.settings', [], 'Nastavení'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">

      <h4><?=h(t('panel_config.php_fpm.heading', [], 'PHP-FPM panelu'))?></h4>
      <div class="grid2">
        <label><?=h(t('panel_config.field.php_version', [], 'PHP verze'))?><br><input name="panel_php_version" value="<?=h($vals['panel_php_version'])?>"><small><?=t('panel_config.field.php_version_help', [], 'Např. <code>8.2</code>. Zapíše se do <code>/etc/php/VERZE/fpm/conf.d/zz-oris-admin-panel.ini</code>.')?></small></label>
        <label>memory_limit<br><input name="panel_php_memory_limit" value="<?=h($vals['panel_php_memory_limit'])?>"></label>
        <label>upload_max_filesize<br><input name="panel_php_upload_max_filesize" value="<?=h($vals['panel_php_upload_max_filesize'])?>"></label>
        <label>post_max_size<br><input name="panel_php_post_max_size" value="<?=h($vals['panel_php_post_max_size'])?>"></label>
        <label>max_execution_time<br><input name="panel_php_max_execution_time" value="<?=h($vals['panel_php_max_execution_time'])?>"></label>
        <label>max_input_time<br><input name="panel_php_max_input_time" value="<?=h($vals['panel_php_max_input_time'])?>"></label>
        <label>max_file_uploads<br><input name="panel_php_max_file_uploads" value="<?=h($vals['panel_php_max_file_uploads'])?>"></label>
        <label>timezone<br><input name="panel_php_timezone" value="<?=h($vals['panel_php_timezone'])?>"></label>
      </div>

      <h4 style="margin-top:18px"><?=h(t('panel_config.nginx.heading', [], 'Nginx vhost admin panelu'))?></h4>
      <div class="grid2">
        <label>client_max_body_size<br><input name="panel_nginx_client_max_body_size" value="<?=h($vals['panel_nginx_client_max_body_size'])?>"><small><?=t('panel_config.client_max_body_help', [], 'Řeší chybu <code>413 Request Entity Too Large</code> při uploadu záloh.')?></small></label>
      </div>

      <label style="display:block;margin-top:10px"><?=h(t('panel_config.field.nginx_extra', [], 'Extra nginx direktivy uvnitř admin server bloku'))?><br>
        <textarea name="panel_nginx_extra" rows="7" placeholder="<?=h(t('panel_config.placeholder.nginx_extra', [], 'např.'))?>&#10;add_header X-Robots-Tag noindex;\n"><?=h($vals['panel_nginx_extra'])?></textarea>
      </label>
      <small><?=t('panel_config.nginx_extra_forbidden_help', [], 'Zakázané jsou <code>server {}</code>, <code>listen</code>, <code>root</code>, <code>include</code>, <code>ssl_certificate</code> a <code>ssl_certificate_key</code>.')?></small>

      <div class="row" style="margin-top:16px">
        <button class="btn" name="save" value="1" onclick="return confirm(<?=json_encode(t('panel_config.confirm.save_apply', [], 'Uložit a aplikovat přes provisioner?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('panel_config.action.save_apply', [], 'Uložit + aplikovat'))?></button>
        <a class="btn2" href="/jobs.php" style="text-decoration:none;display:inline-block"><?=h(t('panel_config.action.show_jobs', [], 'Zobrazit jobs'))?></a>
      </div>
    </form>
  </div>

  <div class="card">
    <h3><?=h(t('panel_config.provisioner_changes.heading', [], 'Co provisioner upraví'))?></h3>
    <pre>/etc/php/<?=h($vals['panel_php_version'])?>/fpm/conf.d/zz-oris-admin-panel.ini
/etc/nginx/sites-available/oris-panel.conf</pre>
  </div>
<?php });

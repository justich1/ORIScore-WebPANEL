<?php
declare(strict_types=1);
require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

$defaults = [
  'php_memory_limit' => '512M',
  'php_upload_max_filesize' => '256M',
  'php_post_max_size' => '256M',
  'php_max_execution_time' => '300',
  'php_max_input_time' => '300',
  'php_timezone' => 'Europe/Prague',
  'php_opcache_enable' => '1',
  'php_opcache_memory_consumption' => '256',
  'php_opcache_max_accelerated_files' => '20000',
  'php_opcache_validate_timestamps' => '1',
  'php_opcache_revalidate_freq' => '2',
  'php_pm' => 'dynamic',
  'php_pm_max_children' => '20',
  'php_pm_start_servers' => '4',
  'php_pm_min_spare_servers' => '2',
  'php_pm_max_spare_servers' => '6',
  'php_pm_max_requests' => '500',
  'php_request_terminate_timeout' => '300',
];
function sget(PDO $pdo, string $k, string $d): string { return (string)setting($pdo,$k,$d); }
function size_ok(string $v): bool { return (bool)preg_match('~^\d+[KMG]?$~i',$v); }
function num_ok(string $v): bool { return (bool)preg_match('~^\d+$~',$v); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();
  try {
    $new=[];
    foreach ($defaults as $k=>$d) $new[$k]=trim((string)($_POST[$k] ?? $d));
    foreach (['php_memory_limit','php_upload_max_filesize','php_post_max_size'] as $k) if(!size_ok($new[$k])) throw new RuntimeException(t('php.err.invalid_value', ['key'=>$k], 'Neplatná hodnota {key}'));
    foreach (['php_max_execution_time','php_max_input_time','php_opcache_enable','php_opcache_memory_consumption','php_opcache_max_accelerated_files','php_opcache_validate_timestamps','php_opcache_revalidate_freq','php_pm_max_children','php_pm_start_servers','php_pm_min_spare_servers','php_pm_max_spare_servers','php_pm_max_requests','php_request_terminate_timeout'] as $k) if(!num_ok($new[$k])) throw new RuntimeException(t('php.err.invalid_value', ['key'=>$k], 'Neplatná hodnota {key}'));
    if(!in_array($new['php_pm'], ['dynamic','ondemand','static'], true)) throw new RuntimeException(t('php.err.invalid_pm', [], 'pm musí být dynamic/ondemand/static'));
    if($new['php_timezone']==='' || !preg_match('~^[A-Za-z0-9_./+-]+$~',$new['php_timezone'])) throw new RuntimeException(t('php.err.invalid_timezone', [], 'Neplatná timezone'));
    $pdo->beginTransaction();
    foreach($new as $k=>$v) set_setting($pdo,$k,$v);
    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('php_apply_config',0,'queued',JSON_OBJECT('action','global_php'))")->execute();
    $pdo->commit();
    flash_set('ok', t('php.flash.saved_queued', [], 'PHP nastavení uloženo a zařazeno do fronty. Provisioner zapíše konfiguraci a reloadne PHP-FPM.'));
  } catch(Throwable $e) {
    if($pdo->inTransaction()) $pdo->rollBack();
    flash_set('err',$e->getMessage());
  }
  header('Location: /php.php'); exit;
}

$values=[]; foreach($defaults as $k=>$d) $values[$k]=sget($pdo,$k,$d);
$last=$pdo->query("SELECT * FROM jobs WHERE type='php_apply_config' ORDER BY id DESC LIMIT 1")->fetch();
$unit=''; $socket='';
foreach (glob('/run/php/php*-fpm.sock') ?: [] as $s) { $socket=$s; }
foreach (glob('/etc/php/*/fpm') ?: [] as $d) { $unit='php'.basename(dirname($d)).'-fpm'; }

render($pdo, t('page.php.title', [], 'PHP'), function() use ($values,$last,$unit,$socket) { ?>
  <div class="card">
    <h2><?=h(t('php.heading', [], 'PHP-FPM'))?></h2>
    <p><?=h(t('php.detected_service', [], 'Detekovaná služba:'))?> <code><?=h($unit ?: t('common.unknown', [], 'neznámá'))?></code> • socket: <code><?=h($socket ?: '/run/php/php-fpm.sock')?></code></p>
    <?php if($last): ?><small><?=h(t('common.last_job', ['id'=>$last['id']], 'Poslední job #{id}:'))?> <span class="pill <?= $last['status']==='done'?'ok':($last['status']==='error'?'err':'run') ?>"><?=h(t('status.'.$last['status'], [], (string)$last['status']))?></span></small><?php endif; ?>
  </div>
  <div class="card">
    <h3><?=h(t('php.global_settings.heading', [], 'Globální nastavení PHP'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <h4><?=h(t('php.section.basic', [], 'Základ'))?></h4>
      <div class="grid2">
        <label><?=h(t('php.field.memory_limit', [], 'memory_limit'))?><br><input name="php_memory_limit" value="<?=h($values['php_memory_limit'])?>"></label>
        <label><?=h(t('php.field.upload_max_filesize', [], 'upload_max_filesize'))?><br><input name="php_upload_max_filesize" value="<?=h($values['php_upload_max_filesize'])?>"></label>
        <label><?=h(t('php.field.post_max_size', [], 'post_max_size'))?><br><input name="php_post_max_size" value="<?=h($values['php_post_max_size'])?>"></label>
        <label><?=h(t('php.field.max_execution_time', [], 'max_execution_time'))?><br><input name="php_max_execution_time" value="<?=h($values['php_max_execution_time'])?>"></label>
        <label><?=h(t('php.field.max_input_time', [], 'max_input_time'))?><br><input name="php_max_input_time" value="<?=h($values['php_max_input_time'])?>"></label>
        <label><?=h(t('php.field.timezone', [], 'timezone'))?><br><input name="php_timezone" value="<?=h($values['php_timezone'])?>"></label>
      </div>
      <h4 style="margin-top:16px"><?=h(t('php.section.opcache', [], 'OPcache'))?></h4>
      <div class="grid2">
        <label><?=h(t('php.field.opcache_enable', [], 'enable 0/1'))?><br><input name="php_opcache_enable" value="<?=h($values['php_opcache_enable'])?>"></label>
        <label><?=h(t('php.field.opcache_memory_consumption', [], 'memory_consumption'))?><br><input name="php_opcache_memory_consumption" value="<?=h($values['php_opcache_memory_consumption'])?>"></label>
        <label><?=h(t('php.field.opcache_max_accelerated_files', [], 'max_accelerated_files'))?><br><input name="php_opcache_max_accelerated_files" value="<?=h($values['php_opcache_max_accelerated_files'])?>"></label>
        <label><?=h(t('php.field.opcache_validate_timestamps', [], 'validate_timestamps 0/1'))?><br><input name="php_opcache_validate_timestamps" value="<?=h($values['php_opcache_validate_timestamps'])?>"></label>
        <label><?=h(t('php.field.opcache_revalidate_freq', [], 'revalidate_freq'))?><br><input name="php_opcache_revalidate_freq" value="<?=h($values['php_opcache_revalidate_freq'])?>"></label>
      </div>
      <h4 style="margin-top:16px"><?=h(t('php.section.pool_www', [], 'PHP-FPM pool www'))?></h4>
      <div class="grid2">
        <label><?=h(t('php.field.pm', [], 'pm'))?><br><input name="php_pm" value="<?=h($values['php_pm'])?>"></label>
        <label><?=h(t('php.field.pm_max_children', [], 'pm.max_children'))?><br><input name="php_pm_max_children" value="<?=h($values['php_pm_max_children'])?>"></label>
        <label><?=h(t('php.field.pm_start_servers', [], 'pm.start_servers'))?><br><input name="php_pm_start_servers" value="<?=h($values['php_pm_start_servers'])?>"></label>
        <label><?=h(t('php.field.pm_min_spare_servers', [], 'pm.min_spare_servers'))?><br><input name="php_pm_min_spare_servers" value="<?=h($values['php_pm_min_spare_servers'])?>"></label>
        <label><?=h(t('php.field.pm_max_spare_servers', [], 'pm.max_spare_servers'))?><br><input name="php_pm_max_spare_servers" value="<?=h($values['php_pm_max_spare_servers'])?>"></label>
        <label><?=h(t('php.field.pm_max_requests', [], 'pm.max_requests'))?><br><input name="php_pm_max_requests" value="<?=h($values['php_pm_max_requests'])?>"></label>
        <label><?=h(t('php.field.request_terminate_timeout', [], 'request_terminate_timeout'))?><br><input name="php_request_terminate_timeout" value="<?=h($values['php_request_terminate_timeout'])?>"></label>
      </div>
      <div style="margin-top:16px"><button class="btn" type="submit" onclick="return confirm(<?=json_encode(t('php.confirm.apply', [], 'Uložit a aplikovat přes Python provisioner?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('common.save_apply', [], 'Uložit + aplikovat'))?></button></div>
    </form>
  </div>
<?php });

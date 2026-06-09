<?php
// ORIS Panel - Server config editor přes Python provisioner
// Nginx/PHP-FPM aktuální verze, žádný Apache legacy seznam.
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

function enqueue_job(PDO $pdo, string $type, int $refId=0, array $payload=[]): void {
  $st=$pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES(?,?, 'queued', ?)");
  $st->execute([$type,$refId,json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}
function setting_kv(PDO $pdo, string $k, string $def=''): string {
  $v = setting($pdo, $k, null);
  return $v === null ? $def : (string)$v;
}
function set_setting_kv(PDO $pdo, string $k, string $v): void { set_setting($pdo, $k, $v); }
function cfg_fid(string $path): string { return substr(sha1($path), 0, 12); }
function cfg_add_file(array &$files, string $group, string $path): void {
  $path = trim($path);
  if ($path === '' || !is_file($path)) return;
  $files[$group][cfg_fid($path)] = $path;
}
function cfg_add_glob(array &$files, string $group, string $pattern): void {
  $items = glob($pattern, GLOB_NOSORT) ?: [];
  sort($items, SORT_NATURAL);
  foreach ($items as $p) cfg_add_file($files, $group, $p);
}
function cfg_build_files(): array {
  $files = [];

  // NGINX - aktuální stack
  cfg_add_file($files, 'nginx', '/etc/nginx/nginx.conf');
  cfg_add_glob($files, 'nginx', '/etc/nginx/conf.d/*.conf');
  cfg_add_glob($files, 'nginx', '/etc/nginx/sites-available/*.conf');
  cfg_add_glob($files, 'nginx', '/etc/nginx/snippets/*.conf');

  // PHP-FPM - automatická detekce verzí, žádné hardcoded 8.4/8.3/8.2
  $versions = glob('/etc/php/*/fpm', GLOB_ONLYDIR | GLOB_NOSORT) ?: [];
  usort($versions, 'strnatcmp');
  foreach ($versions as $fpmDir) {
    $base = dirname($fpmDir); // /etc/php/8.x
    cfg_add_file($files, 'php', $fpmDir . '/php.ini');
    cfg_add_file($files, 'php', $fpmDir . '/php-fpm.conf');
    cfg_add_glob($files, 'php', $fpmDir . '/pool.d/*.conf');
    cfg_add_glob($files, 'php', $fpmDir . '/conf.d/*.ini');
    cfg_add_file($files, 'php', $base . '/cli/php.ini');
  }

  // phpMyAdmin konfigurace bez apache.conf jako hlavní položky
  cfg_add_file($files, 'phpmyadmin', '/etc/phpmyadmin/config.inc.php');
  cfg_add_file($files, 'phpmyadmin', '/etc/phpmyadmin/config-db.php');
  cfg_add_file($files, 'phpmyadmin', '/etc/phpmyadmin/config.header.inc.php');
  cfg_add_file($files, 'phpmyadmin', '/etc/phpmyadmin/config.footer.inc.php');

  // Mail stack
  cfg_add_file($files, 'mail', '/etc/postfix/main.cf');
  cfg_add_file($files, 'mail', '/etc/postfix/master.cf');
  cfg_add_glob($files, 'mail', '/etc/postfix/mysql-*.cf');
  cfg_add_file($files, 'mail', '/etc/dovecot/dovecot.conf');
  cfg_add_glob($files, 'mail', '/etc/dovecot/conf.d/*.conf');
  cfg_add_file($files, 'mail', '/etc/dovecot/dovecot-sql.conf.ext');
  cfg_add_glob($files, 'mail', '/etc/rspamd/local.d/*.conf');
  cfg_add_glob($files, 'mail', '/etc/rspamd/override.d/*.conf');
  cfg_add_file($files, 'mail', '/etc/roundcube/config.inc.php');
  cfg_add_file($files, 'mail', '/etc/aliases');

  // Security
  cfg_add_glob($files, 'fail2ban', '/etc/fail2ban/jail.d/*.local');
  cfg_add_glob($files, 'fail2ban', '/etc/fail2ban/filter.d/oris*.conf');
  cfg_add_file($files, 'fail2ban', '/etc/fail2ban/fail2ban.local');
  cfg_add_file($files, 'fail2ban', '/etc/fail2ban/jail.local');

  cfg_add_file($files, 'ufw', '/etc/ufw/ufw.conf');
  cfg_add_file($files, 'ufw', '/etc/ufw/user.rules');
  cfg_add_file($files, 'ufw', '/etc/ufw/user6.rules');
  cfg_add_file($files, 'ufw', '/etc/ufw/before.rules');
  cfg_add_file($files, 'ufw', '/etc/ufw/before6.rules');
  cfg_add_file($files, 'ufw', '/etc/ufw/after.rules');
  cfg_add_file($files, 'ufw', '/etc/ufw/after6.rules');
  cfg_add_glob($files, 'ufw', '/etc/ufw/applications.d/*');

  // FTP / VPN / systém
  cfg_add_file($files, 'vsftpd', '/etc/vsftpd.conf');
  cfg_add_glob($files, 'vsftpd', '/etc/vsftpd_user_conf/*');

  cfg_add_glob($files, 'wireguard', '/etc/wireguard/*.conf');

  cfg_add_file($files, 'system', '/etc/hostname');
  cfg_add_file($files, 'system', '/etc/hosts');
  cfg_add_file($files, 'system', '/etc/sysctl.conf');
  cfg_add_glob($files, 'system', '/etc/sysctl.d/*.conf');
  cfg_add_file($files, 'system', '/etc/crontab');
  cfg_add_glob($files, 'system', '/etc/cron.d/*');

  return $files;
}
function safe_backup_name(string $name): string {
  $name = basename($name);
  if (!preg_match('~^[A-Za-z0-9._-]+\.(tar\.gz|tgz)$~', $name)) return '';
  return $name;
}
function backup_dir(PDO $pdo): string {
  return rtrim(setting_kv($pdo, 'servercfg_backup_dir', '/var/lib/oris-core/backups/servercfg'), '/');
}
function upload_dir(PDO $pdo): string {
  return rtrim(setting_kv($pdo, 'upload_staging_dir', '/var/lib/oris-core/uploads'), '/') . '/servercfg';
}

$FILES = cfg_build_files();
$TABS = [
  'overview'   => t('servercfg.tab.overview', [], 'Přehled'),
  'nginx'      => 'Nginx',
  'php'        => 'PHP-FPM',
  'phpmyadmin' => 'phpMyAdmin',
  'mail'       => 'Mail stack',
  'fail2ban'   => 'Fail2ban',
  'ufw'        => 'UFW',
  'vsftpd'     => 'VSFTPD',
  'wireguard'  => 'WireGuard',
  'system'     => t('servercfg.tab.system', [], 'Systém'),
  'backup'     => t('servercfg.tab.backup_restore', [], 'Záloha/obnova'),
];

// Přímé stažení hotové servercfg zálohy je jen čtení z povoleného adresáře.
if (isset($_GET['download_backup'])) {
  $name = safe_backup_name((string)$_GET['download_backup']);
  if ($name === '') { http_response_code(400); echo t('servercfg.err.invalid_backup_name', [], 'Neplatný název zálohy'); exit; }
  $base = backup_dir($pdo);
  $path = $base . '/' . $name;
  if (!is_file($path)) { http_response_code(404); echo t('servercfg.err.backup_not_exists', [], 'Záloha neexistuje'); exit; }
  header('Content-Type: application/gzip');
  header('Content-Disposition: attachment; filename="'.basename($path).'"');
  header('Content-Length: '.filesize($path));
  readfile($path);
  exit;
}

$tab = (string)($_GET['tab'] ?? $_POST['tab'] ?? 'overview');
if (!isset($TABS[$tab])) $tab = 'overview';
$group = $tab;

$fid = (string)($_GET['fid'] ?? $_POST['fid'] ?? '');
if ($fid === '' && isset($FILES[$group])) {
  $first = array_key_first($FILES[$group]);
  $fid = $first ? (string)$first : '';
}
$path = ($fid !== '' && isset($FILES[$group][$fid])) ? $FILES[$group][$fid] : '';
$settingKey = ($group && $fid) ? "servercfg.$group.$fid" : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();
  $action = (string)($_POST['action'] ?? '');
  $tab = (string)($_POST['tab'] ?? $tab);
  $group = $tab;
  $fid = (string)($_POST['fid'] ?? '');
  $path = ($fid !== '' && isset($FILES[$group][$fid])) ? $FILES[$group][$fid] : '';
  $settingKey = ($group && $fid) ? "servercfg.$group.$fid" : '';

  if ($action === 'save_file') {
    if ($path === '' || $settingKey === '') { flash_set('err', t('servercfg.err.invalid_file', [], 'Neplatný soubor.')); header('Location:/server_config.php?tab='.rawurlencode($tab)); exit; }
    set_setting_kv($pdo, $settingKey, (string)($_POST['content'] ?? ''));
    set_setting_kv($pdo, "servercfg.path.$group.$fid", $path);
    flash_set('ok', t('servercfg.flash.saved_db', [], 'Uloženo do DB.'));
    header('Location:/server_config.php?tab='.rawurlencode($tab).'&fid='.rawurlencode($fid)); exit;
  }

  if ($action === 'sync_file') {
    if ($path === '' || $settingKey === '') { flash_set('err', t('servercfg.err.invalid_file', [], 'Neplatný soubor.')); header('Location:/server_config.php?tab='.rawurlencode($tab)); exit; }
    set_setting_kv($pdo, "servercfg.path.$group.$fid", $path);
    enqueue_job($pdo, 'servercfg_sync_file', 0, ['group'=>$group, 'path'=>$path, 'setting_key'=>$settingKey]);
    flash_set('ok', t('servercfg.flash.sync_queued', [], 'Načtení ze systému zařazeno do fronty.'));
    header('Location:/jobs.php'); exit;
  }

  if ($action === 'apply_file') {
    if ($path === '' || $settingKey === '') { flash_set('err', t('servercfg.err.invalid_file', [], 'Neplatný soubor.')); header('Location:/server_config.php?tab='.rawurlencode($tab)); exit; }
    set_setting_kv($pdo, $settingKey, (string)($_POST['content'] ?? ''));
    set_setting_kv($pdo, "servercfg.path.$group.$fid", $path);
    enqueue_job($pdo, 'servercfg_apply_file', 0, ['group'=>$group, 'path'=>$path, 'setting_key'=>$settingKey]);
    flash_set('ok', t('servercfg.flash.apply_queued', [], 'Apply do systému zařazen do fronty.'));
    header('Location:/jobs.php'); exit;
  }

  if ($action === 'backup_full') {
    enqueue_job($pdo, 'servercfg_backup_full', 0, []);
    flash_set('ok', t('servercfg.flash.backup_queued', [], 'Vytvoření zálohy server konfigurace zařazeno do fronty.'));
    header('Location:/jobs.php'); exit;
  }

  if ($action === 'delete_backup') {
    $name = safe_backup_name((string)($_POST['backup_name'] ?? ''));
    if ($name === '') { flash_set('err', t('servercfg.err.invalid_backup_name_dot', [], 'Neplatný název zálohy.')); header('Location:/server_config.php?tab=backup'); exit; }
    enqueue_job($pdo, 'servercfg_backup_delete', 0, ['name'=>$name]);
    flash_set('ok', t('servercfg.flash.delete_backup_queued', [], 'Mazání zálohy zařazeno do fronty.'));
    header('Location:/jobs.php'); exit;
  }

  if ($action === 'restore_full_backup') {
    if (!isset($_FILES['backup']) || $_FILES['backup']['error'] !== UPLOAD_ERR_OK) {
      flash_set('err', t('servercfg.err.upload_failed', [], 'Chyba uploadu.')); header('Location:/server_config.php?tab=backup'); exit;
    }
    $name = basename((string)$_FILES['backup']['name']);
    if (!preg_match('~\.(tar\.gz|tgz)$~', $name)) {
      flash_set('err', t('servercfg.err.expected_tar_gz', [], 'Očekávám .tar.gz nebo .tgz')); header('Location:/server_config.php?tab=backup'); exit;
    }
    $dir = upload_dir($pdo);
    if (!is_dir($dir)) @mkdir($dir, 0770, true);
    $dst = $dir . '/' . date('Ymd-His') . '-servercfg-' . preg_replace('~[^A-Za-z0-9._-]+~','_', $name);
    if (!move_uploaded_file($_FILES['backup']['tmp_name'], $dst)) {
      flash_set('err', t('servercfg.err.upload_save_failed', [], 'Nelze uložit upload.')); header('Location:/server_config.php?tab=backup'); exit;
    }
    enqueue_job($pdo, 'servercfg_restore_full', 0, ['path'=>$dst]);
    flash_set('ok', t('servercfg.flash.restore_queued', [], 'Obnova server konfigurace zařazena do fronty.'));
    header('Location:/jobs.php'); exit;
  }
}

$content = '';
if ($fid !== '' && $group !== 'backup' && isset($FILES[$group][$fid])) {
  $content = setting_kv($pdo, "servercfg.$group.$fid", '');
}

$backups = [];
$bdir = backup_dir($pdo);
if (is_dir($bdir)) {
  $items = glob($bdir . '/*.{tar.gz,tgz}', GLOB_BRACE) ?: [];
  rsort($items, SORT_NATURAL);
  foreach ($items as $p) if (is_file($p)) $backups[] = ['name'=>basename($p), 'size'=>filesize($p), 'mtime'=>filemtime($p)];
}

render($pdo, t('page.server_config.title', [], 'Konfigurace serveru'), function() use ($pdo, $FILES, $TABS, $tab, $group, $fid, $path, $content, $backups) { ?>
<div class="page">
  <div class="page-head">
    <h1><?=h(t('page.server_config.title', [], 'Konfigurace serveru'))?></h1>
    <div class="muted"><?=h(t('servercfg.intro', [], 'Nginx/PHP-FPM konfigurace. Čtení a zápis do systému dělá Python provisioner.'))?></div>
  </div>

  <div class="tabs">
    <?php foreach ($TABS as $k=>$label): ?>
      <a class="tab <?= $tab===$k?'active':'' ?>" href="/server_config.php?tab=<?=h($k)?>"><?=h($label)?></a>
    <?php endforeach; ?>
  </div>

  <?php if ($tab === 'overview'): ?>
    <div class="card">
      <h3><?=h(t('servercfg.overview.heading', [], 'Přehled'))?></h3>
      <p class="muted"><?=h(t('servercfg.overview.help_prefix', [], 'Apache legacy položky jsou odstraněné. PHP-FPM se detekuje podle skutečných adresářů'))?> <code>/etc/php/*/fpm</code><?=h(t('servercfg.overview.help_suffix', [], ', takže se nezasekne na staré verzi.'))?></p>
      <ul>
        <li><b><?=h(t('servercfg.action.save', [], 'Uložit'))?></b> = <?=h(t('servercfg.overview.save_desc', [], 'uloží aktuální obsah do DB'))?></li>
        <li><b><?=h(t('servercfg.action.sync', [], 'Načíst ze systému'))?></b> = <?=h(t('servercfg.overview.sync_desc_prefix', [], 'Python přečte soubor z'))?> <code>/etc</code> <?=h(t('servercfg.overview.sync_desc_suffix', [], 'a uloží ho do DB'))?></li>
        <li><b><?=h(t('servercfg.action.apply', [], 'Apply'))?></b> = <?=h(t('servercfg.overview.apply_desc_prefix', [], 'Python zapíše obsah z DB do'))?> <code>/etc</code>, <?=h(t('servercfg.overview.apply_desc_suffix', [], 'udělá backup a reload/test služby'))?></li>
      </ul>
    </div>
  <?php elseif ($tab === 'backup'): ?>
    <div class="card">
      <h3><?=h(t('servercfg.backup.heading', [], 'Kompletní záloha/obnova'))?></h3>
      <p class="muted"><?=h(t('servercfg.backup.help', [], 'Zálohuje aktuální Nginx/PHP/mail/security konfiguraci. Nezálohuje Apache legacy strom.'))?></p>
      <form method="post" style="margin:0 0 14px 0;">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <button class="btn2" name="action" value="backup_full"><?=h(t('servercfg.backup.create_full', [], 'Vytvořit kompletní zálohu přes provisioner'))?></button>
      </form>

      <h4><?=h(t('servercfg.backup.existing', [], 'Existující zálohy'))?></h4>
      <table>
        <tr><th><?=h(t('common.file', [], 'Soubor'))?></th><th><?=h(t('common.size', [], 'Velikost'))?></th><th><?=h(t('common.date', [], 'Datum'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
        <?php if (!$backups): ?><tr><td colspan="4"><?=h(t('servercfg.backup.none', [], 'Žádné zálohy'))?></td></tr><?php else: foreach($backups as $b): ?>
          <tr>
            <td><?=h($b['name'])?></td>
            <td><?=h(number_format((float)$b['size']/1024/1024, 2, ',', ' '))?> MB</td>
            <td><?=h(date('d.m.Y H:i:s', (int)$b['mtime']))?></td>
            <td style="display:flex;gap:8px;flex-wrap:wrap">
              <a class="btn2" href="/server_config.php?tab=backup&download_backup=<?=urlencode($b['name'])?>"><?=h(t('common.download', [], 'Stáhnout'))?></a>
              <form method="post" style="margin:0" onsubmit="return confirm(<?=json_encode(t('servercfg.confirm.delete_backup', ['name'=>$b['name']], 'Smazat zálohu {name}?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>)">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="backup_name" value="<?=h($b['name'])?>">
                <button class="btn-danger" name="action" value="delete_backup"><?=h(t('common.delete', [], 'Smazat'))?></button>
              </form>
            </td>
          </tr>
        <?php endforeach; endif; ?>
      </table>

      <hr>
      <h4><?=h(t('servercfg.restore.heading', [], 'Obnova ze zálohy'))?></h4>
      <form method="post" enctype="multipart/form-data">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <div class="row">
          <input type="file" name="backup" accept=".tar.gz,.tgz" required>
          <button class="btn danger" name="action" value="restore_full_backup" onclick="return confirm(<?=json_encode(t('servercfg.confirm.restore_full', [], 'Opravdu obnovit kompletní server konfiguraci?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('servercfg.restore.button', [], 'Obnovit přes provisioner'))?></button>
        </div>
      </form>
    </div>
  <?php else: ?>
    <div class="card">
      <div class="row space">
        <div>
          <h3><?=h($TABS[$tab])?></h3>
          <div class="muted"><?=h(t('common.file', [], 'Soubor'))?>: <?=h($path ?: '—')?></div>
        </div>
        <form method="get" action="/server_config.php" class="row" style="margin:0;">
          <input type="hidden" name="tab" value="<?=h($tab)?>">
          <select name="fid" onchange="this.form.submit()">
            <?php foreach (($FILES[$group] ?? []) as $id=>$p): ?>
              <option value="<?=h($id)?>" <?=$id===$fid?'selected':''?>><?=h($p)?></option>
            <?php endforeach; ?>
          </select>
        </form>
      </div>

      <?php if (empty($FILES[$group] ?? [])): ?>
        <p class="muted"><?=h(t('servercfg.no_files_in_group', [], 'Pro tuto skupinu nebyly na systému nalezeny žádné konfigurační soubory.'))?></p>
      <?php else: ?>
      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="tab" value="<?=h($tab)?>">
        <input type="hidden" name="fid" value="<?=h($fid)?>">
        <textarea name="content" class="code" rows="24" spellcheck="false"><?=h($content)?></textarea>
        <div class="row" style="margin-top:10px;">
          <button class="btn2" name="action" value="save_file"><?=h(t('servercfg.action.save_db', [], 'Uložit do DB'))?></button>
          <button class="btn" name="action" value="sync_file"><?=h(t('servercfg.action.sync_provisioner', [], 'Načíst ze systému přes provisioner'))?></button>
          <button class="btn primary" name="action" value="apply_file" onclick="return confirm(<?=json_encode(t('servercfg.confirm.apply_system', [], 'Aplikovat do systému (/etc)?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('servercfg.action.apply_provisioner', [], 'Apply přes provisioner'))?></button>
        </div>
      </form>
      <?php endif; ?>
    </div>
  <?php endif; ?>
</div>
<?php });

<?php
require __DIR__.'/_boot.php';
require __DIR__.'/_view.php';
require_login();

$u = me($pdo);

$id = (int)($_GET['id'] ?? 0);
$st = $pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
$st->execute([$id, (int)$u['id']]);
$site = $st->fetch();

if (!$site) {
  flash_set('err', t('common.not_found', [], 'Nenalezeno'));
  header("Location:/sites.php");
  exit;
}

$sitesDir = rtrim(setting($pdo, 'sites_base_dir', '/var/lib/oris-core/sites'), '/') . '/';

// Povolené base cesty pro root webů (Settings -> web_root_bases, jedna cesta na řádek)
$basesRaw = (string)setting($pdo, 'web_root_bases', '');
$allowedBases = [$sitesDir];

foreach (preg_split('~\R+~', $basesRaw) as $line) {
  $line = trim($line);
  if ($line === '') continue;
  $allowedBases[] = rtrim($line, '/') . '/';
}

if (count($allowedBases) === 1) {
  $allowedBases[] = '/var/www/html/';
  $allowedBases[] = '/data/www/';
}

$allowedBases = array_values(array_unique($allowedBases));

function path_ok_multi(string $path, array $bases): bool {
  $path = trim($path);

  if ($path === '') return false;
  if (str_contains($path, "\0")) return false;
  if (str_contains($path, '..')) return false;

  foreach ($bases as $base) {
    $base = rtrim($base, '/') . '/';
    if (str_starts_with($path, $base)) return true;
  }

  return false;
}

function size_value_ok(string $v): bool {
  return (bool)preg_match('~^\d+[KMG]?$~i', $v);
}

function int_value_ok(string $v): bool {
  return (bool)preg_match('~^\d+$~', $v);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  if (isset($_POST['disable'])) {
    $pdo->prepare("UPDATE sites SET status='disabled' WHERE id=? AND user_id=?")
        ->execute([$id, (int)$u['id']]);

    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_site',?, 'queued', JSON_OBJECT('action','web'))")
        ->execute([$id]);

    flash_set('ok', t('site.flash.disabled', [], 'Web byl zakázán.'));
    header("Location:/site.php?id=" . $id);
    exit;
  }

  if (isset($_POST['enable'])) {
    $pdo->prepare("UPDATE sites SET status='active' WHERE id=? AND user_id=?")
        ->execute([$id, (int)$u['id']]);

    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_site',?, 'queued', JSON_OBJECT('action','web'))")
        ->execute([$id]);

    flash_set('ok', t('site.flash.enabled', [], 'Web byl povolen.'));
    header("Location:/site.php?id=" . $id);
    exit;
  }

  if (isset($_POST['apply'])) {
    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_site',?, 'queued', JSON_OBJECT('action','web'))")
        ->execute([$id]);

    flash_set('ok', t('sites.flash.queued_rebuild', [], 'Rebuild webu zařazen do fronty.'));
    header("Location:/site.php?id=" . $id);
    exit;
  }

  if (isset($_POST['save'])) {
    try {
      $root = trim((string)($_POST['root_path'] ?? ''));

      if (!path_ok_multi($root, $allowedBases)) {
        throw new RuntimeException(t('site.flash.root_must_be_under', ['bases' => implode(', ', $allowedBases)]));
      }

      $force = isset($_POST['force_https']) ? 1 : 0;
      $hsts = isset($_POST['hsts']) ? 1 : 0;
      $pretty = isset($_POST['pretty_urls']) ? 1 : 0;
      $phpEnabled = isset($_POST['php_enabled']) ? 1 : 0;
      $phpMemory = trim((string)($_POST['php_memory_limit'] ?? '512M'));
      $phpUpload = trim((string)($_POST['php_upload_max_filesize'] ?? '256M'));
      $phpPost = trim((string)($_POST['php_post_max_size'] ?? '256M'));
      $phpMaxExec = trim((string)($_POST['php_max_execution_time'] ?? '300'));
      $phpMaxInput = trim((string)($_POST['php_max_input_time'] ?? '300'));
      $phpTz = trim((string)($_POST['php_timezone'] ?? 'Europe/Prague'));
      $phpOpcache = isset($_POST['php_opcache_enabled']) ? 1 : 0;
      $phpCustom = trim((string)($_POST['php_custom_ini'] ?? ''));
      $nginxExtra = trim((string)($_POST['nginx_extra'] ?? ''));

      foreach ([$phpMemory, $phpUpload, $phpPost] as $v) {
        if (!size_value_ok($v)) {
          throw new RuntimeException(t('site.err.invalid_php_size', [], 'Neplatná PHP velikost. Použij např. 256M.'));
        }
      }

      foreach ([$phpMaxExec, $phpMaxInput] as $v) {
        if (!int_value_ok($v)) {
          throw new RuntimeException(t('site.err.php_times_integer', [], 'PHP časy musí být celé číslo.'));
        }
      }

      if ($phpTz === '' || !preg_match('~^[A-Za-z0-9_./+-]+$~', $phpTz)) {
        throw new RuntimeException(t('site.err.invalid_timezone', [], 'Neplatná timezone.'));
      }

      if (strlen($phpCustom) > 12000 || strlen($nginxExtra) > 12000) {
        throw new RuntimeException(t('site.err.custom_config_too_long', [], 'Vlastní konfigurace je moc dlouhá.'));
      }

      $pdo->beginTransaction();

      $pdo->prepare("UPDATE sites SET root_path=?, force_https=?, hsts=?, pretty_urls=?, nginx_extra=?, php_enabled=?, php_memory_limit=?, php_upload_max_filesize=?, php_post_max_size=?, php_max_execution_time=?, php_max_input_time=?, php_timezone=?, php_opcache_enabled=?, php_custom_ini=? WHERE id=? AND user_id=?")
          ->execute([$root, $force, $hsts, $pretty, $nginxExtra, $phpEnabled, $phpMemory, $phpUpload, $phpPost, (int)$phpMaxExec, (int)$phpMaxInput, $phpTz, $phpOpcache, $phpCustom, $id, (int)$u['id']]);

      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_site',?, 'queued', JSON_OBJECT('action','web_config'))")
          ->execute([$id]);

      $pdo->commit();
      flash_set('ok', t('site.flash.saved_and_rebuild_queued', [], 'Uloženo a zařazeno přegenerování vhostu/PHP poolu.'));
    } catch (Throwable $e) {
      if ($pdo->inTransaction()) $pdo->rollBack();
      flash_set('err', $e->getMessage());
    }

    header("Location:/site.php?id=" . $id);
    exit;
  }
}

// Fresh reload after POST changes could have happened.
$st = $pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
$st->execute([$id, (int)$u['id']]);
$site = $st->fetch();

$root = rtrim((string)$site['root_path'], '/');
$dataDir = $root . '/backup/data';
$dbDir = $root . '/backup/db';

function list_backups(string $dir): array {
  if (!is_dir($dir)) return [];

  $files = glob(rtrim($dir, '/') . '/*') ?: [];
  $out = [];

  foreach ($files as $f) {
    if (!is_file($f)) continue;

    $out[] = [
      'name' => basename($f),
      'mtime' => filemtime($f) ?: 0,
      'size' => filesize($f) ?: 0,
    ];
  }

  usort($out, fn($a, $b) => $b['mtime'] <=> $a['mtime']);
  return $out;
}

function human_bytes(int $bytes): string {
  $u = ['B', 'KB', 'MB', 'GB', 'TB'];
  $i = 0;
  $b = (float)$bytes;

  while ($b >= 1024 && $i < count($u) - 1) {
    $b /= 1024;
    $i++;
  }

  return sprintf('%.2f %s', $b, $u[$i]);
}

function sf(array $site, string $key, $def = '') {
  return $site[$key] ?? $def;
}

$backData = list_backups($dataDir);
$backDb = list_backups($dbDir);

render($pdo, t('page.site.title', [], 'Detail webu'), function() use ($site, $allowedBases, $backData, $backDb) {
?>
  <div class="card">
    <h2><?=h($site['domain'])?></h2>
    <small>
      <?php te('common.id', [], 'ID'); ?>: <?=h($site['id'])?> •
      <?php te('common.status', [], 'Status'); ?>:
      <span class="pill <?= $site['status'] === 'active' ? 'ok' : ($site['status'] === 'error' ? 'err' : 'run') ?>">
        <?=h(t('status.'.(string)$site['status'], [], (string)$site['status']))?>
      </span>
    </small>

    <?php if ($site['last_error']): ?>
      <pre><?=h($site['last_error'])?></pre>
    <?php endif; ?>
  </div>

  <div class="card">
    <h3><?php te('site.domain_settings', [], 'Nastavení domény'); ?></h3>

    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">

      <div class="row">
        <div>
          <label><?php te('site.field.root_path', [], 'Root webu'); ?></label>
          <select id="root_base" class="inp" style="max-width:360px; margin-bottom:6px;"
            onchange="(function(sel){var base=sel.value;var inp=document.querySelector('input[name=\'root_path\']');if(!inp) return; if(base && (inp.value==='' || inp.value===<?=json_encode($site['root_path'])?> || inp.value.startsWith(base))){ inp.value = base + <?=json_encode($site['domain'] . '/public')?>; } })(this);">
            <option value=""><?=h(t('site.root_base.placeholder', [], 'Root base…'))?></option>
            <?php foreach ($allowedBases as $b): ?>
              <option value="<?=h(rtrim($b, '/') . '/')?>"><?=h($b)?></option>
            <?php endforeach; ?>
          </select>
          <input name="root_path" value="<?=h($site['root_path'])?>" required>
          <small>
            <?=h(t('site.help.root_path_prefix', [], 'Root webu má být např.'))?> <code>/var/lib/oris-core/sites/domena.cz/public</code>.
            <?=h(t('site.help.root_path_suffix', [], 'Provisioner už nevytváří www a rebuild nepřepisuje existující index.php.'))?>
          </small>
        </div>
      </div>

      <div class="row">
        <div>
          <label>
            <input type="checkbox" name="force_https" value="1" <?= (int)sf($site, 'force_https', 0) ? 'checked' : '' ?>>
            <?php te('site.field.force_https', [], 'Vynutit HTTPS'); ?>
          </label>
          <small><?php te('site.help.force_https', [], 'Přesměruje HTTP na HTTPS, pokud je dostupný certifikát.'); ?></small>
        </div>

        <div>
          <label>
            <input type="checkbox" name="hsts" value="1" <?= (int)sf($site, 'hsts', 0) ? 'checked' : '' ?>>
            <?php te('site.field.hsts', [], 'HSTS'); ?>
          </label>
          <small><?php te('site.help.hsts', [], 'Zapne Strict-Transport-Security hlavičku.'); ?></small>
        </div>

        <div>
          <label>
            <input type="checkbox" name="pretty_urls" value="1" <?= (int)sf($site, 'pretty_urls', 1) ? 'checked' : '' ?>>
            <?php te('site.field.pretty_urls', [], 'Hezké URL / front controller'); ?>
          </label>
          <small>
            <?=h(t('site.help.pretty_urls_prefix', [], 'Zapne Nginx obdobu běžného .htaccess:'))?>
            <code>try_files $uri $uri/ /index.php?$query_string</code>.
            <?=h(t('site.help.pretty_urls_suffix', [], 'Potřebné pro adresy typu'))?> <code>/cs/hlavni</code>.
          </small>
        </div>
      </div>

      <h3 style="margin-top:18px"><?=h(t('site.php.heading', [], 'PHP pro tento web'))?></h3>

      <div class="row">
        <div>
          <label>
            <input type="checkbox" name="php_enabled" value="1" <?= (int)sf($site, 'php_enabled', 1) ? 'checked' : '' ?>>
            <?php te('site.field.php_enabled', [], 'PHP-FPM pool pro web'); ?>
          </label>
          <small><?php te('site.help.php_enabled', [], 'Provisioner vytvoří samostatný pool/socket pro tento web.'); ?></small>
        </div>

        <div>
          <label>
            <input type="checkbox" name="php_opcache_enabled" value="1" <?= (int)sf($site, 'php_opcache_enabled', 1) ? 'checked' : '' ?>>
            <?php te('site.field.opcache', [], 'OPcache'); ?>
          </label>
        </div>
      </div>

      <div class="grid2">
        <label>memory_limit<br><input name="php_memory_limit" value="<?=h(sf($site, 'php_memory_limit', '512M'))?>"></label>
        <label>upload_max_filesize<br><input name="php_upload_max_filesize" value="<?=h(sf($site, 'php_upload_max_filesize', '256M'))?>"></label>
        <label>post_max_size<br><input name="php_post_max_size" value="<?=h(sf($site, 'php_post_max_size', '256M'))?>"></label>
        <label>max_execution_time<br><input name="php_max_execution_time" value="<?=h(sf($site, 'php_max_execution_time', '300'))?>"></label>
        <label>max_input_time<br><input name="php_max_input_time" value="<?=h(sf($site, 'php_max_input_time', '300'))?>"></label>
        <label>timezone<br><input name="php_timezone" value="<?=h(sf($site, 'php_timezone', 'Europe/Prague'))?>"></label>
      </div>

      <label style="margin-top:10px;display:block">
        <?=h(t('site.field.php_custom_ini', [], 'Vlastní PHP ini direktivy pro web'))?><br>
        <textarea name="php_custom_ini" rows="5" placeholder="<?=h(t('site.placeholder.php_custom_ini', [], 'např.'))?>&#10;display_errors=Off&#10;max_file_uploads=50"><?=h(sf($site, 'php_custom_ini', ''))?></textarea>
      </label>

      <h3 style="margin-top:18px"><?=h(t('site.nginx.heading', [], 'Vlastní nastavení vhostu'))?></h3>

      <label>
        <?=h(t('site.field.nginx_extra', [], 'Extra Nginx direktivy uvnitř server bloku'))?><br>
        <textarea name="nginx_extra" rows="7" placeholder="<?=h(t('site.placeholder.nginx_extra', [], 'např.'))?>&#10;client_max_body_size 512M;&#10;add_header X-Robots-Tag noindex;"><?=h(sf($site, 'nginx_extra', ''))?></textarea>
      </label>

      <small>
        <?=h(t('site.help.nginx_extra_1', [], 'Používej direktivy pro server blok. Můžeš vložit i vlastní location bloky.'))?>
        <?=h(t('site.help.nginx_extra_2', [], 'Pokud vložíš vlastní location / blok, provisioner automaticky nevygeneruje výchozí location /, aby nevznikla duplicita try_files.'))?>
        <?=h(t('site.help.nginx_extra_3', [], 'Nebezpečné věci jako nový server blok, listen, root nebo vlastní include se ignorují.'))?>
      </small>

      <div class="row" style="margin-top:16px">
        <button class="btn" name="save" value="1"><?=h(t('site.action.save_rebuild', [], 'Uložit + přegenerovat'))?></button>
        <button class="btn2" name="apply" value="1" onclick="return confirm(<?=json_encode(t('site.confirm.rebuild_vhost', [], 'Přegenerovat vhost/PHP pool?'))?>);">
          <?php te('common.apply_rebuild', [], 'Aplikovat / rebuild'); ?>
        </button>

        <?php if ($site['status'] === 'active'): ?>
          <button class="btn-danger" name="disable" value="1" onclick="return confirm(<?=json_encode(t('site.confirm.disable', [], 'Zakázat web?'))?>);">
            <?php te('common.disable', [], 'Zakázat'); ?>
          </button>
        <?php else: ?>
          <button class="btn" name="enable" value="1" onclick="return confirm(<?=json_encode(t('site.confirm.enable', [], 'Povolit web?'))?>);">
            <?php te('common.enable', [], 'Povolit'); ?>
          </button>
        <?php endif; ?>

        <a class="btn2" href="/sites.php" style="text-decoration:none;display:inline-block"><?php te('common.back', [], 'Zpět'); ?></a>
      </div>
    </form>
  </div>

  <div class="card">
    <h3><?php te('backup.heading', [], 'Zálohy'); ?></h3>
    <small>
      <?php te('backup.help', [], 'Zálohy a obnovy webu.'); ?>
      <?php te('backup.help.provisioner_rights', [], 'Akce běží přes provisioner, takže fungují i tam, kde PHP/web user nemá přímá práva na root webu.'); ?>
    </small>

    <div class="row" style="margin-top:12px;">
      <form method="post" action="/backup.php?id=<?=h($site['id'])?>" style="margin:0;">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="id" value="<?=h($site['id'])?>">
        <button class="btn2" name="create_data" value="1" onclick="return confirm(<?=json_encode(t('backup.confirm.create_data', [], 'Vytvořit zálohu dat?'))?>);">
          <?php te('backup.action.create_data', [], 'Vytvořit zálohu dat'); ?>
        </button>
      </form>

      <form method="post" action="/backup.php?id=<?=h($site['id'])?>" style="margin:0;">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="id" value="<?=h($site['id'])?>">
        <button class="btn2" name="create_db" value="1" onclick="return confirm(<?=json_encode(t('backup.confirm.create_db', [], 'Vytvořit zálohu databáze?'))?>);">
          <?php te('backup.action.create_db', [], 'Vytvořit zálohu DB'); ?>
        </button>
      </form>
    </div>

    <hr style="border:0;border-top:1px solid #22314f; margin:16px 0;">

    <div class="row">
      <div>
        <h4><?php te('backup.data.restore_upload.heading', [], 'Obnova dat ze ZIP / TAR.GZ'); ?></h4>

        <form method="post" action="/backup.php?id=<?=h($site['id'])?>" enctype="multipart/form-data" class="js-upload-progress-form">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="id" value="<?=h($site['id'])?>">
          <input type="file" name="data_file" accept=".zip,.tar.gz,.tgz" required>
          <small><?php te('backup.help.upload_data', [], 'Nahraj ZIP/TAR.GZ se soubory webu.'); ?></small>

          <div style="margin-top:8px">
            <button class="btn2" name="restore_data" value="1" onclick="return confirm(<?=json_encode(t('backup.confirm.upload_restore_data', [], 'Nahrát soubor a obnovit data?'))?>);">
              <?php te('backup.action.upload_restore_data', [], 'Nahrát a obnovit data'); ?>
            </button>
          </div>
        </form>
      </div>

      <div>
        <h4><?php te('backup.db.restore_upload.heading', [], 'Obnova DB ze SQL / SQL.GZ'); ?></h4>

        <form method="post" action="/backup.php?id=<?=h($site['id'])?>" enctype="multipart/form-data" class="js-upload-progress-form">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="id" value="<?=h($site['id'])?>">
          <input type="file" name="db_file" accept=".sql,.gz,.sql.gz" required>
          <small><?php te('backup.help.upload_db', [], 'Nahraj SQL nebo SQL.GZ dump databáze.'); ?></small>

          <div style="margin-top:8px">
            <button class="btn2" name="restore_db" value="1" onclick="return confirm(<?=json_encode(t('backup.confirm.upload_restore_db', [], 'Nahrát soubor a obnovit databázi?'))?>);">
              <?php te('backup.action.upload_restore_db', [], 'Nahrát a obnovit DB'); ?>
            </button>
          </div>
        </form>
      </div>
    </div>

    <hr style="border:0;border-top:1px solid #22314f; margin:16px 0;">

    <div class="row">
      <div>
        <h4><?php te('backup.data.heading', [], 'Zálohy dat'); ?></h4>

        <?php if (!$backData): ?>
          <small><?php te('backup.none', [], 'Žádné zálohy.'); ?></small>
        <?php else: ?>
          <div class="table-scroll">
            <table>
              <tr>
                <th><?php te('backup.col.file', [], 'Soubor'); ?></th>
                <th><?php te('backup.col.size', [], 'Velikost'); ?></th>
                <th><?php te('backup.col.date', [], 'Datum'); ?></th>
                <th><?php te('common.actions', [], 'Akce'); ?></th>
              </tr>

              <?php foreach ($backData as $b): ?>
                <tr>
                  <td><code><?=h($b['name'])?></code></td>
                  <td><?=h(human_bytes((int)$b['size']))?></td>
                  <td><?=h(date('Y-m-d H:i:s', (int)$b['mtime']))?></td>
                  <td>
                    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
                      <a class="btn2" href="/backup.php?action=download&type=data&id=<?=h($site['id'])?>&file=<?=h($b['name'])?>" style="text-decoration:none;display:inline-block">
                        <?php te('common.download', [], 'Stáhnout'); ?>
                      </a>

                      <form method="post" action="/backup.php?id=<?=h($site['id'])?>" style="margin:0;display:inline-block">
                        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                        <input type="hidden" name="id" value="<?=h($site['id'])?>">
                        <input type="hidden" name="file" value="<?=h($b['name'])?>">
                        <button class="btn2" name="restore_existing_data" value="1" onclick="return confirm(<?=json_encode(t('backup.confirm.restore_data', ['file' => $b['name']], 'Obnovit zálohu {file}?'))?>);">
                          <?=h(t('common.restore', [], 'Obnovit'))?>
                        </button>
                      </form>

                      <form method="post" action="/backup.php?id=<?=h($site['id'])?>" style="margin:0;display:inline-block">
                        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                        <input type="hidden" name="id" value="<?=h($site['id'])?>">
                        <input type="hidden" name="type" value="data">
                        <input type="hidden" name="file" value="<?=h($b['name'])?>">
                        <button class="btn-danger" name="delete_backup" value="1" onclick="return confirm(<?=json_encode(t('backup.confirm.delete', [], 'Smazat zálohu?'))?>);">
                          <?=h(t('common.delete', [], 'Smazat'))?>
                        </button>
                      </form>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
            </table>
          </div>
        <?php endif; ?>
      </div>

      <div>
        <h4><?php te('backup.db.heading', [], 'Zálohy databáze'); ?></h4>

        <?php if (!$backDb): ?>
          <small><?php te('backup.none', [], 'Žádné zálohy.'); ?></small>
        <?php else: ?>
          <div class="table-scroll">
            <table>
              <tr>
                <th><?php te('backup.col.file', [], 'Soubor'); ?></th>
                <th><?php te('backup.col.size', [], 'Velikost'); ?></th>
                <th><?php te('backup.col.date', [], 'Datum'); ?></th>
                <th><?php te('common.actions', [], 'Akce'); ?></th>
              </tr>

              <?php foreach ($backDb as $b): ?>
                <tr>
                  <td><code><?=h($b['name'])?></code></td>
                  <td><?=h(human_bytes((int)$b['size']))?></td>
                  <td><?=h(date('Y-m-d H:i:s', (int)$b['mtime']))?></td>
                  <td>
                    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
                      <a class="btn2" href="/backup.php?action=download&type=db&id=<?=h($site['id'])?>&file=<?=h($b['name'])?>" style="text-decoration:none;display:inline-block">
                        <?php te('common.download', [], 'Stáhnout'); ?>
                      </a>

                      <form method="post" action="/backup.php?id=<?=h($site['id'])?>" style="margin:0;display:inline-block">
                        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                        <input type="hidden" name="id" value="<?=h($site['id'])?>">
                        <input type="hidden" name="file" value="<?=h($b['name'])?>">
                        <button class="btn2" name="restore_existing_db" value="1" onclick="return confirm(<?=json_encode(t('backup.confirm.restore_db', ['file' => $b['name']], 'Obnovit databázovou zálohu {file}?'))?>);">
                          <?=h(t('common.restore', [], 'Obnovit'))?>
                        </button>
                      </form>

                      <form method="post" action="/backup.php?id=<?=h($site['id'])?>" style="margin:0;display:inline-block">
                        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                        <input type="hidden" name="id" value="<?=h($site['id'])?>">
                        <input type="hidden" name="type" value="db">
                        <input type="hidden" name="file" value="<?=h($b['name'])?>">
                        <button class="btn-danger" name="delete_backup" value="1" onclick="return confirm(<?=json_encode(t('backup.confirm.delete', [], 'Smazat zálohu?'))?>);">
                          <?=h(t('common.delete', [], 'Smazat'))?>
                        </button>
                      </form>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
            </table>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <div id="uploadProgressModal" class="upload-modal" hidden>
    <div class="upload-modal-box">
      <h3><?=h(t('site.upload.heading', [], 'Nahrávání zálohy'))?></h3>
      <p id="uploadProgressText"><?=h(t('site.upload.preparing', [], 'Připravuji upload...'))?></p>

      <div class="upload-progress-wrap">
        <div id="uploadProgressBar" class="upload-progress-bar" style="width:0%"></div>
      </div>

      <div class="upload-progress-meta">
        <span id="uploadProgressPercent">0 %</span>
        <span id="uploadProgressSize"></span>
      </div>

      <p class="muted" style="margin-top:12px;">
        <?=h(t('site.upload.do_not_close', [], 'Nezavírej stránku, dokud upload neskončí.'))?>
      </p>
    </div>
  </div>

  <style>
    .upload-modal {
      position: fixed;
      inset: 0;
      z-index: 9999;
      background: rgba(0, 0, 0, .65);
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .upload-modal[hidden] {
      display: none;
    }

    .upload-modal-box {
      width: min(520px, calc(100vw - 32px));
      background: #111827;
      border: 1px solid #24324a;
      border-radius: 16px;
      padding: 22px;
      box-shadow: 0 20px 70px rgba(0, 0, 0, .45);
    }

    .upload-modal-box h3 {
      margin: 0 0 10px;
    }

    .upload-progress-wrap {
      width: 100%;
      height: 18px;
      background: #0b1220;
      border: 1px solid #24324a;
      border-radius: 999px;
      overflow: hidden;
      margin-top: 12px;
    }

    .upload-progress-bar {
      height: 100%;
      width: 0;
      background: linear-gradient(90deg, #38bdf8, #22c55e);
      transition: width .15s linear;
    }

    .upload-progress-meta {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      margin-top: 8px;
      font-size: 13px;
      color: #9ca3af;
    }
  </style>

  <script>
    (function () {
      const TXT_UPLOADING = <?=json_encode(t('site.upload.uploading', [], 'Nahrávám zálohu...'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>;
      const TXT_PROCESSING = <?=json_encode(t('site.upload.processing', [], 'Upload dokončen, server zpracovává soubor...'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>;
      const TXT_DONE = <?=json_encode(t('site.upload.done_redirect', [], 'Hotovo, přecházím na výsledek...'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>;
      const TXT_FAILED_HTTP = <?=json_encode(t('site.upload.failed_http', [], 'Upload selhal: HTTP '), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>;
      const TXT_FAILED_CONNECTION = <?=json_encode(t('site.upload.failed_connection', [], 'Upload selhal: chyba spojení.'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>;
      const TXT_ABORTED = <?=json_encode(t('site.upload.aborted', [], 'Upload byl přerušen.'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>;

      function fmtBytes(bytes) {
        if (!Number.isFinite(bytes) || bytes <= 0) return '';

        const units = ['B', 'KB', 'MB', 'GB'];
        let size = bytes;
        let unit = 0;

        while (size >= 1024 && unit < units.length - 1) {
          size /= 1024;
          unit++;
        }

        return size.toFixed(unit === 0 ? 0 : 1) + ' ' + units[unit];
      }

      const modal = document.getElementById('uploadProgressModal');
      const bar = document.getElementById('uploadProgressBar');
      const text = document.getElementById('uploadProgressText');
      const percentText = document.getElementById('uploadProgressPercent');
      const sizeText = document.getElementById('uploadProgressSize');

      if (!modal || !bar || !text || !percentText || !sizeText) {
        return;
      }

      document.querySelectorAll('form.js-upload-progress-form').forEach(function (form) {
        form.addEventListener('submit', function (ev) {
          ev.preventDefault();

          const submitter = ev.submitter || document.activeElement;
          const fd = new FormData(form);

          // FormData(form) nemusí přidat kliknuté tlačítko.
          // Bez toho backup.php neuvidí restore_data / restore_db.
          if (submitter && submitter.name && !fd.has(submitter.name)) {
            fd.append(submitter.name, submitter.value || '1');
          }

          modal.hidden = false;
          bar.style.width = '0%';
          text.textContent = TXT_UPLOADING;
          percentText.textContent = '0 %';
          sizeText.textContent = '';

          const xhr = new XMLHttpRequest();
          xhr.open('POST', form.action, true);
          xhr.withCredentials = true;

          xhr.upload.addEventListener('progress', function (e) {
            if (!e.lengthComputable) {
              text.textContent = TXT_UPLOADING;
              return;
            }

            const pct = Math.round((e.loaded / e.total) * 100);
            bar.style.width = pct + '%';
            percentText.textContent = pct + ' %';
            sizeText.textContent = fmtBytes(e.loaded) + ' / ' + fmtBytes(e.total);

            if (pct >= 100) {
              text.textContent = TXT_PROCESSING;
            }
          });

          xhr.onload = function () {
            if (xhr.status >= 200 && xhr.status < 400) {
              text.textContent = TXT_DONE;
              bar.style.width = '100%';
              percentText.textContent = '100 %';

              window.location.href = xhr.responseURL || form.action;
              return;
            }

            text.textContent = TXT_FAILED_HTTP + xhr.status;
          };

          xhr.onerror = function () {
            text.textContent = TXT_FAILED_CONNECTION;
          };

          xhr.onabort = function () {
            text.textContent = TXT_ABORTED;
          };

          xhr.send(fd);
        });
      });
    })();
  </script>
<?php
});

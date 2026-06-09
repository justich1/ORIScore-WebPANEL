<?php
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

/** @var PDO $pdo */
/** @var ?PDO $pdoMail */
/** @var array $config */

if (!$pdoMail) {
  render($pdo, t('page.mail_server.title', [], 'E-mail server'), function(){ ?>
    <div class="card">
      <h2><?=h(t('page.mail_server.title', [], 'E-mail server'))?></h2>
      <p class="pill err"><?=h(t('mail.err.db_missing', [], 'Mail DB není nakonfigurovaná. Doplň <code>mail_db</code> do <code>config.php</code>.'))?></p>
    </div>
  <?php });
  exit;
}

function s(PDO $pdo, string $k, string $def=''): string {
  $v = setting($pdo, $k, $def);
  return $v === null ? $def : (string)$v;
}
function b(PDO $pdo, string $k, bool $def=false): bool {
  return s($pdo, $k, $def ? '1':'0') === '1';
}
function setb(PDO $pdo, string $k, bool $v): void {
  set_setting($pdo, $k, $v ? '1' : '0');
}

function read_kv_file(string $path): array {
  if (!is_file($path) || !is_readable($path)) return [];
  $rows = @file($path, FILE_IGNORE_NEW_LINES);
  if (!is_array($rows)) return [];
  $out = [];
  foreach ($rows as $ln) {
    $ln = trim((string)$ln);
    if ($ln==='' || str_starts_with($ln,'#')) continue;
    // postfix style: key = value
    if (preg_match('/^([a-zA-Z0-9_]+)\s*=\s*(.+)$/', $ln, $m)) {
      $k = trim($m[1]);
      $v = trim($m[2]);
      $out[$k] = $v;
    }
  }
  return $out;
}

function read_rspamd_actions_scores(): array {
  $paths = ['/etc/rspamd/local.d/actions.conf','/etc/rspamd/actions.conf','/usr/share/rspamd/config/actions.conf'];
  $txt = '';
  foreach ($paths as $p) {
    if (is_file($p) && is_readable($p)) { $txt = (string)@file_get_contents($p); if ($txt!=='') break; }
  }
  $out = ['reject'=>null,'add_header'=>null,'greylist'=>null,'rewrite_subject'=>null];
  if ($txt==='') return $out;
  foreach (array_keys($out) as $k) {
    if (preg_match('/\b'.preg_quote($k,'/').'\s*=\s*([-+]?\d+(?:\.\d+)?)\s*;/', $txt, $m)) $out[$k] = (float)$m[1];
  }
  return $out;
}

function read_rspamd_metrics_weight(string $symbol): ?float {
  $files = [
    '/etc/rspamd/local.d/metrics.conf',
    '/etc/rspamd/metrics.conf',
    '/usr/share/rspamd/config/metrics.conf',
  ];
  foreach ($files as $f) {
    if (!is_file($f) || !is_readable($f)) continue;
    $txt = @file_get_contents($f);
    if (!is_string($txt) || $txt==='') continue;

    // Match: symbol "BAYES_SPAM" { ... weight = 4.0; ... }
    $re = '/symbol\s+["\']'.preg_quote($symbol,'/').'["\']\s*\{.*?\bweight\s*=\s*([-+]?\d+(?:\.\d+)?)\s*;/si';
    if (preg_match($re, $txt, $m)) return (float)$m[1];

    // Match: BAYES_SPAM = 4.0; (fallback)
    $re2 = '/\b'.preg_quote($symbol,'/').'\b\s*=\s*([-+]?\d+(?:\.\d+)?)\s*;/' ;
    if (preg_match($re2, $txt, $m2)) return (float)$m2[1];
  }
  return null;
}


function queue_mail_job(PDO $pdo, string $type, int $refId = 0, array $payload = []): void {
  $json = $payload ? json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE) : '{}';
  $st = $pdo->prepare("INSERT INTO jobs(type,ref_id,payload,status) VALUES(?,?,?, 'queued')");
  $st->execute([$type, $refId, $json]);
}

function roundcube_plugin_enabled(string $plugin): bool {
  // Debian default
  $paths = [
    '/etc/roundcube/config.inc.php',
    '/var/lib/roundcube/config/config.inc.php',
    '/usr/share/roundcube/config/config.inc.php',
  ];
  foreach ($paths as $p) {
    if (!is_file($p) || !is_readable($p)) continue;
    $txt = @file_get_contents($p);
    if (!is_string($txt) || $txt==='') continue;
    // cheap-but-safe: check if plugin name appears in config
    if (preg_match('/\\b'.preg_quote($plugin,'/').'\\b/i', $txt)) return true;
  }
  // fallback: plugin directory exists (doesn't mean enabled, but indicates availability)
  $dirs = [
    '/usr/share/roundcube/plugins/'.$plugin,
    '/var/lib/roundcube/plugins/'.$plugin,
    '/usr/share/roundcubemail/plugins/'.$plugin,
  ];
  foreach ($dirs as $d) if (is_dir($d)) return true;
  return false;
}

function up_tmp(array $f): string {
  if (!isset($f['error']) || $f['error'] !== UPLOAD_ERR_OK) {
    throw new RuntimeException(t('mail_server.err.upload_failed', [], 'Upload se nepovedl'));
  }
  $src = (string)($f['tmp_name'] ?? '');
  if ($src === '' || !is_file($src)) throw new RuntimeException(t('mail_server.err.upload_tmp_missing', [], 'Upload tmp soubor chybí'));
  $dst = tempnam(sys_get_temp_dir(), 'oris_upload_');
  if ($dst === false) throw new RuntimeException(t('common.err.tmp_create_failed', [], 'Nelze vytvořit tmp'));
  if (!move_uploaded_file($src, $dst)) {
    @unlink($dst);
    throw new RuntimeException(t('mail_server.err.upload_move_failed', [], 'Nelze přesunout upload'));
  }
  return $dst;
}


function oris_safe_filename(string $name): string {
  $name = basename($name);
  $name = preg_replace('~[^A-Za-z0-9._-]+~', '_', $name) ?: 'upload.bin';
  return trim($name, '._') ?: 'upload.bin';
}

function oris_mail_upload_dir(PDO $pdo): string {
  return rtrim(setting($pdo, 'upload_staging_dir', '/var/lib/oris-core/uploads') ?: '/var/lib/oris-core/uploads', '/') . '/mail';
}

function oris_mail_backup_dir(PDO $pdo): string {
  return rtrim(setting($pdo, 'mail_backup_dir', '/var/lib/oris-core/backups/mail') ?: '/var/lib/oris-core/backups/mail', '/');
}

function oris_mail_bayes_backup_dir(PDO $pdo): string {
  return rtrim(setting($pdo, 'mail_bayes_backup_dir', '/var/lib/oris-core/backups/rspamd') ?: '/var/lib/oris-core/backups/rspamd', '/');
}

function store_upload_for_job(PDO $pdo, array $f, string $prefix, string $extRegex): string {
  if (!isset($f['error']) || $f['error'] !== UPLOAD_ERR_OK) {
    throw new RuntimeException(t('mail_server.err.upload_failed', [], 'Upload se nepovedl'));
  }

  $orig = oris_safe_filename((string)($f['name'] ?? 'upload.bin'));
  if (!preg_match($extRegex, $orig)) {
    throw new RuntimeException(t('mail_server.err.bad_file_type', ['file' => $orig], 'Nepovolený typ souboru: {file}'));
  }

  $dir = oris_mail_upload_dir($pdo);
  if (!is_dir($dir) && !mkdir($dir, 0770, true) && !is_dir($dir)) {
    throw new RuntimeException(t('mail_server.err.staging_create_failed', ['dir' => $dir], 'Nelze vytvořit upload staging adresář: {dir}'));
  }

  $dst = $dir . '/' . date('Ymd-His') . '-' . $prefix . '-' . $orig;
  if (!move_uploaded_file((string)$f['tmp_name'], $dst)) {
    throw new RuntimeException(t('mail_server.err.upload_move_to_staging_failed', [], 'Nelze přesunout upload do staging adresáře.'));
  }
  @chmod($dst, 0640);
  return $dst;
}

function list_backup_files(string $dir, string $pattern): array {
  if (!is_dir($dir)) return [];
  $rows = [];
  foreach (glob(rtrim($dir, '/') . '/' . $pattern) ?: [] as $p) {
    if (!is_file($p) || !is_readable($p)) continue;
    $rows[] = [
      'name' => basename($p),
      'path' => $p,
      'size' => filesize($p) ?: 0,
      'mtime' => filemtime($p) ?: 0,
    ];
  }
  usort($rows, fn($a,$b) => $b['mtime'] <=> $a['mtime']);
  return $rows;
}

function download_backup_file(PDO $pdo, string $kind, string $name): void {
  $name = oris_safe_filename($name);
  $base = match ($kind) {
    'bayes' => oris_mail_bayes_backup_dir($pdo),
    default => oris_mail_backup_dir($pdo),
  };
  $path = realpath($base . '/' . $name);
  $root = realpath($base);
  if (!$path || !$root || !str_starts_with($path, $root . DIRECTORY_SEPARATOR) || !is_file($path) || !is_readable($path)) {
    http_response_code(404);
    echo t('common.file_not_found', [], 'Soubor nenalezen');
    exit;
  }

  $ctype = str_ends_with($name, '.zip') ? 'application/zip' : 'application/gzip';
  header('Content-Type: ' . $ctype);
  header('Content-Disposition: attachment; filename="' . str_replace('"', '', basename($path)) . '"');
  header('Content-Length: ' . filesize($path));
  readfile($path);
  exit;
}

function mkzip_download(array $files, string $zipName): void {
  $tmp = tempnam(sys_get_temp_dir(), 'oris_mailzip_');
  if ($tmp === false) throw new RuntimeException(t('common.err.tmp_create_failed', [], 'Nelze vytvořit tmp'));
  @unlink($tmp);
  $zipPath = $tmp.'.zip';

  $z = new ZipArchive();
  if ($z->open($zipPath, ZipArchive::CREATE)!==true) throw new RuntimeException(t('mail_server.err.zip_create_failed', [], 'Nelze vytvořit ZIP'));
  foreach ($files as $pathInZip => $content) $z->addFromString($pathInZip, (string)$content);
  $z->close();

  header('Content-Type: application/zip');
  header('Content-Disposition: attachment; filename="'.$zipName.'"');
  header('Content-Length: '.filesize($zipPath));
  readfile($zipPath);
  @unlink($zipPath);
  exit;
}


if (isset($_GET['download_backup'])) {
  download_backup_file($pdo, (string)($_GET['kind'] ?? 'full'), (string)$_GET['download_backup']);
}

// ---- System (live) values (what is REALLY in /etc right now)
$postfix = read_kv_file('/etc/postfix/main.cf');
$rspamdActions = read_rspamd_actions_scores();
$sys = [
  'myhostname' => $postfix['myhostname'] ?? null,
  'tls_cert'   => $postfix['smtpd_tls_cert_file'] ?? null,
  'tls_key'    => $postfix['smtpd_tls_key_file'] ?? null,
  'milter'     => null,
  'reject'     => $rspamdActions['reject'],
  'add_header' => $rspamdActions['add_header'],
  'greylist'   => $rspamdActions['greylist'],
  'rewrite_subject' => $rspamdActions['rewrite_subject'],
  'bayes_spam_weight' => read_rspamd_metrics_weight('BAYES_SPAM'),
  'bayes_ham_weight'  => read_rspamd_metrics_weight('BAYES_HAM'),
  'learn_ham_script'  => is_file('/etc/dovecot/sieve-pipe/rspamc-learn-ham'),
  'learn_spam_script' => is_file('/etc/dovecot/sieve-pipe/rspamc-learn-spam'),
  'rc_markasjunk'     => roundcube_plugin_enabled('markasjunk'),
];

if (isset($postfix['smtpd_milters'])) {
  // try to extract inet:host:port
  if (preg_match('/inet:([^\s,]+)/', (string)$postfix['smtpd_milters'], $m)) $sys['milter'] = $m[1];
}

// ---- Panel values (stored)
$cfg = [
  'myhostname' => s($pdo,'mail.postfix.myhostname', (string)($sys['myhostname'] ?? '')),
  'tls_cert'   => s($pdo,'mail.postfix.tls_cert', (string)($sys['tls_cert'] ?? '/etc/ssl/certs/ssl-cert-snakeoil.pem')),
  'tls_key'    => s($pdo,'mail.postfix.tls_key', (string)($sys['tls_key'] ?? '/etc/ssl/private/ssl-cert-snakeoil.key')),

  'rspamd_enabled' => b($pdo,'mail.rspamd.enabled', true),
  'rspamd_milter'  => s($pdo,'mail.rspamd.milter', (string)($sys['milter'] ?? '127.0.0.1:11332')),
  'rspamd_reject'  => (int)s($pdo,'mail.rspamd.reject_score', (string)((int)($sys['reject'] ?? 15))),
  'rspamd_addhdr'  => (int)s($pdo,'mail.rspamd.add_header_score', (string)((int)($sys['add_header'] ?? 6))),
  'rspamd_greylist'=> (int)s($pdo,'mail.rspamd.greylist_score', (string)((int)($sys['greylist'] ?? 4))),
  'rspamd_rewrite' => (int)s($pdo,'mail.rspamd.rewrite_subject_score', (string)((int)($sys['rewrite_subject'] ?? 7))),

  'fail2ban_enabled' => b($pdo,'mail.fail2ban.enabled', true),
  'f2b_findtime'     => s($pdo,'mail.fail2ban.findtime','10m'),
  'f2b_bantime'      => s($pdo,'mail.fail2ban.bantime','1h'),
  'f2b_maxretry'     => s($pdo,'mail.fail2ban.maxretry','6'),

  'aliases_enabled'  => b($pdo,'mail.postfix.aliases.enabled', false),
  'mask_secrets_zip' => b($pdo,'mail.pack.mask_secrets', true),

  // Rspamd symbol weights
  'bayes_spam_score' => (float)s($pdo,'mail.rspamd.score.BAYES_SPAM', (string)($sys['bayes_spam_weight'] ?? 4.0)),
  'bayes_ham_score'  => (float)s($pdo,'mail.rspamd.score.BAYES_HAM',  (string)($sys['bayes_ham_weight'] ?? -1.0)),

  // Roundcube
  'rc_enabled'       => b($pdo,'mail.roundcube.enabled', true),
  'rc_junk_mbox'     => s($pdo,'mail.roundcube.junk_mbox','Junk'),
  'rc_learn_enabled' => b($pdo,'mail.roundcube.learn.enabled', true),
  'rc_rspamc_host'   => s($pdo,'mail.roundcube.rspamc_host','127.0.0.1:11334'),
  'rc_rspamc_pass'   => s($pdo,'mail.roundcube.rspamc_pass_file',''),
];

$domains = $pdoMail->query("
  SELECT d.id, d.domain, d.is_active,
         dk.selector, dk.dns_txt, dk.updated_at
  FROM domains d
  LEFT JOIN domain_dkim dk ON dk.domain_id = d.id
  ORDER BY d.domain
")->fetchAll();

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();
  $action = (string)($_POST['action'] ?? '');

  try {
    if ($action === 'save') {
      // Ukládej jen to, co patří k aktuální záložce.
      // Každý <form> posílá hidden input: tab=tab-overview|tab-rspamd|tab-roundcube|tab-f2b
      $tab = (string)($_POST['tab'] ?? 'tab-overview');

      // helper: nastav jen když pole fakt přišlo v POSTu (jiná záložka ho neposílá)
      $set_if = function(string $k, string $field, callable $norm) use ($pdo): void {
        if (!array_key_exists($field, $_POST)) return;
        $v = $norm($_POST[$field]);
        set_setting($pdo, $k, (string)$v);
      };
      $setb_if = function(string $k, string $field) use ($pdo): void {
        if (!array_key_exists($field, $_POST)) return;
        setb($pdo, $k, !empty($_POST[$field]));
      };

      if ($tab === 'tab-overview') {
        $set_if('mail.postfix.myhostname', 'myhostname', fn($v)=>trim((string)$v));
        $set_if('mail.postfix.tls_cert',   'tls_cert',   fn($v)=>trim((string)$v));
        $set_if('mail.postfix.tls_key',    'tls_key',    fn($v)=>trim((string)$v));

        $setb_if('mail.postfix.aliases.enabled', 'aliases_enabled');
        $setb_if('mail.pack.mask_secrets',       'mask_secrets_zip');
      }

      if ($tab === 'tab-rspamd') {
        $setb_if('mail.rspamd.enabled', 'rspamd_enabled');

        $set_if('mail.rspamd.milter',                'rspamd_milter',   fn($v)=>trim((string)$v));
        $set_if('mail.rspamd.reject_score',          'rspamd_reject',   fn($v)=>(string)(int)$v);
        $set_if('mail.rspamd.add_header_score',      'rspamd_addhdr',   fn($v)=>(string)(int)$v);
        $set_if('mail.rspamd.greylist_score',        'rspamd_greylist', fn($v)=>(string)(int)$v);
        $set_if('mail.rspamd.rewrite_subject_score', 'rspamd_rewrite',  fn($v)=>(string)(int)$v);

        $set_if('mail.rspamd.score.BAYES_SPAM', 'bayes_spam_score', fn($v)=>(string)(float)$v);
        $set_if('mail.rspamd.score.BAYES_HAM',  'bayes_ham_score',  fn($v)=>(string)(float)$v);
      }

      if ($tab === 'tab-f2b') {
        $setb_if('mail.fail2ban.enabled', 'fail2ban_enabled');
        $set_if('mail.fail2ban.findtime', 'f2b_findtime', fn($v)=>trim((string)$v));
        $set_if('mail.fail2ban.bantime',  'f2b_bantime',  fn($v)=>trim((string)$v));
        $set_if('mail.fail2ban.maxretry', 'f2b_maxretry', fn($v)=>trim((string)$v));
      }

      if ($tab === 'tab-roundcube') {
        $setb_if('mail.roundcube.enabled',       'rc_enabled');
        $set_if ('mail.roundcube.junk_mbox',     'rc_junk_mbox', fn($v)=>trim((string)$v));
        $setb_if('mail.roundcube.learn.enabled', 'rc_learn_enabled');
        $set_if ('mail.roundcube.rspamc_host',   'rc_rspamc_host', fn($v)=>trim((string)$v));
        $set_if ('mail.roundcube.rspamc_pass_file', 'rc_rspamc_pass', fn($v)=>trim((string)$v));
      }

      flash_set('ok', t('common.saved', [], 'Uloženo'));
      header('Location: /mail_server.php?tab='.rawurlencode($tab)); exit;
    }

    if ($action === 'reload_from_system') {
      // Pull from /etc into DB settings (so UI reflects real state)
      $postfix = read_kv_file('/etc/postfix/main.cf');
      $rspamdActions = read_rspamd_actions_scores();

      if (isset($postfix['myhostname'])) set_setting($pdo,'mail.postfix.myhostname', (string)$postfix['myhostname']);
      if (isset($postfix['smtpd_tls_cert_file'])) set_setting($pdo,'mail.postfix.tls_cert', (string)$postfix['smtpd_tls_cert_file']);
      if (isset($postfix['smtpd_tls_key_file'])) set_setting($pdo,'mail.postfix.tls_key', (string)$postfix['smtpd_tls_key_file']);

      if (isset($postfix['smtpd_milters']) && preg_match('/inet:([^\s,]+)/', (string)$postfix['smtpd_milters'], $m)) {
        set_setting($pdo,'mail.rspamd.milter', trim($m[1]));
      }

      if ($rspamdActions['reject']!==null) set_setting($pdo,'mail.rspamd.reject_score', (string)(int)$rspamdActions['reject']);
      if ($rspamdActions['add_header']!==null) set_setting($pdo,'mail.rspamd.add_header_score', (string)(int)$rspamdActions['add_header']);
      if ($rspamdActions['greylist']!==null) set_setting($pdo,'mail.rspamd.greylist_score', (string)(int)$rspamdActions['greylist']);
      if ($rspamdActions['rewrite_subject']!==null) set_setting($pdo,'mail.rspamd.rewrite_subject_score', (string)(int)$rspamdActions['rewrite_subject']);

      $bs = read_rspamd_metrics_weight('BAYES_SPAM');
      $bh = read_rspamd_metrics_weight('BAYES_HAM');
      if ($bs!==null) set_setting($pdo,'mail.rspamd.score.BAYES_SPAM', (string)$bs);
      if ($bh!==null) set_setting($pdo,'mail.rspamd.score.BAYES_HAM', (string)$bh);

      // Roundcube plugin reality (best-effort)
      set_setting($pdo,'mail.roundcube.enabled', roundcube_plugin_enabled('markasjunk') ? '1' : '0');

      flash_set('ok', t('mail_server.flash.loaded_from_system', [], 'Načteno ze systému (/etc) do panelu'));
      header('Location: /mail_server.php'); exit;
    }

    if ($action === 'apply') {
      queue_mail_job($pdo, 'mail_stack_apply');
      flash_set('ok', t('mail_server.flash.apply_queued', [], 'Aplikace mailserver konfigurace zařazena do Python fronty.'));
      header('Location: /mail_server.php'); exit;
    }

    if ($action === 'apply_roundcube') {
      queue_mail_job($pdo, 'mail_roundcube_apply');
      flash_set('ok', t('mail_server.flash.roundcube_apply_queued', [], 'Aplikace Roundcube konfigurace zařazena do Python fronty.'));
      header('Location: /mail_server.php'); exit;
    }

    if ($action === 'test') {
      queue_mail_job($pdo, 'mail_stack_test');
      flash_set('ok', t('mail_server.flash.test_queued', [], 'Test mailserveru zařazen do Python fronty. Výsledek najdeš v Jobs.'));
      header('Location: /mail_server.php'); exit;
    }

    if ($action === 'test_roundcube') {
      queue_mail_job($pdo, 'mail_roundcube_test');
      flash_set('ok', t('mail_server.flash.roundcube_test_queued', [], 'Test Roundcube zařazen do Python fronty. Výsledek najdeš v Jobs.'));
      header('Location: /mail_server.php'); exit;
    }

    if ($action === 'restore_zip') {
      $path = store_upload_for_job($pdo, $_FILES['zip'] ?? [], 'legacy-zip', '~\.zip$~i');
      queue_mail_job($pdo, 'mail_restore_zip', 0, ['path' => $path]);
      flash_set('ok', t('mail_server.flash.restore_zip_queued', [], 'Obnova ZIP zařazena do Python fronty.'));
      header('Location: /jobs.php'); exit;
    }


    if ($action === 'bayes_backup') {
      queue_mail_job($pdo, 'mail_bayes_backup');
      flash_set('ok', t('mail_server.flash.bayes_backup_queued', [], 'Záloha Bayes/Rspamd učení zařazena do Python fronty.'));
      header('Location: /jobs.php'); exit;
    }


    if ($action === 'bayes_restore') {
      $path = store_upload_for_job($pdo, $_FILES['bayes'] ?? [], 'bayes-restore', '~\.(tar\.gz|tgz|gz|redis)$~i');
      queue_mail_job($pdo, 'mail_bayes_restore', 0, ['path' => $path]);
      flash_set('ok', t('mail_server.flash.bayes_restore_queued', [], 'Obnova Bayes/Rspamd učení zařazena do Python fronty.'));
      header('Location: /jobs.php'); exit;
    }


    if ($action === 'full_backup') {
      $mask = b($pdo,'mail.pack.mask_secrets', false);
      queue_mail_job($pdo, 'mail_backup_full', 0, ['mask' => $mask]);
      flash_set('ok', t('mail_server.flash.full_backup_queued', [], 'FULL záloha mailserveru zařazena do Python fronty.'));
      header('Location: /jobs.php'); exit;
    }


    if ($action === 'full_restore') {
      $path = store_upload_for_job($pdo, $_FILES['full'] ?? [], 'full-restore', '~\.(tar\.gz|tgz)$~i');
      queue_mail_job($pdo, 'mail_restore_full', 0, ['path' => $path]);
      flash_set('ok', t('mail_server.flash.full_restore_queued', [], 'FULL obnova mailserveru zařazena do Python fronty.'));
      header('Location: /jobs.php'); exit;
    }

    if ($action === 'delete_backup') {
      $kind = (string)($_POST['kind'] ?? 'full');
      $name = oris_safe_filename((string)($_POST['name'] ?? ''));
      if ($name === '' || !in_array($kind, ['full','bayes'], true)) {
        flash_set('err', t('mail_server.err.invalid_backup_delete', [], 'Neplatná záloha pro smazání.'));
        header('Location: /mail_server.php?tab=tab-backup'); exit;
      }
      $jobType = $kind === 'bayes' ? 'mail_bayes_backup_delete' : 'mail_backup_delete';
      queue_mail_job($pdo, $jobType, 0, ['name' => $name]);
      flash_set('ok', t('mail_server.flash.delete_backup_queued', [], 'Smazání zálohy zařazeno do Python fronty.'));
      header('Location: /jobs.php'); exit;
    }


    if ($action === 'download_zip') {
      $mailDb = $config['mail_db'] ?? [];
      $db_host = (string)($mailDb['host'] ?? '127.0.0.1');
      $db_port = (string)($mailDb['port'] ?? '3306');
      $db_name = (string)($mailDb['name'] ?? 'oris_mail');
      $db_user = (string)($mailDb['user'] ?? '');
      $db_pass = (string)($mailDb['pass'] ?? '');

      if (b($pdo,'mail.pack.mask_secrets', true) && $db_pass !== '') $db_pass = '***MASKED***';

      $myhostname = s($pdo,'mail.postfix.myhostname','');
      $tls_cert   = s($pdo,'mail.postfix.tls_cert','');
      $tls_key    = s($pdo,'mail.postfix.tls_key','');

      $rspamd_milter = s($pdo,'mail.rspamd.milter','127.0.0.1:11332');
      $aliases_on = b($pdo,'mail.postfix.aliases.enabled', false);

      $files = [];

      $files['postfix/mysql-virtual-mailbox-domains.cf'] =
"user = {$db_user}\npassword = {$db_pass}\nhosts = {$db_host}\nport = {$db_port}\ndbname = {$db_name}\nquery = SELECT 1 FROM domains WHERE domain='%s' AND is_active=1\n";
      $files['postfix/mysql-virtual-mailbox-maps.cf'] =
"user = {$db_user}\npassword = {$db_pass}\nhosts = {$db_host}\nport = {$db_port}\ndbname = {$db_name}\nquery = SELECT maildir FROM mailboxes WHERE email='%s' AND is_active=1\n";
      $files['postfix/mysql-virtual-aliases.cf'] =
"user = {$db_user}\npassword = {$db_pass}\nhosts = {$db_host}\nport = {$db_port}\ndbname = {$db_name}\nquery = SELECT destination FROM aliases WHERE source='%s' AND is_active=1\n";

      $files['rspamd/local.d/actions.conf'] =
"reject = ".(int)s($pdo,'mail.rspamd.reject_score','15').";\n".
"add_header = ".(int)s($pdo,'mail.rspamd.add_header_score','6').";\n".
"greylist = ".(int)s($pdo,'mail.rspamd.greylist_score','4').";\n".
"rewrite_subject = ".(int)s($pdo,'mail.rspamd.rewrite_subject_score','7').";\n";

      // IMPORTANT: rspamd uses 'weight' for symbol weights in metrics
      $files['rspamd/local.d/metrics.conf'] =
"symbols {\n".
"  symbol \"BAYES_SPAM\" { weight = ".(float)s($pdo,'mail.rspamd.score.BAYES_SPAM','4.0')."; }\n".
"  symbol \"BAYES_HAM\"  { weight = ".(float)s($pdo,'mail.rspamd.score.BAYES_HAM','-1.0')."; }\n".
"}\n";

      $files['roundcube/ORIS-snippet.php'] =
"// BEGIN ORIS MAIL\n".
"\$config['junk_mbox'] = '".addslashes(s($pdo,'mail.roundcube.junk_mbox','Junk'))."';\n".
"// END ORIS MAIL\n";

      $passf = trim(s($pdo,'mail.roundcube.rspamc_pass_file',''));
      $passPart = ($passf !== '') ? ('-P '.$passf.' ') : '';
      $rhost = trim(s($pdo,'mail.roundcube.rspamc_host','127.0.0.1:11334'));

      $files['roundcube/plugins/markasjunk/config.inc.php'] =
"<?php\n".
"\$config['markasjunk_mbox'] = '".addslashes(s($pdo,'mail.roundcube.junk_mbox','Junk'))."';\n".
"\$config['markasjunk_read'] = true;\n".
"\$config['markasjunk_learning_driver'] = 'cmd_learn';\n".
"\$config['markasjunk_spam_cmd'] = '".addslashes('rspamc '.$passPart.'-h '.$rhost.' learn_spam %f')."';\n".
"\$config['markasjunk_ham_cmd']  = '".addslashes('rspamc '.$passPart.'-h '.$rhost.' learn_ham %f')."';\n";

      $files['fail2ban/jail.d/oris-mail.conf'] =
"[postfix-sasl]\n".
"enabled = ".(b($pdo,'mail.fail2ban.enabled',true)?'true':'false')."\n".
"port = submission,465,smtp\n".
"filter = postfix[mode=auth]\n".
"logpath = /var/log/mail.log\n".
"maxretry = ".s($pdo,'mail.fail2ban.maxretry','6')."\n".
"findtime = ".s($pdo,'mail.fail2ban.findtime','10m')."\n".
"bantime = ".s($pdo,'mail.fail2ban.bantime','1h')."\n\n".
"[dovecot]\n".
"enabled = ".(b($pdo,'mail.fail2ban.enabled',true)?'true':'false')."\n".
"port = pop3,pop3s,imap,imaps,submission,465\n".
"logpath = /var/log/mail.log\n".
"maxretry = ".s($pdo,'mail.fail2ban.maxretry','6')."\n".
"findtime = ".s($pdo,'mail.fail2ban.findtime','10m')."\n".
"bantime = ".s($pdo,'mail.fail2ban.bantime','1h')."\n";

      $dkimTxt = [];
      foreach ($domains as $d) {
        if (!empty($d['dns_txt'])) $dkimTxt[] = $d['domain']."\n".$d['dns_txt']."\n";
      }
      $files['dns/DKIM.txt'] = $dkimTxt ? implode("\n",$dkimTxt) : "No DKIM records in domain_dkim\n";

      $files['postfix/ORIS-snippet.txt'] =
"myhostname = {$myhostname}\n".
"smtpd_tls_cert_file = {$tls_cert}\n".
"smtpd_tls_key_file = {$tls_key}\n".
"smtpd_milters = inet:{$rspamd_milter}\n".
"non_smtpd_milters = inet:{$rspamd_milter}\n".
"virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf\n".
"virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf\n".
"virtual_transport = lmtp:unix:private/dovecot-lmtp\n".
($aliases_on ? "virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-aliases.cf\n" : "# aliases disabled\n");

      mkzip_download($files, 'oris-mail-panel-configs.zip');
    }

  } catch (Throwable $e) {
    flash_set('err', $e->getMessage());
    header('Location: /mail_server.php'); exit;
  }
}


$mailBackupDir = oris_mail_backup_dir($pdo);
$bayesBackupDir = oris_mail_bayes_backup_dir($pdo);
$mailBackups = list_backup_files($mailBackupDir, '*.tar.gz');
$bayesBackups = array_merge(
  list_backup_files($bayesBackupDir, '*.tar.gz'),
  list_backup_files($bayesBackupDir, '*.tgz'),
  list_backup_files($bayesBackupDir, '*.gz'),
  list_backup_files($bayesBackupDir, '*.redis')
);

render($pdo, t('page.mail_server.title', [], 'E-mail server'), function() use ($cfg, $domains, $sys, $mailBackups, $bayesBackups) {
  $pill = function($label, $val) {
    if ($val === null || $val === '') return;
    ?><span class="pill"><?=h($label)?>: <b><?=h((string)$val)?></b></span><?php
  };
?>
  <div class="card">
    <h2><?=h(t('page.mail_server.title', [], 'E-mail server'))?></h2>

    <div class="oris-tabs" role="tablist" aria-label="<?=h(t('mail_server.tabs.aria', [], 'Mail server tabs'))?>">
      <button class="oris-tabbtn" type="button" role="tab" aria-selected="true"  data-tab="tab-overview"><?=h(t('mail_server.tab.overview', [], 'Přehled'))?></button>
      <button class="oris-tabbtn" type="button" role="tab" aria-selected="false" data-tab="tab-rspamd"><?=h(t('mail_server.tab.rspamd', [], 'Rspamd'))?></button>
      <button class="oris-tabbtn" type="button" role="tab" aria-selected="false" data-tab="tab-roundcube"><?=h(t('mail_server.tab.roundcube', [], 'Roundcube'))?></button>
      <button class="oris-tabbtn" type="button" role="tab" aria-selected="false" data-tab="tab-f2b"><?=h(t('mail_server.tab.fail2ban', [], 'Fail2Ban'))?></button>
      <button class="oris-tabbtn" type="button" role="tab" aria-selected="false" data-tab="tab-backup"><?=h(t('mail_server.tab.backup_restore', [], 'Záloha/Obnova'))?></button>
      <button class="oris-tabbtn" type="button" role="tab" aria-selected="false" data-tab="tab-dkim"><?=h(t('mail_server.tab.dkim', [], 'DKIM'))?></button>
    </div>

    <div id="tab-overview" class="oris-tabpanel is-active" role="tabpanel">
      <div class="oris-kv">
        <?php $pill('myhostname', $sys['myhostname']); ?>
        <?php $pill('TLS cert', $sys['tls_cert']); ?>
        <?php $pill('TLS key', $sys['tls_key']); ?>
        <?php $pill('milter', $sys['milter']); ?>
        <?php if ($sys['learn_ham_script']) $pill('learn ham', '/etc/dovecot/sieve-pipe/rspamc-learn-ham'); ?>
        <?php if ($sys['learn_spam_script']) $pill('learn spam', '/etc/dovecot/sieve-pipe/rspamc-learn-spam'); ?>
      </div>

      <div class="oris-smallhint">
        <?=t('mail_server.overview.tip', [], '<b>Tip:</b> hodnoty v inputech jsou „panelové“ (uložené). Pod tím ti ukazuju i <b>Systém</b> hodnoty načtené přímo z <code>/etc</code>. Pokud jsi něco měnil ručně v konfigu, klikni na <b>Načíst ze systému</b>.')?>
      </div>

      <div class="row" style="margin-top:12px;gap:10px;flex-wrap:wrap;">
        <form method="post" style="margin:0;display:inline">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="reload_from_system">
          <button class="btn2" onclick="return confirm(<?=json_encode(t('mail_server.confirm.reload_from_system', [], 'Načíst reálné hodnoty z /etc do panelu?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('mail_server.action.reload_from_system', [], 'Načíst ze systému'))?></button>
        </form>

        <form method="post" style="margin:0;display:inline">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="apply">
          <button class="btn2" onclick="return confirm(<?=json_encode(t('mail_server.confirm.apply', [], 'Nasadit nastavení panelu do /etc a reloadnout služby?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('mail_server.action.apply', [], 'Apply (nasadit)'))?></button>
        </form>

        <form method="post" style="margin:0;display:inline">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="test">
          <button class="btn2"><?=h(t('common.test', [], 'Test'))?></button>
        </form>

        <form method="post" style="margin:0;display:inline">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="download_zip">
          <button class="btn2"><?=h(t('mail_server.action.download_snippets_zip', [], 'Stáhnout "snippety" (ZIP)'))?></button>
        </form>
      </div>

      <hr style="margin:16px 0; opacity:.2">

      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="tab" value="tab-overview">

        <div class="grid2">
          <div>
            <label><?=h(t('mail_server.field.postfix_myhostname', [], 'Postfix myhostname'))?></label>
            <?php if (!empty($sys['myhostname'])): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['myhostname'])?></b></div><?php endif; ?>
            <input class="inp" name="myhostname" value="<?=h($cfg['myhostname'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.tls_cert_path', [], 'TLS cert path'))?></label>
            <?php if (!empty($sys['tls_cert'])): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['tls_cert'])?></b></div><?php endif; ?>
            <input class="inp" name="tls_cert" value="<?=h($cfg['tls_cert'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.tls_key_path', [], 'TLS key path'))?></label>
            <?php if (!empty($sys['tls_key'])): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['tls_key'])?></b></div><?php endif; ?>
            <input class="inp" name="tls_key" value="<?=h($cfg['tls_key'])?>">
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 0 0">
          <label class="pill"><input type="checkbox" name="aliases_enabled" value="1" <?=$cfg['aliases_enabled']?'checked':''?>> <?=h(t('mail_server.field.enable_aliases', [], 'Zapnout aliasy (virtual_alias_maps)'))?></label>
          <label class="pill"><input type="checkbox" name="mask_secrets_zip" value="1" <?=$cfg['mask_secrets_zip']?'checked':''?>> <?=h(t('mail_server.field.mask_secrets', [], 'Maskovat hesla v exportech'))?></label>
        </div>

        <div class="row" style="margin-top:12px; gap:10px; flex-wrap:wrap;">
          <button class="btn2"><?=h(t('common.save', [], 'Uložit'))?></button>
        </div>
      </form>
    </div>

    <div id="tab-rspamd" class="oris-tabpanel" role="tabpanel">
      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="tab" value="tab-rspamd">

        <h3 style="margin:0 0 8px 0;"><?=h(t('mail_server.tab.rspamd', [], 'Rspamd'))?></h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">
          <label class="pill"><input type="checkbox" name="rspamd_enabled" value="1" <?=$cfg['rspamd_enabled']?'checked':''?>> <?=h(t('mail_server.field.rspamd_enabled', [], 'Rspamd enabled'))?></label>
        </div>

        <div class="grid2">
          <div>
            <label><?=h(t('mail_server.field.milter', [], 'Milter (host:port)'))?></label>
            <?php if (!empty($sys['milter'])): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['milter'])?></b></div><?php endif; ?>
            <input class="inp" name="rspamd_milter" value="<?=h($cfg['rspamd_milter'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.reject', [], 'reject'))?></label>
            <?php if ($sys['reject']!==null): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['reject'])?></b></div><?php endif; ?>
            <input class="inp" name="rspamd_reject" value="<?=h((string)$cfg['rspamd_reject'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.add_header', [], 'add_header'))?></label>
            <?php if ($sys['add_header']!==null): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['add_header'])?></b></div><?php endif; ?>
            <input class="inp" name="rspamd_addhdr" value="<?=h((string)$cfg['rspamd_addhdr'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.greylist', [], 'greylist'))?></label>
            <?php if ($sys['greylist']!==null): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['greylist'])?></b></div><?php endif; ?>
            <input class="inp" name="rspamd_greylist" value="<?=h((string)$cfg['rspamd_greylist'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.rewrite_subject', [], 'rewrite_subject'))?></label>
            <?php if ($sys['rewrite_subject']!==null): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['rewrite_subject'])?></b></div><?php endif; ?>
            <input class="inp" name="rspamd_rewrite" value="<?=h((string)$cfg['rspamd_rewrite'])?>">
          </div>
        </div>

        <div class="grid2" style="margin-top:10px;">
          <div>
            <label><?=h(t('mail_server.field.bayes_spam_weight', [], 'BAYES_SPAM weight'))?></label>
            <?php if ($sys['bayes_spam_weight']!==null): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['bayes_spam_weight'])?></b></div><?php endif; ?>
            <input class="inp" name="bayes_spam_score" value="<?=h((string)$cfg['bayes_spam_score'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.bayes_ham_weight', [], 'BAYES_HAM weight'))?></label>
            <?php if ($sys['bayes_ham_weight']!==null): ?><div class="muted" style="margin-top:4px;"><?=h(t('common.system', [], 'Systém'))?>: <b><?=h((string)$sys['bayes_ham_weight'])?></b></div><?php endif; ?>
            <input class="inp" name="bayes_ham_score" value="<?=h((string)$cfg['bayes_ham_score'])?>">
          </div>
        </div>

        <div class="row" style="margin-top:12px; gap:10px; flex-wrap:wrap;">
          <button class="btn2"><?=h(t('common.save', [], 'Uložit'))?></button>
          <span class="muted"><?=t('mail_server.rspamd.bayes_note', [], 'Pozn.: Bayes učení skripty jsou v <code>/etc/dovecot/sieve-pipe/</code> (zálohuje se to v "FULL" i v Bayes backupu).')?></span>
        </div>
      </form>

      <hr style="margin:16px 0; opacity:.2">

      <h3 style="margin:0 0 8px 0;"><?=h(t('mail_server.bayes.heading', [], 'Učení spamu (Rspamd Bayes)'))?></h3>
      <div class="row" style="gap:10px;flex-wrap:wrap;">
        <form method="post" style="display:inline;margin:0">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="bayes_backup">
          <button class="btn2"><?=h(t('mail_server.action.create_bayes_backup', [], 'Vytvořit zálohu učení (job)'))?></button>
        </form>

        <form method="post" enctype="multipart/form-data" style="display:inline;margin:0">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="bayes_restore">
          <input class="inp" type="file" name="bayes" accept=".tar.gz,.tgz,.gz,.redis" required>
          <button class="btn2" onclick="return confirm(<?=json_encode(t('mail_server.confirm.restore_bayes', [], 'Obnovit Bayes učení přes provisioner?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('mail_server.action.restore_bayes', [], 'Obnovit Bayes přes provisioner'))?></button>
        </form>
      </div>
      <?php if (!empty($bayesBackups)): ?>
        <table style="margin-top:10px"><tr><th><?=h(t('common.backup', [], 'Záloha'))?></th><th><?=h(t('common.size', [], 'Velikost'))?></th><th><?=h(t('common.date', [], 'Datum'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
        <?php foreach (array_slice($bayesBackups, 0, 10) as $b): ?>
          <tr>
            <td><?=h($b['name'])?></td>
            <td><?=h(number_format((int)$b['size']/1024/1024, 2, ',', ' '))?> MB</td>
            <td><?=h(date('d.m.Y H:i:s', (int)$b['mtime']))?></td>
            <td>
              <a class="btn2" href="/mail_server.php?download_backup=<?=urlencode($b['name'])?>&kind=bayes"><?=h(t('common.download', [], 'Stáhnout'))?></a>
              <form method="post" style="display:inline;margin:0" onsubmit="return confirm(<?=json_encode(t('mail_server.confirm.delete_bayes_backup', ['file' => (string)$b['name']], 'Smazat Bayes zálohu {file}?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>)">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="delete_backup">
                <input type="hidden" name="kind" value="bayes">
                <input type="hidden" name="name" value="<?=h($b['name'])?>">
                <button class="btn-danger"><?=h(t('common.delete', [], 'Smazat'))?></button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?></table>
      <?php endif; ?>
    </div>

    <div id="tab-roundcube" class="oris-tabpanel" role="tabpanel">
      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="tab" value="tab-roundcube">

        <h3 style="margin:0 0 8px 0;"><?=h(t('mail_server.tab.roundcube', [], 'Roundcube'))?></h3>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">
          <label class="pill"><input type="checkbox" name="rc_enabled" value="1" <?=$cfg['rc_enabled']?'checked':''?>> <?=t('mail_server.field.enable_markasjunk', [], 'Zapnout plugin <code>markasjunk</code>')?></label>
          <label class="pill"><input type="checkbox" name="rc_learn_enabled" value="1" <?=$cfg['rc_learn_enabled']?'checked':''?>> <?=h(t('mail_server.field.learn_on_spam_ham', [], 'Učit Rspamd při označení spam/ham'))?></label>
        </div>
        <div class="muted" style="margin:-2px 0 10px 0;">
          <?=h(t('common.system', [], 'Systém'))?>: markasjunk <b><?=h($sys['rc_markasjunk'] ? t('common.enabled_upper', [], 'ZAPNUTO') : t('common.disabled_upper', [], 'VYPNUTO'))?></b> <?=t('mail_server.roundcube.system_note_suffix', [], '(pokud nesedí, dej <b>Načíst ze systému</b>)')?>
        </div>

        <div class="grid2">
          <div>
            <label><?=h(t('mail_server.field.junk_mailbox', [], 'Junk mailbox'))?></label>
            <input class="inp" name="rc_junk_mbox" value="<?=h($cfg['rc_junk_mbox'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.rspamc_host', [], 'Rspamc host:port (controller)'))?></label>
            <input class="inp" name="rc_rspamc_host" value="<?=h($cfg['rc_rspamc_host'])?>">
          </div>
          <div>
            <label><?=h(t('mail_server.field.rspamc_password_file', [], 'Rspamc password file (volitelné)'))?></label>
            <input class="inp" name="rc_rspamc_pass" value="<?=h($cfg['rc_rspamc_pass'])?>" placeholder="/etc/rspamd/local.d/worker-controller.inc">
          </div>
        </div>

        <div class="row" style="margin-top:12px; gap:10px; flex-wrap:wrap;">
          <button class="btn2"><?=h(t('common.save', [], 'Uložit'))?></button>
        </div>
      </form>

      <hr style="margin:16px 0; opacity:.2">

      <div class="row" style="gap:10px;flex-wrap:wrap;">
        <form method="post" style="display:inline;margin:0">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="apply_roundcube">
          <button class="btn2" onclick="return confirm(<?=json_encode(t('mail_server.confirm.apply_roundcube', [], 'Nasadit Roundcube config?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('mail_server.action.apply_roundcube', [], 'Apply Roundcube'))?></button>
        </form>
        <form method="post" style="display:inline;margin:0">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="test_roundcube">
          <button class="btn2"><?=h(t('mail_server.action.test_roundcube', [], 'Test Roundcube'))?></button>
        </form>
      </div>

      <div class="oris-smallhint">
        <?=t('mail_server.roundcube.learn_help', [], 'Učení v Roundcube (markasjunk) je navázané na <code>rspamc learn_spam/learn_ham</code>. Pokud používáš Sieve učení přes <code>/etc/dovecot/sieve-pipe</code>, tohle je kompatibilní – jen je dobré mít obě cesty konzistentní.')?>
      </div>
    </div>

    <div id="tab-f2b" class="oris-tabpanel" role="tabpanel">
      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="tab" value="tab-f2b">

        <h3 style="margin:0 0 8px 0;"><?=h(t('mail_server.tab.fail2ban', [], 'Fail2Ban'))?></h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">
          <label class="pill"><input type="checkbox" name="fail2ban_enabled" value="1" <?=$cfg['fail2ban_enabled']?'checked':''?>> <?=h(t('mail_server.field.fail2ban_enabled', [], 'Fail2Ban enabled'))?></label>
        </div>

        <div class="grid2">
          <div><label><?=h(t('mail_server.field.findtime', [], 'findtime'))?></label><input class="inp" name="f2b_findtime" value="<?=h($cfg['f2b_findtime'])?>"></div>
          <div><label><?=h(t('mail_server.field.bantime', [], 'bantime'))?></label><input class="inp" name="f2b_bantime" value="<?=h($cfg['f2b_bantime'])?>"></div>
          <div><label><?=h(t('mail_server.field.maxretry', [], 'maxretry'))?></label><input class="inp" name="f2b_maxretry" value="<?=h($cfg['f2b_maxretry'])?>"></div>
        </div>

        <div class="row" style="margin-top:12px; gap:10px; flex-wrap:wrap;">
          <button class="btn2"><?=h(t('common.save', [], 'Uložit'))?></button>
        </div>
      </form>
    </div>

    <div id="tab-backup" class="oris-tabpanel" role="tabpanel">
      <h3 style="margin:0 0 8px 0;"><?=h(t('mail_server.full_backup.heading', [], 'Kompletní záloha & obnova (centrálně)'))?></h3>
      <p class="muted" style="margin-top:6px;"><?=t('mail_server.full_backup.help', [], 'Zálohuje celé adresáře konfigurací: <code>/etc/postfix</code>, <code>/etc/dovecot</code>, <code>/etc/rspamd</code>, <code>/etc/roundcube</code>, <code>/etc/fail2ban</code>, <code>/etc/dovecot/sieve-pipe</code> a databázi <code>oris_mail</code>. Akce běží přes Python provisioner.')?></p>

      <div class="row" style="gap:10px;flex-wrap:wrap;">
        <form method="post" style="display:inline;margin:0">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="full_backup">
          <button class="btn2"><?=h(t('mail_server.action.create_full_backup', [], 'Vytvořit FULL zálohu (job)'))?></button>
        </form>

        <form method="post" enctype="multipart/form-data" style="display:inline;margin:0">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="full_restore">
          <input class="inp" type="file" name="full" accept=".tar.gz,.tgz" required>
          <button class="btn2" onclick="return confirm(<?=json_encode(t('mail_server.confirm.restore_full', [], 'Obnovit CELÝ mail server config ze zálohy? Přepíše /etc/...'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('mail_server.action.restore_full', [], 'Obnovit FULL přes provisioner'))?></button>
        </form>
      </div>

      <h4 style="margin:14px 0 8px 0;"><?=h(t('mail_server.full_backup.ready_heading', [], 'Hotové FULL zálohy'))?></h4>
      <?php if (!$mailBackups): ?>
        <div class="muted"><?=h(t('mail_server.backup.none_created', [], 'Zatím žádná vytvořená záloha.'))?></div>
      <?php else: ?>
        <table><tr><th><?=h(t('common.file', [], 'Soubor'))?></th><th><?=h(t('common.size', [], 'Velikost'))?></th><th><?=h(t('common.date', [], 'Datum'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
        <?php foreach (array_slice($mailBackups, 0, 20) as $b): ?>
          <tr>
            <td><?=h($b['name'])?></td>
            <td><?=h(number_format((int)$b['size']/1024/1024, 2, ',', ' '))?> MB</td>
            <td><?=h(date('d.m.Y H:i:s', (int)$b['mtime']))?></td>
            <td>
              <a class="btn2" href="/mail_server.php?download_backup=<?=urlencode($b['name'])?>&kind=full"><?=h(t('common.download', [], 'Stáhnout'))?></a>
              <form method="post" style="display:inline;margin:0" onsubmit="return confirm(<?=json_encode(t('mail_server.confirm.delete_full_backup', ['file' => (string)$b['name']], 'Smazat FULL zálohu {file}?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>)">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="delete_backup">
                <input type="hidden" name="kind" value="full">
                <input type="hidden" name="name" value="<?=h($b['name'])?>">
                <button class="btn-danger"><?=h(t('common.delete', [], 'Smazat'))?></button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?></table>
      <?php endif; ?>

      <hr style="margin:16px 0; opacity:.2">

      <h3 style="margin:0 0 8px 0;"><?=h(t('mail_server.restore_zip.heading', [], 'Obnova ze ZIPu (legacy import)'))?></h3>
      <form method="post" enctype="multipart/form-data" class="row" style="gap:10px;flex-wrap:wrap;">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="restore_zip">
        <input class="inp" type="file" name="zip" accept=".zip" required>
        <button class="btn2" onclick="return confirm(<?=json_encode(t('mail_server.confirm.restore_zip', [], 'Obnovit z ZIPu přes provisioner?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('mail_server.action.restore_zip', [], 'Obnovit ZIP přes provisioner'))?></button>
      </form>
    </div>

    <div id="tab-dkim" class="oris-tabpanel" role="tabpanel">
      <h3 style="margin:0 0 8px 0;"><?=h(t('mail_server.dkim.heading', [], 'DKIM (DNS TXT)'))?></h3>
      <div class="muted" style="margin:6px 0 10px 0;"><?=t('mail_server.dkim.help', [], 'Zobrazuje záznamy z tabulky <code>domain_dkim</code>.')?></div>

      <?php if (!$domains): ?>
        <div class="pill"><?=h(t('mail.domains.none_db', [], 'Žádné domény v DB.'))?></div>
      <?php else: ?>
        <div class="grid2">
          <?php foreach ($domains as $d): ?>
            <div class="card" style="margin:0;">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">
                <h3 style="margin:0; font-size:16px;"><?=h($d['domain'])?></h3>
                <span class="pill <?=((int)$d['is_active']===1?'ok':'err')?>"><?=h((int)$d['is_active']===1 ? t('status.active', [], 'active') : t('status.inactive', [], 'inactive'))?></span>
              </div>
              <?php if (!empty($d['dns_txt'])): ?>
                <pre style="white-space:pre-wrap; margin-top:10px;"><code><?=h((string)$d['dns_txt'])?></code></pre>
              <?php else: ?>
                <div class="muted" style="margin-top:8px;"><?=h(t('mail.dkim.txt_not_generated', [], 'DKIM TXT není vygenerovaný.'))?></div>
              <?php endif; ?>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </div>

  </div>

  <script>
  (function(){
    function activate(id){
      document.querySelectorAll('.oris-tabpanel').forEach(p=>p.classList.remove('is-active'));
      var el = document.getElementById(id);
      if (el) el.classList.add('is-active');
      document.querySelectorAll('.oris-tabbtn').forEach(b=>{
        var on = b.getAttribute('data-tab')===id;
        b.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      try{ localStorage.setItem('oris_mail_tab', id); }catch(e){}
    }
    document.querySelectorAll('.oris-tabbtn').forEach(btn=>{
      btn.addEventListener('click', ()=>activate(btn.getAttribute('data-tab')));
    });
    try{
      var last = localStorage.getItem('oris_mail_tab');
      if (last && document.getElementById(last)) activate(last);
    }catch(e){}
  })();
  </script>
<?php });

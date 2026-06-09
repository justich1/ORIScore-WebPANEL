<?php
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require_login();
$u = me($pdo);

function backup_allowed_bases(PDO $pdo): array {
  $bases = [];
  $sitesDir = trim((string)setting($pdo, 'sites_base_dir', '/var/lib/oris-core/sites'));
  if ($sitesDir !== '') $bases[] = rtrim($sitesDir, '/') . '/';

  $raw = trim((string)setting($pdo, 'web_root_bases', ''));
  if ($raw !== '') {
    foreach (preg_split('~\R+~', $raw) as $line) {
      $line = trim((string)$line);
      if ($line === '') continue;
      $bases[] = rtrim($line, '/') . '/';
    }
  } else {
    $bases[] = '/var/www/html/';
    $bases[] = '/data/www/';
  }
  return array_values(array_unique($bases));
}

function backup_path_ok(string $path, array $bases): bool {
  $path = trim($path);
  if ($path === '' || str_contains($path, "\0") || str_contains($path, '..')) return false;
  $path = rtrim($path, '/') . '/';
  foreach ($bases as $base) {
    $base = rtrim((string)$base, '/') . '/';
    if (str_starts_with($path, $base)) return true;
  }
  return false;
}

function backup_dir_for(string $root, string $type): string {
  return rtrim($root, '/') . '/backup/' . $type;
}

function safe_file_name(string $name): string {
  $name = basename($name);
  if ($name === '' || $name === '.' || $name === '..') {
    throw new RuntimeException(t('backup.err.invalid_file', [], 'Neplatný soubor.'));
  }
  if (!preg_match('~^[A-Za-z0-9_.@+ -]+$~', $name)) {
    throw new RuntimeException(t('backup.err.invalid_file_chars', [], 'Název souboru obsahuje nepovolené znaky.'));
  }
  return $name;
}

function enqueue_job(PDO $pdo, string $type, int $refId, array $payload = []): int {
  $st = $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES(?,?, 'queued', ?)");
  $st->execute([$type, $refId, json_encode($payload, JSON_UNESCAPED_UNICODE)]);
  return (int)$pdo->lastInsertId();
}

function ensure_upload_staging(PDO $pdo): string {
  $base = rtrim((string)setting($pdo, 'upload_staging_dir', '/var/lib/oris-core/uploads'), '/');
  if ($base === '') $base = sys_get_temp_dir();
  $dir = $base . '/site-backup';
  if (!is_dir($dir) && !@mkdir($dir, 0770, true) && !is_dir($dir)) {
    $dir = sys_get_temp_dir() . '/oris-site-backup-upload';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
      throw new RuntimeException(t('backup.err.upload_staging_create', [], 'Nelze vytvořit upload staging adresář.'));
    }
  }
  return $dir;
}

function store_upload_for_job(PDO $pdo, string $field, array $allowedSuffixes): array {
  if (empty($_FILES[$field]['tmp_name']) || !is_uploaded_file($_FILES[$field]['tmp_name'])) {
    throw new RuntimeException(t('backup.err.missing_file', [], 'Chybí uploadovaný soubor.'));
  }
  $originalRaw = basename(str_replace('\\', '/', (string)($_FILES[$field]['name'] ?? 'upload.bin')));
  if ($originalRaw === '' || $originalRaw === '.' || $originalRaw === '..') $originalRaw = 'upload.bin';
  $lower = strtolower($originalRaw);
  $ok = false;
  foreach ($allowedSuffixes as $suffix) {
    if (str_ends_with($lower, strtolower($suffix))) { $ok = true; break; }
  }
  if (!$ok) {
    throw new RuntimeException(t('backup.err.unsupported_file_type', ['file' => $originalRaw], 'Nepodporovaný typ souboru: {file}'));
  }
  $original = preg_replace('~[^A-Za-z0-9_.@+ -]+~', '_', $originalRaw) ?: 'upload.bin';
  $dir = ensure_upload_staging($pdo);
  $stored = $dir . '/' . date('Ymd-His') . '-' . bin2hex(random_bytes(6)) . '-' . $original;
  if (!move_uploaded_file($_FILES[$field]['tmp_name'], $stored)) {
    throw new RuntimeException(t('backup.err.upload_save', [], 'Uploadovaný soubor se nepodařilo uložit.'));
  }
  @chmod($stored, 0660);
  return ['upload_path' => $stored, 'original_name' => $original];
}

function redirect_site(int $id): never {
  header('Location:/site.php?id=' . $id);
  exit;
}

$id = (int)($_REQUEST['id'] ?? 0);
if (!$id) {
  flash_set('err', t('backup.flash.missing_site_id', [], 'Chybí ID webu. Otevři zálohy z detailu webu.'));
  header('Location:/sites.php');
  exit;
}

$st = $pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
$st->execute([$id, (int)$u['id']]);
$site = $st->fetch();
if (!$site) {
  flash_set('err', t('common.not_found', [], 'Nenalezeno.'));
  header('Location:/sites.php');
  exit;
}

$root = rtrim((string)$site['root_path'], '/');
$allowedBases = backup_allowed_bases($pdo);
if (!backup_path_ok($root, $allowedBases)) {
  flash_set('err', t('backup.flash.root_not_allowed', ['bases' => implode(', ', $allowedBases)], 'Root path není v povolených base cestách: {bases}'));
  redirect_site($id);
}

$dataDir = backup_dir_for($root, 'data');
$dbDir   = backup_dir_for($root, 'db');

try {
  if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['action'] ?? '') === 'download') {
    $type = (string)($_GET['type'] ?? '');
    $file = safe_file_name((string)($_GET['file'] ?? ''));
    if (!in_array($type, ['data','db'], true)) throw new RuntimeException(t('backup.err.bad_request', [], 'Neplatný požadavek.'));
    $base = $type === 'data' ? $dataDir : $dbDir;
    $path = rtrim($base, '/') . '/' . $file;

    $realBase = realpath($base);
    $realPath = realpath($path);
    if (!$realBase || !$realPath || !str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR)) {
      throw new RuntimeException(t('backup.err.bad_path', [], 'Neplatná cesta.'));
    }
    if (!is_file($realPath)) throw new RuntimeException(t('backup.err.file_not_exists', [], 'Soubor neexistuje.'));

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . str_replace('"', '', $file) . '"');
    header('Content-Length: ' . filesize($realPath));
    readfile($realPath);
    exit;
  }

  if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    flash_set('err', t('backup.flash.invalid_method', [], 'Neplatná metoda.'));
    redirect_site($id);
  }

  csrf_check();

  if (isset($_POST['create_data'])) {
    $jobId = enqueue_job($pdo, 'site_backup_data', $id, ['source' => 'web']);
    flash_set('ok', t('backup.flash.data_backup_queued', ['job' => $jobId], 'Vytvoření zálohy dat zařazeno do fronty jako job #{job}.'));
    header('Location:/jobs.php'); exit;
  }

  if (isset($_POST['create_db'])) {
    $jobId = enqueue_job($pdo, 'site_backup_db', $id, ['source' => 'web']);
    flash_set('ok', t('backup.flash.db_backup_queued', ['job' => $jobId], 'Vytvoření zálohy DB zařazeno do fronty jako job #{job}.'));
    header('Location:/jobs.php'); exit;
  }

  if (isset($_POST['restore_existing_data'])) {
    $file = safe_file_name((string)($_POST['file'] ?? ''));
    $jobId = enqueue_job($pdo, 'site_restore_data_existing', $id, ['file' => $file]);
    flash_set('ok', t('backup.flash.data_restore_existing_queued', ['job' => $jobId], 'Obnova dat zařazena do fronty jako job #{job}.'));
    header('Location:/jobs.php'); exit;
  }

  if (isset($_POST['restore_existing_db'])) {
    $file = safe_file_name((string)($_POST['file'] ?? ''));
    $jobId = enqueue_job($pdo, 'site_restore_db_existing', $id, ['file' => $file]);
    flash_set('ok', t('backup.flash.db_restore_existing_queued', ['job' => $jobId], 'Obnova DB zařazena do fronty jako job #{job}.'));
    header('Location:/jobs.php'); exit;
  }

  if (isset($_POST['restore_data'])) {
    $payload = store_upload_for_job($pdo, 'data_file', ['.zip', '.tar.gz', '.tgz']);
    $jobId = enqueue_job($pdo, 'site_restore_data_upload', $id, $payload);
    flash_set('ok', t('backup.flash.data_restore_upload_queued', ['job' => $jobId], 'Upload a obnova dat zařazena do fronty jako job #{job}.'));
    header('Location:/jobs.php'); exit;
  }

  if (isset($_POST['restore_db'])) {
    $payload = store_upload_for_job($pdo, 'db_file', ['.sql', '.sql.gz']);
    $jobId = enqueue_job($pdo, 'site_restore_db_upload', $id, $payload);
    flash_set('ok', t('backup.flash.db_restore_upload_queued', ['job' => $jobId], 'Upload a obnova DB zařazena do fronty jako job #{job}.'));
    header('Location:/jobs.php'); exit;
  }

  if (isset($_POST['delete_backup'])) {
    $type = (string)($_POST['type'] ?? '');
    if (!in_array($type, ['data','db'], true)) throw new RuntimeException(t('backup.err.bad_request', [], 'Neplatný požadavek.'));
    $file = safe_file_name((string)($_POST['file'] ?? ''));
    $jobId = enqueue_job($pdo, 'site_backup_delete', $id, ['backup_type' => $type, 'file' => $file]);
    flash_set('ok', t('backup.flash.delete_queued', ['job' => $jobId], 'Smazání zálohy zařazeno do fronty jako job #{job}.'));
    header('Location:/jobs.php'); exit;
  }

  throw new RuntimeException(t('backup.err.unknown_action', [], 'Neznámá akce.'));

} catch (Throwable $e) {
  flash_set('err', t('common.error_with_msg', ['msg' => $e->getMessage()], 'Chyba: {msg}'));
  redirect_site($id);
}

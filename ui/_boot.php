<?php
declare(strict_types=1);

$configPath = __DIR__ . '/config.php';
if (!file_exists($configPath)) { http_response_code(500); echo "Missing config.php. Run /install.php"; exit; }
$config = require $configPath;

session_name($config['session_name'] ?? 'oris_panel');
session_start();

$host = $config['db']['host'] ?? '127.0.0.1';
$port = (int)($config['db']['port'] ?? 3306);
$dbn  = $config['db']['name'] ?? '';
$usr  = $config['db']['user'] ?? '';
$pwd  = $config['db']['pass'] ?? '';

$dsn = "mysql:host={$host};port={$port};dbname={$dbn};charset=utf8mb4";
$pdo = new PDO($dsn, $usr, $pwd, [
  PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
  PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

// Optional: second DB connection for mail server (oris_mail)
$pdoMail = null;
if (!empty($config['mail_db']['name'])) {
  $mh = $config['mail_db']['host'] ?? '127.0.0.1';
  $mp = (int)($config['mail_db']['port'] ?? 3306);
  $mn = $config['mail_db']['name'] ?? '';
  $mu = $config['mail_db']['user'] ?? '';
  $mw = $config['mail_db']['pass'] ?? '';
  if ($mn && $mu !== '') {
    $mdsn = "mysql:host={$mh};port={$mp};dbname={$mn};charset=utf8mb4";
    $pdoMail = new PDO($mdsn, $mu, $mw, [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
  }
}

function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function require_login(): void { if (empty($_SESSION['uid'])) { header("Location: /login.php"); exit; } }
function is_admin(): bool { return ($_SESSION['role'] ?? '') === 'admin'; }
function require_admin(): void { require_login(); if (!is_admin()) { http_response_code(403); echo h(t('auth.forbidden', [], 'Forbidden')); exit; } }

function csrf_token(): string { if (empty($_SESSION['_csrf'])) $_SESSION['_csrf'] = bin2hex(random_bytes(16)); return $_SESSION['_csrf']; }
function csrf_check(): void {
  return;
  $t = $_POST['_csrf'] ?? '';
  if (!$t || empty($_SESSION['_csrf']) || !hash_equals($_SESSION['_csrf'], $t)) {
    $_SESSION['_flash'] = ['type'=>'err','msg'=>t('security.csrf_invalid', [], 'Neplatný / expirovaný CSRF token. Obnov stránku a zkus akci znovu.')];
    $target = '/';
    $ref = (string)($_SERVER['HTTP_REFERER'] ?? '');
    if ($ref !== '') {
      $p = parse_url($ref);
      $hostOk = empty($p['host']) || strcasecmp((string)$p['host'], (string)($_SERVER['HTTP_HOST'] ?? '')) === 0;
      if ($hostOk) {
        $path = (string)($p['path'] ?? '/');
        $query = isset($p['query']) ? ('?' . $p['query']) : '';
        $target = $path . $query;
      }
    }
    header('Location: ' . $target, true, 303);
    exit;
  }
}

function flash_set(string $type, string $msg): void { $_SESSION['_flash'] = ['type'=>$type,'msg'=>$msg]; }
function flash_get(): ?array { $f = $_SESSION['_flash'] ?? null; unset($_SESSION['_flash']); return $f; }

function me(PDO $pdo): ?array {
  if (empty($_SESSION['uid'])) return null;
  $st=$pdo->prepare("SELECT id,email,role,is_active FROM users WHERE id=?");
  $st->execute([(int)$_SESSION['uid']]);
  return $st->fetch() ?: null;
}

function setting(PDO $pdo, string $k, ?string $def=null): ?string {
  $st=$pdo->prepare("SELECT v FROM settings WHERE k=?");
  $st->execute([$k]);
  $r=$st->fetch();
  return $r ? (string)$r['v'] : $def;
}
function set_setting(PDO $pdo, string $k, string $v): void {
  $st=$pdo->prepare("INSERT INTO settings(k,v) VALUES(?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)");
  $st->execute([$k,$v]);
}
function domain_valid(string $d): bool {
  $d=strtolower(trim($d));
  if (strlen($d)<3 || strlen($d)>253) return false;
  return (bool)preg_match('~^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$~',$d);
}


// --- i18n/l10n (translations in /language) ---
$__DEFAULT_LANG = __i18n_normalize_lang((string)($config['default_lang'] ?? 'cs')) ?: 'cs';
$__CONFIG_LANGS = [];
if (isset($config['langs']) && is_array($config['langs'])) {
  foreach ($config['langs'] as $lang) {
    $lang = __i18n_normalize_lang((string)$lang);
    if ($lang !== '') $__CONFIG_LANGS[] = $lang;
  }
}
$__AVAILABLE_LANGS = __i18n_discover_langs(__DIR__ . '/language', array_values(array_unique(array_merge([$__DEFAULT_LANG], $__CONFIG_LANGS))));
if (!in_array($__DEFAULT_LANG, $__AVAILABLE_LANGS, true)) {
  $__DEFAULT_LANG = $__AVAILABLE_LANGS[0] ?? 'cs';
}
$GLOBALS['_available_langs'] = $__AVAILABLE_LANGS;
$GLOBALS['_default_lang'] = $__DEFAULT_LANG;

function current_lang(): string { return $GLOBALS['_lang'] ?? ($GLOBALS['_default_lang'] ?? 'cs'); }
function available_langs(): array { return $GLOBALS['_available_langs'] ?? ['cs']; }

function lang_label(string $lang): string {
  $lang = __i18n_normalize_lang($lang);
  if ($lang === '') return '';
  return t('lang.' . $lang, [], strtoupper($lang));
}

function __i18n_normalize_lang(string $lang): string {
  $lang = strtolower(trim(str_replace('_', '-', $lang)));
  return preg_match('~^[a-z]{2,3}(?:-[a-z0-9]{2,8})?$~', $lang) ? $lang : '';
}

function __i18n_discover_langs(string $dir, array $preferred = []): array {
  $found = [];
  foreach (glob(rtrim($dir, '/') . '/*.php') ?: [] as $file) {
    $lang = __i18n_normalize_lang((string)pathinfo($file, PATHINFO_FILENAME));
    if ($lang !== '') $found[$lang] = $lang;
  }

  if (!$found) {
    return ['cs'];
  }

  $ordered = [];
  foreach ($preferred as $lang) {
    $lang = __i18n_normalize_lang((string)$lang);
    if ($lang !== '' && isset($found[$lang]) && !in_array($lang, $ordered, true)) {
      $ordered[] = $lang;
    }
  }
  foreach (array_keys($found) as $lang) {
    if (!in_array($lang, $ordered, true)) {
      $ordered[] = $lang;
    }
  }

  return $ordered;
}

function __i18n_pick_lang(array $available, string $default): string {
  // 1) explicit ?lang=xx
  $q = __i18n_normalize_lang((string)($_GET['lang'] ?? ''));
  if ($q !== '' && in_array($q, $available, true)) {
    $_SESSION['_lang'] = $q;
    // light cookie (1 year)
    setcookie('lang', $q, time() + 365*86400, '/');
    return $q;
  }

  // 2) session/cookie
  $s = __i18n_normalize_lang((string)($_SESSION['_lang'] ?? ''));
  if ($s !== '' && in_array($s, $available, true)) return $s;
  $c = __i18n_normalize_lang((string)($_COOKIE['lang'] ?? ''));
  if ($c !== '' && in_array($c, $available, true)) { $_SESSION['_lang'] = $c; return $c; }

  // 3) Accept-Language best effort
  $al = strtolower((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''));
  foreach (preg_split('~\s*,\s*~', $al) as $part) {
    $tag = __i18n_normalize_lang((string)trim(explode(';', $part)[0]));
    if ($tag === '') continue;
    $tag2 = substr($tag, 0, 2);
    if (in_array($tag, $available, true)) return $tag;
    if (in_array($tag2, $available, true)) return $tag2;
  }

  return in_array($default, $available, true) ? $default : ($available[0] ?? 'cs');
}

$GLOBALS['_lang'] = __i18n_pick_lang($__AVAILABLE_LANGS, $__DEFAULT_LANG);

// Load dictionaries: fallback is default language
function __i18n_load(string $lang): array {
  $lang = __i18n_normalize_lang($lang);
  if ($lang === '') return [];

  $p = __DIR__ . '/language/' . $lang . '.php';
  if (is_file($p)) {
    $d = require $p;
    return is_array($d) ? $d : [];
  }
  return [];
}
$__i18n_fallback = __i18n_load($__DEFAULT_LANG);
$__i18n_active   = __i18n_load($GLOBALS['_lang']);
$GLOBALS['_tr']  = $GLOBALS['_lang'] === $__DEFAULT_LANG
  ? $__i18n_fallback
  : array_replace($__i18n_fallback, $__i18n_active);

function t(string $key, array $vars = [], ?string $fallback = null): string {
  $tr = $GLOBALS['_tr'] ?? [];
  $s = $tr[$key] ?? ($fallback ?? $key);
  if ($vars) {
    foreach ($vars as $k => $v) {
      $s = str_replace('{' . $k . '}', (string)$v, $s);
    }
  }
  return (string)$s;
}
function te(string $key, array $vars = [], ?string $fallback = null): void {
  echo h(t($key, $vars, $fallback));
}

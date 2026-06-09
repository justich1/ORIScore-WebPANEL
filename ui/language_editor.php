<?php
/**
 * ORIS Panel - Language editor
 *
 * Umístění: ui/language_editor.php
 * Pracuje se slovníky ui/language/*.php, které vrací asociativní pole:
 *   <?php return ['key' => 'Text'];
 */
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

/** @var PDO $pdo */
/** @var array $config */

$languageDir = __DIR__ . '/language';
$defaultLang = (string)($config['default_lang'] ?? 'cs');

function le_flash_redirect(string $url = '/language_editor.php'): never {
  header('Location: ' . $url, true, 303);
  exit;
}

function le_language_dir(): string {
  return __DIR__ . '/language';
}

function le_lang_valid(string $lang): bool {
  // cs, en, sk, de, cs-CZ, pt-BR ...
  return (bool)preg_match('~^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$~', $lang);
}

function le_key_valid(string $key): bool {
  if ($key === '' || strlen($key) > 190) return false;
  // klíče typu common.save, page.site.title, status.active, mail.flash.xxx
  return (bool)preg_match('~^[A-Za-z0-9_.:-]+$~', $key);
}

function le_safe_lang(string $lang): string {
  $lang = trim($lang);
  if (!le_lang_valid($lang)) {
    throw new RuntimeException(t('language_editor.err.invalid_lang', [], 'Neplatný kód jazyka.'));
  }
  return $lang;
}

function le_dict_path(string $lang): string {
  $lang = le_safe_lang($lang);
  return le_language_dir() . '/' . $lang . '.php';
}

function le_available_langs(): array {
  $dir = le_language_dir();
  if (!is_dir($dir)) return [];

  $langs = [];
  foreach (glob($dir . '/*.php') ?: [] as $file) {
    $name = basename($file, '.php');
    if (le_lang_valid($name)) $langs[] = $name;
  }

  sort($langs, SORT_NATURAL | SORT_FLAG_CASE);
  return $langs;
}

function le_load_dict(string $lang): array {
  $path = le_dict_path($lang);
  if (!is_file($path)) return [];

  $data = require $path;
  if (!is_array($data)) {
    throw new RuntimeException(t('language_editor.err.not_array', ['file' => basename($path)], 'Soubor {file} nevrací pole.'));
  }

  $out = [];
  foreach ($data as $k => $v) {
    $key = (string)$k;
    if ($key === '') continue;
    $out[$key] = (string)$v;
  }

  ksort($out, SORT_NATURAL | SORT_FLAG_CASE);
  return $out;
}

function le_export_array(array $data): string {
  ksort($data, SORT_NATURAL | SORT_FLAG_CASE);
  return "<?php\n" .
    "declare(strict_types=1);\n\n" .
    "return " . var_export($data, true) . ";\n";
}

function le_write_dict(string $lang, array $data): void {
  $path = le_dict_path($lang);
  $dir = dirname($path);

  if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
    throw new RuntimeException(t('language_editor.err.cannot_create_dir', [], 'Nelze vytvořit složku language.'));
  }

  $clean = [];
  foreach ($data as $k => $v) {
    $key = trim((string)$k);
    if ($key === '') continue;
    if (!le_key_valid($key)) {
      throw new RuntimeException(t('language_editor.err.invalid_key_named', ['key' => $key], 'Neplatný klíč: {key}'));
    }
    $clean[$key] = (string)$v;
  }
  ksort($clean, SORT_NATURAL | SORT_FLAG_CASE);

  if (is_file($path)) {
    $backupDir = $dir . '/.backup';
    if (!is_dir($backupDir)) @mkdir($backupDir, 0775, true);
    if (is_dir($backupDir)) {
      @copy($path, $backupDir . '/' . basename($path) . '.' . date('Ymd-His') . '.bak');
    }
  }

  $tmp = $path . '.tmp.' . bin2hex(random_bytes(4));
  $bytes = file_put_contents($tmp, le_export_array($clean), LOCK_EX);
  if ($bytes === false) {
    @unlink($tmp);
    throw new RuntimeException(t('language_editor.err.write_tmp_failed', [], 'Nelze zapsat dočasný soubor.'));
  }

  @chmod($tmp, 0664);
  if (!@rename($tmp, $path)) {
    @unlink($tmp);
    throw new RuntimeException(t('language_editor.err.replace_failed', [], 'Nelze přepsat jazykový soubor.'));
  }
}

function le_src_php_files(string $dir): array {
  $out = [];
  $skipDirs = ['language', 'vendor', 'node_modules', '.git'];
  $it = new RecursiveIteratorIterator(
    new RecursiveCallbackFilterIterator(
      new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
      function (SplFileInfo $file) use ($skipDirs): bool {
        if ($file->isDir()) return !in_array($file->getFilename(), $skipDirs, true);
        return strtolower($file->getExtension()) === 'php';
      }
    )
  );

  foreach ($it as $file) {
    if ($file instanceof SplFileInfo && $file->isFile()) $out[] = $file->getPathname();
  }
  sort($out, SORT_NATURAL | SORT_FLAG_CASE);
  return $out;
}

function le_php_unquote(string $s): string {
  // Stačí pro běžné jednořádkové fallbacky v t('x', [], 'Text') / te('x', [], 'Text')
  return stripcslashes($s);
}

function le_scan_source_keys(string $root): array {
  $found = [];

  foreach (le_src_php_files($root) as $file) {
    $txt = @file_get_contents($file);
    if (!is_string($txt) || $txt === '') continue;

    // t('key', ..., 'fallback') nebo te('key', ..., 'fallback')
    // fallback je volitelný; pokud není, použije se samotný klíč.
    $rx = '~\b(t|te)\s*\(\s*([\'\"])([A-Za-z0-9_.:-]+)\2(?:(?:[^\'\"\\]|\\.|[\'\"][^\'\"]*[\'\"])*?([\'\"])((?:\\.|(?!\4).)*)\4)?~s';
    if (!preg_match_all($rx, $txt, $m, PREG_SET_ORDER)) continue;

    foreach ($m as $row) {
      $key = (string)($row[3] ?? '');
      if (!le_key_valid($key)) continue;
      $fallback = isset($row[5]) && $row[5] !== '' ? le_php_unquote((string)$row[5]) : $key;
      if (!isset($found[$key]) || $found[$key] === $key) $found[$key] = $fallback;
    }
  }

  ksort($found, SORT_NATURAL | SORT_FLAG_CASE);
  return $found;
}

function le_filter_keys(array $data, string $query): array {
  $query = trim($query);
  if ($query === '') return $data;

  $out = [];
  foreach ($data as $k => $v) {
    if (stripos((string)$k, $query) !== false || stripos((string)$v, $query) !== false) {
      $out[$k] = $v;
    }
  }
  return $out;
}

$langs = le_available_langs();
if (!$langs) {
  $langs = [$defaultLang ?: 'cs'];
}

$lang = (string)($_GET['lang'] ?? $_POST['lang'] ?? ($defaultLang ?: $langs[0]));
if (!le_lang_valid($lang) || !in_array($lang, $langs, true)) {
  $lang = in_array($defaultLang, $langs, true) ? $defaultLang : $langs[0];
}

$q = trim((string)($_GET['q'] ?? ''));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();
  $action = (string)($_POST['action'] ?? '');

  try {
    if ($action === 'create_lang') {
      $newLang = strtolower(trim((string)($_POST['new_lang'] ?? '')));
      $copyFrom = trim((string)($_POST['copy_from'] ?? ''));
      le_safe_lang($newLang);

      $newPath = le_dict_path($newLang);
      if (is_file($newPath)) {
        throw new RuntimeException(t('language_editor.err.lang_exists', ['lang' => $newLang], 'Jazyk {lang} už existuje.'));
      }

      $data = [];
      if ($copyFrom !== '') {
        le_safe_lang($copyFrom);
        $data = le_load_dict($copyFrom);
      }
      le_write_dict($newLang, $data);
      flash_set('ok', t('language_editor.flash.lang_created', ['lang' => $newLang], 'Jazyk {lang} vytvořen.'));
      le_flash_redirect('/language_editor.php?lang=' . rawurlencode($newLang));
    }

    if ($action === 'delete_lang') {
      $delLang = le_safe_lang((string)($_POST['lang'] ?? ''));
      if ($delLang === $defaultLang) {
        throw new RuntimeException(t('language_editor.err.cannot_delete_default', [], 'Výchozí jazyk nejde smazat.'));
      }
      if (empty($_POST['confirm_delete_lang'])) {
        throw new RuntimeException(t('language_editor.err.confirm_delete_lang', [], 'Potvrď smazání jazyka.'));
      }
      $path = le_dict_path($delLang);
      if (!is_file($path)) {
        throw new RuntimeException(t('language_editor.err.lang_not_found', [], 'Jazykový soubor neexistuje.'));
      }
      $trashDir = dirname($path) . '/.deleted';
      if (!is_dir($trashDir)) @mkdir($trashDir, 0775, true);
      $trash = $trashDir . '/' . basename($path) . '.' . date('Ymd-His') . '.deleted';
      if (!@rename($path, $trash)) {
        throw new RuntimeException(t('language_editor.err.delete_failed', [], 'Jazyk se nepodařilo smazat.'));
      }
      flash_set('ok', t('language_editor.flash.lang_deleted', ['lang' => $delLang], 'Jazyk {lang} smazán.'));
      le_flash_redirect('/language_editor.php');
    }

    if ($action === 'save_values') {
      $editLang = le_safe_lang((string)($_POST['lang'] ?? $lang));
      $dict = le_load_dict($editLang);
      $values = $_POST['value'] ?? [];
      if (!is_array($values)) $values = [];

      foreach ($values as $key => $value) {
        $key = (string)$key;
        if (!le_key_valid($key)) continue;
        if (array_key_exists($key, $dict)) $dict[$key] = (string)$value;
      }

      le_write_dict($editLang, $dict);
      flash_set('ok', t('language_editor.flash.saved', [], 'Překlady uloženy.'));
      le_flash_redirect('/language_editor.php?lang=' . rawurlencode($editLang) . ($q !== '' ? '&q=' . rawurlencode($q) : ''));
    }

    if ($action === 'add_key') {
      $editLang = le_safe_lang((string)($_POST['lang'] ?? $lang));
      $key = trim((string)($_POST['new_key'] ?? ''));
      $value = (string)($_POST['new_value'] ?? '');
      if (!le_key_valid($key)) throw new RuntimeException(t('language_editor.err.invalid_key', [], 'Neplatný klíč.'));

      $dict = le_load_dict($editLang);
      if (isset($dict[$key]) && empty($_POST['overwrite'])) {
        throw new RuntimeException(t('language_editor.err.key_exists', ['key' => $key], 'Klíč {key} už existuje.'));
      }
      $dict[$key] = $value;
      le_write_dict($editLang, $dict);
      flash_set('ok', t('language_editor.flash.key_added', ['key' => $key], 'Klíč {key} uložen.'));
      le_flash_redirect('/language_editor.php?lang=' . rawurlencode($editLang) . '&q=' . rawurlencode($key));
    }

    if ($action === 'rename_key') {
      $editLang = le_safe_lang((string)($_POST['lang'] ?? $lang));
      $oldKey = trim((string)($_POST['old_key'] ?? ''));
      $newKey = trim((string)($_POST['rename_to'] ?? ''));
      if (!le_key_valid($oldKey) || !le_key_valid($newKey)) throw new RuntimeException(t('language_editor.err.invalid_key', [], 'Neplatný klíč.'));

      $dict = le_load_dict($editLang);
      if (!array_key_exists($oldKey, $dict)) throw new RuntimeException(t('language_editor.err.key_not_found', [], 'Klíč neexistuje.'));
      if ($oldKey !== $newKey && array_key_exists($newKey, $dict)) throw new RuntimeException(t('language_editor.err.key_exists', ['key' => $newKey], 'Klíč {key} už existuje.'));

      $dict[$newKey] = $dict[$oldKey];
      if ($oldKey !== $newKey) unset($dict[$oldKey]);
      le_write_dict($editLang, $dict);
      flash_set('ok', t('language_editor.flash.key_renamed', [], 'Klíč přejmenován.'));
      le_flash_redirect('/language_editor.php?lang=' . rawurlencode($editLang) . '&q=' . rawurlencode($newKey));
    }

    if ($action === 'delete_key') {
      $editLang = le_safe_lang((string)($_POST['lang'] ?? $lang));
      $key = trim((string)($_POST['key'] ?? ''));
      if (!le_key_valid($key)) throw new RuntimeException(t('language_editor.err.invalid_key', [], 'Neplatný klíč.'));

      $dict = le_load_dict($editLang);
      unset($dict[$key]);
      le_write_dict($editLang, $dict);
      flash_set('ok', t('language_editor.flash.key_deleted', ['key' => $key], 'Klíč {key} smazán.'));
      le_flash_redirect('/language_editor.php?lang=' . rawurlencode($editLang));
    }

    if ($action === 'copy_missing') {
      $editLang = le_safe_lang((string)($_POST['lang'] ?? $lang));
      $sourceLang = le_safe_lang((string)($_POST['source_lang'] ?? $defaultLang));
      if ($editLang === $sourceLang) throw new RuntimeException(t('language_editor.err.same_lang', [], 'Zdrojový a cílový jazyk je stejný.'));

      $target = le_load_dict($editLang);
      $source = le_load_dict($sourceLang);
      $added = 0;
      foreach ($source as $key => $value) {
        if (!array_key_exists($key, $target)) {
          $target[$key] = (string)$value;
          $added++;
        }
      }
      le_write_dict($editLang, $target);
      flash_set('ok', t('language_editor.flash.missing_copied', ['count' => $added], 'Doplněno chybějících klíčů: {count}.'));
      le_flash_redirect('/language_editor.php?lang=' . rawurlencode($editLang));
    }

    if ($action === 'scan_sources') {
      $editLang = le_safe_lang((string)($_POST['lang'] ?? $lang));
      $dict = le_load_dict($editLang);
      $found = le_scan_source_keys(__DIR__);
      $added = 0;
      foreach ($found as $key => $fallback) {
        if (!array_key_exists($key, $dict)) {
          $dict[$key] = (string)$fallback;
          $added++;
        }
      }
      le_write_dict($editLang, $dict);
      flash_set('ok', t('language_editor.flash.scan_added', ['count' => $added], 'Sken hotový. Nových klíčů: {count}.'));
      le_flash_redirect('/language_editor.php?lang=' . rawurlencode($editLang));
    }

    throw new RuntimeException(t('language_editor.err.unknown_action', [], 'Neznámá akce.'));
  } catch (Throwable $e) {
    flash_set('err', $e->getMessage());
    le_flash_redirect('/language_editor.php?lang=' . rawurlencode($lang));
  }
}

$langs = le_available_langs();
if (!$langs) $langs = [$defaultLang ?: 'cs'];
if (!in_array($lang, $langs, true)) $lang = $langs[0];

$dict = le_load_dict($lang);
$baseDict = in_array($defaultLang, $langs, true) ? le_load_dict($defaultLang) : [];
$displayDict = le_filter_keys($dict, $q);
$missingFromBase = [];
if ($baseDict && $lang !== $defaultLang) {
  foreach ($baseDict as $key => $value) {
    if (!array_key_exists($key, $dict)) $missingFromBase[$key] = $value;
  }
}

render($pdo, t('page.language_editor.title', [], 'Editor překladů'), function() use ($lang, $langs, $defaultLang, $dict, $displayDict, $missingFromBase, $q) { ?>
  <style>
    .le-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;align-items:start}
    .le-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
    .le-table textarea{min-height:44px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
    .le-key{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;white-space:nowrap}
    .le-muted{opacity:.75}
    @media(max-width:900px){.le-grid{grid-template-columns:1fr}.le-key{white-space:normal}}
  </style>

  <div class="card">
    <h2><?=h(t('page.language_editor.title', [], 'Editor překladů'))?></h2>
    <small><?=h(t('language_editor.help', [], 'Editor pracuje přímo se soubory language/*.php. Při každém uložení vytvoří zálohu ve složce language/.backup.'))?></small>
  </div>

  <div class="le-grid">
    <div class="card">
      <h3><?=h(t('language_editor.choose_lang', [], 'Vybrat jazyk'))?></h3>
      <form method="get" class="le-actions">
        <div>
          <label><?=h(t('language_editor.field.lang', [], 'Jazyk'))?></label>
          <select name="lang" onchange="this.form.submit()">
            <?php foreach ($langs as $l): ?>
              <option value="<?=h($l)?>" <?=$l === $lang ? 'selected' : ''?>><?=h($l)?><?=$l === $defaultLang ? ' — ' . h(t('language_editor.default_lang', [], 'výchozí')) : ''?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div>
          <label><?=h(t('language_editor.field.search', [], 'Hledat'))?></label>
          <input name="q" value="<?=h($q)?>" placeholder="<?=h(t('language_editor.placeholder.search', [], 'klíč nebo text'))?>">
        </div>
        <button class="btn2" type="submit"><?=h(t('common.search', [], 'Hledat'))?></button>
        <a class="btn2" href="/language_editor.php?lang=<?=h(rawurlencode($lang))?>" style="text-decoration:none;display:inline-block"><?=h(t('common.reset', [], 'Reset'))?></a>
      </form>
      <p><small><?=h(t('language_editor.stats', ['shown' => count($displayDict), 'total' => count($dict)], 'Zobrazeno {shown} z {total} klíčů.'))?></small></p>
    </div>

    <div class="card">
      <h3><?=h(t('language_editor.create_lang', [], 'Vytvořit jazyk'))?></h3>
      <form method="post" class="le-actions">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="create_lang">
        <div>
          <label><?=h(t('language_editor.field.new_lang', [], 'Kód jazyka'))?></label>
          <input name="new_lang" placeholder="en, de, sk, cs-CZ">
        </div>
        <div>
          <label><?=h(t('language_editor.field.copy_from', [], 'Kopírovat z'))?></label>
          <select name="copy_from">
            <option value=""><?=h(t('language_editor.empty_lang', [], 'prázdný slovník'))?></option>
            <?php foreach ($langs as $l): ?>
              <option value="<?=h($l)?>" <?=$l === $defaultLang ? 'selected' : ''?>><?=h($l)?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <button class="btn" type="submit"><?=h(t('common.create', [], 'Vytvořit'))?></button>
      </form>
    </div>
  </div>

  <div class="le-grid">
    <div class="card">
      <h3><?=h(t('language_editor.add_key', [], 'Přidat klíč'))?></h3>
      <form method="post">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="add_key">
        <input type="hidden" name="lang" value="<?=h($lang)?>">
        <div class="row">
          <div>
            <label><?=h(t('language_editor.field.key', [], 'Klíč'))?></label>
            <input name="new_key" placeholder="page.example.title">
          </div>
          <div>
            <label><?=h(t('language_editor.field.value', [], 'Text'))?></label>
            <input name="new_value" placeholder="Český text">
          </div>
        </div>
        <label style="display:block;margin-top:8px"><input type="checkbox" name="overwrite" value="1"> <?=h(t('language_editor.overwrite_key', [], 'Přepsat, pokud klíč existuje'))?></label>
        <button class="btn" type="submit" style="margin-top:10px"><?=h(t('language_editor.save_key', [], 'Uložit klíč'))?></button>
      </form>
    </div>

    <div class="card">
      <h3><?=h(t('language_editor.tools', [], 'Nástroje'))?></h3>
      <div class="le-actions">
        <form method="post" style="margin:0">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="action" value="scan_sources">
          <input type="hidden" name="lang" value="<?=h($lang)?>">
          <button class="btn2" type="submit"><?=h(t('language_editor.scan_sources', [], 'Doplnit klíče nalezené ve zdrojácích'))?></button>
        </form>

        <?php if ($lang !== $defaultLang && in_array($defaultLang, $langs, true)): ?>
          <form method="post" style="margin:0">
            <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
            <input type="hidden" name="action" value="copy_missing">
            <input type="hidden" name="lang" value="<?=h($lang)?>">
            <input type="hidden" name="source_lang" value="<?=h($defaultLang)?>">
            <button class="btn2" type="submit"><?=h(t('language_editor.copy_missing', ['lang' => $defaultLang], 'Doplnit chybějící z {lang}'))?></button>
          </form>
        <?php endif; ?>
      </div>

      <?php if ($lang !== $defaultLang): ?>
        <p><small><?=h(t('language_editor.missing_count', ['count' => count($missingFromBase), 'lang' => $defaultLang], 'Chybí proti {lang}: {count} klíčů.'))?></small></p>
      <?php endif; ?>

      <?php if ($lang !== $defaultLang): ?>
        <details style="margin-top:10px">
          <summary><span class="pill err"><?=h(t('language_editor.delete_lang', [], 'Smazat jazyk'))?></span></summary>
          <form method="post" style="margin-top:10px" onsubmit="return confirm(<?=h(json_encode(t('language_editor.confirm.delete_lang', ['lang' => $lang], 'Opravdu smazat jazyk {lang}?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES))?>);">
            <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
            <input type="hidden" name="action" value="delete_lang">
            <input type="hidden" name="lang" value="<?=h($lang)?>">
            <label><input type="checkbox" name="confirm_delete_lang" value="1"> <?=h(t('language_editor.confirm_delete_lang_checkbox', [], 'Ano, chci smazat tento jazykový soubor.'))?></label><br>
            <button class="btn-danger" type="submit" style="margin-top:8px"><?=h(t('common.delete', [], 'Smazat'))?></button>
          </form>
        </details>
      <?php endif; ?>
    </div>
  </div>

  <form method="post" class="card">
    <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
    <input type="hidden" name="action" value="save_values">
    <input type="hidden" name="lang" value="<?=h($lang)?>">

    <div class="row space" style="align-items:center">
      <div>
        <h3><?=h(t('language_editor.translations_for', ['lang' => $lang], 'Překlady: {lang}'))?></h3>
        <small><?=h(t('language_editor.save_all_help', [], 'Uprav hodnoty a ulož. Mazání a přejmenování klíče je po řádcích přes samostatné tlačítko.'))?></small>
      </div>
      <button class="btn" type="submit"><?=h(t('common.save', [], 'Uložit'))?></button>
    </div>

    <div class="table-scroll" style="margin-top:12px">
      <table class="le-table">
        <thead>
          <tr>
            <th style="width:28%"># / <?=h(t('language_editor.col.key', [], 'Klíč'))?></th>
            <th><?=h(t('language_editor.col.value', [], 'Text'))?></th>
            <th style="width:230px"><?=h(t('common.actions', [], 'Akce'))?></th>
          </tr>
        </thead>
        <tbody>
          <?php if (!$displayDict): ?>
            <tr><td colspan="3"><small><?=h(t('language_editor.no_keys', [], 'Žádné klíče k zobrazení.'))?></small></td></tr>
          <?php endif; ?>

          <?php $i = 0; foreach ($displayDict as $key => $value): $i++; ?>
            <tr>
              <td>
                <small class="le-muted"><?= (int)$i ?></small><br>
                <span class="le-key"><?=h($key)?></span>
              </td>
              <td>
                <textarea name="value[<?=h($key)?>]" rows="2"><?=h($value)?></textarea>
              </td>
              <td>
                <div style="display:grid;gap:6px">
                  <form method="post" style="display:flex;gap:6px;margin:0">
                    <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                    <input type="hidden" name="action" value="rename_key">
                    <input type="hidden" name="lang" value="<?=h($lang)?>">
                    <input type="hidden" name="old_key" value="<?=h($key)?>">
                    <input name="rename_to" value="<?=h($key)?>" title="<?=h(t('language_editor.rename_to', [], 'Nový název klíče'))?>">
                    <button class="btn2" type="submit"><?=h(t('language_editor.rename', [], 'Přejmenovat'))?></button>
                  </form>

                  <form method="post" style="margin:0" onsubmit="return confirm(<?=h(json_encode(t('language_editor.confirm.delete_key', ['key' => $key], 'Smazat klíč {key}?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES))?>);">
                    <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                    <input type="hidden" name="action" value="delete_key">
                    <input type="hidden" name="lang" value="<?=h($lang)?>">
                    <input type="hidden" name="key" value="<?=h($key)?>">
                    <button class="btn-danger" type="submit"><?=h(t('common.delete', [], 'Smazat'))?></button>
                  </form>
                </div>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <p style="margin-top:12px"><button class="btn" type="submit"><?=h(t('common.save', [], 'Uložit'))?></button></p>
  </form>
<?php });

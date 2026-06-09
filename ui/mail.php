<?php
require __DIR__.'/_boot.php';
require __DIR__.'/_view.php';
require_admin();

// fallback helper (některé stránky ho mají jinde)
if (!function_exists('human_bytes')) {
  function human_bytes(int $bytes): string {
    $units = ['B','KB','MB','GB','TB','PB'];
    $b = max(0, $bytes);
    $i = 0;
    while ($b >= 1024 && $i < count($units)-1) { $b /= 1024; $i++; }
    $prec = ($i === 0) ? 0 : 1;
    return number_format($b, $prec, '.', ' ') . ' ' . $units[$i];
  }
}


/** @var PDO $pdo */
/** @var ?PDO $pdoMail */
if (!$pdoMail) {
  render($pdo, t('page.mail.title', [], 'E-mail'), function(){ ?>
    <div class="card">
      <h2><?=h(t('page.mail.title', [], 'E-mail'))?></h2>
      <p class="pill err"><?=h(t('mail.err.db_missing', [], 'Mail DB není nakonfigurovaná. Doplň <code>mail_db</code> do <code>config.php</code>.'))?></p>
    </div>
  <?php });
  exit;
}

function lp_valid(string $lp): bool {
  // jednoduchá validace localpart (bez uvozovek a exotiky)
  return (bool)preg_match('~^[a-z0-9][a-z0-9._+-]{0,188}[a-z0-9]$~i', $lp);
}


function list_mail_backups(string $dir): array {
  if (!is_dir($dir)) return [];
  $out = [];
  foreach (scandir($dir) ?: [] as $f) {
    if ($f === '.' || $f === '..') continue;
    $p = rtrim($dir,'/').'/'.$f;
    if (!is_file($p)) continue;
    $out[] = [
      'name' => $f,
      'size' => filesize($p) ?: 0,
      'mtime'=> filemtime($p) ?: 0,
    ];
  }
  usort($out, fn($a,$b)=>($b['mtime']<=>$a['mtime']));
  return $out;
}

function mail_backup_paths(PDO $pdo, string $domain): array {
  $base = rtrim(setting($pdo,'mail_backup_dir','/var/lib/oris-core/mail-backups'),'/');
  $domDir = $base.'/'.$domain.'/backup';
  return [
    'base' => $base,
    'dom'  => $domDir,
    'data' => $domDir.'/data',
    'db'   => $domDir.'/db',
  ];
}


// --- actions ---
if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();
  $action = (string)($_POST['action'] ?? '');

  try {
    if ($action === 'domain_add') {
      $domain = strtolower(trim((string)($_POST['domain'] ?? '')));
      if (!domain_valid($domain)) throw new RuntimeException(t('mail.err.invalid_domain', [], 'Neplatná doména'));

      $st = $pdoMail->prepare("INSERT INTO domains(domain,is_active) VALUES(?,1)");
      $st->execute([$domain]);
      $id = (int)$pdoMail->lastInsertId();

      // Queue vhost creation for mail.+webmail.
      $pdo->prepare("INSERT INTO jobs(type,ref_id,payload,status) VALUES('mail_domain_apply',?,JSON_OBJECT('action','apply'),'queued')")
          ->execute([$id]);

      flash_set('ok', t('mail.flash.domna_pidna_a_zaazena_do_provisioningu', [], 'Doména přidána a zařazena do provisioningu'));
      header('Location: /mail.php');
      exit;
    }

    if ($action === 'domain_toggle') {
      $id = (int)($_POST['id'] ?? 0);
      $pdoMail->prepare("UPDATE domains SET is_active = IF(is_active=1,0,1) WHERE id=?")->execute([$id]);
      flash_set('ok', t('mail.flash.domna_upravena', [], 'Doména upravena'));
      header('Location: /mail.php');
      exit;
    }

    if ($action === 'domain_delete') {
      $id = (int)($_POST['id'] ?? 0);
      $st = $pdoMail->prepare("SELECT domain FROM domains WHERE id=?");
      $st->execute([$id]);
      $row = $st->fetch();
      $domain = $row ? (string)$row['domain'] : '';
      $payload = json_encode(['action'=>'remove','domain'=>$domain], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
      $pdo->prepare("INSERT INTO jobs(type,ref_id,payload,status) VALUES('mail_domain_remove',?,?, 'queued')")
          ->execute([$id, $payload]);
      $pdoMail->prepare("DELETE FROM domains WHERE id=?")->execute([$id]);
      flash_set('ok', t('mail.flash.domna_smazna_vhosty_budou_odstranny_jobe', [], 'Doména smazána (vhosty budou odstraněny jobem)'));
      header('Location: /mail.php');
      exit;
    }


if ($action === 'domain_dkim_regen') {
  $id = (int)($_POST['id'] ?? 0);
  if ($id<=0) throw new RuntimeException(t('mail.err.invalid_domain_id', [], 'Neplatné ID domény'));

  $pdo->prepare("INSERT INTO jobs(type,ref_id,payload,status) VALUES('mail_domain_dkim_regen',?,JSON_OBJECT('action','dkim_regen'),'queued')")
      ->execute([$id]);

  flash_set('ok', t('mail.flash.dkim_regenerace_zaazena_do_job_provision', [], 'DKIM regenerace zařazena do jobů (provisioner)'));
  header('Location: /mail.php?d='.$id.'#dns');
  exit;
}

if ($action === 'domain_rebuild') {
  $id = (int)($_POST['id'] ?? 0);
  if ($id<=0) throw new RuntimeException(t('mail.err.invalid_domain_id', [], 'Neplatné ID domény'));
  $pdo->prepare("INSERT INTO jobs(type,ref_id,payload,status) VALUES('mail_domain_apply',?,JSON_OBJECT('action','apply'),'queued')")
      ->execute([$id]);
  flash_set('ok', t('mail.flash.domain_rebuild_queued', [], 'Regenerace mail domény zařazena do jobů.'));
  header('Location: /mail.php?d='.$id); exit;
}

if ($action === 'domain_certbot_issue') {
  $id = (int)($_POST['id'] ?? 0);
  if ($id<=0) throw new RuntimeException(t('mail.err.invalid_domain_id', [], 'Neplatné ID domény'));
  $pdo->prepare("INSERT INTO jobs(type,ref_id,payload,status) VALUES('mail_domain_certbot_issue',?,JSON_OBJECT('action','certbot'),'queued')")
      ->execute([$id]);
  flash_set('ok', t('mail.flash.domain_certbot_queued', [], 'Vystavení certifikátu pro mail/webmail/roundcube zařazeno do jobů.'));
  header('Location: /mail.php?d='.$id.'#dns'); exit;
}

    if ($action === 'mailbox_add') {
      $domainId = (int)($_POST['domain_id'] ?? 0);
      $local = trim((string)($_POST['local_part'] ?? ''));
      $pw = (string)($_POST['password'] ?? '');
      $quota = (int)($_POST['quota_mb'] ?? 1024);
      if ($domainId<=0) throw new RuntimeException(t('mail.err.select_domain', [], 'Vyber doménu'));
      if (!lp_valid($local)) throw new RuntimeException(t('mail.err.invalid_localpart', [], 'Neplatný local-part'));
      if (strlen($pw) < 8) throw new RuntimeException(t('mail.err.password_min8', [], 'Heslo musí mít alespoň 8 znaků'));
      if ($quota < 0) $quota = 0;

      $d = $pdoMail->prepare("SELECT domain FROM domains WHERE id=?");
      $d->execute([$domainId]);
      $dom = $d->fetch();
      if (!$dom) throw new RuntimeException(t('mail.err.domain_not_found', [], 'Doména nenalezena'));
      $domain = (string)$dom['domain'];

      $email = strtolower($local.'@'.$domain);

      // vmail_root je v oris_panel settings
      $vroot = setting($pdo,'vmail_root','/var/vmail') ?? '/var/vmail';
      $vroot = rtrim($vroot,'/');
      $maildir = $vroot.'/'.$domain.'/'.$local.'/';

      // pass_hash musí být NOT NULL -> dáme placeholder a schránku necháme inactive do doběhnutí jobu
      $pdoMail->prepare("INSERT INTO mailboxes(domain_id,email,local_part,pass_hash,maildir,quota_mb,is_active) VALUES(?,?,?,?,?,?,0)")
              ->execute([$domainId,$email,$local,'*PENDING*',$maildir,$quota]);
      $mid = (int)$pdoMail->lastInsertId();

      $payload = json_encode(['password'=>$pw], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
      $pdo->prepare("INSERT INTO jobs(type,ref_id,payload,status) VALUES('mailbox_apply',?,?, 'queued')")
          ->execute([$mid, $payload]);

      flash_set('ok', t('mail.flash.schrnka_pidna_hash_maildir_vytvo_provisi', [], 'Schránka přidána (hash + maildir vytvoří provisioner)'));
      header('Location: /mail.php?d='.$domainId);
      exit;
    }

    if ($action === 'mailbox_toggle') {
      $id = (int)($_POST['id'] ?? 0);
      $domainId = (int)($_POST['domain_id'] ?? 0);
      $pdoMail->prepare("UPDATE mailboxes SET is_active = IF(is_active=1,0,1) WHERE id=?")->execute([$id]);
      flash_set('ok', t('mail.flash.schrnka_upravena', [], 'Schránka upravena'));
      header('Location: /mail.php?d='.$domainId);
      exit;
    }

    if ($action === 'mailbox_pass') {
      $id = (int)($_POST['id'] ?? 0);
      $domainId = (int)($_POST['domain_id'] ?? 0);
      $pw = (string)($_POST['password'] ?? '');
      if (strlen($pw) < 8) throw new RuntimeException(t('mail.err.password_min8', [], 'Heslo musí mít alespoň 8 znaků'));
      $payload = json_encode(['password'=>$pw], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
      $pdo->prepare("INSERT INTO jobs(type,ref_id,payload,status) VALUES('mailbox_set_password',?,?, 'queued')")
          ->execute([$id, $payload]);
      flash_set('ok', t('mail.flash.zmna_hesla_zaazena_do_job', [], 'Změna hesla zařazena do jobů'));
      header('Location: /mail.php?d='.$domainId);
      exit;
    }

    if ($action === 'mailbox_delete') {
      $id = (int)($_POST['id'] ?? 0);
      $domainId = (int)($_POST['domain_id'] ?? 0);
      $pdoMail->prepare("DELETE FROM mailboxes WHERE id=?")->execute([$id]);
      flash_set('ok', t('mail.flash.schrnka_smazna', [], 'Schránka smazána'));
      header('Location: /mail.php?d='.$domainId);
      exit;
    }

    if ($action === 'alias_add') {
      $domainId = (int)($_POST['domain_id'] ?? 0);
      $src = strtolower(trim((string)($_POST['source'] ?? '')));
      $dst = trim((string)($_POST['destination'] ?? ''));
      if ($domainId<=0) throw new RuntimeException(t('mail.err.select_domain', [], 'Vyber doménu'));
      if ($src==='' || $dst==='') throw new RuntimeException(t('mail.err.alias_source_dest_required', [], 'Source i destination jsou povinné'));

      // pokud uživatel zadal jen localpart, doplníme @domain
      if (strpos($src,'@') === false) {
        $d = $pdoMail->prepare("SELECT domain FROM domains WHERE id=?");
        $d->execute([$domainId]);
        $dom = $d->fetch();
        if (!$dom) throw new RuntimeException(t('mail.err.domain_not_found', [], 'Doména nenalezena'));
        $src = $src.'@'.$dom['domain'];
      }

      $pdoMail->prepare("INSERT INTO aliases(domain_id,source,destination,is_active) VALUES(?,?,?,1)")
              ->execute([$domainId,$src,$dst]);

      flash_set('ok', t('mail.flash.alias_pidn', [], 'Alias přidán'));
      header('Location: /mail.php?d='.$domainId.'#aliases');
      exit;
    }

    if ($action === 'alias_toggle') {
      $id = (int)($_POST['id'] ?? 0);
      $domainId = (int)($_POST['domain_id'] ?? 0);
      $pdoMail->prepare("UPDATE aliases SET is_active = IF(is_active=1,0,1) WHERE id=?")->execute([$id]);
      flash_set('ok', t('mail.flash.alias_upraven', [], 'Alias upraven'));
      header('Location: /mail.php?d='.$domainId.'#aliases');
      exit;
    }

    if ($action === 'alias_delete') {
      $id = (int)($_POST['id'] ?? 0);
      $domainId = (int)($_POST['domain_id'] ?? 0);
      $pdoMail->prepare("DELETE FROM aliases WHERE id=?")->execute([$id]);
      flash_set('ok', t('mail.flash.alias_smazn', [], 'Alias smazán'));
      header('Location: /mail.php?d='.$domainId.'#aliases');
      exit;
    }

    throw new RuntimeException(t('common.unknown_action', [], 'Neznámá akce'));
  } catch (Throwable $e) {
    flash_set('err', $e->getMessage());
    header('Location: /mail.php');
    exit;
  }
}

// --- data ---
$domains = $pdoMail->query("SELECT * FROM domains ORDER BY domain ASC")->fetchAll();
$domainId = (int)($_GET['d'] ?? 0);
if ($domainId<=0 && $domains) $domainId = (int)$domains[0]['id'];

$mailboxes = [];
$aliases = [];
$domainRow = null;
if ($domainId>0) {
  $st = $pdoMail->prepare("SELECT * FROM domains WHERE id=?");
  $st->execute([$domainId]);
  $domainRow = $st->fetch() ?: null;

  $st = $pdoMail->prepare("SELECT * FROM mailboxes WHERE domain_id=? ORDER BY local_part ASC");
  $st->execute([$domainId]);
  $mailboxes = $st->fetchAll();

  $st = $pdoMail->prepare("SELECT * FROM aliases WHERE domain_id=? ORDER BY source ASC");
  $st->execute([$domainId]);
  $aliases = $st->fetchAll();
// DKIM DNS (generated by provisioner via rspamadm)
$dkimRow = null;
try {
  $st = $pdoMail->prepare("SELECT selector, public_key, dns_txt FROM domain_dkim WHERE domain_id=? LIMIT 1");
  $st->execute([$domainId]);
  $dkimRow = $st->fetch() ?: null;
} catch (Throwable $e) {
  $dkimRow = null; // table may not exist yet
}


}


$backupPaths = null;
$backData = [];
$backDb = [];
if ($domainRow) {
  $backupPaths = mail_backup_paths($pdo, (string)$domainRow['domain']);
  $backData = list_mail_backups($backupPaths['data']);
  $backDb   = list_mail_backups($backupPaths['db']);
}


render($pdo, t('page.mail.title', [], 'E-mail'), function() use($domains,$domainId,$domainRow,$mailboxes,$aliases,$dkimRow,$backupPaths,$backData,$backDb){ ?>
  <div class="card">
    <h2><?=h(t('page.mail.title', [], 'E-mail'))?></h2>
    <small><?=t('mail.help', [], 'Správa domén, schránek a aliasů v DB <code>oris_mail</code>. Vhosty pro <code>mail.DOMÉNA</code> a <code>webmail.DOMÉNA</code> vytváří job <code>mail_domain_apply</code>.')?></small>
  </div>

  <div class="card">
    <h3><?=h(t('mail.domains.heading', [], 'Domény'))?></h3>
    <form method="post" style="display:flex;gap:10px;align-items:end;flex-wrap:wrap">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="action" value="domain_add">
      <div>
        <label><?=h(t('mail.domain.new', [], 'Nová doména'))?></label>
        <input name="domain" placeholder="example.com">
      </div>
      <div>
        <button class="btn"><?=h(t('common.add', [], 'Přidat'))?></button>
      </div>
    </form>

    <?php if(!$domains): ?>
      <p style="margin-top:10px"><small><?=h(t('mail.domains.empty', [], 'Zatím žádné domény.'))?></small></p>
    <?php else: ?>
<div class="table-scroll">
      <table style="margin-top:12px">
        <tr><th><?=h(t('common.domain', [], 'Doména'))?></th><th><?=h(t('common.status', [], 'Stav'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
        <?php foreach($domains as $d): ?>
          <tr>
            <td><a href="/mail.php?d=<?= (int)$d['id'] ?>"><?=h($d['domain'])?></a></td>
            <td><?= (int)$d['is_active']===1 ? '<span class="pill ok">'.h(t('status.active', [], 'active')).'</span>' : '<span class="pill">'.h(t('status.disabled', [], 'disabled')).'</span>' ?></td>
            <td style="white-space:nowrap">
              <form method="post" style="display:inline">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="domain_toggle">
                <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
                <button class="btn" type="submit"><?=h(t('common.on_off', [], 'On/Off'))?></button>
              </form>
              <form method="post" style="display:inline">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="domain_rebuild">
                <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
                <button class="btn" type="submit"><?=h(t('mail.action.vhosts', [], 'Vhosty'))?></button>
              </form>
              <form method="post" style="display:inline">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="domain_certbot_issue">
                <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
                <button class="btn" type="submit"><?=h(t('mail.action.https_mail', [], 'HTTPS mail'))?></button>
              </form>
              <form method="post" style="display:inline" onsubmit="return confirm(<?=json_encode(t('mail.confirm.delete_domain', [], 'Smazat doménu a všechny schránky/aliasy?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="domain_delete">
                <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
                <button class="btn" type="submit"><?=h(t('common.delete', [], 'Smazat'))?></button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
    <?php endif; ?>
  </div>

<?php if($domainRow): ?>
  <div class="card" id="dns">
    <h3><?=h(t('mail.dkim.heading', [], 'DNS – DKIM'))?></h3>
    <small><?=t('mail.dkim.help', [], 'Generování DKIM klíče dělá provisioner (job <code>mail_domain_dkim_regen</code>). Níž máš TXT záznam připravený ke vložení do DNS.')?></small>


<?php
$dkimTxt = null;

if ($dkimRow && !empty($dkimRow['selector']) && !empty($dkimRow['public_key'])) {

    $selector = $dkimRow['selector'];
    $domain   = $domainRow['domain'];

    // odstraníme mezery a nové řádky z public key
    $publicKey = preg_replace('~\s+~', '', $dkimRow['public_key']);

    $value = 'v=DKIM1; k=rsa; p=' . $publicKey;

    // DNS TXT by měl být rozdělen po cca 200 znacích
    $chunks = str_split($value, 200);
    $quoted = array_map(fn($c) => '"' . $c . '"', $chunks);

    $dkimTxt = $selector . '._domainkey.' . $domain . ' IN TXT (' . implode(' ', $quoted) . ')';
}
?>

<?php if($dkimTxt): ?>
  <div style="margin-top:12px">
    <label><?=h(t('mail.dkim.txt_label', [], 'TXT (DKIM)'))?></label>
    <textarea readonly style="width:100%;min-height:120px"><?=h($dkimTxt)?></textarea>
  </div>

  <form method="post" style="margin-top:10px">
    <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
    <input type="hidden" name="action" value="domain_dkim_regen">
    <input type="hidden" name="id" value="<?= (int)$domainRow['id'] ?>">
    <button class="btn" type="submit"><?=h(t('mail.dkim.regenerate', [], 'Regenerovat DKIM'))?></button>
  </form>

<?php else: ?>
      <p style="margin-top:12px"><span class="pill"><?=h(t('mail.dkim.not_generated', [], 'DKIM zatím není vygenerovaný'))?></span></p>
      <form method="post" style="margin-top:10px">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="domain_dkim_regen">
        <input type="hidden" name="id" value="<?= (int)$domainRow['id'] ?>">
        <button class="btn" type="submit"><?=h(t('mail.dkim.generate', [], 'Vygenerovat DKIM'))?></button>
      </form>
    <?php endif; ?>
  </div>

    <div class="card">
      <h3><?=h(t('mail.mailboxes.heading_domain', ['domain' => (string)$domainRow['domain']], 'Schránky – {domain}'))?></h3>
      <form method="post" style="display:flex;gap:10px;align-items:end;flex-wrap:wrap">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="mailbox_add">
        <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
        <div>
          <label><?=h(t('mail.mailbox.local_part', [], 'local-part'))?></label>
          <input name="local_part" placeholder="info">
        </div>
        <div>
          <label><?=h(t('common.password', [], 'Heslo'))?></label>
          <input name="password" type="password" placeholder="<?=h(t('mail.placeholder.password_min8', [], 'min. 8 znaků'))?>">
        </div>
        <div>
          <label><?=h(t('mail.mailbox.quota_mb', [], 'Quota (MB)'))?></label>
          <input name="quota_mb" type="number" value="1024" min="0">
        </div>
        <div><button class="btn"><?=h(t('common.create', [], 'Vytvořit'))?></button></div>
      </form>
<div class="table-scroll">
      <table style="margin-top:12px">
        <tr>
          <th><?=h(t('common.email', [], 'E-mail'))?></th>
          <th><?=h(t('mail.mailbox.quota', [], 'Quota'))?></th>
          <th><?=h(t('mail.mailbox.maildir', [], 'Maildir'))?></th>
          <th><?=h(t('common.status', [], 'Stav'))?></th>
          <th><?=h(t('common.actions', [], 'Akce'))?></th>
        </tr>
        <?php foreach($mailboxes as $m): ?>
          <tr>
            <td><?=h($m['email'])?></td>
            <td><?=h($m['quota_mb'])?> MB</td>
            <td><code><?=h($m['maildir'])?></code></td>
            <td><?= (int)$m['is_active']===1 ? '<span class="pill ok">'.h(t('status.active', [], 'active')).'</span>' : '<span class="pill">'.h(t('status.pending_disabled', [], 'pending/disabled')).'</span>' ?></td>
            <td style="white-space:nowrap">
              <form method="post" style="display:inline">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="mailbox_toggle">
                <input type="hidden" name="id" value="<?= (int)$m['id'] ?>">
                <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                <button class="btn"><?=h(t('common.on_off', [], 'On/Off'))?></button>
              </form>

              <form method="post" style="display:inline">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="mailbox_pass">
                <input type="hidden" name="id" value="<?= (int)$m['id'] ?>">
                <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                <input name="password" type="password" placeholder="<?=h(t('mail.placeholder.new_password', [], 'nové heslo'))?>" style="width:160px">
                <button class="btn"><?=h(t('common.change', [], 'Změnit'))?></button>
              </form>

              <form method="post" style="display:inline" onsubmit="return confirm(<?=json_encode(t('mail.confirm.delete_mailbox', [], 'Smazat schránku? (maildir na disku zůstane)'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="mailbox_delete">
                <input type="hidden" name="id" value="<?= (int)$m['id'] ?>">
                <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                <button class="btn"><?=h(t('common.delete', [], 'Smazat'))?></button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
</div>
    <div class="card" id="aliases">
      <h3><?=h(t('mail.aliases.heading_domain', ['domain' => (string)$domainRow['domain']], 'Aliasy – {domain}'))?></h3>
      <form method="post" style="display:flex;gap:10px;align-items:end;flex-wrap:wrap">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="alias_add">
        <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
        <div>
          <label><?=h(t('mail.alias.source', [], 'Source'))?></label>
          <input name="source" placeholder="sales (nebo sales@<?=h($domainRow['domain'])?>)">
        </div>
        <div style="flex:1;min-width:320px">
          <label><?=h(t('mail.alias.destination', [], 'Destination'))?></label>
          <input name="destination" placeholder="info@<?=h($domainRow['domain'])?>, external@example.net">
        </div>
        <div><button class="btn"><?=h(t('common.add', [], 'Přidat'))?></button></div>
      </form>
<div class="table-scroll">
      <table style="margin-top:12px">
        <tr><th><?=h(t('mail.alias.source', [], 'Source'))?></th><th><?=h(t('mail.alias.destination', [], 'Destination'))?></th><th><?=h(t('common.status', [], 'Stav'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
        <?php foreach($aliases as $a): ?>
          <tr>
            <td><?=h($a['source'])?></td>
            <td><code><?=h($a['destination'])?></code></td>
            <td><?= (int)$a['is_active']===1 ? '<span class="pill ok">'.h(t('status.active', [], 'active')).'</span>' : '<span class="pill">'.h(t('status.disabled', [], 'disabled')).'</span>' ?></td>
            <td style="white-space:nowrap">
              <form method="post" style="display:inline">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="alias_toggle">
                <input type="hidden" name="id" value="<?= (int)$a['id'] ?>">
                <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                <button class="btn"><?=h(t('common.on_off', [], 'On/Off'))?></button>
              </form>
              <form method="post" style="display:inline" onsubmit="return confirm(<?=json_encode(t('mail.confirm.delete_alias', [], 'Smazat alias?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="action" value="alias_delete">
                <input type="hidden" name="id" value="<?= (int)$a['id'] ?>">
                <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                <button class="btn"><?=h(t('common.delete', [], 'Smazat'))?></button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  <div class="card" id="backups">
    <h3><?=h(t('mail.backups.heading_domain', ['domain' => (string)$domainRow['domain']], 'Zálohy e-mailů – {domain}'))?></h3>
    <small><?=t('mail.backups.help', ['path' => h((string)($backupPaths['dom'] ?? ''))], 'Zálohy se ukládají do <code>{path}</code> (data + db zvlášť).')?></small>

    <div class="row" style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
      <form method="post" action="/mail-backup.php" style="margin:0;">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
        <button class="btn2" name="create_mail_data" value="1"
          onclick="return confirm(<?=json_encode(t('mail.confirm.create_maildir_backup', [], 'Vytvořit zálohu MAILDIR (data pošty)?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
          <?=h(t('mail.backup.create_maildir', [], 'Vytvořit zálohu maildir (data)'))?>
        </button>
      </form>

      <form method="post" action="/mail-backup.php" style="margin:0;">
        <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
        <button class="btn2" name="create_mail_db" value="1"
          onclick="return confirm(<?=json_encode(t('mail.confirm.create_db_backup', [], 'Vytvořit zálohu konfigurace (DB)?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
          <?=h(t('mail.backup.create_db', [], 'Vytvořit zálohu DB (konfigurace)'))?>
        </button>
      </form>
    </div>

    <hr style="border:0;border-top:1px solid #22314f; margin:16px 0;">

    <div class="row" style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
      <div>
        <h4><?=h(t('mail.backup.data_maildir', [], 'Data (maildir)'))?></h4>

        <?php if (!$backData): ?>
          <small><?=h(t('mail.backups.none', [], 'Žádné zálohy.'))?></small>
        <?php else: ?>
          <div class="table-scroll">
            <table style="margin-top:12px">
              <tr><th><?=h(t('common.file', [], 'Soubor'))?></th><th><?=h(t('common.size', [], 'Velikost'))?></th><th><?=h(t('common.date', [], 'Datum'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
              <?php foreach($backData as $b): ?>
                <tr>
                  <td><code><?=h($b['name'])?></code></td>
                  <td><?=h(human_bytes((int)$b['size']))?></td>
                  <td><?=h(date('Y-m-d H:i:s',(int)$b['mtime']))?></td>
                  <td style="display:flex; gap:8px; flex-wrap:wrap;">
                    <a class="btn2" href="/mail-backup.php?action=download&type=data&domain_id=<?= (int)$domainRow['id'] ?>&file=<?=h($b['name'])?>" style="text-decoration:none;display:inline-block"><?=h(t('common.download', [], 'Stáhnout'))?></a>

                    <form method="post" action="/mail-backup.php" style="margin:0;">
                      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                      <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                      <input type="hidden" name="file" value="<?=h($b['name'])?>">
                      <button class="btn" name="restore_existing_mail_data" value="1"
                        onclick="return confirm(<?=json_encode(t('mail.confirm.restore_maildir_existing', ['file' => (string)$b['name']], 'Obnovit MAILDIR z {file}? Přepíše data pošty pro doménu.'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
                        <?=h(t('common.restore', [], 'Obnovit'))?>
                      </button>
                    </form>

                    <form method="post" action="/mail-backup.php" style="margin:0;">
                      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                      <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                      <input type="hidden" name="type" value="data">
                      <input type="hidden" name="file" value="<?=h($b['name'])?>">
                      <button class="btn" name="delete_backup" value="1"
                        onclick="return confirm(<?=json_encode(t('mail.confirm.delete_backup', [], 'Smazat zálohu?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
                        <?=h(t('common.delete', [], 'Smazat'))?>
                      </button>
                    </form>
                  </td>
                </tr>
              <?php endforeach; ?>
            </table>
          </div>
        <?php endif; ?>

        <div style="margin-top:12px;">
          <h4><?=h(t('mail.backup.restore_maildir_upload_heading', [], 'Obnovit maildir (nahráním ZIP)'))?></h4>
          <form method="post" action="/mail-backup.php" enctype="multipart/form-data">
            <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
            <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
            <input type="file" name="mail_data_file" required>
            <button class="btn" name="restore_mail_data" value="1"
              onclick="return confirm(<?=json_encode(t('mail.confirm.restore_maildir_upload', [], 'Obnovit maildir z nahraného ZIP? Přepíše data pošty pro doménu.'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
              <?=h(t('common.upload_and_restore', [], 'Nahrát a obnovit'))?>
            </button>
          </form>
        </div>
      </div>

      <div>
        <h4><?=h(t('mail.backup.db_config', [], 'DB (konfigurace)'))?></h4>

        <?php if (!$backDb): ?>
          <small><?=h(t('mail.backups.none', [], 'Žádné zálohy.'))?></small>
        <?php else: ?>
          <div class="table-scroll">
            <table style="margin-top:12px">
              <tr><th><?=h(t('common.file', [], 'Soubor'))?></th><th><?=h(t('common.size', [], 'Velikost'))?></th><th><?=h(t('common.date', [], 'Datum'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
              <?php foreach($backDb as $b): ?>
                <tr>
                  <td><code><?=h($b['name'])?></code></td>
                  <td><?=h(human_bytes((int)$b['size']))?></td>
                  <td><?=h(date('Y-m-d H:i:s',(int)$b['mtime']))?></td>
                  <td style="display:flex; gap:8px; flex-wrap:wrap;">
                    <a class="btn2" href="/mail-backup.php?action=download&type=db&domain_id=<?= (int)$domainRow['id'] ?>&file=<?=h($b['name'])?>" style="text-decoration:none;display:inline-block"><?=h(t('common.download', [], 'Stáhnout'))?></a>

                    <form method="post" action="/mail-backup.php" style="margin:0;">
                      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                      <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                      <input type="hidden" name="file" value="<?=h($b['name'])?>">
                      <button class="btn" name="restore_existing_mail_db" value="1"
                        onclick="return confirm(<?=json_encode(t('mail.confirm.restore_db_existing', ['file' => (string)$b['name']], 'Obnovit konfiguraci DB z {file}? Přepíše schránky/aliasy/DKIM pro doménu.'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
                        <?=h(t('common.restore', [], 'Obnovit'))?>
                      </button>
                    </form>

                    <form method="post" action="/mail-backup.php" style="margin:0;">
                      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                      <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
                      <input type="hidden" name="type" value="db">
                      <input type="hidden" name="file" value="<?=h($b['name'])?>">
                      <button class="btn" name="delete_backup" value="1"
                        onclick="return confirm(<?=json_encode(t('mail.confirm.delete_backup', [], 'Smazat zálohu?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
                        <?=h(t('common.delete', [], 'Smazat'))?>
                      </button>
                    </form>
                  </td>
                </tr>
              <?php endforeach; ?>
            </table>
          </div>
        <?php endif; ?>

        <div style="margin-top:12px;">
          <h4><?=h(t('mail.backup.restore_db_upload_heading', [], 'Obnovit DB (nahráním JSON.GZ)'))?></h4>
          <form method="post" action="/mail-backup.php" enctype="multipart/form-data">
            <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
            <input type="hidden" name="domain_id" value="<?= (int)$domainRow['id'] ?>">
            <input type="file" name="mail_db_file" required>
            <button class="btn" name="restore_mail_db" value="1"
              onclick="return confirm(<?=json_encode(t('mail.confirm.restore_db_upload', [], 'Obnovit konfiguraci DB z nahraného souboru? Přepíše schránky/aliasy/DKIM pro doménu.'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);">
              <?=h(t('common.upload_and_restore', [], 'Nahrát a obnovit'))?>
            </button>
          </form>
        </div>
      </div>
    </div>
  </div>
<?php endif; ?>
</div>
<?php });


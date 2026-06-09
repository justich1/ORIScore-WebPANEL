<?php require __DIR__.'/_boot.php'; require __DIR__.'/_view.php'; require_login();
$u=me($pdo);


$sitesDir = rtrim(setting($pdo,'sites_base_dir','/var/lib/oris-core/sites'), '/').'/';
$webRootBasesRaw = trim((string)setting($pdo,'web_root_bases',''));
$allowedBases = [$sitesDir];
if($webRootBasesRaw!==''){
  foreach(preg_split("~\R+~", $webRootBasesRaw) as $line){
    $b=trim($line);
    if($b==='') continue;
    $allowedBases[] = rtrim($b,'/').'/';
  }
}
$allowedBases = array_values(array_unique($allowedBases));

function path_ok_multi(string $path, array $bases): bool {
  $path = trim($path);
  if ($path === '') return false;
  if (str_contains($path, "\0")) return false;
  if (str_contains($path, '..')) return false;
  foreach ($bases as $base) {
    $base = rtrim($base, '/').'/';
    if (str_starts_with($path, $base)) return true;
  }
  return false;
}


if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();

  if (isset($_POST['create'])) {
    $domain=strtolower(trim($_POST['domain']??''));
    if (!domain_valid($domain)) { flash_set('err', t('sites.flash.invalid_domain', [], 'Neplatná doména')); header("Location:/sites.php"); exit; }

    
    $base = (string)($_POST['root_base'] ?? $sitesDir);
    $suffix = trim((string)($_POST['root_suffix'] ?? ''));
    if($suffix==='') $suffix = "$domain/public";
    $root = rtrim($base,'/').'/'.ltrim($suffix,'/');

    if(!path_ok_multi($root, $allowedBases)){
      flash_set('err', t('sites.flash.root_must_be_under_allowed', [], 'Root webu musí být pod povolenými cestami.'));
      header("Location:/sites.php"); exit;
    }

    $force = isset($_POST['force_https']) ? 1 : 0;
    $hsts  = isset($_POST['hsts']) ? 1 : 0;

    try{
      $pdo->beginTransaction();
      $pdo->prepare("INSERT INTO sites(user_id,domain,root_path,force_https,hsts,status) VALUES(?,?,?,?,?, 'provisioning')")
          ->execute([(int)$u['id'],$domain,$root,$force,$hsts]);
      $sid=(int)$pdo->lastInsertId();
      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_site',?, 'queued', JSON_OBJECT('action','web'))")
          ->execute([$sid]);
      $pdo->commit();
      flash_set('ok', t('sites.flash.queued_provision', [], 'Web zařazen do provisioningu.'));
    } catch(Throwable $e){
      $pdo->rollBack();
      flash_set('err', t('common.error_with_msg', ['msg'=>$e->getMessage()]));
    }
    header("Location:/sites.php"); exit;
  }

  if (isset($_POST['delete'])) {
    $id=(int)($_POST['id']??0);
    $st=$pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
    $st->execute([$id,(int)$u['id']]);
    $site=$st->fetch();
    if(!$site){ flash_set('err', t('common.not_found', [], 'Nenalezeno')); header("Location:/sites.php"); exit; }

    $pdo->beginTransaction();
    $pdo->prepare("UPDATE sites SET status='provisioning' WHERE id=?")->execute([$id]);
    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('deprovision_site',?, 'queued', JSON_OBJECT('action','delete'))")->execute([$id]);
    $pdo->commit();

    flash_set('ok', t('sites.flash.queued_delete', [], 'Smazání webu zařazeno do fronty.'));
    header("Location:/sites.php"); exit;
  }

  if (isset($_POST['reset_db_pass'])) {
    $id=(int)($_POST['id']??0);
    $st=$pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
    $st->execute([$id,(int)$u['id']]);
    if(!$st->fetch()){ flash_set('err', t('common.not_found', [], 'Nenalezeno')); header("Location:/sites.php"); exit; }

    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('site_reset_db_pass',?, 'queued', JSON_OBJECT('action','reset_db_pass'))")->execute([$id]);
    flash_set('ok', t('sites.flash.queued_reset_db_pass', [], 'Reset DB hesla zařazen do fronty.'));
    header("Location:/sites.php"); exit;
  }

  if (isset($_POST['rebuild'])) {
    $id=(int)($_POST['id']??0);
    $st=$pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
    $st->execute([$id,(int)$u['id']]);
    if(!$st->fetch()){ flash_set('err', t('common.not_found', [], 'Nenalezeno')); header("Location:/sites.php"); exit; }

    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_site',?, 'queued', JSON_OBJECT('action','rebuild'))")->execute([$id]);
    flash_set('ok', t('sites.flash.queued_rebuild', [], 'Rebuild webu zařazen do fronty.'));
    header("Location:/sites.php"); exit;
  }
}

$st=$pdo->prepare("SELECT * FROM sites WHERE user_id=? ORDER BY id DESC LIMIT 200");
$st->execute([(int)$u['id']]); $sites=$st->fetchAll();

render($pdo, t('page.sites.title', [], 'Weby'), function() use($sites,$allowedBases){ ?>
  <div class="card">
    <h2><?php te('page.sites.heading', [], 'Weby'); ?></h2>
    <small><?php te('sites.help', [], 'Správa webů a vhostů přes provisioner.'); ?></small>
  </div>

  <div class="card">
    <h3><?php te('sites.new.heading', [], 'Nový web'); ?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row">
        <div><label><?php te('sites.field.domain', [], 'Doména'); ?></label><input name="domain" placeholder="example.com" required></div>
        <div style="display:flex;align-items:flex-end"><button class="btn" name="create" value="1"><?php te('common.create', [], 'Vytvořit'); ?></button></div>
      </div>
<div class="row" style="margin-top:12px;">
  <div>
    <label><?=h(t('sites.field.root_base', [], 'Základ rootu'))?></label>
    <select name="root_base">
      <?php foreach($allowedBases as $b): ?>
        <option value="<?=h($b)?>"><?=h($b)?></option>
      <?php endforeach; ?>
    </select>
    <small><?=h(t('sites.help.root_base_prefix', [], 'Vyber základní cestu ze Settings:'))?> <code>web_root_bases</code>.</small>
  </div>
  <div>
    <label><?=h(t('sites.field.root_suffix', [], 'Doplněk rootu'))?></label>
    <input name="root_suffix" placeholder="<?=h(t('sites.placeholder.root_suffix', [], 'např. example.com/public'))?>">
    <small><?=h(t('sites.help.root_suffix', [], 'Když necháš prázdné, použije se'))?> <code>domena/public</code>.</small>
  </div>
</div>

<div class="row">
  <div>
    <label><input type="checkbox" name="force_https" value="1" checked> <?=h(t('site.field.force_https', [], 'Vynutit HTTPS'))?></label>
  </div>
  <div>
    <label><input type="checkbox" name="hsts" value="1"> <?=h(t('site.field.hsts', [], 'HSTS'))?></label>
  </div>
</div>

    </form>
  </div>

  <div class="card">
    <h3><?php te('common.list', [], 'Seznam'); ?></h3>
<div class="table-scroll">
    <table>
      <tr><th><?php te('sites.col.domain', [], 'Doména'); ?></th><th><?php te('common.status', [], 'Status'); ?></th><th><?php te('sites.col.db', [], 'Databáze'); ?></th><th><?php te('common.actions', [], 'Akce'); ?></th></tr>
      <?php foreach($sites as $s): ?>
        <tr>
          <td><?=h($s['domain'])?><br><small><?=h($s['root_path'])?></small></td>
          <td>
            <span class="pill <?= $s['status']==='active'?'ok':($s['status']==='error'?'err':'run') ?>"><?=h(t('status.'.(string)$s['status'], [], (string)$s['status']))?></span>
            <?php if($s['last_error']): ?><br><small><?=h($s['last_error'])?></small><?php endif; ?>
          </td>
          <td>
            <small><?php te('sites.db.name', [], 'DB'); ?>:</small> <?=h($s['db_name']?:'-')?> <br>
            <small><?php te('sites.db.user', [], 'Uživatel'); ?>:</small> <?=h($s['db_user']?:'-')?> <br>
            <?php if($s['db_pass']): ?><small><?php te('sites.db.pass', [], 'Heslo'); ?>:</small> <code><?=h($s['db_pass'])?></code><?php endif; ?>
          </td>
          <td>
            <form method="post" style="margin:0; display:grid; gap:6px;">
              <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
              <input type="hidden" name="id" value="<?=h($s['id'])?>">
              <a class="btn2" href="/site.php?id=<?=h($s['id'])?>" style="text-decoration:none;display:inline-block;text-align:center"><?php te('common.settings', [], 'Nastavení'); ?></a>
              <button class="btn2" name="rebuild" value="1"><?php te('common.rebuild', [], 'Rebuild'); ?></button>
              <button class="btn2" name="reset_db_pass" value="1"><?php te('sites.action.reset_db_pass', [], 'Reset DB hesla'); ?></button>
              <button class="btn-danger" name="delete" value="1" onclick="return confirm(<?=json_encode(t('common.confirm_delete', [], 'Opravdu smazat?'))?>);"><?php te('common.delete', [], 'Smazat'); ?></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
  </div>
</div>
<?php });

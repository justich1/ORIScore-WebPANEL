<?php require __DIR__.'/_boot.php'; require __DIR__.'/_view.php'; require_login();
$u=me($pdo);

$id=(int)($_GET['id'] ?? 0);
$st=$pdo->prepare("SELECT * FROM tunnels WHERE id=? AND user_id=?");
$st->execute([$id,(int)$u['id']]);
$t=$st->fetch();
if(!$t){ flash_set('err', t('common.not_found', [], 'Nenalezeno')); header("Location:/tunnels.php"); exit; }

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_check();

  if(isset($_POST['save'])){
    $up=trim((string)($_POST['upstream'] ?? ''));
    if(!preg_match('~^https?://~i',$up)){
      flash_set('err', t('tunnels.flash.invalid_upstream', [], 'Neplatný upstream. Musí začínat http:// nebo https://'));
      header("Location:/tunnel.php?id=".$id); exit;
    }
    $force = isset($_POST['force_https']) ? 1 : 0;
    $hsts  = isset($_POST['hsts']) ? 1 : 0;

    $pdo->prepare("UPDATE tunnels SET upstream=?, force_https=?, hsts=? WHERE id=? AND user_id=?")
        ->execute([$up,$force,$hsts,$id,(int)$u['id']]);

    flash_set('ok', t('common.saved', [], 'Uloženo'));
    header("Location:/tunnel.php?id=".$id); exit;
  }

  if(isset($_POST['apply'])){
    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_tunnel',?, 'queued', JSON_OBJECT('action','rebuild'))")
        ->execute([$id]);
    flash_set('ok', t('tunnels.flash.queued_rebuild', [], 'Přegenerování proxy zařazeno do fronty.'));
    header("Location:/tunnel.php?id=".$id); exit;
  }

  if(isset($_POST['disable'])){
    $pdo->prepare("UPDATE tunnels SET status='disabled' WHERE id=? AND user_id=?")
        ->execute([$id,(int)$u['id']]);

    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_tunnel',?, 'queued', JSON_OBJECT('action','rebuild'))")
        ->execute([$id]);

    flash_set('ok', t('tunnel.flash.disabled', [], 'Proxy vypnuta a přegenerování zařazeno do fronty.'));
    header("Location:/tunnel.php?id=".$id); exit;
  }

  if(isset($_POST['enable'])){
    $pdo->prepare("UPDATE tunnels SET status='active' WHERE id=? AND user_id=?")
        ->execute([$id,(int)$u['id']]);

    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_tunnel',?, 'queued', JSON_OBJECT('action','rebuild'))")
        ->execute([$id]);

    flash_set('ok', t('tunnel.flash.enabled', [], 'Proxy zapnuta a přegenerování zařazeno do fronty.'));
    header("Location:/tunnel.php?id=".$id); exit;
  }
}

render($pdo, t('page.tunnel.title', [], 'Proxy detail'), function() use($t){ ?>
  <div class="card">
    <h2><?=h($t['subdomain'])?></h2>
    <small><?=h(t('common.id', [], 'ID'))?>: <?=h($t['id'])?> • <?=h(t('common.status', [], 'Stav'))?>: <span class="pill <?= $t['status']==='active'?'ok':($t['status']==='error'?'err':'run') ?>"><?=h(t('status.'.$t['status'], [], (string)$t['status']))?></span></small>
    <?php if($t['last_error']): ?><pre><?=h($t['last_error'])?></pre><?php endif; ?>
  </div>

  <div class="card">
    <h3><?=h(t('tunnel.heading', [], 'Nastavení proxy'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">

      <div class="row">
        <div>
          <label><?=h(t('tunnels.field.upstream', [], 'Upstream'))?></label>
          <input name="upstream" value="<?=h($t['upstream'])?>" required>
          <small><?=t('tunnel.upstream.help', [], 'Pro backend s vlastním HTTPS certifikátem použij např. <code>https://109.164.100.162</code>. Nginx nastaví SNI podle veřejné domény a <code>proxy_ssl_verify off</code>.')?></small>
        </div>
      </div>

      <div class="row">
        <div>
          <label><input type="checkbox" name="force_https" value="1" <?= (int)$t['force_https'] ? 'checked' : '' ?>> <?=h(t('tunnel.force_https', [], 'Vynutit HTTPS'))?></label>
        </div>
        <div>
          <label><input type="checkbox" name="hsts" value="1" <?= (int)$t['hsts'] ? 'checked' : '' ?>> <?=h(t('tunnel.hsts', [], 'HSTS'))?></label>
        </div>
      </div>

      <div class="row">
        <button class="btn" name="save" value="1"><?=h(t('common.save', [], 'Uložit'))?></button>
        <button class="btn2" name="apply" value="1" onclick="return confirm(<?=json_encode(t('common.confirm_apply', [], 'Aplikovat změny?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('common.apply_rebuild', [], 'Aplikovat / přegenerovat'))?></button>
<?php if ($t['status'] === 'active'): ?>
  <button class="btn-danger" name="disable" value="1"
    onclick="return confirm(<?=json_encode(t('common.confirm_disable', [], 'Opravdu vypnout?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('common.disable', [], 'Vypnout'))?></button>
<?php else: ?>
  <button class="btn" name="enable" value="1"
    onclick="return confirm(<?=json_encode(t('common.confirm_enable', [], 'Opravdu zapnout?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('common.enable', [], 'Zapnout'))?></button>
<?php endif; ?>
        <a class="btn2" href="/tunnels.php" style="text-decoration:none;display:inline-block"><?=h(t('common.back', [], 'Zpět'))?></a>
      </div>
    </form>
  </div>
<?php });

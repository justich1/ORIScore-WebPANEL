<?php require __DIR__.'/_boot.php'; require __DIR__.'/_view.php'; require_login();
$u=me($pdo);

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();

  if (isset($_POST['create'])) {
    $sub=strtolower(trim($_POST['subdomain']??''));
    $up=trim($_POST['upstream']??'');
    if (!domain_valid($sub)) { flash_set('err', t('tunnels.flash.invalid_subdomain', [], 'Neplatná proxy doména.')); header("Location:/tunnels.php"); exit; }
    if (!preg_match('~^https?://~i',$up)) { flash_set('err', t('tunnels.flash.invalid_upstream', [], 'Neplatný upstream. Musí začínat http:// nebo https://')); header("Location:/tunnels.php"); exit; }

    $pdo->beginTransaction();
    $pdo->prepare("INSERT INTO tunnels(user_id,subdomain,upstream,status) VALUES(?,?,?, 'provisioning')")->execute([(int)$u['id'],$sub,$up]);
    $tid=(int)$pdo->lastInsertId();
    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_tunnel',?, 'queued', JSON_OBJECT('action','provision'))")->execute([$tid]);
    $pdo->commit();

    flash_set('ok', t('tunnels.flash.queued_provision', [], 'Proxy vytvořena a provisioning zařazen do fronty.'));
    header("Location:/tunnels.php"); exit;
  }

  if (isset($_POST['delete'])) {
    $id=(int)($_POST['id']??0);
    $st=$pdo->prepare("SELECT * FROM tunnels WHERE id=? AND user_id=?");
    $st->execute([$id,(int)$u['id']]);
    $t=$st->fetch();
    if(!$t){ flash_set('err', t('common.not_found', [], 'Nenalezeno')); header("Location:/tunnels.php"); exit; }

    $pdo->beginTransaction();
    $pdo->prepare("UPDATE tunnels SET status='provisioning' WHERE id=?")->execute([$id]);
    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('deprovision_tunnel',?, 'queued', JSON_OBJECT('action','delete'))")->execute([$id]);
    $pdo->commit();

    flash_set('ok', t('tunnels.flash.queued_delete', [], 'Smazání proxy zařazeno do fronty.'));
    header("Location:/tunnels.php"); exit;
  }

  if (isset($_POST['rebuild'])) {
    $id=(int)($_POST['id']??0);
    $st=$pdo->prepare("SELECT * FROM tunnels WHERE id=? AND user_id=?");
    $st->execute([$id,(int)$u['id']]);
    if(!$st->fetch()){ flash_set('err', t('common.not_found', [], 'Nenalezeno')); header("Location:/tunnels.php"); exit; }

    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('provision_tunnel',?, 'queued', JSON_OBJECT('action','rebuild'))")->execute([$id]);
    flash_set('ok', t('tunnels.flash.queued_rebuild', [], 'Přegenerování proxy zařazeno do fronty.'));
    header("Location:/tunnels.php"); exit;
  }
}

$st=$pdo->prepare("SELECT * FROM tunnels WHERE user_id=? ORDER BY id DESC LIMIT 200");
$st->execute([(int)$u['id']]); $tunnels=$st->fetchAll();

render($pdo, t('page.tunnels.title', [], 'Proxy / reverse proxy'), function() use($tunnels){ ?>
  <div class="card">
    <h2><?=h(t('page.tunnels.title', [], 'Proxy / reverse proxy'))?></h2>
    <small><?=h(t('tunnels.help', [], 'Nginx HTTP/HTTPS reverse proxy. Provisioner vytvoří vhost a přesměruje doménu na upstream.'))?></small>
  </div>

  <div class="card">
    <h3><?=h(t('tunnels.new.heading', [], 'Nová proxy'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row">
        <div><label><?=h(t('tunnels.field.subdomain', [], 'Proxy doména'))?></label><input name="subdomain" placeholder="<?=h(t('tunnels.placeholder.subdomain', [], 'app.example.com'))?>" required></div>
        <div><label><?=h(t('tunnels.field.upstream', [], 'Upstream'))?></label><input name="upstream" placeholder="<?=h(t('tunnels.placeholder.upstream', [], 'http://127.0.0.1:3000 nebo https://10.0.0.10'))?>" required><small><?=h(t('tunnels.upstream.help', [], 'HTTPS backend se self-signed certifikátem je podporovaný. Provisioner předá SNI podle proxy domény a vypne ověření backend certifikátu.'))?></small></div>
      </div>
      <p style="margin-top:12px"><button class="btn" name="create" value="1"><?=h(t('common.create', [], 'Vytvořit'))?></button></p>
    </form>
  </div>

  <div class="card">
    <h3><?=h(t('common.list', [], 'Seznam'))?></h3>
<div class="table-scroll">
    <table>
      <tr><th><?=h(t('tunnels.col.subdomain', [], 'Proxy doména'))?></th><th><?=h(t('tunnels.col.upstream', [], 'Upstream'))?></th><th><?=h(t('common.status', [], 'Stav'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
      <?php foreach($tunnels as $t): ?>
        <tr>
          <td><?=h($t['subdomain'])?></td>
          <td><?=h($t['upstream'])?></td>
          <td>
            <span class="pill <?= $t['status']==='active'?'ok':($t['status']==='error'?'err':'run') ?>"><?=h(t('status.'.$t['status'], [], (string)$t['status']))?></span>
            <?php if($t['last_error']): ?><br><small><?=h($t['last_error'])?></small><?php endif; ?>
          </td>
          <td>
            <form method="post" style="margin:0; display:grid; gap:6px;">
              <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
              <input type="hidden" name="id" value="<?=h($t['id'])?>">
              <a class="btn2" href="/tunnel.php?id=<?=h($t['id'])?>" style="text-decoration:none;display:inline-block;text-align:center"><?=h(t('common.settings', [], 'Nastavení'))?></a>
              <button class="btn2" name="rebuild" value="1"><?=h(t('common.rebuild', [], 'Přegenerovat'))?></button>
              <button class="btn-danger" name="delete" value="1" onclick="return confirm(<?=json_encode(t('common.confirm_delete', [], 'Opravdu smazat?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('common.delete', [], 'Smazat'))?></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      <?php if(!$tunnels): ?><tr><td colspan="4"><small><?=h(t('tunnels.empty', [], 'Žádné proxy zatím nejsou vytvořené.'))?></small></td></tr><?php endif; ?>
    </table>
  </div>
</div>
<?php });

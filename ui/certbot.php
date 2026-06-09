<?php
require __DIR__.'/_boot.php';
require __DIR__.'/_view.php';
require_login();
$u=me($pdo);

function enqueue_job(PDO $pdo, string $type, int $refId, array $payload=[]): void {
  $st=$pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES(?,?, 'queued', ?)");
  $st->execute([$type,$refId,json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}

function certbot_status_label(?string $status): string {
  $status = trim((string)$status);
  if ($status === '') return t('common.status.none', [], 'žádný');
  return t('common.status.' . $status, [], $status);
}

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();
  $action=$_POST['action'] ?? '';
  $email = trim((string)($_POST['email'] ?? setting($pdo,'certbot_email','')));

  if ($action === 'save_email') {
    set_setting($pdo,'certbot_email',$email);
    flash_set('ok', t('certbot.flash.email_saved', [], 'Certbot e-mail uložen.'));
    header('Location:/certbot.php'); exit;
  }

  if (in_array($action, ['test','issue'], true)) {
    $siteId=(int)($_POST['site_id'] ?? 0);
    $includeWww = !empty($_POST['include_www']);
    $st=$pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
    $st->execute([$siteId,(int)$u['id']]);
    $site=$st->fetch();
    if(!$site){ flash_set('err', t('certbot.flash.site_not_found', [], 'Web nenalezen.')); header('Location:/certbot.php'); exit; }
    enqueue_job($pdo, $action==='test'?'certbot_test_acme':'certbot_issue', $siteId, ['include_www'=>$includeWww,'email'=>$email]);
    flash_set('ok', $action==='test'
      ? t('certbot.flash.site_acme_test_queued', [], 'ACME test webu zařazen.')
      : t('certbot.flash.site_issue_queued', [], 'Vystavení certifikátu webu zařazeno.'));
    header('Location:/jobs.php'); exit;
  }

  if (in_array($action, ['proxy_test','proxy_issue'], true)) {
    $tunnelId=(int)($_POST['tunnel_id'] ?? 0);
    $includeWww = !empty($_POST['include_www']);
    $st=$pdo->prepare("SELECT * FROM tunnels WHERE id=? AND user_id=?");
    $st->execute([$tunnelId,(int)$u['id']]);
    $tun=$st->fetch();
    if(!$tun){ flash_set('err', t('certbot.flash.proxy_not_found', [], 'Proxy nenalezena.')); header('Location:/certbot.php'); exit; }
    enqueue_job($pdo, $action==='proxy_test'?'certbot_test_acme_proxy':'certbot_issue_proxy', $tunnelId, ['include_www'=>$includeWww,'email'=>$email]);
    flash_set('ok', $action==='proxy_test'
      ? t('certbot.flash.proxy_acme_test_queued', [], 'ACME test proxy zařazen.')
      : t('certbot.flash.proxy_issue_queued', [], 'Vystavení certifikátu proxy zařazeno.'));
    header('Location:/jobs.php'); exit;
  }

  if ($action === 'renew_all') {
    enqueue_job($pdo, 'certbot_renew_all', 0, []);
    flash_set('ok', t('certbot.flash.renew_all_queued', [], 'Obnova všech certifikátů zařazena.'));
    header('Location:/jobs.php'); exit;
  }

  if ($action === 'dry_run') {
    enqueue_job($pdo, 'certbot_dry_run', 0, []);
    flash_set('ok', t('certbot.flash.dry_run_queued', [], 'Certbot kontrola nanečisto zařazena.'));
    header('Location:/jobs.php'); exit;
  }
}

$sites=$pdo->prepare("SELECT * FROM sites WHERE user_id=? ORDER BY domain ASC");
$sites->execute([(int)$u['id']]);
$sites=$sites->fetchAll();

$tunnels=$pdo->prepare("SELECT * FROM tunnels WHERE user_id=? ORDER BY subdomain ASC");
$tunnels->execute([(int)$u['id']]);
$tunnels=$tunnels->fetchAll();

$email=setting($pdo,'certbot_email','');
$acme=setting($pdo,'acme_webroot','/var/www/letsencrypt');

render($pdo, t('page.certbot.title', [], 'Certbot'), function() use($sites,$tunnels,$email,$acme){ ?>
  <div class="card">
    <h2><?=h(t('certbot.heading', [], 'Certbot / HTTPS'))?></h2>
    <small>
      <?=h(t('certbot.intro.before_acme_path', [], 'Reálný Python job: ACME test, vystavení certifikátu a obnova. ACME challenge se obsluhuje z'))?>
      <code><?=h($acme)?></code>
      <?=h(t('certbot.intro.after_acme_path', [], 'a nepřesměrovává se na HTTPS.'))?>
    </small>
  </div>

  <div class="card">
    <h3><?=h(t('certbot.settings.heading', [], 'Nastavení'))?></h3>
    <form method="post" class="row">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="action" value="save_email">
      <div>
        <label><?=h(t('certbot.settings.email_label', [], "Let's Encrypt e-mail"))?></label>
        <input name="email" value="<?=h($email)?>" placeholder="admin@example.com">
      </div>
      <div style="display:flex;align-items:flex-end"><button class="btn"><?=h(t('common.save', [], 'Uložit'))?></button></div>
    </form>
  </div>

  <div class="card">
    <h3><?=h(t('certbot.sites.heading', [], 'Weby'))?></h3>
    <div class="table-scroll"><table>
      <tr>
        <th><?=h(t('common.domain', [], 'Doména'))?></th>
        <th><?=h(t('common.status', [], 'Stav'))?></th>
        <th><?=h(t('certbot.table.ssl', [], 'SSL'))?></th>
        <th><?=h(t('common.actions', [], 'Akce'))?></th>
      </tr>
      <?php foreach($sites as $s): ?>
        <tr>
          <td><?=h($s['domain'])?><br><small><?=h($s['root_path'])?></small></td>
          <td><span class="pill <?= $s['status']==='active'?'ok':($s['status']==='error'?'err':'run') ?>"><?=h(certbot_status_label((string)$s['status']))?></span></td>
          <td>
            <span class="pill <?= ($s['ssl_status']??'')==='active'?'ok':(($s['ssl_status']??'')==='error'?'err':'run') ?>"><?=h(certbot_status_label($s['ssl_status'] ?? ''))?></span>
            <?php if(!empty($s['ssl_last_error'])): ?><br><small><?=h($s['ssl_last_error'])?></small><?php endif; ?>
          </td>
          <td>
            <form method="post" style="display:grid;gap:6px;margin:0">
              <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
              <input type="hidden" name="site_id" value="<?=h($s['id'])?>">
              <input type="hidden" name="email" value="<?=h($email)?>">
              <label><input type="checkbox" name="include_www" value="1" checked> <?=h(t('certbot.form.include_www', [], 'zahrnout'))?> www.<?=h($s['domain'])?></label>
              <button class="btn2" name="action" value="test"><?=h(t('certbot.action.test_acme', [], 'Test ACME'))?></button>
              <button class="btn" name="action" value="issue"><?=h(t('certbot.action.issue_https', [], 'Vystavit HTTPS'))?></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
    </table></div>
  </div>

  <div class="card">
    <h3><?=h(t('certbot.proxy.heading', [], 'Proxy / reverzní proxy'))?></h3>
    <small>
      <?=h(t('certbot.proxy.intro.before_example', [], 'Certifikát pro proxy doménu. www se defaultně nepřidává, protože proxy bývá typicky subdoména jako'))?>
      <code>kotel.example.cz</code>.
    </small>
    <div class="table-scroll"><table>
      <tr>
        <th><?=h(t('certbot.table.proxy_domain', [], 'Proxy doména'))?></th>
        <th><?=h(t('certbot.table.upstream', [], 'Cílový server'))?></th>
        <th><?=h(t('common.status', [], 'Stav'))?></th>
        <th><?=h(t('certbot.table.ssl', [], 'SSL'))?></th>
        <th><?=h(t('common.actions', [], 'Akce'))?></th>
      </tr>
      <?php foreach($tunnels as $t): ?>
        <tr>
          <td><?=h($t['subdomain'])?></td>
          <td><small><?=h($t['upstream'])?></small></td>
          <td><span class="pill <?= $t['status']==='active'?'ok':($t['status']==='error'?'err':'run') ?>"><?=h(certbot_status_label((string)$t['status']))?></span></td>
          <td>
            <span class="pill <?= ($t['ssl_status']??'')==='active'?'ok':(($t['ssl_status']??'')==='error'?'err':'run') ?>"><?=h(certbot_status_label($t['ssl_status'] ?? ''))?></span>
            <?php if(!empty($t['ssl_last_error'])): ?><br><small><?=h($t['ssl_last_error'])?></small><?php endif; ?>
          </td>
          <td>
            <form method="post" style="display:grid;gap:6px;margin:0">
              <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
              <input type="hidden" name="tunnel_id" value="<?=h($t['id'])?>">
              <input type="hidden" name="email" value="<?=h($email)?>">
              <label><input type="checkbox" name="include_www" value="1"> <?=h(t('certbot.form.include_www', [], 'zahrnout'))?> www.<?=h($t['subdomain'])?></label>
              <button class="btn2" name="action" value="proxy_test"><?=h(t('certbot.action.test_acme', [], 'Test ACME'))?></button>
              <button class="btn" name="action" value="proxy_issue"><?=h(t('certbot.action.issue_https', [], 'Vystavit HTTPS'))?></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
    </table></div>
  </div>

  <div class="card">
    <h3><?=h(t('certbot.maintenance.heading', [], 'Údržba'))?></h3>
    <form method="post" style="display:flex;gap:8px;flex-wrap:wrap">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <button class="btn2" name="action" value="dry_run"><?=h(t('certbot.action.renew_dry_run', [], 'Obnova nanečisto'))?></button>
      <button class="btn" name="action" value="renew_all"><?=h(t('certbot.action.renew_all', [], 'Obnovit vše'))?></button>
    </form>
  </div>
<?php });

<?php require __DIR__.'/_boot.php'; require __DIR__.'/_view.php'; require_login();
$u=me($pdo);

function val_user(PDO $pdo, int $ftpId, int $uid): ?array {
  $st=$pdo->prepare("SELECT * FROM ftp_accounts WHERE id=? AND user_id=?");
  $st->execute([$ftpId,$uid]);
  return $st->fetch() ?: null;
}

function ftp_status_label(string $status): string {
  return t('status.' . $status, [], $status);
}

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();

  if (isset($_POST['create'])) {
    $site_id=(int)($_POST['site_id']??0);

    $st=$pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
    $st->execute([$site_id,(int)$u['id']]);
    $site=$st->fetch();
    if(!$site){ flash_set('err', t('common.invalid_site', [], 'Neplatný web')); header("Location:/ftp.php"); exit; }

    $prefix = setting($pdo,'ftp_username_prefix','ftp_');
    $rand = bin2hex(random_bytes(3));
    $username = strtolower($prefix.$site_id."_".$rand);

    $home = dirname($site['root_path']);

    try{
      $pdo->beginTransaction();
      $pdo->prepare("INSERT INTO ftp_accounts(user_id,site_id,username,home_dir,status) VALUES(?,?,?,?, 'provisioning')")
          ->execute([(int)$u['id'],$site_id,$username,$home]);
      $fid=(int)$pdo->lastInsertId();
      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('ftp_create',?, 'queued', JSON_OBJECT('action','create'))")
          ->execute([$fid]);
      $pdo->commit();
      flash_set('ok', t('ftp.flash.queued_create', [], 'Vytvoření FTP účtu zařazeno do fronty.'));
    } catch(Throwable $e){
      $pdo->rollBack();
      flash_set('err', t('common.error_with_msg', ['msg'=>$e->getMessage()], 'Chyba: {msg}'));
    }
    header("Location:/ftp.php"); exit;
  }

  if (isset($_POST['reset_pass'])) {
    $id=(int)($_POST['id']??0);
    if(!val_user($pdo,$id,(int)$u['id'])){ flash_set('err', t('common.not_found', [], 'Nenalezeno')); header("Location:/ftp.php"); exit; }
    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('ftp_reset_pass',?, 'queued', JSON_OBJECT('action','reset_pass'))")->execute([$id]);
    flash_set('ok', t('ftp.flash.queued_reset_pass', [], 'Reset hesla FTP účtu zařazen do fronty.'));
    header("Location:/ftp.php"); exit;
  }

  if (isset($_POST['delete'])) {
    $id=(int)($_POST['id']??0);
    if(!val_user($pdo,$id,(int)$u['id'])){ flash_set('err', t('common.not_found', [], 'Nenalezeno')); header("Location:/ftp.php"); exit; }
    $pdo->beginTransaction();
    $pdo->prepare("UPDATE ftp_accounts SET status='provisioning' WHERE id=?")->execute([$id]);
    $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('ftp_delete',?, 'queued', JSON_OBJECT('action','delete'))")->execute([$id]);
    $pdo->commit();
    flash_set('ok', t('ftp.flash.queued_delete', [], 'Smazání FTP účtu zařazeno do fronty.'));
    header("Location:/ftp.php"); exit;
  }
}

$sites=$pdo->prepare("SELECT id,domain,root_path,status FROM sites WHERE user_id=? ORDER BY id DESC");
$sites->execute([(int)$u['id']]);
$sites=$sites->fetchAll();

$accounts=$pdo->prepare("SELECT fa.*, s.domain FROM ftp_accounts fa LEFT JOIN sites s ON s.id=fa.site_id WHERE fa.user_id=? ORDER BY fa.id DESC LIMIT 200");
$accounts->execute([(int)$u['id']]);
$accounts=$accounts->fetchAll();

render($pdo, t('page.ftp.title', [], 'FTP'), function() use($sites,$accounts){ ?>
  <div class="card">
    <h2><?php te('page.ftp.heading', [], 'FTP účty'); ?></h2>
    <small><?php te('ftp.help', [], 'FTP účty pro jednotlivé weby. Systémové změny provádí provisioner přes job frontu.'); ?></small>
  </div>

  <div class="card">
    <h3><?php te('ftp.new.heading', [], 'Nový FTP účet'); ?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row">
        <div>
          <label><?php te('ftp.field.site', [], 'Web'); ?></label>
          <select name="site_id" required>
            <option value=""><?php te('common.select', [], '— vyber —'); ?></option>
            <?php foreach($sites as $s): ?>
              <option value="<?=h($s['id'])?>"><?=h($s['domain'])?> (<?=h(ftp_status_label((string)$s['status']))?>)</option>
            <?php endforeach; ?>
          </select>
          <small><?php te('ftp.new.help', [], 'Domovský adresář FTP účtu bude nastaven na adresář webu.'); ?></small>
        </div>
        <div style="display:flex;align-items:flex-end">
          <button class="btn" name="create" value="1"><?php te('common.create', [], 'Vytvořit'); ?></button>
        </div>
      </div>
    </form>
  </div>

  <div class="card">
    <h3><?php te('common.list', [], 'Seznam'); ?></h3>
<div class="table-scroll">
    <table>
      <tr>
        <th><?php te('common.web', [], 'Web'); ?></th>
        <th><?php te('ftp.col.username', [], 'Uživatel'); ?></th>
        <th><?php te('ftp.col.home', [], 'Domovský adresář'); ?></th>
        <th><?php te('common.status', [], 'Stav'); ?></th>
        <th><?php te('common.password', [], 'Heslo'); ?></th>
        <th><?php te('common.actions', [], 'Akce'); ?></th>
      </tr>
      <?php foreach($accounts as $a): ?>
        <tr>
          <td><?=h($a['domain'] ?: ('site#'.$a['site_id']))?></td>
          <td><code><?=h($a['username'])?></code></td>
          <td><small><?=h($a['home_dir'])?></small></td>
          <td><span class="pill <?= $a['status']==='active'?'ok':($a['status']==='error'?'err':'run') ?>"><?=h(ftp_status_label((string)$a['status']))?></span>
            <?php if($a['last_error']): ?><br><small><?=h($a['last_error'])?></small><?php endif; ?>
          </td>
          <td><?php if($a['ftp_pass']): ?><code><?=h($a['ftp_pass'])?></code><?php else: ?><small>-</small><?php endif; ?></td>
          <td>
            <form method="post" style="margin:0; display:grid; gap:6px;">
              <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
              <input type="hidden" name="id" value="<?=h($a['id'])?>">
              <button class="btn2" name="reset_pass" value="1"><?php te('common.reset_password', [], 'Reset hesla'); ?></button>
              <button class="btn-danger" name="delete" value="1" onclick="return confirm(<?=json_encode(t('ftp.confirm.delete', [], 'Smazat FTP účet?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?php te('common.delete', [], 'Smazat'); ?></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
    </table>
</div>
    <small><?php te('ftp.password_after_job', [], 'Heslo se zobrazí po doběhnutí jobu. (MVP)'); ?></small>
  </div>

  <div class="card">
    <h3><?php te('ftp.vsftpd.heading', [], 'vsftpd minimální konfigurace'); ?></h3>
    <pre><?=h(t('ftp.vsftpd.config', [], "sudo apt install -y vsftpd\nsudo nano /etc/vsftpd.conf\n\n# doporučené:\nlocal_enable=YES\nwrite_enable=YES\nchroot_local_user=YES\nallow_writeable_chroot=YES\n\nsudo systemctl restart vsftpd"))?></pre>
  </div>
<?php });

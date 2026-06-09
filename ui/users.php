<?php require __DIR__.'/_boot.php'; require __DIR__.'/_view.php'; require_admin();

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();

  if (isset($_POST['create'])) {
    $email=strtolower(trim($_POST['email']??''));
    $role=$_POST['role']??'customer';
    $pass=(string)($_POST['password']??'');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { flash_set('err', t('users.flash.invalid_email', [], 'Neplatný email')); header("Location:/users.php"); exit; }
    if (!in_array($role,['admin','customer'],true)) $role='customer';
    if (strlen($pass)<8) { flash_set('err', t('users.flash.password_min_8', [], 'Heslo musí mít alespoň 8 znaků.')); header("Location:/users.php"); exit; }

    $hash=password_hash($pass,PASSWORD_DEFAULT);
    try{
      $pdo->prepare("INSERT INTO users(email,pass_hash,role,is_active) VALUES(?,?,?,1)")->execute([$email,$hash,$role]);
      flash_set('ok', t('users.flash.created', [], 'Uživatel vytvořen'));
    } catch(Throwable $e){
      flash_set('err', t('users.flash.create_failed_email_exists', [], 'Nelze vytvořit uživatele. Email už možná existuje.'));
    }
    header("Location:/users.php"); exit;
  }

  if (isset($_POST['toggle'])) {
    $id=(int)($_POST['id']??0);
    $pdo->prepare("UPDATE users SET is_active = IF(is_active=1,0,1) WHERE id=?")->execute([$id]);
    flash_set('ok', t('users.flash.activation_changed', [], 'Aktivace změněna'));
    header("Location:/users.php"); exit;
  }

  if (isset($_POST['reset_pass'])) {
    $id=(int)($_POST['id']??0);
    $new=bin2hex(random_bytes(4)).'A!';
    $hash=password_hash($new,PASSWORD_DEFAULT);
    $pdo->prepare("UPDATE users SET pass_hash=? WHERE id=?")->execute([$hash,$id]);
    flash_set('ok', t('users.flash.new_password', ['id'=>$id, 'password'=>$new], 'Nové heslo pro user #{id}: {password}'));
    header("Location:/users.php"); exit;
  }

  if (isset($_POST['delete'])) {
    $id=(int)($_POST['id']??0);
    if ($id === (int)($_SESSION['uid']??0)) { flash_set('err', t('users.flash.cannot_delete_self', [], 'Nemůžeš smazat sám sebe')); header("Location:/users.php"); exit; }
    $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$id]);
    flash_set('ok', t('users.flash.deleted', [], 'Uživatel smazán'));
    header("Location:/users.php"); exit;
  }
}

$users=$pdo->query("SELECT id,email,role,is_active,created_at FROM users ORDER BY id DESC")->fetchAll();

render($pdo, t('page.users.title', [], 'Uživatelé'), function() use($users){ ?>
  <div class="card">
    <h2><?=h(t('page.users.title', [], 'Uživatelé'))?></h2>
    <small><?=h(t('users.help', [], 'Admin správa účtů.'))?></small>
  </div>

  <div class="card">
    <h3><?=h(t('users.create.heading', [], 'Vytvořit uživatele'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row3">
        <div><label><?=h(t('users.field.email', [], 'Email'))?></label><input name="email" required></div>
        <div><label><?=h(t('users.field.role', [], 'Role'))?></label>
          <select name="role">
            <option value="customer"><?=h(t('users.role.customer', [], 'customer'))?></option>
            <option value="admin"><?=h(t('users.role.admin', [], 'admin'))?></option>
          </select>
        </div>
        <div><label><?=h(t('users.field.password', [], 'Heslo'))?></label><input name="password" type="password" required></div>
      </div>
      <p style="margin-top:12px"><button class="btn" name="create" value="1"><?=h(t('common.create', [], 'Vytvořit'))?></button></p>
    </form>
  </div>

  <div class="card">
    <h3><?=h(t('common.list', [], 'Seznam'))?></h3>
<div class="table-scroll">
    <table>
      <tr><th><?=h(t('common.id', [], 'ID'))?></th><th><?=h(t('users.col.email', [], 'Email'))?></th><th><?=h(t('users.col.role', [], 'Role'))?></th><th><?=h(t('users.col.active', [], 'Aktivní'))?></th><th><?=h(t('users.col.created', [], 'Vytvořeno'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
      <?php foreach($users as $u): ?>
      <tr>
        <td><?=h($u['id'])?></td>
        <td><?=h($u['email'])?></td>
        <td><?=h(t('users.role.'.$u['role'], [], (string)$u['role']))?></td>
        <td><?= (int)$u['is_active']===1 ? '<span class="pill ok">'.h(t('common.yes', [], 'ano')).'</span>' : '<span class="pill err">'.h(t('common.no', [], 'ne')).'</span>' ?></td>
        <td><?=h($u['created_at'])?></td>
        <td>
          <form method="post" style="margin:0; display:flex; gap:6px; flex-wrap:wrap;">
            <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
            <input type="hidden" name="id" value="<?=h($u['id'])?>">
            <button class="btn2" name="toggle" value="1"><?=h(t('users.action.toggle', [], 'Přepnout'))?></button>
            <button class="btn2" name="reset_pass" value="1"><?=h(t('users.action.reset_pass', [], 'Reset hesla'))?></button>
            <button class="btn-danger" name="delete" value="1" onclick="return confirm(<?=json_encode(t('users.confirm.delete', [], 'Smazat uživatele?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('common.delete', [], 'Smazat'))?></button>
          </form>
        </td>
      </tr>
      <?php endforeach; ?>
      <?php if(!$users): ?><tr><td colspan="6"><small><?=h(t('users.empty', [], 'Žádní uživatelé.'))?></small></td></tr><?php endif; ?>
    </table>
    <small><?=h(t('users.reset_password.note', [], 'Reset hesla vypíše nové heslo jako flash hlášku (MVP).'))?></small>
  </div>
<div>
<?php });

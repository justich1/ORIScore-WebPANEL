<?php require __DIR__.'/_boot.php'; require __DIR__.'/_view.php';
if (me($pdo)) { header("Location: /dashboard.php"); exit; }

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();
  $email=strtolower(trim($_POST['email']??''));
  $pass=(string)($_POST['password']??'');
  $st=$pdo->prepare("SELECT id,pass_hash,role,is_active FROM users WHERE email=? LIMIT 1");
  $st->execute([$email]); $u=$st->fetch();
  if ($u && (int)$u['is_active']===1 && password_verify($pass,$u['pass_hash'])) {
    session_regenerate_id(true);
    $_SESSION['uid']=(int)$u['id']; $_SESSION['role']=$u['role'];
    header("Location:/dashboard.php"); exit;
  }
  flash_set('err', t('login.bad_credentials', [], 'Neplatný e-mail nebo heslo.'));
  header("Location:/login.php"); exit;
}

render($pdo, t('login.title', [], 'Přihlášení'), function(){ ?>
  <div class="card">
    <h2><?php te('login.heading', [], 'Přihlášení'); ?></h2>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row">
        <div><label><?php te('login.email', [], 'E-mail'); ?></label><input type="email" name="email" required></div>
        <div><label><?php te('login.password', [], 'Heslo'); ?></label><input type="password" name="password" required></div>
      </div>
      <p style="margin-top:12px"><button class="btn"><?php te('login.submit', [], 'Přihlásit'); ?></button></p>
    </form>
  </div>
<?php });

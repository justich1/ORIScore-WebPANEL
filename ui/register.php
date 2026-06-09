<?php require __DIR__.'/_boot.php'; require __DIR__.'/_view.php';
if (me($pdo)) { header("Location: /dashboard.php"); exit; }

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();
  $email=strtolower(trim($_POST['email']??''));
  $pass=(string)($_POST['password']??'');
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) flash_set('err',t('i18n.register.php.neplatny_email.368a174d', [], 'Neplatný email'));
  elseif (strlen($pass)<8) flash_set('err',t('i18n.register.php.heslo_min_8_znaku.969197d8', [], 'Heslo min 8 znaků'));
  else {
    $hash=password_hash($pass,PASSWORD_DEFAULT);
    try{
      $pdo->prepare("INSERT INTO users(email,pass_hash,role,is_active) VALUES(?,?, 'customer',1)")->execute([$email,$hash]);
      flash_set('ok',t('i18n.register.php.registrace_hotova_prihlas_se.f5ccd930', [], 'Registrace hotová. Přihlas se.'));
      header("Location:/login.php"); exit;
    } catch(Throwable $e){
      flash_set('err','Registrace selhala (email existuje?).');
    }
  }
  header("Location:/register.php"); exit;
}

render($pdo,'Registrace', function(){ ?>
  <div class="card">
    <h2><?=h(t('i18n.register.text.registrace.1b6c3a45', [], 'Registrace'))?></h2>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row">
        <div><label><?=h(t('i18n.register.text.email.84add5b2', [], 'Email'))?></label><input type="email" name="email" required></div>
        <div><label><?=h(t('i18n.register.text.heslo.894f36e5', [], 'Heslo'))?></label><input type="password" name="password" required></div>
      </div>
      <p style="margin-top:12px"><button class="btn"><?=h(t('i18n.register.text.vytvorit_ucet.d4bc76b1', [], 'Vytvořit účet'))?></button></p>
    </form>
  </div>
<?php });
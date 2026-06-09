<?php
require __DIR__.'/_boot.php';
require __DIR__.'/_view.php';
require_login();

$u=me($pdo);
$st=$pdo->prepare("SELECT COUNT(*) c FROM sites WHERE user_id=?"); $st->execute([(int)$u['id']]); $siteCount=(int)$st->fetch()['c'];
$st=$pdo->prepare("SELECT COUNT(*) c FROM tunnels WHERE user_id=?"); $st->execute([(int)$u['id']]); $tunCount=(int)$st->fetch()['c'];
$jobCount=(int)$pdo->query("SELECT COUNT(*) c FROM jobs WHERE status IN('queued','running')")->fetch()['c'];

render($pdo, t('page.dashboard.title', [], 'Dashboard'), function() use($u,$siteCount,$tunCount,$jobCount){ ?>
  <div class="card">
    <h2><?=h(t('page.dashboard.title', [], 'Dashboard'))?></h2>
    <small><?=h($u['email'])?> (<?=h($u['role'])?>)</small>
  </div>
  <div class="row3">
    <div class="card"><h3><?=h(t('dashboard.sites', [], 'Weby'))?></h3><p><span class="pill run"><?=h($siteCount)?></span></p><p><a class="btn2" href="/sites.php"><?=h(t('common.manage', [], 'Spravovat'))?></a></p></div>
    <div class="card"><h3><?=h(t('dashboard.tunnels', [], 'Proxy'))?></h3><p><span class="pill run"><?=h($tunCount)?></span></p><p><a class="btn2" href="/tunnels.php"><?=h(t('common.manage', [], 'Spravovat'))?></a></p></div>
    <div class="card"><h3><?=h(t('dashboard.jobs', [], 'Úlohy'))?></h3><p><span class="pill run"><?=h($jobCount)?></span></p><p><a class="btn2" href="/jobs.php"><?=h(t('common.view', [], 'Zobrazit'))?></a></p></div>
  </div>
<?php });

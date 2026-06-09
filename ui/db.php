<?php
declare(strict_types=1);

require __DIR__.'/_boot.php';
require __DIR__.'/_view.php';
require_login();
$u = me($pdo);

$id = (int)($_GET['id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  csrf_check();

  $sid = (int)($_POST['id'] ?? 0);
  $st = $pdo->prepare("SELECT * FROM sites WHERE id=? AND user_id=?");
  $st->execute([$sid, (int)$u['id']]);
  $site = $st->fetch();
  if (!$site) {
    flash_set('err', t('common.not_found'));
    header('Location:/db.php'.($id?('?id='.$id):''));
    exit;
  }

  try {
    if (isset($_POST['ensure_db'])) {
      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('site_ensure_db',?, 'queued', JSON_OBJECT('action','db'))")
          ->execute([$sid]);
      flash_set('ok', 'Zařazeno: vytvořit/ověřit DB');
    } elseif (isset($_POST['reset_db_pass'])) {
      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('site_reset_db_pass',?, 'queued', JSON_OBJECT('action','reset_db_pass'))")
          ->execute([$sid]);
      flash_set('ok', t('sites.flash.queued_reset_db_pass'));
    } elseif (isset($_POST['delete_db'])) {
      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('site_delete_db',?, 'queued', JSON_OBJECT('action','delete_db'))")
          ->execute([$sid]);
      flash_set('ok', 'Zařazeno: smazat DB');
    }
  } catch (Throwable $e) {
    flash_set('err', t('common.error_with_msg', ['msg' => $e->getMessage()]));
  }

  header('Location:/db.php'.($id?('?id='.$id):''));
  exit;
}

$st = $pdo->prepare("SELECT * FROM sites WHERE user_id=? ORDER BY id DESC");
$st->execute([(int)$u['id']]);
$all = $st->fetchAll();
$sites = $id ? array_values(array_filter($all, fn($r) => (int)$r['id'] === $id)) : $all;

render($pdo, t('sites.col.db'), function() use ($sites, $id, $all) { ?>
  <div class="card">
    <h2><?php te('sites.col.db'); ?></h2>
    <small>Správa databází je tady zvlášť – web provisioning DB nevytváří.</small>
  </div>

  <div class="card">
    <!-- GET jen na výběr domény (žádné hidden id, ať se neposílá 2×) -->
    <form method="get" class="row" style="margin:0; gap:10px; flex-wrap:wrap; align-items:flex-end;">
      <div style="min-width:260px;">
        <label><?php te('sites.col.domain'); ?></label>
        <select name="id" onchange="this.form.submit()">
          <option value=""><?php echo h(t('common.list')); ?></option>
          <?php foreach($all as $s): ?>
            <option value="<?=h($s['id'])?>" <?=((int)$id === (int)$s['id']) ? 'selected' : ''?>><?=h($s['domain'])?> (ID <?=h($s['id'])?>)</option>
          <?php endforeach; ?>
        </select>
      </div>
      <div>
        <button class="btn2" type="submit"><?php echo h(t('common.open', [], 'Otevřít')); ?></button>
      </div>
    </form>

    <?php if ($id): ?>
      <div style="margin-top:10px">
        <form method="post" class="row" style="margin:0; gap:10px; flex-wrap:wrap; align-items:center;">
          <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
          <input type="hidden" name="id" value="<?=h($id)?>">

          <button class="btn2" name="ensure_db" value="1" onclick="return confirm('Vytvořit databázi (DB + uživatel + heslo) pro vybranou doménu?');">
            Vytvořit DB
          </button>

          <button class="btn2" name="reset_db_pass" value="1" onclick="return confirm(<?=json_encode(t('sites.confirm.reset_db_pass'))?>);">
            <?php te('sites.action.reset_db_pass'); ?>
          </button>

          <button class="btn2" name="delete_db" value="1" onclick="return confirm('Smazat databázi (DROP DB + uživatel) pro vybranou doménu?');">
            Smazat DB
          </button>
        </form>
      </div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h3><?php te('common.list'); ?></h3>
    <div class="table-scroll">
      <table>
        <tr>
          <th><?php te('sites.col.domain'); ?></th>
          <th><?php te('sites.col.db'); ?></th>
          <th><?php te('common.actions'); ?></th>
        </tr>
        <?php foreach($sites as $s): ?>
          <tr>
            <td><?=h($s['domain'])?><br><small>ID: <?=h($s['id'])?></small></td>
            <td>
              <small><?php te('sites.db.name'); ?>:</small> <?=h($s['db_name'] ?: '-')?> <br>
              <small><?php te('sites.db.user'); ?>:</small> <?=h($s['db_user'] ?: '-')?> <br>
              <?php if ($s['db_pass']): ?>
                <small><?php te('sites.db.pass'); ?>:</small> <code><?=h($s['db_pass'])?></code>
              <?php endif; ?>
            </td>
            <td>
              <form method="post" style="margin:0; display:grid; gap:6px;">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="id" value="<?=h($s['id'])?>">

                <a class="btn2" href="/site.php?id=<?=h($s['id'])?>" style="text-decoration:none;display:inline-block;text-align:center"><?php te('common.settings'); ?></a>

                <button class="btn2" name="ensure_db" value="1" onclick="return confirm('Vygenerovat databázi (DB + uživatel + heslo) pro tento web?');">Vygenerovat DB</button>

                <button class="btn2" name="reset_db_pass" value="1" onclick="return confirm(<?=json_encode(t('sites.confirm.reset_db_pass'))?>);">
                  <?php te('sites.action.reset_db_pass'); ?>
                </button>

                <button class="btn2" name="delete_db" value="1" onclick="return confirm('Smazat databázi (DROP DB + uživatel) pro tento web?');">
                  Smazat DB
                </button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </div>
<?php });

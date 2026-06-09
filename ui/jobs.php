<?php require __DIR__.'/_boot.php'; require __DIR__.'/_view.php'; require_login();

function jobs_status_label(string $status): string {
  return t('status.' . $status, [], $status);
}

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();
  if (isset($_POST['cancel'])) {
    $id=(int)($_POST['id']??0);
    $pdo->prepare("UPDATE jobs SET status='cancelled', updated_at=NOW(), error='cancelled_by_user' WHERE id=? AND status IN('queued','running')")
        ->execute([$id]);
    flash_set('ok', t('jobs.flash.cancelled', ['id'=>$id], 'Úloha #{id} byla zrušena.'));
    header("Location:/jobs.php"); exit;
  }
}

$jobs=$pdo->query("SELECT * FROM jobs ORDER BY id DESC LIMIT 200")->fetchAll();

render($pdo, t('page.jobs.title', [], 'Úlohy'), function() use($jobs){ ?>
  <div class="card">
    <h2><?php te('page.jobs.heading', [], 'Úlohy'); ?></h2>
    <small><?php te('jobs.help', [], 'Fronta úloh zpracovávaná Python provisionerem.'); ?></small>
  </div>

  <div class="card">
<div class="table-scroll">
    <table>
      <tr>
        <th><?php te('common.id', [], 'ID'); ?></th>
        <th><?php te('jobs.col.type', [], 'Typ'); ?></th>
        <th><?php te('jobs.col.status', [], 'Stav'); ?></th>
        <th><?php te('jobs.col.ref', [], 'Ref'); ?></th>
        <th><?php te('jobs.col.updated', [], 'Aktualizováno'); ?></th>
        <th><?php te('jobs.col.log', [], 'Log'); ?></th>
        <th><?php te('common.actions', [], 'Akce'); ?></th>
      </tr>
      <?php foreach($jobs as $j): ?>
      <tr>
        <td><?=h($j['id'])?></td>
        <td><?=h($j['type'])?></td>
        <td><span class="pill <?= $j['status']==='done'?'ok':($j['status']==='error'?'err':'run') ?>"><?=h(jobs_status_label((string)$j['status']))?></span></td>
        <td><?=h($j['ref_id'])?></td>
        <td><?=h($j['updated_at'] ?? '')?></td>
        <td>
          <?php if($j['error']): ?><small><?=h($j['error'])?></small><?php endif; ?>
          <?php if($j['log']): ?><details><summary><?php te('jobs.log', [], 'Zobrazit log'); ?></summary><pre><?=h($j['log'])?></pre></details><?php endif; ?>
        </td>
        <td>
          <?php if(in_array($j['status'],['queued','running'])): ?>
            <form method="post" style="margin:0">
              <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
              <input type="hidden" name="id" value="<?=h($j['id'])?>">
              <button class="btn-danger" name="cancel" value="1"><?php te('common.cancel', [], 'Zrušit'); ?></button>
            </form>
          <?php endif; ?>
        </td>
      </tr>
      <?php endforeach; ?>
      <?php if(!$jobs): ?>
        <tr><td colspan="7"><small><?php te('jobs.empty', [], 'Žádné úlohy.'); ?></small></td></tr>
      <?php endif; ?>
    </table>
  </div>
</div>
<?php });

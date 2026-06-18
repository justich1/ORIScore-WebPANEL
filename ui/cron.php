<?php
declare(strict_types=1);
require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

$sites = $pdo->query("SELECT id, domain, root_path FROM sites ORDER BY domain")->fetchAll(PDO::FETCH_ASSOC);
$siteId = (int)($_GET['site_id'] ?? ($_POST['site_id'] ?? 0));
$selected = null; foreach($sites as $s){ if((int)$s['id']===$siteId){ $selected=$s; break; } }

function cron_status_label(string $status): string {
  return t('common.status.' . $status, [], $status);
}

function cron_schedule_from_post(): string {
  $mode = (string)($_POST['mode'] ?? 'advanced');
  if ($mode === 'every') {
    $n = max(1, min(1440, (int)($_POST['every_minutes'] ?? 5)));
    return '*/'.$n.' * * * *';
  }
  if ($mode === 'daily') {
    $time = (string)($_POST['daily_time'] ?? '02:00');
    if(!preg_match('~^(\d{1,2}):(\d{2})$~',$time,$m)) throw new RuntimeException(t('cron.err.invalid_daily_time', [], 'Neplatný denní čas.'));
    $h=max(0,min(23,(int)$m[1])); $min=max(0,min(59,(int)$m[2]));
    return "$min $h * * *";
  }
  if ($mode === 'weekly') {
    $dow = max(0,min(7,(int)($_POST['weekly_day'] ?? 1)));
    $time = (string)($_POST['weekly_time'] ?? '02:00');
    if(!preg_match('~^(\d{1,2}):(\d{2})$~',$time,$m)) throw new RuntimeException(t('cron.err.invalid_weekly_time', [], 'Neplatný týdenní čas.'));
    $h=max(0,min(23,(int)$m[1])); $min=max(0,min(59,(int)$m[2]));
    return "$min $h * * $dow";
  }
  if ($mode === 'monthly') {
    $day = max(1,min(28,(int)($_POST['monthly_day'] ?? 1)));
    $time = (string)($_POST['monthly_time'] ?? '02:00');
    if(!preg_match('~^(\d{1,2}):(\d{2})$~',$time,$m)) throw new RuntimeException(t('cron.err.invalid_monthly_time', [], 'Neplatný měsíční čas.'));
    $h=max(0,min(23,(int)$m[1])); $min=max(0,min(59,(int)$m[2]));
    return "$min $h $day * *";
  }
  $expr = trim((string)($_POST['schedule'] ?? ''));
  if(!preg_match('~^\S+\s+\S+\s+\S+\s+\S+\s+\S+$~',$expr)) throw new RuntimeException(t('cron.err.expression_5_fields', [], 'Cron výraz musí mít 5 polí.'));
  return $expr;
}

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_check();
  try{
    if(isset($_POST['save_job'])){
      if(!$selected) throw new RuntimeException(t('cron.err.select_site', [], 'Vyber web.'));
      $cid=(int)($_POST['cron_id'] ?? 0);
      $name=trim((string)($_POST['name'] ?? t('cron.default.name', [], 'Cron')));
      $cmd=trim((string)($_POST['command'] ?? ''));
      if($cmd==='') throw new RuntimeException(t('cron.err.command_required', [], 'Příkaz nesmí být prázdný.'));
      if(strlen($cmd)>2000) throw new RuntimeException(t('cron.err.command_too_long', [], 'Příkaz je moc dlouhý.'));
      $schedule=cron_schedule_from_post();
      $enabled=isset($_POST['enabled']) ? 1 : 0;
      $runAs=trim((string)($_POST['run_as'] ?? 'www-data')) ?: 'www-data';
      if(!preg_match('~^[A-Za-z0-9_.-]+$~',$runAs)) throw new RuntimeException(t('cron.err.invalid_linux_user', [], 'Neplatný Linux user.'));
      if($cid>0){
        $pdo->prepare("UPDATE cron_jobs SET name=?, schedule=?, command=?, run_as=?, enabled=?, updated_at=NOW() WHERE id=? AND site_id=?")
            ->execute([$name,$schedule,$cmd,$runAs,$enabled,$cid,$siteId]);
      } else {
        $pdo->prepare("INSERT INTO cron_jobs(site_id,name,schedule,command,run_as,enabled,updated_at) VALUES(?,?,?,?,?,?,NOW())")
            ->execute([$siteId,$name,$schedule,$cmd,$runAs,$enabled]);
      }
      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('cron_apply',?, 'queued', JSON_OBJECT('action','apply'))")->execute([$siteId]);
      flash_set('ok', $cid>0 ? t('cron.flash.updated_queued', [], 'Cron upraven a konfigurace bude přegenerována.') : t('cron.flash.saved_queued', [], 'Cron uložen a zařazen do fronty.'));
    }
    if(isset($_POST['delete_job'])){
      $cid=(int)($_POST['cron_id'] ?? 0);
      $pdo->prepare("DELETE FROM cron_jobs WHERE id=? AND site_id=?")->execute([$cid,$siteId]);
      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('cron_apply',?, 'queued', JSON_OBJECT('action','apply'))")->execute([$siteId]);
      flash_set('ok', t('cron.flash.deleted_queued', [], 'Cron smazán a konfigurace bude přegenerována.'));
    }
    if(isset($_POST['run_now'])){
      $cid=(int)($_POST['cron_id'] ?? 0);
      $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES('cron_run',?, 'queued', JSON_OBJECT('cron_id',?))")->execute([$cid,$cid]);
      flash_set('ok', t('cron.flash.run_now_queued', [], 'Ruční spuštění zařazeno do fronty.'));
    }
  } catch(Throwable $e){ flash_set('err',$e->getMessage()); }
  header('Location: /cron.php?site_id='.$siteId); exit;
}

$rows=[];
$editId=(int)($_GET['edit_id'] ?? 0);
$editRow=null;
if($selected){
  $st=$pdo->prepare("SELECT * FROM cron_jobs WHERE site_id=? ORDER BY id DESC"); $st->execute([$siteId]); $rows=$st->fetchAll(PDO::FETCH_ASSOC);
  if($editId>0){
    $st=$pdo->prepare("SELECT * FROM cron_jobs WHERE id=? AND site_id=? LIMIT 1"); $st->execute([$editId,$siteId]); $editRow=$st->fetch(PDO::FETCH_ASSOC) ?: null;
  }
}
$last=$pdo->query("SELECT * FROM jobs WHERE type IN ('cron_apply','cron_run') ORDER BY id DESC LIMIT 1")->fetch();

render($pdo, t('page.cron.title', [], 'Cron'), function() use ($sites,$siteId,$selected,$rows,$last,$editRow){ ?>
  <style>.rowgrid{display:grid;grid-template-columns:1fr 1fr 2fr auto;gap:10px;align-items:end}.rowgrid input,.rowgrid select{width:100%}.cron-actions{display:grid;gap:6px;margin:0}.cron-actions .btn2,.cron-actions .btn-danger{width:100%;box-sizing:border-box;text-align:center}@media(max-width:900px){.rowgrid{grid-template-columns:1fr}}</style>
  <div class="card">
    <h2><?=h(t('cron.heading', [], 'Cron pro web'))?></h2>
    <small><?=h(t('cron.intro', [], 'Cron zapisuje Python provisioner do /etc/cron.d/oris-sites. Samotné běhy prochází přes Python runner, který ukládá poslední výstup a exit code.'))?></small>
    <?php if($last): ?>
      <br><small><?=h(t('cron.last_job', ['id' => $last['id']], 'Poslední job #{id}:'))?> <span class="pill <?= $last['status']==='done'?'ok':($last['status']==='error'?'err':'run') ?>"><?=h(cron_status_label((string)$last['status']))?></span></small>
    <?php endif; ?>
  </div>
  <div class="card">
    <form method="get" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
      <label><?=h(t('common.website', [], 'Web'))?><br><select name="site_id"><option value="0"><?=h(t('common.select_placeholder', [], '— vyber —'))?></option><?php foreach($sites as $s): ?><option value="<?=h($s['id'])?>" <?=((int)$s['id']===$siteId?'selected':'')?>><?=h($s['domain'])?></option><?php endforeach; ?></select></label>
      <button class="btn" type="submit"><?=h(t('common.load', [], 'Načíst'))?></button>
    </form>
    <?php if($selected): ?><small><?=h(t('common.root', [], 'Kořen'))?>: <code><?=h($selected['root_path'])?></code></small><?php endif; ?>
  </div>
  <?php if($selected): ?>
  <div class="card" id="cron-form">
    <h3><?=h($editRow ? t('cron.edit.heading', [], 'Upravit cron') : t('cron.new.heading', [], 'Nový cron'))?></h3>
    <?php if($editRow): ?><small><?=h(t('cron.edit.intro', [], 'Upravuješ existující úlohu. Po uložení se systémový cron přegeneruje.'))?></small><?php endif; ?>
    <form method="post" style="display:grid;gap:12px">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="site_id" value="<?=h($siteId)?>">
      <?php if($editRow): ?><input type="hidden" name="cron_id" value="<?=h($editRow['id'])?>"><?php endif; ?>
      <div class="grid2">
        <label><?=h(t('common.name', [], 'Název'))?><br><input name="name" value="<?=h($editRow['name'] ?? t('cron.default.task_name', [], 'Úloha'))?>"></label>
        <label><?=h(t('cron.form.linux_user', [], 'Linux uživatel'))?><br><input name="run_as" value="<?=h($editRow['run_as'] ?? 'www-data')?>"></label>
      </div>
      <div class="grid2">
        <label><?=h(t('cron.form.mode', [], 'Režim'))?><br><select name="mode">
          <option value="every" <?=(!$editRow?'selected':'')?>><?=h(t('cron.mode.every', [], 'Každých N minut'))?></option>
          <option value="daily"><?=h(t('cron.mode.daily', [], 'Denně'))?></option>
          <option value="weekly"><?=h(t('cron.mode.weekly', [], 'Týdně'))?></option>
          <option value="monthly"><?=h(t('cron.mode.monthly', [], 'Měsíčně'))?></option>
          <option value="advanced" <?=($editRow?'selected':'')?>><?=h(t('cron.mode.advanced', [], 'Pokročilý cron výraz'))?></option>
        </select></label>
        <label><?=h(t('cron.form.advanced_expression', [], 'Pokročilý výraz'))?><br><input name="schedule" placeholder="*/5 * * * *" value="<?=h($editRow['schedule'] ?? '')?>"></label>
        <label><?=h(t('cron.form.every_minutes', [], 'Každých minut'))?><br><input name="every_minutes" value="5"></label>
        <label><?=h(t('cron.form.daily_at', [], 'Denně v'))?><br><input name="daily_time" value="02:00"></label>
        <label><?=h(t('cron.form.weekly_day', [], 'Týdenní den 0-7'))?><br><input name="weekly_day" value="1"></label>
        <label><?=h(t('cron.form.weekly_at', [], 'Týdně v'))?><br><input name="weekly_time" value="02:00"></label>
        <label><?=h(t('cron.form.monthly_day', [], 'Den v měsíci 1-28'))?><br><input name="monthly_day" value="1"></label>
        <label><?=h(t('cron.form.monthly_at', [], 'Měsíčně v'))?><br><input name="monthly_time" value="02:00"></label>
      </div>
      <label><?=h(t('cron.form.command', [], 'Příkaz'))?><br><input name="command" placeholder="php public/index.php cron/run" value="<?=h($editRow['command'] ?? '')?>" required></label>
      <label><input type="checkbox" name="enabled" value="1" <?=(!$editRow || (int)$editRow['enabled']===1 ? 'checked' : '')?>> <?=h(t('common.enable', [], 'Povolit'))?></label>
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        <button class="btn" name="save_job" value="1"><?=h($editRow ? t('cron.action.update', [], 'Uložit změny') : t('cron.action.save', [], 'Uložit cron'))?></button>
        <?php if($editRow): ?><a class="btn2" href="/cron.php?site_id=<?=h($siteId)?>"><?=h(t('common.cancel', [], 'Zrušit'))?></a><?php endif; ?>
      </div>
    </form>
  </div>
  <div class="card"><h3><?=h(t('cron.jobs.heading', [], 'Úlohy'))?></h3>
    <?php if(!$rows): ?><small><?=h(t('cron.empty', [], 'Žádné cron úlohy.'))?></small><?php else: ?>
    <div class="table-scroll"><table><tr>
      <th><?=h(t('common.name', [], 'Název'))?></th>
      <th><?=h(t('cron.table.time', [], 'Čas'))?></th>
      <th><?=h(t('cron.table.command', [], 'Příkaz'))?></th>
      <th><?=h(t('common.status', [], 'Stav'))?></th>
      <th><?=h(t('cron.table.last_run', [], 'Poslední běh'))?></th>
      <th><?=h(t('common.actions', [], 'Akce'))?></th>
    </tr>
    <?php foreach($rows as $r): ?><tr>
      <td><?=h($r['name'])?></td><td><code><?=h($r['schedule'])?></code><br><small><?=h($r['run_as'] ?: 'www-data')?></small></td><td><code><?=h($r['command'])?></code></td>
      <td><span class="pill <?=((int)$r['enabled']?'ok':'run')?>"><?=((int)$r['enabled'] ? h(t('common.status.enabled', [], 'povoleno')) : h(t('common.status.disabled', [], 'vypnuto')))?></span></td>
      <td><small><?=h($r['last_run_at'] ?: '—')?> / <?=h(t('cron.table.exit_code', [], 'návratový kód'))?> <?=h($r['last_exit_code'] ?? '—')?></small><?php if($r['last_output']): ?><pre><?=h(mb_substr((string)$r['last_output'],0,1000))?></pre><?php endif; ?></td>
      <td><div class="cron-actions"><a class="btn2" href="/cron.php?site_id=<?=h($siteId)?>&edit_id=<?=h($r['id'])?>#cron-form"><?=h(t('common.edit', [], 'Upravit'))?></a><form method="post" class="cron-actions"><input type="hidden" name="_csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="site_id" value="<?=h($siteId)?>"><input type="hidden" name="cron_id" value="<?=h($r['id'])?>"><button class="btn2" name="run_now" value="1"><?=h(t('common.run', [], 'Spustit'))?></button><button class="btn-danger" name="delete_job" value="1" onclick="return confirm(<?=h(json_encode(t('cron.confirm.delete', [], 'Smazat cron?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES))?>)"><?=h(t('common.delete', [], 'Smazat'))?></button></form></div></td>
    </tr><?php endforeach; ?></table></div><?php endif; ?>
  </div>
  <?php endif; ?>
<?php });

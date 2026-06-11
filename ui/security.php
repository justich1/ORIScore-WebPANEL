<?php
require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

function enqueue_job(PDO $pdo, string $type, int $refId=0, array $payload=[]): void {
  $st=$pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES(?,?, 'queued', ?)");
  $st->execute([$type,$refId,json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}
function shx(string $cmd): string {
  $out=[]; $rc=0; exec($cmd.' 2>&1', $out, $rc); return trim(implode("\n", $out));
}
function svc_state(string $name): string {
  $s=shx('sudo /usr/bin/systemctl is-active '.escapeshellarg($name));
  return $s ?: 'unknown';
}
function pill_class(string $state): string {
  return $state==='active' || $state==='enabled' ? 'ok' : ($state==='inactive' || $state==='disabled' ? 'run' : 'err');
}
function parse_jails(string $status): array {
  if (preg_match('~Jail list:\s*(.+)$~m', $status, $m)) {
    $j = array_map('trim', explode(',', $m[1]));
    return array_values(array_filter($j, fn($x)=>$x!==''));
  }
  return [];
}
function first_nonempty_setting(PDO $pdo, string $k, string $def=''): string { return setting($pdo, $k, $def) ?? $def; }

$settingsDefaults = [
  'security_nginx_rate_enabled' => '0',
  'security_nginx_rate' => '10r/s',
  'security_nginx_burst' => '30',
  'security_nginx_conn' => '30',
  'security_phpmyadmin_rate_enabled' => '1',
  'security_phpmyadmin_allowlist_enabled' => '0',
  'security_phpmyadmin_allowlist' => '',
  'security_admin_allowlist_enabled' => '0',
  'security_admin_allowlist' => '',
  'security_fail2ban_phpmyadmin_enabled' => '1',
  'security_fail2ban_badbots_enabled' => '1',
  'security_fail2ban_bantime' => '3600',
  'security_fail2ban_findtime' => '600',
  'security_fail2ban_maxretry' => '5',
  'security_fail2ban_recidive_enabled' => '1',
  'security_fail2ban_oris_perm_enabled' => '1',
  'security_fail2ban_recidive_maxretry' => '5',
  'security_fail2ban_recidive_findtime' => '7d',
  'security_fail2ban_recidive_bantime' => '-1',
  'security_fail2ban_perm_bantime' => '-1',
];

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();
  $action = (string)($_POST['action'] ?? '');

  if ($action === 'security_save') {
    foreach ($settingsDefaults as $k=>$def) {
      if (in_array($k, ['security_nginx_rate_enabled','security_phpmyadmin_rate_enabled','security_phpmyadmin_allowlist_enabled','security_admin_allowlist_enabled','security_fail2ban_phpmyadmin_enabled','security_fail2ban_badbots_enabled','security_fail2ban_recidive_enabled','security_fail2ban_oris_perm_enabled'], true)) {
        $v = !empty($_POST[$k]) ? '1' : '0';
      } else {
        $v = trim((string)($_POST[$k] ?? $def));
      }
      set_setting($pdo, $k, $v);
    }
    enqueue_job($pdo, 'security_apply');
    flash_set('ok', t('security.flash.saved_queued', [], 'Security Center nastavení uloženo a aplikace zařazena do fronty.'));
    header('Location: /jobs.php'); exit;
  }

  if ($action === 'ufw_enable') { enqueue_job($pdo, 'ufw_enable'); flash_set('ok', t('security.flash.ufw_enable_queued', [], 'Zapnutí UFW zařazeno.')); header('Location:/jobs.php'); exit; }
  if ($action === 'ufw_disable') { enqueue_job($pdo, 'ufw_disable'); flash_set('ok', t('security.flash.ufw_disable_queued', [], 'Vypnutí UFW zařazeno.')); header('Location:/jobs.php'); exit; }
  if ($action === 'ufw_allow') {
    enqueue_job($pdo, 'ufw_allow', 0, [
      'port'=>trim((string)($_POST['port'] ?? '')),
      'proto'=>trim((string)($_POST['proto'] ?? 'tcp')),
      'source'=>trim((string)($_POST['source'] ?? '')),
    ]);
    flash_set('ok', t('security.flash.ufw_allow_queued', [], 'Přidání UFW pravidla zařazeno.')); header('Location:/jobs.php'); exit;
  }
  if ($action === 'ufw_delete') {
    enqueue_job($pdo, 'ufw_delete', 0, ['num'=>(int)($_POST['num'] ?? 0)]);
    flash_set('ok', t('security.flash.ufw_delete_queued', [], 'Smazání UFW pravidla zařazeno.')); header('Location:/jobs.php'); exit;
  }

  if ($action === 'fail2ban_reload') { enqueue_job($pdo, 'fail2ban_reload'); flash_set('ok', t('security.flash.fail2ban_reload_queued', [], 'Restart Fail2ban zařazen.')); header('Location:/jobs.php'); exit; }
  if ($action === 'fail2ban_ban_ip' || $action === 'fail2ban_unban_ip') {
    enqueue_job($pdo, $action, 0, [
      'jail'=>trim((string)($_POST['jail'] ?? 'sshd')),
      'ip'=>trim((string)($_POST['ip'] ?? '')),
    ]);
    flash_set('ok', $action==='fail2ban_ban_ip' ? t('security.flash.ban_ip_queued', [], 'Ban IP zařazen.') : t('security.flash.unban_ip_queued', [], 'Unban IP zařazen.')); header('Location:/jobs.php'); exit;
  }
  if ($action === 'fail2ban_perm_ban_ip') {
    enqueue_job($pdo, 'fail2ban_ban_ip', 0, [
      'jail'=>'oris-perm',
      'ip'=>trim((string)($_POST['ip'] ?? '')),
    ]);
    flash_set('ok', t('security.flash.perm_ban_queued', [], 'Permanentní blokace IP zařazena.')); header('Location:/jobs.php'); exit;
  }
}

$vals=[]; foreach($settingsDefaults as $k=>$def) $vals[$k]=first_nonempty_setting($pdo,$k,$def);
$services = ['nginx','mariadb','php8.2-fpm','vsftpd','fail2ban','ufw','oris-provisioner','oris-stats-worker'];
$svcStates=[]; foreach($services as $s) $svcStates[$s]=svc_state($s);
$ufwStatus = shx('sudo /usr/sbin/ufw status numbered');
$f2bStatus = shx('sudo /usr/bin/fail2ban-client status');
$jails = parse_jails($f2bStatus);
$jailDetails=[];
foreach($jails as $j) $jailDetails[$j] = shx('sudo /usr/bin/fail2ban-client status '.escapeshellarg($j));
$recentAuth = shx('sudo /usr/bin/journalctl -u ssh -u fail2ban -n 40 --no-pager');
$nginxErr = shx('sudo /usr/bin/tail -n 40 /var/log/nginx/error.log');

render($pdo, t('page.security.title', [], 'Centrum zabezpečení'), function() use($vals,$svcStates,$ufwStatus,$f2bStatus,$jails,$jailDetails,$recentAuth,$nginxErr){ ?>
  <div class="card">
    <h2><?=h(t('page.security.title', [], 'Centrum zabezpečení'))?></h2>
    <small><?=h(t('security.intro', [], 'UFW, Fail2ban, Nginx limity, ochrana phpMyAdminu a přístup k administraci. Změny se aplikují přes Python provisioner.'))?></small>
  </div>

  <div class="card">
    <h3><?=h(t('security.services.heading', [], 'Bezpečnostní přehled služeb'))?></h3>
    <div class="table-scroll"><table>
      <tr><th><?=h(t('common.service', [], 'Služba'))?></th><th><?=h(t('common.status', [], 'Stav'))?></th></tr>
      <?php foreach($svcStates as $name=>$state): ?>
        <tr><td><?=h($name)?></td><td><span class="pill <?=h(pill_class($state))?>"><?=h(t('status.'.$state, [], $state))?></span></td></tr>
      <?php endforeach; ?>
    </table></div>
  </div>

  <div class="card">
    <h3><?=h(t('security.protection.heading', [], 'Nastavení ochrany'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="action" value="security_save">

      <h4><?=h(t('security.nginx_rate.heading', [], 'Nginx rate-limit'))?></h4>
      <div class="row">
        <div><label><input type="checkbox" name="security_nginx_rate_enabled" value="1" <?= $vals['security_nginx_rate_enabled']==='1'?'checked':'' ?>> <?=h(t('security.nginx_rate.enable_global', [], 'Zapnout globální rate-limit ve vhostech'))?></label><small><?=h(t('security.nginx_rate.help', [], 'Vhodné proti běžným HTTP floodům. Velký DDoS musí filtrovat provider/CDN.'))?></small></div>
        <div><label><?=h(t('security.field.rate', [], 'Rate'))?></label><input name="security_nginx_rate" value="<?=h($vals['security_nginx_rate'])?>" placeholder="10r/s"><small><?=h(t('security.hint.rate', [], 'Např. 10r/s nebo 300r/m.'))?></small></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><?=h(t('security.field.burst', [], 'Burst'))?></label><input name="security_nginx_burst" value="<?=h($vals['security_nginx_burst'])?>"></div>
        <div><label><?=h(t('security.field.max_connections_per_ip', [], 'Max spojení z IP'))?></label><input name="security_nginx_conn" value="<?=h($vals['security_nginx_conn'])?>"></div>
      </div>

      <h4 style="margin-top:18px"><?=h(t('security.phpmyadmin.heading', [], 'phpMyAdmin'))?></h4>
      <div class="row">
        <div><label><input type="checkbox" name="security_phpmyadmin_rate_enabled" value="1" <?= $vals['security_phpmyadmin_rate_enabled']==='1'?'checked':'' ?>> <?=h(t('security.phpmyadmin.rate_limit', [], 'Rate-limit pro /phpmyadmin/'))?></label></div>
        <div><label><input type="checkbox" name="security_phpmyadmin_allowlist_enabled" value="1" <?= $vals['security_phpmyadmin_allowlist_enabled']==='1'?'checked':'' ?>> <?=h(t('security.phpmyadmin.allowlist_only', [], 'Povolit phpMyAdmin jen z IP allowlistu'))?></label></div>
      </div>
      <label><?=h(t('security.field.phpmyadmin_allowlist', [], 'phpMyAdmin allowlist IP/CIDR'))?></label>
      <textarea name="security_phpmyadmin_allowlist" rows="3" placeholder="1.2.3.4&#10;10.0.0.0/8"><?=h($vals['security_phpmyadmin_allowlist'])?></textarea>

      <h4 style="margin-top:18px"><?=h(t('security.admin.heading', [], 'Administrace panelu'))?></h4>
      <div class="row">
        <div><label><input type="checkbox" name="security_admin_allowlist_enabled" value="1" <?= $vals['security_admin_allowlist_enabled']==='1'?'checked':'' ?>> <?=h(t('security.admin.allowlist_only', [], 'Povolit administraci jen z IP allowlistu'))?></label><small><?=h(t('security.admin.allowlist_warning', [], 'Nezapínej, dokud do seznamu nedáš svoji veřejnou IP nebo VPN rozsah.'))?></small></div>
        <div><label><?=h(t('security.field.admin_allowlist', [], 'Admin allowlist IP/CIDR'))?></label><textarea name="security_admin_allowlist" rows="3" placeholder="1.2.3.4&#10;10.42.0.0/24"><?=h($vals['security_admin_allowlist'])?></textarea></div>
      </div>

      <h4 style="margin-top:18px"><?=h(t('security.fail2ban.heading', [], 'Fail2ban'))?></h4>
      <div class="row">
        <div><label><input type="checkbox" name="security_fail2ban_phpmyadmin_enabled" value="1" <?= $vals['security_fail2ban_phpmyadmin_enabled']==='1'?'checked':'' ?>> <?=h(t('security.fail2ban.jail_phpmyadmin', [], 'Jail phpMyAdmin'))?></label></div>
        <div><label><input type="checkbox" name="security_fail2ban_badbots_enabled" value="1" <?= $vals['security_fail2ban_badbots_enabled']==='1'?'checked':'' ?>> <?=h(t('security.fail2ban.jail_badbots', [], 'Jail Nginx badbots/scannery'))?></label></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><?=h(t('security.field.bantime_seconds', [], 'Bantime sekund'))?></label><input name="security_fail2ban_bantime" value="<?=h($vals['security_fail2ban_bantime'])?>"></div>
        <div><label><?=h(t('security.field.findtime_seconds', [], 'Findtime sekund'))?></label><input name="security_fail2ban_findtime" value="<?=h($vals['security_fail2ban_findtime'])?>"></div>
        <div><label><?=h(t('security.field.max_retry', [], 'Max retry'))?></label><input name="security_fail2ban_maxretry" value="<?=h($vals['security_fail2ban_maxretry'])?>"></div>
      </div>

      <h4 style="margin-top:18px"><?=h(t('security.permanent.heading', [], 'Permanentní blokace / recidive'))?></h4>
      <div class="row">
        <div><label><input type="checkbox" name="security_fail2ban_oris_perm_enabled" value="1" <?= $vals['security_fail2ban_oris_perm_enabled']==='1'?'checked':'' ?>> <?=h(t('security.permanent.oris_perm_jail', [], 'Jail oris-perm pro ruční permanentní blokace'))?></label></div>
        <div><label><input type="checkbox" name="security_fail2ban_recidive_enabled" value="1" <?= $vals['security_fail2ban_recidive_enabled']==='1'?'checked':'' ?>> <?=h(t('security.permanent.recidive_auto', [], 'Recidive automatická eskalace'))?></label></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><?=h(t('security.field.recidive_max_bans', [], 'Recidive max banů'))?></label><input name="security_fail2ban_recidive_maxretry" value="<?=h($vals['security_fail2ban_recidive_maxretry'])?>"><small><?=h(t('security.hint.default_5_bans', [], 'Výchozí 5 banů.'))?></small></div>
        <div><label><?=h(t('security.field.recidive_findtime', [], 'Recidive období'))?></label><input name="security_fail2ban_recidive_findtime" value="<?=h($vals['security_fail2ban_recidive_findtime'])?>"><small><?=h(t('security.hint.duration_examples', [], 'Např. 7d, 24h nebo 604800.'))?></small></div>
        <div><label><?=h(t('security.field.recidive_bantime', [], 'Recidive bantime'))?></label><input name="security_fail2ban_recidive_bantime" value="<?=h($vals['security_fail2ban_recidive_bantime'])?>"><small><?=h(t('security.hint.minus_one_permanent', [], '-1 = permanentně.'))?></small></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><?=h(t('security.field.oris_perm_bantime', [], 'oris-perm bantime'))?></label><input name="security_fail2ban_perm_bantime" value="<?=h($vals['security_fail2ban_perm_bantime'])?>"><small><?=h(t('security.hint.minus_one_permanent', [], '-1 = permanentně.'))?></small></div>
      </div>
      <p style="margin-top:12px"><button class="btn"><?=h(t('security.button.save_apply', [], 'Uložit a aplikovat zabezpečení'))?></button></p>
    </form>
  </div>

  <div class="card">
    <h3><?=h(t('security.ufw.heading', [], 'Firewall / UFW'))?></h3>
    <form method="post" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <button class="btn" name="action" value="ufw_enable"><?=h(t('security.ufw.enable', [], 'Zapnout UFW'))?></button>
      <button class="btn-danger" name="action" value="ufw_disable" onclick="return confirm(<?=json_encode(t('security.confirm.disable_firewall', [], 'Vypnout firewall?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('security.ufw.disable', [], 'Vypnout UFW'))?></button>
    </form>
    <form method="post" class="row">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="action" value="ufw_allow">
      <div><label><?=h(t('security.field.port_or_range', [], 'Port nebo rozsah'))?></label><input name="port" placeholder="443 nebo 40000:40100" required></div>
      <div><label><?=h(t('security.field.protocol', [], 'Protokol'))?></label><select name="proto"><option>tcp</option><option>udp</option></select></div>
      <div><label><?=h(t('security.field.source_ip_optional', [], 'Zdroj IP/CIDR volitelně'))?></label><input name="source" placeholder="<?=h(t('security.placeholder.ip_example', [], 'např. 1.2.3.4'))?>"></div>
      <div style="align-self:end"><button class="btn2"><?=h(t('security.ufw.add_rule', [], 'Přidat pravidlo'))?></button></div>
    </form>
    <h4><?=h(t('security.ufw.current_rules', [], 'Aktuální pravidla'))?></h4>
    <pre style="white-space:pre-wrap;max-height:360px;overflow:auto"><?=h($ufwStatus ?: t('security.ufw.no_output', [], 'UFW bez výstupu'))?></pre>
    <form method="post" style="display:flex;gap:8px;align-items:end;flex-wrap:wrap">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="action" value="ufw_delete">
      <div><label><?=h(t('security.field.rule_number_delete', [], 'Číslo pravidla ke smazání'))?></label><input name="num" placeholder="<?=h(t('security.placeholder.rule_number', [], 'např. 3'))?>"></div>
      <button class="btn-danger" onclick="return confirm(<?=json_encode(t('security.confirm.delete_ufw_rule', [], 'Smazat UFW pravidlo?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('security.ufw.delete_rule', [], 'Smazat pravidlo'))?></button>
    </form>
  </div>

  <div class="card">
    <h3>Fail2ban</h3>
    <form method="post" style="margin-bottom:12px">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <button class="btn2" name="action" value="fail2ban_reload"><?=h(t('security.fail2ban.restart', [], 'Restartovat Fail2ban'))?></button>
    </form>
    <pre style="white-space:pre-wrap;max-height:220px;overflow:auto"><?=h($f2bStatus ?: t('security.fail2ban.no_output', [], 'Fail2ban bez výstupu'))?></pre>

    <form method="post" class="row" style="margin-top:12px">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div><label><?=h(t('security.field.permanent_ip_ban', [], 'Permanentní blokace IP'))?></label><input name="ip" placeholder="1.2.3.4"></div>
      <div style="align-self:end"><button class="btn-danger" name="action" value="fail2ban_perm_ban_ip"><?=h(t('security.fail2ban.permanent_block', [], 'Permanentně blokovat'))?></button></div>
    </form>

    <form method="post" class="row" style="margin-top:12px">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div><label><?=h(t('security.field.jail', [], 'Jail'))?></label><input name="jail" value="sshd"></div>
      <div><label><?=h(t('common.ip', [], 'IP'))?></label><input name="ip" placeholder="1.2.3.4"></div>
      <div style="align-self:end;display:flex;gap:8px"><button class="btn-danger" name="action" value="fail2ban_ban_ip"><?=h(t('security.fail2ban.ban', [], 'Ban'))?></button><button class="btn2" name="action" value="fail2ban_unban_ip"><?=h(t('security.fail2ban.unban', [], 'Unban'))?></button></div>
    </form>

    <?php foreach($jailDetails as $jail=>$detail): ?>
      <h4><?=h($jail)?></h4>
      <pre style="white-space:pre-wrap;max-height:180px;overflow:auto"><?=h($detail)?></pre>
    <?php endforeach; ?>
  </div>

  <div class="card">
    <h3><?=h(t('security.logs.heading', [], 'Poslední bezpečnostní logy'))?></h3>
    <h4><?=h(t('security.logs.ssh_fail2ban', [], 'SSH / Fail2ban'))?></h4>
    <pre style="white-space:pre-wrap;max-height:260px;overflow:auto"><?=h($recentAuth)?></pre>
    <h4><?=h(t('security.logs.nginx_error', [], 'Nginx error log'))?></h4>
    <pre style="white-space:pre-wrap;max-height:260px;overflow:auto"><?=h($nginxErr)?></pre>
  </div>
<?php });

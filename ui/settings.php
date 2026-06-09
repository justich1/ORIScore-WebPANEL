<?php
require __DIR__.'/_boot.php';
require __DIR__.'/_view.php';
require_admin();

function enqueue_job(PDO $pdo, string $type, int $refId=0, array $payload=[]): void {
  $st=$pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES(?,?, 'queued', ?)");
  $st->execute([$type,$refId,json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}

$keys = [
  'sites_base_dir' => '/var/lib/oris-core/sites',
  'web_root_bases' => "/var/lib/oris-core/sites\n/var/www/html\n/data/www",

  // Nginx stack, ne Apache
  'nginx_sites_available' => '/etc/nginx/sites-available',
  'nginx_sites_enabled' => '/etc/nginx/sites-enabled',
  'nginx_snippets_dir' => '/etc/nginx/snippets',

  'cert_mode' => 'selfsigned',
  'certbot_email' => '',
  'acme_webroot' => '/var/www/letsencrypt',

  // Administrace panelu
  'panel_access_mode' => 'ip',
  'panel_domain' => '',
  'panel_force_https' => '0',

  // Mailbox storage
  'vmail_root' => '/var/vmail',
  'vmail_user' => 'vmail',
  'vmail_group' => 'vmail',
  'dovecot_hash_scheme' => 'BLF-CRYPT',
  'roundcube_root' => '/usr/share/roundcube',

  // Python pracovní adresáře
  'upload_staging_dir' => '/var/lib/oris-core/uploads',
  'servercfg_backup_dir' => '/var/lib/oris-core/backups/servercfg',
  'mail_backup_dir' => '/var/lib/oris-core/backups/mail',
  'mail_bayes_backup_dir' => '/var/lib/oris-core/backups/rspamd',

  // Povolené kořeny pro server_config editor, 1 cesta na řádek.
  'servercfg_allowed_roots' => "/etc/nginx\n/etc/php\n/etc/phpmyadmin\n/etc/postfix\n/etc/dovecot\n/etc/rspamd\n/etc/roundcube\n/etc/fail2ban\n/etc/ufw\n/etc/vsftpd.conf\n/etc/vsftpd_user_conf\n/etc/wireguard\n/etc/sysctl.conf\n/etc/sysctl.d\n/etc/cron.d\n/etc/crontab\n/etc/hostname\n/etc/hosts",

  'hooks_dir' => '/var/www/oris-panel/extras/hooks',
];

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();
  $action = (string)($_POST['action'] ?? 'save');

  foreach($keys as $k=>$def){
    if ($k === 'panel_force_https') {
      $v = !empty($_POST[$k]) ? '1' : '0';
    } else {
      $v = trim((string)($_POST[$k] ?? $def));
    }
    if ($k === 'panel_access_mode' && !in_array($v, ['ip','ip_domain','domain'], true)) $v = 'ip';
    if ($k === 'panel_domain' && $v !== '' && !domain_valid($v)) {
      flash_set('err', t('settings.err.invalid_admin_domain', [], 'Admin doména není platná.')); header("Location:/settings.php"); exit;
    }
    set_setting($pdo, $k, $v);
  }

  if ($action === 'panel_apply') {
    enqueue_job($pdo, 'panel_apply');
    flash_set('ok', t('settings.flash.panel_apply_queued', [], 'Nastavení uloženo, přegenerování administrace zařazeno.'));
    header("Location:/jobs.php"); exit;
  }
  if ($action === 'panel_certbot_test') {
    enqueue_job($pdo, 'panel_certbot_test');
    flash_set('ok', t('settings.flash.panel_acme_test_queued', [], 'ACME test administrace zařazen.'));
    header("Location:/jobs.php"); exit;
  }
  if ($action === 'panel_certbot_issue') {
    enqueue_job($pdo, 'panel_certbot_issue');
    flash_set('ok', t('settings.flash.panel_cert_queued', [], 'Vystavení certifikátu pro administraci zařazeno.'));
    header("Location:/jobs.php"); exit;
  }
  if ($action === 'settings_apply') {
    enqueue_job($pdo, 'settings_apply');
    flash_set('ok', t('settings.flash.dirs_prepare_queued', [], 'Nastavení uloženo, příprava adresářů zařazena do fronty.'));
    header("Location:/jobs.php"); exit;
  }

  flash_set('ok', t('settings.flash.saved', [], 'Nastavení uloženo'));
  header("Location:/settings.php"); exit;
}

$vals = [];
foreach($keys as $k=>$def) $vals[$k] = setting($pdo,$k,$def);
$panelSslStatus = setting($pdo, 'panel_ssl_status', 'none') ?: 'none';
$panelSslError = setting($pdo, 'panel_ssl_last_error', '') ?: '';

render($pdo, t('page.settings.title', [], 'Nastavení'), function() use($vals,$panelSslStatus,$panelSslError){ ?>
  <div class="card"><h2><?=h(t('page.settings.title', [], 'Nastavení'))?></h2><small><?=h(t('settings.intro', [], 'Globální cesty, certifikáty, administrace a pracovní adresáře provisioneru.'))?></small></div>

  <div class="card">
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">

      <h3><?=h(t('settings.panel_admin.heading', [], 'Administrace panelu'))?></h3>
      <div class="row" style="margin-top:10px">
        <div>
          <label><?=h(t('settings.panel_access.label', [], 'Dostupnost administrace'))?></label>
          <select name="panel_access_mode">
            <option value="ip" <?= $vals['panel_access_mode']==='ip'?'selected':'' ?>><?=h(t('settings.panel_access.ip', [], 'jen přes IP / default vhost'))?></option>
            <option value="ip_domain" <?= $vals['panel_access_mode']==='ip_domain'?'selected':'' ?>><?=h(t('settings.panel_access.ip_domain', [], 'přes IP i admin doménu'))?></option>
            <option value="domain" <?= $vals['panel_access_mode']==='domain'?'selected':'' ?>><?=h(t('settings.panel_access.domain', [], 'jen přes admin doménu'))?></option>
          </select>
        </div>
        <div><label><?=h(t('settings.field.admin_domain', [], 'Admin doména'))?></label><input name="panel_domain" value="<?=h($vals['panel_domain'])?>" placeholder="admin.oris-core.cz"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><input type="checkbox" name="panel_force_https" value="1" <?= $vals['panel_force_https']==='1'?'checked':'' ?>> <?=h(t('settings.panel.force_https', [], 'Přesměrovat admin doménu na HTTPS, pokud existuje certifikát'))?></label></div>
        <div><label><?=h(t('settings.panel.https_status', [], 'Stav HTTPS administrace'))?></label><input value="<?=h($panelSslStatus)?>" readonly><?php if($panelSslError): ?><small style="color:#ff9b9b"><?=h($panelSslError)?></small><?php endif; ?></div>
      </div>
      <p style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" name="action" value="panel_apply"><?=h(t('settings.button.save_rebuild_panel', [], 'Uložit a přegenerovat administraci'))?></button>
        <button class="btn2" name="action" value="panel_certbot_test"><?=h(t('settings.button.test_acme_admin', [], 'Test ACME admin domény'))?></button>
        <button class="btn2" name="action" value="panel_certbot_issue"><?=h(t('settings.button.issue_https_admin', [], 'Vystavit HTTPS pro admin doménu'))?></button>
      </p>

      <hr style="border:0;border-top:1px solid rgba(255,255,255,.1);margin:18px 0">
      <h3><?=h(t('settings.nginx.heading', [], 'Nginx / webhosting'))?></h3>
      <div class="row">
        <div><label>nginx_sites_available</label><input name="nginx_sites_available" value="<?=h($vals['nginx_sites_available'])?>"></div>
        <div><label>nginx_sites_enabled</label><input name="nginx_sites_enabled" value="<?=h($vals['nginx_sites_enabled'])?>"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label>nginx_snippets_dir</label><input name="nginx_snippets_dir" value="<?=h($vals['nginx_snippets_dir'])?>"></div>
        <div><label>hooks_dir</label><input name="hooks_dir" value="<?=h($vals['hooks_dir'])?>"></div>
      </div>
      <div style="margin-top:10px"><label>web_root_bases</label><textarea name="web_root_bases" rows="5" style="min-height:110px;width:100%;"><?=h($vals['web_root_bases'])?></textarea></div>

      <h3 style="margin-top:18px"><?=h(t('settings.certbot.heading', [], 'Certbot / ACME'))?></h3>
      <div class="row">
        <div><label>cert_mode</label><select name="cert_mode"><option value="selfsigned" <?= $vals['cert_mode']==='selfsigned'?'selected':'' ?>>selfsigned</option><option value="letsencrypt" <?= $vals['cert_mode']==='letsencrypt'?'selected':'' ?>>letsencrypt</option></select></div>
        <div><label>certbot_email</label><input name="certbot_email" value="<?=h($vals['certbot_email'])?>" placeholder="admin@example.com"></div>
      </div>
      <div style="margin-top:10px"><label>acme_webroot</label><input name="acme_webroot" value="<?=h($vals['acme_webroot'])?>"></div>

      <h3 style="margin-top:18px"><?=h(t('settings.mail.heading', [], 'Mail / Roundcube'))?></h3>
      <div class="row">
        <div><label>vmail_root</label><input name="vmail_root" value="<?=h($vals['vmail_root'])?>"></div>
        <div><label>roundcube_root</label><input name="roundcube_root" value="<?=h($vals['roundcube_root'])?>"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label>vmail_user</label><input name="vmail_user" value="<?=h($vals['vmail_user'])?>"></div>
        <div><label>vmail_group</label><input name="vmail_group" value="<?=h($vals['vmail_group'])?>"></div>
      </div>
      <div style="margin-top:10px"><label>dovecot_hash_scheme</label><input name="dovecot_hash_scheme" value="<?=h($vals['dovecot_hash_scheme'])?>" placeholder="BLF-CRYPT"></div>

      <h3 style="margin-top:18px"><?=h(t('settings.provisioner.heading', [], 'Python provisioner / zálohy'))?></h3>
      <div class="row">
        <div><label>upload_staging_dir</label><input name="upload_staging_dir" value="<?=h($vals['upload_staging_dir'])?>"></div>
        <div><label>servercfg_backup_dir</label><input name="servercfg_backup_dir" value="<?=h($vals['servercfg_backup_dir'])?>"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label>mail_backup_dir</label><input name="mail_backup_dir" value="<?=h($vals['mail_backup_dir'])?>"></div>
        <div><label>mail_bayes_backup_dir</label><input name="mail_bayes_backup_dir" value="<?=h($vals['mail_bayes_backup_dir'])?>"></div>
      </div>
      <div style="margin-top:10px"><label>servercfg_allowed_roots</label><textarea name="servercfg_allowed_roots" rows="8" style="min-height:150px;width:100%;"><?=h($vals['servercfg_allowed_roots'])?></textarea><small><?=h(t('settings.servercfg_allowed_roots.help', [], 'Povolené cesty pro editor server konfigurace. Apache tu schválně není.'))?></small></div>

      <p style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" name="action" value="save"><?=h(t('common.save', [], 'Uložit'))?></button>
        <button class="btn2" name="action" value="settings_apply"><?=h(t('settings.button.save_prepare_dirs', [], 'Uložit + připravit adresáře přes provisioner'))?></button>
      </p>
    </form>
  </div>
<?php });

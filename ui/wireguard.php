<?php
require __DIR__.'/_boot.php';
require __DIR__.'/_view.php';
require_admin();

$keys = [
  'wg_iface' => 'wg0',
  'wg_server_address' => '10.42.0.1/24',
  'wg_listen_port' => '51820',
  'wg_endpoint' => '',
  'wg_dns' => '',
  'wg_client_allowed_ips' => '0.0.0.0/0, ::/0',
  'wg_mtu' => '',
  'wg_post_up' => '',
  'wg_post_down' => '',
  'wg_keepalive' => '25',
];

function wg_enqueue(PDO $pdo, string $type, int $refId = 0, array $payload = []): void {
  $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  $st = $pdo->prepare("INSERT INTO jobs(type,ref_id,status,payload) VALUES(?,?, 'queued', ?)");
  $st->execute([$type, $refId, $json ?: '{}']);
}

function wg_parse_ipv4_cidr(string $cidr): ?array {
  $cidr = trim($cidr);
  if (!preg_match('~^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\/(\d{1,2})$~', $cidr, $m)) return null;
  $ip = $m[1];
  $p = (int)$m[2];
  if ($p < 0 || $p > 32) return null;
  foreach (explode('.', $ip) as $o) { $oi = (int)$o; if ($oi < 0 || $oi > 255) return null; }
  return ['ip'=>$ip,'prefix'=>$p];
}

function wg_suggest_ip24(string $serverIp, array $taken): ?string {
  $parts = explode('.', $serverIp);
  if (count($parts)!==4) return null;
  $prefix = $parts[0].'.'.$parts[1].'.'.$parts[2].'.';
  $takenSet = array_fill_keys($taken, true);
  for ($i=2; $i<=254; $i++) {
    $ip = $prefix.$i;
    if (!isset($takenSet[$ip])) return $ip;
  }
  return null;
}

function wg_safe_file(?string $path): ?string {
  $path = (string)$path;
  if ($path === '') return null;
  $base = realpath('/var/lib/oris-core/wireguard/clients');
  $real = realpath($path);
  if (!$base || !$real || !str_starts_with($real, $base.'/')) return null;
  if (!is_file($real)) return null;
  return $real;
}

function wg_is_key(string $k): bool {
  $k = trim($k);
  return $k === '' || (bool)preg_match('~^[A-Za-z0-9+/]{42,44}={0,2}$~', $k);
}

$peerTableOk = true;
try {
  $pdo->query("SELECT private_key,config_path,qr_path,updated_at FROM wg_peers LIMIT 1");
} catch (Throwable $e) {
  $peerTableOk = false;
}

if (isset($_GET['download']) && $peerTableOk) {
  $id = (int)$_GET['download'];
  $st = $pdo->prepare("SELECT name,config_path FROM wg_peers WHERE id=?");
  $st->execute([$id]);
  $p = $st->fetch();
  $file = $p ? wg_safe_file($p['config_path'] ?? '') : null;
  if (!$file) { http_response_code(404); echo h(t('wireguard.err.config_not_found', [], 'Config nenalezen. Spusť přegenerovat QR/config.')); exit; }
  $name = preg_replace('~[^a-zA-Z0-9_.-]+~', '-', (string)$p['name']);
  header('Content-Type: text/plain; charset=utf-8');
  header('Content-Disposition: attachment; filename="wg-'.$name.'.conf"');
  readfile($file); exit;
}

if ((isset($_GET['qr']) || isset($_GET['qr_download'])) && $peerTableOk) {
  $id = (int)($_GET['qr'] ?? $_GET['qr_download']);
  $st = $pdo->prepare("SELECT name,qr_path FROM wg_peers WHERE id=?");
  $st->execute([$id]);
  $p = $st->fetch();
  $file = $p ? wg_safe_file($p['qr_path'] ?? '') : null;
  if (!$file) { http_response_code(404); echo h(t('wireguard.err.qr_not_found', [], 'QR nenalezen. Klikni u peeru na Vygenerovat QR/config.')); exit; }
  $name = preg_replace('~[^a-zA-Z0-9_.-]+~', '-', (string)($p['name'] ?? 'peer'));
  header('Content-Type: image/png');
  if (isset($_GET['qr_download'])) {
    header('Content-Disposition: attachment; filename="wg-'.$name.'-qr.png"');
  }
  readfile($file); exit;
}

$vals = [];
foreach ($keys as $k=>$def) $vals[$k] = setting($pdo, $k, $def) ?? $def;
$serverPub = setting($pdo, 'wg_server_public_key', '') ?? '';

if ($_SERVER['REQUEST_METHOD']==='POST') {
  csrf_check();

  try {
    if (isset($_POST['save_settings'])) {
      foreach ($keys as $k=>$def) {
        $v = trim((string)($_POST[$k] ?? $def));
        set_setting($pdo, $k, $v);
      }
      wg_enqueue($pdo, 'wg_apply', 0, ['reason'=>'settings']);
      flash_set('ok', t('wireguard.flash.settings_saved', [], 'Nastavení uloženo a wg_apply je ve frontě.'));
      header('Location:/wireguard.php'); exit;
    }

    if (isset($_POST['install_wg'])) {
      wg_enqueue($pdo, 'wg_install', 0, []);
      flash_set('ok', t('wireguard.flash.install_queued', [], 'wg_install je ve frontě.'));
      header('Location:/wireguard.php'); exit;
    }

    if (isset($_POST['apply_now'])) {
      wg_enqueue($pdo, 'wg_apply', 0, ['reason'=>'manual']);
      flash_set('ok', t('wireguard.flash.apply_queued', [], 'wg_apply je ve frontě.'));
      header('Location:/wireguard.php'); exit;
    }

    if (isset($_POST['restart_wg'])) {
      wg_enqueue($pdo, 'wg_service_restart', 0, []);
      flash_set('ok', t('wireguard.flash.restart_queued', [], 'Restart WireGuard služby je ve frontě.'));
      header('Location:/wireguard.php'); exit;
    }

    if (isset($_POST['add_peer'])) {
      if (!$peerTableOk) throw new RuntimeException(t('wireguard.err.missing_migration', [], 'Chybí DB migrace pro wg_peers. Spusť upgrade.'));
      $name = trim((string)($_POST['name'] ?? ''));
      $ip = trim((string)($_POST['ip'] ?? ''));
      $public = trim((string)($_POST['public_key'] ?? ''));
      $private = trim((string)($_POST['private_key'] ?? ''));
      $psk = trim((string)($_POST['preshared_key'] ?? ''));
      $allowed = trim((string)($_POST['allowed_ips'] ?? ''));
      if ($name === '' || strlen($name) > 190) throw new RuntimeException(t('wireguard.err.name_required', [], 'Jméno je povinné a max 190 znaků.'));
      if (!filter_var($ip, FILTER_VALIDATE_IP)) throw new RuntimeException(t('wireguard.err.invalid_peer_ip', [], 'IP peeru není validní.'));
      foreach (['PublicKey'=>$public,'PrivateKey'=>$private,'PresharedKey'=>$psk] as $label=>$key) {
        if (!wg_is_key($key)) throw new RuntimeException(t('wireguard.err.invalid_key', ['label'=>$label], '{label} nevypadá jako WireGuard klíč.'));
      }
      wg_enqueue($pdo, 'wg_peer_create', 0, [
        'name'=>$name,
        'ip'=>$ip,
        'public_key'=>$public,
        'private_key'=>$private,
        'preshared_key'=>$psk,
        'allowed_ips'=>$allowed,
      ]);
      flash_set('ok', t('wireguard.flash.peer_create_queued', [], 'Vytvoření peeru je ve frontě. Klíče/config/QR vygeneruje Python provisioner.'));
      header('Location:/wireguard.php'); exit;
    }

    if (isset($_POST['enable_peer']) || isset($_POST['disable_peer']) || isset($_POST['delete_peer']) || isset($_POST['regen_peer']) || isset($_POST['regen_qr'])) {
      if (!$peerTableOk) throw new RuntimeException(t('wireguard.err.missing_migration', [], 'Chybí DB migrace pro wg_peers. Spusť upgrade.'));
      $id = (int)($_POST['id'] ?? 0);
      if ($id <= 0) throw new RuntimeException(t('wireguard.err.bad_peer_id', [], 'Chybné ID peeru.'));
      if (isset($_POST['enable_peer'])) wg_enqueue($pdo, 'wg_peer_enable', $id, []);
      if (isset($_POST['disable_peer'])) wg_enqueue($pdo, 'wg_peer_disable', $id, []);
      if (isset($_POST['delete_peer'])) wg_enqueue($pdo, 'wg_peer_delete', $id, []);
      if (isset($_POST['regen_peer'])) wg_enqueue($pdo, 'wg_peer_regenerate', $id, []);
      if (isset($_POST['regen_qr'])) wg_enqueue($pdo, 'wg_peer_qr', $id, []);
      flash_set('ok', t('wireguard.flash.action_queued', [], 'WireGuard akce je ve frontě.'));
      header('Location:/wireguard.php'); exit;
    }
  } catch (Throwable $e) {
    flash_set('err', $e->getMessage());
    header('Location:/wireguard.php'); exit;
  }
}

$peers = [];
if ($peerTableOk) {
  $peers = $pdo->query("SELECT * FROM wg_peers ORDER BY id DESC LIMIT 500")->fetchAll();
}
$suggestIp = '';
$cidr = wg_parse_ipv4_cidr((string)$vals['wg_server_address']);
if ($cidr && $cidr['prefix']===24) {
  $taken = array_map(fn($p)=> (string)$p['ip'], $peers);
  $taken[] = $cidr['ip'];
  $suggestIp = wg_suggest_ip24($cidr['ip'], $taken) ?: '';
}

$recentJobs = $pdo->query("SELECT id,type,status,error,created_at,updated_at FROM jobs WHERE type LIKE 'wg_%' ORDER BY id DESC LIMIT 10")->fetchAll();

render($pdo, t('page.wireguard.title', [], 'WireGuard'), function() use($vals,$keys,$serverPub,$peers,$peerTableOk,$suggestIp,$recentJobs){ ?>
  <div class="card">
    <h2><?=h(t('wireguard.heading', [], 'WireGuard VPN'))?></h2>
    <small><?=h(t('wireguard.help', [], 'UI zůstává v PHP, ale systémové akce dělá Python provisioner přes frontu. PHP nespouští wg/systemctl/iptables.'))?></small>
  </div>

  <?php if(!$peerTableOk): ?>
    <div class="card"><p class="pill err"><?=t('wireguard.err.missing_migration_html', [], 'Chybí DB migrace pro WireGuard. Spusť <code>install/upgrade.sh</code>.')?></p></div>
  <?php endif; ?>

  <div class="card">
    <h3><?=h(t('wireguard.service_actions.heading', [], 'Akce služby'))?></h3>
    <form method="post" style="display:flex; gap:8px; flex-wrap:wrap;">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <button class="btn2" name="install_wg" value="1"><?=h(t('wireguard.action.install_packages', [], 'Instalovat WG balíky'))?></button>
      <button class="btn" name="apply_now" value="1"><?=h(t('wireguard.action.apply_config', [], 'Aplikovat konfiguraci'))?></button>
      <button class="btn2" name="restart_wg" value="1"><?=h(t('wireguard.action.restart_service', [], 'Restart wg služby'))?></button>
    </form>
  </div>

  <div class="card">
    <h3><?=h(t('wireguard.network.heading', [], 'Nastavení sítě'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row3">
        <div><label><?=h(t('wireguard.field.interface', [], 'Interface'))?></label><input name="wg_iface" value="<?=h($vals['wg_iface'])?>" placeholder="wg0"></div>
        <div><label><?=h(t('wireguard.field.server_address', [], 'Server adresa'))?></label><input name="wg_server_address" value="<?=h($vals['wg_server_address'])?>" placeholder="10.42.0.1/24"></div>
        <div><label><?=h(t('wireguard.field.udp_port', [], 'UDP port'))?></label><input name="wg_listen_port" value="<?=h($vals['wg_listen_port'])?>" placeholder="51820"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><?=h(t('wireguard.field.endpoint', [], 'Endpoint pro klienty'))?></label><input name="wg_endpoint" value="<?=h($vals['wg_endpoint'])?>" placeholder="vpn.example.com:51820"></div>
        <div><label><?=h(t('wireguard.field.dns', [], 'DNS pro klienty'))?></label><input name="wg_dns" value="<?=h($vals['wg_dns'])?>" placeholder="1.1.1.1, 8.8.8.8"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><?=h(t('wireguard.field.client_allowed_ips', [], 'AllowedIPs v klientském configu'))?></label><input name="wg_client_allowed_ips" value="<?=h($vals['wg_client_allowed_ips'])?>" placeholder="0.0.0.0/0, ::/0"></div>
        <div><label><?=h(t('wireguard.field.mtu', [], 'MTU volitelně'))?></label><input name="wg_mtu" value="<?=h($vals['wg_mtu'])?>" placeholder="1420"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><?=h(t('wireguard.field.post_up', [], 'PostUp volitelně'))?></label><textarea name="wg_post_up" placeholder="<?=h(t('wireguard.placeholder.auto_nat', [], 'prázdné = automatický NAT přes default route'))?>"><?=h($vals['wg_post_up'])?></textarea></div>
        <div><label><?=h(t('wireguard.field.post_down', [], 'PostDown volitelně'))?></label><textarea name="wg_post_down" placeholder="<?=h(t('wireguard.placeholder.auto_nat', [], 'prázdné = automatický NAT přes default route'))?>"><?=h($vals['wg_post_down'])?></textarea></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div><label><?=h(t('wireguard.field.keepalive', [], 'PersistentKeepalive pro klienty'))?></label><input name="wg_keepalive" value="<?=h($vals['wg_keepalive'])?>" placeholder="25"></div>
        <div></div>
      </div>
      <p style="margin-top:12px"><button class="btn" name="save_settings" value="1"><?=h(t('common.save_apply', [], 'Uložit + aplikovat'))?></button></p>
    </form>
  </div>

  <div class="card">
    <h3><?=h(t('wireguard.server_public_key.heading', [], 'Server PublicKey'))?></h3>
    <?php if($serverPub): ?><pre><?=h($serverPub)?></pre><?php else: ?><small><?=h(t('wireguard.server_public_key.empty', [], 'Zatím není v DB. Spusť Instalovat WG balíky nebo Aplikovat konfiguraci.'))?></small><?php endif; ?>
  </div>

  <div class="card">
    <h3><?=h(t('wireguard.add_peer.heading', [], 'Přidat peer'))?></h3>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row3">
        <div><label><?=h(t('wireguard.field.name', [], 'Jméno'))?></label><input name="name" required placeholder="telefon-jan"></div>
        <div><label><?=h(t('wireguard.field.client_ip', [], 'IP klienta'))?></label><input name="ip" required value="<?=h($suggestIp)?>" placeholder="10.42.0.2"></div>
        <div><label><?=h(t('wireguard.field.server_allowed_ips', [], 'AllowedIPs na serveru'))?></label><input name="allowed_ips" placeholder="<?=h(t('wireguard.placeholder.ip32', [], 'prázdné = IP/32'))?>"></div>
      </div>
      <details style="margin-top:10px">
        <summary><?=h(t('wireguard.manual_keys.summary', [], 'Ruční klíče / import existujícího klienta'))?></summary>
        <div class="row" style="margin-top:10px">
          <div><label><?=h(t('wireguard.field.client_public_key', [], 'PublicKey klienta'))?></label><input name="public_key" placeholder="<?=h(t('wireguard.placeholder.generated_by_provisioner', [], 'prázdné = provisioner vygeneruje'))?>"></div>
          <div><label><?=h(t('wireguard.field.client_private_key', [], 'PrivateKey klienta volitelně'))?></label><input name="private_key" placeholder="<?=h(t('wireguard.placeholder.private_key_import', [], 'jen pokud chceš config/QR pro importovaný peer'))?>"></div>
        </div>
        <div style="margin-top:10px"><label><?=h(t('wireguard.field.preshared_key', [], 'PresharedKey'))?></label><input name="preshared_key" placeholder="<?=h(t('wireguard.placeholder.generated_by_provisioner', [], 'prázdné = provisioner vygeneruje'))?>"></div>
      </details>
      <p style="margin-top:12px"><button class="btn" name="add_peer" value="1"><?=h(t('wireguard.action.create_via_provisioner', [], 'Vytvořit přes provisioner'))?></button></p>
    </form>
  </div>

  <div class="card">
    <h3><?=h(t('wireguard.peers.heading', [], 'Peery'))?></h3>
    <div class="table-scroll">
      <table>
        <tr><th><?=h(t('common.id', [], 'ID'))?></th><th><?=h(t('wireguard.col.name', [], 'Jméno'))?></th><th><?=h(t('wireguard.col.ip', [], 'IP'))?></th><th><?=h(t('wireguard.col.public_key', [], 'PublicKey'))?></th><th><?=h(t('wireguard.col.active', [], 'Aktivní'))?></th><th><?=h(t('wireguard.col.config_qr', [], 'Config/QR'))?></th><th><?=h(t('common.actions', [], 'Akce'))?></th></tr>
        <?php foreach($peers as $p): ?>
          <tr>
            <td><?=h($p['id'])?></td>
            <td><?=h($p['name'])?><br><small><?=h($p['created_at'] ?? '')?></small></td>
            <td><code><?=h($p['ip'])?></code></td>
            <td><small><?=h(substr((string)$p['public_key'],0,18))?>…<?=h(substr((string)$p['public_key'],-6))?></small></td>
            <td><?= ((int)$p['is_active']===1) ? '<span class="pill ok">'.h(t('common.yes', [], 'ano')).'</span>' : '<span class="pill err">'.h(t('common.no', [], 'ne')).'</span>' ?></td>
            <td>
              <?php if(!empty($p['config_path'])): ?>
                <a class="btn2" href="/wireguard.php?download=<?=h($p['id'])?>"><?=h(t('wireguard.action.download_conf', [], 'Stáhnout .conf'))?></a>
              <?php else: ?>
                <small><?=h(t('wireguard.config_missing', [], 'config chybí'))?></small>
              <?php endif; ?>

              <?php if(!empty($p['qr_path'])): ?>
                <a class="btn2" href="/wireguard.php?qr=<?=h($p['id'])?>" target="_blank"><?=h(t('wireguard.action.show_qr', [], 'Zobrazit QR'))?></a>
                <a class="btn2" href="/wireguard.php?qr_download=<?=h($p['id'])?>"><?=h(t('wireguard.action.download_qr', [], 'Stáhnout QR'))?></a>
                <details style="margin-top:8px">
                  <summary><?=h(t('wireguard.qr_preview', [], 'náhled QR'))?></summary>
                  <div style="margin-top:8px; background:#fff; padding:10px; display:inline-block; border-radius:10px">
                    <img src="/wireguard.php?qr=<?=h($p['id'])?>" alt="<?=h(t('wireguard.qr_alt', [], 'WireGuard QR'))?>" style="width:180px; height:180px; display:block">
                  </div>
                </details>
              <?php else: ?>
                <small><?=h(t('wireguard.qr_missing', [], 'QR chybí'))?></small>
              <?php endif; ?>
            </td>
            <td>
              <form method="post" style="margin:0; display:flex; gap:6px; flex-wrap:wrap;">
                <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                <input type="hidden" name="id" value="<?=h($p['id'])?>">
                <?php if((int)$p['is_active']===1): ?>
                  <button class="btn2" name="disable_peer" value="1"><?=h(t('common.disable', [], 'Vypnout'))?></button>
                <?php else: ?>
                  <button class="btn2" name="enable_peer" value="1"><?=h(t('common.enable', [], 'Zapnout'))?></button>
                <?php endif; ?>
                <button class="btn2" name="regen_qr" value="1"><?=h(t('wireguard.action.regen_qr_config', [], 'Vygenerovat QR/config'))?></button>
                <button class="btn2" name="regen_peer" value="1" onclick="return confirm(<?=json_encode(t('wireguard.confirm.regen_keys', [], 'Vygenerovat nové klíče? Starý klient přestane fungovat.'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('wireguard.action.new_keys', [], 'Nové klíče'))?></button>
                <button class="btn-danger" name="delete_peer" value="1" onclick="return confirm(<?=json_encode(t('wireguard.confirm.delete_peer', [], 'Smazat peer?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)?>);"><?=h(t('common.delete', [], 'Smazat'))?></button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        <?php if(!$peers): ?><tr><td colspan="7"><small><?=h(t('wireguard.peers.empty', [], 'Žádní peeři.'))?></small></td></tr><?php endif; ?>
      </table>
    </div>
  </div>

  <div class="card">
    <h3><?=h(t('wireguard.recent_jobs.heading', [], 'Poslední WG joby'))?></h3>
    <div class="table-scroll"><table>
      <tr><th><?=h(t('common.id', [], 'ID'))?></th><th><?=h(t('jobs.col.type', [], 'Typ'))?></th><th><?=h(t('jobs.col.status', [], 'Stav'))?></th><th><?=h(t('wireguard.col.time', [], 'Čas'))?></th><th><?=h(t('wireguard.col.error', [], 'Chyba'))?></th></tr>
      <?php foreach($recentJobs as $j): ?>
        <tr><td><?=h($j['id'])?></td><td><?=h($j['type'])?></td><td><?=h(t('status.'.$j['status'], [], (string)$j['status']))?></td><td><small><?=h($j['updated_at'] ?: $j['created_at'])?></small></td><td><small><?=h($j['error'] ?? '')?></small></td></tr>
      <?php endforeach; ?>
      <?php if(!$recentJobs): ?><tr><td colspan="5"><small><?=h(t('wireguard.recent_jobs.empty', [], 'Žádné WG joby.'))?></small></td></tr><?php endif; ?>
    </table></div>
    <small><?=t('wireguard.recent_jobs.help', [], 'Detailní log je v <a href="/jobs.php">Úlohách</a>.')?></small>
  </div>
<?php });

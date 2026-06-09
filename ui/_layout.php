<?php
/** @var string $title */
/** @var string $content */
/** @var PDO $pdo */
$u = me($pdo);
$f = flash_get();
?>
<!doctype html>
<html lang="<?=h(current_lang())?>">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/style.css">
<title><?=h($title)?> | Oris Panel</title>

<div class="topbar">
  <div class="wrap topbar-inner">
    <div class="brand"><a href="/dashboard.php">Oris Panel</a></div>

    <div class="lang-switch" style="margin-left:auto;display:flex;gap:8px;align-items:center">
      <?php
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $parts = parse_url($uri);
        $path = $parts['path'] ?? '/';
        $qs = [];
        if (!empty($parts['query'])) parse_str($parts['query'], $qs);
        $mk = function(string $lang) use ($path, $qs) {
          $q = $qs;
          $q['lang'] = $lang;
          $qq = http_build_query($q);
          return $path . ($qq ? ('?' . $qq) : '');
        };
        $cl = current_lang();
      ?>
      <?php foreach (available_langs() as $lang): ?>
        <a class="pill <?=($cl===$lang?'ok':'')?>" href="<?=h($mk($lang))?>"><?=h(lang_label($lang))?></a>
      <?php endforeach; ?>
    </div>


    <?php if($u): ?>
      <button class="nav-toggle" type="button" aria-label="<?=h(t('nav.menu', [], 'Menu'))?>" onclick="toggleNav()">
        ☰
      </button>
    <?php endif; ?>

    <div class="nav" id="nav">
      <?php if($u): ?>
        <div class="nav-cat" data-cat="web">
          <button class="nav-cat-btn" type="button"><?=h(t('nav.web_server', [], 'Web server'))?></button>
          <div class="nav-drop">
            <a href="/sites.php"><?=h(t('nav.websites', [], 'Weby'))?></a>
            <a href="/db.php"><?=h(t('nav.databases', [], 'Databáze'))?></a>
            <a href="/tunnels.php"><?=h(t('nav.proxy', [], 'Proxy'))?></a>
            <a href="/ftp.php"><?=h(t('nav.ftp', [], 'FTP'))?></a>
            <a href="/certbot.php"><?=h(t('nav.certbot', [], 'Certbot'))?></a>
            <a href="/cron.php"><?=h(t('nav.cron', [], 'Cron'))?></a>
            <a href="/php.php"><?=h(t('nav.php', [], 'PHP'))?></a>
          </div>
        </div>

        <div class="nav-cat" data-cat="mail">
          <button class="nav-cat-btn" type="button"><?=h(t('nav.email', [], 'E-mail'))?></button>
          <div class="nav-drop">
            <a href="/mail.php"><?=h(t('nav.email', [], 'E-mail'))?></a>
            <a href="/mail_server.php"><?=h(t('nav.settings', [], 'Nastavení'))?></a>
          </div>
        </div>

        <div class="nav-cat" data-cat="network">
          <button class="nav-cat-btn" type="button"><?=h(t('nav.network', [], 'Síť'))?></button>
          <div class="nav-drop">
            <a href="/network-stat.php"><?=h(t('nav.network_traffic', [], 'Síťový provoz'))?></a>
            <a href="/wireguard.php"><?=h(t('nav.wireguard', [], 'WireGuard'))?></a>
          </div>
        </div>

        <div class="nav-cat" data-cat="security">
          <button class="nav-cat-btn" type="button"><?=h(t('nav.security', [], 'Zabezpečení'))?></button>
          <div class="nav-drop">
            <a href="/security.php"><?=h(t('nav.security_center', [], 'Centrum zabezpečení'))?></a>
            <a href="/firewall.php"><?=h(t('nav.fail2ban', [], 'Fail2ban'))?></a>
            <a href="/ufw.php"><?=h(t('nav.ufw', [], 'UFW'))?></a>
          </div>
        </div>

        <div class="nav-cat" data-cat="system">
          <button class="nav-cat-btn" type="button"><?=h(t('nav.system', [], 'Systém'))?></button>
          <div class="nav-drop">
            <a href="/jobs.php"><?=h(t('nav.jobs', [], 'Úlohy'))?></a>
            <a href="/logs.php"><?=h(t('nav.logs', [], 'Logy'))?></a>
            <a href="/stoarge-cpu.php"><?=h(t('nav.storage_cpu', [], 'Uložiště, CPU'))?></a>
            <a href="/daemon.php"><?=h(t('nav.services', [], 'Služby'))?></a>
            <a href="/users.php"><?=h(t('nav.users', [], 'Uživatelé'))?></a>
            <a href="/api_tokens.php"><?=h(t('nav.api_tokens', [], 'API tokeny'))?></a>
            <a href="/api_explorer.php"><?=h(t('nav.api_explorer', [], 'API explorer'))?></a>
            <a href="/server_config.php"><?=h(t('nav.server_config', [], 'Konfigurace serveru'))?></a>
            <a href="/panel_config.php"><?=h(t('nav.panel_config', [], 'Admin panel PHP / vhost'))?></a>
            <a href="/settings.php"><?=h(t('nav.settings', [], 'Nastavení'))?></a>
	    <a href="/language_editor.php"><?=h(t('nav.language_editor', [], 'Překlady'))?></a>
          </div>
        </div>

        <div class="nav-auth">
          <a class="pill" href="/logout.php"><?=h(t('nav.logout', [], 'Logout'))?></a>
        </div>
      <?php else: ?>
        <a href="/login.php"><?=h(t('nav.login', [], 'Login'))?></a>
      <?php endif; ?>
    </div>
  </div>
</div>
<div class="wrap">
  <?php if($f): ?>
    <div class="card"><p class="pill <?= $f['type']==='ok'?'ok':'err' ?>"><?=h($f['msg'])?></p></div>
  <?php endif; ?>
  <?= $content ?>
</div>
<script>
  function toggleNav(){
    const nav = document.getElementById('nav');
    if(!nav) return;
    nav.classList.toggle('open');
  }

  function closeAllCats(){
    document.querySelectorAll('.nav-cat.open').forEach(el => el.classList.remove('open'));
  }

  document.addEventListener('click', (e) => {
    const nav = document.getElementById('nav');
    if(!nav) return;

    const toggleBtn = document.querySelector('.nav-toggle');
    const isMobile = window.innerWidth <= 900;

    // klik na hamburger -> řeší inline onclick
    if (toggleBtn && (toggleBtn === e.target || toggleBtn.contains(e.target))) return;

    // klik na button kategorie
    const catBtn = e.target.closest('.nav-cat-btn');
    if (catBtn) {
      const cat = catBtn.closest('.nav-cat');
      const willOpen = !cat.classList.contains('open');
      closeAllCats();
      if (willOpen) cat.classList.add('open');
      return;
    }

    // klik na link
    if (e.target.closest('#nav a')) {
      closeAllCats();
      if (isMobile && nav.classList.contains('open')) nav.classList.remove('open');
      return;
    }

    // klik mimo navigaci: zavřít dropdowny
    if (!e.target.closest('#nav')) closeAllCats();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    closeAllCats();
    const nav = document.getElementById('nav');
    if (nav && window.innerWidth <= 900) nav.classList.remove('open');
  });
</script>
</html>

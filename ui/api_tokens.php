<?php
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

function token_plain(): string { return bin2hex(random_bytes(24)); } // 48 chars
function token_hash(string $plain): string { return hash('sha256', $plain); }

$showToken = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create'])) {
  csrf_check();

  $name = trim((string)($_POST['name'] ?? ''));
  $scopesArr = (array)($_POST['scopes'] ?? []);
  $userId = trim((string)($_POST['user_id'] ?? ''));
  $expires = trim((string)($_POST['expires_at'] ?? ''));

  if ($name === '') {
    flash_set('err', t('api_tokens.flash.name_required', [], 'Název je povinný'));
    header("Location: /admin/api_tokens.php"); exit;
  }

  $allowed = ['web','db','ftp','proxy','wireguard','jobs','logs','settings','users','cron','php','panel','services','firewall','mail','servercfg','admin'];
  $scopesArr = array_values(array_unique(array_filter($scopesArr, fn($s)=>in_array($s,$allowed,true))));
  if (!$scopesArr) {
    flash_set('err', t('api_tokens.flash.scope_required', [], 'Vyber aspoň jeden scope'));
    header("Location: /admin/api_tokens.php"); exit;
  }

  $uid = null;
  if ($userId !== '' && ctype_digit($userId)) $uid = (int)$userId;

  $expiresAt = null;
  if ($expires !== '') {
    // očekáváme HTML datetime-local => "YYYY-MM-DDTHH:MM"
    $expires = str_replace('T', ' ', $expires) . ':00';
    $dt = DateTime::createFromFormat('Y-m-d H:i:s', $expires);
    if ($dt) $expiresAt = $dt->format('Y-m-d H:i:s');
  }

  $plain = token_plain();
  $hash  = token_hash($plain);
  $scopes = implode(',', $scopesArr);

  $st = $pdo->prepare("INSERT INTO api_tokens(name, token_hash, scopes, user_id, expires_at) VALUES(?,?,?,?,?)");
  $st->execute([$name, $hash, $scopes, $uid, $expiresAt]);

  $showToken = $plain; // zobrazit jen jednou
  flash_set('ok', t('api_tokens.flash.created_once', [], 'Token vytvořen (zobrazí se níže jen jednou).'));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['revoke'])) {
  csrf_check();
  $id = (int)($_POST['id'] ?? 0);
  $pdo->prepare("UPDATE api_tokens SET is_active=0 WHERE id=?")->execute([$id]);
  flash_set('ok', t('api_tokens.flash.revoked', ['id'=>$id], 'Token #{id} deaktivován'));
  header("Location: /admin/api_tokens.php"); exit;
}

$tokens = $pdo->query("SELECT t.*, u.email AS user_email
                       FROM api_tokens t
                       LEFT JOIN users u ON u.id=t.user_id
                       ORDER BY t.id DESC")->fetchAll();

$users = $pdo->query("SELECT id,email FROM users ORDER BY id ASC")->fetchAll();

render($pdo, t('page.api_tokens.title', [], 'API tokeny'), function() use ($tokens, $users, $showToken) { ?>
  <div class="card">
    <h2><?=h(t('page.api_tokens.title', [], 'API tokeny'))?></h2>
    <p><small><?=h(t('api_tokens.help.token_shown_once', [], 'Token se zobrazí jen při vytvoření. Ulož si ho hned.'))?></small></p>

    <?php if ($showToken): ?>
      <div class="card" style="margin-top:10px">
        <p class="pill ok"><?=h(t('api_tokens.new_token.label', [], 'NOVÝ TOKEN (zkopíruj si ho teď):'))?></p>
        <pre><?=h($showToken)?></pre>
      </div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2><?=h(t('api_tokens.section.create', [], 'Vytvořit token'))?></h2>
    <form method="post">
      <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
      <div class="row">
        <div style="flex:2">
          <label><?=h(t('api_tokens.field.name', [], 'Název'))?></label>
          <input name="name" placeholder="<?=h(t('api_tokens.placeholder.name', [], 'např. Deploy bot'))?>" required>
        </div>
        <div style="flex:1">
          <label><?=h(t('api_tokens.field.user_optional', [], 'Uživatel (volitelné)'))?></label>
          <select name="user_id">
            <option value=""><?=h(t('api_tokens.option.admin_token', [], '— (admin token)'))?></option>
            <?php foreach($users as $u): ?>
              <option value="<?= (int)$u['id'] ?>"><?=h($u['email'])?> (#<?= (int)$u['id'] ?>)</option>
            <?php endforeach; ?>
          </select>
        </div>
        <div style="flex:1">
          <label><?=h(t('api_tokens.field.expires_optional', [], 'Expirace (volitelně)'))?></label>
          <input type="datetime-local" name="expires_at">
        </div>
      </div>

      <div class="row" style="margin-top:10px">
        <label style="min-width:120px"><?=h(t('api_tokens.field.scopes', [], 'Scopes'))?></label>
        <?php foreach (['web','db','ftp','proxy','wireguard','jobs','logs','settings','users','cron','php','panel','services','firewall','mail','servercfg','admin'] as $scope): ?>
          <label><input type="checkbox" name="scopes[]" value="<?=h($scope)?>"> <?=h($scope)?></label>
        <?php endforeach; ?>
      </div>

      <button class="btn" name="create" value="1" type="submit" style="margin-top:10px"><?=h(t('common.create', [], 'Vytvořit'))?></button>
    </form>
  </div>

  <div class="card">
    <h2><?=h(t('api_tokens.section.list', [], 'Seznam tokenů'))?></h2>
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>#</th><th><?=h(t('api_tokens.table.name', [], 'Název'))?></th><th><?=h(t('api_tokens.table.scopes', [], 'Scopes'))?></th><th><?=h(t('api_tokens.table.user', [], 'Uživatel'))?></th><th><?=h(t('api_tokens.table.active', [], 'Aktivní'))?></th><th><?=h(t('api_tokens.table.expires', [], 'Expirace'))?></th><th><?=h(t('api_tokens.table.last_used', [], 'Naposledy použito'))?></th><th></th>
          </tr>
        </thead>
        <tbody>
          <?php foreach($tokens as $t): ?>
            <tr>
              <td><code><?= (int)$t['id'] ?></code></td>
              <td><?= h($t['name']) ?></td>
              <td><code><?= h($t['scopes']) ?></code></td>
              <td><?= h($t['user_email'] ?? '—') ?></td>
              <td>
                <?php if ((int)$t['is_active']===1): ?>
                  <span class="pill ok"><?=h(t('common.yes', [], 'ano'))?></span>
                <?php else: ?>
                  <span class="pill err"><?=h(t('common.no', [], 'ne'))?></span>
                <?php endif; ?>
              </td>
              <td><small><?= h($t['expires_at'] ?? '—') ?></small></td>
              <td><small><?= h($t['last_used_at'] ?? '—') ?></small></td>
              <td style="text-align:right">
                <?php if ((int)$t['is_active']===1): ?>
                  <form method="post" style="display:inline" onsubmit="return confirm(<?=h(json_encode(t('api_tokens.confirm.revoke', ['id'=>(int)$t['id']], 'Deaktivovat token #{id}?'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES))?>);">
                    <input type="hidden" name="_csrf" value="<?=h(csrf_token())?>">
                    <input type="hidden" name="id" value="<?= (int)$t['id'] ?>">
                    <button class="btn-danger" name="revoke" value="1" type="submit"><?=h(t('api_tokens.button.revoke', [], 'Deaktivovat'))?></button>
                  </form>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          <?php if(!$tokens): ?>
            <tr><td colspan="8"><small><?=h(t('api_tokens.empty', [], 'Žádné tokeny'))?></small></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>

<details class="card" style="margin-top:10px">
  <summary><span class="pill run"><?=h(t('api_tokens.quick_reference.title', [], 'API endpointy (rychlý přehled)'))?></span></summary>
  <pre style="white-space:pre-wrap"><?= h(t('api_tokens.quick_reference.text', [], <<<'TXT'
Auth:
  Authorization: Bearer <TOKEN>
  Content-Type: application/json

Base:
  /api/v1/index.php?r=...   (bez rewrite)
  /api/v1/...               (pokud máš rewrite)

Health:
  GET  /health

WEB (sites) [scope: web]
  GET   /sites?user_id=1
  GET   /sites/{id}
  POST  /sites                 (idempotent: user_id + domain)
        body: {user_id, domain, root_path, force_https?, hsts?, disabled?}
  PATCH /sites/{id}
  DELETE /sites/{id}
  POST  /sites/{id}/db/reset-pass   [scope: db]

PROXY (tunnels) [scope: proxy]
  GET   /tunnels?user_id=1
  GET   /tunnels/{id}
  POST  /tunnels               (idempotent: user_id + subdomain)
        body: {user_id, subdomain, upstream, force_https?, hsts?, disabled?}
  PATCH /tunnels/{id}
  DELETE /tunnels/{id}

FTP [scope: ftp]
  GET    /ftp?user_id=1
  POST   /ftp                   body: {site_id}
  POST   /ftp/{id}/reset-pass
  DELETE /ftp/{id}

Jobs/logs/data:
  GET    /lookup                   vrátí dostupná data podle scopů tokenu
  GET    /jobs?limit=100           [scope: jobs]
  GET    /jobs/{id}                [scope: jobs nebo scope daného jobu]
  POST   /jobs                     body: {type, ref_id?, payload?}
  GET    /logs/sources             [scope: logs]
  GET    /logs?src=unit:nginx&n=200&q=error  [scope: logs]
  GET    /settings?keys=sites_base_dir,wg_endpoint [scope: settings]
  GET    /users                    [scope: users]

WireGuard [scope: wireguard]
  GET    /wg/peers
  GET    /wg/peers/{id}
  POST   /wg/peers              (idempotent: public_key)
        body: {name?, ip, public_key, preshared_key?, allowed_ips?, is_active?}
  POST   /wg/peers/{id}/toggle  body: {is_active:true|false}
  DELETE /wg/peers/{id}

Notes:
  - API zapisuje do DB + vkládá job do jobs => uvidíš v "Úlohách".
  - Scope admin nebo * má přístup ke všemu.
  - Logy se čtou přes sudo whitelist wrapper extras/oris-log.
TXT
)) ?></pre>
</details>

  </div>
<?php }); ?>

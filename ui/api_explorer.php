<?php
declare(strict_types=1);

require __DIR__ . '/_boot.php';
require __DIR__ . '/_view.php';
require_admin();

$me = me($pdo);
$defaultUserId = (int)($me['id'] ?? 1);

function json_out(int $code, array $data): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  exit;
}

function http_request(
  string $method,
  string $url,
  array $headers = [],
  ?string $body = null,
  int $timeout = 15,
  ?string $resolveTo = null
): array {
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
  curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
  curl_setopt($ch, CURLOPT_HEADER, true);

  if ($resolveTo !== null && $resolveTo !== '') {
    $uHost = parse_url($url, PHP_URL_HOST);
    $uPort = parse_url($url, PHP_URL_PORT);
    $uScheme = parse_url($url, PHP_URL_SCHEME);

    if (is_string($uHost) && $uHost !== '') {
      if (!$uPort) {
        $uPort = ($uScheme === 'https') ? 443 : 80;
      }

      curl_setopt($ch, CURLOPT_RESOLVE, [
        $uHost . ':' . $uPort . ':' . $resolveTo
      ]);
    }
  }

  if ($body !== null) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
  }

  $h = [];
  foreach ($headers as $k => $v) {
    $h[] = "$k: $v";
  }

  if ($h) {
    curl_setopt($ch, CURLOPT_HTTPHEADER, $h);
  }

  $resp = curl_exec($ch);
  $err  = curl_error($ch);
  $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $hsz  = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
  curl_close($ch);

  if ($resp === false) {
    return [
      'ok' => false,
      'code' => 0,
      'error' => $err ?: 'curl_exec failed',
      'headers' => '',
      'body' => '',
    ];
  }

  return [
    'ok' => true,
    'code' => $code,
    'headers' => substr($resp, 0, $hsz),
    'body' => substr($resp, $hsz),
    'error' => '',
  ];
}

function starts_with(string $s, string $prefix): bool {
  return strncmp($s, $prefix, strlen($prefix)) === 0;
}

function api_explorer_current_host(): string {
  $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
  $host = trim((string)$host);

  // Ochrana proti CRLF / bordelu v Host hlavičce
  $clean = preg_replace('~[^a-zA-Z0-9\.\-:\[\]]~', '', $host);
  $host = is_string($clean) ? $clean : '';

  return $host !== '' ? $host : 'localhost';
}

function api_explorer_is_https(): bool {
  if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    return true;
  }

  if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
    return strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https';
  }

  if (!empty($_SERVER['REQUEST_SCHEME'])) {
    return strtolower((string)$_SERVER['REQUEST_SCHEME']) === 'https';
  }

  return false;
}

function api_explorer_base_url(): string {
  return (api_explorer_is_https() ? 'https' : 'http') . '://' . api_explorer_current_host();
}

function build_curl(string $method, string $path, string $tokenPlain, ?string $jsonBody): string {
  $cmd = 'curl -i -X '.escapeshellarg($method).' ';
  $cmd .= '-H '.escapeshellarg('Accept: application/json').' ';

  if ($tokenPlain !== '') {
    $cmd .= '-H '.escapeshellarg('Authorization: Bearer '.$tokenPlain).' ';
  }

  if ($jsonBody !== null) {
    $cmd .= '-H '.escapeshellarg('Content-Type: application/json').' -d '.escapeshellarg($jsonBody).' ';
  }

  $cmd .= escapeshellarg(api_explorer_base_url().$path);
  return $cmd;
}

/* ---------------- AJAX TRY (server-side call to localhost) ---------------- */

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['api_try'])) {
  csrf_check();

  $method = strtoupper(trim((string)($_POST['api_method'] ?? 'GET')));
  $path   = trim((string)($_POST['api_path'] ?? '/api/v1/index.php?r=/health'));
  $tokenPlain = trim((string)($_POST['api_token_plain'] ?? ''));
  $body   = (string)($_POST['api_body'] ?? '');
  $timeout= (int)($_POST['api_timeout'] ?? 15);

  if (!in_array($method, ['GET','POST','PATCH','PUT','DELETE'], true)) {
    json_out(400, ['ok'=>false,'error'=>'invalid_method']);
  }

  if ($timeout < 3 || $timeout > 60) $timeout = 15;

  if (!starts_with($path, '/api/')) {
    json_out(400, ['ok'=>false,'error'=>t('api_explorer.error.path_must_start_api', [], 'Path musí začínat /api/')]);
  }

  // Voláme lokálně přes 127.0.0.1, ale pošleme Host, aby nginx trefil správný vhost.
  $url = api_explorer_base_url() . $path;

  $headers = [
    'Accept' => 'application/json',
    'X-Forwarded-Host' => api_explorer_current_host(),
    'X-Forwarded-Proto' => api_explorer_is_https() ? 'https' : 'http',
  ];

  if ($tokenPlain !== '') {
    $headers['Authorization'] = 'Bearer '.$tokenPlain;
  }

  $sendBody = null;

  if (in_array($method, ['POST','PATCH','PUT'], true)) {
    $sendBody = ($body === '') ? '{}' : $body;
    $headers['Content-Type'] = 'application/json';

    json_decode($sendBody, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
      json_out(400, ['ok'=>false,'error'=>t('api_explorer.error.body_invalid_json', ['error'=>json_last_error_msg()], 'Body není validní JSON: {error}')]);
    }
  }

  $resp = http_request($method, $url, $headers, $sendBody, $timeout, '127.0.0.1');
  $resp['curl'] = build_curl($method, $path, $tokenPlain, $sendBody);
  $resp['request'] = [
    'method'=>$method,
    'url'=>$url,
    'host'=>api_explorer_current_host(),
    'path'=>$path,
    'timeout'=>$timeout
  ];

  json_out(200, $resp);
}

/* ---------------- PAGE ---------------- */

render($pdo, t('page.api_explorer.title', [], 'API Explorer'), function() use ($defaultUserId) {
  $js = static fn(string $key, string $fallback): string => json_encode(t($key, [], $fallback), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
?>
  <div class="card">
    <h2><?=h(t('page.api_explorer.title', [], 'API Explorer'))?></h2>
    <small>
      <?=h(t('api_explorer.intro.main', [], 'Testování ORIS API přes prohlížeč. Presety ti předvyplní metodu / route / query / JSON body. Vygeneruje to i cURL.'))?>
      <br><?=h(t('api_explorer.intro.tip', [], 'Tip: router bez rewrite používá'))?> <code>/api/v1/index.php?r=/route</code> <?=h(t('api_explorer.intro.query_suffix', [], 'a query se přidává přes'))?> <code>&amp;...</code>.
      <br><b><?=h(t('common.note', [], 'Pozn.:'))?></b> <?=h(t('api_explorer.intro.server_side', [], 'Request jde server-side přes'))?> <code>http://127.0.0.1</code> → <?=h(t('api_explorer.intro.server_side_suffix', [], 'funguje i když API nepustíš ven.'))?>
    </small>
  </div>

  <style>
    .api-grid{ display:grid; grid-template-columns: 1fr 1.6fr; gap:12px; }
    @media (max-width:900px){ .api-grid{ grid-template-columns: 1fr; } }
    .api-actions{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    .api-actions .btn, .api-actions .btn2, .api-actions .btn-danger{ width:auto; }
    .api-inline{ display:flex; gap:12px; align-items:flex-end; }
    .api-inline > *{ flex:1; }
    .api-inline .w-140{ flex:0 0 140px; }
    .api-inline .w-180{ flex:0 0 180px; }
    .api-pre-dark{ background:#0b1220; border:1px solid #22314f; border-radius:10px; padding:10px; overflow:auto; }
    .api-pre-json{ color:#7dd3fc; }
    .api-pre-curl{ color:#cbd5e1; }
  </style>

  <div class="api-grid">
    <!-- REQUEST -->
    <div class="card">
      <h3><?=h(t('api_explorer.section.request', [], 'Požadavek'))?></h3>

      <div class="card" style="margin:12px 0;">
        <h3 style="margin-bottom:6px;"><?=h(t('api_explorer.auth.title', [], 'Autorizace'))?></h3>
        <small><?=h(t('api_explorer.auth.sent_as', [], 'Posílá se jako'))?> <code>Authorization: Bearer ...</code>. <?=h(t('api_explorer.auth.not_saved', [], 'Neukládá se.'))?></small>
        <div style="margin-top:10px;">
          <label><small><?=h(t('api_explorer.field.token_plain', [], 'Token (plaintext)'))?></small></label>
          <input id="api-token" placeholder="<?=h(t('api_explorer.placeholder.token', [], 'oris_xxx nebo hex token'))?>">
        </div>
      </div>

      <div>
        <label><small><?=h(t('api_explorer.field.preset', [], 'Preset'))?></small></label>
        <select id="api-preset" onchange="applyPreset()"></select>
        <small id="preset-hint"><?=h(t('api_explorer.hint.preset_default', [], 'Preset nastaví metodu + route + query + body.'))?></small>
      </div>

      <div class="api-inline" style="margin-top:12px;">
        <div class="w-140">
          <label><small><?=h(t('api_explorer.field.method', [], 'Metoda'))?></small></label>
          <select id="api-method" onchange="updateBodyVisibility()">
            <option>GET</option>
            <option>POST</option>
            <option>PATCH</option>
            <option>PUT</option>
            <option>DELETE</option>
          </select>
        </div>
        <div>
          <label><small><?=h(t('api_explorer.field.route', [], 'Route'))?></small></label>
          <input id="api-route" placeholder="/sites, /tunnels, /ftp, /wg/peers ...">
        </div>
      </div>

      <div class="row" style="margin-top:12px;">
        <div>
          <label><small><?=h(t('api_explorer.field.query_no_question', [], 'Query (bez ?)'))?></small></label>
          <input id="api-query" placeholder="user_id=1">
        </div>
        <div>
          <label><small><?=h(t('api_explorer.field.base_path', [], 'Základní cesta'))?></small></label>
          <input id="api-base" value="/api/v1/index.php">
          <small>
            <?=h(t('api_explorer.hint.no_rewrite', [], 'Bez rewrite:'))?> <code>/api/v1/index.php?r=/sites&amp;user_id=1</code><br>
            <?=h(t('api_explorer.hint.with_rewrite', [], 'S rewrite: nastav'))?> <code>/api/v1</code> <?=h(t('api_explorer.hint.with_rewrite_suffix', [], 'a route třeba'))?> <code>/sites</code>
          </small>
        </div>
      </div>

      <div class="row" style="margin-top:12px;">
        <div>
          <label><small><?=h(t('api_explorer.field.timeout_seconds', [], 'Timeout (sekundy)'))?></small></label>
          <input id="api-timeout" value="15">
          <small><?=h(t('api_explorer.hint.timeout', [], '3–60s. Když provisioner chvíli trvá, dej 30–60.'))?></small>
        </div>
        <div>
          <label><small><?=h(t('api_explorer.field.final_path', [], 'Výsledná path (volá se přes localhost)'))?></small></label>
          <input id="api-path" readonly>
          <small><?=h(t('api_explorer.hint.must_start_with', [], 'Musí začínat'))?> <code>/api/</code>.</small>
        </div>
      </div>

      <div id="body-group" style="display:none; margin-top:12px;">
        <label><small><?=h(t('api_explorer.field.json_body', [], 'JSON tělo'))?></small></label>
        <textarea id="api-body" placeholder='{"hello":"world"}'></textarea>
        <div class="api-actions" style="margin-top:10px;">
          <button type="button" class="btn2" onclick="formatJSON()"><?=h(t('api_explorer.button.format_json', [], 'Zformátovat JSON'))?></button>
          <button type="button" class="btn2" onclick="setBodyEmptyObject()"><?=h(t('api_explorer.button.set_empty_object', [], 'Nastavit {}'))?></button>
          <small id="body-hint"></small>
        </div>
      </div>

      <div class="api-actions" style="margin-top:12px;">
        <button type="button" class="btn" onclick="sendAPIRequest()"><?=h(t('common.send', [], 'Odeslat'))?></button>
        <button type="button" class="btn2" onclick="clearResponse()"><?=h(t('api_explorer.button.clear_response', [], 'Vymazat odpověď'))?></button>
      </div>
    </div>

    <!-- RESPONSE -->
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
        <h3><?=h(t('api_explorer.section.response', [], 'Odpověď'))?></h3>
        <span id="res-status" class="pill run" style="display:none;"></span>
      </div>

      <div id="res-empty" style="margin-top:10px;">
        <small><?=h(t('api_explorer.response.empty', [], 'Zatím nebyl odeslán žádný požadavek.'))?></small>
      </div>

      <div id="res-loading" style="display:none; margin-top:10px;">
        <small class="pill run"><?=h(t('api_explorer.response.running', [], 'Běží…'))?></small>
      </div>

      <div id="res-json-wrap" style="display:none; margin-top:10px;">
        <h3 style="margin-bottom:6px;"><?=h(t('api_explorer.response.body', [], 'Tělo'))?></h3>
        <pre id="res-body" class="api-pre-dark api-pre-json"></pre>
      </div>

      <div id="res-wg-wrap" style="display:none; margin-top:12px;">
        <h3 style="margin-bottom:6px;"><?=h(t('api_explorer.response.wg_config', [], 'WireGuard konfigurace'))?></h3>
        <small><?=h(t('api_explorer.response.wg_config_hint_prefix', [], 'Pokud endpoint vrací'))?> <code>config</code> / <code>wg_config</code> / <code>generated.config</code>, <?=h(t('api_explorer.response.wg_config_hint_suffix', [], 'zobrazí se tady.'))?></small>
        <pre id="res-wg" class="api-pre-dark api-pre-curl"></pre>
        <div class="api-actions" style="margin-top:10px;">
          <button type="button" class="btn2" onclick="copyText('res-wg')"><?=h(t('api_explorer.button.copy_wg_config', [], 'Kopírovat WG config'))?></button>
        </div>
      </div>

      <div id="curl-wrap" style="display:none; margin-top:12px;">
        <h3 style="margin-bottom:6px;">cURL</h3>
        <pre id="curl-output" class="api-pre-dark api-pre-curl"></pre>
        <div class="api-actions" style="margin-top:10px;">
          <button type="button" class="btn2" onclick="copyText('curl-output')"><?=h(t('api_explorer.button.copy_curl', [], 'Kopírovat cURL'))?></button>
        </div>
      </div>

      <div id="res-raw-wrap" style="display:none; margin-top:12px;">
        <h3 style="margin-bottom:6px;"><?=h(t('api_explorer.response.raw_non_json', [], 'Raw (ne-JSON)'))?></h3>
        <pre id="res-raw" class="api-pre-dark"></pre>
      </div>
    </div>
  </div>

  <script>
    const DEFAULT_USER_ID = <?= (int)$defaultUserId ?>;
    const CSRF = <?= json_encode(csrf_token(), JSON_UNESCAPED_SLASHES) ?>;
    const I18N = {
      presetDefaultHint: <?= $js('api_explorer.hint.preset_default', 'Preset nastaví metodu + route + query + body.') ?>,
      bodyMustBeJson: <?= $js('api_explorer.js.body_must_be_json', 'Body musí být validní JSON.') ?>,
      invalidJsonPrefix: <?= $js('api_explorer.js.invalid_json_prefix', 'Neplatný JSON: ') ?>,
      bodyInvalidJsonPrefix: <?= $js('api_explorer.js.body_invalid_json_prefix', 'Body není validní JSON: ') ?>,
      copyFailed: <?= $js('api_explorer.js.copy_failed', 'Kopírování selhalo (oprávnění prohlížeče).') ?>,
      emptyResponse: <?= $js('api_explorer.js.empty_response', '(prázdné)') ?>,
      fetchErrorPrefix: <?= $js('api_explorer.js.fetch_error_prefix', 'Chyba fetch: ') ?>
    };

    const PRESETS = [
      { label: <?= $js('api_explorer.preset.health.label', 'Health check') ?>, method:"GET", route:"/health", query:"", body:"", hint: <?= $js('api_explorer.preset.health.hint', 'Základní test, jestli API žije.') ?> },
      { label: <?= $js('api_explorer.preset.auth_me.label', 'Autorizace: Já') ?>, method:"GET", route:"/me", query:"", body:"", hint: <?= $js('api_explorer.preset.auth_me.hint', 'Ověření tokenu a scopů.') ?> },
      { label: <?= $js('api_explorer.preset.lookup.label', 'Lookup: dostupná data') ?>, method:"GET", route:"/lookup", query:"", body:"", hint: <?= $js('api_explorer.preset.lookup.hint', 'Vrátí sites/tunnels/FTP/WG/job/log sources podle scopů tokenu.') ?> },

      // JOBS + LOGS
      { label: <?= $js('api_explorer.preset.jobs_list.label', 'Úlohy: poslední seznam') ?>, method:"GET", route:"/jobs", query:"limit=50", body:"", hint: <?= $js('api_explorer.preset.jobs_list.hint', 'GET /jobs [scope jobs]') ?> },
      { label: <?= $js('api_explorer.preset.jobs_detail.label', 'Úlohy: detail') ?>, method:"GET", route:"/jobs/1", query:"", body:"", hint: <?= $js('api_explorer.preset.jobs_detail.hint', 'GET /jobs/{id}') ?> },
      { label: <?= $js('api_explorer.preset.jobs_queue.label', 'Úlohy: zařadit obecnou úlohu') ?>, method:"POST", route:"/jobs", query:"",
        body: JSON.stringify({ type:"service_status_refresh", ref_id:0, payload:{ source:"api_explorer" } }, null, 2),
        hint: <?= $js('api_explorer.preset.jobs_queue.hint', 'POST /jobs {type,ref_id,payload}; typ se validuje proti whitelistu.') ?> },
      { label: <?= $js('api_explorer.preset.logs_sources.label', 'Logy: zdroje') ?>, method:"GET", route:"/logs/sources", query:"", body:"", hint: <?= $js('api_explorer.preset.logs_sources.hint', 'GET /logs/sources [scope logs]') ?> },
      { label: <?= $js('api_explorer.preset.logs_nginx.label', 'Logy: číst chyby nginx') ?>, method:"GET", route:"/logs", query:"src=file:nginx_error&n=200", body:"", hint: <?= $js('api_explorer.preset.logs_nginx.hint', 'GET /logs přes sudo whitelist wrapper.') ?> },
      { label: <?= $js('api_explorer.preset.settings_keys.label', 'Nastavení: vybrané klíče') ?>, method:"GET", route:"/settings", query:"keys=sites_base_dir,wg_endpoint,php_fpm_socket", body:"", hint: <?= $js('api_explorer.preset.settings_keys.hint', 'GET /settings?keys=... [scope settings]') ?> },
      { label: <?= $js('api_explorer.preset.users_list.label', 'Uživatelé: seznam') ?>, method:"GET", route:"/users", query:"", body:"", hint: <?= $js('api_explorer.preset.users_list.hint', 'GET /users [scope users]') ?> },

      // WEB
      { label: <?= $js('api_explorer.preset.web_sites_list.label', 'Web: seznam webů (user_id)') ?>, method:"GET", route:"/sites", query:"user_id="+DEFAULT_USER_ID, body:"", hint: <?= $js('api_explorer.preset.web_sites_list.hint', 'GET /sites') ?> },
      { label: <?= $js('api_explorer.preset.web_site_detail.label', 'Web: detail webu (id)') ?>, method:"GET", route:"/sites/12", query:"", body:"", hint: <?= $js('api_explorer.preset.web_site_detail.hint', 'GET /sites/{id}') ?> },
      { label: <?= $js('api_explorer.preset.web_site_upsert.label', 'Web: vytvořit/upravit web (idempotentně)') ?>, method:"POST", route:"/sites", query:"",
        body: JSON.stringify({
          user_id: DEFAULT_USER_ID,
          domain: "demo.example.com",
          root_path: "/var/lib/oris-core/sites/demo.example.com/public",
          force_https: true,
          hsts: false,
          disabled: false
        }, null, 2),
        hint: <?= $js('api_explorer.preset.web_site_upsert.hint', 'POST /sites (idempotent: user_id+domain)') ?>
      },
      { label: <?= $js('api_explorer.preset.web_site_disable.label', 'Web: vypnout web (PATCH /sites/{id})') ?>, method:"PATCH", route:"/sites/12", query:"",
        body: JSON.stringify({ disabled:true }, null, 2),
        hint: <?= $js('api_explorer.preset.web_site_disable.hint', 'PATCH /sites/{id} {disabled:true}') ?>
      },
      { label: <?= $js('api_explorer.preset.db_ensure.label', 'DB: založit/ověřit databázi webu') ?>, method:"POST", route:"/sites/12/db/ensure", query:"",
        body: JSON.stringify({}, null, 2),
        hint: <?= $js('api_explorer.preset.db_ensure.hint', 'POST /sites/{id}/db/ensure [scope db]') ?>
      },
      { label: <?= $js('api_explorer.preset.db_reset_pass.label', 'DB: reset hesla databáze webu') ?>, method:"POST", route:"/sites/12/db/reset-pass", query:"",
        body: JSON.stringify({}, null, 2),
        hint: <?= $js('api_explorer.preset.db_reset_pass.hint', 'POST /sites/{id}/db/reset-pass [scope db]') ?>
      },

      // PROXY
      { label: <?= $js('api_explorer.preset.proxy_list.label', 'Proxy: seznam tunelů (user_id)') ?>, method:"GET", route:"/tunnels", query:"user_id="+DEFAULT_USER_ID, body:"", hint: <?= $js('api_explorer.preset.proxy_list.hint', 'GET /tunnels') ?> },
      { label: <?= $js('api_explorer.preset.proxy_upsert.label', 'Proxy: vytvořit/upravit tunel (idempotentně)') ?>, method:"POST", route:"/tunnels", query:"",
        body: JSON.stringify({
          user_id: DEFAULT_USER_ID,
          subdomain: "app.example.com",
          upstream: "http://192.168.10.6",
          force_https: true,
          hsts: false,
          disabled: false
        }, null, 2),
        hint: <?= $js('api_explorer.preset.proxy_upsert.hint', 'POST /tunnels (idempotent: user_id+subdomain)') ?>
      },
      { label: <?= $js('api_explorer.preset.proxy_disable.label', 'Proxy: vypnout tunel (PATCH /tunnels/{id})') ?>, method:"PATCH", route:"/tunnels/24", query:"",
        body: JSON.stringify({ disabled:true }, null, 2),
        hint: <?= $js('api_explorer.preset.proxy_disable.hint', 'PATCH /tunnels/{id} {disabled:true}') ?>
      },

      // FTP
      { label: <?= $js('api_explorer.preset.ftp_list.label', 'FTP: seznam účtů (user_id)') ?>, method:"GET", route:"/ftp", query:"user_id="+DEFAULT_USER_ID, body:"", hint: <?= $js('api_explorer.preset.ftp_list.hint', 'GET /ftp') ?> },
      { label: <?= $js('api_explorer.preset.ftp_create.label', 'FTP: vytvořit účet (site_id)') ?>, method:"POST", route:"/ftp", query:"",
        body: JSON.stringify({ site_id: 18 }, null, 2),
        hint: <?= $js('api_explorer.preset.ftp_create.hint', 'POST /ftp {site_id}') ?>
      },
      { label: <?= $js('api_explorer.preset.ftp_reset_pass.label', 'FTP: reset hesla (POST /ftp/{id}/reset-pass)') ?>, method:"POST", route:"/ftp/11/reset-pass", query:"",
        body: JSON.stringify({}, null, 2),
        hint: <?= $js('api_explorer.preset.ftp_reset_pass.hint', 'POST /ftp/{id}/reset-pass') ?>
      },
      { label: <?= $js('api_explorer.preset.ftp_fix_perms.label', 'FTP: opravit práva (POST /ftp/{id}/fix-perms)') ?>, method:"POST", route:"/ftp/11/fix-perms", query:"",
        body: JSON.stringify({}, null, 2),
        hint: <?= $js('api_explorer.preset.ftp_fix_perms.hint', 'POST /ftp/{id}/fix-perms') ?>
      },
      { label: <?= $js('api_explorer.preset.ftp_delete.label', 'FTP: smazat účet (DELETE /ftp/{id})') ?>, method:"DELETE", route:"/ftp/11", query:"", body:"", hint: <?= $js('api_explorer.preset.ftp_delete.hint', 'DELETE /ftp/{id}') ?> },

      // WireGuard
      { label: <?= $js('api_explorer.preset.wg_list.label', 'WG: seznam peerů') ?>, method:"GET", route:"/wg/peers", query:"", body:"", hint: <?= $js('api_explorer.preset.wg_list.hint', 'GET /wg/peers') ?> },
      { label: <?= $js('api_explorer.preset.wg_detail.label', 'WG: detail peeru (id)') ?>, method:"GET", route:"/wg/peers/5", query:"", body:"", hint: <?= $js('api_explorer.preset.wg_detail.hint', 'GET /wg/peers/{id}') ?> },

      { label: <?= $js('api_explorer.preset.wg_create_config.label', 'WG: vytvořit peer + vrátit config (generate=1)') ?>, method:"POST", route:"/wg/peers", query:"generate=1",
        body: JSON.stringify({
          name: "telefon",
          ip: "10.42.0.50",
          public_key: "",
          preshared_key: "",
          allowed_ips: "",
          is_active: true
        }, null, 2),
        hint: <?= $js('api_explorer.preset.wg_create_config.hint', 'POST /wg/peers?generate=1 (API může v odpovědi vrátit config)') ?>
      },

      { label: <?= $js('api_explorer.preset.wg_toggle.label', 'WG: přepnout peer (POST /wg/peers/{id}/toggle)') ?>, method:"POST", route:"/wg/peers/5/toggle", query:"",
        body: JSON.stringify({ is_active:false }, null, 2),
        hint: <?= $js('api_explorer.preset.wg_toggle.hint', 'POST /wg/peers/{id}/toggle') ?>
      },
      { label: <?= $js('api_explorer.preset.wg_delete.label', 'WG: smazat peer') ?>, method:"DELETE", route:"/wg/peers/5", query:"", body:"", hint: <?= $js('api_explorer.preset.wg_delete.hint', 'DELETE /wg/peers/{id}') ?> },
    ];

    function qsEscape(s){ return encodeURIComponent(s); }
    function show(elId, on){ document.getElementById(elId).style.display = on ? 'block' : 'none'; }

    function initPresets(){
      const sel = document.getElementById('api-preset');
      sel.innerHTML = '';
      PRESETS.forEach((p, i) => {
        const o = document.createElement('option');
        o.value = String(i);
        o.textContent = p.label;
        sel.appendChild(o);
      });
      sel.value = "0";
      applyPreset();
    }

    function applyPreset(){
      const idx = parseInt(document.getElementById('api-preset').value || "0", 10);
      const p = PRESETS[idx] || PRESETS[0];

      document.getElementById('api-method').value = p.method;
      document.getElementById('api-route').value = p.route;
      document.getElementById('api-query').value = p.query || "";
      document.getElementById('api-body').value = p.body || "";
      document.getElementById('preset-hint').textContent = p.hint || I18N.presetDefaultHint;

      updateBodyVisibility();
      syncPath();
      clearResponse(false);
    }

    function updateBodyVisibility(){
      const m = document.getElementById('api-method').value;
      const showBody = (m === 'POST' || m === 'PATCH' || m === 'PUT');
      document.getElementById('body-group').style.display = showBody ? 'block' : 'none';

      const hint = document.getElementById('body-hint');
      hint.textContent = showBody ? I18N.bodyMustBeJson : "";
      syncPath();
    }

    function setBodyEmptyObject(){
      document.getElementById('api-body').value = "{}";
    }

    function formatJSON(){
      const el = document.getElementById('api-body');
      const t = (el.value || '').trim();
      if (!t) return;
      try {
        const obj = JSON.parse(t);
        el.value = JSON.stringify(obj, null, 2);
      } catch (e) {
        alert(I18N.invalidJsonPrefix + e.message);
      }
    }

    function buildPath(){
      const base = (document.getElementById('api-base').value || '/api/v1/index.php').trim();
      const route = (document.getElementById('api-route').value || '/health').trim();
      const query = (document.getElementById('api-query').value || '').trim().replace(/^\?+/, '');

      const rewriteStyle = (base === '/api/v1' || base.endsWith('/api/v1'));

      if (rewriteStyle) {
        let u = base.replace(/\/+$/,'') + route;
        if (query) u += '?' + query;
        return u;
      }

      // router bez rewrite
      let u = base + '?r=' + qsEscape(route);
      if (query) u += '&' + query;
      return u;
    }

    function syncPath(){
      document.getElementById('api-path').value = buildPath();
    }

    function setStatus(code){
      const el = document.getElementById('res-status');
      el.style.display = 'inline-block';
      el.textContent = 'HTTP ' + code;

      el.classList.remove('ok','err','run');
      if (code >= 200 && code < 300) el.classList.add('ok');
      else el.classList.add('err');
    }

    function clearResponse(resetStatus=true){
      show('res-loading', false);
      show('res-json-wrap', false);
      show('res-raw-wrap', false);
      show('curl-wrap', false);
      show('res-wg-wrap', false);
      show('res-empty', true);

      document.getElementById('res-body').textContent = '';
      document.getElementById('res-raw').textContent = '';
      document.getElementById('curl-output').textContent = '';
      document.getElementById('res-wg').textContent = '';

      if (resetStatus){
        const st = document.getElementById('res-status');
        st.style.display = 'none';
        st.textContent = '';
      }
    }

    function copyText(id){
      const t = document.getElementById(id).textContent || '';
      if (!t) return;
      navigator.clipboard.writeText(t).catch(()=>alert(I18N.copyFailed));
    }

    function extractWgConfig(parsed){
      if (!parsed) return '';
      if (typeof parsed.config === 'string') return parsed.config;
      if (typeof parsed.wg_config === 'string') return parsed.wg_config;
      if (parsed.generated && typeof parsed.generated.config === 'string') return parsed.generated.config;
      if (parsed.data && typeof parsed.data.config === 'string') return parsed.data.config;
      return '';
    }

    async function sendAPIRequest(){
      const method = document.getElementById('api-method').value;
      const token = (document.getElementById('api-token').value || '').trim();
      const path = buildPath();
      const timeout = parseInt((document.getElementById('api-timeout').value || '15').trim(), 10) || 15;

      const hasBody = (method === 'POST' || method === 'PATCH' || method === 'PUT');
      const bodyText = (document.getElementById('api-body').value || '').trim();

      let body = '';
      if (hasBody) {
        const candidate = bodyText === '' ? '{}' : bodyText;
        try { JSON.parse(candidate); body = candidate; }
        catch (e) { alert(I18N.bodyInvalidJsonPrefix + e.message); return; }
      }

      clearResponse(false);
      show('res-empty', false);
      show('res-loading', true);

      try{
        const fd = new FormData();
        fd.append('api_try', '1');
        fd.append('_csrf', CSRF);
        fd.append('api_method', method);
        fd.append('api_path', path);
        fd.append('api_token_plain', token);
        fd.append('api_timeout', String(timeout));
        fd.append('api_body', body);

        const resp = await fetch(location.pathname, { method:'POST', body: fd });
        const payloadText = await resp.text();

        show('res-loading', false);

        let payload = null;
        try { payload = JSON.parse(payloadText); }
        catch(e){
          setStatus(0);
          document.getElementById('res-raw').textContent = payloadText || I18N.emptyResponse;
          show('res-raw-wrap', true);
          return;
        }

        const httpCode = (payload && typeof payload.code === 'number') ? payload.code : 0;
        setStatus(httpCode);

        document.getElementById('curl-output').textContent = payload.curl || '';
        show('curl-wrap', true);

        const apiBody = (payload && typeof payload.body === 'string') ? payload.body : '';

        try{
          const parsed = JSON.parse(apiBody);
          document.getElementById('res-body').textContent = JSON.stringify(parsed, null, 2);
          show('res-json-wrap', true);

          const cfg = extractWgConfig(parsed);
          if (cfg && cfg.trim() !== '') {
            document.getElementById('res-wg').textContent = cfg;
            show('res-wg-wrap', true);
          }
        } catch(e){
          document.getElementById('res-raw').textContent = apiBody || I18N.emptyResponse;
          show('res-raw-wrap', true);
        }

      } catch(e){
        show('res-loading', false);
        setStatus(0);
        document.getElementById('res-raw').textContent = I18N.fetchErrorPrefix + (e && e.message ? e.message : String(e));
        show('res-raw-wrap', true);
      }
    }

    ['api-base','api-route','api-query'].forEach(id=>{
      const el = document.getElementById(id);
      el.addEventListener('input', syncPath);
      el.addEventListener('change', syncPath);
    });

    initPresets();
    updateBodyVisibility();
    syncPath();
  </script>
<?php }); ?>

<?php
declare(strict_types=1);

function api_fail(int $code, string $msg): never {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['ok'=>false,'error'=>$msg], JSON_UNESCAPED_UNICODE);
  exit;
}

function api_get_bearer(): string {
  $h = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
  if(!$h && function_exists('apache_request_headers')){
    $hh = apache_request_headers();
    $h = $hh['Authorization'] ?? $hh['authorization'] ?? '';
  }
  if(!preg_match('~^Bearer\s+(.+)$~i', trim($h), $m)) return '';
  return trim($m[1]);
}

function api_auth(PDO $pdo, string $needScope): array {
  $token = api_get_bearer();
  if($token==='') api_fail(401,'Missing Bearer token');

  $hash = hash('sha256', $token);
  $st = $pdo->prepare("SELECT * FROM api_tokens WHERE token_hash=? AND is_active=1");
  $st->execute([$hash]);
  $t = $st->fetch();
  if(!$t) api_fail(401,'Invalid token');

  $scopes = json_decode((string)$t['scopes'], true);
  if(!is_array($scopes)) $scopes = [];
  if(!in_array($needScope, $scopes, true)) api_fail(403,'Missing scope: '.$needScope);

  $pdo->prepare("UPDATE api_tokens SET last_used_at=NOW() WHERE id=?")->execute([(int)$t['id']]);
  return $t; // obsahuje user_id, scopes, ...
}

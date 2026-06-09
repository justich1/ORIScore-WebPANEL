from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from ..common import atomic_write, run
from ..context import Ctx

HANDLED_TYPES = {"provision_site", "deprovision_site"}


def ensure_phpmyadmin_snippet() -> None:
    # Security Center base snippets must exist before any vhost includes them.
    try:
        from .security import ensure_security_files
        ensure_security_files(None)
    except Exception:
        Path("/etc/nginx/snippets").mkdir(parents=True, exist_ok=True)
        Path("/etc/nginx/snippets/oris-rate-limit.conf").write_text("# ORIS rate limit disabled\n", encoding="utf-8")
    path = Path("/etc/nginx/snippets/phpmyadmin.conf")
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, """location = /phpmyadmin {
    return 301 /phpmyadmin/;
}

location /phpmyadmin/ {
    alias /usr/share/phpmyadmin/;
    index index.php index.html;
    try_files $uri $uri/ /phpmyadmin/index.php?$query_string;
}

location ~ ^/phpmyadmin/(.+\\.php)$ {
    alias /usr/share/phpmyadmin/$1;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /usr/share/phpmyadmin/$1;
    fastcgi_param SCRIPT_NAME /phpmyadmin/$1;
    fastcgi_param DOCUMENT_ROOT /usr/share/phpmyadmin;
    fastcgi_pass unix:/run/php/php-fpm.sock;
}

location ~* ^/phpmyadmin/(.+\\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff|woff2|ttf|map))$ {
    alias /usr/share/phpmyadmin/$1;
    expires 7d;
    access_log off;
}
""")


def _fpm_info() -> tuple[str, Path, str]:
    dirs = sorted(Path("/etc/php").glob("*/fpm/pool.d"), key=lambda p: p.parts[-3])
    if not dirs:
        return "", Path("/etc/php/unknown/fpm/pool.d"), "php-fpm"
    pool_dir = dirs[-1]
    version = pool_dir.parts[-3]
    return version, pool_dir, f"php{version}-fpm"


def _reload_fpm(unit: str) -> None:
    rc, _ = run(["systemctl", "reload", unit], check=False)
    if rc != 0:
        run(["systemctl", "restart", unit], check=False)


PANEL_PHP_SOCKET = "/run/php/oris-panel.sock"


def ensure_panel_php_pool() -> str:
    """Zajistí stabilní PHP-FPM pool/socket pro administraci ORISu.

    Běžné weby používají vlastní oris-site-X.sock. Panel a phpMyAdmin nesmí
    záviset na aliasu /run/php/php-fpm.sock, protože ten na Debianu často
    neexistuje nebo je jen rozbitý alternatives symlink.
    """
    version, pool_dir, unit = _fpm_info()
    if not version:
        raise RuntimeError("PHP-FPM pool.d adresář nebyl nalezen v /etc/php/*/fpm/pool.d")

    pool_dir.mkdir(parents=True, exist_ok=True)
    conf = f"""[oris_panel]
user = www-data
group = www-data

listen = {PANEL_PHP_SOCKET}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = ondemand
pm.max_children = 5
pm.process_idle_timeout = 10s
pm.max_requests = 300

request_terminate_timeout = 300s

php_admin_value[memory_limit] = 1024M
php_admin_value[upload_max_filesize] = 1024M
php_admin_value[post_max_size] = 1024M
php_admin_value[max_execution_time] = 300
php_admin_value[max_input_time] = 300
php_admin_value[date.timezone] = Europe/Prague
"""

    pool_file = pool_dir / "oris_panel.conf"
    old = pool_file.read_text(encoding="utf-8", errors="ignore") if pool_file.exists() else ""
    if old != conf:
        atomic_write(pool_file, conf)

    rc, out = run([f"php-fpm{version}", "-t"], check=False)
    if rc != 0:
        raise RuntimeError(f"PHP-FPM konfigurace je chybná:\n{out}")

    _reload_fpm(unit)
    return PANEL_PHP_SOCKET


def _size(v: Any, default: str) -> str:
    s = str(v or default).strip()
    return s if re.match(r"^\d+[KMG]?$", s, re.I) else default


def _num(v: Any, default: int) -> int:
    try:
        n = int(v)
        return max(0, n)
    except Exception:
        return default


def _tz(v: Any) -> str:
    s = str(v or "Europe/Prague").strip()
    return s if re.match(r"^[A-Za-z0-9_./+-]+$", s) else "Europe/Prague"


def _ini_extra(text: Any) -> str:
    out = []
    for line in str(text or "").splitlines():
        ln = line.strip()
        if not ln or ln.startswith((";", "#")):
            continue
        if not re.match(r"^[A-Za-z0-9_.-]+\s*=", ln):
            continue
        out.append(ln)
    return "\n".join(out)


def _strip_nginx_comment(line: str) -> str:
    # Jednoduché odříznutí komentáře pro bezpečnostní kontroly.
    # Neřeší uvozovky, ale pro administrátorské extra direktivy stačí.
    return line.split("#", 1)[0]


def _nginx_extra(text: Any) -> str:
    """Vrátí bezpečně odsazené server-level extra direktivy.

    Důležité: starší verze zahazovala řádky s { } a nechala uvnitř jen
    samotné `try_files`, čímž vznikalo `try_files directive is duplicate`.
    Tady naopak povolujeme kompletní `location ... { ... }` bloky, ale
    blokujeme direktivy, které by rozbily systémový vhost.
    """
    raw = str(text or "").strip()
    if not raw:
        return ""

    banned = re.compile(r"\b(server|listen|root|ssl_certificate|ssl_certificate_key|include)\b", re.I)
    safe_lines: list[str] = []
    brace_balance = 0

    for line in raw.splitlines():
        code = _strip_nginx_comment(line)
        stripped = code.strip()

        if stripped and banned.search(stripped):
            safe_lines.append(f"# ORIS skipped unsafe directive: {line.strip()}")
            continue

        if brace_balance == 0 and re.match(r"^try_files\b", stripped):
            safe_lines.append(f"# ORIS skipped top-level try_files, vlož ho do location bloku: {line.strip()}")
            continue

        brace_balance += code.count("{") - code.count("}")
        if brace_balance < 0:
            return "\n    # ORIS custom vhost directives ignored: invalid closing brace\n"

        safe_lines.append(line.rstrip())

    if brace_balance != 0:
        return "\n    # ORIS custom vhost directives ignored: unbalanced braces\n"

    safe = "\n".join("    " + x for x in safe_lines if x.strip())
    return ("\n    # ORIS custom vhost directives\n" + safe + "\n") if safe else ""


def _has_custom_root_location(extra: str) -> bool:
    # Kolize jen s `location / { ... }`, ne s `/admin/`, `= /`, `^~ /themes/` apod.
    return bool(re.search(r"(?m)^\s*location\s+/\s*\{", extra or ""))


def _has_custom_php_location(extra: str) -> bool:
    # Když si admin definuje vlastní PHP location, nevygenerujeme druhý regex blok.
    return bool(re.search(r"(?is)^\s*location\s+[^\n{]*\.php[^\n{]*\{", extra or ""))


def _write_site_php_pool(ctx: Ctx, site: dict[str, Any], job_id: int) -> str:
    if int(site.get("php_enabled") or 1) != 1:
        return ctx.php_socket()
    version, pool_dir, unit = _fpm_info()
    pool_dir.mkdir(parents=True, exist_ok=True)
    sid = int(site["id"])
    pool_name = f"oris_site_{sid}"
    sock = f"/run/php/oris-site-{sid}.sock"
    mem = _size(site.get("php_memory_limit"), "512M")
    upload = _size(site.get("php_upload_max_filesize"), "256M")
    post = _size(site.get("php_post_max_size"), "256M")
    max_exec = _num(site.get("php_max_execution_time"), 300)
    max_input = _num(site.get("php_max_input_time"), 300)
    tz = _tz(site.get("php_timezone"))
    opcache = "1" if int(site.get("php_opcache_enabled") or 0) else "0"
    extra = _ini_extra(site.get("php_custom_ini"))
    extra_lines = ""
    if extra:
        for ln in extra.splitlines():
            k, v = ln.split("=", 1)
            extra_lines += f"php_admin_value[{k.strip()}] = {v.strip()}\n"
    conf = f"""[{pool_name}]
user = www-data
group = www-data
listen = {sock}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 10s
pm.max_requests = 500
chdir = {str(site['root_path']).rstrip('/')}
php_admin_value[memory_limit] = {mem}
php_admin_value[upload_max_filesize] = {upload}
php_admin_value[post_max_size] = {post}
php_admin_value[max_execution_time] = {max_exec}
php_admin_value[max_input_time] = {max_input}
php_admin_value[date.timezone] = {tz}
php_admin_value[opcache.enable] = {opcache}
{extra_lines}"""
    atomic_write(pool_dir / f"{pool_name}.conf", conf)
    _reload_fpm(unit)
    ctx.job_log(job_id, f"PHP pool {pool_name} zapsán: {sock}")
    return sock


def panel_vhost(ctx: Ctx) -> None:
    # Panelový vhost musí vždy používat vlastní stabilní socket.
    sock = ensure_panel_php_pool()
    try:
        ctx.exec(
            "INSERT INTO settings(k,v) VALUES('php_fpm_socket', %s) "
            "ON DUPLICATE KEY UPDATE v=VALUES(v)",
            (sock,),
        )
    except Exception:
        pass

    from .panel import write_panel_vhost
    write_panel_vhost(ctx)

def _ssl_paths(domain: str):
    cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    key = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    return cert, key


def _safe_prepare_root(root: str) -> tuple[Path, bool]:
    root_path = Path(root)
    existed = root_path.exists()
    root_path.mkdir(parents=True, exist_ok=True)
    return root_path, existed


def _write_default_index_only_once(root_path: Path) -> None:
    index_php = root_path / "index.php"
    index_html = root_path / "index.html"
    if index_php.exists() or index_html.exists():
        return
    index_php.write_text("<?php echo 'ORIS web OK: '.htmlspecialchars($_SERVER['HTTP_HOST'] ?? '', ENT_QUOTES).' / PHP '.PHP_VERSION; ?>\n", encoding="utf-8")


def _try_files(site: dict[str, Any]) -> str:
    return "try_files $uri $uri/ /index.php?$query_string;" if int(site.get("pretty_urls") or 0) == 1 else "try_files $uri $uri/ =404;"


def _php_location(sock: str) -> str:
    return f"""
    location ~ \.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:{sock};
    }}
"""


def write_site_vhost(ctx: Ctx, job_id: int, site: dict[str, Any], *, force_plain_http: bool = False) -> None:
    ensure_phpmyadmin_snippet()
    domain = str(site["domain"]).lower().strip()
    if not ctx.domain_valid(domain):
        raise RuntimeError(f"Neplatná doména: {domain}")
    root = str(site["root_path"]).rstrip("/")
    if not root or "\x00" in root or ".." in root:
        raise RuntimeError(f"Neplatná root_path: {root}")

    root_path, existed_before = _safe_prepare_root(root)
    _write_default_index_only_once(root_path)
    if not existed_before:
        run(["chown", "-R", "www-data:www-data", str(root_path.parent)], check=False)
        run(["chmod", "-R", "u+rwX,g+rwX,o-rwx", str(root_path.parent)], check=False)

    acme = ctx.ensure_acme_webroot()
    sock = _write_site_php_pool(ctx, site, job_id)
    names = f"{domain} www.{domain}"
    force_https = (int(site.get("force_https") or 0) == 1) and not force_plain_http
    hsts = int(site.get("hsts") or 0) == 1
    cert, key = _ssl_paths(domain)
    have_ssl = cert.exists() and key.exists()
    extra = _nginx_extra(site.get("nginx_extra"))
    try_files = _try_files(site)
    has_custom_root_location = _has_custom_root_location(extra)
    has_custom_php_location = _has_custom_php_location(extra)

    default_root_location = "" if has_custom_root_location else f"""
    location / {{
        {try_files}
    }}
"""
    default_php_location = "" if has_custom_php_location else _php_location(sock)

    if has_custom_root_location:
        ctx.job_log(job_id, "Vlastní vhost obsahuje `location /`; defaultní ORIS location / se negeneruje.")
    if has_custom_php_location:
        ctx.job_log(job_id, "Vlastní vhost obsahuje PHP location; defaultní ORIS PHP location se negeneruje.")

    common_site_locations = f"""
    root {root};
    index index.php index.html;

    location ^~ /backup/ {{
        deny all;
    }}
{extra}
{default_root_location}{default_php_location}
    location ~ /\\. {{
        deny all;
    }}
"""

    if force_https and have_ssl:
        http_location = """
    location / {
        return 301 https://$host$request_uri;
    }
"""
    else:
        http_location = common_site_locations
        if force_https and not have_ssl:
            ctx.job_log(job_id, "Force HTTPS zatím nevynucuji: certifikát ještě neexistuje. ACME musí zůstat dostupné přes HTTP.")

    http_block = f"""server {{
    listen 80;
    listen [::]:80;
    server_name {names};

    include snippets/phpmyadmin.conf;

    client_max_body_size 256M;
    include snippets/oris-rate-limit.conf;

    location ^~ /.well-known/acme-challenge/ {{
        root {acme};
        default_type text/plain;
        try_files $uri =404;
    }}
{http_location}}}
"""

    ssl_block = ""
    if have_ssl:
        hsts_header = '\n    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;' if hsts else ""
        ssl_block = f"""
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {names};

    include snippets/phpmyadmin.conf;

    client_max_body_size 256M;
    include snippets/oris-rate-limit.conf;

    ssl_certificate {cert};
    ssl_certificate_key {key};{hsts_header}

    location ^~ /.well-known/acme-challenge/ {{
        root {acme};
        default_type text/plain;
        try_files $uri =404;
    }}
{common_site_locations}}}
"""
    else:
        ctx.job_log(job_id, "HTTPS blok nevytvořen: certifikát ještě neexistuje.")

    avail = Path(f"/etc/nginx/sites-available/{domain}.conf")
    enabled = Path(f"/etc/nginx/sites-enabled/{domain}.conf")
    if avail.exists():
        backup = str(avail) + ".bak." + datetime.now().strftime("%Y%m%d-%H%M%S")
        avail.replace(backup)
    atomic_write(avail, http_block + ssl_block)
    if enabled.exists() or enabled.is_symlink():
        enabled.unlink()
    enabled.symlink_to(avail)
    panel_vhost(ctx)
    ctx.nginx_reload_checked()


def handle(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    typ = str(job["type"])
    site_id = int(job.get("ref_id") or 0)

    if typ == "provision_site":
        site = ctx.one("SELECT * FROM sites WHERE id=%s", (site_id,))
        if not site:
            raise RuntimeError(f"Web nenalezen: {site_id}")
        if site.get("status") == "disabled":
            Path(f"/etc/nginx/sites-enabled/{site['domain']}.conf").unlink(missing_ok=True)
            ctx.nginx_reload_checked()
            ctx.job_log(job_id, "Web je disabled, vhost vypnut.")
            return
        ctx.job_log(job_id, f"Generuji Nginx vhost/PHP pool pro {site['domain']}")
        write_site_vhost(ctx, job_id, site)
        ctx.exec("UPDATE sites SET status='active', last_error=NULL WHERE id=%s", (site_id,))
        ctx.job_log(job_id, "Web hotovo.")
        return

    if typ == "deprovision_site":
        site = ctx.one("SELECT * FROM sites WHERE id=%s", (site_id,))
        if not site:
            ctx.job_log(job_id, "Web už v DB není.")
            return
        domain = str(site["domain"])
        ctx.job_log(job_id, f"Mažu vhost {domain}")
        Path(f"/etc/nginx/sites-enabled/{domain}.conf").unlink(missing_ok=True)
        Path(f"/etc/nginx/sites-available/{domain}.conf").unlink(missing_ok=True)
        _, pool_dir, unit = _fpm_info()
        pool_file = pool_dir / f"oris_site_{site_id}.conf"
        pool_file.unlink(missing_ok=True)
        _reload_fpm(unit)
        ctx.nginx_reload_checked()
        ctx.exec("UPDATE sites SET status='cancelled' WHERE id=%s", (site_id,))
        return

    raise RuntimeError(f"Plugin site neumí job {typ}")
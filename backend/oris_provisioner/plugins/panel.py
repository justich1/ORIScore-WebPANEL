from __future__ import annotations

from pathlib import Path
from typing import Any
import ipaddress
import re

from ..common import atomic_write, run
from ..context import Ctx

HANDLED_TYPES = {"panel_apply", "panel_certbot_test", "panel_certbot_issue", "panel_config_apply"}


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "ano"}




def _size_setting(ctx: Ctx, key: str, default: str) -> str:
    value = ctx.setting(key, default).strip() or default
    return value if re.fullmatch(r"\d+[KMG]?", value, re.I) else default


def _num_setting(ctx: Ctx, key: str, default: str) -> str:
    value = ctx.setting(key, default).strip() or default
    return value if re.fullmatch(r"\d+", value) else default


def _panel_client_max_body_size(ctx: Ctx) -> str:
    return _size_setting(ctx, "panel_nginx_client_max_body_size", "2048M")


def _clean_panel_nginx_extra(extra: str) -> str:
    extra = str(extra or "").strip()
    if len(extra) > 12000:
        raise RuntimeError("Extra nginx konfigurace admin panelu je moc dlouhá.")
    forbidden = [
        r"\bserver\s*\{",
        r"\blisten\b",
        r"\broot\b",
        r"\binclude\b",
        r"\bssl_certificate\b",
        r"\bssl_certificate_key\b",
    ]
    for rx in forbidden:
        if re.search(rx, extra, re.I):
            raise RuntimeError("Extra nginx konfigurace admin panelu obsahuje zakázanou direktivu.")
    return extra


def _panel_nginx_extra_block(ctx: Ctx) -> str:
    extra = _clean_panel_nginx_extra(ctx.setting("panel_nginx_extra", ""))
    if not extra:
        return ""
    lines = ["    # ORIS_PANEL_EXTRA_BEGIN"]
    for line in extra.splitlines():
        lines.append("    " + line if line.strip() else "")
    lines.append("    # ORIS_PANEL_EXTRA_END")
    return "\n" + "\n".join(lines) + "\n"


def _ip_lines(text: Any) -> list[str]:
    out: list[str] = []
    for line in str(text or "").replace(",", "\n").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        try:
            if "/" in item:
                ipaddress.ip_network(item, strict=False)
            else:
                ipaddress.ip_address(item)
            out.append(item)
        except Exception:
            continue
    return out


def _admin_allowlist(ctx: Ctx) -> str:
    if not _truthy(ctx.setting("security_admin_allowlist_enabled", "0")):
        return ""
    ips = _ip_lines(ctx.setting("security_admin_allowlist", ""))
    if not ips:
        return ""
    lines = ["    # ORIS Security Center - admin allowlist"]
    for ip in ips:
        lines.append(f"    allow {ip};")
    lines.append("    deny all;")
    return "\n".join(lines) + "\n"

def _clean_domain(ctx: Ctx, value: Any) -> str:
    domain = str(value or "").lower().strip()
    return domain if domain and ctx.domain_valid(domain) else ""


def _ssl_paths(domain: str) -> tuple[Path, Path]:
    return Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem"), Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")


def _phpmyadmin_include() -> str:
    return "    include snippets/phpmyadmin.conf;\n"


def _acme_location(acme: str) -> str:
    return f"""
    location ^~ /.well-known/acme-challenge/ {{
        root {acme};
        default_type text/plain;
        allow all;
        try_files $uri =404;
    }}
"""


def _panel_locations(ctx: Ctx, sock: str, acme: str, *, include_phpmyadmin: bool = True) -> str:
    phpmyadmin = _phpmyadmin_include() if include_phpmyadmin else ""
    admin_acl = _admin_allowlist(ctx)
    return f"""
{phpmyadmin}
    root /var/www/oris-panel;
    index index.php index.html;
    client_max_body_size {_panel_client_max_body_size(ctx)};
    include snippets/oris-rate-limit.conf;{_panel_nginx_extra_block(ctx)}
{admin_acl}{_acme_location(acme)}
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:{sock};
    }}

    location ~ /\\.(?!well-known) {{
        deny all;
    }}
"""


def _deny_locations(ctx: Ctx, acme: str) -> str:
    # ACME necháme dostupné i na default IP vhostu, zbytek se při režimu "jen doména" nezobrazí.
    return f"""
    client_max_body_size {_panel_client_max_body_size(ctx)};
{_acme_location(acme)}
    location / {{
        return 404;
    }}
"""


def _http_server(block_name: str, server_name: str, body: str, *, default: bool = False) -> str:
    default_suffix = " default_server" if default else ""
    return (
        "server {\n"
        f"    listen 80{default_suffix};\n"
        f"    listen [::]:80{default_suffix};\n"
        f"    server_name {server_name};\n"
        f"{body}"
        "}\n\n"
    )


def _https_server(ctx: Ctx, domain: str, sock: str, acme: str, cert: Path, key: Path) -> str:
    body = _panel_locations(ctx, sock, acme, include_phpmyadmin=True)
    return (
        "server {\n"
        "    listen 443 ssl http2;\n"
        "    listen [::]:443 ssl http2;\n"
        f"    server_name {domain};\n\n"
        f"    ssl_certificate {cert};\n"
        f"    ssl_certificate_key {key};\n"
        f"{body}"
        "}\n\n"
    )


def write_panel_vhost(ctx: Ctx, *, force_plain_http: bool = False) -> None:
    from .site import ensure_phpmyadmin_snippet

    ensure_phpmyadmin_snippet()
    try:
        from .security import ensure_security_files
        ensure_security_files(ctx)
    except Exception:
        pass
    sock = ctx.php_socket()
    acme = ctx.ensure_acme_webroot()

    mode = ctx.setting("panel_access_mode", "ip").strip().lower()
    if mode not in {"ip", "ip_domain", "domain"}:
        mode = "ip"

    domain = _clean_domain(ctx, ctx.setting("panel_domain", ""))
    if mode in {"ip_domain", "domain"} and not domain:
        # Bez platné domény nesmíme uživatele odříznout od administrace.
        mode = "ip"

    force_https = _truthy(ctx.setting("panel_force_https", "0")) and not force_plain_http
    cert = key = None
    have_ssl = False
    if domain:
        cert, key = _ssl_paths(domain)
        have_ssl = cert.exists() and key.exists()

    parts: list[str] = []

    if mode == "ip":
        parts.append(_http_server("ip", "_", _panel_locations(ctx, sock, acme, include_phpmyadmin=True), default=True))

    elif mode == "ip_domain":
        # IP/default server obslouží panel i bez DNS. Doména má vlastní blok, aby šel později bezpečně redirect na HTTPS.
        parts.append(_http_server("ip", "_", _panel_locations(ctx, sock, acme, include_phpmyadmin=True), default=True))
        if force_https and have_ssl:
            domain_http_body = f"""
    client_max_body_size {_panel_client_max_body_size(ctx)};
{_acme_location(acme)}
    location / {{
        return 301 https://$host$request_uri;
    }}
"""
        else:
            domain_http_body = _panel_locations(ctx, sock, acme, include_phpmyadmin=True)
        parts.append(_http_server("domain", domain, domain_http_body, default=False))
        if have_ssl and cert and key:
            parts.append(_https_server(ctx, domain, sock, acme, cert, key))

    else:  # domain only
        parts.append(_http_server("default-deny", "_", _deny_locations(ctx, acme), default=True))
        if force_https and have_ssl:
            domain_http_body = f"""
    client_max_body_size {_panel_client_max_body_size(ctx)};
{_acme_location(acme)}
    location / {{
        return 301 https://$host$request_uri;
    }}
"""
        else:
            domain_http_body = _panel_locations(ctx, sock, acme, include_phpmyadmin=True)
        parts.append(_http_server("domain", domain, domain_http_body, default=False))
        if have_ssl and cert and key:
            parts.append(_https_server(ctx, domain, sock, acme, cert, key))

    conf = "".join(parts)
    atomic_write("/etc/nginx/sites-available/oris-panel.conf", conf)
    Path("/etc/nginx/sites-enabled/default").unlink(missing_ok=True)
    enabled = Path("/etc/nginx/sites-enabled/oris-panel.conf")
    if enabled.exists() or enabled.is_symlink():
        enabled.unlink()
    enabled.symlink_to("/etc/nginx/sites-available/oris-panel.conf")


def _ensure_test_file(ctx: Ctx) -> None:
    acme = Path(ctx.ensure_acme_webroot()) / ".well-known/acme-challenge/oris-panel-test.txt"
    acme.parent.mkdir(parents=True, exist_ok=True)
    acme.write_text("ORIS-PANEL-ACME-OK\n", encoding="utf-8")
    run(["chown", "-R", "www-data:www-data", str(acme.parents[2])], check=False)


def _test_acme(ctx: Ctx, job_id: int, domain: str) -> None:
    _ensure_test_file(ctx)
    url = f"http://{domain}/.well-known/acme-challenge/oris-panel-test.txt"
    rc, out = run(["curl", "-fsS", "--max-time", "10", url], check=False)
    if rc != 0 or "ORIS-PANEL-ACME-OK" not in out:
        raise RuntimeError(f"ACME test administrace selhal: {url}\n{out}")
    ctx.job_log(job_id, f"ACME test administrace OK: {domain}")


def _issue_cert(ctx: Ctx, job_id: int, domain: str) -> None:
    email = ctx.setting("certbot_email", "").strip()
    cmd = [
        "certbot", "certonly", "--webroot",
        "-w", ctx.setting("acme_webroot", "/var/www/letsencrypt"),
        "--non-interactive", "--agree-tos", "--keep-until-expiring",
        "--cert-name", domain,
        "-d", domain,
    ]
    if email:
        cmd += ["-m", email]
    else:
        cmd += ["--register-unsafely-without-email"]
    ctx.job_log(job_id, "Spouštím: " + " ".join(cmd))
    rc, out = run(cmd, check=False)
    ctx.job_log(job_id, out.strip() or f"certbot exit={rc}")
    if rc != 0:
        ctx.set_setting("panel_ssl_status", "error")
        ctx.set_setting("panel_ssl_last_error", out[-4000:])
        raise RuntimeError(f"Certbot pro administraci selhal exit={rc}")
    ctx.set_setting("panel_ssl_status", "active")
    ctx.set_setting("panel_ssl_last_error", "")



def _panel_php_version(ctx: Ctx) -> str:
    ver = ctx.setting("panel_php_version", "").strip()
    if ver and re.fullmatch(r"\d+\.\d+", ver):
        return ver
    dirs = sorted(Path("/etc/php").glob("*/fpm"), key=lambda p: p.parts[-2])
    if not dirs:
        raise RuntimeError("Nenalezeno /etc/php/*/fpm")
    return dirs[-1].parts[-2]


def apply_panel_config(ctx: Ctx, job_id: int) -> None:
    ver = _panel_php_version(ctx)
    confd = Path(f"/etc/php/{ver}/fpm/conf.d")
    if not confd.is_dir():
        raise RuntimeError(f"Neexistuje PHP-FPM conf.d: {confd}")

    timezone = ctx.setting("panel_php_timezone", "Europe/Prague").strip() or "Europe/Prague"
    if not re.fullmatch(r"[A-Za-z0-9_./+-]+", timezone):
        raise RuntimeError("Neplatná timezone pro admin panel.")

    ini = f"""; ORIS admin panel PHP-FPM overrides
; Generated by ORIS provisioner. Do not edit manually.

enable_post_data_reading = On
memory_limit = {_size_setting(ctx, 'panel_php_memory_limit', '1024M')}
upload_max_filesize = {_size_setting(ctx, 'panel_php_upload_max_filesize', '1024M')}
post_max_size = {_size_setting(ctx, 'panel_php_post_max_size', '1024M')}
max_execution_time = {_num_setting(ctx, 'panel_php_max_execution_time', '300')}
max_input_time = {_num_setting(ctx, 'panel_php_max_input_time', '300')}
max_file_uploads = {_num_setting(ctx, 'panel_php_max_file_uploads', '20')}
date.timezone = {timezone}
"""
    atomic_write(confd / "zz-oris-admin-panel.ini", ini)
    ctx.job_log(job_id, f"Zapsáno PHP nastavení panelu: {confd / 'zz-oris-admin-panel.ini'}")

    unit = f"php{ver}-fpm"
    rc, out = run(["systemctl", "restart", unit], check=False)
    ctx.job_log(job_id, out.strip() or f"Restart {unit}: exit={rc}")
    if rc != 0:
        raise RuntimeError(f"Restart PHP-FPM selhal: {unit}")

    write_panel_vhost(ctx)
    ctx.nginx_reload_checked()
    ctx.job_log(job_id, f"Nastavení admin panelu aplikováno. nginx client_max_body_size={_panel_client_max_body_size(ctx)}")


def handle(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    typ = str(job["type"])
    domain = _clean_domain(ctx, ctx.setting("panel_domain", ""))

    if typ == "panel_config_apply":
        apply_panel_config(ctx, job_id)
        return

    if typ == "panel_apply":
        write_panel_vhost(ctx)
        ctx.nginx_reload_checked()
        ctx.job_log(job_id, "Administrace přegenerována podle nastavení.")
        return

    if typ in {"panel_certbot_test", "panel_certbot_issue"}:
        if not domain:
            raise RuntimeError("Pro certifikát administrace nastav platnou panel_domain.")
        # Při ACME testu/vystavení nesmí HTTP admin doména přesměrovávat na HTTPS.
        write_panel_vhost(ctx, force_plain_http=True)
        ctx.nginx_reload_checked()
        _test_acme(ctx, job_id, domain)
        if typ == "panel_certbot_issue":
            _issue_cert(ctx, job_id, domain)
            write_panel_vhost(ctx)
            ctx.nginx_reload_checked()
            ctx.job_log(job_id, "Certifikát administrace vystaven a panelový vhost přegenerován.")
        return

    raise RuntimeError(f"Plugin panel neumí job {typ}")

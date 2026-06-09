from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

from ..common import atomic_write, run
from ..context import Ctx
from .site import panel_vhost

HANDLED_TYPES = {"provision_tunnel", "deprovision_tunnel"}


def _valid_upstream(value: Any) -> str:
    upstream = str(value or "").strip().rstrip("/")
    parsed = urlparse(upstream)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError(f"Neplatný upstream: {upstream}. Musí být http(s)://host[:port]")
    if any(ch in upstream for ch in ['"', "'", "`", "\n", "\r", "\t", " "]):
        raise RuntimeError(f"Neplatný upstream: {upstream}")
    return upstream


def _ssl_paths(domain: str) -> tuple[Path, Path]:
    cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    key = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    return cert, key


def _proxy_locations(upstream: str, *, forwarded_proto: str = "$scheme", forwarded_port: str = "$server_port") -> str:
    parsed = urlparse(upstream)

    # Když je backend HTTPS a běží třeba na IP se self-signed certifikátem,
    # potřebujeme poslat SNI podle veřejné proxy domény ($host).
    # Jinak Apache/Nginx backend často vrací 421 Misdirected Request.
    ssl_part = ""
    if parsed.scheme == "https":
        ssl_part = """
        proxy_ssl_verify off;
        proxy_ssl_server_name on;
        proxy_ssl_name $host;
"""

    forwarded_ssl = ""
    if forwarded_proto == "https":
        forwarded_ssl = "\n        proxy_set_header X-Forwarded-Ssl on;"

    return f"""
    location / {{
        proxy_pass {upstream};
{ssl_part}        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto {forwarded_proto};
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port {forwarded_port};{forwarded_ssl}

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_redirect off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
"""


def _write_proxy_vhost(ctx: Ctx, job_id: int, tunnel: dict[str, Any], *, force_plain_http: bool = False) -> None:
    domain = str(tunnel["subdomain"]).lower().strip()
    if not ctx.domain_valid(domain):
        raise RuntimeError(f"Neplatná proxy doména: {domain}")

    upstream = _valid_upstream(tunnel.get("upstream"))
    acme = ctx.ensure_acme_webroot()
    cert, key = _ssl_paths(domain)
    have_ssl = cert.exists() and key.exists()
    force_https = (int(tunnel.get("force_https") or 0) == 1) and not force_plain_http
    hsts = int(tunnel.get("hsts") or 0) == 1

    if force_https and have_ssl:
        http_location = """
    location / {
        return 301 https://$host$request_uri;
    }
"""
    else:
        http_location = _proxy_locations(upstream)
        if force_https and not have_ssl:
            ctx.job_log(job_id, "Force HTTPS zatím nevynucuji: certifikát ještě neexistuje. ACME musí zůstat dostupné přes HTTP.")

    http_block = f"""server {{
    listen 80;
    listen [::]:80;
    server_name {domain};


    client_max_body_size 256M;

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
    server_name {domain};


    client_max_body_size 256M;

    ssl_certificate {cert};
    ssl_certificate_key {key};{hsts_header}

    location ^~ /.well-known/acme-challenge/ {{
        root {acme};
        default_type text/plain;
        try_files $uri =404;
    }}
{_proxy_locations(upstream, forwarded_proto="https", forwarded_port="443")}}}
"""
    else:
        ctx.job_log(job_id, "HTTPS blok pro proxy nevytvořen: certifikát ještě neexistuje.")

    avail = Path(f"/etc/nginx/sites-available/{domain}.conf")
    enabled = Path(f"/etc/nginx/sites-enabled/{domain}.conf")
    backup = None
    if avail.exists():
        backup = Path(str(avail) + ".bak." + datetime.now().strftime("%Y%m%d-%H%M%S"))
        avail.replace(backup)

    try:
        atomic_write(avail, http_block + ssl_block)
        if enabled.exists() or enabled.is_symlink():
            enabled.unlink()
        enabled.symlink_to(avail)
        panel_vhost(ctx)
        ctx.nginx_reload_checked()
    except Exception:
        if enabled.exists() or enabled.is_symlink():
            enabled.unlink(missing_ok=True)
        if backup and backup.exists():
            backup.replace(avail)
            enabled.symlink_to(avail)
            run(["nginx", "-t"], check=False)
            run(["systemctl", "reload", "nginx"], check=False)
        else:
            avail.unlink(missing_ok=True)
            run(["nginx", "-t"], check=False)
        raise


def handle(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    typ = str(job["type"])
    tunnel_id = int(job.get("ref_id") or 0)

    if typ == "provision_tunnel":
        tunnel = ctx.one("SELECT * FROM tunnels WHERE id=%s", (tunnel_id,))
        if not tunnel:
            raise RuntimeError(f"Proxy nenalezena: {tunnel_id}")

        domain = str(tunnel["subdomain"])
        if tunnel.get("status") == "disabled":
            Path(f"/etc/nginx/sites-enabled/{domain}.conf").unlink(missing_ok=True)
            ctx.nginx_reload_checked()
            ctx.exec("UPDATE tunnels SET last_error=NULL WHERE id=%s", (tunnel_id,))
            ctx.job_log(job_id, "Proxy je disabled, vhost vypnut.")
            return

        ctx.job_log(job_id, f"Generuji Nginx reverse proxy {domain} -> {tunnel['upstream']}")
        _write_proxy_vhost(ctx, job_id, tunnel)
        ctx.exec("UPDATE tunnels SET status='active', last_error=NULL WHERE id=%s", (tunnel_id,))
        ctx.job_log(job_id, "Proxy hotovo.")
        return

    if typ == "deprovision_tunnel":
        tunnel = ctx.one("SELECT * FROM tunnels WHERE id=%s", (tunnel_id,))
        if not tunnel:
            ctx.job_log(job_id, "Proxy už v DB není.")
            return

        domain = str(tunnel["subdomain"])
        ctx.job_log(job_id, f"Mažu proxy vhost {domain}")
        Path(f"/etc/nginx/sites-enabled/{domain}.conf").unlink(missing_ok=True)
        Path(f"/etc/nginx/sites-available/{domain}.conf").unlink(missing_ok=True)
        ctx.nginx_reload_checked()
        ctx.exec("DELETE FROM tunnels WHERE id=%s", (tunnel_id,))
        ctx.job_log(job_id, "Proxy byla úplně smazána.")
        return

    raise RuntimeError(f"Plugin proxy neumí job {typ}")


def write_proxy_vhost(ctx: Ctx, job_id: int, tunnel: dict[str, Any], *, force_plain_http: bool = False) -> None:
    _write_proxy_vhost(ctx, job_id, tunnel, force_plain_http=force_plain_http)

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from ..common import run
from ..context import Ctx
from .site import write_site_vhost
from .proxy import write_proxy_vhost

HANDLED_TYPES = {
    "certbot_test_acme",
    "certbot_issue",
    "certbot_test_acme_proxy",
    "certbot_issue_proxy",
    "certbot_renew_all",
    "certbot_dry_run",
}


def _payload(job: dict) -> dict:
    p = job.get("payload")
    if isinstance(p, dict):
        return p
    if isinstance(p, str) and p.strip():
        try:
            return json.loads(p)
        except Exception:
            return {}
    return {}


def _site(ctx: Ctx, site_id: int) -> dict:
    row = ctx.one("SELECT * FROM sites WHERE id=%s", (site_id,))
    if not row:
        raise RuntimeError(f"Web nenalezen: {site_id}")
    return row


def _proxy(ctx: Ctx, tunnel_id: int) -> dict:
    row = ctx.one("SELECT * FROM tunnels WHERE id=%s", (tunnel_id,))
    if not row:
        raise RuntimeError(f"Proxy nenalezena: {tunnel_id}")
    return row


def _public_ipv4_candidates() -> set[str]:
    ips = set()
    for cmd in (["ip", "-4", "addr"], ["hostname", "-I"]):
        rc, out = run(cmd, check=False)
        if rc == 0:
            for token in out.replace("/", " ").split():
                parts = token.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    if not token.startswith(("127.", "10.", "192.168.", "172.16.")):
                        ips.add(token)
                    elif token.startswith(("89.", "80.")):
                        ips.add(token)
    return ips


def _dns_a(host: str) -> list[str]:
    try:
        return sorted({x[4][0] for x in socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)})
    except Exception:
        return []


def _domains_for_base(domain: str, payload: dict, *, default_www: bool) -> list[str]:
    domain = str(domain).lower().strip()
    domains = [domain]
    include_www = payload.get("include_www")
    if include_www is None:
        include_www = default_www
    if include_www and not domain.startswith("www."):
        domains.append("www." + domain)
    return domains


def _ensure_test_file(ctx: Ctx) -> str:
    acme = ctx.ensure_acme_webroot()
    test = Path(acme) / ".well-known/acme-challenge/oris-test.txt"
    test.parent.mkdir(parents=True, exist_ok=True)
    test.write_text("ORIS-ACME-OK\n", encoding="utf-8")
    run(["chown", "-R", "www-data:www-data", acme], check=False)
    return str(test)


def _validate_dns(ctx: Ctx, job_id: int, domains: list[str]) -> None:
    candidates = _public_ipv4_candidates()
    ctx.job_log(job_id, "Veřejné/lokální IPv4 kandidáti serveru: " + (", ".join(sorted(candidates)) if candidates else "nenalezeno"))
    for d in domains:
        ips = _dns_a(d)
        ctx.job_log(job_id, f"DNS A {d}: " + (", ".join(ips) if ips else "nenalezeno"))
        if candidates and ips and not (set(ips) & candidates):
            ctx.job_log(job_id, f"VAROVÁNÍ: {d} nemíří na detekované IP serveru.")


def _curl_acme(ctx: Ctx, job_id: int, domains: list[str]) -> None:
    _ensure_test_file(ctx)
    for d in domains:
        url = f"http://{d}/.well-known/acme-challenge/oris-test.txt"
        rc, out = run(["curl", "-fsS", "--max-time", "10", url], check=False)
        if rc != 0 or "ORIS-ACME-OK" not in out:
            raise RuntimeError(f"ACME test selhal pro {d}: {url}\n{out}")
        ctx.job_log(job_id, f"ACME test OK: {d}")


def _certbot_cmd(ctx: Ctx, cert_name: str, domains: list[str], email: str) -> list[str]:
    cmd = [
        "certbot", "certonly", "--webroot",
        "-w", ctx.setting("acme_webroot", "/var/www/letsencrypt"),
        "--non-interactive", "--agree-tos", "--keep-until-expiring",
        "--cert-name", cert_name,
    ]
    if email:
        cmd += ["-m", email]
    else:
        cmd += ["--register-unsafely-without-email"]
    for d in domains:
        cmd += ["-d", d]
    return cmd


def _issue(ctx: Ctx, job_id: int, cert_name: str, domains: list[str], email: str) -> tuple[int, str]:
    cmd = _certbot_cmd(ctx, cert_name, domains, email)
    ctx.job_log(job_id, "Spouštím: " + " ".join(cmd))
    return run(cmd, check=False)


def _handle_site(ctx: Ctx, job: dict, *, issue: bool) -> None:
    job_id = int(job["id"])
    ref = int(job.get("ref_id") or 0)
    payload = _payload(job)
    site = _site(ctx, ref)
    domain = str(site["domain"]).lower().strip()
    domains = _domains_for_base(domain, payload, default_www=True)

    ctx.job_log(job_id, "Připravuji HTTP vhost a ACME webroot pro web.")
    write_site_vhost(ctx, job_id, site, force_plain_http=True)
    _validate_dns(ctx, job_id, domains)
    _curl_acme(ctx, job_id, domains)
    if not issue:
        ctx.job_log(job_id, "ACME test hotový.")
        return

    email = str(payload.get("email") or ctx.setting("certbot_email", ""))
    rc, out = _issue(ctx, job_id, domain, domains, email)
    ctx.job_log(job_id, out.strip() or f"certbot exit={rc}")
    if rc != 0:
        ctx.exec("UPDATE sites SET ssl_status='error', ssl_last_error=%s WHERE id=%s", (out[-4000:], ref))
        raise RuntimeError(f"Certbot selhal exit={rc}")
    ctx.exec("UPDATE sites SET ssl_status='active', ssl_last_error=NULL WHERE id=%s", (ref,))
    site = _site(ctx, ref)
    write_site_vhost(ctx, job_id, site)
    ctx.job_log(job_id, "Certifikát webu vystaven a vhost přegenerován s HTTPS.")


def _handle_proxy(ctx: Ctx, job: dict, *, issue: bool) -> None:
    job_id = int(job["id"])
    ref = int(job.get("ref_id") or 0)
    payload = _payload(job)
    tunnel = _proxy(ctx, ref)
    domain = str(tunnel["subdomain"]).lower().strip()
    # U proxy je www defaultně vypnuté. Certifikát pro www proxy dává smysl jen výjimečně.
    domains = _domains_for_base(domain, payload, default_www=False)

    ctx.job_log(job_id, f"Připravuji HTTP proxy vhost a ACME webroot pro {domain}.")
    write_proxy_vhost(ctx, job_id, tunnel, force_plain_http=True)
    _validate_dns(ctx, job_id, domains)
    _curl_acme(ctx, job_id, domains)
    if not issue:
        ctx.job_log(job_id, "ACME test proxy hotový.")
        return

    email = str(payload.get("email") or ctx.setting("certbot_email", ""))
    rc, out = _issue(ctx, job_id, domain, domains, email)
    ctx.job_log(job_id, out.strip() or f"certbot exit={rc}")
    if rc != 0:
        ctx.exec("UPDATE tunnels SET ssl_status='error', ssl_last_error=%s WHERE id=%s", (out[-4000:], ref))
        raise RuntimeError(f"Certbot proxy selhal exit={rc}")
    ctx.exec("UPDATE tunnels SET ssl_status='active', ssl_last_error=NULL WHERE id=%s", (ref,))
    tunnel = _proxy(ctx, ref)
    write_proxy_vhost(ctx, job_id, tunnel)
    ctx.job_log(job_id, "Certifikát proxy vystaven a proxy vhost přegenerován s HTTPS.")


def handle(ctx: Ctx, job: dict) -> None:
    job_id = int(job["id"])
    typ = str(job["type"])

    if typ == "certbot_test_acme":
        _handle_site(ctx, job, issue=False)
        return

    if typ == "certbot_issue":
        _handle_site(ctx, job, issue=True)
        return

    if typ == "certbot_test_acme_proxy":
        _handle_proxy(ctx, job, issue=False)
        return

    if typ == "certbot_issue_proxy":
        _handle_proxy(ctx, job, issue=True)
        return

    if typ == "certbot_renew_all":
        rc, out = run(["certbot", "renew"], check=False)
        ctx.job_log(job_id, out.strip() or f"renew exit={rc}")
        if rc != 0:
            raise RuntimeError(f"certbot renew selhal exit={rc}")
        # Po renewu znovu reloadnout nginx. Vhosty už cert cesty obsahují.
        ctx.nginx_reload_checked()
        ctx.job_log(job_id, "Certbot renew hotovo.")
        return

    if typ == "certbot_dry_run":
        rc, out = run(["certbot", "renew", "--dry-run"], check=False)
        ctx.job_log(job_id, out.strip() or f"dry-run exit={rc}")
        if rc != 0:
            raise RuntimeError(f"certbot dry-run selhal exit={rc}")
        return

    raise RuntimeError(f"Plugin certbot neumí job {typ}")

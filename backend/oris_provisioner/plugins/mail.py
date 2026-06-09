from __future__ import annotations

import json
import os
import re
import grp
import tarfile
import zipfile
import shutil
import tempfile
from datetime import datetime
import pwd
import socket
from pathlib import Path
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

from ..common import atomic_write, run
from ..context import Ctx

HANDLED_TYPES = {
    "mail_stack_apply",
    "mail_stack_test",
    "mail_roundcube_apply",
    "mail_roundcube_test",
    "mail_domain_apply",
    "mail_domain_remove",
    "mail_domain_dkim_regen",
    "mail_domain_certbot_issue",
    "mailbox_apply",
    "mailbox_set_password",
    "mail_backup_full",
    "mail_restore_full",
    "mail_restore_zip",
    "mail_bayes_backup",
    "mail_bayes_restore",
    "mail_backup_delete",
    "mail_bayes_backup_delete",
}


def _payload(job: dict[str, Any]) -> dict[str, Any]:
    p = job.get("payload")
    if isinstance(p, dict):
        return p
    if isinstance(p, str) and p.strip():
        try:
            return json.loads(p)
        except Exception:
            return {}
    return {}


def _mail_db_cfg(ctx: Ctx) -> dict[str, Any]:
    cfg = ctx.cfg.get("mail_db") or {}
    if not cfg.get("name") or not cfg.get("user"):
        raise RuntimeError("Mail DB není v /etc/oris-panel/provisioner.json nastavena")
    return cfg


def _mail_conn(ctx: Ctx):
    cfg = _mail_db_cfg(ctx)
    return pymysql.connect(
        host=cfg.get("host", "127.0.0.1"),
        port=int(cfg.get("port", 3306)),
        user=cfg.get("user", ""),
        password=cfg.get("pass", ""),
        database=cfg.get("name"),
        charset="utf8mb4",
        autocommit=True,
        cursorclass=DictCursor,
    )


def _mail_one(ctx: Ctx, sql: str, args: tuple[Any, ...] = ()): 
    with _mail_conn(ctx) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchone()


def _mail_all(ctx: Ctx, sql: str, args: tuple[Any, ...] = ()): 
    with _mail_conn(ctx) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchall()


def _mail_exec(ctx: Ctx, sql: str, args: tuple[Any, ...] = ()) -> int:
    with _mail_conn(ctx) as conn:
        with conn.cursor() as cur:
            return cur.execute(sql, args)


def _setting_bool(ctx: Ctx, key: str, default: bool = False) -> bool:
    return ctx.setting(key, "1" if default else "0") in {"1", "true", "yes", "on"}


def _vmail_ids() -> tuple[int, int]:
    try:
        uid = pwd.getpwnam("vmail").pw_uid
    except KeyError:
        uid = 5000
    try:
        gid = grp.getgrnam("mail").gr_gid
    except KeyError:
        gid = 8
    return uid, gid


def _ensure_dirs(ctx: Ctx) -> None:
    vroot = ctx.setting("vmail_root", "/var/vmail").rstrip("/")
    keydir = ctx.setting("dkim_key_dir", "/var/lib/rspamd/dkim").rstrip("/")
    for p in [vroot, keydir, "/var/www/oris-mail-info", "/var/www/letsencrypt/.well-known/acme-challenge"]:
        Path(p).mkdir(parents=True, exist_ok=True)
    run(["id", "vmail"], check=False)
    if run(["id", "vmail"], check=False)[0] != 0:
        run(["useradd", "-r", "-u", "5000", "-g", "mail", "-d", vroot, "-s", "/usr/sbin/nologin", "vmail"], check=False)
    run(["chown", "-R", "vmail:mail", vroot], check=False)
    run(["chmod", "770", vroot], check=False)
    run(["chown", "-R", "_rspamd:_rspamd", keydir], check=False)
    run(["chmod", "750", keydir], check=False)


def _mysql_maps(ctx: Ctx) -> None:
    cfg = _mail_db_cfg(ctx)
    host = cfg.get("host", "127.0.0.1")
    port = str(cfg.get("port", 3306))
    name = cfg.get("name", "oris_mail")
    user = cfg.get("user", "oris_mail")
    pw = cfg.get("pass", "")
    base = f"user = {user}\npassword = {pw}\nhosts = {host}\ndbname = {name}\n"
    files = {
        "/etc/postfix/mysql-virtual-mailbox-domains.cf": base + "query = SELECT 1 FROM domains WHERE domain='%s' AND is_active=1\n",
        "/etc/postfix/mysql-virtual-mailbox-maps.cf": base + "query = SELECT maildir FROM mailboxes WHERE email='%s' AND is_active=1\n",
        "/etc/postfix/mysql-virtual-aliases.cf": base + "query = SELECT destination FROM aliases WHERE source='%s' AND is_active=1\n",
    }
    for path, content in files.items():
        atomic_write(path, content, 0o640)
        run(["chown", "root:postfix", path], check=False)


def _write_dovecot_sql(ctx: Ctx) -> None:
    cfg = _mail_db_cfg(ctx)
    uid, gid = _vmail_ids()
    content = f"""driver = mysql
connect = host={cfg.get('host','127.0.0.1')} dbname={cfg.get('name','oris_mail')} user={cfg.get('user','oris_mail')} password={cfg.get('pass','')}
default_pass_scheme = {ctx.setting('dovecot_hash_scheme','BLF-CRYPT')}
password_query = SELECT email AS user, pass_hash AS password FROM mailboxes WHERE email='%u' AND is_active=1
user_query = SELECT CONCAT('{ctx.setting('vmail_root','/var/vmail').rstrip('/')}/', SUBSTRING_INDEX(email, '@', -1), '/', local_part) AS home, CONCAT('maildir:{ctx.setting('vmail_root','/var/vmail').rstrip('/')}/', SUBSTRING_INDEX(email, '@', -1), '/', local_part) AS mail, {uid} AS uid, {gid} AS gid FROM mailboxes WHERE email='%u' AND is_active=1
"""
    atomic_write("/etc/dovecot/dovecot-sql.conf.ext", content, 0o640)
    run(["chown", "root:dovecot", "/etc/dovecot/dovecot-sql.conf.ext"], check=False)


def _write_dovecot(ctx: Ctx) -> None:
    vroot = ctx.setting("vmail_root", "/var/vmail").rstrip("/")
    auth = f"""# ORIS virtual mail auth
mail_location = maildir:{vroot}/%d/%n
mail_privileged_group = mail
disable_plaintext_auth = no
auth_mechanisms = plain login

passdb {{
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}}

userdb {{
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}}
"""
    lmtp = """# ORIS Postfix integration
protocols = imap lmtp sieve

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
"""
    atomic_write("/etc/dovecot/conf.d/99-oris-auth.conf", auth)
    atomic_write("/etc/dovecot/conf.d/99-oris-lmtp.conf", lmtp)
    _write_dovecot_sql(ctx)


def _write_rspamd(ctx: Ctx) -> None:
    keydir = ctx.setting("dkim_key_dir", "/var/lib/rspamd/dkim").rstrip("/")
    selector = ctx.setting("dkim_selector", "s1")
    Path("/etc/rspamd/local.d").mkdir(parents=True, exist_ok=True)
    actions = f"""reject = {int(ctx.setting('mail.rspamd.reject_score','15'))};
add_header = {int(ctx.setting('mail.rspamd.add_header_score','6'))};
greylist = {int(ctx.setting('mail.rspamd.greylist_score','4'))};
rewrite_subject = {int(ctx.setting('mail.rspamd.rewrite_subject_score','7'))};
"""
    atomic_write("/etc/rspamd/local.d/actions.conf", actions)
    metrics = f"""symbols {{
  symbol "BAYES_SPAM" {{ weight = {float(ctx.setting('mail.rspamd.score.BAYES_SPAM','4.0'))}; }}
  symbol "BAYES_HAM"  {{ weight = {float(ctx.setting('mail.rspamd.score.BAYES_HAM','-1.0'))}; }}
}}
"""
    atomic_write("/etc/rspamd/local.d/metrics.conf", metrics)
    signing = f"""enabled = true;
path = "{keydir}/$domain.{selector}.key";
selector = "{selector}";
allow_username_mismatch = true;
allow_hdrfrom_mismatch = false;
sign_authenticated = true;
sign_local = true;
use_domain = "header";
try_fallback = true;
"""
    atomic_write("/etc/rspamd/local.d/dkim_signing.conf", signing)
    milter_headers = """extended_spam_headers = true;
use = ["authentication-results", "x-spamd-result", "x-spam-status", "x-rspamd-server", "x-rspamd-queue-id"];
authenticated_headers = ["authentication-results"];
"""
    atomic_write("/etc/rspamd/local.d/milter_headers.conf", milter_headers)


def _postconf(key: str, value: str) -> None:
    run(["postconf", "-e", f"{key}={value}"], check=False)


def _write_postfix(ctx: Ctx) -> None:
    uid, gid = _vmail_ids()
    hostname = ctx.setting("mail.postfix.myhostname", "") or socket.getfqdn()
    milter = ctx.setting("mail.rspamd.milter", "127.0.0.1:11332")
    aliases_on = _setting_bool(ctx, "mail.postfix.aliases.enabled", True)
    tls_cert = ctx.setting("mail.postfix.tls_cert", "/etc/ssl/certs/ssl-cert-snakeoil.pem")
    tls_key = ctx.setting("mail.postfix.tls_key", "/etc/ssl/private/ssl-cert-snakeoil.key")
    _mysql_maps(ctx)
    settings = {
        "myhostname": hostname,
        "mydestination": "localhost",
        "virtual_mailbox_domains": "mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf",
        "virtual_mailbox_maps": "mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf",
        "virtual_transport": "lmtp:unix:private/dovecot-lmtp",
        "virtual_uid_maps": f"static:{uid}",
        "virtual_gid_maps": f"static:{gid}",
        "smtpd_sasl_type": "dovecot",
        "smtpd_sasl_path": "private/auth",
        "smtpd_sasl_auth_enable": "yes",
        "smtpd_tls_security_level": "may",
        "smtpd_tls_cert_file": tls_cert,
        "smtpd_tls_key_file": tls_key,
        "smtpd_milters": f"inet:{milter}",
        "non_smtpd_milters": f"inet:{milter}",
        "milter_protocol": "6",
        "milter_default_action": "accept",
        "local_recipient_maps": "$virtual_mailbox_maps",
    }
    if aliases_on:
        settings["virtual_alias_maps"] = "mysql:/etc/postfix/mysql-virtual-aliases.cf"
    else:
        settings["virtual_alias_maps"] = ""
    for k, v in settings.items():
        _postconf(k, v)


def _roundcube_root() -> str:
    for p in ["/var/lib/roundcube/public_html", "/var/lib/roundcube", "/usr/share/roundcube"]:
        if Path(p, "index.php").exists():
            return p
    return "/usr/share/roundcube"


def _write_roundcube_config(ctx: Ctx) -> None:
    cfg = ctx.cfg.get("roundcube_db") or {}
    pw = cfg.get("pass", "")
    db = cfg.get("name", "roundcube")
    user = cfg.get("user", "roundcube")
    junk = ctx.setting("mail.roundcube.junk_mbox", "Junk")
    plugins = "['archive', 'zipdownload', 'markasjunk']" if _setting_bool(ctx, "mail.roundcube.enabled", True) else "['archive', 'zipdownload']"
    des = ctx.setting("roundcube_des_key", "")
    if not des:
        import secrets, string
        chars = string.ascii_letters + string.digits
        des = "".join(secrets.choice(chars) for _ in range(24))
        ctx.set_setting("roundcube_des_key", des)
    content = f"""<?php
$config = [];
$config['db_dsnw'] = 'mysql://{user}:{pw}@localhost/{db}';

// IMAP na lokálním Dovecotu. Ponecháváme staré i nové názvy voleb kvůli kompatibilitě Debian/Roundcube balíků.
$config['imap_host'] = 'localhost:143';
$config['default_host'] = 'localhost';
$config['default_port'] = 143;

// SMTP přes lokální Postfix bez SMTP autentizace. Roundcube běží na stejném serveru.
$config['smtp_host'] = '127.0.0.1:25';
$config['smtp_server'] = '127.0.0.1';
$config['smtp_port'] = 25;
$config['smtp_user'] = '';
$config['smtp_pass'] = '';
$config['smtp_auth_type'] = null;

$config['support_url'] = '';
$config['product_name'] = 'ORIS Webmail';
$config['des_key'] = '{des}';
$config['plugins'] = {plugins};
$config['junk_mbox'] = '{junk}';
$config['default_folders'] = ['INBOX', 'Drafts', 'Sent', '{junk}', 'Trash', 'Archive'];
"""
    atomic_write("/etc/roundcube/config.inc.php", content, 0o640)
    run(["chown", "root:www-data", "/etc/roundcube/config.inc.php"], check=False)


def apply_stack(ctx: Ctx, job_id: int) -> None:
    ctx.job_log(job_id, "Nastavuji mail stack: Postfix, Dovecot, Rspamd, Roundcube")
    _ensure_dirs(ctx)
    _write_postfix(ctx)
    _write_dovecot(ctx)
    _write_rspamd(ctx)
    _write_roundcube_config(ctx)
    for svc in ["redis-server", "rspamd", "dovecot", "postfix"]:
        run(["systemctl", "enable", svc], check=False)
        run(["systemctl", "restart", svc], check=False)
    _ensure_all_mailbox_folders(ctx, job_id)
    ctx.job_log(job_id, "Mail stack aplikován, Rspamd hlavičky zapnuty a služby restartovány.")


def _safe_domain(domain: str) -> str:
    domain = domain.lower().strip()
    if not Ctx.domain_valid(domain):
        raise RuntimeError(f"Neplatná doména: {domain}")
    return domain


def _cert_name(domain: str) -> str:
    return f"mail.{domain}"


def _ssl_exists(domain: str) -> bool:
    cert_name = _cert_name(domain)
    return Path(f"/etc/letsencrypt/live/{cert_name}/fullchain.pem").exists() and Path(f"/etc/letsencrypt/live/{cert_name}/privkey.pem").exists()


def _acme_location() -> str:
    return """    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type text/plain;
        try_files $uri =404;
    }
"""


def _php_loc(ctx: Ctx) -> str:
    return f"""    location ~ \.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:{ctx.php_socket()};
    }}
"""


def _mail_info_page(domain: str) -> str:
    root = Path("/var/www/oris-mail-info") / domain
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(f"""<!doctype html><html><head><meta charset=\"utf-8\"><title>Mail {domain}</title></head>
<body style=\"font-family:sans-serif;background:#0b1020;color:#e8eefc;padding:40px\">
<h1>Mail server pro {domain}</h1>
<p>IMAP/SMTP hostname: <b>mail.{domain}</b></p>
<p>Webmail: <a href=\"https://webmail.{domain}/\">webmail.{domain}</a></p>
</body></html>\n""", encoding="utf-8")
    run(["chown", "-R", "www-data:www-data", str(root)], check=False)
    return str(root)


def write_mail_vhosts(ctx: Ctx, job_id: int, domain: str, *, force_plain_http: bool = False) -> None:
    domain = _safe_domain(domain)

    avail = Path(ctx.setting("nginx_sites_available", "/etc/nginx/sites-available"))
    enabled = Path(ctx.setting("nginx_sites_enabled", "/etc/nginx/sites-enabled"))

    avail.mkdir(parents=True, exist_ok=True)
    enabled.mkdir(parents=True, exist_ok=True)

    cert_name = _cert_name(domain)
    cert = f"/etc/letsencrypt/live/{cert_name}/fullchain.pem"
    key = f"/etc/letsencrypt/live/{cert_name}/privkey.pem"

    have_ssl = _ssl_exists(domain) and not force_plain_http
    rc_root = _roundcube_root()

    server_names = f"mail.{domain} webmail.{domain} roundcube.{domain}"

    def roundcube_vhost(names: str, root: str) -> str:
        body = f"""server {{
    listen 80;
    listen [::]:80;
    server_name {names};

    client_max_body_size 128M;

{_acme_location()}
"""

        if have_ssl:
            body += """    location / {
        return 301 https://$host$request_uri;
    }
}

"""
            body += f"""server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {names};

    ssl_certificate {cert};
    ssl_certificate_key {key};

    client_max_body_size 128M;

{_acme_location()}
    root {root};
    index index.php index.html;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

{_php_loc(ctx)}
    location ~ /\. {{
        deny all;
    }}
}}
"""
        else:
            body += f"""    root {root};
    index index.php index.html;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

{_php_loc(ctx)}
    location ~ /\. {{
        deny all;
    }}
}}
"""

        return body

    # Jeden společný Roundcube vhost pro:
    # - mail.domena.cz
    # - webmail.domena.cz
    # - roundcube.domena.cz
    conf_path = avail / f"webmail.{domain}.conf"
    conf_content = roundcube_vhost(server_names, rc_root)

    atomic_write(conf_path, conf_content)

    # Starý samostatný mail vhost pryč, aby nepřebíjel Roundcube.
    (enabled / f"mail.{domain}.conf").unlink(missing_ok=True)
    (avail / f"mail.{domain}.conf").unlink(missing_ok=True)

    # Zapnout nový společný vhost.
    (enabled / conf_path.name).unlink(missing_ok=True)
    (enabled / conf_path.name).symlink_to(conf_path)

    ctx.nginx_reload_checked()
    ctx.job_log(
        job_id,
        f"Mail vhosty zapsány na Roundcube: mail.{domain}, webmail.{domain}, roundcube.{domain}"
    )

def _domain_by_id(ctx: Ctx, domain_id: int) -> dict[str, Any]:
    row = _mail_one(ctx, "SELECT * FROM domains WHERE id=%s", (domain_id,))
    if not row:
        raise RuntimeError(f"Mail doména nenalezena: {domain_id}")
    return row


def _parse_dkim_dns(out: str) -> tuple[str, str]:
    # rspamadm vrací TXT s uvozovkami; vytáhneme hodnotu p=...
    txt = " ".join(out.split())
    m = re.search(r"v=DKIM1;\s*k=rsa;\s*p=([A-Za-z0-9+/=\s]+)", txt)
    if not m:
        # fallback: spoj quoted části
        parts = re.findall(r'"([^"]+)"', out)
        joined = "".join(parts)
        m = re.search(r"p=([A-Za-z0-9+/=]+)", joined)
        if m:
            pub = re.sub(r"\s+", "", m.group(1))
            return pub, f"v=DKIM1; k=rsa; p={pub}"
        raise RuntimeError("Nepodařilo se přečíst DKIM public key z rspamadm výstupu:\n" + out)
    pub = re.sub(r"\s+", "", m.group(1))
    return pub, f"v=DKIM1; k=rsa; p={pub}"


def ensure_dkim(ctx: Ctx, job_id: int, domain_id: int, domain: str, force: bool = False) -> None:
    selector = ctx.setting("dkim_selector", "s1")
    bits = int(ctx.setting("dkim_key_bits", "2048") or 2048)
    keydir = Path(ctx.setting("dkim_key_dir", "/var/lib/rspamd/dkim"))
    keydir.mkdir(parents=True, exist_ok=True)
    key_path = keydir / f"{domain}.{selector}.key"
    existing = _mail_one(ctx, "SELECT * FROM domain_dkim WHERE domain_id=%s", (domain_id,))
    if existing and key_path.exists() and not force:
        ctx.job_log(job_id, f"DKIM už existuje pro {domain} selector={selector}")
        return
    if force and key_path.exists():
        key_path.unlink()
    rc, out = run(["rspamadm", "dkim_keygen", "-b", str(bits), "-s", selector, "-d", domain, "-k", str(key_path)], check=False)
    if rc != 0:
        raise RuntimeError("rspamadm dkim_keygen selhal:\n" + out)
    pub, dns_value = _parse_dkim_dns(out)
    dns_txt = f"{selector}._domainkey.{domain} IN TXT \"{dns_value}\""
    _mail_exec(ctx, "INSERT INTO domain_dkim(domain_id,selector,public_key,dns_txt) VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE selector=VALUES(selector), public_key=VALUES(public_key), dns_txt=VALUES(dns_txt), updated_at=NOW()", (domain_id, selector, pub, dns_txt))
    run(["chown", "_rspamd:_rspamd", str(key_path)], check=False)
    run(["chmod", "640", str(key_path)], check=False)
    ctx.job_log(job_id, f"DKIM vygenerován pro {domain}: {selector}._domainkey")


def _certbot_mail(ctx: Ctx, job_id: int, domain: str) -> None:
    domains = [f"mail.{domain}", f"webmail.{domain}", f"roundcube.{domain}"]
    write_mail_vhosts(ctx, job_id, domain, force_plain_http=True)
    # jednoduchý ACME test
    acme = ctx.ensure_acme_webroot()
    test = Path(acme) / ".well-known/acme-challenge/oris-test.txt"
    test.parent.mkdir(parents=True, exist_ok=True)
    test.write_text("ORIS-ACME-OK\n", encoding="utf-8")
    for d in domains:
        rc, out = run(["curl", "-fsS", "--max-time", "10", f"http://{d}/.well-known/acme-challenge/oris-test.txt"], check=False)
        if rc != 0 or "ORIS-ACME-OK" not in out:
            raise RuntimeError(f"ACME test selhal pro {d}: {out}")
    cmd = ["certbot", "certonly", "--webroot", "-w", acme, "--non-interactive", "--agree-tos", "--keep-until-expiring", "--cert-name", _cert_name(domain)]
    email = ctx.setting("certbot_email", "")
    if email:
        cmd += ["-m", email]
    else:
        cmd += ["--register-unsafely-without-email"]
    for d in domains:
        cmd += ["-d", d]
    ctx.job_log(job_id, "Spouštím: " + " ".join(cmd))
    rc, out = run(cmd, check=False)
    ctx.job_log(job_id, out.strip() or f"certbot exit={rc}")
    if rc != 0:
        raise RuntimeError("Certbot pro mail doménu selhal")
    write_mail_vhosts(ctx, job_id, domain)


def _maildir_for(email: str, local: str, domain: str, row_maildir: str | None = None) -> str:
    if row_maildir:
        return row_maildir.rstrip("/") + "/"
    return f"/var/vmail/{domain}/{local}/"


def _hash_password(password: str) -> str:
    rc, out = run(["doveadm", "pw", "-s", "BLF-CRYPT", "-p", password], check=False)
    if rc != 0:
        raise RuntimeError("doveadm pw selhal:\n" + out)
    return out.strip()


def _ensure_maildir_folder(maildir: str, folder: str) -> None:
    root = Path(maildir.rstrip("/"))
    folder_dir = root / f".{folder}"
    for sub in ["cur", "new", "tmp"]:
        (folder_dir / sub).mkdir(parents=True, exist_ok=True)
    subs = root / "subscriptions"
    existing = set()
    if subs.exists():
        existing = {line.strip() for line in subs.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()}
    if folder not in existing:
        with subs.open("a", encoding="utf-8") as f:
            f.write(folder + "\n")


def _ensure_mailbox_folders(ctx: Ctx, email: str, maildir: str, job_id: int | None = None) -> None:
    folders = ["Junk", "Sent", "Drafts", "Trash", "Archive"]
    for folder in folders:
        _ensure_maildir_folder(maildir, folder)
        run(["doveadm", "mailbox", "create", "-u", email, "-s", folder], check=False)
    run(["chown", "-R", "vmail:mail", str(Path(maildir.rstrip("/")).parent)], check=False)
    run(["chmod", "-R", "770", str(Path(maildir.rstrip("/")).parent)], check=False)
    if job_id:
        ctx.job_log(job_id, f"Složky schránky připraveny: {email} (Junk/Sent/Drafts/Trash/Archive)")


def _ensure_all_mailbox_folders(ctx: Ctx, job_id: int | None = None) -> None:
    rows = _mail_all(ctx, "SELECT m.*, d.domain FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.is_active=1")
    for row in rows:
        maildir = _maildir_for(str(row["email"]), str(row["local_part"]), str(row["domain"]), row.get("maildir"))
        Path(maildir).mkdir(parents=True, exist_ok=True)
        _ensure_mailbox_folders(ctx, str(row["email"]), maildir, job_id=None)
    if job_id is not None:
        ctx.job_log(job_id, f"Standardní složky zkontrolovány pro {len(rows)} aktivních schránek.")


def _mailbox_apply(ctx: Ctx, job: dict[str, Any], *, set_password_only: bool = False) -> None:
    job_id = int(job["id"])
    mid = int(job.get("ref_id") or 0)
    payload = _payload(job)
    row = _mail_one(ctx, "SELECT m.*, d.domain FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.id=%s", (mid,))
    if not row:
        raise RuntimeError(f"Schránka nenalezena: {mid}")
    password = str(payload.get("password") or "")
    if password:
        ph = _hash_password(password)
        _mail_exec(ctx, "UPDATE mailboxes SET pass_hash=%s, is_active=1 WHERE id=%s", (ph, mid))
    if not set_password_only:
        maildir = _maildir_for(str(row["email"]), str(row["local_part"]), str(row["domain"]), row.get("maildir"))
        Path(maildir).mkdir(parents=True, exist_ok=True)
        run(["chown", "-R", "vmail:mail", str(Path(maildir).parent)], check=False)
        run(["chmod", "-R", "770", str(Path(maildir).parent)], check=False)
        ctx.job_log(job_id, f"Maildir připraven: {maildir}")
    apply_stack(ctx, job_id)
    maildir = _maildir_for(str(row["email"]), str(row["local_part"]), str(row["domain"]), row.get("maildir"))
    _ensure_mailbox_folders(ctx, str(row["email"]), maildir, job_id)


def remove_domain_vhosts(ctx: Ctx, job_id: int, domain: str) -> None:
    domain = _safe_domain(domain)
    avail = Path(ctx.setting("nginx_sites_available", "/etc/nginx/sites-available"))
    enabled = Path(ctx.setting("nginx_sites_enabled", "/etc/nginx/sites-enabled"))
    for name in [f"mail.{domain}.conf", f"webmail.{domain}.conf", f"roundcube.{domain}.conf"]:
        (enabled / name).unlink(missing_ok=True)
        (avail / name).unlink(missing_ok=True)
    ctx.nginx_reload_checked()
    ctx.job_log(job_id, f"Mail vhosty odstraněny pro {domain}")



def _backup_dir(ctx: Ctx, key: str, default: str) -> Path:
    p = Path(ctx.setting(key, default)).resolve()
    p.mkdir(parents=True, exist_ok=True)
    run(["chown", "-R", "www-data:www-data", str(p)], check=False)
    run(["chmod", "770", str(p)], check=False)
    return p


def _safe_backup_name(name: str) -> str:
    name = Path(str(name or "")).name
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise RuntimeError("Neplatný název zálohy")
    return name


def _delete_backup_file(ctx: Ctx, job: dict[str, Any], *, kind: str) -> None:
    job_id = int(job["id"])
    payload = _payload(job)
    name = _safe_backup_name(str(payload.get("name", "")))

    if kind == "bayes":
        base = _backup_dir(ctx, "mail_bayes_backup_dir", "/var/lib/oris-core/backups/rspamd")
        allowed_suffixes = (".tar.gz", ".tgz", ".gz", ".redis")
    else:
        base = _backup_dir(ctx, "mail_backup_dir", "/var/lib/oris-core/backups/mail")
        allowed_suffixes = (".tar.gz", ".tgz")

    if not name.endswith(allowed_suffixes):
        raise RuntimeError("Nepovolený typ zálohy pro smazání")

    path = (base / name).resolve()
    if not str(path).startswith(str(base.resolve()) + os.sep):
        raise RuntimeError("Záloha je mimo povolený adresář")
    if not path.is_file():
        raise RuntimeError(f"Záloha neexistuje: {name}")

    path.unlink()
    ctx.job_log(job_id, f"Záloha smazána: {path}")


def _upload_root(ctx: Ctx) -> Path:
    p = Path(ctx.setting("upload_staging_dir", "/var/lib/oris-core/uploads")).resolve()
    p.mkdir(parents=True, exist_ok=True)
    run(["chown", "-R", "www-data:www-data", str(p)], check=False)
    run(["chmod", "770", str(p)], check=False)
    return p


def _require_staged_upload(ctx: Ctx, raw_path: str, subdir: str) -> Path:
    root = (_upload_root(ctx) / subdir).resolve()
    path = Path(raw_path).resolve()
    if not str(path).startswith(str(root) + os.sep):
        raise RuntimeError(f"Upload mimo povolený staging adresář: {path}")
    if not path.is_file():
        raise RuntimeError(f"Upload soubor neexistuje: {path}")
    return path


def _safe_extract_tar(archive: Path, dest: Path) -> None:
    dest = dest.resolve()
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                raise RuntimeError(f"Nebezpečná cesta v archivu: {member.name}")
        tf.extractall(dest)


def _safe_extract_zip(archive: Path, dest: Path) -> None:
    dest = dest.resolve()
    with zipfile.ZipFile(archive) as zf:
        for member in zf.namelist():
            target = (dest / member).resolve()
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                raise RuntimeError(f"Nebezpečná cesta v ZIPu: {member}")
        zf.extractall(dest)


def _copy_into_backup(src: str, root: Path, job_id: int | None, ctx: Ctx) -> None:
    sp = Path(src)
    if not sp.exists():
        return
    rel = str(sp).lstrip("/")
    dst = root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    if sp.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(sp, dst, symlinks=True)
    else:
        shutil.copy2(sp, dst)
    if job_id is not None:
        ctx.job_log(job_id, f"Přidáno do zálohy: {src}")


def _mail_db_dump(ctx: Ctx, out_sql: Path, job_id: int) -> None:
    cfg = _mail_db_cfg(ctx)
    cmd = [
        "mysqldump",
        "-h", str(cfg.get("host", "127.0.0.1")),
        "-P", str(cfg.get("port", 3306)),
        "-u", str(cfg.get("user", "oris_mail")),
        f"-p{cfg.get('pass','')}",
        str(cfg.get("name", "oris_mail")),
    ]
    rc, out = run(cmd, check=False)
    if rc != 0:
        out_sql.write_text("-- mysqldump selhal\n" + out, encoding="utf-8")
        ctx.job_log(job_id, "VAROVÁNÍ: mysqldump selhal, SQL dump není kompletní:\n" + out.strip())
        return
    out_sql.write_text(out, encoding="utf-8")


def _mail_db_restore(ctx: Ctx, sql_file: Path, job_id: int) -> None:
    if not sql_file.is_file():
        return
    cfg = _mail_db_cfg(ctx)
    txt = sql_file.read_text(encoding="utf-8", errors="replace")
    if "mysqldump selhal" in txt or "***MASKED***" in txt:
        ctx.job_log(job_id, "SQL dump je prázdný/maskovaný, DB restore přeskakuji.")
        return
    cmd = [
        "mysql",
        "-h", str(cfg.get("host", "127.0.0.1")),
        "-P", str(cfg.get("port", 3306)),
        "-u", str(cfg.get("user", "oris_mail")),
        f"-p{cfg.get('pass','')}",
        str(cfg.get("name", "oris_mail")),
    ]
    rc, out = run(cmd, check=False, input_text=txt)
    ctx.job_log(job_id, "$ mysql < db/oris_mail.sql\n" + (out.strip() or f"exit={rc}"))
    if rc != 0:
        raise RuntimeError("Restore mail DB selhal")


def mail_backup_full(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    payload = _payload(job)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = _backup_dir(ctx, "mail_backup_dir", "/var/lib/oris-core/backups/mail")
    archive = out_dir / f"oris-mail-full-{ts}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="oris-mail-full-backup-") as td:
        root = Path(td)
        for src in [
            "/etc/postfix",
            "/etc/dovecot",
            "/etc/rspamd",
            "/etc/roundcube",
            "/etc/fail2ban",
            "/etc/dovecot/sieve-pipe",
            "/etc/aliases",
            "/etc/hostname",
            "/etc/hosts",
        ]:
            _copy_into_backup(src, root, job_id, ctx)

        db_dir = root / "db"
        db_dir.mkdir(parents=True, exist_ok=True)
        _mail_db_dump(ctx, db_dir / "oris_mail.sql", job_id)

        manifest = root / "MANIFEST.txt"
        manifest.write_text(
            f"ORIS mail full backup\ncreated={ts}\nmask={bool(payload.get('mask'))}\n",
            encoding="utf-8",
        )

        with tarfile.open(archive, "w:gz") as tf:
            tf.add(root, arcname=".")

    run(["chown", "www-data:www-data", str(archive)], check=False)
    run(["chmod", "640", str(archive)], check=False)
    ctx.job_log(job_id, f"FULL mail záloha vytvořena: {archive}")


def _restore_tree_from_extracted(ctx: Ctx, job_id: int, root: Path, *, legacy_zip: bool = False) -> None:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safety = _backup_dir(ctx, "mail_backup_dir", "/var/lib/oris-core/backups/mail") / f"pre-restore-{ts}"
    safety.mkdir(parents=True, exist_ok=True)

    restore_rels = [
        "etc/postfix",
        "etc/dovecot",
        "etc/rspamd",
        "etc/roundcube",
        "etc/fail2ban",
        "etc/dovecot/sieve-pipe",
        "etc/aliases",
        "etc/hostname",
        "etc/hosts",
    ]

    # Legacy ZIP může mít soubory rovnou v rootu, nebo pod podadresářem.
    candidates = [root]
    candidates += [p for p in root.iterdir() if p.is_dir()]

    for rel in restore_rels:
        src = None
        for c in candidates:
            if (c / rel).exists():
                src = c / rel
                break
        if src is None:
            continue

        dst = Path("/") / rel
        if dst.exists():
            _copy_into_backup(str(dst), safety, None, ctx)
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            if dst.is_dir():
                shutil.rmtree(dst)
            else:
                dst.unlink()
        if src.is_dir():
            shutil.copytree(src, dst, symlinks=True)
        else:
            shutil.copy2(src, dst)
        ctx.job_log(job_id, f"Obnoveno: /{rel}")

    # DB restore z nového taru.
    for sql in [root / "db/oris_mail.sql", *root.glob("*/db/oris_mail.sql")]:
        if sql.is_file():
            _mail_db_restore(ctx, sql, job_id)
            break

    if Path("/etc/dovecot/sieve-pipe").is_dir():
        run(["chmod", "+x", "/etc/dovecot/sieve-pipe/rspamc-learn-ham"], check=False)
        run(["chmod", "+x", "/etc/dovecot/sieve-pipe/rspamc-learn-spam"], check=False)

    for svc in ["postfix", "dovecot", "rspamd", "redis-server", "fail2ban"]:
        run(["systemctl", "restart", svc], check=False)

    ctx.job_log(job_id, f"Obnova dokončena. Safety backup: {safety}")


def mail_restore_full(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    path = _require_staged_upload(ctx, str(_payload(job).get("path", "")), "mail")
    with tempfile.TemporaryDirectory(prefix="oris-mail-full-restore-") as td:
        root = Path(td)
        _safe_extract_tar(path, root)
        _restore_tree_from_extracted(ctx, job_id, root)


def mail_restore_zip(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    path = _require_staged_upload(ctx, str(_payload(job).get("path", "")), "mail")
    with tempfile.TemporaryDirectory(prefix="oris-mail-zip-restore-") as td:
        root = Path(td)
        _safe_extract_zip(path, root)
        _restore_tree_from_extracted(ctx, job_id, root, legacy_zip=True)


def mail_bayes_backup(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = _backup_dir(ctx, "mail_bayes_backup_dir", "/var/lib/oris-core/backups/rspamd")
    archive = out_dir / f"rspamd-bayes-{ts}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="oris-bayes-backup-") as td:
        root = Path(td)
        meta = [f"timestamp={ts}"]

        # Prefer Redis, protože Rspamd v tomto stacku běží s Redisem.
        rc, _ = run(["systemctl", "is-active", "--quiet", "redis-server"], check=False)
        if rc == 0 and shutil.which("redis-cli"):
            meta.append("backend=redis")
            rc2, out = run(["redis-cli", "--rdb", str(root / "dump.rdb")], check=False)
            if rc2 != 0:
                raise RuntimeError("redis-cli --rdb selhal:\n" + out)
        else:
            meta.append("backend=sqlite")
            db = Path("/var/lib/rspamd/bayes.sqlite")
            if not db.is_file():
                raise RuntimeError("Nenalezen Redis ani SQLite Bayes DB")
            shutil.copy2(db, root / db.name)

        (root / "meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")

        cfg_dir = root / "cfg"
        for src in [
            "/etc/rspamd/local.d/metrics.conf",
            "/etc/rspamd/local.d/classifier-bayes.conf",
            "/etc/roundcube/config.inc.php",
            "/etc/roundcube/plugins/markasjunk/config.inc.php",
            "/etc/dovecot/sieve-pipe/rspamc-learn-ham",
            "/etc/dovecot/sieve-pipe/rspamc-learn-spam",
        ]:
            if Path(src).is_file():
                _copy_into_backup(src, cfg_dir, None, ctx)

        with tarfile.open(archive, "w:gz") as tf:
            tf.add(root, arcname=".")

    run(["chown", "www-data:www-data", str(archive)], check=False)
    run(["chmod", "640", str(archive)], check=False)
    ctx.job_log(job_id, f"Bayes/Rspamd záloha vytvořena: {archive}")


def mail_bayes_restore(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    path = _require_staged_upload(ctx, str(_payload(job).get("path", "")), "mail")
    with tempfile.TemporaryDirectory(prefix="oris-bayes-restore-") as td:
        root = Path(td)
        _safe_extract_tar(path, root)
        meta = (root / "meta.txt").read_text(encoding="utf-8", errors="replace") if (root / "meta.txt").is_file() else ""
        backend = "redis" if "backend=redis" in meta else "sqlite" if "backend=sqlite" in meta else ""

        # Restore learning config files if present.
        cfg = root / "cfg"
        if cfg.is_dir():
            for src in cfg.rglob("*"):
                if not src.is_file():
                    continue
                rel = src.relative_to(cfg)
                dst = Path("/") / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                if dst.exists():
                    shutil.copy2(dst, str(dst) + ".bak." + datetime.now().strftime("%Y%m%d-%H%M%S"))
                shutil.copy2(src, dst)
                ctx.job_log(job_id, f"Obnoven learning config: /{rel}")

        if backend == "redis":
            rdb = root / "dump.rdb"
            if not rdb.is_file():
                raise RuntimeError("V archivu chybí dump.rdb")
            if not shutil.which("redis-cli"):
                raise RuntimeError("redis-cli není dostupný")
            rc1, redis_dir = run(["redis-cli", "CONFIG", "GET", "dir"], check=False)
            rc2, redis_file = run(["redis-cli", "CONFIG", "GET", "dbfilename"], check=False)
            if rc1 != 0 or rc2 != 0:
                raise RuntimeError("Nelze zjistit Redis dump cestu")
            redis_dir_val = redis_dir.strip().splitlines()[-1]
            redis_file_val = redis_file.strip().splitlines()[-1]
            target = Path(redis_dir_val) / redis_file_val
            run(["systemctl", "stop", "redis-server"], check=False)
            shutil.copy2(rdb, target)
            run(["chown", "redis:redis", str(target)], check=False)
            run(["systemctl", "start", "redis-server"], check=False)
        elif backend == "sqlite":
            sqlite_files = list(root.glob("*.sqlite"))
            if not sqlite_files:
                raise RuntimeError("V archivu chybí SQLite Bayes DB")
            target = Path("/var/lib/rspamd/bayes.sqlite")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sqlite_files[0], target)
            run(["chown", "_rspamd:_rspamd", str(target)], check=False)
        else:
            raise RuntimeError("Neznámý typ Bayes archivu")

    for svc in ["rspamd", "dovecot"]:
        run(["systemctl", "restart", svc], check=False)
    ctx.job_log(job_id, "Bayes/Rspamd učení obnoveno.")


def handle(ctx: Ctx, job: dict[str, Any]) -> None:
    typ = str(job.get("type") or "")
    job_id = int(job["id"])
    ref = int(job.get("ref_id") or 0)
    payload = _payload(job)

    if typ == "mail_stack_apply":
        apply_stack(ctx, job_id)
        return
    if typ == "mail_stack_test":
        for cmd in (["postfix", "check"], ["doveconf", "-n"], ["rspamadm", "configtest"]):
            rc, out = run(cmd, check=False)
            ctx.job_log(job_id, "$ " + " ".join(cmd) + "\n" + (out.strip() or f"exit={rc}"))
            if rc != 0:
                raise RuntimeError("Test selhal: " + " ".join(cmd))
        return
    if typ == "mail_roundcube_apply":
        _write_roundcube_config(ctx)
        ctx.job_log(job_id, "Roundcube config zapsán.")
        return
    if typ == "mail_roundcube_test":
        root = _roundcube_root()
        if not Path(root, "index.php").exists():
            raise RuntimeError(f"Roundcube index.php nenalezen v {root}")
        ctx.job_log(job_id, f"Roundcube OK: {root}")
        return

    if typ == "mail_domain_apply":
        d = _domain_by_id(ctx, ref)
        domain = _safe_domain(str(d["domain"]))
        apply_stack(ctx, job_id)
        ensure_dkim(ctx, job_id, ref, domain, False)
        write_mail_vhosts(ctx, job_id, domain)
        return
    if typ == "mail_domain_dkim_regen":
        d = _domain_by_id(ctx, ref)
        ensure_dkim(ctx, job_id, ref, _safe_domain(str(d["domain"])), True)
        run(["systemctl", "restart", "rspamd"], check=False)
        return
    if typ == "mail_domain_certbot_issue":
        d = _domain_by_id(ctx, ref)
        _certbot_mail(ctx, job_id, _safe_domain(str(d["domain"])))
        return
    if typ == "mail_domain_remove":
        domain = str(payload.get("domain") or "").strip()
        if not domain and ref:
            row = _mail_one(ctx, "SELECT domain FROM domains WHERE id=%s", (ref,))
            domain = str(row["domain"]) if row else ""
        if not domain:
            ctx.job_log(job_id, "Doména už není v DB a payload ji neobsahuje; není co mazat.")
            return
        remove_domain_vhosts(ctx, job_id, domain)
        return
    if typ == "mailbox_apply":
        _mailbox_apply(ctx, job, set_password_only=False)
        return
    if typ == "mailbox_set_password":
        _mailbox_apply(ctx, job, set_password_only=True)
        return
    if typ == "mail_backup_full":
        mail_backup_full(ctx, job)
        return
    if typ == "mail_restore_full":
        mail_restore_full(ctx, job)
        return
    if typ == "mail_restore_zip":
        mail_restore_zip(ctx, job)
        return
    if typ == "mail_bayes_backup":
        mail_bayes_backup(ctx, job)
        return
    if typ == "mail_bayes_restore":
        mail_bayes_restore(ctx, job)
        return
    if typ == "mail_backup_delete":
        _delete_backup_file(ctx, job, kind="full")
        return
    if typ == "mail_bayes_backup_delete":
        _delete_backup_file(ctx, job, kind="bayes")
        return
    raise RuntimeError(f"Mail plugin neumí job {typ}")

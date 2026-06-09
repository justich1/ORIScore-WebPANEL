from __future__ import annotations

import re
from pathlib import Path

from ..common import atomic_write, run
from ..context import Ctx, randpass

HANDLED_TYPES = {"ftp_create", "ftp_reset_pass", "ftp_delete", "ftp_fix_perms"}


def ensure_vsftpd_ready():
    shells = Path("/etc/shells")
    text = shells.read_text(encoding="utf-8") if shells.exists() else ""
    if "/usr/sbin/nologin" not in text:
        with shells.open("a", encoding="utf-8") as f:
            f.write("\n/usr/sbin/nologin\n")
    conf = Path("/etc/vsftpd.conf")
    if not conf.exists() or "pasv_min_port=40000" not in conf.read_text(encoding="utf-8", errors="ignore"):
        if conf.exists():
            conf.replace(f"/etc/vsftpd.conf.bak.oris")
        atomic_write(conf, """listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=002
chroot_local_user=YES
allow_writeable_chroot=YES
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
seccomp_sandbox=NO
""")
    run(["systemctl", "enable", "--now", "vsftpd"], check=False)
    run(["systemctl", "restart", "vsftpd"], check=False)


def ftp_account(ctx: Ctx, ftp_id: int) -> dict:
    row = ctx.one("SELECT fa.*, s.domain, s.root_path FROM ftp_accounts fa LEFT JOIN sites s ON s.id=fa.site_id WHERE fa.id=%s", (ftp_id,))
    if not row:
        raise RuntimeError(f"FTP účet nenalezen: {ftp_id}")
    return row


def _fix_tree_permissions(path: str) -> None:
    """Nastaví práva tak, aby webový user i FTP user ve skupině www-data mohli adresář procházet a zapisovat."""
    p = Path(path)
    if not p.exists():
        return
    run(["chown", "-R", "www-data:www-data", str(p)], check=False)
    run(["chmod", "-R", "u+rwX,g+rwX,o-rwx", str(p)], check=False)
    # setgid na adresáře: nové soubory/složky zůstanou ve skupině www-data
    run(["find", str(p), "-type", "d", "-exec", "chmod", "2770", "{}", "+"], check=False)


def _ensure_ftp_user_access(user: str, home: str) -> None:
    # FTP user musí být ve skupině www-data, jinak po obnově dat vlastněných www-data:www-data
    # neuvidí složky ani když mají group rwx.
    run(["usermod", "-aG", "www-data", user], check=False)
    _fix_tree_permissions(home)


def handle(ctx: Ctx, job: dict) -> None:
    job_id = int(job["id"])
    typ = str(job["type"])
    ftp_id = int(job.get("ref_id") or 0)
    ensure_vsftpd_ready()

    if typ == "ftp_create":
        a = ftp_account(ctx, ftp_id)
        user = str(a["username"])
        if not re.match(r"^[A-Za-z0-9_.-]+$", user):
            raise RuntimeError("Neplatné FTP uživatelské jméno")
        home = str(a["home_dir"]).rstrip("/")
        root_path = str(a.get("root_path") or "").rstrip("/")
        if not home or ".." in home or "\x00" in home:
            raise RuntimeError("Neplatný FTP home")
        # FTP home je adresář webu, typicky /var/lib/oris-core/sites/domena.
        # Public root už je /public. Nikdy nevytvářet /www.
        Path(home).mkdir(parents=True, exist_ok=True)
        if root_path and root_path.startswith(home):
            Path(root_path).mkdir(parents=True, exist_ok=True)
        else:
            Path(home, "public").mkdir(parents=True, exist_ok=True)
        pwd = randpass(12)
        rc, _ = run(["id", "-u", user], check=False)
        if rc != 0:
            # -g www-data = primární skupina pro nové soubory; zároveň user zůstává chrootovaný do home.
            run(["useradd", "-d", home, "-s", "/usr/sbin/nologin", "-g", "www-data", user])
        else:
            run(["usermod", "-d", home, "-s", "/usr/sbin/nologin", "-g", "www-data", user])
        run(["chpasswd"], input_text=f"{user}:{pwd}\n")
        _ensure_ftp_user_access(user, home)
        ctx.exec("UPDATE ftp_accounts SET status='active', ftp_pass=%s, last_error=NULL WHERE id=%s", (pwd, ftp_id))
        ctx.job_log(job_id, f"FTP účet vytvořen: {user} home={home}")
        return

    if typ == "ftp_reset_pass":
        a = ftp_account(ctx, ftp_id)
        user = str(a["username"])
        rc, _ = run(["id", "-u", user], check=False)
        if rc != 0:
            raise RuntimeError(f"System user neexistuje: {user}")
        pwd = randpass(12)
        run(["chpasswd"], input_text=f"{user}:{pwd}\n")
        home = str(a.get("home_dir") or "").rstrip("/")
        if home:
            _ensure_ftp_user_access(user, home)
        ctx.exec("UPDATE ftp_accounts SET status='active', ftp_pass=%s, last_error=NULL WHERE id=%s", (pwd, ftp_id))
        ctx.job_log(job_id, f"FTP heslo resetováno a práva opravena: {user}")
        return

    if typ == "ftp_fix_perms":
        a = ftp_account(ctx, ftp_id)
        user = str(a["username"])
        home = str(a.get("home_dir") or "").rstrip("/")
        rc, _ = run(["id", "-u", user], check=False)
        if rc != 0:
            raise RuntimeError(f"System user neexistuje: {user}")
        if not home or ".." in home or "\x00" in home:
            raise RuntimeError("Neplatný FTP home")
        _ensure_ftp_user_access(user, home)
        ctx.exec("UPDATE ftp_accounts SET status='active', last_error=NULL WHERE id=%s", (ftp_id,))
        ctx.job_log(job_id, f"FTP práva opravena: {user} home={home}")
        return

    if typ == "ftp_delete":
        a = ftp_account(ctx, ftp_id)
        user = str(a["username"])
        home = str(a.get("home_dir") or "")
        run(["userdel", user], check=False)
        if home and Path(home).exists():
            run(["chown", "-R", "www-data:www-data", home], check=False)
        # FTP účet má po smazání zmizet úplně, ne cancelled.
        ctx.exec("DELETE FROM ftp_accounts WHERE id=%s", (ftp_id,))
        ctx.job_log(job_id, f"FTP účet úplně smazán: {user}")
        return

    raise RuntimeError(f"Plugin ftp neumí job {typ}")

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from ..common import atomic_write, run
from ..context import Ctx

HANDLED_TYPES = {
    "servercfg_sync_file",
    "servercfg_apply_file",
    "servercfg_backup_full",
    "servercfg_restore_full",
    "servercfg_backup_delete",
    "settings_apply",
}


def _payload(job: dict[str, Any]) -> dict[str, Any]:
    p = job.get("payload")
    if isinstance(p, dict):
        return p
    if isinstance(p, str) and p.strip():
        import json
        try:
            return json.loads(p)
        except Exception:
            return {}
    return {}


def _allowed_roots(ctx: Ctx) -> list[Path]:
    roots = [
        "/etc/nginx",
        "/etc/php",
        "/etc/phpmyadmin",
        "/etc/ufw",
        "/etc/vsftpd.conf",
        "/etc/vsftpd_user_conf",
        "/etc/wireguard",
        "/etc/postfix",
        "/etc/dovecot",
        "/etc/rspamd",
        "/etc/roundcube",
        "/etc/fail2ban",
        "/etc/aliases",
        "/etc/hostname",
        "/etc/hosts",
    ]
    extra = ctx.setting("servercfg_allowed_roots", "")
    for line in extra.splitlines():
        line = line.strip()
        if line:
            roots.append(line)
    return [Path(r).resolve() for r in roots]


def _allowed_path(ctx: Ctx, raw: str) -> Path:
    p = Path(raw).resolve()
    for root in _allowed_roots(ctx):
        if p == root or str(p).startswith(str(root) + os.sep):
            return p
    raise RuntimeError(f"Cesta není v povolených servercfg roots: {p}")


def _backup_dir(ctx: Ctx) -> Path:
    p = Path(ctx.setting("servercfg_backup_dir", "/var/lib/oris-core/backups/servercfg")).resolve()
    p.mkdir(parents=True, exist_ok=True)
    run(["chown", "-R", "www-data:www-data", str(p)], check=False)
    run(["chmod", "770", str(p)], check=False)
    return p


def _safe_backup_name(name: str) -> str:
    import re
    name = Path(str(name or "")).name
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise RuntimeError("Neplatný název zálohy")
    if not name.endswith((".tar.gz", ".tgz")):
        raise RuntimeError("Nepovolený typ zálohy pro smazání")
    return name


def servercfg_backup_delete(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    name = _safe_backup_name(str(_payload(job).get("name", "")))
    base = _backup_dir(ctx).resolve()
    path = (base / name).resolve()
    if not str(path).startswith(str(base) + os.sep):
        raise RuntimeError("Záloha je mimo povolený adresář")
    if not path.is_file():
        raise RuntimeError(f"Záloha neexistuje: {name}")
    path.unlink()
    ctx.job_log(job_id, f"Záloha servercfg smazána: {path}")


def _upload_root(ctx: Ctx) -> Path:
    p = Path(ctx.setting("upload_staging_dir", "/var/lib/oris-core/uploads")).resolve()
    p.mkdir(parents=True, exist_ok=True)
    run(["chown", "-R", "www-data:www-data", str(p)], check=False)
    run(["chmod", "770", str(p)], check=False)
    return p


def _require_staged_upload(ctx: Ctx, raw_path: str) -> Path:
    root = (_upload_root(ctx) / "servercfg").resolve()
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


def _after_apply(ctx: Ctx, job_id: int, group: str, path: Path) -> None:
    group = group.lower()
    p = str(path)

    if group == "nginx" or "/etc/nginx/" in p:
        run(["nginx", "-t"])
        run(["systemctl", "reload", "nginx"])
        ctx.job_log(job_id, "nginx -t + reload OK")
        return

    if group == "php" or "/etc/php/" in p:
        run("systemctl restart php*-fpm", shell=True, check=False)
        ctx.job_log(job_id, "php-fpm restart OK")
        return

    if group == "ufw" or "/etc/ufw/" in p:
        run(["ufw", "reload"], check=False)
        ctx.job_log(job_id, "ufw reload hotovo")
        return

    if group == "fail2ban" or "/etc/fail2ban/" in p:
        run(["fail2ban-client", "-t"])
        run(["systemctl", "restart", "fail2ban"])
        ctx.job_log(job_id, "fail2ban test + restart OK")
        return

    if group == "wireguard" or "/etc/wireguard/" in p:
        run(["systemctl", "restart", "wg-quick@wg0"], check=False)
        ctx.job_log(job_id, "wg-quick@wg0 restart hotovo")
        return

    if group == "postfix" or "/etc/postfix/" in p:
        run(["postfix", "check"])
        run(["systemctl", "reload", "postfix"], check=False)
        ctx.job_log(job_id, "postfix check + reload OK")
        return

    if group == "dovecot" or "/etc/dovecot/" in p:
        run(["doveconf", "-n"])
        run(["systemctl", "restart", "dovecot"], check=False)
        ctx.job_log(job_id, "dovecot check + restart OK")
        return

    if group == "rspamd" or "/etc/rspamd/" in p:
        run(["rspamadm", "configtest"])
        run(["systemctl", "restart", "rspamd"], check=False)
        ctx.job_log(job_id, "rspamd configtest + restart OK")
        return

    if group == "roundcube" or "/etc/roundcube/" in p:
        run("systemctl restart php*-fpm", shell=True, check=False)
        ctx.job_log(job_id, "roundcube/php-fpm restart hotovo")
        return

    ctx.job_log(job_id, "Soubor zapsán bez reload akce pro tuto skupinu.")


def servercfg_sync_file(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    pld = _payload(job)
    path = _allowed_path(ctx, str(pld.get("path", "")))
    key = str(pld.get("setting_key") or "")
    if not key.startswith("servercfg."):
        raise RuntimeError("Neplatný setting_key")
    if not path.is_file():
        raise RuntimeError(f"Soubor neexistuje: {path}")
    content = path.read_text(encoding="utf-8", errors="replace")
    ctx.set_setting(key, content)
    ctx.job_log(job_id, f"Načteno ze systému do DB: {path}")


def servercfg_apply_file(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    pld = _payload(job)
    group = str(pld.get("group") or "")
    path = _allowed_path(ctx, str(pld.get("path", "")))
    key = str(pld.get("setting_key") or "")
    if not key.startswith("servercfg."):
        raise RuntimeError("Neplatný setting_key")
    content = ctx.setting(key, "")
    if content == "":
        raise RuntimeError(f"V DB není uložen obsah pro {key}")

    if path.exists():
        bak = path.with_name(path.name + ".bak." + datetime.now().strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, bak)
        ctx.job_log(job_id, f"Záloha původního souboru: {bak}")

    atomic_write(path, content)
    ctx.job_log(job_id, f"Zapsáno do systému: {path}")
    _after_apply(ctx, job_id, group, path)


def _copy_tree_or_file(src: Path, root: Path, ctx: Ctx, job_id: int) -> None:
    if not src.exists():
        return
    rel = str(src).lstrip("/")
    dst = root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst)
    ctx.job_log(job_id, f"Přidáno do zálohy: {src}")


def servercfg_backup_full(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = _backup_dir(ctx) / f"oris-servercfg-{ts}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="oris-servercfg-backup-") as td:
        root = Path(td)
        for src in _allowed_roots(ctx):
            _copy_tree_or_file(src, root, ctx, job_id)
        (root / "MANIFEST.txt").write_text(f"ORIS server config backup\ncreated={ts}\n", encoding="utf-8")
        with tarfile.open(out, "w:gz") as tf:
            tf.add(root, arcname=".")

    run(["chown", "www-data:www-data", str(out)], check=False)
    run(["chmod", "640", str(out)], check=False)
    ctx.job_log(job_id, f"Kompletní servercfg záloha vytvořena: {out}")


def servercfg_restore_full(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    archive = _require_staged_upload(ctx, str(_payload(job).get("path", "")))
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safety = _backup_dir(ctx) / f"pre-restore-{ts}"
    safety.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="oris-servercfg-restore-") as td:
        root = Path(td)
        _safe_extract_tar(archive, root)

        for allowed in _allowed_roots(ctx):
            rel = str(allowed).lstrip("/")
            src = root / rel
            if not src.exists():
                continue
            dst = Path("/") / rel
            if dst.exists():
                _copy_tree_or_file(dst, safety, ctx, job_id)
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
            ctx.job_log(job_id, f"Obnoveno: {dst}")

    # Po full restore radši otestuj/reloadni důležité služby best-effort.
    for cmd in [
        ["nginx", "-t"],
        ["systemctl", "reload", "nginx"],
        ["postfix", "check"],
        ["systemctl", "reload", "postfix"],
        ["doveconf", "-n"],
        ["systemctl", "restart", "dovecot"],
        ["rspamadm", "configtest"],
        ["systemctl", "restart", "rspamd"],
        ["fail2ban-client", "-t"],
        ["systemctl", "restart", "fail2ban"],
    ]:
        run(cmd, check=False)

    ctx.job_log(job_id, f"Servercfg restore hotový. Safety backup: {safety}")


def settings_apply(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    dirs = [
        ctx.setting("upload_staging_dir", "/var/lib/oris-core/uploads"),
        ctx.setting("servercfg_backup_dir", "/var/lib/oris-core/backups/servercfg"),
        ctx.setting("mail_backup_dir", "/var/lib/oris-core/backups/mail"),
        ctx.setting("mail_bayes_backup_dir", "/var/lib/oris-core/backups/rspamd"),
    ]
    for d in dirs:
        p = Path(d)
        p.mkdir(parents=True, exist_ok=True)
        run(["chown", "-R", "www-data:www-data", str(p)], check=False)
        run(["chmod", "770", str(p)], check=False)
        ctx.job_log(job_id, f"Připraven adresář: {p}")


def handle(ctx: Ctx, job: dict[str, Any]) -> None:
    typ = str(job.get("type") or "")

    if typ == "servercfg_sync_file":
        servercfg_sync_file(ctx, job)
        return
    if typ == "servercfg_apply_file":
        servercfg_apply_file(ctx, job)
        return
    if typ == "servercfg_backup_full":
        servercfg_backup_full(ctx, job)
        return
    if typ == "servercfg_restore_full":
        servercfg_restore_full(ctx, job)
        return
    if typ == "servercfg_backup_delete":
        servercfg_backup_delete(ctx, job)
        return
    if typ == "settings_apply":
        settings_apply(ctx, job)
        return

    raise RuntimeError(f"servercfg plugin neumí job {typ}")

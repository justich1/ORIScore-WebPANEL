from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from ..common import run
from ..context import Ctx

HANDLED_TYPES = {
    "site_backup_data",
    "site_backup_db",
    "site_restore_data_existing",
    "site_restore_db_existing",
    "site_restore_data_upload",
    "site_restore_db_upload",
    "site_backup_delete",
}


def _payload(job: dict[str, Any]) -> dict[str, Any]:
    p = job.get("payload")
    if isinstance(p, dict):
        return p
    if not p:
        return {}
    try:
        return json.loads(str(p))
    except Exception:
        return {}


def _safe_name(name: str) -> str:
    name = Path(str(name)).name
    if not name or name in {".", ".."}:
        raise RuntimeError("Neplatný název souboru.")
    if not re.match(r"^[A-Za-z0-9_.@+ -]+$", name):
        raise RuntimeError("Název souboru obsahuje nepovolené znaky.")
    return name


def _allowed_bases(ctx: Ctx) -> list[Path]:
    bases: list[str] = []
    sites_base = ctx.setting("sites_base_dir", "/var/lib/oris-core/sites").strip()
    if sites_base:
        bases.append(sites_base)

    raw = ctx.setting("web_root_bases", "").strip()
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            if line:
                bases.append(line)
    else:
        bases.extend(["/var/www/html", "/data/www"])

    out: list[Path] = []
    seen: set[str] = set()
    for base in bases:
        try:
            p = Path(base).expanduser().resolve(strict=False)
        except Exception:
            continue
        s = str(p)
        if s not in seen:
            seen.add(s)
            out.append(p)
    return out


def _under(path: Path, base: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(base.resolve(strict=False))
        return True
    except Exception:
        return False


def _site(ctx: Ctx, site_id: int) -> dict[str, Any]:
    site = ctx.one("SELECT * FROM sites WHERE id=%s", (site_id,))
    if not site:
        raise RuntimeError(f"Web nenalezen: {site_id}")
    return site


def _root(ctx: Ctx, site: dict[str, Any]) -> Path:
    raw = str(site.get("root_path") or "").strip()
    if not raw or "\x00" in raw or ".." in Path(raw).parts:
        raise RuntimeError("Neplatná root_path.")
    root = Path(raw).expanduser().resolve(strict=False)
    bases = _allowed_bases(ctx)
    if not any(_under(root, b) for b in bases):
        allowed = ", ".join(str(b) for b in bases)
        raise RuntimeError(f"Root path není v povolených base cestách: {allowed}")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _backup_dir(root: Path, typ: str) -> Path:
    if typ not in {"data", "db"}:
        raise RuntimeError("Neplatný typ zálohy.")
    p = root / "backup" / typ
    p.mkdir(parents=True, exist_ok=True)
    # Panel běží typicky jako www-data, aby šly zálohy zobrazit/stáhnout.
    run(["chown", "-R", "www-data:www-data", str(root / "backup")], check=False)
    run(["chmod", "-R", "u+rwX,g+rwX,o-rwx", str(root / "backup")], check=False)
    return p


def _safe_backup_path(root: Path, typ: str, name: str, *, must_exist: bool = True) -> Path:
    base = _backup_dir(root, typ).resolve(strict=False)
    path = (base / _safe_name(name)).resolve(strict=False)
    if not _under(path, base):
        raise RuntimeError("Bad path.")
    if must_exist and not path.is_file():
        raise RuntimeError("Soubor zálohy neexistuje.")
    return path


def _zip_is_safe(zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            parts = [p for p in name.split("/") if p]
            if name.startswith("/") or ".." in parts:
                raise RuntimeError(f"ZIP obsahuje nebezpečnou cestu: {info.filename}")


def _tar_is_safe(tar_path: Path) -> None:
    with tarfile.open(tar_path, "r:*") as tf:
        for m in tf.getmembers():
            name = m.name.replace("\\", "/")
            parts = [p for p in name.split("/") if p]
            if name.startswith("/") or ".." in parts:
                raise RuntimeError(f"TAR obsahuje nebezpečnou cestu: {m.name}")
            if m.issym() or m.islnk():
                link = (m.linkname or "").replace("\\", "/")
                link_parts = [p for p in link.split("/") if p]
                if link.startswith("/") or ".." in link_parts:
                    raise RuntimeError(f"TAR obsahuje nebezpečný odkaz: {m.name}")


def _copy_tree(src: Path, dst: Path, *, skip_top: set[str]) -> None:
    for item in src.iterdir():
        if item.name in skip_top:
            continue
        target = dst / item.name
        if item.is_dir() and not item.is_symlink():
            target.mkdir(parents=True, exist_ok=True)
            _copy_tree(item, target, skip_top=set())
        elif item.is_file() or item.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            shutil.copy2(item, target, follow_symlinks=False)


def _create_data_zip(ctx: Ctx, job_id: int, root: Path, out_file: Path) -> None:
    root = root.resolve(strict=False)
    backup_root = (root / "backup").resolve(strict=False)
    count = 0
    with zipfile.ZipFile(out_file, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dp = Path(dirpath).resolve(strict=False)
            if _under(dp, backup_root):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if not _under((Path(dirpath) / d).resolve(strict=False), backup_root)]
            rel_dir = dp.relative_to(root)
            if str(rel_dir) != ".":
                zf.write(dp, str(rel_dir) + "/")
            for filename in filenames:
                fp = Path(dirpath) / filename
                if fp.is_symlink():
                    ctx.job_log(job_id, f"Přeskakuji symlink: {fp}")
                    continue
                if not fp.is_file():
                    continue
                zf.write(fp, str(fp.resolve(strict=False).relative_to(root)))
                count += 1
    ctx.job_log(job_id, f"ZIP obsahuje {count} souborů.")


def _db_conn_args(ctx: Ctx, site: dict[str, Any]) -> tuple[str, int, str, str, str]:
    db_name = str(site.get("db_name") or "")
    db_user = str(site.get("db_user") or "")
    db_pass = str(site.get("db_pass") or "")
    if not db_name or not db_user:
        raise RuntimeError("Web nemá přiřazenou DB.")
    if not ctx.ident_valid(db_name) or not ctx.ident_valid(db_user):
        raise RuntimeError("Neplatný název DB nebo DB user.")
    host = str(ctx.db_cfg.get("host", "127.0.0.1"))
    port = int(ctx.db_cfg.get("port", 3306))
    return host, port, db_name, db_user, db_pass


def _run_mysql(cmd: list[str], password: str, *, input_bytes: bytes | None = None) -> str:
    env = os.environ.copy()
    env["MYSQL_PWD"] = password
    p = subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    out = (p.stdout or b"").decode("utf-8", "replace")
    if p.returncode != 0:
        raise RuntimeError(f"CMD failed ({p.returncode}): {' '.join(cmd)}\n{out}")
    return out


def _backup_db(ctx: Ctx, site: dict[str, Any], out_file: Path) -> None:
    host, port, db_name, db_user, db_pass = _db_conn_args(ctx, site)
    cmd = [
        "mysqldump",
        f"--host={host}",
        f"--port={port}",
        f"--user={db_user}",
        "--single-transaction",
        "--routines",
        "--triggers",
        "--events",
        "--databases",
        db_name,
    ]
    env = os.environ.copy()
    env["MYSQL_PWD"] = db_pass
    with gzip.open(out_file, "wb", compresslevel=9) as gz:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        assert p.stdout is not None
        shutil.copyfileobj(p.stdout, gz)
        err = p.stderr.read() if p.stderr else b""
        code = p.wait()
    if code != 0:
        out_file.unlink(missing_ok=True)
        raise RuntimeError(f"mysqldump selhal ({code}): {err.decode('utf-8', 'replace').strip()}")


def _restore_db(ctx: Ctx, site: dict[str, Any], src: Path) -> None:
    host, port, db_name, db_user, db_pass = _db_conn_args(ctx, site)
    lower = src.name.lower()
    if lower.endswith(".sql.gz"):
        data = gzip.decompress(src.read_bytes())
    elif lower.endswith(".sql"):
        data = src.read_bytes()
    else:
        raise RuntimeError("Podporujeme jen .sql nebo .sql.gz")
    cmd = ["mysql", f"--host={host}", f"--port={port}", f"--user={db_user}", db_name]
    _run_mysql(cmd, db_pass, input_bytes=data)


def _restore_data(root: Path, src: Path) -> None:
    lower = src.name.lower()
    with tempfile.TemporaryDirectory(prefix="oris-site-restore-") as td:
        tmp = Path(td)
        if lower.endswith(".zip"):
            _zip_is_safe(src)
            with zipfile.ZipFile(src, "r") as zf:
                zf.extractall(tmp)
        elif lower.endswith(".tar.gz") or lower.endswith(".tgz"):
            _tar_is_safe(src)
            with tarfile.open(src, "r:*") as tf:
                tf.extractall(tmp)
        else:
            raise RuntimeError("Obnova dat podporuje .zip, .tar.gz nebo .tgz")
        _copy_tree(tmp, root, skip_top={"backup"})


def _upload_safe_name(name: str, fallback: str = "upload.bin") -> str:
    name = Path(str(name).replace("\\", "/")).name
    if not name or name in {".", ".."}:
        name = fallback
    name = re.sub(r"[^A-Za-z0-9_.@+ -]+", "_", name).strip(" .")
    return name or fallback


def _upload_staging_dir(ctx: Ctx) -> Path:
    base = ctx.setting("upload_staging_dir", "/var/lib/oris-core/uploads").strip() or "/var/lib/oris-core/uploads"
    return (Path(base).expanduser() / "site-backup").resolve(strict=False)


def _suffix_ok(path: Path, suffixes: set[str]) -> bool:
    lower = path.name.lower()
    return any(lower.endswith(s.lower()) for s in suffixes)


def _safe_uploaded_restore_path(ctx: Ctx, raw: str, suffixes: set[str]) -> Path:
    if not raw:
        raise RuntimeError("Chybí cesta uploadovaného souboru.")

    p = Path(str(raw)).expanduser()
    if not p.is_absolute():
        p = _upload_staging_dir(ctx) / p.name

    try:
        rp = p.resolve(strict=True)
    except FileNotFoundError:
        raise RuntimeError("Uploadovaný soubor už neexistuje.")

    base = _upload_staging_dir(ctx)
    if not _under(rp, base):
        raise RuntimeError("Uploadovaný soubor není ve staging adresáři.")
    if not rp.is_file():
        raise RuntimeError("Uploadovaný soubor není soubor.")
    if not _suffix_ok(rp, suffixes):
        raise RuntimeError("Nepodporovaný typ uploadovaného souboru.")

    return rp


def _cleanup_uploaded_restore(ctx: Ctx, job_id: int, path: Path | None) -> None:
    if path is None:
        return
    try:
        rp = path.resolve(strict=False)
        base = _upload_staging_dir(ctx)
        if not _under(rp, base):
            ctx.job_log(job_id, f"Upload cleanup přeskočen mimo staging: {rp}")
            return
        if rp.exists():
            rp.unlink()
            ctx.job_log(job_id, f"Dočasný upload smazán: {rp.name}")
    except Exception as e:
        ctx.job_log(job_id, f"VAROVÁNÍ: dočasný upload se nepodařilo smazat: {e}")


def _store_uploaded_file(ctx: Ctx, job_id: int, src: Path, root: Path, typ: str, original_name: str) -> Path:
    if not src.is_file():
        raise RuntimeError("Upload soubor už neexistuje.")
    safe_original = _upload_safe_name(original_name, src.name or "upload.bin")
    dest_name = f"upload-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{safe_original}"
    dest = _safe_backup_path(root, typ, dest_name, must_exist=False)
    shutil.copy2(src, dest)
    try:
        src.unlink()
    except Exception:
        pass
    ctx.job_log(job_id, f"Upload uložen do záloh: {dest.name}")
    return dest


def handle(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    typ = str(job["type"])
    site_id = int(job.get("ref_id") or 0)
    payload = _payload(job)
    site = _site(ctx, site_id)
    root = _root(ctx, site)

    if typ == "site_backup_data":
        out_dir = _backup_dir(root, "data")
        out = out_dir / f"data-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
        ctx.job_log(job_id, f"Vytvářím zálohu dat: {out}")
        _create_data_zip(ctx, job_id, root, out)
        run(["chown", "www-data:www-data", str(out)], check=False)
        run(["chmod", "0660", str(out)], check=False)
        ctx.job_log(job_id, f"Záloha dat hotová: {out.name}")
        return

    if typ == "site_backup_db":
        out_dir = _backup_dir(root, "db")
        out = out_dir / f"db-{datetime.now().strftime('%Y%m%d-%H%M%S')}.sql.gz"
        ctx.job_log(job_id, f"Vytvářím zálohu DB: {out}")
        _backup_db(ctx, site, out)
        run(["chown", "www-data:www-data", str(out)], check=False)
        run(["chmod", "0660", str(out)], check=False)
        ctx.job_log(job_id, f"Záloha DB hotová: {out.name}")
        return

    if typ == "site_restore_data_existing":
        name = str(payload.get("file") or "")
        src = _safe_backup_path(root, "data", name)
        ctx.job_log(job_id, f"Obnovuji data z existující zálohy: {src.name}")
        _restore_data(root, src)
        run(["chown", "-R", "www-data:www-data", str(root)], check=False)
        ctx.job_log(job_id, "Obnova dat hotová.")
        return

    if typ == "site_restore_db_existing":
        name = str(payload.get("file") or "")
        src = _safe_backup_path(root, "db", name)
        ctx.job_log(job_id, f"Obnovuji DB z existující zálohy: {src.name}")
        _restore_db(ctx, site, src)
        ctx.job_log(job_id, "Obnova DB hotová.")
        return

    if typ == "site_restore_data_upload":
        src: Path | None = None
        try:
            src = _safe_uploaded_restore_path(ctx, str(payload.get("upload_path") or ""), {".zip", ".tar.gz", ".tgz"})
            original = str(payload.get("original_name") or src.name or "upload.zip")
            ctx.job_log(job_id, f"Obnovuji data z uploadu: {original}")
            _restore_data(root, src)
            run(["chown", "-R", "www-data:www-data", str(root)], check=False)
            ctx.job_log(job_id, "Obnova dat z uploadu hotová.")
        finally:
            _cleanup_uploaded_restore(ctx, job_id, src)
        return

    if typ == "site_restore_db_upload":
        src: Path | None = None
        try:
            src = _safe_uploaded_restore_path(ctx, str(payload.get("upload_path") or ""), {".sql", ".sql.gz"})
            original = str(payload.get("original_name") or src.name or "upload.sql")
            ctx.job_log(job_id, f"Obnovuji DB z uploadu: {original}")
            _restore_db(ctx, site, src)
            ctx.job_log(job_id, "Obnova DB z uploadu hotová.")
        finally:
            _cleanup_uploaded_restore(ctx, job_id, src)
        return

    if typ == "site_backup_delete":
        btype = str(payload.get("backup_type") or "")
        if btype not in {"data", "db"}:
            raise RuntimeError("Neplatný typ zálohy.")
        name = str(payload.get("file") or "")
        path = _safe_backup_path(root, btype, name)
        path.unlink()
        ctx.job_log(job_id, f"Záloha smazána: {path.name}")
        return

    raise RuntimeError(f"Plugin site_backup neumí job {typ}")

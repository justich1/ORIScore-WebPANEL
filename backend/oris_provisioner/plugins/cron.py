from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from ..common import atomic_write, run
from ..context import Ctx

HANDLED_TYPES = {"cron_apply", "cron_run"}

CRON_FILE = Path("/etc/cron.d/oris-sites")
BACKEND_DIR = Path(__file__).resolve().parents[2]
INSTALL_DIR = BACKEND_DIR.parent


def _safe_user(user: str) -> str:
    import re
    return user if re.match(r"^[A-Za-z0-9_.-]+$", user or "") else "www-data"


def _python_bin(ctx: Ctx) -> str:
    py = str(ctx.cfg.get("python_bin") or "").strip()
    if py:
        return py
    cand = INSTALL_DIR / ".venv" / "bin" / "python"
    if cand.exists():
        return str(cand)
    return "/opt/oris_webserver/.venv/bin/python"


def _backend_dir(ctx: Ctx) -> str:
    p = str(ctx.cfg.get("backend_dir") or BACKEND_DIR).strip()
    return str(Path(p).resolve())


def _config_path() -> str:
    return os.environ.get("ORIS_PROVISIONER_CONFIG", "/etc/oris-panel/provisioner.json")


def _write_cron(ctx: Ctx, job_id: int) -> None:
    rows = ctx.q("SELECT cj.*, s.root_path, s.domain FROM cron_jobs cj JOIN sites s ON s.id=cj.site_id WHERE cj.enabled=1 ORDER BY cj.id ASC")
    lines = ["# ORIS generated cron file - do not edit manually", "SHELL=/bin/bash", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", ""]
    py = _python_bin(ctx)
    backend = _backend_dir(ctx)
    config = _config_path()

    for r in rows:
        schedule = str(r["schedule"]).strip()
        if len(schedule.split()) != 5:
            ctx.job_log(job_id, f"Přeskakuji cron #{r['id']}: neplatný schedule")
            continue

        # /etc/cron.d spouští pouze runner jako root, aby mohl číst /etc/oris-panel/provisioner.json.
        # Samotný příkaz už cron_runner pustí pod uživatelem z cron_jobs.run_as.
        root = str(r.get("root_path") or "/tmp")
        line = (
            f"{schedule} root cd {shlex.quote(root)} && "
            f"ORIS_PROVISIONER_CONFIG={shlex.quote(config)} "
            f"PYTHONPATH={shlex.quote(backend)} "
            f"{shlex.quote(py)} -m oris_provisioner.cron_runner {int(r['id'])} "
            f">> /var/log/oris-core/cron.log 2>&1"
        )
        lines.append(line)

    lines.append("")
    atomic_write(CRON_FILE, "\n".join(lines), 0o644)
    run(["systemctl", "enable", "--now", "cron"], check=False)
    run(["systemctl", "restart", "cron"], check=False)
    ctx.job_log(job_id, f"Cron konfigurace zapsána: {CRON_FILE} ({len(rows)} aktivních úloh)")


def handle(ctx: Ctx, job: dict) -> None:
    job_id = int(job["id"])
    typ = str(job["type"])
    if typ == "cron_apply":
        _write_cron(ctx, job_id)
        return
    if typ == "cron_run":
        payload = job.get("payload")
        if isinstance(payload, str) and payload.strip():
            try: payload = json.loads(payload)
            except Exception: payload = {}
        cron_id = int((payload or {}).get("cron_id") or job.get("ref_id") or 0)
        py = _python_bin(ctx)
        backend = _backend_dir(ctx)
        config = _config_path()
        rc, out = run(["env", f"ORIS_PROVISIONER_CONFIG={config}", f"PYTHONPATH={backend}", py, "-m", "oris_provisioner.cron_runner", str(cron_id)], check=False)
        ctx.job_log(job_id, out.strip() or f"cron_runner exit={rc}")
        if rc != 0:
            raise RuntimeError(f"Cron ruční spuštění selhalo exit={rc}")
        return
    raise RuntimeError(f"Plugin cron neumí job {typ}")

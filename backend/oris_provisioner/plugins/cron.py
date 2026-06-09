from __future__ import annotations

import json
from pathlib import Path

from ..common import atomic_write, run
from ..context import Ctx

HANDLED_TYPES = {"cron_apply", "cron_run"}

CRON_FILE = Path("/etc/cron.d/oris-sites")


def _safe_user(user: str) -> str:
    import re
    return user if re.match(r"^[A-Za-z0-9_.-]+$", user or "") else "www-data"


def _write_cron(ctx: Ctx, job_id: int) -> None:
    rows = ctx.q("SELECT cj.*, s.root_path, s.domain FROM cron_jobs cj JOIN sites s ON s.id=cj.site_id WHERE cj.enabled=1 ORDER BY cj.id ASC")
    lines = ["# ORIS generated cron file - do not edit manually", "SHELL=/bin/bash", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", ""]
    py = ctx.cfg.get("python_bin") or "/opt/oris-hosting/.venv/bin/python"
    for r in rows:
        schedule = str(r["schedule"]).strip()
        if len(schedule.split()) != 5:
            ctx.job_log(job_id, f"Přeskakuji cron #{r['id']}: neplatný schedule")
            continue
        user = _safe_user(str(r.get("run_as") or "www-data"))
        root = str(r.get("root_path") or "/tmp").replace(" ", "\\ ")
        line = f"{schedule} {user} cd {root} && ORIS_PROVISIONER_CONFIG=/etc/oris-panel/provisioner.json PYTHONPATH=/opt/oris-hosting/backend {py} -m oris_provisioner.cron_runner {int(r['id'])} >> /var/log/oris-core/cron.log 2>&1"
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
        py = ctx.cfg.get("python_bin") or "/opt/oris-hosting/.venv/bin/python"
        rc, out = run([py, "-m", "oris_provisioner.cron_runner", str(cron_id)], check=False)
        ctx.job_log(job_id, out.strip() or f"cron_runner exit={rc}")
        if rc != 0:
            raise RuntimeError(f"Cron ruční spuštění selhalo exit={rc}")
        return
    raise RuntimeError(f"Plugin cron neumí job {typ}")

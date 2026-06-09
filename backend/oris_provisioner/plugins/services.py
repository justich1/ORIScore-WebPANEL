from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from ..common import run
from ..context import Ctx

HANDLED_TYPES = {
    "service_status_refresh",
    "service_action",
}

ALLOWED_ACTIONS = {"start", "stop", "restart", "reload"}

# UI používá service_key. Provisioner si jej tady převádí na skutečný systemd unit.
SERVICE_DEFS: dict[str, dict[str, Any]] = {
    "nginx": {"label": "NGINX", "unit": "nginx"},
    "php-fpm": {"label": "PHP-FPM", "unit": "auto:php-fpm"},
    "mariadb": {"label": "MariaDB", "unit": "mariadb"},
    "postfix": {"label": "Postfix", "unit": "postfix"},
    "dovecot": {"label": "Dovecot", "unit": "dovecot"},
    "rspamd": {"label": "Rspamd", "unit": "rspamd"},
    "redis": {"label": "Redis", "unit": "redis-server"},
    "fail2ban": {"label": "Fail2ban", "unit": "fail2ban"},
    "ufw": {"label": "UFW", "unit": "ufw"},
    "vsftpd": {"label": "VSFTPD", "unit": "vsftpd"},
    "cron": {"label": "Cron", "unit": "cron"},
    "wireguard": {"label": "WireGuard wg0", "unit": "wg-quick@wg0"},
    "provisioner": {"label": "ORIS Provisioner", "unit": "oris-provisioner"},
    "stats-worker": {"label": "ORIS Stats Worker", "unit": "oris-stats-worker"},
}


def _payload(job: dict[str, Any]) -> dict[str, Any]:
    raw = job.get("payload") or "{}"
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _systemctl(args: list[str], *, check: bool = False) -> tuple[int, str]:
    return run(["systemctl", *args], check=check)


def _unit_exists(unit: str) -> bool:
    rc, _ = _systemctl(["status", unit, "--no-pager"], check=False)
    # systemctl status vrací 0 active, 3 inactive, 4 not-found.
    return rc != 4


def _detect_php_fpm_unit() -> str:
    candidates: list[str] = []

    # Nejspolehlivější je systemd list-unit-files.
    rc, out = _systemctl(["list-unit-files", "--type=service", "--no-legend"], check=False)
    if rc == 0:
        for line in out.splitlines():
            name = line.split()[0] if line.split() else ""
            if re.fullmatch(r"php[0-9.]+-fpm\.service", name):
                candidates.append(name[:-8])

    # Fallback podle unit souborů.
    for base in (Path("/lib/systemd/system"), Path("/usr/lib/systemd/system"), Path("/etc/systemd/system")):
        if base.exists():
            for p in base.glob("php*-fpm.service"):
                candidates.append(p.name[:-8])

    # Fallback podle socketů.
    runphp = Path("/run/php")
    if runphp.exists():
        for p in runphp.glob("php*-fpm.sock"):
            candidates.append(p.name.replace(".sock", ""))

    unique = sorted(set(candidates), key=_php_version_key)
    if not unique:
        raise RuntimeError("Nenalezen žádný php*-fpm systemd unit")
    return unique[-1]


def _php_version_key(unit: str) -> tuple[int, ...]:
    m = re.search(r"php([0-9.]+)-fpm", unit)
    if not m:
        return (0,)
    return tuple(int(x) for x in m.group(1).split(".") if x.isdigit())


def resolve_unit(service_key: str) -> str:
    if service_key not in SERVICE_DEFS:
        raise RuntimeError(f"Nepovolená služba: {service_key}")
    unit = str(SERVICE_DEFS[service_key]["unit"])
    if unit == "auto:php-fpm":
        return _detect_php_fpm_unit()
    return unit


def _status_for(service_key: str) -> dict[str, Any]:
    label = SERVICE_DEFS[service_key]["label"]
    row: dict[str, Any] = {
        "key": service_key,
        "label": label,
        "unit": "",
        "active": "unknown",
        "enabled": "unknown",
        "active_enter_timestamp": "",
        "error": "",
    }
    try:
        unit = resolve_unit(service_key)
        row["unit"] = unit
        if not _unit_exists(unit):
            row["active"] = "not-found"
            row["enabled"] = "not-found"
            return row

        rc, out = _systemctl(["is-active", unit], check=False)
        row["active"] = (out.strip() or "unknown")
        rc, out = _systemctl(["is-enabled", unit], check=False)
        row["enabled"] = (out.strip() or "unknown")
        rc, out = _systemctl(["show", unit, "--property=ActiveEnterTimestamp", "--value"], check=False)
        row["active_enter_timestamp"] = out.strip()
        return row
    except Exception as e:
        row["error"] = str(e)
        return row


def write_status(ctx: Ctx, job_id: int) -> None:
    rows = [_status_for(key) for key in SERVICE_DEFS.keys()]
    data = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "services": rows,
    }
    ctx.set_setting("service_status_json", json.dumps(data, ensure_ascii=False))
    ctx.job_log(job_id, "Stavy služeb uloženy do settings.service_status_json")


def service_action(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    payload = _payload(job)
    service_key = str(payload.get("service_key") or "")
    action = str(payload.get("action") or "")

    if service_key not in SERVICE_DEFS:
        raise RuntimeError(f"Nepovolená služba: {service_key}")
    if action not in ALLOWED_ACTIONS:
        raise RuntimeError(f"Nepovolená akce: {action}")

    unit = resolve_unit(service_key)
    if not _unit_exists(unit):
        raise RuntimeError(f"Unit neexistuje: {unit}")

    # reload některé služby neumí. Když selže reload, chyba zůstane v jobu vidět.
    ctx.job_log(job_id, f"systemctl {action} {unit}")
    rc, out = _systemctl([action, unit], check=False)
    if rc != 0:
        raise RuntimeError(f"systemctl {action} {unit} selhal exit={rc}:\n{out}")

    write_status(ctx, job_id)


def handle(ctx: Ctx, job: dict[str, Any]) -> None:
    typ = str(job.get("type") or "")
    job_id = int(job["id"])

    if typ == "service_status_refresh":
        write_status(ctx, job_id)
        return

    if typ == "service_action":
        service_action(ctx, job)
        return

    raise RuntimeError(f"Neznámý service job: {typ}")

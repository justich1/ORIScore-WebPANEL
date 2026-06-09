from __future__ import annotations

import re
from pathlib import Path

from ..common import atomic_write, run
from ..context import Ctx

HANDLED_TYPES = {"php_apply_config"}


def _fpm_info() -> tuple[str, Path, Path, str]:
    dirs = sorted(Path("/etc/php").glob("*/fpm"), key=lambda p: p.parts[-2])
    if not dirs:
        raise RuntimeError("Nenalezeno /etc/php/*/fpm")
    fpm = dirs[-1]
    ver = fpm.parts[-2]
    return ver, fpm / "conf.d", fpm / "pool.d", f"php{ver}-fpm"


def _setting(ctx: Ctx, key: str, default: str) -> str:
    return ctx.setting(key, default).strip() or default


def _size(v: str, default: str) -> str:
    return v if re.match(r"^\d+[KMG]?$", v, re.I) else default


def _num(v: str, default: str) -> str:
    return v if re.match(r"^\d+$", v) else default


def _replace_or_append(text: str, key: str, value: str) -> str:
    lines = text.splitlines()
    done = False
    out = []
    pat = re.compile(r"^\s*;?\s*" + re.escape(key) + r"\s*=")
    for line in lines:
        if pat.match(line):
            out.append(f"{key} = {value}")
            done = True
        else:
            out.append(line)
    if not done:
        out.append(f"{key} = {value}")
    return "\n".join(out) + "\n"


def handle(ctx: Ctx, job: dict) -> None:
    job_id = int(job["id"])
    ver, confd, poold, unit = _fpm_info()
    confd.mkdir(parents=True, exist_ok=True)
    poold.mkdir(parents=True, exist_ok=True)

    ini = f"""; ORIS global PHP overrides
memory_limit = {_size(_setting(ctx,'php_memory_limit','512M'),'512M')}
upload_max_filesize = {_size(_setting(ctx,'php_upload_max_filesize','256M'),'256M')}
post_max_size = {_size(_setting(ctx,'php_post_max_size','256M'),'256M')}
max_execution_time = {_num(_setting(ctx,'php_max_execution_time','300'),'300')}
max_input_time = {_num(_setting(ctx,'php_max_input_time','300'),'300')}
date.timezone = {_setting(ctx,'php_timezone','Europe/Prague')}
opcache.enable = {_num(_setting(ctx,'php_opcache_enable','1'),'1')}
opcache.memory_consumption = {_num(_setting(ctx,'php_opcache_memory_consumption','256'),'256')}
opcache.max_accelerated_files = {_num(_setting(ctx,'php_opcache_max_accelerated_files','20000'),'20000')}
opcache.validate_timestamps = {_num(_setting(ctx,'php_opcache_validate_timestamps','1'),'1')}
opcache.revalidate_freq = {_num(_setting(ctx,'php_opcache_revalidate_freq','2'),'2')}
"""
    atomic_write(confd / "99-oris-panel.ini", ini)
    www = poold / "www.conf"
    if www.exists():
        text = www.read_text(encoding="utf-8", errors="ignore")
        pm = _setting(ctx, "php_pm", "dynamic")
        if pm not in {"dynamic", "ondemand", "static"}:
            pm = "dynamic"
        repl = {
            "pm": pm,
            "pm.max_children": _num(_setting(ctx,"php_pm_max_children","20"),"20"),
            "pm.start_servers": _num(_setting(ctx,"php_pm_start_servers","4"),"4"),
            "pm.min_spare_servers": _num(_setting(ctx,"php_pm_min_spare_servers","2"),"2"),
            "pm.max_spare_servers": _num(_setting(ctx,"php_pm_max_spare_servers","6"),"6"),
            "pm.max_requests": _num(_setting(ctx,"php_pm_max_requests","500"),"500"),
            "request_terminate_timeout": _num(_setting(ctx,"php_request_terminate_timeout","300"),"300"),
        }
        for k, v in repl.items():
            text = _replace_or_append(text, k, v)
        atomic_write(www, text)
    rc, out = run(["systemctl", "restart", unit], check=False)
    ctx.job_log(job_id, out.strip() or f"Restart {unit}: exit={rc}")
    if rc != 0:
        raise RuntimeError(f"Restart PHP-FPM selhal: {unit}")
    ctx.job_log(job_id, f"PHP konfigurace aplikována pro verzi {ver}.")

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pymysql
from pymysql.cursors import DictCursor

from .common import load_config


def connect(cfg):
    db = cfg["db"]
    return pymysql.connect(host=db.get("host", "127.0.0.1"), port=int(db.get("port", 3306)), user=db.get("user"), password=db.get("pass"), database=db.get("name"), charset="utf8mb4", autocommit=True, cursorclass=DictCursor)


def _safe_user(user: str) -> str:
    return user if re.match(r"^[A-Za-z0-9_.-]+$", user or "") else "www-data"


def _run_command(cmd: str, root: Path, user: str) -> subprocess.CompletedProcess[str]:
    root_s = str(root if root.exists() and root.is_dir() else Path("/tmp"))
    shell_cmd = f"cd {shlex.quote(root_s)} && {cmd}"

    if os.geteuid() == 0:
        if shutil.which("runuser"):
            argv = ["runuser", "-u", user, "--", "bash", "-lc", shell_cmd]
        else:
            argv = ["su", "-s", "/bin/bash", "-c", shell_cmd, user]
    else:
        argv = ["bash", "-lc", shell_cmd]

    return subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3600)


def main():
    if len(sys.argv) < 2:
        print("missing cron id", file=sys.stderr); return 2
    cron_id = int(sys.argv[1])
    cfg = load_config()
    conn = connect(cfg)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT cj.*, s.root_path, s.domain FROM cron_jobs cj JOIN sites s ON s.id=cj.site_id WHERE cj.id=%s", (cron_id,))
            row = cur.fetchone()
        if not row:
            print(f"cron #{cron_id} not found", file=sys.stderr); return 1
        if int(row.get("enabled") or 0) != 1:
            print(f"cron #{cron_id} disabled"); return 0
        root = Path(str(row.get("root_path") or "/tmp"))
        cmd = str(row.get("command") or "")
        user = _safe_user(str(row.get("run_as") or "www-data"))
        print(f"[{datetime.now().isoformat()}] ORIS cron #{cron_id} {row.get('domain')} as {user} $ {cmd}")
        p = _run_command(cmd, root, user)
        out = (p.stdout or "")[-12000:]
        print(out, end="")
        with conn.cursor() as cur:
            cur.execute("UPDATE cron_jobs SET last_run_at=NOW(), last_exit_code=%s, last_output=%s, updated_at=NOW() WHERE id=%s", (p.returncode, out, cron_id))
        return p.returncode
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())

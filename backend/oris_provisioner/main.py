from __future__ import annotations

import importlib
import os
import signal
import time
from datetime import datetime
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

from .common import load_config, log_file
from .context import Ctx

STOP = False


def _stop(signum, frame):
    global STOP
    STOP = True


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)


PLUGIN_MODULES = [
    "oris_provisioner.plugins.site",
    "oris_provisioner.plugins.site_backup",
    "oris_provisioner.plugins.mariadb",
    "oris_provisioner.plugins.ftp",
    "oris_provisioner.plugins.certbot",
    "oris_provisioner.plugins.proxy",
    "oris_provisioner.plugins.php",
    "oris_provisioner.plugins.cron",
    "oris_provisioner.plugins.panel",
    "oris_provisioner.plugins.security",
    "oris_provisioner.plugins.wireguard",
    "oris_provisioner.plugins.mail",
    "oris_provisioner.plugins.services",
]


def main_log(msg: str) -> None:
    log_file("/var/log/oris-core/provisioner-python.log", f"{datetime.now().isoformat()} {msg}")


def connect(db: dict[str, Any], with_db: bool = True):
    return pymysql.connect(
        host=db.get("host", "127.0.0.1"),
        port=int(db.get("port", 3306)),
        user=db.get("user", ""),
        password=db.get("pass", ""),
        database=db.get("name") if with_db else None,
        charset="utf8mb4",
        autocommit=True,
        cursorclass=DictCursor,
        connect_timeout=10,
        read_timeout=30,
        write_timeout=30,
    )


class Provisioner:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.db_cfg = cfg["db"]
        self.conn = connect(self.db_cfg, True)
        self.plugins = self.load_plugins()

    def load_plugins(self):
        mapping = {}
        for mod_name in PLUGIN_MODULES:
            mod = importlib.import_module(mod_name)
            for typ in getattr(mod, "HANDLED_TYPES", set()):
                mapping[typ] = mod
        main_log("loaded plugins: " + ", ".join(sorted(mapping)))
        return mapping

    def ctx(self):
        return Ctx(self.cfg, self.conn)

    def reconnect(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.conn = connect(self.db_cfg, True)

    def one(self, sql: str, args: tuple[Any, ...] = ()):
        with self.conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchone()

    def exec(self, sql: str, args: tuple[Any, ...] = ()) -> int:
        with self.conn.cursor() as cur:
            return cur.execute(sql, args)

    def job_log(self, job_id: int, line: str) -> None:
        self.ctx().job_log(job_id, line)

    def process_one(self, job: dict[str, Any]) -> None:
        job_id = int(job["id"])
        typ = str(job["type"])
        ref = int(job.get("ref_id") or 0)
        self.job_log(job_id, f"Start {typ} ref={ref} plugin=python")
        mod = self.plugins.get(typ)
        if mod is None:
            from oris_provisioner.plugins import stub
            stub.handle(self.ctx(), job)
        else:
            mod.handle(self.ctx(), job)
        self.exec("UPDATE jobs SET status='done', updated_at=NOW(), error=NULL WHERE id=%s", (job_id,))
        self.job_log(job_id, "Hotovo.")

    def loop(self, once: bool = False):
        main_log(f"started pid={os.getpid()} once={'yes' if once else 'no'}")
        while not STOP:
            try:
                try:
                    self.exec("SELECT 1")
                except Exception:
                    self.reconnect()
                job = self.one("SELECT * FROM jobs WHERE status='queued' ORDER BY id ASC LIMIT 1")
                if not job:
                    if once:
                        return
                    time.sleep(2)
                    continue
                job_id = int(job["id"])
                changed = self.exec("UPDATE jobs SET status='running', updated_at=NOW(), error=NULL WHERE id=%s AND status='queued'", (job_id,))
                if changed < 1:
                    continue
                try:
                    self.process_one(job)
                except Exception as e:
                    msg = str(e)
                    try:
                        self.job_log(job_id, "ERROR: " + msg)
                    except Exception:
                        pass
                    self.exec("UPDATE jobs SET status='error', error=%s, updated_at=NOW() WHERE id=%s", (msg, job_id))
                    ref = int(job.get("ref_id") or 0)
                    typ = str(job.get("type") or "")
                    if typ.startswith("ftp_"):
                        self.exec("UPDATE ftp_accounts SET status='error', last_error=%s WHERE id=%s", (msg, ref))
                    if typ in {"provision_site", "deprovision_site", "site_ensure_db", "site_reset_db_pass", "site_delete_db", "certbot_issue", "certbot_test_acme", "site_backup_data", "site_backup_db", "site_restore_data_existing", "site_restore_db_existing", "site_restore_data_upload", "site_restore_db_upload", "site_backup_delete"}:
                        self.exec("UPDATE sites SET last_error=%s WHERE id=%s", (msg, ref))
                    if typ in {"certbot_issue_proxy", "certbot_test_acme_proxy", "provision_tunnel", "deprovision_tunnel"}:
                        self.exec("UPDATE tunnels SET last_error=%s WHERE id=%s", (msg, ref))
            except Exception as e:
                main_log("LOOP ERROR: " + str(e))
                if once:
                    raise
                time.sleep(5)
            if once:
                return


def main():
    import sys
    once = "--once" in sys.argv
    cfg = load_config()
    Provisioner(cfg).loop(once=once)


if __name__ == "__main__":
    main()

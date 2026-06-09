from __future__ import annotations

import os
import re
import secrets
import string
from datetime import datetime
from pathlib import Path
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

from .common import atomic_write, run


def now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def randpass(n: int = 24) -> str:
    chars = string.ascii_letters + string.digits + "_@%+=:,.^-"
    return "".join(secrets.choice(chars) for _ in range(max(1, n - 2))) + "A1"


class Ctx:
    def __init__(self, cfg: dict[str, Any], conn):
        self.cfg = cfg
        self.conn = conn
        self.db_cfg = cfg["db"]
        self.admin_cfg = cfg.get("db_admin", {})

    def q(self, sql: str, args: tuple[Any, ...] = ()):  # list rows
        with self.conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchall()

    def one(self, sql: str, args: tuple[Any, ...] = ()):  # single row
        with self.conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchone()

    def exec(self, sql: str, args: tuple[Any, ...] = ()) -> int:
        with self.conn.cursor() as cur:
            return cur.execute(sql, args)

    def admin_db(self):
        return pymysql.connect(
            host=self.db_cfg.get("host", "127.0.0.1"),
            port=int(self.db_cfg.get("port", 3306)),
            user=self.admin_cfg.get("user", "oris_admin"),
            password=self.admin_cfg.get("pass", ""),
            charset="utf8mb4",
            autocommit=True,
            cursorclass=DictCursor,
            connect_timeout=10,
            read_timeout=30,
            write_timeout=30,
        )

    def setting(self, key: str, default: str = "") -> str:
        row = self.one("SELECT v FROM settings WHERE k=%s", (key,))
        if row and row.get("v") is not None:
            return str(row["v"])
        # config fallback
        paths = self.cfg.get("paths", {})
        if key == "acme_webroot":
            return str(paths.get("acme_webroot", default or "/var/www/letsencrypt"))
        if key == "sites_base_dir":
            return str(paths.get("sites_base_dir", default or "/var/lib/oris-core/sites"))
        return default

    def set_setting(self, key: str, value: str) -> None:
        self.exec("INSERT INTO settings(k,v) VALUES(%s,%s) ON DUPLICATE KEY UPDATE v=VALUES(v)", (key, value))

    def job_log(self, job_id: int, line: str) -> None:
        self.exec(
            "UPDATE jobs SET log=CONCAT(IFNULL(log,''), %s) WHERE id=%s",
            (f"[{now()}] {line}\n", job_id),
        )

    def php_socket(self) -> str:
        preferred = Path("/run/php/php-fpm.sock")
        if preferred.exists():
            return str(preferred)
        sockets = sorted(Path("/run/php").glob("php*-fpm.sock")) if Path("/run/php").exists() else []
        if sockets:
            return str(sockets[-1])
        return "/run/php/php-fpm.sock"

    @staticmethod
    def domain_valid(domain: str) -> bool:
        return bool(re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", domain))

    @staticmethod
    def ident_valid(name: str) -> bool:
        return bool(re.match(r"^[A-Za-z0-9_]+$", name))

    def ensure_acme_webroot(self) -> str:
        acme = self.setting("acme_webroot", "/var/www/letsencrypt").rstrip("/")
        Path(acme, ".well-known/acme-challenge").mkdir(parents=True, exist_ok=True)
        run(["chown", "-R", "www-data:www-data", acme], check=False)
        return acme

    def nginx_reload_checked(self) -> None:
        run(["nginx", "-t"])
        run(["systemctl", "reload", "nginx"])

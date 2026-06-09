from __future__ import annotations

from ..context import Ctx, randpass

HANDLED_TYPES = {"site_ensure_db", "site_reset_db_pass", "site_delete_db"}


def handle(ctx: Ctx, job: dict) -> None:
    job_id = int(job["id"])
    typ = str(job["type"])
    site_id = int(job.get("ref_id") or 0)

    if typ == "site_ensure_db":
        site = ctx.one("SELECT * FROM sites WHERE id=%s", (site_id,))
        if not site:
            raise RuntimeError(f"Web nenalezen: {site_id}")
        if site.get("db_name") and site.get("db_user"):
            ctx.job_log(job_id, f"DB už existuje: {site['db_name']}")
            return
        db_name = f"oris_site_{site_id}"
        db_user = f"oris_u_{site_id}"
        db_pass = randpass(24)
        admin = ctx.admin_db()
        try:
            with admin.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                cur.execute(f"CREATE USER IF NOT EXISTS `{db_user}`@'localhost' IDENTIFIED BY %s", (db_pass,))
                cur.execute(f"ALTER USER `{db_user}`@'localhost' IDENTIFIED BY %s", (db_pass,))
                cur.execute(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO `{db_user}`@'localhost'")
                cur.execute("FLUSH PRIVILEGES")
        finally:
            admin.close()
        ctx.exec("UPDATE sites SET db_name=%s, db_user=%s, db_pass=%s WHERE id=%s", (db_name, db_user, db_pass, site_id))
        ctx.job_log(job_id, f"DB vytvořena: {db_name} / {db_user}")
        return

    if typ == "site_reset_db_pass":
        site = ctx.one("SELECT db_user FROM sites WHERE id=%s", (site_id,))
        if not site or not site.get("db_user"):
            raise RuntimeError("Web nemá DB user.")
        db_user = str(site["db_user"])
        if not ctx.ident_valid(db_user):
            raise RuntimeError("Neplatný DB user")
        db_pass = randpass(24)
        admin = ctx.admin_db()
        try:
            with admin.cursor() as cur:
                cur.execute(f"ALTER USER `{db_user}`@'localhost' IDENTIFIED BY %s", (db_pass,))
                cur.execute("FLUSH PRIVILEGES")
        finally:
            admin.close()
        ctx.exec("UPDATE sites SET db_pass=%s WHERE id=%s", (db_pass, site_id))
        ctx.job_log(job_id, "DB heslo resetováno.")
        return

    if typ == "site_delete_db":
        site = ctx.one("SELECT db_name,db_user FROM sites WHERE id=%s", (site_id,))
        if not site:
            ctx.job_log(job_id, "Web v DB nenalezen, není co mazat.")
            return
        admin = ctx.admin_db()
        try:
            with admin.cursor() as cur:
                if site.get("db_name") and ctx.ident_valid(str(site["db_name"])):
                    cur.execute(f"DROP DATABASE IF EXISTS `{site['db_name']}`")
                if site.get("db_user") and ctx.ident_valid(str(site["db_user"])):
                    cur.execute(f"DROP USER IF EXISTS `{site['db_user']}`@'localhost'")
                cur.execute("FLUSH PRIVILEGES")
        finally:
            admin.close()
        ctx.exec("UPDATE sites SET db_name=NULL, db_user=NULL, db_pass=NULL WHERE id=%s", (site_id,))
        ctx.job_log(job_id, "DB smazána.")
        return

    raise RuntimeError(f"Plugin mariadb neumí job {typ}")

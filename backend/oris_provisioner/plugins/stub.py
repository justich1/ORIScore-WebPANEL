from __future__ import annotations

from ..context import Ctx

HANDLED_TYPES = set()


def handle(ctx: Ctx, job: dict) -> None:
    typ = str(job.get("type") or "")
    job_id = int(job["id"])
    ctx.job_log(job_id, f"Job '{typ}' je v přípravě. Základ fronty běží, ale tato funkce ještě nemá plugin.")

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


def load_config() -> dict[str, Any]:
    path = os.environ.get("ORIS_PROVISIONER_CONFIG", "/etc/oris-panel/provisioner.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run(cmd: list[str] | str, *, check: bool = True, shell: bool = False, input_text: str | None = None) -> tuple[int, str]:
    p = subprocess.run(
        cmd,
        shell=shell,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out = p.stdout or ""
    if check and p.returncode != 0:
        raise RuntimeError(f"CMD failed ({p.returncode}): {cmd}\n{out}")
    return p.returncode, out


def atomic_write(path: str | Path, content: str, mode: int = 0o644) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)


def log_file(path: str, line: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")

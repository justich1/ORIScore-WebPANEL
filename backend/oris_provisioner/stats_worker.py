from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any


def cmd_json(cmd: list[str]) -> Any:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return json.loads(out) if out.strip() else []
    except Exception:
        return []


def df_mounts():
    try:
        out = subprocess.check_output(["df", "-B1", "-P", "-T"], text=True, stderr=subprocess.DEVNULL).splitlines()[1:]
    except Exception:
        return []
    rows = []
    for line in out:
        c = line.split()
        if len(c) < 7:
            continue
        fs, typ, total, used, avail, pct, mp = c[:7]
        if typ in {"tmpfs", "devtmpfs", "overlay", "squashfs"}:
            continue
        total_i, used_i, free_i = int(total), int(used), int(avail)
        rows.append({"fs": fs, "type": typ, "mountpoint": mp, "total": total_i, "used": used_i, "free": free_i, "used_pct": round((used_i / total_i) * 100, 2) if total_i else 0})
    return rows


def mem_stats():
    d = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            parts = line.replace(":", "").split()
            if len(parts) >= 2:
                d[parts[0]] = int(parts[1]) * 1024
    except Exception:
        pass
    total = d.get("MemTotal", 0)
    available = d.get("MemAvailable", 0)
    used = max(0, total - available)
    return {"total": total, "available": available, "used": used, "used_pct": round((used / total) * 100, 2) if total else 0}


def proc_stat():
    try:
        parts = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        vals = [int(x) for x in parts]
        idle = vals[3] + vals[4]
        return {"total": sum(vals), "idle": idle}
    except Exception:
        return {"total": 0, "idle": 0}


def cpu_stats(api_dir: Path):
    now = proc_stat()
    prev_file = api_dir / ".cpu_prev.json"
    prev = None
    if prev_file.exists():
        try:
            prev = json.loads(prev_file.read_text())
        except Exception:
            prev = None
    prev_file.write_text(json.dumps(now))
    pct = None
    if prev and now["total"] > prev.get("total", 0):
        total_delta = now["total"] - int(prev["total"])
        idle_delta = now["idle"] - int(prev["idle"])
        pct = max(0, min(100, round((1 - idle_delta / total_delta) * 100, 2))) if total_delta else 0
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        load1 = load5 = load15 = 0
    return {"usage_pct": pct, "load1": load1, "load5": load5, "load15": load15}


def route_src(cmd: list[str]):
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        parts = out.split()
        if "src" in parts:
            return parts[parts.index("src") + 1]
    except Exception:
        return None
    return None


def network_stats():
    ifaces = {}
    rx_sum = tx_sum = 0
    for p in Path("/sys/class/net").glob("*"):
        try:
            rx = int((p / "statistics/rx_bytes").read_text())
            tx = int((p / "statistics/tx_bytes").read_text())
        except Exception:
            rx = tx = 0
        rx_sum += rx
        tx_sum += tx
        ifaces[p.name] = {"rx_bytes": rx, "tx_bytes": tx}
    by = {}
    for l in cmd_json(["ip", "-j", "link"]) or []:
        name = l.get("ifname")
        if name:
            by[name] = {"ifname": name, "operstate": l.get("operstate"), "state": l.get("state"), "mac": l.get("address"), "mtu": l.get("mtu"), "ipv4": [], "ipv6": []}
    for a in cmd_json(["ip", "-j", "addr"]) or []:
        name = a.get("ifname")
        if not name:
            continue
        by.setdefault(name, {"ifname": name, "operstate": None, "state": None, "mac": None, "mtu": None, "ipv4": [], "ipv6": []})
        for ai in a.get("addr_info", []):
            ip = ai.get("local")
            pl = ai.get("prefixlen")
            fam = ai.get("family")
            if ip and pl is not None and fam == "inet":
                by[name]["ipv4"].append({"ip": ip, "prefixlen": int(pl)})
            if ip and pl is not None and fam == "inet6":
                by[name]["ipv6"].append({"ip": ip, "prefixlen": int(pl)})
    return {"ifaces": ifaces, "sum": {"rx_bytes": rx_sum, "tx_bytes": tx_sum}, "interfaces": list(by.values()), "public": {"ipv4": route_src(["ip", "route", "get", "1.1.1.1"]), "ipv6": route_src(["ip", "-6", "route", "get", "2001:4860:4860::8888"])}}


def lsblk_devices():
    j = cmd_json(["lsblk", "-b", "-J", "-o", "NAME,KNAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,TRAN,UUID,ROTA"])
    return j.get("blockdevices", []) if isinstance(j, dict) else []


def write_stats(api_dir: Path):
    data = {"ok": True, "ts": int(time.time()), "host": os.uname().nodename, "disk": {"mounts": df_mounts()}, "mem": mem_stats(), "cpu": cpu_stats(api_dir), "net": network_stats(), "storage": {"devices": lsblk_devices()}}
    api_dir.mkdir(parents=True, exist_ok=True)
    tmp = api_dir / "system_stats_cache.json.tmp"
    dst = api_dir / "system_stats_cache.json"
    tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    tmp.replace(dst)


def main():
    api_dir = Path(os.environ.get("ORIS_STATS_API_DIR", "/var/www/oris-panel/admin/api"))
    interval = max(1, min(30, int(os.environ.get("ORIS_STATS_INTERVAL", "2"))))
    once = "--once" in os.sys.argv
    while True:
        try:
            write_stats(api_dir)
        except Exception as e:
            Path("/var/log/oris-stats-worker.log").write_text(str(e) + "\n", encoding="utf-8")
        if once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()

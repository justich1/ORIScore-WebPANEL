from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from ..common import atomic_write, run
from ..context import Ctx

HANDLED_TYPES = {
    "wg_install",
    "wg_apply",
    "wg_peer_create",
    "wg_peer_delete",
    "wg_peer_enable",
    "wg_peer_disable",
    "wg_peer_regenerate",
    "wg_peer_qr",
    "wg_service_restart",
}

WG_BASE = Path("/var/lib/oris-core/wireguard")
WG_CLIENTS = WG_BASE / "clients"


def _payload(job: dict[str, Any]) -> dict[str, Any]:
    raw = job.get("payload")
    if raw is None or raw == "":
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(str(raw))
    except Exception:
        return {}


def _safe_name(value: Any, default: str = "client") -> str:
    name = str(value or default).strip().lower()
    name = re.sub(r"[^a-z0-9_.-]+", "-", name)
    name = name.strip(".-_") or default
    return name[:80]


def _iface(value: Any) -> str:
    iface = str(value or "wg0").strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", iface):
        raise RuntimeError(f"Neplatný WireGuard interface: {iface}")
    return iface


def _port(value: Any) -> int:
    try:
        p = int(str(value or "51820"))
    except Exception:
        p = 51820
    if not (1 <= p <= 65535):
        raise RuntimeError(f"Neplatný WireGuard port: {p}")
    return p


def _key(value: Any, name: str, allow_empty: bool = False) -> str:
    v = str(value or "").strip()
    if allow_empty and v == "":
        return ""
    if not re.match(r"^[A-Za-z0-9+/]{42,44}={0,2}$", v):
        raise RuntimeError(f"{name} nevypadá jako WireGuard klíč")
    return v


def _ip(value: Any) -> str:
    ip = str(value or "").strip()
    try:
        ipaddress.ip_address(ip)
    except Exception:
        raise RuntimeError(f"Neplatná IP adresa peeru: {ip}")
    return ip


def _cidr(value: Any, default: str = "10.42.0.1/24") -> str:
    raw = str(value or default).strip()
    try:
        ipaddress.ip_interface(raw)
    except Exception:
        raise RuntimeError(f"Neplatná WG server adresa/CIDR: {raw}")
    return raw


def _allowed_ips(value: Any, default: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return default
    out: list[str] = []
    for part in raw.split(","):
        p = part.strip()
        if not p:
            continue
        try:
            ipaddress.ip_network(p, strict=False)
        except Exception:
            raise RuntimeError(f"Neplatné AllowedIPs: {p}")
        out.append(p)
    return ", ".join(out) if out else default


def _run_out(cmd: list[str], *, input_text: str | None = None) -> str:
    rc, out = run(cmd, input_text=input_text)
    return out.strip()


def _have_cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _wg_private_key() -> str:
    return _run_out(["wg", "genkey"])


def _wg_public_key(private_key: str) -> str:
    return _run_out(["wg", "pubkey"], input_text=private_key + "\n")


def _wg_psk() -> str:
    return _run_out(["wg", "genpsk"])


def _settings(ctx: Ctx) -> dict[str, str]:
    return {
        "iface": ctx.setting("wg_iface", "wg0"),
        "server_address": ctx.setting("wg_server_address", "10.42.0.1/24"),
        "listen_port": ctx.setting("wg_listen_port", "51820"),
        "endpoint": ctx.setting("wg_endpoint", ""),
        "dns": ctx.setting("wg_dns", ""),
        "client_allowed_ips": ctx.setting("wg_client_allowed_ips", "0.0.0.0/0, ::/0"),
        "mtu": ctx.setting("wg_mtu", ""),
        "post_up": ctx.setting("wg_post_up", ""),
        "post_down": ctx.setting("wg_post_down", ""),
        "keepalive": ctx.setting("wg_keepalive", "25"),
        "server_private_key": ctx.setting("wg_server_private_key", ""),
        "server_public_key": ctx.setting("wg_server_public_key", ""),
    }


def _default_wan_iface() -> str:
    rc, out = run("ip route | awk '/default/ {print $5; exit}'", shell=True, check=False)
    iface = (out or "").strip()
    if re.match(r"^[A-Za-z0-9_.-]{1,32}$", iface):
        return iface
    return "eth0"


def _peer_default_allowed(peer_ip: str) -> str:
    ip = ipaddress.ip_address(peer_ip)
    return f"{peer_ip}/32" if ip.version == 4 else f"{peer_ip}/128"


def _ensure_dirs() -> None:
    Path("/etc/wireguard").mkdir(parents=True, exist_ok=True)
    WG_CLIENTS.mkdir(parents=True, exist_ok=True)
    run(["chown", "-R", "root:www-data", str(WG_BASE)], check=False)
    run(["chmod", "-R", "750", str(WG_BASE)], check=False)


def _ensure_server_keys(ctx: Ctx, log_job_id: int) -> tuple[str, str]:
    if not _have_cmd("wg"):
        raise RuntimeError("Chybí příkaz wg. Nainstaluj wireguard-tools nebo spusť wg_install.")
    priv = ctx.setting("wg_server_private_key", "").strip()
    pub = ctx.setting("wg_server_public_key", "").strip()
    if priv and pub:
        return priv, pub
    if not priv:
        priv = _wg_private_key()
        ctx.set_setting("wg_server_private_key", priv)
        ctx.job_log(log_job_id, "Vygenerován server PrivateKey.")
    pub = _wg_public_key(priv)
    ctx.set_setting("wg_server_public_key", pub)
    return priv, pub


def _write_sysctl(log_job_id: int, ctx: Ctx) -> None:
    atomic_write("/etc/sysctl.d/99-oris-wireguard.conf", "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n")
    run(["sysctl", "--system"], check=False)
    ctx.job_log(log_job_id, "IP forwarding povolen přes /etc/sysctl.d/99-oris-wireguard.conf")


def _write_client_files(ctx: Ctx, peer: dict[str, Any], settings: dict[str, str], server_pub: str) -> tuple[str, str]:
    priv = str(peer.get("private_key") or "").strip()
    if not priv:
        return "", ""
    name = _safe_name(peer.get("name"), f"peer-{peer.get('id')}")
    peer_ip = str(peer.get("ip") or peer.get("client_address") or "").strip()
    client_addr = _peer_default_allowed(peer_ip)
    psk = str(peer.get("preshared_key") or "").strip()
    dns = str(settings.get("dns") or "").strip()
    mtu = str(settings.get("mtu") or "").strip()
    endpoint = str(settings.get("endpoint") or "").strip()
    keepalive = str(settings.get("keepalive") or "25").strip() or "25"
    client_allowed = _allowed_ips(settings.get("client_allowed_ips"), "0.0.0.0/0, ::/0")

    lines = ["[Interface]", f"PrivateKey = {priv}", f"Address = {client_addr}"]
    if dns:
        lines.append(f"DNS = {dns}")
    if mtu:
        lines.append(f"MTU = {mtu}")
    lines += ["", "[Peer]", f"PublicKey = {server_pub}"]
    if psk:
        lines.append(f"PresharedKey = {psk}")
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    lines.append(f"AllowedIPs = {client_allowed}")
    lines.append(f"PersistentKeepalive = {keepalive}")
    content = "\n".join(lines) + "\n"

    conf = WG_CLIENTS / f"{name}-{peer.get('id')}.conf"
    png = WG_CLIENTS / f"{name}-{peer.get('id')}.png"
    atomic_write(conf, content, 0o640)
    run(["chown", "root:www-data", str(conf)], check=False)
    # QR musí vzniknout vždy, když existuje klientský private key.
    # Pokud qrencode na systému chybí, provisioner ho doinstaluje; chyba QR už nesmí být potichu schovaná.
    if not _have_cmd("qrencode"):
        run(["apt-get", "update"], check=False)
        run(["apt-get", "install", "-y", "qrencode"], check=False)

    if not _have_cmd("qrencode"):
        raise RuntimeError("Chybí příkaz qrencode, nelze vytvořit QR kód pro WireGuard klienta.")

    run(["qrencode", "-o", str(png), "-t", "PNG"], input_text=content)
    if not png.exists():
        raise RuntimeError(f"QR soubor nebyl vytvořen: {png}")
    run(["chown", "root:www-data", str(png)], check=False)
    run(["chmod", "640", str(png)], check=False)
    return str(conf), str(png)


def _write_wg_conf(ctx: Ctx, job_id: int) -> None:
    _ensure_dirs()
    settings = _settings(ctx)
    iface = _iface(settings["iface"])
    server_address = _cidr(settings["server_address"])
    port = _port(settings["listen_port"])
    server_priv, server_pub = _ensure_server_keys(ctx, job_id)

    wan = _default_wan_iface()
    post_up = str(settings.get("post_up") or "").strip()
    post_down = str(settings.get("post_down") or "").strip()
    if not post_up:
        post_up = f"iptables -A FORWARD -i {iface} -j ACCEPT; iptables -A FORWARD -o {iface} -j ACCEPT; iptables -t nat -A POSTROUTING -o {wan} -j MASQUERADE"
    if not post_down:
        post_down = f"iptables -D FORWARD -i {iface} -j ACCEPT; iptables -D FORWARD -o {iface} -j ACCEPT; iptables -t nat -D POSTROUTING -o {wan} -j MASQUERADE"

    lines = [
        "# Generated by ORIS Hosting provisioner. Do not edit manually.",
        "[Interface]",
        f"Address = {server_address}",
        f"ListenPort = {port}",
        f"PrivateKey = {server_priv}",
    ]
    mtu = str(settings.get("mtu") or "").strip()
    if mtu:
        lines.append(f"MTU = {mtu}")
    if post_up:
        lines.append(f"PostUp = {post_up}")
    if post_down:
        lines.append(f"PostDown = {post_down}")
    lines.append("")

    peers = ctx.q("SELECT * FROM wg_peers WHERE is_active=1 ORDER BY id ASC")
    for p in peers:
        pub = _key(p.get("public_key"), "Peer PublicKey")
        peer_ip = str(p.get("ip") or "").strip()
        allowed = str(p.get("allowed_ips") or "").strip() or _peer_default_allowed(peer_ip)
        allowed = _allowed_ips(allowed, _peer_default_allowed(peer_ip))
        lines += [
            "[Peer]",
            f"# {p.get('name')} id={p.get('id')}",
            f"PublicKey = {pub}",
        ]
        psk = str(p.get("preshared_key") or "").strip()
        if psk:
            lines.append(f"PresharedKey = {psk}")
        lines.append(f"AllowedIPs = {allowed}")
        lines.append("")

        conf_path, qr_path = _write_client_files(ctx, p, settings, server_pub)
        if conf_path or qr_path:
            ctx.exec("UPDATE wg_peers SET config_path=%s, qr_path=%s, updated_at=NOW() WHERE id=%s", (conf_path or None, qr_path or None, int(p["id"])))

    conf = Path(f"/etc/wireguard/{iface}.conf")
    atomic_write(conf, "\n".join(lines).rstrip() + "\n", 0o600)
    run(["chown", "root:root", str(conf)], check=False)
    ctx.job_log(job_id, f"Zapsán {conf}")


def _restart_service(ctx: Ctx, job_id: int) -> None:
    iface = _iface(ctx.setting("wg_iface", "wg0"))
    port = _port(ctx.setting("wg_listen_port", "51820"))
    _write_sysctl(job_id, ctx)
    run(["systemctl", "enable", f"wg-quick@{iface}"], check=False)
    # Restart je bezpečnější přes stop/start; wg-quick občas nechá rozhraní ve špatném stavu.
    run(["systemctl", "restart", f"wg-quick@{iface}"])
    rc, out = run(["ufw", "status"], check=False)
    if rc == 0 and "Status: active" in out:
        run(["ufw", "allow", f"{port}/udp"], check=False)
        ctx.job_log(job_id, f"UFW povoleno: {port}/udp")


def _install(ctx: Ctx, job_id: int) -> None:
    run(["apt-get", "update"], check=False)
    run(["apt-get", "install", "-y", "wireguard", "wireguard-tools", "qrencode", "iptables", "iproute2"])
    _ensure_dirs()
    _ensure_server_keys(ctx, job_id)
    _write_sysctl(job_id, ctx)
    ctx.job_log(job_id, "WireGuard balíky a základ připraveny.")


def _apply(ctx: Ctx, job_id: int) -> None:
    if not _have_cmd("wg"):
        _install(ctx, job_id)
    _write_wg_conf(ctx, job_id)
    _restart_service(ctx, job_id)
    ctx.job_log(job_id, "WireGuard konfigurace aplikována.")


def _create_peer(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    p = _payload(job)
    name = str(p.get("name") or "").strip()
    if not name or len(name) > 190:
        raise RuntimeError("Jméno peeru je povinné a max 190 znaků.")
    ip = _ip(p.get("ip"))
    public_key = str(p.get("public_key") or "").strip()
    private_key = str(p.get("private_key") or "").strip()
    preshared_key = str(p.get("preshared_key") or "").strip()

    if public_key:
        public_key = _key(public_key, "PublicKey")
        if private_key:
            private_key = _key(private_key, "PrivateKey")
    else:
        if not _have_cmd("wg"):
            _install(ctx, job_id)
        private_key = _wg_private_key()
        public_key = _wg_public_key(private_key)
        ctx.job_log(job_id, "Vygenerován klientský keypair.")

    if not preshared_key:
        if not _have_cmd("wg"):
            _install(ctx, job_id)
        preshared_key = _wg_psk()
    else:
        preshared_key = _key(preshared_key, "PresharedKey")

    default_allowed = _peer_default_allowed(ip)
    allowed = _allowed_ips(p.get("allowed_ips"), default_allowed)

    ctx.exec(
        "INSERT INTO wg_peers(name,ip,private_key,public_key,preshared_key,allowed_ips,is_active,updated_at) VALUES(%s,%s,%s,%s,%s,%s,1,NOW())",
        (name, ip, private_key or None, public_key, preshared_key or None, allowed),
    )
    ctx.job_log(job_id, f"Peer vytvořen: {name} {ip}")
    _apply(ctx, job_id)


def _peer_by_id(ctx: Ctx, peer_id: int) -> dict[str, Any]:
    peer = ctx.one("SELECT * FROM wg_peers WHERE id=%s", (peer_id,))
    if not peer:
        raise RuntimeError(f"WireGuard peer nenalezen: {peer_id}")
    return peer


def _delete_peer(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    peer_id = int(job.get("ref_id") or 0)
    peer = ctx.one("SELECT * FROM wg_peers WHERE id=%s", (peer_id,))
    if peer:
        for key in ("config_path", "qr_path"):
            path = str(peer.get(key) or "")
            if path.startswith(str(WG_CLIENTS)):
                Path(path).unlink(missing_ok=True)
        ctx.exec("DELETE FROM wg_peers WHERE id=%s", (peer_id,))
        ctx.job_log(job_id, f"Peer smazán: {peer_id}")
    _apply(ctx, job_id)


def _set_peer_active(ctx: Ctx, job: dict[str, Any], active: bool) -> None:
    peer_id = int(job.get("ref_id") or 0)
    _peer_by_id(ctx, peer_id)
    ctx.exec("UPDATE wg_peers SET is_active=%s, updated_at=NOW() WHERE id=%s", (1 if active else 0, peer_id))
    ctx.job_log(int(job["id"]), f"Peer {peer_id} {'povolen' if active else 'zakázán'}")
    _apply(ctx, int(job["id"]))


def _regenerate_peer(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    peer_id = int(job.get("ref_id") or 0)
    peer = _peer_by_id(ctx, peer_id)
    if not _have_cmd("wg"):
        _install(ctx, job_id)
    priv = _wg_private_key()
    pub = _wg_public_key(priv)
    psk = _wg_psk()
    ctx.exec("UPDATE wg_peers SET private_key=%s, public_key=%s, preshared_key=%s, updated_at=NOW() WHERE id=%s", (priv, pub, psk, peer_id))
    ctx.job_log(job_id, f"Peer {peer.get('name')} má nové klíče.")
    _apply(ctx, job_id)


def _regenerate_qr(ctx: Ctx, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    peer_id = int(job.get("ref_id") or 0)
    _peer_by_id(ctx, peer_id)
    # Přegeneruje soubory bez restartu služby.
    settings = _settings(ctx)
    server_pub = ctx.setting("wg_server_public_key", "")
    peers = ctx.q("SELECT * FROM wg_peers WHERE id=%s", (peer_id,))
    for p in peers:
        conf_path, qr_path = _write_client_files(ctx, p, settings, server_pub)
        ctx.exec("UPDATE wg_peers SET config_path=%s, qr_path=%s, updated_at=NOW() WHERE id=%s", (conf_path or None, qr_path or None, peer_id))
    ctx.job_log(job_id, "QR/config přegenerován.")


def handle(ctx: Ctx, job: dict[str, Any]) -> None:
    typ = str(job.get("type") or "")
    job_id = int(job["id"])

    if typ == "wg_install":
        _install(ctx, job_id)
        return
    if typ == "wg_apply":
        _apply(ctx, job_id)
        return
    if typ == "wg_peer_create":
        _create_peer(ctx, job)
        return
    if typ == "wg_peer_delete":
        _delete_peer(ctx, job)
        return
    if typ == "wg_peer_enable":
        _set_peer_active(ctx, job, True)
        return
    if typ == "wg_peer_disable":
        _set_peer_active(ctx, job, False)
        return
    if typ == "wg_peer_regenerate":
        _regenerate_peer(ctx, job)
        return
    if typ == "wg_peer_qr":
        _regenerate_qr(ctx, job)
        return
    if typ == "wg_service_restart":
        _restart_service(ctx, job_id)
        return

    raise RuntimeError(f"WireGuard plugin neumí job {typ}")

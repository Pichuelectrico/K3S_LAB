"""Cliente del Prometheus del lab (:9090) para el panel de equipos (solo lectura).

Reusa los exporters que ya corren en cada host (node-exporter :9100, dcgm-exporter :9400,
cadvisor :8080, gpu-per-container :9105). El Prometheus de GMED vive en :9393 — no tocar.
"""
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import config


def _query(expr: str) -> list[dict]:
    """Instant query → lista de {metric, value:[ts, val]}."""
    url = config.PROM_URL + "/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            data = json_loads(r.read())
        if data.get("status") != "success":
            return []
        return data["data"]["result"]
    except Exception:
        return []


def json_loads(b: bytes) -> dict:
    import json
    return json.loads(b.decode())


def _f(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _ip(instance: str) -> str:
    return instance.split(":")[0]


def _nombre(instance: str) -> str:
    return config.HOST_NAMES.get(_ip(instance), _ip(instance))


def _human_uptime(s: float) -> str:
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    if d > 0:
        return f"{d}d {h}h"
    return f"{h}h {s // 60}m"


def _gb(b: float) -> float:
    return round(b / 1024**3, 1)


def _os_from_uname(m: dict) -> str:
    """'Ubuntu 24.04' del label version ('#31~24.04.1-Ubuntu SMP...')."""
    v = m.get("version", "")
    if "Ubuntu" in v:
        import re as _re
        mo = _re.search(r"(\d+\.\d+)", v)
        return f"Ubuntu {mo.group(1)}" if mo else "Ubuntu"
    return m.get("sysname", "Linux")


def gpu_counts() -> dict[str, int]:
    """Número de GPUs por host (del dcgm-exporter) para el selector de recursos."""
    out: dict[str, int] = {}
    for r in _query("count by (instance)(DCGM_FI_DEV_GPU_UTIL)"):
        out[_nombre(r["metric"]["instance"])] = int(_f(r["value"][1]))
    return out


def obtener_servers() -> list[dict]:
    """Métricas instantáneas de todos los hosts, agregadas por nombre."""
    queries = {
        "uname": "node_uname_info",
        "boot": "time() - node_boot_time_seconds",
        "load1": "node_load1",
        "load5": "node_load5",
        "load15": "node_load15",
        "cpu": '(1 - avg by (instance)(rate(node_cpu_seconds_total{mode="idle"}[2m]))) * 100',
        "cores": 'count by (instance)(node_cpu_seconds_total{mode="idle"})',
        "ram": '{__name__=~"node_memory_(MemTotal|MemAvailable)_bytes"}',
        "disk": '{__name__=~"node_filesystem_(size|avail)_bytes",mountpoint="/",fstype!~"tmpfs|overlay"}',
        "gpu_util": "DCGM_FI_DEV_GPU_UTIL",
        "fb_used": "DCGM_FI_DEV_FB_USED",
        "fb_free": "DCGM_FI_DEV_FB_FREE",  # total = used + free (no existe FB_TOTAL)
        "conts": 'count(container_last_seen{image!=""}) by (instance)',
    }
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = {k: v for k, v in zip(queries, ex.map(lambda e: _query(e), queries.values()))}

    hosts: dict[str, dict] = {}

    def h(instance: str) -> dict:
        ip = _ip(instance)
        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "nombre": _nombre(instance),
                "hostname": "",
                "os": "",
                "kernel": "",
                "uptime": "",
                "load1": None, "load5": None, "load15": None,
                "cpu_pct": None, "cores": None,
                "ram_total": None, "ram_used": None,
                "disk_total": None, "disk_free": None,
                "gpus": [],
                "contenedores": None,
                "online": False,
            }
        return hosts[ip]

    for r in res["uname"]:
        m = r["metric"]
        host = h(m["instance"])
        host.update({
            "hostname": m.get("nodename", ""),
            "os": _os_from_uname(m),
            "kernel": m.get("release", ""),
            "online": True,
        })
    for r in res["boot"]:
        h(r["metric"]["instance"])["uptime"] = _human_uptime(_f(r["value"][1]))
    for key in ("load1", "load5", "load15"):
        for r in res[key]:
            h(r["metric"]["instance"])[key] = round(_f(r["value"][1]), 2)
    for r in res["cpu"]:
        h(r["metric"]["instance"])["cpu_pct"] = round(_f(r["value"][1]), 1)
    for r in res["cores"]:
        h(r["metric"]["instance"])["cores"] = int(_f(r["value"][1]))
    # RAM: dos pasadas (primero totales, luego used) — el orden de series no está garantizado
    for r in res["ram"]:
        m = r["metric"]
        if m["__name__"] == "node_memory_MemTotal_bytes":
            h(m["instance"])["ram_total"] = _f(r["value"][1])
    for r in res["ram"]:
        m = r["metric"]
        if m["__name__"] == "node_memory_MemAvailable_bytes":
            host = h(m["instance"])
            if host["ram_total"]:
                host["ram_used"] = host["ram_total"] - _f(r["value"][1])
    for r in res["disk"]:
        m = r["metric"]
        host = h(m["instance"])
        if m["__name__"] == "node_filesystem_size_bytes":
            host["disk_total"] = _f(r["value"][1])
        else:
            host["disk_free"] = _f(r["value"][1])
    # GPUs por (ip, gpu index)
    for r in res["gpu_util"]:
        m = r["metric"]
        host = h(m["instance"])
        gpu = {"idx": m.get("gpu", "0"), "model": (m.get("modelName") or "").replace("NVIDIA ", ""),
               "driver": m.get("DCGM_FI_DRIVER_VERSION", ""), "util": _f(r["value"][1]),
               "vram_used": None, "vram_total": None}
        host["gpus"].append(gpu)
    for r in res["fb_used"]:
        m = r["metric"]
        for g in h(m["instance"])["gpus"]:
            if g["idx"] == m.get("gpu"):
                g["vram_used"] = _f(r["value"][1])  # MiB
    for r in res["fb_free"]:
        m = r["metric"]
        for g in h(m["instance"])["gpus"]:
            if g["idx"] == m.get("gpu"):
                g["vram_used"] = g["vram_used"] or 0.0
                g["vram_total"] = g["vram_used"] + _f(r["value"][1])  # MiB
    for r in res["conts"]:
        h(r["metric"]["instance"])["contenedores"] = int(_f(r["value"][1]))

    out = []
    for nombre in config.HOST_ORDER:
        for ip, host in hosts.items():
            if host["nombre"] == nombre:
                host["gpus"].sort(key=lambda g: g["idx"])
                out.append(host)
                break
    # hosts con datos pero fuera del orden conocido (extras)
    known = {h["nombre"] for h in out}
    for host in hosts.values():
        if host["nombre"] not in known:
            out.append(host)
    return out

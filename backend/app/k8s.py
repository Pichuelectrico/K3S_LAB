"""Wrapper de kubectl vía SSH al nodo cabeza (wslab01). Sin sudo (kubeconfig 644)."""
import json
import re
import subprocess
import time

from . import config


def kubectl(args: str, input_data: str | None = None) -> tuple[bool, str]:
    """Ejecuta `ssh WsLab01 'k3s kubectl <args>'`. Devuelve (ok, salida)."""
    cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        config.K3S_SSH_HOST,
        f"{config.KUBECTL_CMD} {args}",
    ]
    try:
        r = subprocess.run(cmd, input=input_data, capture_output=True, text=True,
                           timeout=config.KUBECTL_TIMEOUT)
        ok = r.returncode == 0
        return ok, (r.stdout if ok else (r.stderr or r.stdout))
    except subprocess.TimeoutExpired:
        return False, f"kubectl timeout ({config.KUBECTL_TIMEOUT}s)"
    except Exception as e:  # noqa: BLE001
        return False, f"error ejecutando kubectl: {e}"


def get_nodes() -> list[dict]:
    """Specs de nodos: capacity + labels + status (JSON de kubectl)."""
    ok, out = kubectl("get nodes -o json")
    if not ok:
        raise RuntimeError(out)
    data = json.loads(out)
    nodes = []
    for item in data.get("items", []):
        meta, status = item["metadata"], item["status"]
        labels = meta.get("labels", {})
        cap = status.get("capacity", {})
        nodes.append({
            "name": meta["name"],
            "status": "Ready" if any(c["type"] == "Ready" and c["status"] == "True"
                                     for c in status.get("conditions", [])) else "NotReady",
            "cpu_total": cap.get("cpu"),
            "mem_total": cap.get("memory"),
            "gpu_model": labels.get("gpu-model", ""),
            "vram_gb": labels.get("vram-gpu", ""),
            "tier": labels.get("tier", ""),
        })
    return nodes


def top_nodes() -> dict[str, dict]:
    """Uso en vivo: {nombre: {cpu_millicores, mem_mi}} desde metrics-server."""
    ok, out = kubectl("top nodes --no-headers")
    if not ok:
        return {}
    result = {}
    for line in out.strip().splitlines():
        parts = line.split()
        if len(parts) >= 5:
            result[parts[0]] = {"cpu_m": _to_millicores(parts[1]), "mem_mi": _to_mi(parts[3])}
    return result


def _to_millicores(v: str) -> int:
    v = v.strip()
    return int(v[:-1]) if v.endswith("m") else int(float(v) * 1000)


def _to_mi(v: str) -> int:
    v = v.strip()
    if v.endswith("Mi"):
        return int(v[:-2])
    if v.endswith("Gi"):
        return int(float(v[:-2]) * 1024)
    return int(float(v) / (1024 * 1024)) if v.isdigit() else 0


def get_lab_envs() -> dict[str, dict]:
    """Deployments del lab (label k3slab/managed=yes): {nombre: {replicas, ready}}."""
    ok, out = kubectl("get deploy -A -l k3slab/managed=yes -o json")
    if not ok:
        return {}
    data = json.loads(out)
    result = {}
    for item in data.get("items", []):
        spec, status = item.get("spec", {}), item.get("status", {})
        result[item["metadata"]["name"]] = {
            "replicas": spec.get("replicas", 0),
            "ready": status.get("readyReplicas", 0),
        }
    return result


def get_nodeports_en_uso() -> set[int]:
    """NodePorts ya asignados a Services del lab (por si la BD se resetea)."""
    ok, out = kubectl("get svc -A -l k3slab/managed=yes -o json")
    ports: set[int] = set()
    if not ok:
        return ports
    for item in json.loads(out).get("items", []):
        for p in item.get("spec", {}).get("ports", []):
            if p.get("nodePort"):
                ports.add(int(p["nodePort"]))
    return ports


def apply_yaml(yaml_str: str) -> tuple[bool, str]:
    return kubectl("apply -f -", input_data=yaml_str)


def get_pod_node(name: str, intentos: int = 5, pausa: float = 1.5) -> str | None:
    """Nodo real donde el scheduler de k3s asignó el pod del entorno (label app=<name>).
    Reintenta unos segundos: la asignación del scheduler es inmediata en la práctica."""
    for _ in range(intentos):
        ok, out = kubectl(
            f"get pod -n default -l k3slab/env={name} -o jsonpath='{{.items[0].spec.nodeName}}'")
        if ok and out.strip():
            return out.strip()
        time.sleep(pausa)
    return None


def delete_env_resources(name: str) -> tuple[bool, str]:
    ok1, out1 = kubectl(f"delete deploy {name} -n default --ignore-not-found")
    ok2, out2 = kubectl(f"delete svc {name} -n default --ignore-not-found")
    ok = ok1 and ok2
    return ok, (out1 + out2)


def scale_env(name: str, replicas: int) -> tuple[bool, str]:
    return kubectl(f"scale deploy {name} -n default --replicas={replicas}")


def sync_env_status(name: str, replicas: int) -> tuple[bool, str]:
    """Equivalente a scale pero tolerante a estado igual (para sync)."""
    return scale_env(name, replicas)


def get_pod_token(name: str) -> str | None:
    """Token del runtime Colab: se parsea de la URL que imprime el pod en su log
    (http://127.0.0.1:8080/?token=...). Ver research.google.com/colaboratory/local-runtimes.html"""
    ok, out = kubectl(f"logs deploy/{name} -n default --tail=200")
    if not ok:
        return None
    m = re.search(r"token=([A-Za-z0-9._%-]+)", out)
    return m.group(1) if m else None


def pods_por_nodo() -> dict:
    """Pods Running por nodo del clúster k3s (para el panel de equipos)."""
    ok, out = kubectl(
        "get pods -A --field-selector=status.phase=Running -o jsonpath="
        "'{range .items[*]}{.spec.nodeName}{\"\\n\"}{end}'"
    )
    if not ok:
        return {}
    counts: dict[str, int] = {}
    for line in out.splitlines():
        line = line.strip()
        if line:
            counts[line] = counts.get(line, 0) + 1
    return counts


def uid_gid_en_nodo(owner: str, node: str) -> tuple[int | None, int | None]:
    """UID/GID del owner en el nodo destino. Los UIDs difieren por nodo (Fase 2: Ansible
    los unifica) — se resuelven al crear el entorno para pods que montan el home.
    Conecta por IP (NODE_IPS): los alias de ~/.ssh/config son WsLab0X y los nombres de
    nodo de k8s son lowercase."""
    import subprocess as _sp
    from . import config as _config
    host = f"{_config.SSH_USER}@{_config.NODE_IPS.get(node.lower(), node)}"
    try:
        r = _sp.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host,
                     f"id -u {owner}"], capture_output=True, text=True, timeout=10)
        uid = int(r.stdout.strip()) if r.returncode == 0 else None
        r2 = _sp.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host,
                      f"id -g {owner}"], capture_output=True, text=True, timeout=10)
        gid = int(r2.stdout.strip()) if r2.returncode == 0 else None
        return uid, gid
    except Exception:
        return None, None

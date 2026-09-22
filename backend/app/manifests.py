"""Generación de manifiestos k8s para los entornos del lab (Deployment + Service NodePort).

Convenciones (ver CONTEXT.md §4):
- Labels: k3slab/managed=yes · k3slab/owner=<usuario> · k3slab/type=<tipo> · k3slab/env=<nombre>
- Pods GPU (colab): runtimeClassName nvidia + hostPID true (paridad con --pid=host actual)
- Mounts colab: /media ro, /mnt ro, /home/<owner> en /home/workdir + /dev/shm en memoria
  (shm_size, default 45g — sin limit de memoria el tmpfs coge el sizeLimit directo)
- NodePort del rango propio 31000-31999 (reemplaza el "baile de puertos" manual)
"""
import hashlib
import json

import yaml

from . import config


def build_manifests(name: str, owner: str, node: str, nodeport: int | None,
                    cat, uid: int | None = None, gid: int | None = None,
                    gpu: bool = False,
                    mount_home: bool = True, password: str | None = None,
                    shm_size: str = "45Gi",
                    extra_volumes: list[dict] | None = None) -> str:
    """Devuelve el YAML multi-documento del entorno (Deployment + Service si aplica).
    gpu: GPU como recurso opcional para CUALQUIER tipo, TODO-O-NADA (el catálogo marca
    el default; python/vscode también pueden pedirla) — el nodo expone todas sus GPUs
    o el subconjunto de config.GPU_VISIBLE_POR_NODO (futuro H200: "0,1,2,3").
    mount_home: montar el /home del owner en el contenedor (toggle en Recursos).
    shm_size: sizeLimit del /dev/shm en memoria (colab/matlab/python; default 45Gi) —
    sin limit de memoria el kubelet dimensiona el tmpfs directo al sizeLimit.
    extra_volumes: volúmenes extra (solo devs) [{path: str, ro: bool}] — hostPath del
    nodo montado en el MISMO path dentro del pod."""
    labels = {"k3slab/managed": "yes", "k3slab/owner": owner,
              "k3slab/type": cat.id, "k3slab/env": name}

    # /dev/shm en memoria aplica a colab/matlab/python (volumes/mounts más abajo)
    aplica_shm = cat.id in ("colab", "matlab", "python")

    pod_spec: dict = {
        "containers": [{
            "name": "main",
            "image": cat.image,
            # SOLO requests (sin limits): el pod garantiza cpu/mem del catálogo en el
            # scheduler (reserva mínima, lo que muestra la UI) pero puede usar TODA la
            # RAM/CPU libre del nodo — burst tipo docker sin límites. Si el nodo se
            # queda sin memoria el kernel mata primero al proceso más grande del pod
            # que más excedió su request (oom_score_adj alto), y el kubelet expulsa
            # (evict) primero los pods por encima de su request. Pide GPU = tolera taint.
            "resources": {"requests": {"cpu": cat.cpu, "memory": cat.mem}},
        }],
    }
    if node:
        # Host elegido por el usuario; si no, k3s lo asigna (balanceo nativo)
        pod_spec["nodeSelector"] = {"kubernetes.io/hostname": node}
        # Toleración solo para hosts dedicados con taint k3slab (ej: DGX2 de producción).
        # El balanceo automático (sin nodeSelector) nunca aterriza en nodos con taint.
        pod_spec["tolerations"] = [{"key": "k3slab/dedicated", "operator": "Exists",
                                    "effect": "NoSchedule"}]

    # Variables de entorno del catálogo
    # (colab: el token lo genera la propia imagen y se lee de su log — ver api.py /connect)
    # (vscode: HOME + HASHED_PASSWORD se añaden en su branch más abajo)
    envs: list[dict] = []
    if cat.env_json:
        for k, v in json.loads(cat.env_json).items():
            envs.append({"name": k, "value": str(v)})

    # Puertos
    ports = [int(p) for p in cat.ports_json.split(",") if p.strip()]
    if ports:
        pod_spec["containers"][0]["ports"] = [{"containerPort": p} for p in ports]

    # GPU como recurso (para cualquier tipo): runtime nvidia + hostPID (paridad con
    # --pid=host de los colabs actuales: nvidia-smi ve procesos) + TODO-O-NADA
    wants_gpu = gpu or bool(cat.gpu)
    if wants_gpu:
        pod_spec["runtimeClassName"] = "nvidia"
        pod_spec["hostPID"] = True
        # Sin NVIDIA_VISIBLE_DEVICES el toolkit NO inyecta drivers/nvidia-smi en imágenes
        # que no sean CUDA (p.ej. python-slim, code-server). Todo-o-nada: "all" (todas
        # las GPUs del nodo) o el subconjunto declarado en GPU_VISIBLE_POR_NODO.
        envs.append({"name": "NVIDIA_VISIBLE_DEVICES",
                     "value": config.GPU_VISIBLE_POR_NODO.get(node, "all")})

    # Volúmenes/mounts según tipo
    volumes, mounts = [], []
    # /dev/shm en memoria (tmpfs) para colab/matlab/python: crucial para DataLoader
    # de PyTorch etc. Tamaño configurable (shm_size, default 45g antes 8Gi fijo).
    if aplica_shm:
        volumes.append({"name": "shm", "emptyDir": {"medium": "Memory", "sizeLimit": shm_size}})
        mounts.append({"name": "shm", "mountPath": "/dev/shm"})
    if cat.id == "colab":
        volumes += [
            {"name": "media", "hostPath": {"path": "/media", "type": "DirectoryOrCreate"}},
            {"name": "mnt", "hostPath": {"path": "/mnt", "type": "DirectoryOrCreate"}},
        ]
        mounts += [
            {"name": "media", "mountPath": "/media", "readOnly": True},
            {"name": "mnt", "mountPath": "/mnt", "readOnly": True},
        ]
        if mount_home:
            # /home/workdir: punto de montaje documentado del runtime Colab (persistencia)
            volumes.append({"name": "home", "hostPath": {"path": f"/home/{owner}", "type": "DirectoryOrCreate"}})
            mounts.append({"name": "home", "mountPath": "/home/workdir"})
    if cat.id == "vscode":
        # code-server (VS Code web): home del usuario montado para persistencia.
        # Corre como el uid/gid del owner en el nodo (los UIDs difieren por nodo —
        # Fase 2: Ansible los unificará) para que los archivos queden con dueño correcto.
        if mount_home:
            volumes += [
                {"name": "home", "hostPath": {"path": f"/home/{owner}", "type": "DirectoryOrCreate"}},
            ]
            mounts += [{"name": "home", "mountPath": "/home/coder"}]
        envs += [
            {"name": "HOME", "value": "/home/coder"},
            {"name": "HASHED_PASSWORD",
             "value": hashlib.sha256((password or config.VSCODE_PASSWORD).encode()).hexdigest()},
        ]
        # El entrypoint del coder image hace bind localhost por defecto → override
        pod_spec["containers"][0]["command"] = [
            "code-server", "--bind-addr", "0.0.0.0:8080", "--auth", "password",
        ]
        if uid:
            pod_spec["securityContext"] = {"runAsUser": uid, "runAsGroup": gid or uid,
                                           "runAsNonRoot": True}
    if cat.id == "matlab":
        # MATLAB: VNC 5901 + noVNC 6080 (acceso browser). El image matlab entra como
        # usuario "matlab" vinculado al uid del host → conflictos; correr como root
        # (equivalente al truco -u :$gid del flujo actual) + privileged.
        # El entrypoint (/usr/bin/run.sh) arranca VNC y termina en bash interactivo,
        # que muere sin TTY en k8s → sobreescribimos el comando replicando el arranque:
        # passwd del VNC desde $PASSWORD, vncserver :1 (5901) y noVNC (6080) en foreground.
        pod_spec["containers"][0]["securityContext"] = {"runAsUser": 0, "privileged": True}
        envs += [{"name": "PASSWORD", "value": password or config.MATLAB_PASSWORD}]
        pod_spec["containers"][0]["command"] = [
            "/bin/bash", "-c",
            "mkdir -p /root/.vnc && echo -n \"$PASSWORD\" | vncpasswd -f > /root/.vnc/passwd"
            " && chmod 600 /root/.vnc/passwd && rm -rf /tmp/.X*"
            " && vncserver :1 -localhost no -geometry 1920x1080"
            " && exec /opt/noVNC/utils/launch.sh --vnc localhost:5901",
        ]
        volumes += [
            {"name": "media", "hostPath": {"path": "/media", "type": "DirectoryOrCreate"}},
            {"name": "mnt", "hostPath": {"path": "/mnt", "type": "DirectoryOrCreate"}},
        ]
        mounts += [
            {"name": "media", "mountPath": "/media", "readOnly": True},
            {"name": "mnt", "mountPath": "/mnt", "readOnly": True},
        ]
        if mount_home:
            volumes.append({"name": "home", "hostPath": {"path": f"/home/{owner}", "type": "DirectoryOrCreate"}})
            mounts.append({"name": "home", "mountPath": f"/home/{owner}"})
    if cat.id == "python" and mount_home:
        volumes.append({"name": "home", "hostPath": {"path": f"/home/{owner}", "type": "DirectoryOrCreate"}})
        mounts.append({"name": "home", "mountPath": f"/home/{owner}"})

    # Volúmenes extra (solo devs): hostPath del nodo montado en el MISMO path dentro
    # del pod, rw o ro según se indique. DirectoryOrCreate: no falla si aún no existe.
    for i, v in enumerate(extra_volumes or []):
        if not v.get("path"):
            continue
        vol_name = f"extra-{i}"
        volumes.append({"name": vol_name,
                        "hostPath": {"path": v["path"], "type": "DirectoryOrCreate"}})
        mount = {"name": vol_name, "mountPath": v["path"]}
        if v.get("ro"):
            mount["readOnly"] = True
        mounts.append(mount)

    if volumes:
        pod_spec["volumes"] = volumes
        pod_spec["containers"][0]["volumeMounts"] = mounts

    if envs:
        pod_spec["containers"][0]["env"] = envs

    # python-container: mantener vivo para exec (kubectl exec)
    if cat.access == "console":
        pod_spec["containers"][0]["command"] = ["sleep", "infinity"]

    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": "default", "labels": labels},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"k3slab/env": name}},
            "template": {
                "metadata": {"labels": labels},
                "spec": pod_spec,
            },
        },
    }

    docs = [deployment]

    # Service NodePort solo si el entorno expone puertos
    if ports and nodeport:
        target = ports[0]  # el primer puerto del catálogo es el principal
        docs.append({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": name, "namespace": "default", "labels": labels},
            "spec": {
                "type": "NodePort",
                "selector": {"k3slab/env": name},
                "ports": [{"port": target, "targetPort": target, "nodePort": nodeport}],
            },
        })

    return yaml.safe_dump_all(docs, sort_keys=False)

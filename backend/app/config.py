"""Configuración del K3S Lab (leída de variables de entorno con defaults sensatos)."""
import os
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # backend/
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_URL = os.getenv("K3SLAB_DB_URL", f"sqlite:///{os.path.join(DATA_DIR, 'k3slab.db')}")

# Secreto JWT: variable de entorno o archivo generado la primera vez
_secret_file = os.path.join(DATA_DIR, "jwt.secret")
if os.getenv("K3SLAB_JWT_SECRET"):
    JWT_SECRET = os.getenv("K3SLAB_JWT_SECRET")
elif os.path.exists(_secret_file):
    JWT_SECRET = open(_secret_file).read().strip()
else:
    JWT_SECRET = secrets.token_hex(32)
    with open(_secret_file, "w") as f:
        f.write(JWT_SECRET)

# kubectl se ejecuta vía SSH al nodo cabeza (k3s kubectl, kubeconfig 644 → sin sudo)
K3S_SSH_HOST = os.getenv("K3S_SSH_HOST", "WsLab01")
KUBECTL_CMD = os.getenv("K3S_KUBECTL_CMD", "k3s kubectl")
KUBECTL_TIMEOUT = int(os.getenv("K3S_KUBECTL_TIMEOUT", "30"))

# Rango de NodePorts asignables (propio del lab, definido en Fase 0)
NODEPORT_MIN = int(os.getenv("K3SLAB_NODEPORT_MIN", "31000"))
NODEPORT_MAX = int(os.getenv("K3SLAB_NODEPORT_MAX", "31999"))

# IPs de los nodos (para construir las URLs de acceso a los entornos)
NODE_IPS = {
    "wslab01": "172.21.230.21",
    "wslab02": "172.21.230.22",
    "wslab03": "172.21.230.23",
    "dgx2-station": "172.21.230.12",
}

# Ciclo de vida
IDLE_STOP_DAYS = int(os.getenv("K3SLAB_IDLE_STOP_DAYS", "7"))     # sin uso → detener
IDLE_DELETE_DAYS = int(os.getenv("K3SLAB_IDLE_DELETE_DAYS", "90"))  # sin uso → eliminar
SCHEDULER_INTERVAL_S = int(os.getenv("K3SLAB_SCHEDULER_INTERVAL_S", "60"))  # MVP: 60s

# Cuotas
MAX_ENVS_ACTIVOS_POR_STUDENT = int(os.getenv("K3SLAB_MAX_ENVS_STUDENT", "1"))

# GPUs visibles por nodo (NVIDIA_VISIBLE_DEVICES del runtime NVIDIA): mecanismo
# TODO-O-NADA — "all" (default) = todas las GPUs del nodo, sin elegir índice.
# Si un nodo debe exponer solo un subconjunto se declara aquí y en ese nodo
# "todas" significa ese subconjunto (futuro H200: {"h200": "0,1,2,3"}).
GPU_VISIBLE_POR_NODO = {}

JWT_EXPIRA_H = 12

# Contraseña de code-server (vscode) en el MVP — Fase 2: auth por usuario (PAM/SSO)
VSCODE_PASSWORD = os.getenv("K3SLAB_VSCODE_PASSWORD", "k3slab")

# Contraseña noVNC de MATLAB en el MVP (su flujo usaba PASSWORD env)
MATLAB_PASSWORD = os.getenv("K3SLAB_MATLAB_PASSWORD", "k3slab")

# Usuario admin para SSH directo a los nodos (dueño de la key del lab)
SSH_USER = os.getenv("K3SLAB_SSH_USER", "jreinosoc")

# Monitoreo (Prometheus del lab — el de GMED corre en :9393, no usar)
PROM_URL = os.getenv("K3SLAB_PROM_URL", "http://172.21.230.10:9090")
GRAFANA_URL = os.getenv("K3SLAB_GRAFANA_URL", "https://mlab-grafana.usfq.edu.ec/")

# Nombres amigables de hosts (IP → nombre) para el panel de equipos
HOST_NAMES = {
    "172.21.230.21": "wslab01",
    "172.21.230.22": "wslab02",
    "172.21.230.23": "wslab03",
    "172.21.230.10": "A100",
    "172.28.230.10": "H200",
    "172.21.230.11": "DGX",
    "172.21.230.12": "DGX2",
}
HOST_ORDER = ["wslab01", "wslab02", "wslab03", "A100", "H200", "DGX", "DGX2"]

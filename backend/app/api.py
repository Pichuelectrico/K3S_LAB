"""API del K3S Lab. Filtrado por rol SIEMPRE en el backend (nunca confiar en el frontend)."""
import datetime as dt
import json

from fastapi import APIRouter, Depends, Header, HTTPException

from . import auth, config, k8s, manifests
from .db import ActivityLog, Catalog, Env, SessionLocal, User, WebSesion, now

router = APIRouter(prefix="/api")


# ---------- dependencias ----------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def usuario_actual(authorization: str | None = Header(None), db=Depends(get_db)) -> tuple[User, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Falta token")
    data = auth.decodificar_token(authorization[7:])
    if not data:
        raise HTTPException(401, "Token inválido o expirado")
    user = db.get(User, data["sub"])
    if not user:
        # Usuario real de los nodos: su identidad ya fue verificada por PAM al
        # emitir el token, así que se registra en la BD al primer request.
        # El password_hash vacío es placeholder (verify_password -> False): el
        # login de este usuario siempre pasa por PAM o por el fallback con hash.
        user = User(username=data["sub"], password_hash="")
        db.add(user)
        try:
            db.commit()
        except Exception:  # noqa: BLE001 - carrera con otro request simultáneo
            db.rollback()
            user = db.get(User, data["sub"]) or user
    # Última actividad en la plataforma (para 'Conexiones activas en k3slab');
    # throttled: máximo 1 write/min por usuario
    try:
        ws = db.get(WebSesion, user.username)
        ahora = dt.datetime.utcnow()
        if not ws:
            db.add(WebSesion(username=user.username, login_at=ahora, last_seen=ahora))
            db.commit()
        elif (ahora - (ws.last_seen or ws.login_at)).total_seconds() >= 60:
            ws.last_seen = ahora
            db.commit()
    except Exception:  # noqa: BLE001 — nunca romper auth por el tracking
        db.rollback()
    return user, data.get("role", "student")


def requiere_dev(user_role=Depends(usuario_actual)) -> tuple[User, str]:
    user, role = user_role
    if role != "dev":
        raise HTTPException(403, "Requiere rol dev")
    return user, role


# ---------- auth ----------

# Rate limit anti brute force (in-memory, MVP): 5 fallos por usuario / 5 min
_FAILED_LOGINS: dict[str, tuple[int, float]] = {}
_MAX_LOGIN_FAILS = 5
_LOGIN_WINDOW_S = 300


@router.post("/auth/login")
def login(body: dict, db=Depends(get_db)):
    """PAM real: la contraseña se verifica contra la cuenta Linux del nodo (sshd→PAM).
    El backend NO guarda contraseñas de usuarios (solo fallback bcrypt de emergencia para
    usuarios bootstrap registrados en la DB, p.ej. el dev, cuando los nodos no responden)."""
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        raise HTTPException(400, "username y password son requeridos")

    # Rate limit (in-memory, MVP)
    import time as _t
    ahora = _t.time()
    prev = _FAILED_LOGINS.get(username)
    if prev and prev[0] >= _MAX_LOGIN_FAILS and ahora - prev[1] < _LOGIN_WINDOW_S:
        raise HTTPException(429, "Demasiados intentos fallidos. Espera unos minutos.")
    if prev and ahora - prev[1] >= _LOGIN_WINDOW_S:
        _FAILED_LOGINS.pop(username, None)

    resultado, _nodo = auth.verificar_password_pam(username, password)

    if resultado == "ok":
        user = db.get(User, username)
        role = auth.resolver_rol(user) if user else auth.rol_desde_nodo(username)
        _FAILED_LOGINS.pop(username, None)
        # Registra la sesión en la plataforma (Conexiones activas en k3slab)
        try:
            ahora = dt.datetime.utcnow()
            ws = db.get(WebSesion, username)
            if not ws:
                db.add(WebSesion(username=username, login_at=ahora, last_seen=ahora))
            else:
                ws.login_at = ahora
                ws.last_seen = ahora
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        return {"token": auth.crear_token(username, role),
                "username": username, "role": role}

    if resultado == "bad_password":
        f = _FAILED_LOGINS.get(username)
        _FAILED_LOGINS[username] = (f[0] + 1 if f else 1, ahora)
        raise HTTPException(401, "Contraseña incorrecta (cuenta Linux del nodo)")

    # no_user / unreachable → fallback bcrypt de emergencia solo para usuarios en la DB
    user = db.get(User, username)
    if user and auth.verify_password(password, user.password_hash):
        role = auth.resolver_rol(user)
        _FAILED_LOGINS.pop(username, None)
        return {"token": auth.crear_token(username, role),
                "username": username, "role": role}

    if resultado == "no_user":
        raise HTTPException(401, "Usuario no existe en los nodos")
    raise HTTPException(502, "Los nodos no responden y no hay fallback para este usuario")


@router.get("/auth/me")
def me(user_role=Depends(usuario_actual)):
    user, role = user_role
    return {"username": user.username, "role": role}


# ---------- catálogo y nodos ----------

@router.get("/catalog")
def catalogo(db=Depends(get_db)):
    cats = db.query(Catalog).all()
    return [{
        "id": c.id, "name": c.name, "description": c.description, "image": c.image,
        "cpu": c.cpu, "mem": c.mem, "gpu": bool(c.gpu),
        "ports": [int(p) for p in c.ports_json.split(",") if p.strip()],
        "access": c.access,
    } for c in cats]


@router.get("/nodes")
def nodos(db=Depends(get_db)):
    try:
        specs = {n["name"]: n for n in k8s.get_nodes()}
    except RuntimeError as e:
        raise HTTPException(502, f"kubectl no disponible: {e}")
    top = k8s.top_nodes()
    # GPUs por nodo (del Prometheus del lab) para el selector de recursos
    try:
        from . import prom
        gpu_counts = prom.gpu_counts()
    except Exception:  # noqa: BLE001
        gpu_counts = {}
    out = []
    for name, spec in specs.items():
        t = top.get(name, {})
        activos = db.query(Env).filter(Env.node == name, Env.status == "running").count()
        out.append({
            "name": name,
            "status": spec["status"],
            "cpu_used": t.get("cpu_m", 0),
            "mem_used": t.get("mem_mi", 0),
            "gpu_model": spec["gpu_model"],
            "vram_gb": spec["vram_gb"],
            "gpu_count": gpu_counts.get(name, 0),
            "tier": spec["tier"],
            "envs_activos": activos,
        })
    return out


# ---------- entornos ----------

def _env_a_json(env: Env, nodeport: int | None) -> dict:
    url = None
    if nodeport:
        ip = config.NODE_IPS.get(env.node, env.node)
        url = f"http://{ip}:{nodeport}"
    pass_efectiva = env.password or (
        config.VSCODE_PASSWORD if env.catalog_id == "vscode"
        else config.MATLAB_PASSWORD if env.catalog_id == "matlab" else None)
    return {
        "id": env.id, "name": env.name, "owner": env.owner, "node": env.node,
        "type": env.catalog_id, "status": env.status, "nodeport": nodeport,
        "gpu": bool(env.gpu),
        "shared": env.catalog_id == "playground",  # compartido: todos lo ven, solo dev lo gestiona
        "password": pass_efectiva,  # visible en el card y en el panel dev (MVP)
        "url": url, "created_at": env.created_at.isoformat() if env.created_at else None,
        "last_activity": env.last_activity.isoformat() if env.last_activity else None,
    }


@router.get("/envs")
def listar_envs(user_role=Depends(usuario_actual), db=Depends(get_db)):
    user, role = user_role
    q = db.query(Env).filter(Env.status != "deleting")
    if role != "dev":
        # Los estudiantes ven sus entornos + el playground compartido (solo conectar)
        q = q.filter((Env.owner == user.username) | (Env.catalog_id == "playground"))
    deploy_info = k8s.get_lab_envs()
    out = []
    for env in q.order_by(Env.created_at.desc()).all():
        # Sync de estado con el clúster:
        # 0 réplicas → stopped · réplicas pedidas pero ninguna ready → creating
        info = deploy_info.get(env.name)
        status = env.status
        if info and env.status == "running" and info["replicas"] == 0:
            env.status = "stopped"
            db.commit()
            status = "stopped"
        elif info and env.status == "running" and info["replicas"] > 0 and info["ready"] == 0:
            status = "creating"  # ContainerCreating / pulling imagen / arrancando
        e = _env_a_json(env, env.nodeport)
        e["status"] = status
        out.append(e)
    return out


@router.post("/envs")
def crear_env(body: dict, user_role=Depends(usuario_actual), db=Depends(get_db)):
    user, role = user_role
    cat = db.get(Catalog, body.get("catalog_id") or "")
    if not cat:
        raise HTTPException(400, "catalog_id inválido")

    # Playground compartido: UNA única instancia para todos, sin home, gestionada por los devs
    es_pg = cat.id == "playground"
    if es_pg:
        if role != "dev":
            raise HTTPException(403, "El playground solo lo pueden crear los devs")
        existe = db.query(Env).filter(Env.catalog_id == "playground",
                                      Env.status != "deleting").first()
        if existe:
            raise HTTPException(409, f"El playground ya existe ({existe.name}) — está en el dashboard")

    # Host OPCIONAL: si no se elige, k3s lo asigna (balanceo nativo por requests)
    node = (body.get("node_name") or "").strip()
    if node and node not in config.NODE_IPS:
        raise HTTPException(400, "nodo inválido (elige wslab01, wslab02 o wslab03, o no elijas para que k3s lo asigne)")

    # GPU como recurso (opcional): default del catálogo; el usuario puede pedirla para
    # colab/python/vscode/matlab (todos los tipos del catálogo) y elegir el índice
    wants_gpu = bool(body.get("gpu", bool(cat.gpu)))
    gpu_index = body.get("gpu_index")
    if gpu_index is not None and not wants_gpu:
        gpu_index = None

    # Cuota: 1 entorno activo por student (los devs sin límite en el MVP);
    # crear el playground no cuenta para la cuota del dev
    if role != "dev" and not es_pg:
        activos = db.query(Env).filter(
            Env.owner == user.username, Env.status == "running").count()
        if activos >= config.MAX_ENVS_ACTIVOS_POR_STUDENT:
            raise HTTPException(429, "Ya tienes un entorno activo. Detenlo o elimínalo primero.")

    # NodePort libre del rango propio
    ocupados = k8s.get_nodeports_en_uso()
    ocupados |= {e.nodeport for e in db.query(Env).filter(Env.status != "deleting",
                                                          Env.nodeport.isnot(None)).all()}
    nodeport = None
    if cat.ports_json:
        for p in range(config.NODEPORT_MIN, config.NODEPORT_MAX + 1):
            if p not in ocupados:
                nodeport = p
                break
        if nodeport is None:
            raise HTTPException(507, "No hay NodePorts libres en el rango")

    # El playground comparte nombre fijo (una instancia); el resto lleva el dueño
    nombre = (f"k3slab-playground-{nodeport or 'console'}" if es_pg
              else f"k3slab-{user.username}-{cat.id}-{nodeport or 'console'}")
    env = Env(name=nombre, owner=user.username, node=node, catalog_id=cat.id,
              nodeport=nodeport, gpu=1 if wants_gpu else 0)
    db.add(env)
    db.commit()

    # Password configurable por el usuario (vscode/matlab); vacío → default del config
    ent_password = (body.get("password") or "").strip() \
        if cat.id in ("vscode", "matlab") else None
    if ent_password and len(ent_password) < 4:
        db.delete(env)
        db.commit()
        raise HTTPException(400, "La contraseña debe tener al menos 4 caracteres")
    env.password = ent_password or None
    db.commit()

    mount_home = bool(body.get("mount_home", cat.id in ("colab", "vscode", "matlab")))
    if es_pg:
        mount_home = False  # el playground es compartido: nunca monta un home
    uid = gid = None
    if cat.id == "vscode" and mount_home:
        # Con host automático resolvemos el uid en wslab01 (fuente de verdad de las cuentas);
        # ojo: si los uids del usuario difieren entre nodos (usuarios pre-Ansible) y k3s
        # agenda en otro nodo, puede haber mismatch de permisos hasta unificar uids.
        uid, gid = k8s.uid_gid_en_nodo(user.username, env.node or "wslab01")
    yaml_str = manifests.build_manifests(env.name, env.owner, env.node, nodeport, cat,
                                         uid=uid, gid=gid, gpu=wants_gpu, gpu_index=gpu_index,
                                         mount_home=mount_home, password=env.password)
    ok, out = k8s.apply_yaml(yaml_str)
    if not ok:
        db.delete(env)
        db.commit()
        raise HTTPException(502, f"kubectl apply falló: {out}")

    # Con host automático: guardamos el nodo real que el scheduler de k3s asignó
    if not node:
        real = k8s.get_pod_node(env.name)
        if real:
            env.node = real
            db.commit()

    db.add(ActivityLog(env_id=env.id, username=user.username, action="create"))
    db.commit()
    return _env_a_json(env, nodeport)


def _obtener_env_propio(env_id: int, user: User, role: str, db,
                        permitir_playground: bool = False) -> Env:
    env = db.get(Env, env_id)
    if not env:
        raise HTTPException(404, "Entorno no existe")
    if role != "dev" and env.owner != user.username:
        # El playground es compartido: todos pueden conectarse/iniciarlo,
        # pero detener/eliminar queda solo para los devs (dueño)
        if permitir_playground and env.catalog_id == "playground":
            return env
        raise HTTPException(403, "Ese entorno no es tuyo")
    return env


@router.post("/envs/{env_id}/start")
def iniciar_env(env_id: int, user_role=Depends(usuario_actual), db=Depends(get_db)):
    user, role = user_role
    env = _obtener_env_propio(env_id, user, role, db, permitir_playground=True)
    ok, out = k8s.scale_env(env.name, 1)
    if not ok:
        raise HTTPException(502, f"scale falló: {out}")
    env.status = "running"
    env.last_activity = now()
    env.stopped_at = None
    db.add(ActivityLog(env_id=env.id, username=user.username, action="start"))
    db.commit()
    return _env_a_json(env, env.nodeport)


@router.post("/envs/{env_id}/stop")
def detener_env(env_id: int, user_role=Depends(usuario_actual), db=Depends(get_db)):
    user, role = user_role
    env = _obtener_env_propio(env_id, user, role, db)
    ok, out = k8s.scale_env(env.name, 0)
    if not ok:
        raise HTTPException(502, f"scale falló: {out}")
    env.status = "stopped"
    env.stopped_at = now()
    db.add(ActivityLog(env_id=env.id, username=user.username, action="stop"))
    db.commit()
    return _env_a_json(env, env.nodeport)


@router.delete("/envs/{env_id}")
def eliminar_env(env_id: int, user_role=Depends(usuario_actual), db=Depends(get_db)):
    user, role = user_role
    env = _obtener_env_propio(env_id, user, role, db)
    k8s.delete_env_resources(env.name)
    db.add(ActivityLog(env_id=env.id, username=user.username, action="delete"))
    db.delete(env)  # hard-delete: libera el name único para poder recrear
    db.commit()
    return {"ok": True, "msg": f"{env.name} eliminado"}


@router.post("/envs/{env_id}/activity")
def registrar_actividad(env_id: int, user_role=Depends(usuario_actual), db=Depends(get_db)):
    user, role = user_role
    env = _obtener_env_propio(env_id, user, role, db, permitir_playground=True)
    env.last_activity = now()
    db.add(ActivityLog(env_id=env.id, username=user.username, action="open"))
    db.commit()
    return {"ok": True}


@router.get("/envs/{env_id}/connect")
def conectar_env(env_id: int, user_role=Depends(usuario_actual), db=Depends(get_db)):
    """Instrucciones de conexión por tipo:
    - colab: túnel SSH + token del log (Connect to a local runtime, doc de Google)
    - matlab: port-forward SSH al noVNC + password (la URL directa solo sirve
      desde la red del lab — desde el laptop hace falta el túnel)
    - python (consola): SSH al nodo + kubectl exec dentro del contenedor
      (los estudiantes tienen cuenta en wslab01, donde k3s kubectl está disponible)"""
    user, role = user_role
    env = _obtener_env_propio(env_id, user, role, db, permitir_playground=True)
    if env.status != "running":
        raise HTTPException(409, "El entorno no está corriendo (inícialo primero)")
    ip = config.NODE_IPS.get(env.node, env.node)
    head = config.NODE_IPS.get("wslab01", "wslab01")
    es_pg = env.catalog_id == "playground"
    es_colab = env.catalog_id in ("colab", "playground")  # el playground es colab compartido
    # En un entorno compartido el túnel va por la cuenta del que se conecta, no la del dueño
    tunnel_user = user.username if es_pg else env.owner

    if es_colab:
        if not env.nodeport:
            raise HTTPException(400, "Este entorno no expone puertos")
        token = k8s.get_pod_token(env.name)
        port_local = 9000  # puerto local sugerido (el doc usa 127.0.0.1:9000:8080)
        return {
            "tipo": "colab",
            "shared": es_pg,
            "token": token,
            "ssh_cmd": f"ssh -N -L {port_local}:localhost:{env.nodeport} {tunnel_user}@{ip}",
            "colab_url": f"http://localhost:{port_local}/?token={token}" if token else None,
            "node_url": f"http://{ip}:{env.nodeport}",
            "steps": [
                "En tu terminal lanza el túnel SSH de arriba y deja la ventana abierta.",
                "En colab.research.google.com: botón Connect → Connect to local runtime y pega la URL de abajo.",
                "El playground es compartido: cierra tu sesión en Colab al terminar, no lo detengas ni lo elimines (eso es de los devs)."
                if es_pg else
                "Al terminar tu sesión, detén o elimina el entorno para liberar recursos.",
            ],
        }

    if env.catalog_id == "matlab":
        if not env.nodeport:
            raise HTTPException(400, "Este entorno no expone puertos")
        port_local = 6080  # puerto local sugerido (noVNC)
        return {
            "tipo": "matlab",
            "ssh_cmd": f"ssh -N -L {port_local}:localhost:{env.nodeport} {env.owner}@{ip}",
            "local_url": f"http://localhost:{port_local}",
            "node_url": f"http://{ip}:{env.nodeport}",
            "password": env.password or config.MATLAB_PASSWORD,
            "steps": [
                f"Abre http://{ip}:{env.nodeport} (NodePort directo, igual que VS Code — funciona desde la red del lab).",
                "noVNC pedirá el password del escritorio VNC (abajo). El escritorio tarda ~1 min la primera vez; lanza MATLAB desde su icono.",
                "Tu home del nodo está montado en /home.",
                "Al terminar tu sesión, detén o elimina el entorno para liberar recursos.",
            ],
        }

    # Consola (python): un solo comando — el kubectl exec te conecta e ingresa al contenedor
    # (pasa por wslab01, donde vive el kubeconfig; el home está montado dentro del contenedor)
    deploy = env.name
    return {
        "tipo": "console",
        "exec_cmd": f'ssh {env.owner}@{head} "k3s kubectl exec -it -n default deploy/{deploy} -- bash"',
        "steps": [
            "Este comando te conecta e ingresa directo a tu contenedor de Python (pasa por wslab01, donde vive el kubectl).",
            "Tu home del nodo está montado dentro del contenedor — ahí guardas todo.",
            "El contenedor es efímero: lo que no guardes en tu home se pierde al eliminarlo.",
        ],
    }


# ---------- admin (solo dev) ----------

@router.get("/admin/overview")
def overview(db=Depends(get_db), _=Depends(requiere_dev)):
    envs = db.query(Env).filter(Env.status != "deleting").all()
    top = k8s.top_nodes()
    por_estado = {"running": 0, "stopped": 0}
    for e in envs:
        if e.status in por_estado:
            por_estado[e.status] += 1
    return {
        "total_envs": len(envs),
        "por_estado": por_estado,
        "nodos": [{"name": k, **v} for k, v in top.items()],
        "envs": [_env_a_json(e, e.nodeport) for e in envs],
    }


@router.post("/admin/lifecycle/run")
def lifecycle_manual(_=Depends(requiere_dev)):
    from .scheduler import run_lifecycle
    return run_lifecycle()


@router.get("/admin/servers")
def servers(_=Depends(requiere_dev)):
    """Panel de equipos (solo lectura): SO, kernel, uptime, load, CPU, RAM, disco,
    GPU (modelo/VRAM/util/driver CUDA), contenedores — del Prometheus del lab (:9090)
    + pods k3s por nodo. Ver /admin/overview para el resumen del clúster."""
    from . import prom
    servers_data = prom.obtener_servers()
    try:
        pods = k8s.pods_por_nodo()
    except Exception:
        pods = {}
    for s in servers_data:
        s["pods_k3s"] = pods.get(s["nombre"], 0)
    return {"servers": servers_data, "grafana_url": config.GRAFANA_URL}


@router.get("/admin/activity")
def actividad(_=Depends(requiere_dev)):
    """Quién está conectado (sesiones SSH/consola con `w` en los 3 nodos del lab)
    y qué entornos están corriendo (estado real del clúster), para el panel de devs."""
    # 1. Sesiones en vivo por nodo (la producción NO se toca) + salida cruda de `who`
    sesiones = []
    who_raw = []
    for name in ("wslab01", "wslab02", "wslab03"):
        ip = config.NODE_IPS.get(name)
        if not ip:
            continue
        try:
            r = auth._ssh_cmd(ip, "who", timeout=8)
            w = auth._ssh_cmd(ip, "w -h", timeout=8)
        except Exception:  # noqa: BLE001 — nodo caído/inau-ible
            continue
        if r.returncode == 0:
            who_raw.append({"node": name, "out": r.stdout.strip() or "(sin sesiones)"})
        if w.returncode != 0:
            continue
        for line in r.stdout.splitlines():
            p = line.split()
            if len(p) < 5 or p[0] == "gdm":  # gdm = display manager del sistema, no una persona
                continue
            # Formato `w -h`: USER TTY FROM LOGIN@ IDLE ... — pero las sesiones SSH
            # sin terminal NO traen TTY (la columna colapsa): [user, ip, login, idle, ...]
            user = p[0]
            if p[1].startswith(("pts/", "tty")):
                tty, rest = p[1], p[2:]
            else:
                tty, rest = "-", p[1:]
            if len(rest) < 3:
                continue
            sesiones.append({
                "user": user, "node": name, "node_ip": ip, "tty": tty, "desde": rest[0],
                "login": rest[1], "idle": rest[2],
            })

    # 2. Entornos con estado real del clúster
    deploy_info = k8s.get_lab_envs()
    entornos = []
    with SessionLocal() as db:
        for env in db.query(Env).order_by(Env.owner, Env.name).all():
            info = deploy_info.get(env.name) or {}
            if info.get("ready", 0) > 0:
                status = "running"
            elif info.get("replicas", 0) > 0:
                status = "creating"
            else:
                status = "stopped"
            entornos.append({
                "owner": env.owner, "name": env.name, "type": env.catalog_id,
                "node": env.node, "nodeport": env.nodeport, "status": status,
                "gpu": bool(env.gpu),
                "shared": env.catalog_id == "playground",
            })
    # 3. Sesiones en la plataforma (logins web): activas = actividad en los últimos 15 min
    corte = dt.datetime.utcnow() - dt.timedelta(minutes=15)
    web = [{
        "username": s.username,
        "login_at": s.login_at.isoformat() if s.login_at else None,
        "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        "activo": bool(s.last_seen and s.last_seen >= corte),
    } for s in db.query(WebSesion).order_by(WebSesion.last_seen.desc()).limit(30).all()]

    return {"sesiones": sesiones, "entornos": entornos, "who_raw": who_raw, "web": web}

"""API del K3S Lab. Filtrado por rol SIEMPRE en el backend (nunca confiar en el frontend)."""
import datetime as dt
import json
from urllib.parse import quote_plus

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


# ---------- heartbeat ----------

@router.get("/ping")
def ping(user_role=Depends(usuario_actual)):
    """Pulso ligero del frontend (cada 30s mientras la pestaña esté abierta):
    usuario_actual ya refresca WebSesion.last_seen como efecto secundario, así
    'quién está conectado' refleja la sesión real y no se queda pegado en
    ACTIVA 15 min tras cerrar la pestaña."""
    user, _role = user_role
    return {"ok": True, "user": user.username}


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
            # Memoria TOTAL (capacity, parseada a Mi) para calcular las opciones
            # low/medium/max de RAM/SHM en el wizard según el nodo
            "mem_total_mi": k8s._to_mi(spec.get("mem_total") or "") if spec.get("mem_total") else 0,
            "gpu_model": spec["gpu_model"],
            "vram_gb": spec["vram_gb"],
            # El dcgm-exporter reporta por HOST (ej: "DGX2"); cuando el host es
            # agente k3s con otro nombre (dgx2-station) resolvemos el alias
            "gpu_count": gpu_counts.get(name)
            or gpu_counts.get(config.NODE_HOST_ALIAS.get(name, name), 0),
            "tier": spec["tier"],
            "envs_activos": activos,
        })
    return out


# ---------- entornos ----------

def _env_a_json(env: Env, nodeport: int | None) -> dict:
    pass_efectiva = env.password or (
        config.VSCODE_PASSWORD if env.catalog_id == "vscode"
        else config.MATLAB_PASSWORD if env.catalog_id == "matlab"
        else config.JUPYTER_PASSWORD if env.catalog_id == "jupyter" else None)
    url = None
    if nodeport:
        ip = config.NODE_IPS.get(env.node, env.node)
        url = f"http://{ip}:{nodeport}"
        # JupyterLab: token prefill en la URL (login directo, sin copiar/pegar)
        if env.catalog_id == "jupyter" and pass_efectiva:
            url += f"/lab?token={quote_plus(pass_efectiva)}"
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
    # TODOS (devs incluidos) ven sus entornos + el playground compartido;
    # el inventario completo de todos los usuarios vive en el Panel Dev —
    # no lo duplicamos aquí
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
        raise HTTPException(400, "nodo inválido (elige uno de la lista o no elijas para que k3s lo asigne)")

    # GPU como recurso (opcional): default del catálogo. TODO-O-NADA: sin índices —
    # el nodo expone todas sus GPUs (o el subconjunto de GPU_VISIBLE_POR_NODO).
    wants_gpu = bool(body.get("gpu", bool(cat.gpu)))

    # Destinatario (solo devs, fuera del playground): crear el entorno para OTRO
    # usuario (dueño real = para). Los students siempre crean para sí mismos.
    para = (body.get("para") or "").strip()
    if para and para != user.username and not es_pg:
        if role != "dev":
            raise HTTPException(403, "Solo los devs pueden crear entornos para otros usuarios")
        if not k8s.uid_gid_en_nodo(para, node or "wslab01")[0]:
            raise HTTPException(400, f"El usuario '{para}' no existe en el nodo (revisa el nombre)")
    owner = para if (para and not es_pg) else user.username

    # RAM y SHM (avanzadas, devs): low / medium / max — calculadas según la memoria
    # TOTAL del nodo elegido (o del nodo lab Ready más pequeño si el host es
    # automático): low ≈ 1/8 del total (un poco más del mínimo, razonable de usar),
    # medium ≈ 1/2 del total (default SHM), max = sin límites (default RAM; para
    # SHM, todo el total del nodo). Fallback fijo si kubectl no responde.
    ram = (body.get("ram") or "max").strip().lower()
    shm = (body.get("shm") or "medium").strip().lower()
    if ram not in ("low", "medium", "max") or shm not in ("low", "medium", "max"):
        raise HTTPException(400, "ram/shm deben ser low, medium o max")
    total_mi = k8s.mem_total_nodo(node or None)
    if total_mi:
        low_gi = max(1, round(total_mi / 8 / 1024))
        med_gi = max(1, round(total_mi / 2 / 1024))
        tot_gi = max(1, round(total_mi / 1024))
    else:
        low_gi, med_gi, tot_gi = 6, 23, 46
    ram_gi = {"low": low_gi, "medium": med_gi}.get(ram)  # max → None (sin límites)
    mem_limit = f"{ram_gi}Gi" if ram_gi else None
    shm_size = None
    if cat.id in ("colab", "matlab", "python"):
        shm_size = f"{ {'low': low_gi, 'medium': med_gi, 'max': tot_gi}[shm] }Gi"

    # Volúmenes extra (solo devs): hostPath del nodo montado en el MISMO path
    # dentro del pod, rw o ro. Riesgo real (path arbitrario del nodo) → devs only.
    vols_in = body.get("volumes") or []
    if not isinstance(vols_in, list):
        raise HTTPException(400, "volumes debe ser una lista de {path, ro}")
    if vols_in and role != "dev":
        raise HTTPException(403, "Solo los devs pueden montar volúmenes extra")
    vols_extra, vistos = [], set()
    for v in vols_in[:8]:
        p = (v.get("path") or "").strip() if isinstance(v, dict) else ""
        if not p:
            continue
        if not p.startswith("/"):
            raise HTTPException(400, f"El path del volumen debe ser absoluto: '{p}'")
        if p == "/dev/shm":
            raise HTTPException(400, "'/dev/shm' se controla con shm-size, no como volumen extra")
        if p in vistos:
            raise HTTPException(400, f"Volumen duplicado: '{p}'")
        vistos.add(p)
        vols_extra.append({"path": p, "ro": bool(v.get("ro"))})

    # Cuota: 1 entorno activo de CADA tipo por student (los devs sin límite en el MVP);
    # el playground nunca se cuenta. Pueden tener 1 vscode + 1 jupyter + 1 matlab...
    if role != "dev" and not es_pg:
        activos = db.query(Env).filter(
            Env.owner == user.username, Env.catalog_id == cat.id,
            Env.status == "running").count()
        if activos >= config.MAX_ENVS_ACTIVOS_POR_STUDENT:
            raise HTTPException(
                429, f"Ya tienes un entorno {cat.name} activo — se permite uno de cada "
                     "tipo. Detenlo o elimínalo primero.")

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
              else f"k3slab-{owner}-{cat.id}-{nodeport or 'console'}")
    env = Env(name=nombre, owner=owner, node=node, catalog_id=cat.id,
              nodeport=nodeport, gpu=1 if wants_gpu else 0)
    db.add(env)
    db.commit()

    # Password configurable por el usuario (vscode/matlab/jupyter); vacío → default
    ent_password = (body.get("password") or "").strip() \
        if cat.id in ("vscode", "matlab", "jupyter") else None
    if ent_password and len(ent_password) < 4:
        db.delete(env)
        db.commit()
        raise HTTPException(400, "La contraseña debe tener al menos 4 caracteres")
    env.password = ent_password or None
    db.commit()

    mount_home = bool(body.get("mount_home", cat.id in ("colab", "vscode", "matlab", "jupyter")))
    if es_pg:
        mount_home = False  # el playground es compartido: nunca monta un home
    uid = gid = None
    if cat.id in ("vscode", "jupyter") and mount_home:
        # Con host automático resolvemos el uid en wslab01 (fuente de verdad de las cuentas);
        # ojo: si los uids del usuario difieren entre nodos (usuarios pre-Ansible) y k3s
        # agenda en otro nodo, puede haber mismatch de permisos hasta unificar uids.
        uid, gid = k8s.uid_gid_en_nodo(env.owner, env.node or "wslab01")
    yaml_str = manifests.build_manifests(env.name, env.owner, env.node, nodeport, cat,
                                         uid=uid, gid=gid, gpu=wants_gpu,
                                         mount_home=mount_home, password=env.password,
                                         shm_size=shm_size or "45Gi",
                                         mem_limit=mem_limit, extra_volumes=vols_extra)
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

    # Asegurar el usuario + home en el nodo REAL: los students pueden no existir
    # allí y los UIDs difieren por nodo (pre-Ansible) — el vscode corre con el uid
    # del nodo de referencia y crashea con EACCES si el home no es suyo (ocurrió
    # con csantamaria: uid 1048 en wslab01, no existe en wslab03). Si el uid local
    # difiere del usado en el primer apply, re-aplicamos el manifest con el uid local.
    if cat.id in ("vscode", "jupyter") and mount_home and env.node:
        local_uid, local_gid = k8s.asegurar_usuario_nodo(env.owner, env.node)
        if local_uid and local_uid != (uid or -1):
            yaml_str = manifests.build_manifests(
                env.name, env.owner, env.node, nodeport, cat,
                uid=local_uid, gid=local_gid, gpu=wants_gpu,
                mount_home=mount_home, password=env.password,
                shm_size=shm_size or "45Gi", mem_limit=mem_limit,
                extra_volumes=vols_extra)
            k8s.apply_yaml(yaml_str)

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

    if env.catalog_id == "jupyter":
        # JupyterLab: NodePort directo con el token prefill en la URL (login automático)
        if not env.nodeport:
            raise HTTPException(400, "Este entorno no expone puertos")
        token = env.password or config.JUPYTER_PASSWORD
        return {
            "tipo": "jupyter",
            "node_url": f"http://{ip}:{env.nodeport}/lab?token={quote_plus(token)}",
            "password": token,
            "steps": [
                f"Abre http://{ip}:{env.nodeport}/lab?token=… (NodePort directo, el token ya va en la URL — ábrela y entra solo).",
                "La vista de notebooks es nativa de JupyterLab: no necesita extensiones ni VS Code.",
                "El kernel corre EN EL POD: cierra la pestaña del navegador y la ejecución sigue; al volver, el kernel sigue vivo con tus variables.",
                "Tu home del nodo está montado en /home/jovyan (los .ipynb quedan en tu home real).",
                "Al terminar, detén o elimina el entorno para liberar recursos.",
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
    """Quién está conectado (sesiones SSH/consola con `w` en los nodos del lab)
    y qué entornos están corriendo (estado real del clúster), para el panel de devs."""
    # 1. Sesiones en vivo por nodo (la producción NO se toca) + salida cruda de `who`.
    # Se itera config.NODE_IPS para cubrir automáticamente cualquier nodo del lab.
    sesiones = []
    who_raw = []
    for name in config.NODE_IPS:
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
    # 3. Sesiones en la plataforma (logins web): activas = actividad en los últimos
    # 5 min (el frontend manda un heartbeat /ping cada 30s mientras la pestaña esté
    # abierta, así last_seen se refresca esté en la vista que esté). Se devuelven
    # TODAS las filas (1 por usuario, PK username) para que el frontend filtre por
    # recencia (última hora por defecto / todos).
    corte = dt.datetime.utcnow() - dt.timedelta(minutes=5)
    web = [{
        "username": s.username,
        "login_at": s.login_at.isoformat() if s.login_at else None,
        "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        "activo": bool(s.last_seen and s.last_seen >= corte),
    } for s in db.query(WebSesion).order_by(WebSesion.last_seen.desc()).limit(500).all()]

    return {"sesiones": sesiones, "entornos": entornos, "who_raw": who_raw, "web": web}


@router.get("/admin/topology")
def topology(_=Depends(requiere_dev)):
    """Topología 3D del panel de equipos (frontend/Equipos3D.html): los 7 hosts
    del lab con métricas reales del Prometheus + pods k3s por nodo (con dueños)
    + sesiones SSH en vivo + entornos activos. Misma forma que window.EQUIPOS_DEMO."""
    from . import prom

    # 1. Métricas de hosts del Prometheus del lab (order fijo HOST_ORDER)
    servers_data = prom.obtener_servers()

    # 2. Versión del clúster (k3s) — UNA llamada SSH
    version = ""
    try:
        ok, out = k8s.kubectl("version -o json")
        if ok:
            version = (json.loads(out).get("serverVersion") or {}).get("gitVersion", "")
    except Exception:  # noqa: BLE001
        version = ""

    # 3. Pods k3s con detalles por nodo — UNA llamada SSH (get pods -A -o json)
    pods_por_nodo: dict[str, dict] = {}
    try:
        ok, out = k8s.kubectl("get pods -A -o json")
        if ok:
            for item in json.loads(out).get("items", []):
                nodo = (item.get("spec") or {}).get("nodeName") or ""
                st = item.get("status") or {}
                fase = (st.get("phase") or "unknown").lower()
                meta = item.get("metadata") or {}
                refs = meta.get("ownerReferences") or [{}]
                d = pods_por_nodo.setdefault(nodo, {
                    "count": 0, "running": 0, "pending": 0, "failed": 0,
                    "succeeded": 0, "restarts": 0, "owners": [],
                })
                d["count"] += 1
                if fase in ("running", "pending", "failed", "succeeded"):
                    d[fase] += 1
                d["restarts"] += sum(
                    (cs or {}).get("restartCount", 0)
                    for cs in (st.get("containerStatuses") or [])
                )
                d["owners"].append({
                    "name": meta.get("name", ""),
                    "namespace": meta.get("namespace", "default"),
                    "kind": refs[0].get("kind", "Pod"),
                    "containers": len((item.get("spec") or {}).get("containers") or []),
                })
    except Exception:  # noqa: BLE001
        pods_por_nodo = {}

    # 4. Sesiones SSH en vivo por nodo (mismo criterio que /admin/activity)
    sesiones_por_nodo: dict[str, list] = {}
    for name in config.NODE_IPS:
        ip = config.NODE_IPS.get(name)
        if not ip:
            continue
        try:
            r = auth._ssh_cmd(ip, "who", timeout=8)
        except Exception:  # noqa: BLE001 — nodo caído/inau-ible
            continue
        if r.returncode != 0:
            continue
        for line in r.stdout.splitlines():
            p = line.split()
            if len(p) < 5 or p[0] == "gdm":  # gdm = display manager, no una persona
                continue
            user = p[0]
            if p[1].startswith(("pts/", "tty")):
                tty, rest = p[1], p[2:]
            else:
                tty, rest = "-", p[1:]
            if len(rest) < 3:
                continue
            sesiones_por_nodo.setdefault(name, []).append({
                "user": user, "type": "ssh" if tty.startswith("pts/") else "consola",
                "since": rest[1], "from": tty if tty == "-" else rest[0],
            })

    # 5. Alertas firing del Prometheus, agrupadas por host (cluster-wide por nodo)
    alertas_por_host: dict[str, int] = {}
    try:
        for m in prom._query('ALERTS{alertstate="firing"}'):
            alertas_por_host[prom._nombre(m.get("metric", {}).get("instance", ""))] = \
                alertas_por_host.get(prom._nombre(m.get("metric", {}).get("instance", "")), 0) + 1
    except Exception:  # noqa: BLE001
        pass

    # 6. Targets de scrape del Prometheus (up/total por host)
    import urllib.request
    targets_por_host: dict[str, dict] = {}
    try:
        url = config.PROM_URL + "/api/v1/targets"
        with urllib.request.urlopen(url, timeout=8) as r:
            targets_data = prom.json_loads(r.read())
        for t in (targets_data.get("data") or {}).get("activeTargets") or []:
            host = prom._nombre(t.get("labels", {}).get("instance", ""))
            d = targets_por_host.setdefault(host, {"total": 0, "up": 0})
            d["total"] += 1
            if (t.get("health") or "") == "up":
                d["up"] += 1
    except Exception:  # noqa: BLE001
        pass

    # 7. Red por host (Mbps rx/tx de interfaces físicas) — Prometheus
    red_rx: dict[str, float] = {}
    red_tx: dict[str, float] = {}
    try:
        rx = prom._query('sum by (instance)(rate(node_network_receive_bytes_total'
                         '{device!~"lo|veth.*|docker.*|flannel.*|cali.*|kube-ipvs.*|tunl0|cni.*|cilium.*"}[5m])) * 8 / 1e6')
        tx = prom._query('sum by (instance)(rate(node_network_transmit_bytes_total'
                         '{device!~"lo|veth.*|docker.*|flannel.*|cali.*|kube-ipvs.*|tunl0|cni.*|cilium.*"}[5m])) * 8 / 1e6')
        for m in rx:
            red_rx[prom._nombre(m.get("metric", {}).get("instance", ""))] = prom._f(m["value"][1])
        for m in tx:
            red_tx[prom._nombre(m.get("metric", {}).get("instance", ""))] = prom._f(m["value"][1])
    except Exception:  # noqa: BLE001
        pass

    # 8. Entornos con estado real del clúster (mismo criterio que /admin/activity)
    deploy_info = k8s.get_lab_envs()
    entornos: list[dict] = []
    with SessionLocal() as db:
        for env in db.query(Env).order_by(Env.owner, Env.name).all():
            info = deploy_info.get(env.name) or {}
            if info.get("ready", 0) > 0:
                estado = "running"
            elif info.get("replicas", 0) > 0:
                estado = "creating"
            else:
                estado = "stopped"
            entornos.append({
                "owner": env.owner, "name": env.name, "type": env.catalog_id,
                "node": env.node, "status": estado, "gpu": bool(env.gpu),
            })

    def _pct(used, total) -> float:
        return round(used / total * 100, 1) if total else 0.0

    # Nodos k3s: nombre del panel (HOST_ORDER) → nodeName del clúster.
    # "DGX2" es el nodo k3s "dgx2-station"; el resto coincide.
    K3S_NODE_NAME = {"wslab01": "wslab01", "wslab02": "wslab02",
                     "wslab03": "wslab03", "DGX2": "dgx2-station"}
    nodes = []
    for s in servers_data:
        nombre = s["nombre"]
        cpu_pct = prom._f(s.get("cpu_pct"))
        ram_pct = _pct(s.get("ram_used") or 0, s.get("ram_total") or 0)
        disk_total = s.get("disk_total") or 0
        disk_pct = _pct(disk_total - (s.get("disk_free") or 0), disk_total)
        peor = max(cpu_pct, ram_pct, disk_pct)
        online = bool(s.get("online"))
        health = "ok"
        if not online or peor >= 90:
            health = "critical"
        elif peor >= 75:
            health = "warning"
        pods = pods_por_nodo.get(K3S_NODE_NAME.get(nombre, "")) or \
            {"count": 0, "running": 0, "pending": 0, "failed": 0, "restarts": 0, "owners": []}
        # Actividad por nodo: entornos en ese host (pod caído = warning)
        act = []
        for e in entornos:
            if e["node"] != nombre or e["status"] == "stopped":
                continue
            act.append({
                "level": "info" if e["status"] == "running" else "warning",
                "time": "",
                "message": f"{e['name']} · {e['type']} · {e['owner']}"
                           + (" · GPU" if e["gpu"] else "") + f" — {e['status']}",
            })
        for ses in sesiones_por_nodo.get(nombre, []):
            act.append({"level": "info", "time": ses.get("since", ""),
                        "message": f"{ses['user']} conectado ({ses['type']}) desde {ses.get('from', '?')}"})
        tg = targets_por_host.get(nombre) or {}
        nodes.append({
            "id": nombre,
            "hostname": s.get("hostname") or nombre,
            "role": "MASTER" if nombre == "wslab01" else
                    ("WORKER" if nombre in K3S_NODE_NAME else "HOST"),
            "asset": "WsL" if nombre.startswith("wslab") else
                     ("DGX" if "dgx" in nombre.lower() else "Server"),
            "ip": s.get("ip", ""),
            "os": s.get("os", ""),
            "kernel": s.get("kernel", ""),
            "online": online,
            "health": health,
            "healthScore": max(0, min(100, int(100 - peor))),
            "statusMessage": "" if online else "Sin datos del Prometheus (host caído o inalcanzable)",
            "cpu": {"pct": round(cpu_pct, 1), "cores": s.get("cores"),
                    "load1": s.get("load1"), "load5": s.get("load5"), "load15": s.get("load15")},
            "memory": {"pct": ram_pct, "usedGb": prom._gb(s.get("ram_used") or 0),
                       "totalGb": prom._gb(s.get("ram_total") or 0)},
            "disk": {"pct": disk_pct, "usedGb": prom._gb(disk_total - (s.get("disk_free") or 0)),
                     "totalGb": prom._gb(disk_total)},
            "network": ({"rxMbps": round(red_rx.get(nombre, 0), 1),
                         "txMbps": round(red_tx.get(nombre, 0), 1)}
                        if nombre in red_rx or nombre in red_tx else None),
            "gpus": s.get("gpus") or [],
            "contenedores": s.get("contenedores"),
            "prometheus": {
                "uptime": s.get("uptime", ""),
                "alerts": alertas_por_host.get(nombre, 0),
                "scrapeTargets": tg.get("total"),
                "targetsDown": (tg.get("total") - tg.get("up", 0)) if tg.get("total") else None,
                "cpuLoad1": s.get("load1"),
                "podRestarts24h": pods.get("restarts", 0),
            },
            "pods": {"count": pods.get("count", 0), "running": pods.get("running", 0),
                     "pending": pods.get("pending", 0), "failed": pods.get("failed", 0),
                     "owners": pods.get("owners", [])},
            "sessions": sesiones_por_nodo.get(nombre, []),
            "activity": act,
        })

    return {
        "cluster": {"name": "k3s-lab", "version": version or "k3s"},
        "nodes": nodes,
        "generatedAt": dt.datetime.utcnow().isoformat() + "Z",
    }

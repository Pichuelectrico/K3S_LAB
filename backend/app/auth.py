"""Autenticación: login local (bcrypt) + rol heredado de los grupos reales del nodo."""
import datetime as dt
import subprocess

import bcrypt
import jwt

from . import config
from .db import User, now


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def _ssh_cmd(host_ip: str, cmd: str, timeout: int = 10):
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
         "-o", "StrictHostKeyChecking=accept-new",
         "-i", config.SSH_KEY,
         f"{config.SSH_USER}@{host_ip}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def nodos_pam() -> list[str]:
    """IPs de los nodos donde se verifican las cuentas Linux (head primero)."""
    return [config.NODE_IPS[n] for n in ("wslab01", "wslab02", "wslab03")
            if n in config.NODE_IPS]


def nodo_con_usuario(username: str) -> str | None:
    """Primer nodo donde existe la cuenta Linux del usuario (hasta que Ansible
    unifique las cuentas, pueden existir solo en uno)."""
    for ip in nodos_pam():
        try:
            r = _ssh_cmd(ip, f"id -u {username}")
            if r.returncode == 0:
                return ip
        except Exception:  # noqa: BLE001
            continue
    return None


def verificar_password_pam(username: str, password: str) -> tuple[str, str | None]:
    """Verifica la contraseña contra la cuenta Linux REAL del nodo (sshd → PAM → /etc/shadow).
    Devuelve (resultado, nodo_ip): ok | bad_password | no_user | unreachable.

    - La contraseña nunca se guarda: solo se verifica al vuelo.
    - look_for_keys/allow_agent=False: SOLO password auth (la key del dev no valida)."""
    nodo = nodo_con_usuario(username)
    if not nodo:
        return "no_user", None
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(nodo, port=22, username=username, password=password,
                           allow_agent=False, look_for_keys=False, timeout=8)
            client.close()
            return "ok", nodo
        except paramiko.AuthenticationException:
            return "bad_password", nodo
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001 — nodo inalcanzable u otro error de infra
        return "unreachable", nodo


def rol_desde_nodo(username: str) -> str:
    """Consulta los grupos reales del usuario en los nodos: devs→dev, resto student.
    Prueba los 3 nodos en orden (el grupo devs puede ser suplementario — usermod -aG)."""
    for ip in nodos_pam():
        try:
            r = _ssh_cmd(ip, f"id -nG {username}")
            if r.returncode == 0:
                grupos = r.stdout.split()
                return "dev" if "devs" in grupos else "student"
        except Exception:  # noqa: BLE001
            continue
    return "student"


def resolver_rol(user: User) -> str:
    if user.role_override:
        return user.role_override
    return rol_desde_nodo(user.username)


def crear_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": dt.datetime.utcnow() + dt.timedelta(hours=config.JWT_EXPIRA_H),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")


def decodificar_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None

"""Ciclo de vida: RUNNING →(7d sin actividad)→ STOPPED →(90d)→ DELETED. Ver CONTEXT.md §4."""
import datetime as dt
import traceback

from . import config, k8s
from .db import ActivityLog, Env, SessionLocal, now


def run_lifecycle(log=print) -> dict:
    """Una pasada del scheduler. Devuelve resumen (para el endpoint manual del dev)."""
    db = SessionLocal()
    resumen = {"detenidos": [], "eliminados": [], "errores": []}
    try:
        limite_stop = now() - dt.timedelta(days=config.IDLE_STOP_DAYS)
        limite_del = now() - dt.timedelta(days=config.IDLE_DELETE_DAYS)

        envs = db.query(Env).filter(Env.status.in_(["running", "stopped"])).all()
        for env in envs:
            try:
                ultima = env.last_activity or env.created_at
                if ultima is None:
                    continue
                if env.status == "running" and ultima < limite_stop:
                    ok, out = k8s.scale_env(env.name, 0)
                    if ok:
                        env.status = "stopped"
                        env.stopped_at = now()
                        db.add(ActivityLog(env_id=env.id, username="scheduler",
                                           action="auto-stop"))
                        db.commit()
                        resumen["detenidos"].append(env.name)
                        log(f"[lifecycle] Detenido por inactividad ({config.IDLE_STOP_DAYS}d): {env.name}")
                    else:
                        resumen["errores"].append(f"{env.name}: {out}")
                elif env.status == "stopped" and ultima < limite_del:
                    ok, out = k8s.delete_env_resources(env.name)
                    if ok:
                        db.add(ActivityLog(env_id=env.id, username="scheduler",
                                           action="auto-delete"))
                        db.delete(env)  # hard-delete: el ciclo de vida termina aquí
                        db.commit()
                        resumen["eliminados"].append(env.name)
                        log(f"[lifecycle] Eliminado por inactividad ({config.IDLE_DELETE_DAYS}d): {env.name}")
                    else:
                        resumen["errores"].append(f"{env.name}: {out}")
            except Exception as e:  # noqa: BLE001
                resumen["errores"].append(f"{env.name}: {e}")
                traceback.print_exc()
    finally:
        db.close()
    return resumen


async def loop_scheduler():
    """Loop en background (intervalo configurable; MVP: 60s para poder probar)."""
    import asyncio
    while True:
        try:
            run_lifecycle()
        except Exception as e:  # noqa: BLE001
            print(f"[lifecycle] error: {e}")
        await asyncio.sleep(config.SCHEDULER_INTERVAL_S)

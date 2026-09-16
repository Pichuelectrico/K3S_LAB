"""Seed del K3S Lab: crea tablas + usuario jreinosoc como dev.

Uso:
    K3SLAB_SEED_PASSWORD=tu_password python seed.py
    (sin la variable, usa 'k3slab2026' por defecto — cámbiala para producción)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.auth import hash_password  # noqa: E402
from app.db import User, init_db, now, SessionLocal  # noqa: E402


def main():
    init_db()
    password = os.getenv("K3SLAB_SEED_PASSWORD", "k3slab2026")
    db = SessionLocal()
    try:
        user = db.get(User, "jreinosoc")
        if user:
            user.password_hash = hash_password(password)
            user.role_override = "dev"
            print("Usuario 'jreinosoc' (dev) actualizado ✓")
        else:
            db.add(User(username="jreinosoc", password_hash=hash_password(password),
                        role_override="dev", created_at=now()))
            print("Usuario 'jreinosoc' (dev) creado ✓  password: la que definiste")
        db.commit()
    finally:
        db.close()
    print("Seed completo. Los demás usuarios se crearán con: python seed.py --user <nombre> "
          "(o desde la API cuando exista el endpoint de admin; por ahora: estudiantes = usuarios "
          "sin el grupo 'devs' en wslab01, su rol se deduce de los grupos reales del nodo)")


if __name__ == "__main__":
    main()

"""K3S Lab API — FastAPI. Sirve también el frontend estático (static/) en /."""
import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import config
from .api import router
from .db import init_db

app = FastAPI(title="K3S Lab", version="0.1.0-mvp")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
def startup():
    init_db()
    # Catálogo seed (idempotente)
    from .db import Catalog, SessionLocal
    seed_catalog = [
        ("colab", "Colab runtime", "Notebook con GPU vía Connect to a local runtime (Colab)",
         "us-docker.pkg.dev/colab-images/public/runtime:latest", "2", "8Gi", True,
         "8080", "colab", ""),
        ("vscode", "VS Code Server", "IDE VS Code en el navegador (code-server), con tu home montado",
         "codercom/code-server:latest", "1", "2Gi", False, "8080", "web", ""),
        ("matlab", "MATLAB", "MATLAB con GPU vía noVNC en el navegador (imagen NVIDIA)",
         "nvcr.io/partners/matlab:r2024a", "4", "16Gi", True, "6080", "web", ""),
        ("python", "Python container", "Consola Python (kubectl exec)",
         "python:3.12", "2", "4Gi", False, "", "console", ""),
        ("jupyter", "JupyterLab",
         "Notebooks .ipynb nativos (sin extensiones de VS Code) — el kernel corre en el pod: la ejecución sigue aunque cierres el navegador",
         "quay.io/jupyter/pytorch-notebook:latest", "2", "4Gi", False, "8888", "web", ""),
        ("playground", "Playground · Colab",
         "Notebook Colab COMPARTIDO para todos los estudiantes (sin home) — solo lo crean los devs",
         "us-docker.pkg.dev/colab-images/public/runtime:latest", "2", "8Gi", True,
         "8080", "colab", ""),
    ]
    db = SessionLocal()
    for cid, name, desc, image, cpu, mem, gpu, ports, access, envj in seed_catalog:
        if not db.get(Catalog, cid):
            db.add(Catalog(id=cid, name=name, description=desc, image=image,
                           cpu=cpu, mem=mem, gpu=gpu, ports_json=ports,
                           access=access, env_json=envj))
    db.commit()
    db.close()
    # Scheduler del ciclo de vida en background
    from .scheduler import loop_scheduler
    asyncio.get_event_loop().create_task(loop_scheduler())


# Frontend estático (si existe la carpeta static/)
import os  # noqa: E402

_static = os.path.join(config.BASE_DIR, "static")
if os.path.isdir(_static):
    app.mount("/", StaticFiles(directory=_static, html=True), name="static")

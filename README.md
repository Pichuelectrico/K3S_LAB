# K3S Lab

Plataforma académica tipo *Lightning Studio* sobre un clúster **k3s** de la USFQ: catálogo de entornos por estudiante con **GPU bajo demanda**, homes persistentes de los laboratorios y ciclo de vida automático (7 días inactivo → detenido · 90 días → eliminado).

## ¿Qué hace?

- **Catálogo de entornos**: Colab runtime (connect-to-local-runtime), VS Code web, MATLAB (noVNC), Python console y PostgreSQL — cada estudiante lanza su entorno desde el panel con **1 entorno activo**.
- **GPU como recurso**: cualquier tipo de entorno puede pedir GPU (todas o por índice) vía `runtimeClassName: nvidia` + `NVIDIA_VISIBLE_DEVICES`.
- **Homes persistentes**: los pods montan el `/home/<usuario>` del nodo del laboratorio, así los archivos sobreviven al entorno.
- **PAM real**: el login del panel valida contra las cuentas Linux de los servidores (ssh/paramiko) — una sola contraseña gobierna todo, sin contraseñas semilla.
- **Panel de dev**: monitoreo de los 7 hosts (CPU, GPU modelo/VRAM, RAM, disco, contenedores, kernel) vía Prometheus, y gestión de entornos de estudiantes (detener/eliminar).
- **Ansible**: playbooks para grupos (`students`/`devs`) y alta de usuarios con contraseña unificada en los 3 nodos.

## Arquitectura (estado final planeado)

```mermaid
flowchart LR
    subgraph usuarios["Usuarios (VPN del lab)"]
        E["Estudiantes"]
        D["Devs"]
    end

    subgraph panel["K3S Lab"]
        FE["Frontend SPA<br/>catálogo · recursos · equipos"]
        BE["Backend FastAPI<br/>PAM real · JWT · scheduler 7d/90d"]
    end

    subgraph k3s["Clúster k3s"]
        CP["wslab01<br/>control-plane"]
        A2["wslab02 · agent + GPU"]
        A3["wslab03 · agent + GPU"]
    end

    subgraph catalogo["Entornos por estudiante (1 activo)"]
        C1["Colab runtime<br/>túnel SSH + token"]
        C2["VS Code web<br/>home montado"]
        C3["MATLAB noVNC<br/>GPU"]
        C4["Python console<br/>kubectl exec"]
        C5["PostgreSQL"]
    end

    subgraph ops["Operación"]
        ANS["Ansible<br/>users · groups"]
        PRO["Prometheus :9090<br/>7 hosts · CPU · GPU · RAM · disco"]
    end

    subgraph fase3["Fase 3 (planeado)"]
        A100["Backend en A100<br/>API central"]
        DGX["Catálogo H200/DGX<br/>producción"]
        JH["JupyterHub + FreeIPA<br/>identidad centralizada"]
        DOM["HTTPS + dominio<br/>del lab"]
    end

    E --> FE
    D --> FE
    FE --> BE
    BE -->|"ssh → k3s kubectl"| CP
    CP --> A2
    CP --> A3
    A2 --> C1
    A2 --> C2
    A2 --> C3
    A3 --> C4
    A3 --> C5
    BE --> PRO
    ANS --> CP
    BE -.-> A100
    A100 -.-> DGX
    A100 -.-> JH
    A100 -.-> DOM
```

## Stack

| Capa | Tecnología |
|---|---|
| Clúster | k3s (control-plane + 2 agents GPU: A4000 ×2, RTX A2000) |
| Backend | Python · FastAPI · SQLite · paramiko (PAM) · APScheduler |
| Frontend | SPA estática servida por FastAPI |
| Manifiestos | Generados dinámicamente por tipo/nodo/GPU/mount |
| Operación | Ansible · Prometheus (node/dcgm/cadvisor) |
| Entornos | Colab runtime · code-server · MATLAB r2024a · python-slim · postgres |

## Estado

**MVP validado**: ciclo de vida de entornos, flujo Colab completo (túnel + token), VS Code web con uid/gid del owner, MATLAB con GPU en noVNC, PAM real, panel de equipos y gestión admin.

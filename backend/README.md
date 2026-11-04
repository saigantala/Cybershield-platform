# CyberShield Security API & Execution Engine

Enterprise-grade FastAPI backend, Celery task queue, and Redis message broker for the CyberShield Intelligent Network Security Monitoring & Vulnerability Assessment Platform.

---

## 1. Architecture Overview

```
                                  +-----------------------+
                                  |  Next.js 14 Frontend  |
                                  | (localhost:3000)      |
                                  +-----------+-----------+
                                              | Authorization: Bearer <Supabase JWT>
                                              v
+-----------------------------------------------------------------------------------------+
| FastAPI Security Gateway (localhost:8000/api/v1)                                       |
| - Cryptographic JWT Verification (HMAC-SHA256 / RS256 JWKS)                              |
| - Pydantic Request Validation (IPv4, MAC, UUID, Schemas)                                 |
| - Role-Based Access Control (RBAC: owner, admin, analyst vs viewer)                     |
| - PostgREST Proxy maintaining Supabase Row Level Security (RLS)                         |
+---------------------------+---------------------------------+---------------------------+
                            |                                 |
                            v                                 v
            +---------------+---------------+ +---------------+---------------+
            |  Redis Broker (localhost:6379)| | Supabase PostgreSQL Database  |
            +---------------+---------------+ | - public.assets               |
                            |                 | - public.scans                |
                            v                 | - public.organization_members |
            +---------------+---------------+ | - public.audit_logs (append)  |
            | Celery Background Workers     | +-------------------------------+
            | - process_demo_scan           |
            | - health_check_task           |
            | - cleanup_demo_task           |
            +-------------------------------+
```

---

## 2. Local Environment Setup

### Prerequisites
- Python 3.11+
- Virtualenv
- (Optional for background queues) Redis 7+ or Docker

### Installation
```bash
# 1. Navigate to backend directory
cd backend

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

## 3. Environment Configuration

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

| Key | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | Deployment environment name |
| `DEBUG` | `True` | Debug mode |
| `PROJECT_NAME` | `CyberShield Security API` | API service label |
| `API_V1_STR` | `/api/v1` | Global API prefix |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Whitelist for CORS |
| `SUPABASE_URL` | `https://your-project.supabase.co` | Supabase project URL |
| `SUPABASE_ANON_KEY` | `your-anon-key` | Public client anon key |
| `SUPABASE_JWT_SECRET`| `""` | Optional JWT secret for HS256 (or uses JWKS) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URI |
| `CELERY_BROKER_URL`| `redis://localhost:6379/0` | Celery message broker |
| `CELERY_RESULT_BACKEND`| `redis://localhost:6379/1` | Celery task result store |

---

## 4. Running the Backend Locally

### Option A: Running FastAPI Server
```bash
# From backend directory with venv active
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Documentation will be available at:
- Swagger UI: `http://localhost:8000/api/v1/docs`
- ReDoc: `http://localhost:8000/api/v1/redoc`
- Health Probe: `http://localhost:8000/api/v1/health`

### Option B: Running Celery Worker
```bash
# From backend directory with venv active
celery -A app.workers.celery_app worker -l info -c 4
```

---

## 5. Running with Docker Compose

To launch the entire isolated stack (FastAPI Gateway + Redis + Celery Worker):

```bash
# From repository root
docker compose up -d --build
```

### Checking Services & Logs
```bash
# View running containers
docker compose ps

# View real-time logs
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f redis

# Teardown
docker compose down -v
```

Security highlights of the container setup:
- Non-root user `appuser` (UID 1001) in application containers.
- Redis has no exposed host port (internal `cybershield-net` bridge network only).
- No Docker socket or host networking mounted.
- Health checks configured on all services.

---

## 6. API Endpoint Documentation

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | No | System health and Redis probe |
| `GET` | `/api/v1/auth/me` | Bearer Token | Authenticated operator profile & org roles |
| `GET` | `/api/v1/assets` | Bearer Token | List organization assets (search, filter, sort, paginate) |
| `GET` | `/api/v1/assets/{id}` | Bearer Token | Retrieve single asset by UUID |
| `POST`| `/api/v1/assets` | Bearer Token (Non-viewer) | Register new infrastructure endpoint |
| `PATCH`| `/api/v1/assets/{id}` | Bearer Token (Non-viewer) | Update asset telemetry and risk profile |
| `DELETE`| `/api/v1/assets/{id}`| Bearer Token (Non-viewer) | Decommission endpoint permanently |
| `GET` | `/api/v1/scans` | Bearer Token | List organization scan jobs |
| `POST`| `/api/v1/scans` | Bearer Token (Non-viewer) | Queue demonstration scan job in Celery |
| `GET` | `/api/v1/scans/{id}` | Bearer Token | Inspect scan execution state and findings summary |
| `POST`| `/api/v1/scans/{id}/cancel` | Bearer Token (Non-viewer) | Abort or cancel active scan |

---

## 7. Automated Testing

Run the automated pytest test suite:
```bash
pytest tests/ -v
```

The test suite covers:
1. `test_health.py`: Liveness probe and Redis heartbeat.
2. `test_auth.py`: Missing token (401), invalid token (401), expired token (401), and claims extraction.
3. `test_assets.py`: Validation rules (IPv4 bounds, MAC formats), RBAC permissions (viewer 403), listing, update, and decommissioning.
4. `test_scans.py`: Queuing demo scans, retrieving status, and cancelling jobs.
5. `test_tasks.py`: Celery tasks (`health_check_task`, `process_demo_scan`, `cleanup_demo_task`) and Scanner safety scope boundary checks.

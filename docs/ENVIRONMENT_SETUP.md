# CyberShield – Environment Variables & Configuration Guide

## 1. Environment Variable Architecture

CyberShield utilizes environment variables validated strictly at startup using Pydantic v2 Settings (`app/core/config.py`).

| Variable Name | Required | Default Value | Description |
|---|---|---|---|
| `PROJECT_NAME` | No | `CyberShield Security API` | Name of the platform instance. |
| `VERSION` | No | `1.0.0` | API version. |
| `ENVIRONMENT` | Yes | `development` | `development`, `staging`, `production`. |
| `DEBUG` | No | `False` | Debug mode (disables HSTS in dev). |
| `SECRET_KEY` | Yes | *Generated* | Cryptographic signing secret for step-up tokens. |
| `SUPABASE_URL` | Staging/Prod | `https://your-project.supabase.co` | Remote Supabase project URL. |
| `SUPABASE_SERVICE_ROLE_KEY`| Staging/Prod | `""` | Privileged Supabase service role key. |
| `SUPABASE_JWT_SECRET` | Staging/Prod | `""` | HMAC-SHA256 secret for verifying user tokens. |
| `REDIS_URL` | Yes | `redis://localhost:6379/0` | Redis task queue and sliding-window rate limiter. |
| `CELERY_BROKER_URL` | Yes | `redis://localhost:6379/0` | Broker URL for Celery workers. |
| `CYBERSHIELD_AI_PROVIDER` | No | `mock` | `mock`, `gemini`, `openai`. |
| `CYBERSHIELD_AI_API_KEY` | No | `""` | Google Gemini API Key for grounded LLM assistant. |
| `ALIENVAULT_OTX_API_KEY` | No | `""` | API key for live AlienVault OTX pulses. |
| `SECURITY_HEADERS_ENABLED`| No | `True` | Injects CSP, nosniff, and DENY headers. |
| `RATE_LIMIT_ENABLED` | No | `True` | Sliding-window per-IP rate limiter. |
| `CORS_ORIGINS` | No | `http://localhost:3000` | Comma-separated allowed frontend origins. |
| `TRUSTED_PROXIES` | No | `127.0.0.1,10.0.0.0/8` | IP addresses of reverse proxies/WAFs. |

---

## 2. Production Hardening Rules

1. `ENVIRONMENT` must be set to `production`.
2. `DEBUG` must be `False`.
3. `SECRET_KEY` and `SUPABASE_JWT_SECRET` must have at least 32 cryptographically random characters.
4. `CORS_ORIGINS` must not contain wildcards (`*`).
5. `SUPABASE_SERVICE_ROLE_KEY` must never be shared with client-side code or committed to Git.

# CyberShield – Production Cloud Deployment Guide

## 1. Production Architecture Overview

- **Frontend**: Hosted on Vercel with automatic edge routing and global CDN caching.
- **Backend**: Dockerized FastAPI service deployed on AWS ECS / GCP Cloud Run / Kubernetes.
- **Background Workers**: Celery workers managed via container orchestration.
- **Cache & Broker**: Managed Redis 7 (AWS ElastiCache / Redis Cloud).
- **Database & Auth**: Supabase PostgreSQL with automated WAL archiving and Row Level Security.
- **Edge Security**: Cloudflare WAF, DDoS mitigation, and TLS 1.3 termination.

---

## 2. Step-by-Step Deployment

### Step 1: Database Migration (Supabase)
Apply migrations in numerical sequence:
```bash
# Link local project to Supabase CLI
supabase link --project-ref your-project-id
supabase db push
```

### Step 2: Backend Container Build & Run
```bash
# Build production Docker image
docker build -t cybershield-backend:v1.0.0 backend/

# Run with production compose profile
docker compose -f docker-compose.prod.yml up -d
```

### Step 3: Frontend Deployment (Vercel)
```bash
cd apps/web
vercel --prod
```
Set environment variables:
- `NEXT_PUBLIC_API_URL=https://api.cybershield.your-domain.com/api/v1`
- `NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key`

---

## 3. Rollback Procedure
If a deployment fails health checks:
1. Revert container image tag to previous stable digest (`docker compose -f docker-compose.prod.yml up -d`).
2. Rollback database migrations if schema changes are backward-incompatible.
3. Purge Cloudflare CDN edge cache.

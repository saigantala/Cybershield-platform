# AGENTS.md – CyberShield AI Agent & Developer Reference Guide

## 1. Architecture Overview
CyberShield is a full-stack cybersecurity operations platform:
- **Frontend**: Next.js 14 App Router, TypeScript 5.6, Tailwind CSS, shadcn/ui.
- **Backend**: FastAPI REST Gateway (34 routers in `app/api/routes/`), Celery workers, Redis 7.
- **Database**: Supabase PostgreSQL with 17 sequential migrations and Row Level Security (RLS).
- **Design System**: Premium SOC Dark Glassmorphism (`#080D18`, `#0B1220`, `#111C2D`, `#162338`).

---

## 2. Command Reference

### Running Backend Tests
```bash
cd backend
.venv\Scripts\pytest -q
```
*Current test count: 215 passed, 0 failures.*

### Running Frontend Typecheck
```bash
cd apps/web
..\..\node_modules\.bin\tsc --noEmit
```
*Current status: 0 compilation errors.*

---

## 3. Key Conventions & Rules

1. **Multi-Tenancy**: Every route must verify organization membership and pass `org_id` to database queries.
2. **Never Break Access Control**: Respect role boundaries (`owner`, `admin`, `analyst`, `viewer`).
3. **No Arbitrary Internet Scanning**: Only RFC 1918 private subnets and approved local scopes (`localhost:8000`, `localhost:3000`) are permissible for automated tests.
4. **No Destructive Database Changes**: Migrations in `supabase/migrations/` must be additive and versioned.
5. **Sensitive Data Redaction**: Secrets, tokens, and credentials must never be written to stdout or application logs.

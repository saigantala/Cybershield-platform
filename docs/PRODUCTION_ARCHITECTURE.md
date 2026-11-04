# CyberShield Enterprise Production Architecture

---

## 1. Executive Summary & Design Principles
CyberShield is architected as a high-security, multi-tenant cybersecurity operations and threat intelligence platform designed for 24/7 Security Operations Centers (SOC). 

### Core Architectural Principles
1. **Zero-Trust Network Model**: All internal and external network calls enforce mutual authentication, parameter sanitization, and cryptographic payload verification.
2. **Strict Multi-Tenant Isolation**: Enforced at the PostgreSQL storage engine layer using Supabase Row Level Security (RLS) bound to authenticated tenant organization IDs.
3. **Stateless API Gateway**: The Python FastAPI central gateway is horizontally scalable, state-independent, and delegates background scans to asynchronous Celery workers.
4. **Least-Privilege Containerization**: Containers execute with non-root system users (`UID/GID 1001`), dropped Linux capabilities, read-only root filesystems where practical, and resource quotas.
5. **Defense-in-Depth DevSecOps**: Continuous static analysis (CodeQL), secret detection (Gitleaks), container vulnerability scanning (Trivy), and automated dependency management (Dependabot).

---

## 2. Component Dependency Architecture

```mermaid
graph TD
    Client["Analyst Web Browser / Mobile App"] -->|"HTTPS / TLS 1.3"| Cloudflare["Cloudflare Edge WAF & DDoS Shield"]
    Cloudflare -->|"HSTS / Strict CSP"| Vercel["Vercel Edge Network (Next.js 14 SSR)"]
    Cloudflare -->|"API Reverse Proxy"| ALB["Application Load Balancer"]
    ALB -->|"Rate-Limited REST"| FastAPIGateway["FastAPI Gateway (Multi-Worker Cluster)"]

    subgraph InternalVPC["Isolated Cloud VPC / Secure Container Network"]
        FastAPIGateway -->|"Connection Pool"| SupabaseDB[("Supabase PostgreSQL (RLS Enforced)")]
        FastAPIGateway -->|"Session & Rate State"| RedisCluster[("Redis In-Memory Broker (Password Auth)")]
        FastAPIGateway -->|"Enqueues Scan Tasks"| RedisCluster
        RedisCluster -->|"Pulls Task Queue"| CeleryWorkers["Celery Background Worker Pool"]
        CeleryWorkers -->|"Saves Results via RLS"| SupabaseDB
        CeleryWorkers -->|"Authorized Scans"| ApprovedScopes["Approved Network RFC 1918 Scopes"]
    end

    subgraph ExternalEcosystem["External Threat & SIEM Ecosystem"]
        FastAPIGateway -->|"SSRF Guarded Webhooks"| WebhookReceivers["Webhook Subscribers (HMAC-SHA256)"]
        FastAPIGateway -->|"HEC Event Shipper"| SplunkSIEM[("Splunk Enterprise SIEM")]
        FastAPIGateway -->|"Log Analytics API"| SentinelCloud[("Microsoft Sentinel")]
        CeleryWorkers -->|"Cached Ingestion"| CISAFastFeed[("CISA KEV & NVD 2.0 Feeds")]
    end
```

---

## 3. Service Communication Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as SOC Security Analyst
    participant Frontend as Next.js Web App (Vercel)
    participant Gateway as FastAPI Security Gateway
    participant RateLimiter as Sliding-Window Limiter
    participant Supabase as Supabase Auth & PostgreSQL
    participant Redis as Redis / Celery Pool

    Analyst->>Frontend: Authenticate via SSO / Password
    Frontend->>Supabase: Exchange credentials for JWT
    Supabase-->>Frontend: Issue signed JWT (HS256 / RS256)

    Analyst->>Frontend: Perform SOC Action (e.g. Launch Vulnerability Scan)
    Frontend->>Gateway: POST /api/v1/scans (Bearer JWT, X-Request-ID)
    Gateway->>RateLimiter: Check client IP quota (120 req/min)
    RateLimiter-->>Gateway: Quota OK (X-RateLimit-Remaining: 119)
    Gateway->>Gateway: Verify JWT signature & extract organization_id
    Gateway->>Supabase: Validate RFC 1918 Scope & Tenant Membership (RLS)
    Supabase-->>Gateway: Scope approved & authorized

    Gateway->>Redis: Enqueue Scan Job to Celery Broker
    Redis-->>Gateway: Task ID: task_88921a
    Gateway-->>Frontend: 202 Accepted (Correlation ID: req_9812f)
    Frontend-->>Analyst: Real-time scan timeline updated
```

---

## 4. Environment Profiles & Configuration Matrix

| Variable / Setting | Development | Staging | Production |
| :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | `staging` | `production` |
| `DEBUG` | `True` | `False` | `False` (Enforced on startup) |
| `SECRET_KEY` | Dev placeholder allowed | Unique 256-bit key | Min 32 chars high-entropy secret |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Staging domains | Exact production FQDNs only |
| `SUPABASE_URL` | Local / Dev project | Staging project | Production cluster URL |
| `RATE_LIMIT_ENABLED` | `True` (whitelisted tests) | `True` (120 req/min) | `True` (120 req/min, 15 auth/min) |
| `SECURITY_HEADERS` | Enabled | Enabled | Enabled with strict HSTS preload |
| `CELERY_TASK_EAGER` | `True` (Unit tests) | `False` | `False` (Distributed worker cluster) |

---

## 5. Cloud Deployment Blueprint

### A. Frontend Layer (Next.js on Vercel)
- **Deployment Platform**: Vercel Enterprise or AWS ECS.
- **Routing & SSR**: Next.js App Router with server-side rendering for initial load performance.
- **Static Asset Optimization**: Immutable hashed assets distributed via edge CDN with 1-year cache headers.
- **Content Security Policy**: Script, style, font, and frame restrictions injected on every HTTP response.

### B. Backend Layer (Dockerized FastAPI on AWS ECS / GCP Cloud Run / Linux VM)
- **Base Image**: `python:3.11-slim` running as unprivileged user `appuser` (UID/GID 1001).
- **Process Manager**: `uvicorn` with asynchronous worker threads behind an Application Load Balancer.
- **Auto-Scaling Criteria**: CPU utilization > 70% or average latency > 250ms.
- **Zero-Downtime Rolling Updates**: Blue/Green deployment with `/api/v1/health` and `/api/v1/system-health/ping` probes.

### C. Data & Broker Layer (Supabase & Redis)
- **Database**: Managed PostgreSQL on Supabase with dedicated compute, automated daily snapshots, and WAL point-in-time recovery.
- **Message Broker**: Redis 7.2 with password authentication, in-memory LRU eviction, and isolated internal container networking (`cybershield-internal-net`).

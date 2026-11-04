# CyberShield – Installation & Local Setup Guide

## 1. Prerequisites
- **Node.js**: v20.x or v22.x LTS
- **Python**: 3.12 or 3.13
- **Docker & Docker Compose**: v2.20+
- **Git**

---

## 2. Quickstart with Docker Compose

To spin up the complete CyberShield stack (FastAPI Backend, Redis 7, Celery Worker, and Next.js Web Frontend):

```bash
# Clone the repository
git clone https://github.com/your-org/CyberShield.git
cd CyberShield

# Copy environment file
cp .env.example .env

# Launch services
docker compose up -d --build
```

Access services:
- **Frontend Dashboard**: `http://localhost:3000`
- **FastAPI REST API Docs**: `http://localhost:8000/api/v1/docs`
- **Redis Broker**: `localhost:6379`

---

## 3. Manual Local Development Setup

### Backend Setup (FastAPI)
```bash
cd backend
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# Run backend test suite (215 tests)
pytest -q

# Start FastAPI development server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup (Next.js)
```bash
# From workspace root
npm install

# Run TypeScript type check
cd apps/web
npx tsc --noEmit

# Start Next.js development server
npm run dev
```
Open `http://localhost:3000` in your browser.

import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
import jwt

agent_dir = Path(__file__).resolve().parent
backend_dir = agent_dir.parent / "backend"
sys.path.insert(0, str(agent_dir.parent))
sys.path.insert(0, str(backend_dir))

from app.core.config import settings

# Create signed JWT for admin
key = settings.SUPABASE_JWT_SECRET or settings.SECRET_KEY
payload = {
    "sub": "00000000-0000-0000-0000-000000000001",
    "email": "owner@cybershield.internal",
    "role": "authenticated",
    "aud": "authenticated",
    "exp": datetime.utcnow() + timedelta(days=7),
    "user_metadata": {"full_name": "Admin Operator"},
}
admin_token = jwt.encode(payload, key, algorithm="HS256")

# Now enroll agent
from agent.cybershield_agent import enroll_agent, send_telemetry, DEFAULT_CONFIG_PATH

print("Enrolling agent with CyberShield backend...")
cfg = enroll_agent(
    server_url="http://localhost:8000/api/v1",
    auth_token=admin_token,
    config_path=DEFAULT_CONFIG_PATH,
)

if cfg:
    print("\nEnrollment successful! Sending first live telemetry payload...")
    success = send_telemetry(
        server_url=cfg["server_url"],
        agent_id=cfg["agent_id"],
        api_key=cfg["api_key"],
    )
    print("Telemetry dispatch result:", "SUCCESS" if success else "FAILED")
else:
    print("Enrollment failed.")

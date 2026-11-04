import sys
from pathlib import Path
from datetime import datetime, timedelta

# Ensure backend root is on Python sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import jwt
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.workers.celery_app import celery_app

# Enable eager in-memory execution for testing without live Redis broker
celery_app.conf.update(
    task_always_eager=True,
    task_eager_propagates=True,
)


@pytest.fixture
def client():
    return TestClient(app)


def create_test_token(user_id: str, email: str, expires_in_minutes: int = 60) -> str:
    """Generates a cryptographically signed test JWT for unit testing."""
    key = settings.SUPABASE_JWT_SECRET or settings.SECRET_KEY
    payload = {
        "sub": user_id,
        "email": email,
        "role": "authenticated",
        "aud": "authenticated",
        "exp": datetime.utcnow() + timedelta(minutes=expires_in_minutes),
        "user_metadata": {"full_name": email.split("@")[0].capitalize()},
    }
    return jwt.encode(payload, key, algorithm="HS256")


@pytest.fixture
def owner_token():
    return create_test_token(
        user_id="00000000-0000-0000-0000-000000000001",
        email="owner@cybershield.internal",
    )


@pytest.fixture
def viewer_token():
    return create_test_token(
        user_id="00000000-0000-0000-0000-000000000002",
        email="viewer@cybershield.internal",
    )


@pytest.fixture
def unauthorized_user_token():
    return create_test_token(
        user_id="00000000-0000-0000-0000-000000000099",
        email="intruder@external.io",
    )


@pytest.fixture
def expired_token():
    return create_test_token(
        user_id="00000000-0000-0000-0000-000000000001",
        email="owner@cybershield.internal",
        expires_in_minutes=-10,
    )

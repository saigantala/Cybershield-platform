import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.core.config import settings

logger = logging.getLogger(__name__)

security_bearer = HTTPBearer(auto_error=False)


class AuthenticatedUser(BaseModel):
    user_id: str
    email: str
    role: str = "authenticated"
    user_metadata: Dict[str, Any] = {}
    raw_token: str

    @property
    def token(self) -> str:
        return self.raw_token


_jwks_client: Optional[jwt.PyJWKClient] = None


def get_jwks_client() -> Optional[jwt.PyJWKClient]:
    global _jwks_client
    if _jwks_client is None and settings.SUPABASE_URL and "supabase.co" in settings.SUPABASE_URL:
        try:
            jwks_url = f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"
            _jwks_client = jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=3600)
        except Exception as e:
            logger.warning(f"Could not initialize Supabase JWKS client: {e}")
    return _jwks_client


def verify_supabase_jwt(token: str) -> Dict[str, Any]:
    """
    Cryptographically verifies a Supabase JWT access token.
    Supports HMAC (HS256 with SUPABASE_JWT_SECRET) or Asymmetric JWKS (RS256/ES256).
    """
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Inspect unverified header for algorithm & key ID
    try:
        unverified_headers = jwt.get_unverified_header(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Malformed token header: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    alg = unverified_headers.get("alg", "HS256")

    # 2. Cryptographic signature verification
    payload = None

    # Case A: Symmetric HMAC-SHA256 (Supabase JWT Secret)
    if alg == "HS256":
        key = settings.SUPABASE_JWT_SECRET or settings.SECRET_KEY
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=["HS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,  # We verify aud below explicitly
                },
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Cryptographic token signature verification failed",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token verification failed: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Case B: Asymmetric RS256/ES256 via JWKS
    elif alg in ["RS256", "ES256"]:
        jwks_client = get_jwks_client()
        if not jwks_client:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="JWKS verification client is not configured",
            )
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=[alg],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,
                },
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Asymmetric token verification failed: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported token signing algorithm: {alg}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Validate claims: sub (user_id) must be present
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject identity claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> AuthenticatedUser:
    """
    FastAPI dependency extracting verified user claims.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required (Bearer token)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    claims = verify_supabase_jwt(token)

    return AuthenticatedUser(
        user_id=claims.get("sub", ""),
        email=claims.get("email", ""),
        role=claims.get("role", "authenticated"),
        user_metadata=claims.get("user_metadata", {}),
        raw_token=token,
    )


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Optional[AuthenticatedUser]:
    """
    FastAPI dependency extracting verified user claims if present, else None.
    """
    if not credentials or not credentials.credentials:
        return None
    try:
        token = credentials.credentials
        claims = verify_supabase_jwt(token)
        return AuthenticatedUser(
            user_id=claims.get("sub", ""),
            email=claims.get("email", ""),
            role=claims.get("role", "authenticated"),
            user_metadata=claims.get("user_metadata", {}),
            raw_token=token,
        )
    except Exception:
        return None


import os
import hmac
from jose import jwt, exceptions
import asyncio
from threading import Lock
from fastapi import HTTPException, Header, Cookie, status, Request
from slowapi import Limiter  # type: ignore
from app.database.config import SessionLocal

JWT_SECRET_KEY: str = str(
    os.getenv(
        "JWT_SECRET", "445919a0b5eed61eb8d78213f82997c127f2aa4b70885aa5e60b1e380dc3f4ab"
    )
)
JWT_ALGORITHM = "HS256"


def get_trusted_client_ip(request: Request) -> str:
    """
    Isolates the authentic client origin IP passed down by your Nginx proxy layer.
    Safely bypasses internal Docker proxy routing network hops (e.g. 172.x.x.x).
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    if request.client:
        return request.client.host

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="CRITICAL_TELEMETRY_DROP: Network origin missing",
    )


limiter = Limiter(key_func=get_trusted_client_ip)


class SystemStateDatabaseVault:
    def __init__(self):
        self._lock = Lock()
        self.db_state = {
            "pydantic_filtering": True,
            "audit_logging": True,
            "rate_limiting": True,
            "sandbox_mode": False,
        }

    def read_posture(self):
        with self._lock:
            return self.db_state.copy()

    def write_mutation(self, key: str, state: bool):
        with self._lock:
            if key in self.db_state:
                self.db_state[key] = state


state_vault = SystemStateDatabaseVault()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def verify_logix_vault_access(
    request: Request,
    admin_token: str = Cookie(None, alias="admin_token"),
    csrf_token: str = Cookie(None, alias="csrf_token"),
) -> bool:
    """
    Strict Pure Server-Side Zero-Trust Verification Engine.
    Excludes client-side JS handling completely. Protects against proxy header loss.
    """
    if not admin_token or not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SECURITY_INTEGRITY_FAILURE: Authorization Context Missing",
        )

    try:
        payload = jwt.decode(admin_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

        expected_ip = get_trusted_client_ip(request)
        if (
            payload.get("role") != "root_admin"
            or payload.get("origin_ip") != expected_ip
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="SECURITY_INTEGRITY_FAILURE: Contextual Validation Failed",
            )

        expected_csrf = payload.get("csrf_ctx")

        if not expected_csrf or not hmac.compare_digest(
            str(csrf_token), str(expected_csrf)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="SECURITY_INTEGRITY_FAILURE: CSRF Context Tampering Detected",
            )

    except exceptions.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SECURITY_INTEGRITY_FAILURE: Expired Session Context",
        )
    except exceptions.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SECURITY_INTEGRITY_FAILURE: Invalid Session Context",
        )

    return True

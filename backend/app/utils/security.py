import html
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from dotenv import load_dotenv
from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session
from app.models.audit import AuditLog
from jose import jwt, exceptions

load_dotenv()

SECRET_KEY: str = os.getenv(
    "JWT_SECRET_KEY", "ZERO_TRUST_SIEM_FALLBACK_HARD_SECRET_KEY_32_BYTES_MIN"
)
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("CRITICAL_SECURITY_FAILURE: SECRET_KEY_INSECURE")


def create_access_token(data: dict):
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update(
        {
            "exp": expire,
            "iat": now,
            "nbf": now,
            "jti": secrets.token_urlsafe(16),
        }
    )
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def verify_admin(request: Request):
    token = request.cookies.get("admin_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MISSING_AUTHENTICATION_COOKIE",
        )
    try:
        payload: Dict[str, Any] = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": True, "verify_iat": True, "verify_nbf": True},
        )

        username: Optional[str] = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="INVALID_SESSION_PAYLOAD",
            )

        EXPECTED_ADMIN = os.getenv("ADMIN_USERNAME", "").strip()
        if not EXPECTED_ADMIN or not hmac.compare_digest(username, EXPECTED_ADMIN):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="IDENTITY_MISMATCH_ALERT",
            )
        return username

    except exceptions.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="SESSION_EXPIRED"
        )
    except exceptions.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="MALFORMED_TOKEN"
        )


def log_event(
    db: Session,
    action: str,
    identity: str,
    endpoint: str,
    payload: Optional[str] = None,
    ip: str = "0.0.0.0",
    status_str: str = "SUCCESS",
    target_id: Optional[int] = None,
):
    safe_action = html.escape(str(action))[:50]
    safe_identity = html.escape(str(identity or "ANONYMOUS"))[:50]
    safe_endpoint = html.escape(str(endpoint))[:100]
    safe_payload = html.escape(str(payload))[:1000] if payload else None
    safe_ip = html.escape(str(ip))[:45]

    new_log = AuditLog(
        action=safe_action,
        identity=safe_identity,
        endpoint=safe_endpoint,
        payload=safe_payload,
        ip_address=safe_ip,
        status=status_str[:20],
        target_id=target_id,
    )
    try:
        db.add(new_log)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"CRITICAL: AUDIT_LOG_WRITE_FAILURE - {str(e)}")


def generate_csrf_token():
    return secrets.token_urlsafe(32)
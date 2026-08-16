import hmac
import time
import os
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.dependencies import get_db
from app.models.audit import AuditLog
import logging
from app.utils.logging import logger
from app.dependencies import limiter

from app.utils.signatures import SECURITY_SIGNATURES, analyze_payload_signature
from app.utils.security import create_access_token, generate_csrf_token

ALERT_LEVEL_NUM = 35
logging.addLevelName(ALERT_LEVEL_NUM, "ALERT")

def log_alert(logger_instance, message, *args, **kws):
    if logger_instance.isEnabledFor(ALERT_LEVEL_NUM):
        logger_instance._log(ALERT_LEVEL_NUM, message, args, **kws)

uvicorn_logger = logging.getLogger("uvicorn")


def _sanitize_log(value: str) -> str:
    return value.replace("\n", "").replace("\r", "").replace("\t", "")

router = APIRouter(tags=["Authentication"])

IS_PROD = os.getenv("APP_ENV", "development") == "production"


class LoginPayload(BaseModel):
    username: str
    password: str


def log_security_event(
    db: Session,
    identity: str,
    endpoint: str,
    payload: str,
    action: str,
    ip: str,
    status: str = "RESOLVED",
):
    new_log = AuditLog(
        identity=identity,
        endpoint=endpoint,
        payload=payload,
        action=action,
        ip_address=ip,
        status=status,
    )
    db.add(new_log)
    db.commit()


@router.get("/init-session")
def init_session(request: Request, response: Response):
    token = generate_csrf_token()
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=True,
        secure=IS_PROD,
        samesite="strict" if IS_PROD else "lax",
        path="/",
    )
    return {"session": "initialized"}


@router.post("/login")
@limiter.limit("3/minute")
async def login(
    request: Request,
    payload: LoginPayload,
    db: Session = Depends(get_db),
):
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client is not None else "127.0.0.1"

    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    trusted_boundary = "http://127.0.0.1:8080"

    if origin:
        if origin != trusted_boundary:
            uvicorn_logger.critical(
                f"🚨 SECURITY_ALERT: Auth Origin Mismatch! Origin={_sanitize_log(origin)} from IP={_sanitize_log(client_ip)}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="ZERO_TRUST_ENFORCEMENT: Origin Boundary Violation.",
            )
    elif referer:
        if not referer.startswith(trusted_boundary):
            uvicorn_logger.critical(
                f"🚨 SECURITY_ALERT: Auth Referer Mismatch! Referer={_sanitize_log(referer)} from IP={_sanitize_log(client_ip)}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="ZERO_TRUST_ENFORCEMENT: Referer Boundary Violation.",
            )
    else:
        uvicorn_logger.critical(
            f"🚨 SECURITY_ALERT: Auth Request Missing Immutable Tracking Attributes from IP={_sanitize_log(client_ip)}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ZERO_TRUST_ENFORCEMENT: Missing state tracking attributes.",
        )

    username = payload.username
    password = payload.password

    username_clean = username.strip()[:50]
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    time_window = now_utc - timedelta(minutes=30)

    last_success = (
        db.query(AuditLog)
        .filter(
            AuditLog.ip_address == client_ip,
            AuditLog.status == "GRANTED",
            AuditLog.timestamp >= time_window,
        )
        .order_by(AuditLog.timestamp.desc())
        .first()
    )

    anchor_time = last_success.timestamp if last_success else time_window

    history = (
        db.query(AuditLog)
        .filter(
            AuditLog.ip_address == client_ip,
            AuditLog.status.in_(["ALERT", "DENIED"]),
            AuditLog.timestamp >= anchor_time,
        )
        .order_by(AuditLog.timestamp.desc())
    )

    fail_count = history.count()

    if fail_count >= 3:
        last_event = history.first()

        if last_event is not None:
            penalty_factor = fail_count - 3
            total_lockout = 60 * (2**penalty_factor)  # 60s, 120s, 240s, 480s...
            time_passed = (now_utc - last_event.timestamp).total_seconds()

            if time_passed < total_lockout:
                remaining = int(total_lockout - time_passed)

                import time as py_time

                expires_at = int((py_time.time() + remaining) * 1000)

                logger.warning(
                    "Rate limit exceeded: %s - %s", client_ip, request.url.path
                )

                uvicorn_logger.warning(
                    f"🚨 SECURITY ALERT: BRUTEFORCE ATTEMPT - LOCKOUT ACTIVE. IP: {_sanitize_log(client_ip)} has failed {fail_count} times. Remaining: {remaining}s"
                )

                return JSONResponse(
                    status_code=423,
                    content={
                        "detail": "TERMINAL_LOCKED",
                        "cooldown": remaining,
                        "expires_at": expires_at,
                    },
                )

    time.sleep(1.0)

    ADMIN_USER = os.getenv("ADMIN_USERNAME", "").strip().lower()
    ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "").strip()

    if hmac.compare_digest(username_clean, ADMIN_USER) and hmac.compare_digest(
        password.strip(), ADMIN_PASS
    ):
        log_security_event(
            db,
            username_clean,
            "/api/login",
            "AUTH_GRANTED_ADMIN_DASHBOARD_ACCESS",
            "✅ ADMIN LOGIN: DASHBOARD ACCESS",
            client_ip,
            "GRANTED",
        )

        uvicorn_logger.info(
            f"✅ SUCCESSFUL LOGIN: Admin Authentication Granted For User: '{_sanitize_log(username_clean)}' from IP: {_sanitize_log(client_ip)}"
        )

        authenticated_csrf_token = generate_csrf_token()

        token = create_access_token(
            data={
                "sub": username_clean,
                "role": "root_admin",
                "origin_ip": client_ip,
                "csrf_ctx": authenticated_csrf_token,
            }
        )

        response = JSONResponse(
            content={"status": "AUTHENTICATION_GRANTED"}, status_code=200
        )

        response.set_cookie(
            key="admin_token",
            value=token,
            httponly=True,
            path="/",
            secure=IS_PROD,
            samesite="strict" if IS_PROD else "lax",
        )

        response.set_cookie(
            key="csrf_token",
            value=authenticated_csrf_token,
            httponly=True,
            path="/",
            secure=IS_PROD,
            samesite="strict" if IS_PROD else "lax",
        )

        return response

    determined_exploit_action = analyze_payload_signature(username)

    if determined_exploit_action == SECURITY_SIGNATURES["failed_login"]:
        determined_exploit_action = "⚠️ FAILED LOGIN: INVALID CREDENTIALS"
        uvicorn_logger.warning(
            f"⚠️ FAILED LOGIN ATTEMPT: Invalid Credentials Entered For User: '{_sanitize_log(username_clean)}' from IP: {_sanitize_log(client_ip)}"
        )
        log_status = "DENIED"
    else:
        log_alert(
            uvicorn_logger,
            f"🚨 ATTACK DETECTED: Signature Match - '{_sanitize_log(determined_exploit_action)}' | Vector: '{_sanitize_log(username)}' from IP: {_sanitize_log(client_ip)}"
        )
        log_status = "ALERT"

    log_security_event(
        db,
        username_clean,
        "/api/login",
        username,
        determined_exploit_action,
        client_ip,
        log_status,
    )
    return JSONResponse(status_code=401, content={"detail": "Invalid Credentials"})


@router.post("/logout")
def logout():
    response = JSONResponse(content={"status": "SESSION_REVOKED"}, status_code=200)

    past_date = "Thu, 01 Jan 1970 00:00:00 GMT"

    common_params = {
        "value": "",
        "httponly": True,
        "path": "/",
        "secure": IS_PROD,
        "samesite": "strict" if IS_PROD else "lax",
        "expires": past_date,
        "max_age": 0,
    }

    response.set_cookie(key="admin_token", **common_params)
    response.set_cookie(key="access_token", **common_params)
    response.set_cookie(key="csrf_token", **common_params)

    return response
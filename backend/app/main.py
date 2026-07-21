import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded  # type: ignore
from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session  # FIXED: Handled session initialization explicitly

from app.database.config import Base, engine
from app.dependencies import limiter
from app.middleware.security import SecurityHeadersMiddleware
from app.utils.logging import logger
from app.routers import auth, ingest, public
from app.models.audit import AuditLog

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(docs_url=None, redoc_url=None, title="SIEM-TOOL", lifespan=lifespan)
app.state.limiter = limiter
app.add_middleware(SecurityHeadersMiddleware)

allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",")
allowed_origins = [origin.strip() for origin in allowed_origins if origin.strip()]
if not allowed_origins:
    allowed_origins = [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "X-CSRF-Token",
        "X-Requested-With",
        "X-API-Key",
        "Authorization",
        "Accept",
    ],
    expose_headers=["Set-Cookie"],
)


@app.exception_handler(RateLimitExceeded)
async def slowapi_rate_limit_exception_handler(
    request: Request, exc: RateLimitExceeded
):
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "127.0.0.1"

    logger.warning(
        "SIEM_GATEWAY: Rate limit triggered by IP %s on path %s",
        client_ip,
        request.url.path,
    )
    from datetime import datetime, timezone, timedelta

    escalated_seconds = 60
    fail_count = 0

    try:
        with Session(engine) as db_session:
            time_window = datetime.now(timezone.utc) - timedelta(minutes=30)

            last_success = (
                db_session.query(AuditLog)
                .filter(
                    AuditLog.ip_address == client_ip,
                    AuditLog.status == "GRANTED",
                    AuditLog.timestamp >= time_window,
                )
                .order_by(AuditLog.timestamp.desc())
                .first()
            )

            anchor_time = last_success.timestamp if last_success else time_window

            history = db_session.query(AuditLog).filter(
                AuditLog.ip_address == client_ip,
                AuditLog.status.in_(["ALERT", "DENIED"]),
                AuditLog.timestamp >= anchor_time,
            )

            fail_count = history.count()

            if fail_count >= 3:
                penalty_factor = fail_count - 3
                escalated_seconds = 60 * (2**penalty_factor)
            else:
                escalated_seconds = 60

            db_log = AuditLog(
                identity="SYSTEM_RATE_LIMITER",
                endpoint=request.url.path,
                payload=f"IP exceeded allowed threshold rate constraints. Enforced cooldown: {escalated_seconds}s.",
                action=f"🚨 SECURITY ALERT: Bruteforce Attempt - Lockout Active.",
                ip_address=client_ip,
                status="ALERT",
            )
            db_session.add(db_log)
            db_session.commit()

    except Exception as db_err:
        logger.error(
            "SYSTEM EXCEPTION HANDLER FAULT: Failed to parse backoff math or commit audit record: %s",
            str(db_err),
        )
        escalated_seconds = 60

    import logging

    uvicorn_logger = logging.getLogger("uvicorn")
    uvicorn_logger.warning(
        f"🚨 SECURITY ALERT: Bruteforce Attempt - Lockout Active. IP: {client_ip} has failed {fail_count} times. Remaining: {escalated_seconds}s"
    )

    return JSONResponse(
        status_code=429,
        content={
            "detail": "TERMINAL_LOCKED",
            "cooldown": escalated_seconds,
            "expires_at": int(
                (datetime.now(timezone.utc).timestamp() + escalated_seconds) * 1000
            ),
        },
    )


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


from app.routers import (
    manage,
    auth,
    vault,
    ingest,
    public,
    config as system_config_router,
)

app.include_router(manage.router, prefix="/api/manage")
app.include_router(vault.router, prefix="/api/vault")
app.include_router(ingest.router, prefix="/api/v1/ingest")
app.include_router(system_config_router.router, prefix="/api/config")
app.include_router(auth.router, prefix="/api/auth")
app.include_router(public.router, prefix="/api/public")

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frontend_dir = os.path.join(base_dir, "frontend")

if not os.path.exists(frontend_dir):
    os.makedirs(frontend_dir, exist_ok=True)

# app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="static")
app.mount("/frontend", StaticFiles(directory="/siem-tool/frontend"), name="frontend")

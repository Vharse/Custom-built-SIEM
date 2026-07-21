import logging
import html
import hmac
import os
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.dependencies import get_db, limiter  # Injected access limiter framework
from models.audit import AuditLog

router = APIRouter(tags=["SIEM Ingestion Gateway"])
security_logger = logging.getLogger("security_audit")


class ThirdPartyLogPayload(BaseModel):
    source_node: str = Field(..., min_length=3, max_length=50, pattern="^[A-Z0-9_]+$")
    auth_token: str = Field(..., min_length=16, max_length=128)
    event_action: str = Field(..., min_length=2, max_length=100)
    event_status: str = Field(..., min_length=2, max_length=20, pattern="^[A-Za-z_]+$")
    event_payload: str = Field(..., min_length=1, max_length=2000)


@router.post("/event", status_code=status.HTTP_201_CREATED)
@limiter.limit(
    "20/minute"
)
async def ingest_external_syslog(
    request: Request, payload: ThirdPartyLogPayload, db: Session = Depends(get_db)
):
    forwarded_for = request.headers.get("X-Forwarded-For")
    real_client_ip = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else (request.client.host if request.client else "127.0.0.1")
    )

    env_token_key = f"INGEST_TOKEN_{payload.source_node}"
    expected_token = os.getenv(env_token_key, "").strip()

    if not expected_token or not hmac.compare_digest(
        expected_token, payload.auth_token
    ):
        security_logger.critical(
            f"🚨 SECURITY VULNERABILITY ALERT: Unauthorized Ingestion Threat! Node '{payload.source_node}' verification failed from true origin IP: {real_client_ip}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Access Denied"
        )

    try:
        external_audit_node = AuditLog(
            action=f"[{payload.source_node}] {html.escape(payload.event_action)}",
            identity="external_node",
            ip_address=real_client_ip,
            status=html.escape(payload.event_status),
            endpoint="API Ingestion Gateway",
            payload=html.escape(payload.event_payload),
            timestamp=datetime.now(timezone.utc),
        )

        db.add(external_audit_node)
        db.commit()
        return {"status": "COMMITTED", "trace_id": external_audit_node.id}

    except Exception as e:
        db.rollback()
        security_logger.error(
            f"INGESTION_FAULT: Pipeline write transaction processing failed: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Processing Error",
        )

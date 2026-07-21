import logging
from datetime import datetime, timezone
import hmac
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models.audit import AuditLog
from app.models.alerts import Alert

router = APIRouter(tags=["SIEM Ingestion Gateway"])
security_logger = logging.getLogger("security_audit")

VALID_INGESTION_TOKENS = {
    "NODE_LNX_PRODUCTION_01": "gk_ingest_prod_sec_7781x",
    "NODE_WAF_EDGE_APAC": "gk_ingest_edge_apac_9921z",
}


class ThirdPartyLogPayload(BaseModel):
    source_node: str = Field(
        ..., description="The unique identifier of the remote sending machine"
    )
    auth_token: str = Field(..., description="Secret ingestion authorization token")
    event_action: str = Field(
        ..., description="The detected anomaly or log event action name"
    )
    event_status: str = Field(
        ..., description="Severity context: e.g., INFO, ALERT, CRITICAL"
    )
    event_payload: str = Field(
        ..., description="The raw metadata or log string context"
    )
    source_ip: str = Field(
        "0.0.0.0",
        description="The original IP address that triggered the log entry remote-side",
    )


@router.post("/event", status_code=status.HTTP_201_CREATED)
async def ingest_external_syslog(
    request: Request, payload: ThirdPartyLogPayload, db: Session = Depends(get_db)
):
    expected_token = VALID_INGESTION_TOKENS.get(payload.source_node, "")
    if not hmac.compare_digest(expected_token, payload.auth_token):
        security_logger.warning(
            f"SECURITY_ALERT: Unauthorized ingestion attempt from {payload.source_node}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security Violation: Authentication failed.",
        )

    try:
        clean_action = payload.event_action.replace("<", "&lt;").replace(">", "&gt;")
        clean_payload = payload.event_payload.replace("<", "&lt;").replace(">", "&gt;")

        now_timestamp = datetime.now(timezone.utc).replace(tzinfo=None)

        audit_entry = AuditLog(
            action=f"[{payload.source_node}] {clean_action}",
            identity="external_node",
            ip_address=payload.source_ip,
            status=payload.event_status,
            endpoint="API Ingestion Gateway",
            payload=clean_payload,
            timestamp=now_timestamp,
        )
        db.add(audit_entry)

        if payload.event_status.upper() in ["ALERT", "CRITICAL"]:
            threat_alert = Alert(
                ip_address=payload.source_ip,
                action=f"THREAT_DETECTED: {clean_action}",
                payload_context=clean_payload,
                status="NEW",
            )
            db.add(threat_alert)

        db.commit()
        return {
            "status": "COMMITTED",
            "audit_trace_id": audit_entry.id,
            "alert_promoted": payload.event_status.upper() in ["ALERT", "CRITICAL"],
        }

    except Exception as e:
        db.rollback()
        security_logger.error(f"SYSTEM INGESTION PIPELINE FAULT: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Ingestion Processing Error",
        )
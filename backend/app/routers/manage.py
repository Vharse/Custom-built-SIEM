import logging
import os
import subprocess
import urllib.parse
import ipaddress
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel, Field

from app.dependencies import get_db
from app.utils.security import verify_admin
from app.models.audit import AuditLog
from app.models.vault import Inquiry
from app.dependencies import verify_logix_vault_access
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

# router = APIRouter(prefix="/api/manage", tags=["Management"])
router = APIRouter(tags=["Management"])
security_logger = logging.getLogger("security_audit")

MASTER_KEY: str = os.getenv("MANAGEMENT_API_KEY", "")
if not MASTER_KEY:
    raise RuntimeError(
        "CRITICAL SYSTEM CONFIGURATION FAULT: MANAGEMENT_API_KEY IS NOT MOUNTED IN THE ENVIRONMENT"
    )


def verify_api_key(request: Request, x_api_key: str = Header(..., alias="X-API-Key")):
    if x_api_key != MASTER_KEY:
        client_ip = request.client.host if request.client else "127.0.0.1"
        security_logger.warning(
            f"SECURITY_ALERT: Unauthorized API key handshake failed from IP={client_ip}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security Violation: Invalid Credentials",
        )
    return x_api_key


@router.get("/admin-dashboard")
async def get_admin_dashboard(
    db: Session = Depends(get_db), admin_user: str = Depends(verify_admin)
):
    total_inquiries = db.query(Inquiry).count()
    all_messages = db.query(Inquiry).order_by(Inquiry.timestamp.desc()).all()
    security_alerts = (
        db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(15).all()
    )

    return {
        "status": "SECURE_SYSTEM_ACTIVE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "messages": [
            {
                "id": msg.id,
                "name": msg.name,
                "email": msg.email,
                "message": msg.message,
                "is_read": getattr(msg, "is_read", False),
                "created_at": (
                    msg.timestamp.isoformat()
                    if hasattr(msg.timestamp, "isoformat")
                    else msg.timestamp
                ),
            }
            for msg in all_messages
        ],
        "recent_alerts": [
            {
                "id": log.id,
                "alert": log.action,
                "action": log.action,
                "ip_address": log.ip_address,
                "ip": log.ip_address,
                "payload": "",
                "payload_context": "CONTEXT_DEFERRED_LAZY_LOAD",
                "time_stamp": (
                    log.timestamp.isoformat()
                    if hasattr(log.timestamp, "isoformat")
                    else str(log.timestamp).replace(" ", "T")
                ),
                "timestamp": (
                    log.timestamp.isoformat()
                    if hasattr(log.timestamp, "isoformat")
                    else str(log.timestamp).replace(" ", "T")
                ),
                "time": (
                    log.timestamp.isoformat()
                    if hasattr(log.timestamp, "isoformat")
                    else str(log.timestamp).replace(" ", "T")
                ),
                "status": log.status,
                "actions": {
                    "view": "👁",
                    "block": "🚫",
                    "delete": "🗑",
                    "investigate": "📝",
                    "unblockIP": "🔓",
                },
            }
            for log in security_alerts
        ],
    }


@router.get("/inquiries")
async def get_inquiries(
    db: Session = Depends(get_db), admin_user: str = Depends(verify_admin)
):
    return db.query(Inquiry).order_by(Inquiry.timestamp.desc()).all()


@router.post("/delete/{item_id}", status_code=status.HTTP_200_OK)
async def delete_inquiry(
    item_id: int,
    request: Request,
    db: Session = Depends(get_db),
    authorized: bool = Depends(verify_logix_vault_access),
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    target = db.query(Inquiry).filter(Inquiry.id == item_id).first()

    if not target:
        new_log = AuditLog(
            action="UNAUTHORIZED_DELETE_ATTEMPT",
            identity="admin",
            ip_address=client_ip,
            status="ALERT",
            endpoint=f"{request.url.path}",
            payload=f"Attempted delete on non-existent ID: {item_id}",
        )
        db.add(new_log)
        db.commit()
        raise HTTPException(status_code=404, detail="Resource not found")

    try:
        entry_owner = target.email
        db.delete(target)

        audit_entry = AuditLog(
            action="VAULT_RECORD_DELETION",
            identity="admin",
            ip_address=client_ip,
            status="RESOLVED",
            payload=f"Deleted inquiry from: {entry_owner}",
            endpoint=f"{request.url.path}",
        )
        db.add(audit_entry)
        db.commit()

        return {"status": "success", "audit_id": audit_entry.id}

    except Exception as e:
        db.rollback()
        security_logger.error(f"CRITICAL SYSTEM ERROR DURING NODE EXTRACTION: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Vault Error")


@router.post("/purge-log/{timestamp:path}", status_code=status.HTTP_200_OK)
async def purge_log_entry(
    timestamp: str,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: str = Depends(verify_admin),
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    decoded_timestamp = urllib.parse.unquote(timestamp)

    target_log = (
        db.query(AuditLog).filter(AuditLog.timestamp == decoded_timestamp).first()
    )

    if not target_log:
        raise HTTPException(
            status_code=404, detail="Target audit trace signature not found"
        )

    try:
        db.delete(target_log)
        db.commit()

        return {
            "status": "SUCCESS",
            "detail": "Trace profile purged from tracking grid",
        }

    except Exception as e:
        db.rollback()
        security_logger.error(f"CRITICAL PURGE HANDSHAKE FAULT: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Internal Vault Error during trace purge"
        )


def handle_rate_limit_trigger(request_ip: str, database_session):
    """
    Invoked automatically when an IP breaches the maximum threshold window.
    Calculates an exponential backoff penalty window relative to historical infractions.
    """
    try:
        bruteforce_signature = "🚨 [SECURITY ALERT]: SUSPECTED BRUTEFORCE"

        time_boundary = datetime.now(timezone.utc) - timedelta(hours=24)
        incident_count = (
            database_session.query(AuditLog)
            .filter(
                AuditLog.ip_address == request_ip,
                AuditLog.action == bruteforce_signature,
                AuditLog.timestamp >= time_boundary,
            )
            .count()
        )

        escalated_cooldown = 60 * (2**incident_count)

        new_alert = AuditLog(
            ip_address=request_ip,
            endpoint="RATE_LIMIT_JAIL_LAYER",
            action=bruteforce_signature,
            timestamp=datetime.now(timezone.utc),
            status="ALERT",
            payload=f"Rate limit threshold breached across verification endpoints. Extended Cooldown Penalty Applied: {escalated_cooldown} seconds.",
        )
        database_session.add(new_alert)
        database_session.commit()

        security_logger.warning(
            f"SECURITY_ALERT: Bruteforce threshold breached from IP={request_ip} - Dynamic Penalty: {escalated_cooldown}s"
        )

        print(
            f"[KERNEL_LOG] Registered Bruteforce Profile for Entity: {request_ip} | Dynamic Penalty: {escalated_cooldown}s"
        )

    except Exception as e:
        database_session.rollback()
        print(f"[CORE_KERNEL_ERR] Failed to write security event: {str(e)}")


class InquiryReadRequest(BaseModel):
    inquiry_id: int = Field(
        ..., description="Target database ID to be verified and marked read"
    )
    status: str = Field(..., description="Enforced action status, must be 'READ'")


class InquiryDropRequest(BaseModel):
    inquiry_id: int = Field(
        ..., description="Target database ID to be securely dropped"
    )
    action: str = Field(
        ..., description="Enforced validation payload, must be 'DROP_INQUIRY'"
    )


@router.post("/inquiry-read", status_code=status.HTTP_200_OK)
async def mark_inquiry_as_read(
    payload: InquiryReadRequest,
    request: Request,
    db: Session = Depends(get_db),
    authorized: bool = Depends(verify_logix_vault_access),
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    target = db.query(Inquiry).filter(Inquiry.id == payload.inquiry_id).first()

    if not target:
        unauthorized_log = AuditLog(
            action="SUSPICIOUS_STATE_MUTATION_ATTEMPT",
            identity="admin",
            ip_address=client_ip,
            status="ALERT",
            endpoint=f"{request.url.path}",
            payload=f"Attempted state change on non-existent inquiry ID: {payload.inquiry_id}",
        )
        db.add(unauthorized_log)
        db.commit()
        raise HTTPException(status_code=404, detail="Resource signature not found")

    try:
        target.is_read = True  # type: ignore
        if hasattr(target, "status"):
            target.status = "processed"  # type: ignore

        db.commit()
        return {
            "success": True,
            "message": "State verified and committed.",
            "status": "READ",
        }

    except Exception as e:
        db.rollback()
        security_logger.error(f"SYSTEM WRITE FAULT DURING INQUIRY MUTATION: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Vault State Sync Error")


@router.post("/inquiry-delete", status_code=status.HTTP_200_OK)
async def drop_inquiry_node(
    payload: InquiryDropRequest,
    request: Request,
    db: Session = Depends(get_db),
    authorized: bool = Depends(verify_logix_vault_access),
):
    client_ip = request.client.host if request.client else "127.0.0.1"

    if payload.action != "DROP_INQUIRY":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security Fault: Invalid verification action signature string.",
        )

    target = db.query(Inquiry).filter(Inquiry.id == payload.inquiry_id).first()

    if not target:
        unauthorized_log = AuditLog(
            action="SUSPICIOUS_PURGE_ATTEMPT",
            identity="admin",
            ip_address=client_ip,
            status="ALERT",
            endpoint=f"{request.url.path}",
            payload=f"Attempted destruction action on non-existent inquiry ID: {payload.inquiry_id}",
        )
        db.add(unauthorized_log)
        db.commit()
        raise HTTPException(status_code=404, detail="Resource signature not found")

    try:
        inquiry_owner = target.email
        db.delete(target)

        audit_entry = AuditLog(
            action="INQUIRY_VAULT_NODE_PURGE",
            identity="admin",
            ip_address=client_ip,
            status="RESOLVED",
            payload=f"Permanently purged inquiry node belonging to: {inquiry_owner}",
            endpoint=f"{request.url.path}",
        )
        db.add(audit_entry)
        db.commit()

        return {"success": True, "message": "Node suppressed successfully."}

    except Exception as e:
        db.rollback()
        security_logger.error(
            f"SYSTEM WRITE FAULT DURING INQUIRY SUPPRESSION: {str(e)}"
        )
        raise HTTPException(status_code=500, detail="Internal Vault Destruction Error")


@router.post("/delete-alert/{alert_id}", status_code=status.HTTP_200_OK)
async def delete_alert(
    alert_id: int,
    request: Request,
    admin_user: str = Depends(verify_admin),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    target_alert = db.query(AuditLog).filter(AuditLog.id == alert_id).first()

    if not target_alert:
        raise HTTPException(status_code=404, detail="Resource not found")

    try:
        db.delete(target_alert)
        db.commit()
        return {"success": True, "message": "Alert suppressed successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Destruction Error")


from app.models.alerts import Alert


@router.get("/security-inbox")
async def get_security_inbox(
    db: Session = Depends(get_db), admin_user: str = Depends(verify_admin)
):
    """
    Returns only the 'Prioritized Inbox' data.
    """
    alerts = (
        db.query(Alert)
        .filter(Alert.status != "RESOLVED")
        .order_by(Alert.timestamp.desc())
        .all()
    )
    return {"alerts": alerts}


@router.get("/audit-trail")
async def get_audit_trail(
    db: Session = Depends(get_db), admin_user: str = Depends(verify_admin)
):
    """a
    Returns the exhaustive forensic record (Audit Logs).
    """
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()


@router.post("/unblock-ip/{ip_address}", status_code=status.HTTP_200_OK)
async def unblock_ip(
    ip_address: str,
    db: Session = Depends(get_db),
    authorized: bool = Depends(verify_logix_vault_access),
):
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security Violation: Malformed IP address topology detected.",
        )

    try:
        cmd = ["fail2ban-client", "set", "siem-app", "unbanip", ip_address]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return {
            "status": "success",
            "message": f"IP {ip_address} successfully cleared from network boundary jail layer.",
        }
    except subprocess.CalledProcessError as e:
        error_msg = (
            e.stderr.decode().strip() if e.stderr else "Subprocess execution failure"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OS Firewall mutation failed: {error_msg}",
        )


@router.get("/audit-log/{log_id}/context", status_code=status.HTTP_200_OK)
async def get_audit_log_context(
    log_id: int,
    db: Session = Depends(get_db),
    admin_user: str = Depends(verify_admin),
):
    """
    On-demand contextual retrieval for audit trail entries. Enforces continuous
    session token validation and mitigates initial data over-exposure risks.
    """
    log_entry = db.query(AuditLog).filter(AuditLog.id == log_id).first()
    if not log_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit trace signature not found.",
        )
    return {
        "id": log_entry.id,
        "payload": log_entry.payload if log_entry.payload else "",
        "status": "AUTHORIZED_CONTEXT_RETRIEVED",
    }
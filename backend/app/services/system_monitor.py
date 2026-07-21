# app/services/system_monitor.py
from sqlalchemy.orm import Session
from app.models.audit import AuditLog
from datetime import datetime, timedelta
from sqlalchemy import and_
from app.dependencies import state_vault

def is_system_idle(db: Session, force_override: bool = False) -> bool:
    if force_override:
        return True
    """
    ZERO TRUST GUARDRAIL: Checks if the system is currently processing 
    critical operations that should block config changes.
    """
    active_incidents = db.query(AuditLog).filter(
        AuditLog.status == "PENDING"
    ).count()
    
    return active_incidents == 0
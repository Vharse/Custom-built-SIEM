from sqlalchemy.orm import Session
from app.dependencies import state_vault
from app.models.alerts import Alert
from app.models.audit import AuditLog

MAX_THRESHOLD = 50


def calculate_risk_score(db: Session, config_state: dict) -> float:
    if not config_state.get("audit_logging"):
        return 100.0

    threat_count = db.query(Alert).count()

    return min((threat_count / MAX_THRESHOLD) * 100, 100.0)


def get_risk_trend_data(db: Session):
    current_config = state_vault.read_posture()
    if not current_config.get("audit_logging"):
        return {"data": [], "warning": "AUDIT_LOGGING_DISABLED_NO_DATA"}

    return db.query(AuditLog).all()

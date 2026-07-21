from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime, timezone
from typing import Any
from app.database.config import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = {"extend_existing": True}

    id: Any = Column(Integer, primary_key=True, index=True)
    identity: Any = Column(String(100), nullable=True)
    endpoint: Any = Column(String(255), nullable=False)
    payload: Any = Column(Text, nullable=False, default="NO_PAYLOAD_CONTEXT")
    action: Any = Column(String(100), nullable=True)
    ip_address: Any = Column(String(45), nullable=True)
    status: Any = Column(String(50), nullable=True)
    timestamp: Any = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    hash: Any = Column(String(64), nullable=True)
    previous_hash: Any = Column(String(64), nullable=True)
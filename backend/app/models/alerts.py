from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database.config import Base


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=True)
    action = Column(String(100), nullable=True)
    payload_context = Column(Text, nullable=True)
    status = Column(String(50), default="NEW")
    timestamp = Column(DateTime, server_default=func.now())

    notes = relationship(
        "AlertNote", back_populates="alert", cascade="all, delete-orphan"
    )


class AlertNote(Base):
    __tablename__ = "alert_notes"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), index=True, nullable=False)
    author_id = Column(String(100), nullable=False)
    note_content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    alert = relationship("Alert", back_populates="notes")

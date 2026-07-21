import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status, Response
from sqlalchemy.orm import Session
from app.dependencies import get_db
from app.models.vault import Inquiry
from app.models.audit import AuditLog
from app.schemas.inquiry import ContactRequest as PublicInquirySubmit
from app.security.defenders import sanitize_input_text
from app.utils.security import generate_csrf_token
from app.utils.security import generate_csrf_token  # Enforces aligned module paths
import hmac

router = APIRouter(tags=["Public Handshakes"])
security_logger = logging.getLogger("security_audit")


@router.get("/init-session")
async def initialize_public_session(response: Response):
    """
    SESSION-LESS SECURE HANDSHAKE
    Drops a high-entropy anti-forgery token cookie context for anonymous portfolio guests.
    """
    token = generate_csrf_token()

    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=1800,
    )

    return {"token": token}


@router.post("/submit-inquiry")
async def handle_inquiry(
    request: Request, payload: PublicInquirySubmit, db: Session = Depends(get_db)
):
    csrf_header = request.headers.get("X-CSRF-Token")
    csrf_cookie = request.cookies.get("csrf_token")

    if (
        not csrf_cookie
        or not csrf_header
        or not hmac.compare_digest(csrf_cookie, csrf_header)
    ):
        client_ip = (
            request.headers.get(
                "X-Forwarded-For",
                request.client.host if request.client else "127.0.0.1",
            )
            .split(",")[0]
            .strip()
        )

        security_logger.warning(
            f"🚨 CSRF ALERT: Anonymous submission blocked from true origin IP: {client_ip}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ZERO_TRUST_ENFORCEMENT: Verification anomaly detected.",
        )

    clean_name = sanitize_input_text(payload.name).strip()[:50]
    clean_email = sanitize_input_text(payload.email).strip()[:150]
    clean_msg = sanitize_input_text(payload.message).strip()

    try:
        new_inquiry = Inquiry(
            name=clean_name, email=clean_email, message=clean_msg, is_read=False
        )
        db.add(new_inquiry)
        db.commit()
        return {"status": "SUCCESS", "detail": "Payload verified and stored safely."}

    except Exception as db_err:
        db.rollback()
        security_logger.error(
            f"DATABASE_FAULT: Contact record storage exception: {str(db_err)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Processing Error",
        )

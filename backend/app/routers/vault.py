import html
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from slowapi import Limiter  # type: ignore

# from slowapi.util import get_remote_address
from app.dependencies import get_db, get_trusted_client_ip, limiter

from app.utils.signatures import SECURITY_SIGNATURES
from app.dependencies import get_db
from app.models.vault import Inquiry
from app.schemas.inquiry import (
    ContactRequest,
)

router = APIRouter()

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "http://127.0.0.1:8080",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token, X-Requested-With, X-API-Key, Authorization, Accept",
    "Access-Control-Allow-Credentials": "true",
}


@router.api_route("/contact", methods=["POST", "OPTIONS"])
@limiter.limit("5/minute")
async def post_contact(request: Request, db: Session = Depends(get_db)):

    if request.method == "OPTIONS":
        return Response(
            status_code=204,
            headers={
                **CORS_HEADERS,
                "Access-Control-Max-Age": "86400",
            },
        )
    try:
        raw_data = await request.json()
        inquiry_data = ContactRequest(**raw_data)
    except Exception:
        return JSONResponse(
            status_code=422,
            content={"detail": "INVALID_PAYLOAD_STRUCTURE"},
            headers=CORS_HEADERS,
        )

    try:
        if not inquiry_data.name.strip() or not inquiry_data.message.strip():
            return JSONResponse(
                status_code=400,
                content={"detail": "MALFORMED_INPUT_VECTORS"},
                headers=CORS_HEADERS,
            )

        safe_name = html.escape(inquiry_data.name.strip())
        safe_message = html.escape(inquiry_data.message.strip())
        safe_email = html.escape(inquiry_data.email.strip().lower())

        new_inquiry = Inquiry(name=safe_name, email=safe_email, message=safe_message)

        db.add(new_inquiry)
        db.commit()

        return JSONResponse(
            status_code=200,
            content={"status": "SUCCESS", "message": "PAYLOAD_VAULTED_SECURELY"},
            headers=CORS_HEADERS,
        )

    except Exception as e:
        db.rollback()
        print(f"[SECURITY SYSTEM CRIT]: Data vault ingestion fail. Details: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": "VAULT_STORAGE_ERROR"},
            headers=CORS_HEADERS,
        )

import logging
import os
from jose import jwt, exceptions
import json
from datetime import datetime, timezone
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    Security,
    status,
    Request,
)
from fastapi.security import APIKeyCookie
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.dependencies import get_db, state_vault, SessionLocal
from app.models.audit import AuditLog
from app.schemas.mitigation import MitigationInboundSchema
from app.services.system_monitor import is_system_idle

from google import genai
from google.genai import types
from fastapi.responses import StreamingResponse
import asyncio

router = APIRouter(tags=["System Configuration"])

ENV_MODE = os.getenv("APP_ENV", "development").lower()
IS_PRODUCTION = ENV_MODE == "production"

JWT_SECRET_KEY: str = os.getenv(
    "JWT_SECRET_KEY", "ZERO_TRUST_SIEM_FALLBACK_HARD_SECRET_KEY_32_BYTES_MIN"
)
JWT_ALGORITHM = "HS256"

security_logger = logging.getLogger("security_audit")


_temp_api_key = os.environ.get("GEMINI_API_KEY")

if not _temp_api_key:
    raise ValueError(
        "GEMINI_API_KEY environment variable is missing inside Python context!"
    )

ai_client = genai.Client(api_key=_temp_api_key)
# client = genai.Client(api_key=_temp_api_key)

del _temp_api_key


class ConfigurationMutationSchema(BaseModel):
    feature_key: str = Field(
        ...,
        min_length=10,
        max_length=20,
        pattern="^(pydantic_filtering|audit_logging|ingress_throttling|sandbox_mode)$",
    )
    active_state: bool


async def verify_admin_session_clearance(
    request: Request,
    access_token: str = Security(APIKeyCookie(name="admin_token")),
):
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not access_token:
        security_logger.warning(
            f"SECURITY_ALERT: Session clearance handshake failed from IP={client_ip} - Reason=Missing Cookie"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ZERO_TRUST_ENFORCEMENT: Missing credential handshakes.",
        )

    try:
        payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

        user_identity: str = payload.get("sub", "unknown_node")
        user_role: str = payload.get("role", "unassigned_scope")
        token_origin_ip: str = payload.get("origin_ip", "")

        if IS_PRODUCTION and token_origin_ip and token_origin_ip != client_ip:
            is_internal_hop = (
                client_ip.startswith("172.")
                or client_ip.startswith("127.")
                or client_ip == "localhost"
            )

            if not is_internal_hop:
                security_logger.critical(
                    f"SECURITY_ALERT: Token network mismatch detected! Token IP={token_origin_ip} != Client IP={client_ip}"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="ZERO_TRUST_ENFORCEMENT: Network origin binding mismatch.",
                )

        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            origin = request.headers.get("Origin")
            referer = request.headers.get("Referer")
            trusted_boundary = "http://127.0.0.1:8080"

            if origin:
                if origin != trusted_boundary:
                    security_logger.critical(
                        f"SECURITY_ALERT: Configuration boundary mismatch! Origin={origin} from IP={client_ip}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="ZERO_TRUST_ENFORCEMENT: Origin boundary violation.",
                    )
            elif referer:
                if not referer.startswith(trusted_boundary):
                    security_logger.critical(
                        f"SECURITY_ALERT: Configuration boundary mismatch! Referer={referer} from IP={client_ip}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="ZERO_TRUST_ENFORCEMENT: Referer boundary violation.",
                    )
            else:
                security_logger.critical(
                    f"SECURITY_ALERT: Mutating payload missing tracking headers from IP={client_ip}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="ZERO_TRUST_ENFORCEMENT: Missing state tracking attributes.",
                )

        return {"user": user_identity, "role": user_role}

    except exceptions.ExpiredSignatureError:
        security_logger.warning(
            f"SECURITY_ALERT: Session token expired from IP={client_ip}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ZERO_TRUST_ENFORCEMENT: Session handshake context expired.",
        )
    except exceptions.JWTClaimsError:
        security_logger.error(
            f"SECURITY_ALERT: Token claims verification fault from IP={client_ip}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ZERO_TRUST_ENFORCEMENT: Token validation sequence failure.",
        )
    except Exception as error_context:
        security_logger.error(
            f"SECURITY_ALERT: Token parsing kernel panic from IP={client_ip} - Context={str(error_context)}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ZERO_TRUST_ENFORCEMENT: Unexpected structural boundary anomaly.",
        )


@router.get("/current-posture", status_code=status.HTTP_200_OK)
async def get_current_system_posture(
    admin_context: dict = Depends(verify_admin_session_clearance),
    state_manager=Depends(lambda: state_vault),
):
    if admin_context.get("role") not in ["root_admin", "security_auditor"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ZERO_TRUST_ENFORCEMENT: Insufficient read scope authorization.",
        )
    return state_manager.read_posture()


@router.post("/update-config", status_code=status.HTTP_200_OK)
async def commit_system_configuration_override(
    payload: ConfigurationMutationSchema,
    admin_context: dict = Depends(verify_admin_session_clearance),
    db: Session = Depends(get_db),
    state_manager=Depends(lambda: state_vault),
):
    if admin_context.get("role") != "root_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ZERO_TRUST_ENFORCEMENT: Insufficient write scope authorization.",
        )

    if not is_system_idle(db):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ZERO_TRUST_ENFORCEMENT: System is currently processing active threats. Configuration locked.",
        )

    state_manager.write_mutation(payload.feature_key, payload.active_state)

    security_logger.info(
        f"AUDIT_KERNEL: Config mutation by {admin_context['user']} -> Key: {payload.feature_key} set to {payload.active_state}"
    )

    return {
        "status": "MUTATION_COMMITTED",
        "synchronized_key": payload.feature_key,
        "state": payload.active_state,
    }


@router.post("/logout", status_code=status.HTTP_200_OK)
async def terminate_admin_session_handshake(response: Response):
    """FORCEFUL AUTHENTICATION COOKIE DESTRUCTION"""
    security_logger.info(
        f"AUTH_KERNEL: Eviction sequence triggered. Production Mode: {IS_PRODUCTION}"
    )

    cookie_targets = ["admin_token", "access_token", "csrf_token"]

    for cookie_name in cookie_targets:
        response.set_cookie(
            key=cookie_name,
            value="",
            max_age=0,
            expires=0,
            path="/",
            secure=IS_PRODUCTION,
            httponly=True,
            samesite="strict" if IS_PRODUCTION else "lax",
        )

    return {
        "status": "SESSION_DESTROYED",
        "detail": "Cryptographic tokens purged from all boundary layers.",
    }


@router.post("/mitigate", status_code=status.HTTP_200_OK)
async def commit_incident_mitigation_vector(
    payload: MitigationInboundSchema,
    admin_context: dict = Depends(verify_admin_session_clearance),
    db: Session = Depends(get_db),
):
    """SIEM MITIGATION SYNC HANDSHAKE"""
    if admin_context.get("role") != "root_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ZERO_TRUST_ENFORCEMENT: Insufficient write scope authorization.",
        )

    security_logger.info(
        f"SIEM_KERNEL: Mitigating Alert #{payload.alert_id} for IP {payload.target_ip} -> State: {payload.action_vector}"
    )

    target_alert = db.query(AuditLog).filter(AuditLog.id == payload.alert_id).first()

    if target_alert is not None:
        setattr(target_alert, "status", payload.action_vector)
        db.commit()

    return {
        "status": "TELEMETRY_SYNCHRONIZED",
        "mitigated_target": payload.target_ip,
        "current_vector": payload.action_vector,
    }


class ForensicInvestigationSchema(BaseModel):
    alert_id: int
    thread_id: str = Field(
        ..., min_length=36, max_length=36, pattern=r"^[a-f0-9\-]{36}$"
    )
    note: str = Field(..., min_length=1, max_length=1000)


@router.post("/investigate-stream")
async def stream_forensic_investigation(
    payload: ForensicInvestigationSchema,
    admin_context: dict = Depends(verify_admin_session_clearance),
    db: Session = Depends(get_db),
):
    """
    ZERO-TRUST STATEFUL FORENSIC STREAMING:
    1. Authenticates session via verify_admin_session_clearance.
    2. Persists prompt to an immutable ledger linked securely by thread_id.
    3. Reconstructs running conversation history to provide state memory window.
    4. Streams system analysis tokens via Server-Sent Events over Gemini AI Engine.
    5. Commits downstream AI generation block upon token exhaustion.
    """
    client_identity = admin_context["user"]
    target_endpoint = "/api/config/investigate-stream"

    # DYNAMIC LOG LOOKUP: Fetch the malicious payload details that triggered the alert
    incident_record = db.query(AuditLog).filter(AuditLog.id == payload.alert_id).first()
    malicious_vector = "UNKNOWN_OR_MISSING_PAYLOAD"
    targeted_path = "UNKNOWN_ROUTE"

    if incident_record:
        malicious_vector = incident_record.payload if incident_record.payload else "N/A"
        targeted_path = (
            incident_record.endpoint if incident_record.endpoint else "/api/auth/login"
        )

    db.expunge_all()

    analyst_entry = AuditLog(
        action="FORENSIC_CHAT_PROMPT",
        endpoint=target_endpoint,
        identity=client_identity,
        ip_address="INTERNAL_NODE",
        status="PROCESSED",
        payload=json.dumps(
            {
                "thread_id": payload.thread_id,
                "alert_id": payload.alert_id,
                "message": payload.note,
            }
        ),
    )
    db.add(analyst_entry)
    db.commit()

    historical_logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.endpoint == target_endpoint,
            AuditLog.action.in_(["FORENSIC_CHAT_PROMPT", "FORENSIC_CHAT_RESPONSE"]),
        )
        .order_by(AuditLog.id.asc())
        .all()
    )

    model_memory_buffer = []
    for log in historical_logs:
        try:
            stored_data = json.loads(log.payload)
            if stored_data.get("thread_id") == payload.thread_id:
                role = "user" if log.action == "FORENSIC_CHAT_PROMPT" else "model"
                model_memory_buffer.append(
                    {"role": role, "parts": [{"text": stored_data.get("message", "")}]}
                )
        except (json.JSONDecodeError, TypeError):
            continue

    async def event_generator():
        system_instruction = (
            "You are the RASP_AI_FORENSIC_KERNEL embedded inside a SIEM Security Operations dashboard.\n\n"
            f"CURRENT ATTACK TELETREMETRY UNDER ANALYSIS:\n"
            f"- Targeted Route Path: {targeted_path}\n"
            f"- Trapped Attack Vector Input Content: {malicious_vector}\n\n"
            "YOUR SYSTEM CODEBASE DEFENSIVE PROFILE (FOR CODE LOGIC COMPLIANCE CHECKS):\n"
            "- Core Framework Engine: FastAPI backend routing with a SQLAlchemy ORM layer.\n"
            "- Database Query Engine: All parameters are parsed strictly via explicit SQLAlchemy `.filter()` parameterized syntax expressions.\n"
            "- Input Validation Controls: Authentication login username properties undergo a strict space strip "
            "and length slicing containment check (`username.strip()[:50]`) prior to executing database query scopes.\n"
            "- Rate Limiter Controls: SlowAPI interceptor routines throw standard 429 exceptions to block bruteforce attacks at the gateway level.\n"
            "- Strict Zero-Trust Directive: You don't trust client-side verification controls.\n\n"
            "INSTRUCTIONS:\n"
            "1. Analyze whether the current trapped input payload successfully 'AFFECTED' or was 'NOT AFFECTED' (Mitigated) by the backend logic code or database.\n"
            "2. Under SQLAlchemy parameterized database operations, SQL injection strings (like UNION SELECT or comment markers) are evaluated as literal strings, meaning the database structure is NOT AFFECTED.\n"
            "3. Explicitly present your diagnostic status at the beginning (e.g., [STATUS: NOT AFFECTED] or [STATUS: AFFECTED]), followed by code-level structural explanations and engineering remediation steps. Keep replies concise, raw, and tailored for a SOC analyst."
        )

        accumulated_chunks = []

        try:
            response_stream = await ai_client.aio.models.generate_content_stream(
                model="gemini-2.5-flash",
                contents=model_memory_buffer,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    temperature=0.1,
                ),
            )

            async for chunk in response_stream:
                text = getattr(chunk, "text", None)

                if text:
                    yield f"data: {text}\n\n"
                    accumulated_chunks.append(text)

        except Exception as e:
            yield f"data: 🚨 ENGINE_STREAM_ERROR: LLM runtime fault encountered during telemetry compilation: {str(e)}\n\n"
            return

        full_ai_response = "".join(accumulated_chunks).strip()
        if full_ai_response:
            ai_entry = AuditLog(
                action="FORENSIC_CHAT_RESPONSE",
                endpoint=target_endpoint,
                identity="RASP_AI_KERNEL",
                ip_address="INTERNAL_NODE",
                status="PROCESSED",
                payload=json.dumps(
                    {
                        "thread_id": payload.thread_id,
                        "alert_id": payload.alert_id,
                        "message": full_ai_response,
                    }
                ),
            )
            try:
                db.add(ai_entry)
                db.commit()
            except Exception as write_err:
                security_logger.error(
                    f"INTEGRITY_FAULT: Stream terminal log synchronization failed: {str(write_err)}"
                )

    return StreamingResponse(event_generator(), media_type="text/event-stream")

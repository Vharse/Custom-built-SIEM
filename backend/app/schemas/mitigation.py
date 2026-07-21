from pydantic import BaseModel, Field

class MitigationInboundSchema(BaseModel):
    """
    🛡️ INBOUND MITIGATION DATA VALIDATION MATRIX
    Enforces strict typing and validation boundaries on incoming SIEM state mutations.
    """
    alert_id: int = Field(..., description="The unique database record identification index.")
    action_vector: str = Field(..., description="The mitigation posture state: INVESTIGATING, IP_BLOCKED, or RESOLVED.")
    target_ip: str = Field(..., min_length=7, max_length=45, description="The authenticated IPv4 or IPv6 tracking address.")

    class Config:
        frozen = True
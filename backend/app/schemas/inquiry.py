from pydantic import BaseModel, EmailStr, Field

class ContactRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=50, description="Caller identification sequence")
    email: EmailStr = Field(..., max_length=150, description="Validated electronic routing handle")
    message: str = Field(..., min_length=10, max_length=3000, description="Raw ingestion query text block")

class InquiryReadRequest(BaseModel):
    inquiry_id: int = Field(..., description="Target Database Record Identifier")
    status: str = Field(..., pattern="^READ$", description="Strict State Assertion Value Constraint")

class InquiryResponse(BaseModel):
    id: int
    name: str
    email: str
    message: str
    is_read: bool
    class Config: 
        from_attributes = True
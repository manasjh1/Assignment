from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any

# Registration request (Moved from routes.py and added validators)
class RegistrationRequest(BaseModel):
    email: EmailStr
    password: str
    phone_number: str  
    first_name: str
    last_name: str
    role: str = "user"
    is_active: bool = True
    created_at: Optional[str] = None

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

    @validator('phone_number')
    def validate_phone(cls, v):
        # Remove all non-digit characters except +
        clean_phone = ''.join(c for c in v if c.isdigit() or c == '+')
        
        # Check if it's a valid format
        if clean_phone.startswith('+91') and len(clean_phone) == 13:
            return clean_phone
        elif len(clean_phone) == 10 and clean_phone.isdigit():
            return '+91' + clean_phone
        else:
            raise ValueError('Invalid phone number format')

# Simple OTP Verification for /verify-registration route
class OTPVerificationRequest(BaseModel):
    phone_number: str
    otp_code: str

# Full Verification Request (kept for compatibility if needed)
class VerifyRegistrationOTPRequest(BaseModel):
    phone_number: str
    otp_code: str
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None

# Login request 
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# Forgot password request 
class ForgotPasswordRequest(BaseModel):
    phone_number: str

# Reset password with OTP 
class ResetPasswordRequest(BaseModel):
    phone_number: str
    otp_code: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

# Token response
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    role: str

# User model
class User(BaseModel):
    id: str
    email: str
    phone_number: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: str = "user"
    is_active: bool = True

# Registration OTP response
class RegisterOTPResponse(BaseModel):
    message: str
    phone_number: str
    otp_sent: bool
    temp_id: str 

# Registration completion response
class RegisterCompleteResponse(BaseModel):
    message: str
    user_id: str
    account_created: bool 

# Search Models
class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=500, description="Search query")
    max_results: Optional[int] = Field(10, ge=1, le=50, description="Maximum results")
    
class SearchResult(BaseModel):
    title: str
    snippet: str
    url: str
    source: str
    
class SearchResponse(BaseModel):
    results: List[SearchResult]
    query: str
    total_results: int
    status: str
    search_engine: str
    protocol: str
    error: Optional[str] = None

class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict
    refresh_token: Optional[str] = None

class MessageResponse(BaseModel):
    message: str
    success: bool = True

# Image Generation Models
class ImageGenRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=1000, description="Image description")
    model: str = Field("flux", description="Model to use: flux, flux-realism, etc.")
    width: Optional[int] = Field(1024, ge=256, le=2048)
    height: Optional[int] = Field(1024, ge=256, le=2048)

class ImageGenResponse(BaseModel):
    image_url: str
    prompt: str
    status: str
    provider: str
    error: Optional[str] = None

# History Models
class SearchHistoryItem(BaseModel):
    id: str
    query: str
    results: List[Dict[str, Any]]
    total_results: int
    search_engine: str
    created_at: str

class SearchHistoryResponse(BaseModel):
    searches: List[SearchHistoryItem]
    total: int
    page: int
    limit: int
    total_pages: int

class ImageHistoryItem(BaseModel):
    id: str
    prompt: str
    image_url: str
    model: str
    width: int
    height: int
    provider: str
    created_at: str

class ImageHistoryResponse(BaseModel):
    images: List[ImageHistoryItem]
    total: int
    page: int
    limit: int
    total_pages: int

class DeleteResponse(BaseModel):
    message: str
    deleted: bool
    id: str
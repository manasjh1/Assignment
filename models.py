from pydantic import BaseModel, EmailStr
from typing import Optional

# Registration request 
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    phone_number: str  
    first_name: Optional[str] = None
    last_name: Optional[str] = None

# Verify registration OTP 
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
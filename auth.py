import hashlib
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from passlib.context import CryptContext
import httpx
import config
from database import db
from models import (
    RegisterRequest, LoginRequest, TokenResponse, 
    RegisterOTPResponse, RegisterCompleteResponse,
    ForgotPasswordRequest, ResetPasswordRequest,
    VerifyRegistrationOTPRequest
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class OTPService:
    @staticmethod
    def generate_otp(length: int = 6) -> str:
        """Generate random OTP"""
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    
    @staticmethod
    async def send_sms_otp(phone_number: str, otp_code: str) -> bool:
        """Send OTP via 2Factor.in SMS service"""
        try:
            clean_phone = phone_number.replace("+91", "").replace("+", "").strip()
            
            url = f"{config.TWOFACTOR_BASE_URL}/{config.TWOFACTOR_API_KEY}/SMS/+91{clean_phone}/{otp_code}/OTP1"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                
                if response.status_code == 200:
                    result = response.json()
                    return result.get("Status") == "Success"
                else:
                    print(f"2Factor API error: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            print(f"Error sending SMS via 2Factor: {str(e)}")
            return False

class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password"""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def create_access_token(user_id: str, role: str) -> str:
        """Create JWT access token"""
        expire = datetime.utcnow() + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
        payload = {
            "user_id": user_id,
            "role": role,
            "exp": expire,
            "type": "access"
        }
        return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)
    
    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        """Create JWT refresh token"""
        expire = datetime.utcnow() + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
        payload = {
            "user_id": user_id,
            "exp": expire,
            "type": "refresh"
        }
        return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)
    
    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, config.JWT_SECRET_KEY, algorithms=[config.JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None
    
    @staticmethod
    def hash_token(token: str) -> str:
        """Hash token for database storage"""
        return hashlib.sha256(token.encode()).hexdigest()

async def start_registration(request: RegisterRequest) -> RegisterOTPResponse:
    """Step 1: Start registration process and send OTP"""
    
    existing_user_email = await db.get_user_by_email(request.email)
    if existing_user_email:
        raise Exception("Email already registered")
    
    existing_user_phone = await db.get_user_by_phone(request.phone_number)
    if existing_user_phone:
        raise Exception("Phone number already registered")
    
    otp_code = OTPService.generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=config.OTP_EXPIRY_MINUTES)
    
    registration_data = {
        "email": request.email,
        "password": request.password, 
        "phone_number": request.phone_number,
        "first_name": request.first_name,
        "last_name": request.last_name
    }
    
    temp_id = await db.store_registration_otp(
        request.phone_number, 
        otp_code, 
        expires_at.isoformat(), 
        registration_data
    )
    
    if not temp_id:
        raise Exception("Failed to store registration data")
    
    otp_sent = await OTPService.send_sms_otp(request.phone_number, otp_code)
    
    return RegisterOTPResponse(
        message="OTP sent to your phone number. Please verify to complete registration.",
        phone_number=request.phone_number,
        otp_sent=otp_sent,
        temp_id=temp_id
    )

async def complete_registration(request: VerifyRegistrationOTPRequest) -> RegisterCompleteResponse:
    """Step 2: Verify OTP and create user account"""
    
    otp_record = await db.verify_registration_otp(request.phone_number, request.otp_code)
    if not otp_record:
        raise Exception("Invalid or expired OTP")
    
    registration_data = otp_record["registration_data"]
    
    hashed_password = AuthService.hash_password(registration_data["password"])
    
    user_data = {
        "email": registration_data["email"],
        "password_hash": hashed_password,
        "phone_number": registration_data["phone_number"],
        "first_name": registration_data.get("first_name"),
        "last_name": registration_data.get("last_name"),
        "role": "user",
        "is_active": True,
    }
    
    try:
        user = await db.create_user(user_data)
        
        return RegisterCompleteResponse(
            message="Account created successfully. You can now login.",
            user_id=user["id"],
            account_created=True
        )
        
    except Exception as e:
        raise Exception(f"Account creation failed: {str(e)}")

async def login_user(request: LoginRequest) -> TokenResponse:
    """Login with email and password"""
    
    user = await db.get_user_by_email(request.email)
    if not user:
        raise Exception("Invalid email or password")
    
    if not AuthService.verify_password(request.password, user["password_hash"]):
        raise Exception("Invalid email or password")
    
    if not user.get("is_active", False):
        raise Exception("Account is not active")
    
    access_token = AuthService.create_access_token(user["id"], user["role"])
    refresh_token = AuthService.create_refresh_token(user["id"])
    
    session_data = {
        "user_id": user["id"],
        "token_hash": AuthService.hash_token(refresh_token),
        "expires_at": (datetime.utcnow() + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)).isoformat(),
        "is_active": True
    }
    
    await db.create_session(session_data)
    
    await db.update_user(user["id"], {"last_login": datetime.utcnow().isoformat()})
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user_id=user["id"],
        role=user["role"]
    )

async def start_forgot_password(request: ForgotPasswordRequest) -> Dict[str, Any]:
    """Step 1: Send OTP for password reset"""
    
    user = await db.get_user_by_phone(request.phone_number)
    if not user:
        return {
            "message": "If this phone number is registered, you will receive an OTP.",
            "phone_number": request.phone_number,
            "otp_sent": False
        }
    
    otp_code = OTPService.generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=config.OTP_EXPIRY_MINUTES)
    
    await db.store_forgot_password_otp(request.phone_number, otp_code, expires_at.isoformat())
    
    otp_sent = await OTPService.send_sms_otp(request.phone_number, otp_code)
    
    return {
        "message": "OTP sent to your phone number for password reset.",
        "phone_number": request.phone_number,
        "otp_sent": otp_sent
    }

async def reset_password_with_otp(request: ResetPasswordRequest) -> Dict[str, Any]:
    """Step 2: Reset password with OTP verification"""
    
    is_valid_otp = await db.verify_forgot_password_otp(request.phone_number, request.otp_code)
    if not is_valid_otp:
        raise Exception("Invalid or expired OTP")
    
    new_password_hash = AuthService.hash_password(request.new_password)
    
    success = await db.update_user_password_by_phone(request.phone_number, new_password_hash)
    if not success:
        raise Exception("Failed to update password")
    
    user = await db.get_user_by_phone(request.phone_number)
    if user:
        await db.invalidate_user_sessions(user["id"])
    
    return {
        "message": "Password reset successfully. Please login with your new password.",
        "password_updated": True
    }

async def refresh_access_token(refresh_token: str) -> TokenResponse:
    """Refresh access token"""
    
    payload = AuthService.verify_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise Exception("Invalid refresh token")
    
    token_hash = AuthService.hash_token(refresh_token)
    session = await db.get_session(token_hash)
    if not session:
        raise Exception("Session not found or expired")
    
    user = await db.get_user_by_id(payload["user_id"])
    if not user or not user.get("is_active", False):
        raise Exception("User not found or inactive")
    
    new_access_token = AuthService.create_access_token(user["id"], user["role"])
    new_access_token = AuthService.create_access_token(user["id"], user["role"])
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=refresh_token,
        user_id=user["id"],
        role=user["role"]
    )

async def logout_user(user_id: str, token: str = None) -> bool:
    """Logout user and invalidate session"""
    
    if token:
        token_hash = AuthService.hash_token(token)
        return await db.invalidate_session(token_hash)
    else:
        return await db.invalidate_user_sessions(user_id)

async def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify token and return user data"""
    
    payload = AuthService.verify_token(token)
    if not payload or payload.get("type") != "access":
        return None
    
    user = await db.get_user_by_id(payload["user_id"])
    if not user or not user.get("is_active", False):
        return None
    
    return user
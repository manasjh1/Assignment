import os
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime, timedelta
import random
import string
import json
import logging
from typing import Optional, List
from auth import AuthService
from database import db, DatabaseError
from auth import AuthManager, get_auth_manager
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from search_service import search_service
from image_service import image_service
from models import (
    RegistrationRequest, OTPVerificationRequest, LoginRequest, 
    ForgotPasswordRequest, ResetPasswordRequest, AuthResponse, 
    MessageResponse, SearchRequest, SearchResult, SearchResponse,
    ImageGenRequest, ImageGenResponse
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Security
security = HTTPBearer()

# Simple dependency for getting current user
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth: AuthManager = Depends(get_auth_manager)
):
    """FastAPI dependency to get current user"""
    return await auth.get_current_user(db, credentials)

# Create router
auth_router = APIRouter(prefix="/auth", tags=["authentication"])

# Utility functions
def generate_otp() -> str:
    """Generate 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

async def send_sms_otp(phone_number: str, otp_code: str) -> bool:
    """Send OTP via SMS using 2Factor API"""
    try:
        import httpx
        api_key = os.getenv("TWOFACTOR_API_KEY")
        if not api_key:
            logger.error("TWOFACTOR_API_KEY not configured")
            return False
        
        url = f"https://2factor.in/API/V1/{api_key}/SMS/{phone_number}/{otp_code}/OTP1"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            
        if response.status_code == 200:
            logger.info(f"OTP sent successfully to {phone_number}")
            return True
        else:
            logger.error(f"Failed to send OTP: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"SMS sending failed: {e}")
        return False

# Routes
@auth_router.post("/register", response_model=MessageResponse)
async def register_user(
    request: RegistrationRequest,
    auth: AuthManager = Depends(get_auth_manager)
):
    """Register new user and send OTP"""
    try:
        # Normalize data
        email = request.email.lower().strip()
        phone = request.phone_number.strip()
        
        # Check if user already exists
        existing_user_email = await db.get_user_by_email(email)
        if existing_user_email:
            raise HTTPException(status_code=409, detail="Email already registered")
        
        existing_user_phone = await db.get_user_by_phone(phone)
        if existing_user_phone:
            raise HTTPException(status_code=409, detail="Phone number already registered")
        
        # Generate OTP
        otp_code = generate_otp()
        expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        
        # Store registration data temporarily
        registration_data = {
            "email": email,
            "password": request.password,  # Will be hashed during user creation
            "phone_number": phone,
            "first_name": request.first_name.strip(),
            "last_name": request.last_name.strip()
        }
        
        # Store OTP
        await db.store_registration_otp(
            phone_number=phone,
            otp_code=otp_code,
            expires_at=expires_at,
            registration_data=json.dumps(registration_data)
        )
        
        # Send OTP
        sms_sent = await send_sms_otp(phone, otp_code)
        if not sms_sent:
            logger.warning(f"SMS failed for {phone}, but OTP stored for testing")
        
        return MessageResponse(
            message=f"OTP sent to {phone}. Please verify to complete registration.",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@auth_router.post("/verify-registration", response_model=AuthResponse)
async def verify_registration(
    request: OTPVerificationRequest,
    auth: AuthManager = Depends(get_auth_manager)
):
    """Verify OTP and complete user registration"""
    try:
        # Verify OTP
        otp_result = await db.verify_registration_otp(
            phone_number=request.phone_number.strip(),
            otp_code=request.otp_code.strip()
        )
        
        if not otp_result:
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")
        
        # Parse registration data
        registration_data = json.loads(otp_result['registration_data'])
        
        # Hash password
        hashed_password = auth.hash_password(registration_data['password'])
        
        # Create user
        user_data = {
            "email": registration_data['email'],
            "password_hash": hashed_password,
            "phone_number": registration_data['phone_number'],
            "first_name": registration_data['first_name'],
            "last_name": registration_data['last_name'],
            "role": "user",
            "is_active": True
        }
        
        user = await db.create_user(user_data)
        
        # Create access token
        token_data = {
            "user_id": user['id'],
            "email": user['email'],
            "role": user['role']
        }
        access_token = auth.create_access_token(token_data)
        
        # Create session
        token_hash = auth.create_token_hash(access_token)
        expires_at = (datetime.utcnow() + timedelta(minutes=auth.access_token_expire_minutes)).isoformat()
        
        await db.create_session({
            "user_id": user['id'],
            "token_hash": token_hash,
            "expires_at": expires_at
        })
        
        # Remove sensitive data from user response
        user_safe = user.copy()
        user_safe.pop('password_hash', None)
        
        return AuthResponse(
            access_token=access_token,
            user=user_safe
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration verification failed: {e}")
        raise HTTPException(status_code=500, detail="Verification failed")

@auth_router.post("/login")
async def login_user(
    request: LoginRequest,
    auth: AuthManager = Depends(get_auth_manager)
):
    """Login user and create session"""
    # 1. Get user
    user_dict = await db.get_user_by_email(request.email)
    if not user_dict:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # 2. Verify password
    if not auth.verify_password(request.password, user_dict["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # 3. Create Access Token
    token_data = {
        "user_id": user_dict['id'],
        "email": user_dict['email'],
        "role": user_dict['role']
    }
    access_token = auth.create_access_token(token_data)
    
    # 4. Create Refresh Token
    refresh_token = AuthService.create_refresh_token(user_dict["id"])
    
    # 5. Create Session in Database
    token_hash = auth.create_token_hash(access_token)
    expires_at = (datetime.utcnow() + timedelta(minutes=auth.access_token_expire_minutes)).isoformat()
    
    await db.create_session({
        "user_id": user_dict['id'],
        "token_hash": token_hash,
        "expires_at": expires_at
    })
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {k: v for k, v in user_dict.items() if k != "password_hash"}
    }
    
@auth_router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(request: ForgotPasswordRequest):
    """Request password reset OTP"""
    try:
        phone = request.phone_number.strip()
        
        # Check if user exists
        user = await db.get_user_by_phone(phone)
        if not user:
            raise HTTPException(status_code=404, detail="Phone number not found")
        
        # Generate OTP
        otp_code = generate_otp()
        expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        
        # Store OTP
        await db.store_forgot_password_otp(
            phone_number=phone,
            otp_code=otp_code,
            expires_at=expires_at
        )
        
        # Send OTP
        sms_sent = await send_sms_otp(phone, otp_code)
        if not sms_sent:
            logger.warning(f"SMS failed for {phone}, but OTP stored for testing")
        
        return MessageResponse(
            message=f"Password reset OTP sent to {phone}",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Forgot password failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to process password reset request")

@auth_router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    request: ResetPasswordRequest,
    auth: AuthManager = Depends(get_auth_manager)
):
    """Reset password with OTP"""
    try:
        phone = request.phone_number.strip()
        
        # Verify OTP
        otp_valid = await db.verify_forgot_password_otp(phone, request.otp_code.strip())
        if not otp_valid:
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")
        
        # Hash new password
        hashed_password = auth.hash_password(request.new_password)
        
        # Update password
        success = await db.update_user_password_by_phone(phone, hashed_password)
        if not success:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Invalidate all user sessions
        user = await db.get_user_by_phone(phone)
        if user:
            await db.invalidate_user_sessions(user['id'])
        
        return MessageResponse(
            message="Password reset successfully",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset failed: {e}")
        raise HTTPException(status_code=500, detail="Password reset failed")

@auth_router.post("/logout", response_model=MessageResponse)
async def logout_user(
    current_user: dict = Depends(get_current_user),
    auth: AuthManager = Depends(get_auth_manager)
):
    """Logout user and invalidate session"""
    try:
        await db.invalidate_user_sessions(current_user['id'])
        
        return MessageResponse(
            message="Logged out successfully",
            success=True
        )
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

@auth_router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return current_user

@auth_router.get("/health")
async def auth_health_check():
    """Authentication service health check"""
    try:
        if db.check_connection():
            return {"status": "healthy", "service": "authentication"}
        else:
            raise HTTPException(status_code=503, detail="Database connection failed")
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")
    
@auth_router.post("/refresh", response_model=AuthResponse)
async def refresh_token(
    refresh_token: str,
    auth: AuthManager = Depends(get_auth_manager)
):
    """Refresh access token"""
    try:
        # Verify the refresh token
        payload = auth.verify_token(refresh_token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Get user
        user_id = payload.get("user_id")
        user = await db.get_user_by_id(user_id)
        if not user or not user.get('is_active'):
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        # Create new access token
        token_data = {
            "user_id": user['id'],
            "email": user['email'],
            "role": user['role']
        }
        new_access_token = auth.create_access_token(token_data)
        
        # Create new session
        token_hash = auth.create_token_hash(new_access_token)
        expires_at = (datetime.utcnow() + timedelta(minutes=auth.access_token_expire_minutes)).isoformat()
        
        await db.create_session({
            "user_id": user['id'],
            "token_hash": token_hash,
            "expires_at": expires_at
        })
        
        # Remove sensitive data
        user_safe = user.copy()
        user_safe.pop('password_hash', None)
        
        return AuthResponse(
            access_token=new_access_token,
            user=user_safe
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(status_code=500, detail="Token refresh failed")

@router.post("/search", response_model=SearchResponse)
async def search_web(
    request: SearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """Search using DuckDuckGo MCP server - Protected endpoint"""
    try:
        logger.info(f"Search request from user {current_user.get('email')}: {request.query}")
        
        search_result = await search_service.search(
            query=request.query,
            max_results=request.max_results
        )
        
        results = [SearchResult(**result) for result in search_result["results"]]
        
        logger.info(f"Search completed for user {current_user.get('email')}: {len(results)} results")
        
        return SearchResponse(
            results=results,
            query=search_result["query"],
            total_results=search_result["total_results"],
            status=search_result["status"],
            search_engine=search_result["search_engine"],
            protocol=search_result["protocol"],
            error=search_result.get("error")
        )
        
    except Exception as e:
        logger.error(f"Search API error for user {current_user.get('email')}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Search error: {str(e)}")

@router.post("/admin/search", response_model=SearchResponse)
async def admin_search_web(
    request: SearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """Admin search endpoint with elevated privileges"""
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        logger.info(f"Admin search request from {current_user.get('email')}: {request.query}")
        
        admin_max_results = min(request.max_results, 50)
        
        search_result = await search_service.search(
            query=request.query,
            max_results=admin_max_results
        )
        
        results = [SearchResult(**result) for result in search_result["results"]]
        
        return SearchResponse(
            results=results,
            query=search_result["query"],
            total_results=search_result["total_results"],
            status=search_result["status"],
            search_engine=search_result["search_engine"],
            protocol=search_result["protocol"],
            error=search_result.get("error")
        )
        
    except Exception as e:
        logger.error(f"Admin search error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Search error: {str(e)}")

@router.get("/search/history")
async def get_search_history(current_user: dict = Depends(get_current_user)):
    """Get user's search history"""
    return {
        "message": "Search history feature coming soon",
        "user_id": current_user.get('id'),
        "searches": []
    }

@router.get("/test/protected")
async def test_protected_endpoint(current_user: dict = Depends(get_current_user)):
    """Test endpoint to verify authentication is working"""
    return {
        "message": "Authentication working!",
        "user": current_user.get('email'),
        "role": current_user.get('role'),
        "user_id": current_user.get('id')
    }

@router.post("/image/generate", response_model=ImageGenResponse)
async def generate_image(
    request: ImageGenRequest,
    current_user: dict = Depends(get_current_user)
):
    """Generate image using Flux MCP - Protected endpoint"""
    try:
        logger.info(f"Image generation request from {current_user.get('email')}: {request.prompt}")
        
        result = await image_service.generate_image(
            prompt=request.prompt,
            model=request.model,
            width=request.width,
            height=request.height
        )
        
        return ImageGenResponse(**result)
        
    except Exception as e:
        logger.error(f"Image generation API error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Image generation error: {str(e)}")
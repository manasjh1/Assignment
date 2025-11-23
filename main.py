from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from models import (
    RegisterRequest, LoginRequest, TokenResponse,
    VerifyRegistrationOTPRequest, RegisterOTPResponse, RegisterCompleteResponse,
    ForgotPasswordRequest, ResetPasswordRequest
)
from auth import (
    start_registration, complete_registration, login_user, 
    refresh_access_token, logout_user, verify_token,
    start_forgot_password, reset_password_with_otp
)

app = FastAPI(
    title="AI Content Explorer API",
    description="Authentication with Phone OTP Verification",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    user = await verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

@app.post("/auth/register", response_model=RegisterOTPResponse)
async def register_step1(request: RegisterRequest):
    """Step 1: Start registration and send OTP to phone"""
    try:
        result = await start_registration(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/verify-registration", response_model=RegisterCompleteResponse)
async def register_step2(request: VerifyRegistrationOTPRequest):
    """Step 2: Verify OTP and create user account"""
    try:
        result = await complete_registration(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """Login with email and password (no OTP needed)"""
    try:
        tokens = await login_user(request)
        return tokens
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.post("/auth/forgot-password")
async def forgot_password_step1(request: ForgotPasswordRequest):
    """Step 1: Send OTP to phone for password reset"""
    try:
        result = await start_forgot_password(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/reset-password")
async def forgot_password_step2(request: ResetPasswordRequest):
    """Step 2: Reset password with OTP verification"""
    try:
        result = await reset_password_with_otp(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(refresh_token: str):
    """Refresh access token using refresh token"""
    try:
        new_tokens = await refresh_access_token(refresh_token)
        return new_tokens
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.post("/auth/logout")
async def logout(
    current_user = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Logout user and invalidate session"""
    try:
        token = credentials.credentials
        await logout_user(current_user["id"], token)
        return {"message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
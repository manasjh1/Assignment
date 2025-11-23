import bcrypt
from datetime import datetime, timedelta
import os
import jwt
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import logging
from models import (
    RegisterRequest, LoginRequest, TokenResponse, 
    RegisterOTPResponse, RegisterCompleteResponse,
    ForgotPasswordRequest, ResetPasswordRequest,
    VerifyRegistrationOTPRequest, User
)

logger = logging.getLogger(__name__)

# Password context with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer()

class AuthManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30 * 24 * 60  # 30 days

    def hash_password(self, password: str) -> str:
        """Hash password using passlib bcrypt"""
        try:
            return pwd_context.hash(password)
        except Exception as e:
            logger.error(f"Password hashing failed: {e}")
            raise HTTPException(status_code=500, detail="Password processing failed")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash with multiple fallbacks"""
        try:
            # Primary method: passlib
            return pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.warning(f"Passlib verification failed, trying bcrypt direct: {e}")
            try:
                # Fallback: direct bcrypt
                import bcrypt
                return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
            except Exception as e2:
                logger.error(f"All password verification methods failed: {e2}")
                return False

    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        import uuid
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire})
        
        # Convert any UUID objects to strings for JSON serialization
        for key, value in to_encode.items():
            if isinstance(value, uuid.UUID) or hasattr(value, 'hex') or 'UUID' in str(type(value)):
                to_encode[key] = str(value)
        
        try:
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            return encoded_jwt
        except Exception as e:
            logger.error(f"Token creation failed: {e}")
            raise HTTPException(status_code=500, detail="Token creation failed")

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.JWTError as e:
            logger.warning(f"Token verification failed: {e}")
            return None

    def create_token_hash(self, token: str) -> str:
        """Create hash for token storage"""
        return hashlib.sha256(token.encode()).hexdigest()

    async def authenticate_user(self, db, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with email and password"""
        try:
            # Normalize email
            normalized_email = email.strip().lower()
            
            # Get user
            user = await db.get_user_by_email(normalized_email)
            if not user:
                logger.warning(f"User not found: {normalized_email}")
                return None

            # Check if user is active
            if not user.get('is_active', False):
                logger.warning(f"User account disabled: {normalized_email}")
                return None

            # Verify password
            if self.verify_password(password, user['password_hash']):
                # Remove sensitive data
                user_safe = user.copy()
                user_safe.pop('password_hash', None)
                logger.info(f"User authenticated successfully: {normalized_email}")
                return user_safe
            else:
                logger.warning(f"Invalid password for user: {normalized_email}")
                return None

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    async def get_current_user(self, db, credentials: HTTPAuthorizationCredentials = Depends(security)):
        """Get current user from JWT token"""
        try:
            token = credentials.credentials
            token_hash = self.create_token_hash(token)
            
            # Check if session exists and is valid
            session = await db.get_session_by_token(token_hash)
            if not session:
                raise HTTPException(status_code=401, detail="Invalid or expired session")
            
            # Verify token
            payload = self.verify_token(token)
            if not payload:
                # Token invalid, clean up session
                await db.invalidate_session(token_hash)
                raise HTTPException(status_code=401, detail="Invalid or expired token")
            
            # Get user
            user_id = payload.get("user_id")
            if not user_id:
                raise HTTPException(status_code=401, detail="Invalid token payload")
            
            user = await db.get_user_by_id(user_id)
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            
            if not user.get('is_active', False):
                raise HTTPException(status_code=401, detail="User account disabled")
            
            # Remove sensitive data
            user_safe = user.copy()
            user_safe.pop('password_hash', None)
            return user_safe
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            raise HTTPException(status_code=401, detail="Authentication failed")

# Initialize auth manager
auth_manager = AuthManager(secret_key=os.getenv("JWT_SECRET_KEY", "your-default-secret-key"))

# Dependencies for FastAPI
def get_auth_manager() -> AuthManager:
    """Dependency to get auth manager"""
    return auth_manager

# Just add this AuthService class to your existing auth.py file:

class AuthService:
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    @staticmethod
    def create_access_token(user_id: str, role: str) -> str:
        payload = {
            "user_id": str(user_id),
            "role": role,
            "exp": datetime.utcnow() + timedelta(minutes=30)
        }
        return jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm="HS256")
    
    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        payload = {
            "user_id": str(user_id),
            "exp": datetime.utcnow() + timedelta(days=30)
        }
        return jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm="HS256")
    
    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
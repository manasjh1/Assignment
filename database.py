# database.py - Production-ready Supabase PostgreSQL connection

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from contextlib import contextmanager

from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Text, JSON, Index, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Database Models
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    phone_number = Column(String, unique=True, nullable=False, index=True)
    first_name = Column(String)
    last_name = Column(String)
    role = Column(String, default="user")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert user object to dictionary"""
        return {
            "id": self.id,
            "email": self.email,
            "phone_number": self.phone_number,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

class UserSession(Base):
    __tablename__ = "user_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session object to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "token_hash": self.token_hash,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class RegistrationOTP(Base):
    __tablename__ = "registration_otps"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    phone_number = Column(String, nullable=False, index=True)
    otp_code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    registration_data = Column(JSON)
    is_used = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class ForgotPasswordOTP(Base):
    __tablename__ = "forgot_password_otps"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    phone_number = Column(String, nullable=False, index=True)
    otp_code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    is_used = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SearchHistory(Base):
    __tablename__ = "search_history"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=False, index=True)
    query = Column(String, nullable=False)
    results = Column(JSON)
    total_results = Column(Integer, default=0)
    search_engine = Column(String, default="DuckDuckGo")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert search history object to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "query": self.query,
            "results": self.results,
            "total_results": self.total_results,
            "search_engine": self.search_engine,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class ImageHistory(Base):
    __tablename__ = "image_history"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=False, index=True)
    prompt = Column(Text, nullable=False)
    image_url = Column(Text, nullable=False)
    model = Column(String, default="flux")
    width = Column(Integer, default=1024)
    height = Column(Integer, default=1024)
    provider = Column(String, default="Flux")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert image history object to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "prompt": self.prompt,
            "image_url": self.image_url,
            "model": self.model,
            "width": self.width,
            "height": self.height,
            "provider": self.provider,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class DatabaseError(Exception):
    """Custom database exception"""
    pass

class Database:
    def __init__(self):
        self.connection_string = self._get_connection_string()
        self.engine = self._create_engine()
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self._initialize_database()
        logger.info("Database connection established successfully")

    def _get_connection_string(self) -> str:
        """Get database connection string from environment"""
        connection_string = os.getenv("DATABASE_URL")
        if not connection_string:
            raise DatabaseError("DATABASE_URL environment variable is required")
        return connection_string

    def _create_engine(self):
        """Create SQLAlchemy engine with production settings"""
        return create_engine(
            self.connection_string,
            echo=os.getenv("DEBUG", "false").lower() == "true",
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=3600,  # 1 hour
            connect_args={
                "sslmode": "require",
                "connect_timeout": 30,
                "application_name": "sarthi_backend"
            },
            execution_options={
                "compiled_cache": {},
                "isolation_level": "READ_COMMITTED"
            }
        )

    def _initialize_database(self):
        """Initialize database and create tables"""
        try:
            # Test connection
            with self.engine.connect() as conn:
                conn.execute("SELECT 1")
            
            # Create tables
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables initialized")
            
            # Create sample data only in debug mode
            if os.getenv("DEBUG", "false").lower() == "true":
                self._create_sample_data()
                
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise DatabaseError(f"Failed to initialize database: {e}")

    def _create_sample_data(self):
        """Create sample data for development/testing"""
        try:
            with self.get_session() as session:
                existing_user = session.query(User).filter(User.email == "test@example.com").first()
                if not existing_user:
                    sample_user = User(
                        email="test@example.com",
                        password_hash="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeWWxBXXfBuSsHxNG",
                        phone_number="+911234567890",
                        first_name="Test",
                        last_name="User",
                        role="user",
                        is_active=True
                    )
                    session.add(sample_user)
                    session.commit()
                    logger.info("Sample test user created for development")
        except Exception as e:
            logger.warning(f"Could not create sample data: {e}")

    @contextmanager
    def get_session(self):
        """Context manager for database sessions"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def check_connection(self) -> bool:
        """Health check for database connection"""
        try:
            with self.engine.connect() as conn:
                conn.execute("SELECT 1")
                return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    # User operations
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user"""
        try:
            # Normalize email to lowercase before storage
            normalized_email = user_data["email"].strip().lower()
            
            with self.get_session() as session:
                user = User(
                    email=normalized_email,
                    password_hash=user_data["password_hash"],
                    phone_number=user_data["phone_number"],
                    first_name=user_data.get("first_name"),
                    last_name=user_data.get("last_name"),
                    role=user_data.get("role", "user"),
                    is_active=user_data.get("is_active", True)
                )
                session.add(user)
                session.flush()  # Get the ID without committing
                result = user.to_dict()
                logger.info(f"User created successfully: {normalized_email}")
                return result
                
        except IntegrityError as e:
            logger.error(f"User creation failed - duplicate entry: {e}")
            raise DatabaseError("Email or phone number already exists")
        except Exception as e:
            logger.error(f"User creation failed: {e}")
            raise DatabaseError(f"Failed to create user: {e}")

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email address"""
        try:
            # Normalize email to lowercase for case-insensitive lookup
            normalized_email = email.strip().lower()
            
            with self.get_session() as session:
                user = session.query(User).filter(User.email == normalized_email).first()
                if user:
                    result = user.to_dict()
                    result["password_hash"] = user.password_hash  # Include for auth
                    return result
                return None
        except Exception as e:
            logger.error(f"Failed to get user by email: {e}")
            raise DatabaseError(f"Database query failed: {e}")

    async def get_user_by_phone(self, phone_number: str) -> Optional[Dict[str, Any]]:
        """Get user by phone number"""
        try:
            with self.get_session() as session:
                user = session.query(User).filter(User.phone_number == phone_number).first()
                if user:
                    result = user.to_dict()
                    result["password_hash"] = user.password_hash  # Include for auth
                    return result
                return None
        except Exception as e:
            logger.error(f"Failed to get user by phone: {e}")
            raise DatabaseError(f"Database query failed: {e}")

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            with self.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                return user.to_dict() if user else None
        except Exception as e:
            logger.error(f"Failed to get user by ID: {e}")
            raise DatabaseError(f"Database query failed: {e}")

    async def update_user(self, user_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update user information"""
        try:
            with self.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                if not user:
                    return None
                
                for key, value in update_data.items():
                    if hasattr(user, key) and key not in ['id', 'created_at']:
                        setattr(user, key, value)
                
                user.updated_at = datetime.utcnow()
                session.flush()
                return user.to_dict()
                
        except IntegrityError as e:
            logger.error(f"User update failed - duplicate entry: {e}")
            raise DatabaseError("Email or phone number already exists")
        except Exception as e:
            logger.error(f"Failed to update user: {e}")
            raise DatabaseError(f"Failed to update user: {e}")

    async def update_user_password_by_phone(self, phone_number: str, password_hash: str) -> bool:
        """Update user password by phone number"""
        try:
            with self.get_session() as session:
                user = session.query(User).filter(User.phone_number == phone_number).first()
                if not user:
                    return False
                
                user.password_hash = password_hash
                user.updated_at = datetime.utcnow()
                session.flush()
                logger.info(f"Password updated for user: {phone_number}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to update password: {e}")
            raise DatabaseError(f"Failed to update password: {e}")

    # Session operations
    async def create_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user session"""
        try:
            with self.get_session() as session:
                session_obj = UserSession(
                    user_id=session_data["user_id"],
                    token_hash=session_data["token_hash"],
                    expires_at=datetime.fromisoformat(session_data["expires_at"])
                )
                session.add(session_obj)
                session.flush()
                return session_obj.to_dict()
                
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise DatabaseError(f"Failed to create session: {e}")

    async def get_session_by_token(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Get active session by token hash"""
        try:
            with self.get_session() as session:
                session_obj = session.query(UserSession).filter(
                    UserSession.token_hash == token_hash,
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow()
                ).first()
                
                return session_obj.to_dict() if session_obj else None
                
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            raise DatabaseError(f"Failed to get session: {e}")

    async def invalidate_session(self, token_hash: str) -> bool:
        """Invalidate a specific session"""
        try:
            with self.get_session() as session:
                result = session.query(UserSession).filter(
                    UserSession.token_hash == token_hash
                ).update({"is_active": False})
                return result > 0
                
        except Exception as e:
            logger.error(f"Failed to invalidate session: {e}")
            raise DatabaseError(f"Failed to invalidate session: {e}")

    async def invalidate_user_sessions(self, user_id: str) -> bool:
        """Invalidate all sessions for a user"""
        try:
            with self.get_session() as session:
                session.query(UserSession).filter(
                    UserSession.user_id == user_id
                ).update({"is_active": False})
                logger.info(f"All sessions invalidated for user: {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to invalidate user sessions: {e}")
            raise DatabaseError(f"Failed to invalidate user sessions: {e}")

    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions (utility method)"""
        try:
            with self.get_session() as session:
                result = session.query(UserSession).filter(
                    UserSession.expires_at < datetime.utcnow()
                ).update({"is_active": False})
                logger.info(f"Cleaned up {result} expired sessions")
                return result
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0

    # OTP operations
    async def store_registration_otp(self, phone_number: str, otp_code: str, 
                                   expires_at: str, registration_data: Dict[str, Any]) -> str:
        """Store registration OTP"""
        try:
            with self.get_session() as session:
                # Clean up existing OTPs for this phone
                session.query(RegistrationOTP).filter(
                    RegistrationOTP.phone_number == phone_number
                ).delete()
                
                otp_obj = RegistrationOTP(
                    phone_number=phone_number,
                    otp_code=otp_code,
                    expires_at=datetime.fromisoformat(expires_at),
                    registration_data=registration_data
                )
                session.add(otp_obj)
                session.flush()
                logger.info(f"Registration OTP stored for: {phone_number}")
                return otp_obj.id
                
        except Exception as e:
            logger.error(f"Failed to store registration OTP: {e}")
            raise DatabaseError(f"Failed to store registration OTP: {e}")

    async def verify_registration_otp(self, phone_number: str, otp_code: str) -> Optional[Dict[str, Any]]:
        """Verify registration OTP"""
        try:
            with self.get_session() as session:
                otp_obj = session.query(RegistrationOTP).filter(
                    RegistrationOTP.phone_number == phone_number,
                    RegistrationOTP.otp_code == otp_code,
                    RegistrationOTP.is_used == False,
                    RegistrationOTP.expires_at > datetime.utcnow()
                ).first()
                
                if otp_obj:
                    otp_obj.is_used = True
                    session.flush()
                    
                    result = {
                        "id": otp_obj.id,
                        "phone_number": otp_obj.phone_number,
                        "registration_data": otp_obj.registration_data,
                        "created_at": otp_obj.created_at.isoformat()
                    }
                    logger.info(f"Registration OTP verified for: {phone_number}")
                    return result
                
                logger.warning(f"Registration OTP verification failed for: {phone_number}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to verify registration OTP: {e}")
            raise DatabaseError(f"Failed to verify registration OTP: {e}")

    async def store_forgot_password_otp(self, phone_number: str, otp_code: str, expires_at: str) -> bool:
        """Store forgot password OTP"""
        try:
            with self.get_session() as session:
                # Clean up existing OTPs for this phone
                session.query(ForgotPasswordOTP).filter(
                    ForgotPasswordOTP.phone_number == phone_number
                ).delete()
                
                otp_obj = ForgotPasswordOTP(
                    phone_number=phone_number,
                    otp_code=otp_code,
                    expires_at=datetime.fromisoformat(expires_at)
                )
                session.add(otp_obj)
                session.flush()
                logger.info(f"Forgot password OTP stored for: {phone_number}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to store forgot password OTP: {e}")
            raise DatabaseError(f"Failed to store forgot password OTP: {e}")

    async def verify_forgot_password_otp(self, phone_number: str, otp_code: str) -> bool:
        """Verify forgot password OTP"""
        try:
            with self.get_session() as session:
                otp_obj = session.query(ForgotPasswordOTP).filter(
                    ForgotPasswordOTP.phone_number == phone_number,
                    ForgotPasswordOTP.otp_code == otp_code,
                    ForgotPasswordOTP.is_used == False,
                    ForgotPasswordOTP.expires_at > datetime.utcnow()
                ).first()
                
                if otp_obj:
                    otp_obj.is_used = True
                    session.flush()
                    logger.info(f"Forgot password OTP verified for: {phone_number}")
                    return True
                
                logger.warning(f"Forgot password OTP verification failed for: {phone_number}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to verify forgot password OTP: {e}")
            raise DatabaseError(f"Failed to verify forgot password OTP: {e}")

    async def cleanup_expired_otps(self) -> Dict[str, int]:
        """Clean up expired OTPs (utility method)"""
        try:
            with self.get_session() as session:
                reg_otps = session.query(RegistrationOTP).filter(
                    RegistrationOTP.expires_at < datetime.utcnow(),
                    RegistrationOTP.is_used == False
                ).count()
                
                pwd_otps = session.query(ForgotPasswordOTP).filter(
                    ForgotPasswordOTP.expires_at < datetime.utcnow(),
                    ForgotPasswordOTP.is_used == False
                ).count()
                
                # Delete expired OTPs
                session.query(RegistrationOTP).filter(
                    RegistrationOTP.expires_at < datetime.utcnow()
                ).delete()
                
                session.query(ForgotPasswordOTP).filter(
                    ForgotPasswordOTP.expires_at < datetime.utcnow()
                ).delete()
                
                result = {"registration_otps": reg_otps, "password_otps": pwd_otps}
                logger.info(f"Cleaned up expired OTPs: {result}")
                return result
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired OTPs: {e}")
            return {"registration_otps": 0, "password_otps": 0}

    # Search History operations
    async def save_search_history(self, search_data: Dict[str, Any]) -> str:
        """Save search to history"""
        try:
            with self.get_session() as session:
                search_history = SearchHistory(
                    user_id=search_data["user_id"],
                    query=search_data["query"],
                    results=search_data["results"],
                    total_results=search_data.get("total_results", 0),
                    search_engine=search_data.get("search_engine", "DuckDuckGo")
                )
                session.add(search_history)
                session.flush()
                logger.info(f"Search history saved for user: {search_data['user_id']}")
                return search_history.id
                
        except Exception as e:
            logger.error(f"Failed to save search history: {e}")
            raise DatabaseError(f"Failed to save search history: {e}")

    async def get_search_history(self, user_id: str, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        """Get user's search history with pagination"""
        try:
            offset = (page - 1) * limit
            
            with self.get_session() as session:
                # Get total count
                total = session.query(SearchHistory).filter(
                    SearchHistory.user_id == user_id
                ).count()
                
                # Get paginated results
                searches = session.query(SearchHistory).filter(
                    SearchHistory.user_id == user_id
                ).order_by(SearchHistory.created_at.desc()).offset(offset).limit(limit).all()
                
                return {
                    "searches": [search.to_dict() for search in searches],
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "total_pages": (total + limit - 1) // limit
                }
                
        except Exception as e:
            logger.error(f"Failed to get search history: {e}")
            raise DatabaseError(f"Failed to get search history: {e}")

    async def get_search_by_id(self, search_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get specific search by ID"""
        try:
            with self.get_session() as session:
                search = session.query(SearchHistory).filter(
                    SearchHistory.id == search_id,
                    SearchHistory.user_id == user_id
                ).first()
                
                return search.to_dict() if search else None
                
        except Exception as e:
            logger.error(f"Failed to get search by ID: {e}")
            raise DatabaseError(f"Failed to get search by ID: {e}")

    async def delete_search_history(self, search_id: str, user_id: str) -> bool:
        """Delete specific search from history"""
        try:
            with self.get_session() as session:
                result = session.query(SearchHistory).filter(
                    SearchHistory.id == search_id,
                    SearchHistory.user_id == user_id
                ).delete()
                
                logger.info(f"Search history deleted: {search_id}")
                return result > 0
                
        except Exception as e:
            logger.error(f"Failed to delete search history: {e}")
            raise DatabaseError(f"Failed to delete search history: {e}")

    # Image History operations
    async def save_image_history(self, image_data: Dict[str, Any]) -> str:
        """Save generated image to history"""
        try:
            with self.get_session() as session:
                image_history = ImageHistory(
                    user_id=image_data["user_id"],
                    prompt=image_data["prompt"],
                    image_url=image_data["image_url"],
                    model=image_data.get("model", "flux"),
                    width=image_data.get("width", 1024),
                    height=image_data.get("height", 1024),
                    provider=image_data.get("provider", "Flux")
                )
                session.add(image_history)
                session.flush()
                logger.info(f"Image history saved for user: {image_data['user_id']}")
                return image_history.id
                
        except Exception as e:
            logger.error(f"Failed to save image history: {e}")
            raise DatabaseError(f"Failed to save image history: {e}")

    async def get_image_history(self, user_id: str, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        """Get user's image generation history with pagination"""
        try:
            offset = (page - 1) * limit
            
            with self.get_session() as session:
                # Get total count
                total = session.query(ImageHistory).filter(
                    ImageHistory.user_id == user_id
                ).count()
                
                # Get paginated results
                images = session.query(ImageHistory).filter(
                    ImageHistory.user_id == user_id
                ).order_by(ImageHistory.created_at.desc()).offset(offset).limit(limit).all()
                
                return {
                    "images": [image.to_dict() for image in images],
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "total_pages": (total + limit - 1) // limit
                }
                
        except Exception as e:
            logger.error(f"Failed to get image history: {e}")
            raise DatabaseError(f"Failed to get image history: {e}")

    async def get_image_by_id(self, image_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get specific image by ID"""
        try:
            with self.get_session() as session:
                image = session.query(ImageHistory).filter(
                    ImageHistory.id == image_id,
                    ImageHistory.user_id == user_id
                ).first()
                
                return image.to_dict() if image else None
                
        except Exception as e:
            logger.error(f"Failed to get image by ID: {e}")
            raise DatabaseError(f"Failed to get image by ID: {e}")

    async def delete_image_history(self, image_id: str, user_id: str) -> bool:
        """Delete specific image from history"""
        try:
            with self.get_session() as session:
                result = session.query(ImageHistory).filter(
                    ImageHistory.id == image_id,
                    ImageHistory.user_id == user_id
                ).delete()
                
                logger.info(f"Image history deleted: {image_id}")
                return result > 0
                
        except Exception as e:
            logger.error(f"Failed to delete image history: {e}")
            raise DatabaseError(f"Failed to delete image history: {e}")

# Create database instance
try:
    db = Database()
except Exception as e:
    logger.critical(f"Failed to initialize database: {e}")
    raise
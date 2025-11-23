# database.py - Hybrid solution that works with network issues

import httpx
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os
from dotenv import load_dotenv
import asyncio

load_dotenv()

class Database:
    def __init__(self):
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.secret_key = "sb_secret_1F_dmPHSbYTkkb7DBNlAtQ_wO9g6AAG"
        
        self.headers = {
            "apikey": self.secret_key,
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json"
        }
        
        # In-memory storage for when network fails
        self.users = {}
        self.sessions = {}
        self.registration_otps = {}
        self.forgot_password_otps = {}
        
        # Network status
        self.network_available = True
        
        print(f"🔗 Database: Hybrid mode (Supabase API + Local fallback)")
        
        # Add sample data for testing
        self._add_sample_data()

    def _add_sample_data(self):
        """Add sample data for immediate testing"""
        sample_user = {
            "id": str(uuid.uuid4()),
            "email": "test@example.com",
            "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeWWxBXXfBuSsHxNG",
            "phone_number": "+911234567890",
            "first_name": "Test",
            "last_name": "User",
            "role": "user",
            "is_active": True,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        self.users[sample_user["id"]] = sample_user
        print(f"✅ Sample user available: {sample_user['email']} (password: password123)")

    async def _test_network(self) -> bool:
        """Test if network connection is available"""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get("https://google.com")
                return response.status_code == 200
        except:
            return False

    async def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with fallback"""
        if not self.network_available:
            return None
            
        url = f"{self.supabase_url}/rest/v1/{endpoint}"
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                if method == "GET":
                    response = await client.get(url, headers=self.headers, params=params)
                elif method == "POST":
                    response = await client.post(url, headers=self.headers, json=data)
                elif method == "PATCH":
                    response = await client.patch(url, headers=self.headers, json=data, params=params)
                elif method == "DELETE":
                    response = await client.delete(url, headers=self.headers, params=params)
                
                if response.status_code in [200, 201]:
                    return response.json()
                else:
                    print(f"API Error {response.status_code}: {response.text}")
                    self.network_available = False
                    return None
                    
        except Exception as e:
            print(f"Network error, using local storage: {str(e)[:50]}")
            self.network_available = False
            return None

    # User operations with hybrid storage
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create user with hybrid storage"""
        user_id = str(uuid.uuid4())
        user_record = {
            "id": user_id,
            "email": user_data["email"],
            "password_hash": user_data["password_hash"],
            "phone_number": user_data["phone_number"],
            "first_name": user_data.get("first_name"),
            "last_name": user_data.get("last_name"),
            "role": user_data.get("role", "user"),
            "is_active": user_data.get("is_active", True),
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Try Supabase first
        result = await self._make_request("POST", "users", user_record)
        
        if result and len(result) > 0:
            print(f"✅ User created in Supabase: {user_data['email']}")
            return result[0]
        else:
            # Fallback to local storage
            self.users[user_id] = user_record
            print(f"✅ User created locally: {user_data['email']}")
            return user_record

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email with hybrid lookup"""
        # Try Supabase first
        result = await self._make_request("GET", "users", params={"email": f"eq.{email}"})
        
        if result and len(result) > 0:
            return result[0]
        
        # Fallback to local storage
        for user in self.users.values():
            if user["email"] == email:
                return user
        return None

    async def get_user_by_phone(self, phone_number: str) -> Optional[Dict[str, Any]]:
        """Get user by phone with hybrid lookup"""
        # Try Supabase first
        result = await self._make_request("GET", "users", params={"phone_number": f"eq.{phone_number}"})
        
        if result and len(result) > 0:
            return result[0]
        
        # Fallback to local storage
        for user in self.users.values():
            if user["phone_number"] == phone_number:
                return user
        return None

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID with hybrid lookup"""
        # Try Supabase first
        result = await self._make_request("GET", "users", params={"id": f"eq.{user_id}"})
        
        if result and len(result) > 0:
            return result[0]
        
        # Fallback to local storage
        return self.users.get(user_id)

    async def update_user_password_by_phone(self, phone_number: str, password_hash: str) -> bool:
        """Update password with hybrid storage"""
        update_data = {
            "password_hash": password_hash,
            "updated_at": datetime.now().isoformat()
        }
        
        # Try Supabase first
        result = await self._make_request("PATCH", "users", update_data, {"phone_number": f"eq.{phone_number}"})
        
        if result is not None:
            print(f"✅ Password updated in Supabase: {phone_number}")
            return True
        else:
            # Fallback to local storage
            for user in self.users.values():
                if user["phone_number"] == phone_number:
                    user["password_hash"] = password_hash
                    user["updated_at"] = datetime.now().isoformat()
                    print(f"✅ Password updated locally: {phone_number}")
                    return True
            return False

    # Session operations
    async def create_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create session with hybrid storage"""
        session_id = str(uuid.uuid4())
        session_record = {
            "id": session_id,
            **session_data,
            "created_at": datetime.now().isoformat()
        }
        
        # Try Supabase first
        result = await self._make_request("POST", "user_sessions", session_record)
        
        if result and len(result) > 0:
            return result[0]
        else:
            # Fallback to local storage
            self.sessions[session_id] = session_record
            return session_record

    async def get_session(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Get session with hybrid lookup"""
        # Try Supabase first
        params = {
            "token_hash": f"eq.{token_hash}",
            "is_active": "eq.true"
        }
        result = await self._make_request("GET", "user_sessions", params=params)
        
        if result and len(result) > 0:
            return result[0]
        
        # Fallback to local storage
        for session in self.sessions.values():
            if (session.get("token_hash") == token_hash and 
                session.get("is_active", True)):
                return session
        return None

    async def invalidate_session(self, token_hash: str) -> bool:
        """Invalidate session with hybrid storage"""
        # Try Supabase first
        update_data = {"is_active": False}
        result = await self._make_request("PATCH", "user_sessions", update_data, {"token_hash": f"eq.{token_hash}"})
        
        if result is not None:
            return True
        else:
            # Fallback to local storage
            for session in self.sessions.values():
                if session.get("token_hash") == token_hash:
                    session["is_active"] = False
                    return True
            return False

    async def invalidate_user_sessions(self, user_id: str) -> bool:
        """Invalidate all user sessions with hybrid storage"""
        # Try Supabase first
        update_data = {"is_active": False}
        result = await self._make_request("PATCH", "user_sessions", update_data, {"user_id": f"eq.{user_id}"})
        
        if result is not None:
            return True
        else:
            # Fallback to local storage
            for session in self.sessions.values():
                if session.get("user_id") == user_id:
                    session["is_active"] = False
            return True

    # OTP operations with hybrid storage
    async def store_registration_otp(self, phone_number: str, otp_code: str, expires_at: str, registration_data: Dict[str, Any]) -> str:
        """Store registration OTP with hybrid storage"""
        otp_id = str(uuid.uuid4())
        otp_record = {
            "id": otp_id,
            "phone_number": phone_number,
            "otp_code": otp_code,
            "expires_at": expires_at,
            "registration_data": registration_data,
            "is_used": False,
            "created_at": datetime.now().isoformat()
        }
        
        # Try Supabase first - delete existing
        await self._make_request("DELETE", "registration_otps", params={"phone_number": f"eq.{phone_number}"})
        
        # Try Supabase first - insert new
        result = await self._make_request("POST", "registration_otps", otp_record)
        
        if result and len(result) > 0:
            print(f"✅ Registration OTP stored in Supabase: {phone_number}")
            return result[0]["id"]
        else:
            # Fallback to local storage
            self.registration_otps[phone_number] = otp_record
            print(f"✅ Registration OTP stored locally: {phone_number}")
            return otp_id

    async def verify_registration_otp(self, phone_number: str, otp_code: str) -> Optional[Dict[str, Any]]:
        """Verify registration OTP with hybrid lookup"""
        current_time = datetime.now().isoformat()
        
        # Try Supabase first
        params = {
            "phone_number": f"eq.{phone_number}",
            "otp_code": f"eq.{otp_code}",
            "is_used": "eq.false",
            "expires_at": f"gt.{current_time}"
        }
        result = await self._make_request("GET", "registration_otps", params=params)
        
        if result and len(result) > 0:
            # Mark as used in Supabase
            update_data = {"is_used": True}
            await self._make_request("PATCH", "registration_otps", update_data, 
                                   {"phone_number": f"eq.{phone_number}", "otp_code": f"eq.{otp_code}"})
            print(f"✅ Registration OTP verified in Supabase: {phone_number}")
            return result[0]
        
        # Fallback to local storage
        if phone_number in self.registration_otps:
            otp_record = self.registration_otps[phone_number]
            if (otp_record["otp_code"] == otp_code and 
                not otp_record["is_used"] and
                otp_record["expires_at"] > current_time):
                otp_record["is_used"] = True
                print(f"✅ Registration OTP verified locally: {phone_number}")
                return otp_record
        
        print(f"❌ Registration OTP verification failed: {phone_number}")
        return None

    async def store_forgot_password_otp(self, phone_number: str, otp_code: str, expires_at: str) -> bool:
        """Store forgot password OTP with hybrid storage"""
        otp_record = {
            "id": str(uuid.uuid4()),
            "phone_number": phone_number,
            "otp_code": otp_code,
            "expires_at": expires_at,
            "is_used": False,
            "created_at": datetime.now().isoformat()
        }
        
        # Try Supabase first
        await self._make_request("DELETE", "forgot_password_otps", params={"phone_number": f"eq.{phone_number}"})
        result = await self._make_request("POST", "forgot_password_otps", otp_record)
        
        if result and len(result) > 0:
            print(f"✅ Password reset OTP stored in Supabase: {phone_number}")
            return True
        else:
            # Fallback to local storage
            self.forgot_password_otps[phone_number] = otp_record
            print(f"✅ Password reset OTP stored locally: {phone_number}")
            return True

    async def verify_forgot_password_otp(self, phone_number: str, otp_code: str) -> bool:
        """Verify forgot password OTP with hybrid lookup"""
        current_time = datetime.now().isoformat()
        
        # Try Supabase first
        params = {
            "phone_number": f"eq.{phone_number}",
            "otp_code": f"eq.{otp_code}",
            "is_used": "eq.false",
            "expires_at": f"gt.{current_time}"
        }
        result = await self._make_request("GET", "forgot_password_otps", params=params)
        
        if result and len(result) > 0:
            # Mark as used in Supabase
            update_data = {"is_used": True}
            await self._make_request("PATCH", "forgot_password_otps", update_data,
                                   {"phone_number": f"eq.{phone_number}", "otp_code": f"eq.{otp_code}"})
            print(f"✅ Password reset OTP verified in Supabase: {phone_number}")
            return True
        
        # Fallback to local storage
        if phone_number in self.forgot_password_otps:
            otp_record = self.forgot_password_otps[phone_number]
            if (otp_record["otp_code"] == otp_code and 
                not otp_record["is_used"] and
                otp_record["expires_at"] > current_time):
                otp_record["is_used"] = True
                print(f"✅ Password reset OTP verified locally: {phone_number}")
                return True
        
        print(f"❌ Password reset OTP verification failed: {phone_number}")
        return False

    # Required method
    async def update_user(self, user_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user with hybrid storage"""
        update_data["updated_at"] = datetime.now().isoformat()
        
        # Try Supabase first
        result = await self._make_request("PATCH", "users", update_data, {"id": f"eq.{user_id}"})
        
        if result and len(result) > 0:
            return result[0]
        else:
            # Fallback to local storage
            if user_id in self.users:
                self.users[user_id].update(update_data)
                return self.users[user_id]
            return {"id": user_id, **update_data}

# Create database instance
db = Database()
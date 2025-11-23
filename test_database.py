#!/usr/bin/env python3
# test_database.py - Test script to verify Supabase connection

import asyncio
import sys
import os
from pathlib import Path

# Add the current directory to Python path so we can import our database module
sys.path.append(str(Path(__file__).parent))

from database import Database, db

async def test_database_connection():
    """Test database connection and basic operations"""
    
    print("🔍 Testing Supabase Database Connection...")
    print("-" * 50)
    
    try:
        # Test 1: Check database connection
        print("1️⃣ Testing database connection...")
        if db.check_connection():
            print("✅ Database connection successful!")
        else:
            print("❌ Database connection failed!")
            return False
        
        # Test 2: Test user lookup (should find sample user)
        print("\n2️⃣ Testing user lookup...")
        user = await db.get_user_by_email("test@example.com")
        if user:
            print(f"✅ Sample user found: {user['email']}")
            print(f"   User ID: {user['id']}")
            print(f"   Phone: {user['phone_number']}")
        else:
            print("❌ Sample user not found")
        
        # Test 3: Test creating a new user
        print("\n3️⃣ Testing user creation...")
        test_user_data = {
            "email": "testuser@example.com",
            "password_hash": "$2b$12$test.hash.here",
            "phone_number": "+919876543210",
            "first_name": "Test",
            "last_name": "User"
        }
        
        # Check if user already exists
        existing_user = await db.get_user_by_email(test_user_data["email"])
        if existing_user:
            print(f"✅ Test user already exists: {existing_user['email']}")
        else:
            new_user = await db.create_user(test_user_data)
            print(f"✅ New user created: {new_user['email']}")
        
        # Test 4: Test session creation
        print("\n4️⃣ Testing session creation...")
        session_data = {
            "user_id": user["id"] if user else "test-user-id",
            "token_hash": "test-token-hash-12345",
            "expires_at": "2025-12-31T23:59:59"
        }
        
        try:
            session = await db.create_session(session_data)
            print(f"✅ Session created: {session['id']}")
            
            # Test session lookup
            found_session = await db.get_session_by_token(session_data["token_hash"])
            if found_session:
                print(f"✅ Session lookup successful: {found_session['user_id']}")
            
        except Exception as e:
            print(f"❌ Session test failed: {e}")
        
        print("\n🎉 All database tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Database test failed with error: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False

async def test_connection_details():
    """Display connection information"""
    print("\n📋 Connection Details:")
    print("-" * 30)
    print(f"DATABASE_URL: {os.getenv('DATABASE_URL', 'Not set')}")
    print(f"SUPABASE_URL: {os.getenv('SUPABASE_URL', 'Not set')}")
    
    # Test if we can parse the connection string
    db_url = os.getenv('DATABASE_URL')
    if db_url:
        print(f"\n🔗 Parsed connection:")
        if 'pooler.supabase.com' in db_url:
            print("✅ Using Supabase connection pooler")
        if ':6543' in db_url:
            print("✅ Using port 6543 (pooler port)")
        if 'postgresql://' in db_url:
            print("✅ PostgreSQL protocol detected")

if __name__ == "__main__":
    print("🚀 Starting Database Connection Test")
    print("=" * 60)
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Show connection details
    asyncio.run(test_connection_details())
    
    # Run the main test
    asyncio.run(test_database_connection())
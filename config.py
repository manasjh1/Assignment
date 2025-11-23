# config.py - Configuration with all secrets in .env

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database - Transaction Pooler (add this)
DATABASE_URL = os.getenv("DATABASE_URL")  # Transaction pooler connection string

# Database - Supabase Client (keep existing)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# JWT Settings (from .env)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Security
BCRYPT_ROUNDS = 12

# 2Factor SMS API Configuration (from .env)
TWOFACTOR_API_KEY = os.getenv("TWOFACTOR_API_KEY")
TWOFACTOR_BASE_URL = "https://2factor.in/API/V1"

# OTP Settings
OTP_EXPIRY_MINUTES = 5
OTP_LENGTH = 6

# Environment
DEBUG = os.getenv("DEBUG", "true").lower() == "true"
# main.py - Complete FastAPI application

import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from routes import router

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import your modules
try:
    from database import db, DatabaseError
    from routes import auth_router
    logger.info("All modules imported successfully")
except ImportError as e:
    logger.error(f"Failed to import modules: {e}")
    raise

# Create FastAPI app
app = FastAPI(
    title="Assignment Backend API",
    description="Authentication and user management API",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "https://assignment-react-sigma.vercel.app",
        "https://assignment-react-sigma.vercel.app/"
        ],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom exception handler for database errors
@app.exception_handler(DatabaseError)
async def database_exception_handler(request, exc):
    logger.error(f"Database error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"message": "Database operation failed", "success": False}
    )

app.include_router(router)
app.include_router(auth_router)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Application health check"""
    try:
        # Check database connection
        db_healthy = db.check_connection()
        
        return {
            "status": "healthy" if db_healthy else "unhealthy",
            "database": "connected" if db_healthy else "disconnected",
            "timestamp": "2025-11-23T20:00:00Z"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

# Startup event
@app.on_event("startup")
async def startup_event():
    """Application startup"""
    logger.info("Starting Assignment Backend API...")
    
    # Verify database connection
    if db.check_connection():
        logger.info("Database connection verified")
    else:
        logger.error("Database connection failed")
        raise Exception("Cannot start application without database")
    
    logger.info("Application startup complete")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown"""
    logger.info("Shutting down Assignment Backend API...")
    
@app.get("/")
async def root():
    return {
        "message": "Assignment Backend API is running",
        "docs_url": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    
    # Get configuration from environment
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=debug,
        access_log=True
    )
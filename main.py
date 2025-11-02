"""
AI-Powered Compliance Checking System - FastAPI Backend
Main application entry point with CORS and routing setup
"""
 
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import os
from dotenv import load_dotenv
 
# Load environment variables BEFORE importing route modules so services see them
load_dotenv()
from datetime import datetime
 
# Import route modules (after env loaded)
from routes.upload_routes import router as upload_router
from routes.scan_routes import router as scan_router
from routes.report_routes import router as report_router
from routes.auth_routes import router as auth_router
from routes.chatbot_routes import router as chatbot_router
# Initialize FastAPI app
app = FastAPI(
    title="AI-Powered Compliance Checker",
    description="Automated compliance scanning for HIPAA, GDPR, and DPDP regulations",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)
 
# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5000",  # Replit default port
        "https://8ee4f532-2ef3-44d3-8aa8-159bba9ea2f3-00-udqpxl8b0g8d.pike.replit.dev",
        "https://*.replit.dev",  # Allow all Replit subdomains
        "*"  # Allow all origins for development
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
 
# Include routers
app.include_router(upload_router, prefix="/api/upload", tags=["Upload"])
app.include_router(scan_router, prefix="/api/scan", tags=["Scan"])
app.include_router(report_router, prefix="/api/report", tags=["Report"])
app.include_router(auth_router, prefix="/api/auth", tags=["Auth"])
app.include_router(chatbot_router, prefix="/api/chatbot", tags=["Chatbot"])
 
# Global state for storing scan results (in-memory for demo)
scan_history = []
current_scan_id = 0
 
@app.get("/")
async def root():
    """Root endpoint with basic API information"""
    return {
        "message": "AI-Powered Compliance Checker API",
        "version": "1.0.0",
        "status": "active",
        "endpoints": {
            "health": "/ping",
            "upload": "/api/upload",
            "scan": "/api/scan",
            "report": "/api/report",
            "docs": "/docs"
        }
    }
 
@app.get("/ping")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "compliance-checker-api"
    }
 
@app.get("/api/history")
async def get_scan_history():
    """Get scan history with pipeline tracking (bonus feature for hackathon)"""
    try:
        # Import here to avoid circular imports
        from services.scan_tracker import ScanTracker
       
        scan_tracker = ScanTracker()
        pipelines = scan_tracker.get_all_pipelines()
       
        # Format scan history with pipeline information
        history = []
        for pipeline in pipelines[:10]:  # Get last 10 pipelines
            history.append({
                "pipeline_id": pipeline.get("pipeline_id", "unknown"),
                "file_id": pipeline.get("file_id", "unknown"),
                "scan_type": pipeline.get("scan_type", "comprehensive"),
                "timestamp": pipeline.get("created_at", "unknown"),
                "status": pipeline.get("status", "unknown"),
                "total_scans": pipeline.get("total_scans", 0),
                "current_scan_id": pipeline.get("current_scan_id"),
                "metadata": pipeline.get("metadata", {})
            })
       
        return {
            "total_pipelines": len(pipelines),
            "pipelines": history,
            "message": "Pipeline-based scan history"
        }
    except Exception as e:
        return {
            "total_pipelines": 0,
            "pipelines": [],
            "error": f"Failed to load scan history: {str(e)}"
        }
 
@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Custom 404 handler"""
    return JSONResponse(
        status_code=404,
        content={"error": "Endpoint not found", "path": str(request.url)}
    )
 
@app.exception_handler(500)
async def internal_error_handler(request, exc):
    """Custom 500 handler"""
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "message": "Please try again later"}
    )
 
if __name__ == "__main__":
    # Create uploads directory if it doesn't exist
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
   
    # Get port from environment variable or use default
    port = int(os.getenv("PORT", 8000))
   
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",  # Allow external connections for Replit
        port=port,       # Use port from environment or default 8000
        reload=False,    # Disable reload to avoid issues
        log_level="info"
    )
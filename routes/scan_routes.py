
"""
Scan Routes - Handle compliance scanning operations
"""
 
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse, FileResponse
from datetime import datetime
import uuid
from services.scan_service import ScanService
import asyncio
from services.scan_tracker import ScanTracker
from services.ai_service import AIService
from services.pdf_service import PDFService
from routes.auth_routes import require_role, get_current_user
import os
 
router = APIRouter()
 
@router.post("/reset")
async def reset_scans(current=Depends(require_role("admin"))):
    """Admin-only: wipe all scan history (global & per-user stored scan JSON files)."""
    scan_service = ScanService()
    scan_service.reset_all_scans()
    return {"success": True, "message": "All scan data cleared"}
 
@router.post("/start/{file_id}")
async def start_scan(file_id: str, current=Depends(get_current_user)):
    """
    Start a compliance scan for an uploaded file or repository
   
    Args:
        file_id: The file or repository ID to scan
   
    Returns:
        JSON response with pipeline ID, scan ID and initial status
    """
    try:
        # Initialize services
        scan_service = ScanService()
        scan_tracker = ScanTracker()
       
        # Create pipeline for this scan
        pipeline_id = scan_tracker.create_scan_pipeline(file_id, "comprehensive")
       
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
       
        # Start tracking the scan
        scan_tracker.start_scan(pipeline_id, scan_id)
       
        # Start async task so response returns immediately
        asyncio.create_task(scan_service.start_scan(file_id, scan_id, username=current["username"]))
 
        initial_status = scan_service.scan_status.get(scan_id, {})
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "pipeline_id": pipeline_id,
                "scan_id": scan_id,
                "file_id": file_id,
                "scan_started_at": datetime.now().isoformat(),
                "status": initial_status.get("status", "in_progress"),
                "phase": initial_status.get("phase", "scanning"),
                "progress": initial_status.get("progress", 0),
                "total_files": initial_status.get("total_files", 0),
                "processed_files": initial_status.get("processed_files", 0),
                "message": "Compliance scan started"
            }
        )
       
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start scan: {str(e)}"
        )
 
@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    Get the status of a running or completed scan
   
    Args:
        scan_id: The scan ID to check
   
    Returns:
        JSON response with scan status and progress
    """
    try:
        scan_service = ScanService()
        status = await scan_service.get_scan_status(scan_id)
        if not status:
            raise HTTPException(status_code=404, detail="Scan not found")
        # Provide explicit files_completed alias for frontend clarity
        status_payload = dict(status)
        status_payload["files_completed"] = status_payload.get("processed_files", 0)
        return JSONResponse(status_code=200, content=status_payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan status: {str(e)}")
@router.get("/files/{scan_id}")
async def get_scan_files(scan_id: str):
    """Return list of filenames scanned so far (for live feed)."""
    try:
        scan_service = ScanService()
        results = scan_service.get_scan_results(scan_id)
        if not results:
            # Partial progress: look at status if exists
            status = scan_service.scan_status.get(scan_id)
            processed = status.get("processed_files", 0) if status else 0
            return JSONResponse(status_code=200, content={"success": True, "files": [], "processed": processed})
        files = [f.get("filename") or f.get("file_path") for f in results.get("files_scanned", [])]
        return JSONResponse(status_code=200, content={"success": True, "files": files, "processed": len(files)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scanned files: {e}")
 
@router.get("/results/{scan_id}")
def get_scan_results(scan_id: str):
    """
    Get the detailed results of a completed scan
   
    Args:
        scan_id: The scan ID to get results for
   
    Returns:
        JSON response with detailed scan results
    """
    try:
        scan_service = ScanService()
        results = scan_service.get_scan_results(scan_id)
       
        if not results:
            raise HTTPException(
                status_code=404,
                detail="Scan results not found"
            )
       
        return JSONResponse(
            status_code=200,
            content=results
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get scan results: {str(e)}"
        )
 
@router.post("/quick-scan")
async def quick_scan(file_id: str, current=Depends(get_current_user)):
    """
    Perform a quick compliance scan and return immediate results
   
    Args:
        file_id: The file or repository ID to scan
   
    Returns:
        JSON response with immediate scan results
    """
    try:
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
       
        # Initialize scan service
        scan_service = ScanService()
       
        # Perform quick scan
        results = await scan_service.perform_quick_scan(file_id, scan_id, username=current["username"])
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "scan_id": scan_id,
                "file_id": file_id,
                "scan_completed_at": datetime.now().isoformat(),
                "status": "completed",
                "results": results,
                "message": "Quick scan completed successfully"
            }
        )
       
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to perform quick scan: {str(e)}"
        )
 
@router.get("/my-scans")
async def my_scans(current=Depends(get_current_user)):
    """
    Get all compliance scans initiated by the current user
   
    Returns:
        JSON response with user's scans
    """
    try:
        scan_service = ScanService()
        user_scans = scan_service.get_user_scans(current["username"])
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "total": len(user_scans),
                "scans": user_scans
            }
        )
       
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get user scans: {e}"
        )
 
@router.get("/stats/me")
async def my_scan_stats(current=Depends(get_current_user)):
    """Return aggregated metrics for current user (for dashboard)."""
    try:
        scan_service = ScanService()
        stats = scan_service.compute_user_stats(current['username'])
        return {"success": True, "stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to compute stats: {e}")
 
@router.get("/pipelines")
async def get_all_pipelines():
    """
    Get all scan pipelines with their status and history
   
    Returns:
        JSON response with all pipelines
    """
    try:
        scan_tracker = ScanTracker()
        pipelines = scan_tracker.get_all_pipelines()
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "total_pipelines": len(pipelines),
                "pipelines": pipelines
            }
        )
       
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get pipelines: {str(e)}"
        )
 
@router.get("/pipeline/{pipeline_id}")
async def get_pipeline(pipeline_id: str):
    """
    Get details of a specific pipeline
   
    Args:
        pipeline_id: The pipeline ID
   
    Returns:
        JSON response with pipeline details
    """
    try:
        scan_tracker = ScanTracker()
        pipeline = scan_tracker.get_pipeline(pipeline_id)
       
        if not pipeline:
            raise HTTPException(
                status_code=404,
                detail="Pipeline not found"
            )
       
        return JSONResponse(
            status_code=200,
            content=pipeline
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get pipeline: {str(e)}"
        )
 
@router.post("/ai-summary/{scan_id}")
def generate_ai_summary(scan_id: str, current=Depends(require_role("auditor", "admin"))):
    """
    Generate AI-powered summary for a scan report
    """
    try:
        # Get scan results
        scan_service = ScanService()
        scan_results = scan_service.get_scan_results(scan_id)
       
        if not scan_results:
            raise HTTPException(
                status_code=404,
                detail=f"Scan results not found for scan ID: {scan_id}"
            )
       
        # Generate AI summary (simplified for demo performance)
        ai_service = AIService()
        ai_response = ai_service.generate_compliance_summary(scan_results)
       
        if ai_response["success"]:
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "ai_success": True,
                    "scan_id": scan_id,
                    "ai_summary": ai_response["ai_summary"],
                    "model_used": ai_response["model_used"],
                    "generated_at": ai_response["generated_at"]
                }
            )
        else:
            # Return fallback summary if AI fails
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "ai_success": False,
                    "scan_id": scan_id,
                    "ai_summary": ai_response["fallback_summary"],
                    "model_used": "fallback",
                    "generated_at": datetime.now().isoformat(),
                    "note": "AI service unavailable, showing fallback summary"
                }
            )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate AI summary: {str(e)}"
        )
 
@router.get("/export-pdf/{scan_id}")
def export_pdf_report(scan_id: str, include_ai: bool = True, current=Depends(require_role("auditor", "admin"))):
    """
    Export scan report as PDF
    """
    try:
        # Get scan results
        scan_service = ScanService()
        scan_results = scan_service.get_scan_results(scan_id)
       
        if not scan_results:
            raise HTTPException(
                status_code=404,
                detail=f"Scan results not found for scan ID: {scan_id}"
            )
       
        # Try to get AI summary if requested
        ai_summary = None
        if include_ai:
            try:
                ai_service = AIService()
                ai_response = ai_service.generate_compliance_summary(scan_results)
                if ai_response["success"]:
                    ai_summary = ai_response["ai_summary"]
            except Exception as e:
                print(f"Failed to generate AI summary for PDF: {e}")
                # Continue without AI summary
       
        # Generate PDF with AI summary
        pdf_service = PDFService()
        pdf_path = pdf_service.generate_compliance_report(scan_results, ai_summary)
       
        # Return PDF file
        return FileResponse(
            path=pdf_path,
            media_type='application/pdf',
            filename=f"compliance_report_{scan_id[:8]}.pdf"
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF report: {str(e)}"
        )
 
 
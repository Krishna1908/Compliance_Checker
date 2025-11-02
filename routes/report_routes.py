 
"""
Report Routes - Handle audit report generation and AI summaries
"""
 
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse, FileResponse
from datetime import datetime
from services.ai_service import AIService
from services.ai_usage_service import ai_usage_service
from services.scan_service import ScanService
from services.pdf_service import PDFService
from utils.report_generator import ReportGenerator
from services.email_service import EmailService
from routes.auth_routes import require_role
import tempfile
from email.mime.text import MIMEText
import json
import os
 
router = APIRouter()
 
# Helper to pick the correct recipient email from the current user context
def _resolve_recipient(current) -> str:
    """Return an email for the current user or fallback.
    Preference order:
    1. current['email'] if looks like email
    2. current['username'] if looks like email
    3. DEFAULT_REPORT_EMAIL env var or dev@example.com
    """
    try:
        if isinstance(current, dict):
            email_val = current.get('email')
            if email_val and '@' in email_val:
                return email_val
            user_val = current.get('username')
            if user_val and '@' in user_val:
                return user_val
        return os.getenv('DEFAULT_REPORT_EMAIL', 'dev@example.com')
    except Exception:
        return os.getenv('DEFAULT_REPORT_EMAIL', 'dev@example.com')
 
@router.get("/ai/probe")
async def ai_probe(current=Depends(require_role("auditor", "admin"))):
    """Quick health probe to verify OpenAI / Azure OpenAI credentials without full summary.
 
    Returns success flag and error if any."""
    try:
        svc = AIService()
        result = svc.quick_probe()
        return JSONResponse(status_code=200, content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Probe failed: {e}")
 
@router.get("/ai/usage")
async def ai_usage(current=Depends(require_role("auditor", "admin"))):
    """Return aggregate AI usage metrics for dashboard / assistant panels."""
    try:
        return JSONResponse(status_code=200, content={"success": True, "metrics": ai_usage_service.get_usage()})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load AI usage: {e}")
 
@router.get("/ai/usage-lite")
async def ai_usage_lite():
    """Public lightweight AI usage metrics (no auth, redacts error details)."""
    try:
        metrics = ai_usage_service.get_usage()
        lite = {
            "total_calls": metrics.get("total_calls"),
            "success_rate": metrics.get("success_rate"),
            "fallback_rate": metrics.get("fallback_rate"),
            "last_model": metrics.get("last_model"),
            "last_call_time": metrics.get("last_call_time")
        }
        return JSONResponse(status_code=200, content={"success": True, "metrics": lite})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load lite usage: {e}")
 
@router.get("/generate/{scan_id}")
async def generate_report(scan_id: str):
    """
    Generate a comprehensive audit report with AI summary
   
    Args:
        scan_id: The scan ID to generate report for
   
    Returns:
        JSON response with detailed audit report
    """
    try:
        # Initialize services
        ai_service = AIService()
        report_generator = ReportGenerator()
       
        # Generate the report
        report = await report_generator.generate_comprehensive_report(scan_id)
       
        if not report:
            raise HTTPException(
                status_code=404,
                detail="Scan results not found for report generation"
            )
       
        # Generate AI summary
        ai_summary = await ai_service.generate_audit_summary(report)
       
        # Combine report with AI summary
        comprehensive_report = {
            **report,
            "ai_summary": ai_summary,
            "generated_at": datetime.now().isoformat(),
            "report_type": "comprehensive_audit"
        }
       
        return JSONResponse(
            status_code=200,
            content=comprehensive_report
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {str(e)}"
        )
 
@router.get("/summary/{scan_id}")
async def get_ai_summary(scan_id: str):
    """
    Get AI-generated summary for a scan
   
    Args:
        scan_id: The scan ID to get summary for
   
    Returns:
        JSON response with AI-generated summary and recommendations
    """
    try:
        ai_service = AIService()
        summary = await ai_service.generate_summary_with_ai(scan_id)
       
        if not summary:
            raise HTTPException(
                status_code=404,
                detail="Scan results not found for summary generation"
            )
       
        # TODO: Attach PDF generation + email sending here when user triggers “Generate AI Summary” from UI.
        return JSONResponse(status_code=200, content={
            "success": True,
            "scan_id": scan_id,
            "ai_summary": summary,
            "generated_at": datetime.now().isoformat(),
            "message": "AI summary generated successfully"
        })
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate AI summary: {str(e)}"
        )
 
@router.post("/summary-send/{scan_id}")
async def generate_summary_and_email(scan_id: str, current=Depends(require_role("auditor", "admin"))):
    """Generate AI summary then export PDF and email to current user.
 
    Frontend should call this when user clicks the global AI Summary action that requires email dispatch.
    Returns JSON with status; email may be simulated if SMTP not configured.
    """
    try:
        ai_service = AIService()
        scan_service = ScanService()
        pdf_service = PDFService()
        email_service = EmailService()
 
        # Get base scan results (for PDF context)
        scan_results = scan_service.get_scan_results(scan_id)
        if not scan_results:
            raise HTTPException(status_code=404, detail="Scan results not found for summary/email")
 
        # Generate AI summary (async path uses different service methods; reuse existing summary generator)
        summary = await ai_service.generate_summary_with_ai(scan_id)
        if not summary:
            raise HTTPException(status_code=404, detail="AI summary generation failed")
 
        # Build PDF including summary (executive + recommendations mapping)
        ai_summary_for_pdf = {
            "executive_summary": summary.get("executive_summary"),
            "key_findings": summary.get("key_findings", []),
            "recommendations": summary.get("recommendations", []),
            "next_steps": summary.get("next_steps", [])
        }
        pdf_path = pdf_service.generate_compliance_report(scan_results, ai_summary_for_pdf)
 
        # Determine recipient cleanly
        to_email = _resolve_recipient(current)
 
        subject = f"SecureGuard Pro Compliance AI Summary • {scan_id[:8]}"
        body_lines = [
            f"Compliance AI Summary for scan {scan_id}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "", "Executive Summary:", summary.get("executive_summary", "(none)"), "",
            "Top Recommendations:" ]
        for rec in (summary.get("recommendations", [])[:5] or []):
            body_lines.append(f" - {rec}")
        body_lines.append("\nFull detailed PDF attached.")
        body = "\n".join(body_lines)
 
        email_sent = email_service.send_report_email(to_email, subject, body, pdf_path)
 
        return JSONResponse(status_code=200, content={
            "success": True,
            "scan_id": scan_id,
            "ai_summary": summary,
            "ai_success": summary.get("ai_success", False),
            "pdf_attachment": os.path.basename(pdf_path),
            "email_recipient": to_email,
            "email_sent": email_sent,
            "smtp_configured": email_service.enabled,
            "generated_at": datetime.now().isoformat(),
            "message": "AI summary generated and email dispatched" if email_sent else "AI summary generated (email simulated / not configured)"
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed summary+email: {str(e)}")
 
@router.get("/summary-send/{scan_id}")
async def generate_summary_and_email_get(scan_id: str, current=Depends(require_role("auditor", "admin"))):
    """GET convenience wrapper for users triggering from browser/location bar. Mirrors POST behavior."""
    return await generate_summary_and_email(scan_id, current)
 
@router.post("/email-pdf/{scan_id}")
async def email_existing_pdf(scan_id: str, current=Depends(require_role("auditor", "admin"))):
    """Generate (or re-generate) the compliance PDF WITHOUT re-running AI summary and email it.
 
    This matches user request: AI summary already shown; just send the PDF attachment to user's email.
    """
    try:
        scan_service = ScanService()
        pdf_service = PDFService()
        email_service = EmailService()
        scan_results = scan_service.get_scan_results(scan_id)
        if not scan_results:
            raise HTTPException(status_code=404, detail="Scan results not found for PDF email")
        # Build PDF quickly without AI (pass None)
        pdf_path = pdf_service.generate_compliance_report(scan_results, None)
 
        # Recipient
        to_email = _resolve_recipient(current)
        subject = f"SecureGuard Pro Report • {scan_id[:8]}"
        body = f"Compliance report for scan {scan_id} attached. Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        email_sent = email_service.send_report_email(to_email, subject, body, pdf_path)
        return JSONResponse(status_code=200, content={
            "success": True,
            "scan_id": scan_id,
            "pdf_attachment": os.path.basename(pdf_path),
            "email_recipient": to_email,
            "email_sent": email_sent,
            "smtp_configured": email_service.enabled,
            "message": "PDF emailed" if email_sent else "PDF generated (email not configured)"
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to email PDF: {str(e)}")
 
@router.get("/email-pdf/{scan_id}")
async def email_existing_pdf_get(scan_id: str, current=Depends(require_role("auditor", "admin"))):
    return await email_existing_pdf(scan_id, current)
 
@router.get("/recommendations/{scan_id}")
async def get_recommendations(scan_id: str):
    """
    Get AI-generated remediation recommendations
   
    Args:
        scan_id: The scan ID to get recommendations for
   
    Returns:
        JSON response with actionable recommendations
    """
    try:
        ai_service = AIService()
        recommendations = await ai_service.generate_recommendations(scan_id)
       
        if not recommendations:
            raise HTTPException(
                status_code=404,
                detail="Scan results not found for recommendation generation"
            )
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "scan_id": scan_id,
                "recommendations": recommendations,
                "generated_at": datetime.now().isoformat(),
                "message": "Recommendations generated successfully"
            }
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate recommendations: {str(e)}"
        )
 
@router.get("/export/{scan_id}")
async def export_report(scan_id: str, format: str = "json"):
    """
    Export report in various formats
   
    Args:
        scan_id: The scan ID to export
        format: Export format (json, csv, pdf)
   
    Returns:
        JSON response with export information
    """
    try:
        if format not in ["json", "csv", "pdf"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid format. Supported formats: json, csv, pdf"
            )
       
        report_generator = ReportGenerator()
        export_data = await report_generator.export_report(scan_id, format)
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "scan_id": scan_id,
                "format": format,
                "export_data": export_data,
                "exported_at": datetime.now().isoformat(),
                "message": f"Report exported successfully in {format.upper()} format"
            }
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export report: {str(e)}"
        )
 
@router.get("/download/{scan_id}")
async def download_report(scan_id: str, format: str = "json"):
    """
    Download report file directly
   
    Args:
        scan_id: The scan ID to download
        format: File format (json, csv, pdf)
   
    Returns:
        File download response
    """
    try:
        if format not in ["json", "csv", "pdf"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid format. Supported formats: json, csv, pdf"
            )
       
        # Generate the report first
        report_generator = ReportGenerator()
        report = await report_generator.generate_comprehensive_report(scan_id)
       
        # Export the report
        export_data = await report_generator.export_report(scan_id, format)
       
        if "error" in export_data:
            raise HTTPException(
                status_code=500,
                detail=export_data["error"]
            )
       
        file_path = export_data["file_path"]
        filename = export_data["filename"]
       
        # Check if file exists
        if not os.path.exists(file_path):
            raise HTTPException(
                status_code=404,
                detail="Report file not found"
            )
       
        # Return file for download
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type='application/octet-stream'
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to download report: {str(e)}"
        )
 
 
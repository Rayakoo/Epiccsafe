from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any
from datetime import datetime
import supabase_client as db
from reports_helper import generate_ticket_id, is_blacklisted, is_whitelisted, log_report_activity
from risk_score import calculate_risk_score

router = APIRouter(prefix="/reports", tags=["Reports"])

class SubmitReportRequest(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    url: str = Field(..., description="URL to report")
    description: Optional[str] = Field(None, description="Report description")
    source: str = Field(..., description="Source of report (e.g., 'web', 'extension')")

class SubmitReportResponse(BaseModel):
    ticket_id: str
    status: str
    risk_score: int

class CheckStatusResponse(BaseModel):
    status: str
    final_status: Optional[str]
    created_at: datetime
    resolved_at: Optional[datetime]

@router.post("/submit", response_model=SubmitReportResponse, status_code=201)
async def submit_report(request: SubmitReportRequest):
    """
    Submit a new report for a suspicious URL
    
    - **email**: Reporter's email address
    - **url**: URL to be reported
    - **description**: Optional description of the issue
    - **source**: Source of the report (web, extension, etc.)
    
    Returns ticket_id for tracking the report
    """
    try:
        # Generate ticket ID
        ticket_id = generate_ticket_id()
        
        # Calculate risk score
        risk_score = calculate_risk_score(request.url)
        
        # Check if URL is blacklisted/whitelisted
        if is_blacklisted(request.url):
            final_status = "BLACKLISTED"
        elif is_whitelisted(request.url):
            final_status = "WHITELISTED"
        else:
            final_status = None
        
        # Prepare report data
        report_data = {
            "id": ticket_id,
            "email": request.email,
            "url": request.url,
            "description": request.description,
            "risk_score": risk_score,
            "status": "SUBMITTED",
            "final_status": final_status,
            "source": request.source,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Insert into database
        result = db.supabase_admin.table("reports").insert(report_data).execute()
        
        if not result.data:
            raise HTTPException(status_code=500, detail="Failed to submit report")
        
        return SubmitReportResponse(
            ticket_id=ticket_id,
            status="SUBMITTED",
            risk_score=risk_score
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error submitting report: {str(e)}")

@router.get("/status/{ticket_id}", response_model=CheckStatusResponse)
async def check_report_status(ticket_id: str):
    """
    Check the status of a submitted report
    
    - **ticket_id**: The ticket ID received when submitting the report
    
    Returns current status and timestamps
    """
    try:
        result = db.supabase_admin.table("reports").select("*").eq("id", ticket_id).execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="Report not found")
        
        report = result.data[0]
        
        return CheckStatusResponse(
            status=report.get("status"),
            final_status=report.get("final_status"),
            created_at=datetime.fromisoformat(report.get("created_at")),
            resolved_at=datetime.fromisoformat(report.get("resolved_at")) if report.get("resolved_at") else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking status: {str(e)}")

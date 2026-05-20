from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any
from datetime import datetime
import supabase_client as db
from reports_helper import generate_ticket_id, is_blacklisted, is_whitelisted, log_report_activity
from scan import scan_url_unified, ScanRequest

router = APIRouter(prefix="/reports", tags=["Reports"])

class SubmitReportRequest(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    url: str = Field(..., description="URL to report")
    description: Optional[str] = Field(None, description="Report description")
    source: str = Field(..., description="Source of report (e.g., 'web', 'extension')")
    age: Optional[int] = Field(None, description="Age of the reporter")
    province: Optional[str] = Field(None, description="Province of the reporter")
    reporter_name: Optional[str] = Field(None, description="Name of the reporter")
    phone_number: Optional[str] = Field(None, description="Phone number of the reporter")

class SubmitReportResponse(BaseModel):
    ticket_id: str
    status: str
    risk_score: int

class CheckStatusResponse(BaseModel):
    id: str
    email: str
    url: str
    description: Optional[str]
    risk_score: Optional[int]
    status: str
    final_status: Optional[str]
    source: Optional[str]
    age: Optional[int]
    province: Optional[str]
    reporter_name: Optional[str]
    phone_number: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]
    resolved_at: Optional[datetime]

@router.post("/submit", response_model=SubmitReportResponse, status_code=201)
async def submit_report(request: SubmitReportRequest):
    """
    Submit a new report for a suspicious URL
    
    - **email**: Reporter's email address
    - **url**: URL to be reported
    - **description**: Optional description of the issue
    - **source**: Source of the report (web, extension, etc.)
    - **age**: Optional age of the reporter
    - **province**: Optional province of the reporter
    - **reporter_name**: Optional name of the reporter
    - **phone_number**: Optional phone number of the reporter
    
    Returns ticket_id for tracking the report
    """
    try:
        # Generate ticket ID
        ticket_id = generate_ticket_id()
        
        # Prepare initial report data
        report_data = {
            "id": ticket_id,
            "email": request.email,
            "url": request.url,
            "description": request.description,
            "source": request.source,
            "age": request.age,
            "province": request.province,
            "reporter_name": request.reporter_name,
            "phone_number": request.phone_number,
            "status": "OPEN",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Insert into database
        result = db.supabase_admin.table("reports").insert(report_data).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=500,
                detail=f"[REPORTS][SUBMIT] Database tidak mengembalikan data setelah insert untuk ticket '{ticket_id}'"
            )
        
        # Hit scan endpoint with the URL and save results
        risk_score = 0
        try:
            scan_result = scan_url_unified(ScanRequest(url=request.url))
            risk_score = scan_result.score

            if scan_result.reason == "blacklisted":
                final_status = "BLACKLISTED"
            elif scan_result.reason == "whitelisted":
                final_status = "WHITELISTED"
            elif scan_result.prediction == 0:
                final_status = "SAFE"
            else:
                final_status = None

            db.supabase_admin.table("reports").update({
                "risk_score": risk_score,
                "final_status": final_status,
                "updated_at": datetime.now().isoformat()
            }).eq("id", ticket_id).execute()
        except Exception as scan_err:
            print(f"[REPORTS][SUBMIT] Scan error untuk URL '{request.url}': {scan_err}")
        
        return SubmitReportResponse(
            ticket_id=ticket_id,
            status="OPEN",
            risk_score=risk_score
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"[REPORTS][SUBMIT] Gagal submit laporan untuk URL '{request.url}': {str(e)}"
        )

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
            raise HTTPException(
                status_code=404,
                detail=f"[REPORTS][STATUS] Laporan dengan ticket '{ticket_id}' tidak ditemukan di database"
            )
        
        report = result.data[0]
        
        return CheckStatusResponse(
            id=report.get("id"),
            email=report.get("email"),
            url=report.get("url"),
            description=report.get("description"),
            risk_score=report.get("risk_score"),
            status=report.get("status"),
            final_status=report.get("final_status"),
            source=report.get("source"),
            age=report.get("age"),
            province=report.get("province"),
            reporter_name=report.get("reporter_name"),
            phone_number=report.get("phone_number"),
            created_at=datetime.fromisoformat(report.get("created_at")),
            updated_at=datetime.fromisoformat(report.get("updated_at")) if report.get("updated_at") else None,
            resolved_at=datetime.fromisoformat(report.get("resolved_at")) if report.get("resolved_at") else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"[REPORTS][STATUS] Gagal memeriksa status untuk ticket '{ticket_id}': {str(e)}"
        )

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, date
import supabase_client as db
from reports_helper import log_report_activity, is_blacklisted, is_whitelisted

router = APIRouter(prefix="/admin", tags=["Admin"])

# Models
class UpdateStatusRequest(BaseModel):
    report_id: str = Field(..., description="Report ID to update")
    new_status: str = Field(..., description="New status (SUBMITTED, IN_REVIEW, RESOLVED, etc.)")
    final_status: str = Field(..., description="Final status (BLACKLISTED, WHITELISTED, SAFE, etc.)")
    admin_id: str = Field(..., description="Admin ID making the change")
    note: Optional[str] = Field(None, description="Optional note for the change")

class AddUrlRequest(BaseModel):
    url: str = Field(..., description="URL to add")
    admin_id: str = Field(..., description="Admin ID")

class ReportResponse(BaseModel):
    id: str
    email: str
    url: str
    description: Optional[str]
    risk_score: int
    status: str
    final_status: Optional[str]
    source: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]

@router.get("/reports", response_model=List[ReportResponse])
async def get_all_reports(status: Optional[str] = Query(None, description="Filter by status")):
    """
    Get all reports with optional status filter
    
    - **status**: Optional filter by report status
    """
    try:
        query = db.supabase_admin.table("reports").select("*")
        
        if status:
            query = query.eq("status", status)
        
        result = query.order("created_at", desc=True).execute()
        
        return result.data or []
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"[ADMIN][REPORTS] Gagal mengambil daftar laporan (filter status='{status}'): {str(e)}")


@router.get("/reports/filter", response_model=List[ReportResponse])
async def get_reports(
    status: Optional[str] = Query(None, description="Filter by status"),
    email: Optional[str] = Query(None, description="Filter by reporter email"),
    source: Optional[str] = Query(None, description="Filter by source"),
    date_from: Optional[date] = Query(None, description="Filter from date (YYYY-MM-DD)"),
    date_to: Optional[date] = Query(None, description="Filter to date (YYYY-MM-DD)")
):
    """
    Get reports with multiple filters
    
    - **status**: Filter by status
    - **email**: Filter by reporter email
    - **source**: Filter by source
    - **date_from**: Filter reports from this date
    - **date_to**: Filter reports until this date
    """
    try:
        query = db.supabase_admin.table("reports").select("*")
        
        if status:
            query = query.eq("status", status)
        if email:
            query = query.eq("email", email)
        if source:
            query = query.eq("source", source)
        if date_from:
            query = query.gte("created_at", date_from.isoformat())
        if date_to:
            query = query.lte("created_at", date_to.isoformat())
        
        result = query.order("created_at", desc=True).execute()
        
        return result.data or []
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"[ADMIN][FILTER] Gagal mengambil laporan dengan filter (status='{status}', email='{email}', source='{source}'): {str(e)}"
        )


@router.put("/reports/status")
async def update_report_status(request: UpdateStatusRequest):
    """
    Update report status (Admin only)
    
    - **report_id**: Report ID to update
    - **new_status**: New status
    - **final_status**: Final determination
    - **admin_id**: Admin making the change
    - **note**: Optional note
    """
    try:
        # Get current report
        current = db.supabase_admin.table("reports").select("status").eq("id", request.report_id).execute()
        
        if not current.data:
            raise HTTPException(
                status_code=404,
                detail=f"[ADMIN][UPDATE] Laporan dengan ID '{request.report_id}' tidak ditemukan"
            )
        
        old_status = current.data[0].get("status")
        
        # Update report
        update_data = {
            "status": request.new_status,
            "final_status": request.final_status,
            "updated_at": datetime.now().isoformat()
        }
        
        if request.new_status == "RESOLVED":
            update_data["resolved_at"] = datetime.now().isoformat()
        
        result = db.supabase_admin.table("reports").update(update_data).eq("id", request.report_id).execute()
        
        # Log the activity
        log_report_activity(
            report_id=request.report_id,
            old_status=old_status,
            new_status=request.new_status,
            changed_by=request.admin_id,
            note=request.note
        )
        
        return {"message": "Report status updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"[ADMIN][UPDATE] Gagal update status laporan '{request.report_id}': {str(e)}"
        )


@router.post("/blacklist")
async def add_blacklist(request: AddUrlRequest):
    """
    Add URL to blacklist (Admin only)
    
    - **url**: URL to blacklist
    - **admin_id**: Admin making the change
    """
    try:
        # Check if already blacklisted
        if is_blacklisted(request.url):
            raise HTTPException(
                status_code=400,
                detail=f"[ADMIN][BLACKLIST] URL '{request.url}' sudah ada di blacklist"
            )
        
        blacklist_data = {
            "url": request.url,
            "added_by": request.admin_id,
            "created_at": datetime.now().isoformat()
        }
        
        db.supabase_admin.table("blacklist_urls").insert(blacklist_data).execute()
        
        return {"message": "URL added to blacklist successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"[ADMIN][BLACKLIST] Gagal menambahkan URL '{request.url}' ke blacklist: {str(e)}"
        )


@router.post("/whitelist")
async def add_whitelist(request: AddUrlRequest):
    """
    Add URL to whitelist (Admin only)
    
    - **url**: URL to whitelist
    - **admin_id**: Admin making the change
    """
    try:
        # Check if already whitelisted
        if is_whitelisted(request.url):
            raise HTTPException(
                status_code=400,
                detail=f"[ADMIN][WHITELIST] URL '{request.url}' sudah ada di whitelist"
            )
        
        whitelist_data = {
            "url": request.url,
            "added_by": request.admin_id,
            "created_at": datetime.now().isoformat()
        }
        
        db.supabase_admin.table("whitelist_urls").insert(whitelist_data).execute()
        
        return {"message": "URL added to whitelist successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"[ADMIN][WHITELIST] Gagal menambahkan URL '{request.url}' ke whitelist: {str(e)}"
        )


@router.get("/reports/{report_id}/logs")
async def get_report_logs(report_id: str):
    """
    Get activity logs for a specific report
    
    - **report_id**: Report ID to get logs for
    """
    try:
        result = db.supabase_admin.table("report_logs").select("*").eq("report_id", report_id).order("created_at", desc=True).execute()
        
        return result.data or []
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"[ADMIN][LOGS] Gagal mengambil log untuk laporan '{report_id}': {str(e)}"
        )

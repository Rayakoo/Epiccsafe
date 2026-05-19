import uuid
from datetime import datetime
from typing import Optional, Tuple
import supabase_client as db


def generate_ticket_id() -> str:
    """Generate unique ticket ID for reports"""
    return f"TICKET-{uuid.uuid4().hex[:8].upper()}"


def is_blacklisted(url: str) -> bool:
    """Check if URL is in blacklist"""
    try:
        result = db.supabase_admin.table("blacklist_urls").select("url").eq("url", url).execute()
        return len(result.data) > 0
    except Exception as e:
        print(f"Error checking blacklist: {e}")
        return False


def is_whitelisted(url: str) -> bool:
    """Check if URL is in whitelist"""
    try:
        result = db.supabase_admin.table("whitelist_urls").select("url").eq("url", url).execute()
        return len(result.data) > 0
    except Exception as e:
        print(f"Error checking whitelist: {e}")
        return False


def log_report_activity(report_id: str, old_status: Optional[str], new_status: str, 
                        changed_by: str, note: Optional[str] = None) -> bool:
    """Log report status changes"""
    try:
        log_data = {
            "report_id": report_id,
            "old_status": old_status,
            "new_status": new_status,
            "changed_by": changed_by,
            "note": note,
            "created_at": datetime.now().isoformat()
        }
        db.supabase_admin.table("report_logs").insert(log_data).execute()
        return True
    except Exception as e:
        print(f"Error logging activity: {e}")
        return False


def get_url_domain(url: str) -> str:
    """Extract domain from URL"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc or url
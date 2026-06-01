import uuid
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlparse
import supabase_client as db


def generate_ticket_id() -> str:
    """Generate unique ticket ID for reports"""
    return f"TICKET-{uuid.uuid4().hex[:8].upper()}"


def _get_netloc(url: str) -> str:
    """Extract netloc (domain) from a URL string."""
    parsed = urlparse(url)
    return parsed.netloc.lower() if parsed.netloc else url.lower()


def _is_match(incoming_url: str, stored_url: str) -> bool:
    """Check if stored_url matches the root of incoming_url."""
    a = incoming_url.lower().rstrip("/")
    b = stored_url.lower().rstrip("/")
    # Exact match
    if a == b:
        return True
    # URL starts with stored entry (e.g. https://x.com/page matches https://x.com)
    if a.startswith(b + "/") or a.startswith(b + "?"):
        return True
    # Netloc (domain) match — stored entry is a bare domain
    incoming_netloc = _get_netloc(incoming_url)
    stored_netloc = _get_netloc(stored_url)
    if not stored_netloc:
        return False
    return incoming_netloc == stored_netloc or incoming_netloc.endswith("." + stored_netloc)


def is_blacklisted(url: str) -> bool:
    """Check if URL or its root domain is in blacklist"""
    try:
        result = db.supabase_admin.table("blacklist_urls").select("url").execute()
        if not result.data:
            return False
        for row in result.data:
            stored = row.get("url")
            if stored and _is_match(url, stored):
                return True
        return False
    except Exception as e:
        print(f"Error checking blacklist: {e}")
        return False


def is_whitelisted(url: str) -> bool:
    """Check if URL or its root domain is in whitelist"""
    try:
        result = db.supabase_admin.table("whitelist_urls").select("url").execute()
        if not result.data:
            return False
        for row in result.data:
            stored = row.get("url")
            if stored and _is_match(url, stored):
                return True
        return False
    except Exception as e:
        print(f"Error checking whitelist: {e}")
        return False


def log_report_activity(report_id: str, old_status: Optional[str], new_status: str, 
                        changed_by: str, note: Optional[str] = None) -> bool:
    """Log report status changes"""
    try:
        log_data = {
            "id": str(uuid.uuid4()),
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
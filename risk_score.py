from typing import Tuple
from datetime import datetime
import random
import re
from reports_helper import is_blacklisted, is_whitelisted

def calculate_risk_score(url: str) -> int:
    """
    Calculate risk score for URL (Dummy implementation - ML not ready)
    Returns score from 0-100
    """
    score = 0
    
    # Check blacklist/whitelist first
    if is_blacklisted(url):
        return 100
    if is_whitelisted(url):
        return 0
    
    # Dummy scoring based on simple heuristics
    # In production, this would use ML model
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'bit\.ly', r'tinyurl', r'goo\.gl',  # Shorteners
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
        r'free.*download', r'click.*here',  # Spam patterns
        r'login.*verify', r'account.*suspend'  # Phishing patterns
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            score += 20
    
    # Random factor for dummy (simulate ML uncertainty)
    score += random.randint(0, 30)
    
    # Cap at 100
    return min(score, 100)

def call_scan_api() -> Tuple[int, str]:
    """
    Call external scan API (Dummy implementation)
    Returns: (risk_score, status)
    """
    # Dummy implementation
    dummy_score = random.randint(0, 100)
    status = "scanned" if dummy_score < 70 else "suspicious"
    return dummy_score, status

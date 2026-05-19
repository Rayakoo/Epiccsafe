# --------------------------------------------------------------
# scan.py – URL‑scanning router (whitelist/blacklist + ML model)
# --------------------------------------------------------------
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
import joblib
import numpy as np
import os
import re
import math
import tldextract          # pip install tldextract
import requests            # pip install requests
from bs4 import BeautifulSoup   # pip install beautifulsoup4 lxml
from urllib.parse import urlparse, parse_qs
from reports_helper import is_blacklisted, is_whitelisted
from risk_score import calculate_risk_score, call_scan_api

router = APIRouter(prefix="/scan", tags=["Scan"])

# ------------------------------------------------------------------
# Pydantic models (original 4 endpoints + the new unified one)
# ------------------------------------------------------------------
class ScanUrlResponse(BaseModel):
    is_blacklisted: bool
    is_whitelisted: bool


class ScanUrlExtensionResponse(BaseModel):
    is_blacklisted: bool
    is_whitelisted: bool
    risk_score: int


class CheckStatusResponse(BaseModel):
    status: str


class ScanApiResponse(BaseModel):
    risk_score: int
    status: str


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    url: str
    score: int                     # 0‑100
    reason: str                    # whitelisted, blacklisted, model_prediction
    prediction: int                # 0 = safe, 1 = phishing
    predict_proba: List[float]     # [prob_safe, prob_phishing]
    conclusion: str                # human readable
    features: List[float]          # the 24‑element feature vector
    feature_map: Dict[str, float]  # name → value mapping for debugging


# ------------------------------------------------------------------
# Load the ML model once at startup
# ------------------------------------------------------------------
MODEL_PATH = os.getenv("MODEL_PATH", "/home/rafi/Projects/epiccsafe/model_epiccsafe.pkl")
if not os.path.exists(MODEL_PATH):
    model = None
else:
    model = joblib.load(MODEL_PATH)

# ------------------------------------------------------------------
# Feature order – **must** match the order the model was trained on
# ------------------------------------------------------------------
FITUR_URL_ONLY = [
    'URLLength',
    'DomainLength',
    'IsDomainIP',
    'URLSimilarityIndex',
    'CharContinuationRate',
    'TLDLegitimateProb',
    'URLCharProb',
    'TLDLength',
    'NoOfSubDomain',
    'HasObfuscation',
    'NoOfObfuscatedChar',
    'ObfuscationRatio',
    'LetterRatioInURL',          # <-- note: NOT NoOfLettersInURL
    'NoOfDegitsInURL',
    'DegitRatioInURL',
    'NoOfEqualsInURL',
    'NoOfQMarkInURL',
    'NoOfAmpersandInURL',
    'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL',
    'IsHTTPS',
    'HasSocialNet',
    'HasCopyrightInfo',
    'HasDescription'
]


# ------------------------------------------------------------------
# Helper: safe division (avoid ZeroDivisionError)
# ------------------------------------------------------------------
def _safe_div(a: float, b: float) -> float:
    return a / b if b != 0 else 0.0


# ------------------------------------------------------------------
# Min‑max values supplied by you (feature → {min, max})
# ------------------------------------------------------------------
_FEATURE_RANGES = {
    'URLLength':                {'min': 13.0,  'max': 1769.0},
    'DomainLength':             {'min': 4.0,   'max': 110.0},
    'IsDomainIP':               {'min': 0.0,   'max': 1.0},
    'URLSimilarityIndex':       {'min': 0.50908065, 'max': 100.0},
    'CharContinuationRate':     {'min': 0.0,   'max': 1.0},
    'TLDLegitimateProb':        {'min': 0.0,   'max': 0.5229071},
    'URLCharProb':              {'min': 0.001082764, 'max': 0.090823664},
    'TLDLength':                {'min': 2.0,   'max': 13.0},
    'NoOfSubDomain':            {'min': 0.0,   'max': 10.0},
    'HasObfuscation':           {'min': 0.0,   'max': 1.0},
    'NoOfObfuscatedChar':       {'min': 0.0,   'max': 57.0},
    'ObfuscationRatio':         {'min': 0.0,   'max': 0.348},
    'LetterRatioInURL':         {'min': 0.0,   'max': 0.926},
    'NoOfDegitsInURL':          {'min': 0.0,   'max': 662.0},
    'DegitRatioInURL':          {'min': 0.0,   'max': 0.684},
    'NoOfEqualsInURL':          {'min': 0.0,   'max': 51.0},
    'NoOfQMarkInURL':           {'min': 0.0,   'max': 4.0},
    'NoOfAmpersandInURL':       {'min': 0.0,   'max': 120.0},
    'NoOfOtherSpecialCharsInURL':{'min': 0.0,   'max': 112.0},
    'SpacialCharRatioInURL':    {'min': 0.0,   'max': 0.397},
    'IsHTTPS':                  {'min': 0.0,   'max': 1.0},
    'HasSocialNet':             {'min': 0.0,   'max': 1.0},
    'HasCopyrightInfo':         {'min': 0.0,   'max': 1.0},
    'HasDescription':           {'min': 0.0,   'max': 1.0},
}

# ------------------------------------------------------------------
# Helper: normalise a value to [0,1] using supplied min‑max
# ------------------------------------------------------------------
def _normalise(value: float, feat_name: str) -> float:
    rng = _FEATURE_RANGES.get(feat_name)
    if not rng:
        return value  # safety fallback – should never happen
    mn, mx = rng['min'], rng['max']
    if mx == mn:               # avoid division by zero
        return 0.0
    return (value - mn) / (mx - mn)


# ------------------------------------------------------------------
# Helper: longest‑common‑subsequence ratio (0‑1)
# ------------------------------------------------------------------
def _lcs_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    longest = 0
    for i in range(m):
        for j in range(n):
            if a[i] == b[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
                longest = max(longest, dp[i + 1][j + 1])
    return longest / max(m, n)


# ------------------------------------------------------------------
# REAL FEATURE EXTRACTION
# ------------------------------------------------------------------
def extract_features(url: str) -> List[float]:
    """
    Compute the 24 features expected by the model, in the exact order of FITUR_URL_ONLY.
    All values are returned as float and **already normalised to [0,1]** using the
    min‑max statistics you provided.
    """
    # ---------- URL parsing ----------
    parsed = urlparse(url)
    ext = tldextract.extract(url)          # subdomain, domain, suffix
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    full = url.lower()

    # ----- 1. URLLength -----
    URLLength = float(len(url))

    # ----- 2. DomainLength -----
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    DomainLength = float(len(domain))

    # ----- 3. IsDomainIP -----
    ipv4_pat = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    ipv6_pat = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    IsDomainIP = 1.0 if (ipv4_pat.match(ext.domain) or ipv6_pat.match(ext.domain)) else 0.0

    # ----- 4. URLSimilarityIndex -----
    legit_domains = [
        'google.com', 'youtube.com', 'wikipedia.org', 'github.com',
        'stackoverflow.com', 'amazon.com', 'netflix.com', 'microsoft.com'
    ]
    URLSimilarityIndex = float(
        max(_lcs_ratio(url, d) for d in legit_domains)
    )

    # ----- 5. CharContinuationRate -----
    max_run = cur = 1
    for i in range(1, len(url)):
        if url[i] == url[i - 1]:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 1
    CharContinuationRate = _safe_div(max_run, len(url))

    # ----- 6. TLDLegitimateProb -----
    legit_tlds = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
        'co', 'uk', 'de', 'fr', 'jp', 'au', 'us', 'ca', 'id',
        'sg', 'my', 'ph', 'vn', 'th', 'nl', 'se', 'no', 'dk',
        'fi', 'pl', 'ch', 'at', 'be', 'pt', 'ie', 'gr', 'cz',
        'hu', 'ro', 'tr', 'il', 'za', 'ae', 'sa', 'br', 'mx',
        'ar', 'cl', 'pe', 'za'
    }
    TLDLegitimateProb = 1.0 if ext.suffix in legit_tlds else 0.0

    # ----- 7. URLCharProb -----
    alnum = sum(c.isalnum() for c in url)
    URLCharProb = _safe_div(alnum, len(url))

    # ----- 8. TLDLength -----
    TLDLength = float(len(ext.suffix))

    # ----- 9. NoOfSubDomain -----
    subparts = ext.subdomain.split('.') if ext.subdomain else []
    NoOfSubDomain = float(len([p for p in subparts if p]))

    # ----- 10. HasObfuscation -----
    HasObfuscation = 1.0 if ('%' in url or '//' in url[8:] or '@' in url) else 0.0

    # ----- 11. NoOfObfuscatedChar -----
    NoOfObfuscatedChar = float(len(re.findall(r'%[0-9A-Fa-f]{2}', url)))

    # ----- 12. ObfuscationRatio -----
    ObfuscationRatio = _safe_div(NoOfObfuscatedChar, URLLength)

    # ----- 13. NoOfLettersInURL -----
    NoOfLettersInURL = float(sum(c.isalpha() for c in url))

    # ----- 14. LetterRatioInURL -----
    LetterRatioInURL = _safe_div(NoOfLettersInURL, URLLength)

    # ----- 15. NoOfDegitsInURL -----
    NoOfDegitsInURL = float(sum(c.isdigit() for c in url))

    # ----- 16. DegitRatioInURL -----
    DegitRatioInURL = _safe_div(NoOfDegitsInURL, URLLength)

    # ----- 17. NoOfEqualsInURL -----
    NoOfEqualsInURL = float(url.count('='))

    # ----- 18. NoOfQMarkInURL -----
    NoOfQMarkInURL = float(url.count('?'))

    # ----- 19. NoOfAmpersandInURL -----
    NoOfAmpersandInURL = float(url.count('&'))

    # ----- 20. NoOfOtherSpecialCharsInURL -----
    special = sum(
        1
        for c in url
        if not c.isalnum() and c not in '=?&./:-'
    )
    NoOfOtherSpecialCharsInURL = float(special)

    # ----- 21. SpacialCharRatioInURL -----
    SpacialCharRatioInURL = _safe_div(NoOfOtherSpecialCharsInURL, URLLength)

    # ----- 22. IsHTTPS -----
    IsHTTPS = 1.0 if scheme == 'https' else 0.0

    # ----- 23. HasSocialNet -----
    # Try to fetch the page and look inside <footer> for social links.
    HasSocialNet = 0.0
    # ----- 24. HasCopyrightInfo -----
    HasCopyrightInfo = 0.0
    # ----- 25. HasDescription -----
    HasDescription = 0.0

    # Try to fetch the page (short timeout) – if it fails we fall back to URL‑only heuristics.
    try:
        resp = requests.get(
            url,
            timeout=6,
            headers={'User-Agent': 'EpiccSafeScanner/1.0'},
            allow_redirects=True,
        )
        if resp.status_code == 200 and resp.text:
            soup = BeautifulSoup(resp.text, 'lxml')

            # ----- HasCopyrightInfo -----
            page_text = soup.get_text(separator=' ', strip=True).lower()
            if '©' in page_text or 'copyright' in page_text:
                HasCopyrightInfo = 1.0

            # ----- HasDescription -----
            meta_desc = soup.find('meta', attrs={'name': re.compile(r'description', re.I)})
            if meta_desc and meta_desc.get('content'):
                HasDescription = 1.0
            else:
                # Fallback to query‑parameter check if meta not found.
                qs = parse_qs(query)
                if any(k in qs for k in {'desc', 'description', 'descricao', 'keterangan', 'info'}):
                    HasDescription = 1.0

            # ----- HasSocialNet (search in <footer> first, then whole doc) -----
            socials = {
                'facebook', 'twitter', 'instagram', 'tiktok', 'linkedin',
                'youtube', 'reddit', 'pinterest', 'snapchat', 'whatsapp'
            }
            footer = soup.find('footer')
            search_root = footer if footer else soup
            for a in search_root.find_all('a', href=True):
                href = a['href'].lower()
                if any(s in href for s in socials):
                    HasSocialNet = 1.0
                    break
    except Exception:
        # If the request fails, fall back to the lighter checks we already had.
        # HasCopyrightInfo – just look for the word copyright in the URL string.
        if 'copyright' in full or '©' in url:
            HasCopyrightInfo = 1.0
        # HasDescription – query‑parameter check.
        qs = parse_qs(query)
        if any(k in qs for k in {'desc', 'description', 'descricao', 'keterangan', 'info'}):
            HasDescription = 1.0
        # HasSocialNet – crude URL‑based hint.
        socials = {
            'facebook', 'twitter', 'instagram', 'tiktok', 'linkedin',
            'youtube', 'reddit', 'pinterest', 'snapchat', 'whatsapp'
        }
        if any(s in netloc for s in socials):
            HasSocialNet = 1.0

    # ----- Build raw feature list in the exact order -----
    raw_features = [
        URLLength, DomainLength, IsDomainIP, URLSimilarityIndex,
        CharContinuationRate, TLDLegitimateProb, URLCharProb, TLDLength,
        NoOfSubDomain, HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio,
        LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL,
        NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL,
        NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL,
        IsHTTPS, HasSocialNet, HasCopyrightInfo, HasDescription
    ]

    # ----- Normalise each feature using the supplied min‑max -----
    normalised = [
        _normalise(val, name)
        for val, name in zip(raw_features, FITUR_URL_ONLY)
    ]

    return normalised


# ------------------------------------------------------------------
# ORIGINAL ENDPOINTS (unchanged)
# ------------------------------------------------------------------
@router.get("/url", response_model=ScanUrlResponse)
async def scan_url(url: str = Query(..., description="URL to scan")):
    """
    Quick scan URL to check blacklist/whitelist status
    """
    try:
        return ScanUrlResponse(
            is_blacklisted=is_blacklisted(url),
            is_whitelisted=is_whitelisted(url)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scanning URL: {str(e)}")


@router.get("/url/extension", response_model=ScanUrlExtensionResponse)
async def scan_url_extension(url: str = Query(..., description="URL to scan")):
    """
    Scan URL for extension – returns blacklist/whitelist + dummy risk score
    """
    try:
        return ScanUrlExtensionResponse(
            is_blacklisted=is_blacklisted(url),
            is_whitelisted=is_whitelisted(url),
            risk_score=calculate_risk_score(url)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scanning URL: {str(e)}")


@router.get("/url/status", response_model=CheckStatusResponse)
async def check_url_status(url: str = Query(..., description="URL to check")):
    """
    Check URL status (string)
    """
    try:
        if is_blacklisted(url):
            status = "BLACKLISTED"
        elif is_whitelisted(url):
            status = "WHITELISTED"
        else:
            risk = calculate_risk_score(url)
            status = (
                "SAFE" if risk < 30 else
                "SUSPICIOUS" if risk < 70 else
                "DANGEROUS"
            )
        return CheckStatusResponse(status=status)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking URL status: {str(e)}")


@router.get("/api", response_model=ScanApiResponse)
async def call_scan_api_endpoint():
    """
    Dummy external‑scan API
    """
    try:
        risk_score, status = call_scan_api()
        return ScanApiResponse(risk_score=risk_score, status=status)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error calling scan API: {str(e)}")


# ------------------------------------------------------------------
# NEW UNIFIED ENDPOINT
# ------------------------------------------------------------------
@router.post("", response_model=ScanResponse)
def scan_url_unified(payload: ScanRequest):
    """
    Single endpoint to scan a URL:
      • whitelist → score 0
      • blacklist → score 100
      • otherwise → extract features → run model → score 0‑100
    """
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # 1️⃣ Whitelist check
    if is_whitelisted(url):
        return ScanResponse(
            url=url,
            score=0,
            reason="whitelisted",
            prediction=0,
            predict_proba=[1.0, 0.0],
            conclusion="SAFE (Bukan Phishing)",
            features=[0.0] * len(FITUR_URL_ONLY),
            feature_map={name: 0.0 for name in FITUR_URL_ONLY}
        )

    # 2️⃣ Blacklist check
    if is_blacklisted(url):
        return ScanResponse(
            url=url,
            score=100,
            reason="blacklisted",
            prediction=1,
            predict_proba=[0.0, 1.0],
            conclusion="PHISHING (Bahaya)",
            features=[0.0] * len(FITUR_URL_ONLY),
            feature_map={name: 0.0 for name in FITUR_URL_ONLY}
        )

    # 3️⃣ Feature extraction
    features = extract_features(url)
    if len(features) != len(FITUR_URL_ONLY):
        raise HTTPException(
            status_code=500,
            detail=f"Feature extraction length mismatch: expected {len(FITUR_URL_ONLY)}, got {len(features)}"
        )

    # 4️⃣ Model prediction
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")

    try:
        # model.predict_proba → [prob_safe, prob_phishing]
        probs = model.predict_proba([features])[0]
        prediction = int(model.predict([features])[0])
    except AttributeError:
        # Fallback if the model lacks predict_proba
        pred = model.predict([features])[0]
        prediction = int(pred)
        probs = [0.0, 0.0]
        if prediction == 1:
            probs = [0.0, 1.0]
        else:
            probs = [1.0, 0.0]

    # Convert phishing probability to 0‑100 score
    phishing_prob = probs[1] if len(probs) > 1 else float(prediction)
    score = int(round(phishing_prob * 100))

    # Human‑readable conclusion
    conclusion = "PHISHING (Bahaya)" if prediction == 1 else "SAFE (Bukan Phishing)"

    # Build feature map for debugging
    feature_map = {name: float(val) for name, val in zip(FITUR_URL_ONLY, features)}

    return ScanResponse(
        url=url,
        score=score,
        reason="model_prediction",
        prediction=prediction,
        predict_proba=probs,
        conclusion=conclusion,
        features=features,
        feature_map=feature_map
    )
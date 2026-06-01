# --------------------------------------------------------------
# scan.py – URL‑scanning router (whitelist/blacklist + ML model)
# --------------------------------------------------------------
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
import json
import joblib
import numpy as np
import os
import re
import math
import tldextract
import requests
import difflib
import pandas as pd
from collections import defaultdict
from bs4 import BeautifulSoup
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
# Base directory for model assets
# ------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------------
# Load the ML model once at startup
# ------------------------------------------------------------------
MODEL_PATH = os.environ.get("MODEL_PATH") or os.path.join(_BASE_DIR, "model_epiccsafe.pkl")
if not os.path.exists(MODEL_PATH):
    model = None
else:
    model = joblib.load(MODEL_PATH)

# ------------------------------------------------------------------
# Load the MinMaxScaler and feature list saved during training
# ------------------------------------------------------------------
SCALER_PATH = os.path.join(_BASE_DIR, "scaler_epiccsafe.pkl")
FITUR_PATH  = os.path.join(_BASE_DIR, "fitur_model.json")

if os.path.exists(SCALER_PATH):
    scaler_epiccsafe = joblib.load(SCALER_PATH)
else:
    scaler_epiccsafe = None

if os.path.exists(FITUR_PATH):
    with open(FITUR_PATH, "r") as f:
        FITUR_URL_ONLY = json.load(f)
else:
    FITUR_URL_ONLY = []


# ------------------------------------------------------------------
# N‑Gram model trained from Tranco top domains
# ------------------------------------------------------------------
class ProbabilitasKarakterNGram:
    def __init__(self, csv_path: str, max_domains: int = 10000):
        try:
            df = pd.read_csv(csv_path, header=None, nrows=max_domains)
            self.domain_aman: List[str] = df[1].dropna().tolist()
        except Exception:
            self.domain_aman = ["google.com", "youtube.com", "cimbniaga.co.id", "bca.co.id", "tokopedia.com"]
        self.matriks_transisi = self._bangun_matriks(self.domain_aman)

    def _bangun_matriks(self, domains):
        transisi = defaultdict(int)
        kemunculan = defaultdict(int)
        for domain in domains:
            huruf_saja = "".join(c for c in str(domain) if c.isalpha()).lower()
            if len(huruf_saja) < 2:
                continue
            for i in range(len(huruf_saja) - 1):
                h1, h2 = huruf_saja[i], huruf_saja[i + 1]
                transisi[(h1, h2)] += 1
                kemunculan[h1] += 1
        prob = {}
        for (h1, h2), jml in transisi.items():
            prob[(h1, h2)] = jml / kemunculan[h1]
        return prob

    def hitung_skor_url(self, url: str) -> float:
        huruf_saja = "".join(c for c in url if c.isalpha()).lower()
        if len(huruf_saja) < 2:
            return 0.0
        total = 0.0
        for i in range(len(huruf_saja) - 1):
            prob = self.matriks_transisi.get((huruf_saja[i], huruf_saja[i + 1]), 0.001)
            total += prob
        rata2 = total / (len(huruf_saja) - 1)
        return min(0.09, rata2 * 0.1)


# ------------------------------------------------------------------
# Load N‑gram model (once at startup)
# ------------------------------------------------------------------
_TRANCO_PATH = os.path.join(_BASE_DIR, "tranco_XW7QN.csv")
ngram_model = ProbabilitasKarakterNGram(_TRANCO_PATH)


# ------------------------------------------------------------------
# Helper: safe division (avoid ZeroDivisionError)
# ------------------------------------------------------------------
def _safe_div(a: float, b: float) -> float:
    return a / b if b != 0 else 0.0


# ------------------------------------------------------------------
# Helper: Levenshtein similarity ratio (0‑1)
# ------------------------------------------------------------------
def _levenshtein_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    m, n = len(a), len(b)
    if m < n:
        a, b = b, a
        m, n = n, m
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = curr
    return 1.0 - prev[n] / max(m, n)


# ------------------------------------------------------------------
# TLD dictionary for TLDLegitimateProb
# ------------------------------------------------------------------
_TLD_KAMUS = {
    ".com": 0.5229, ".co.id": 0.4500, ".id": 0.3000,
    ".org": 0.2100, ".net": 0.1500,
}


# ------------------------------------------------------------------
# REAL FEATURE EXTRACTION
# ------------------------------------------------------------------
def extract_features(url: str) -> List[float]:
    """
    Compute the 24 raw (unnormalised) features expected by the model,
    in the exact order of FITUR_URL_ONLY. The caller must apply the
    MinMaxScaler before feeding the vector to predict/predict_proba.
    """
    # ---------- URL parsing ----------
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    full = url.lower()
    url_len = float(len(url))

    # ----- 1. URLLength -----
    URLLength = url_len

    # ----- 2. DomainLength -----
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    DomainLength = float(len(domain))

    # ----- 3. IsDomainIP -----
    ipv4_pat = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    ipv6_pat = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    IsDomainIP = 1.0 if (ipv4_pat.match(ext.domain) or ipv6_pat.match(ext.domain)) else 0.0

    # ----- 4. URLSimilarityIndex (0–100) -----
    host_for_sim = netloc
    if host_for_sim.startswith('www.'):
        host_for_sim = host_for_sim[4:]
    whitelist_sample = ngram_model.domain_aman[:1000]
    URLSimilarityIndex = round(
        max(_levenshtein_similarity(host_for_sim, d) for d in whitelist_sample) * 100, 6
    )

    # ----- 5. CharContinuationRate (0–1) -----
    huruf_sequences = re.findall(r'[a-zA-Z]+', url)
    if url_len > 0 and huruf_sequences:
        CharContinuationRate = max(len(h) for h in huruf_sequences) / url_len
    else:
        CharContinuationRate = 0.0

    # ----- 6. TLDLegitimateProb (0–0.52) -----
    tld_key = "." + ext.suffix.lower()
    TLDLegitimateProb = _TLD_KAMUS.get(tld_key, 0.0)

    # ----- 7. URLCharProb (0.001–0.09) -----
    domain_for_ngram = domain
    if domain_for_ngram.startswith('www.'):
        domain_for_ngram = domain_for_ngram[4:]
    URLCharProb = ngram_model.hitung_skor_url(domain_for_ngram)

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
    ObfuscationRatio = _safe_div(NoOfObfuscatedChar, url_len)

    # ----- 13. NoOfLettersInURL -----
    NoOfLettersInURL = float(sum(c.isalpha() for c in url))

    # ----- 14. LetterRatioInURL -----
    LetterRatioInURL = _safe_div(NoOfLettersInURL, url_len)

    # ----- 15. NoOfDegitsInURL -----
    NoOfDegitsInURL = float(sum(c.isdigit() for c in url))

    # ----- 16. DegitRatioInURL -----
    DegitRatioInURL = _safe_div(NoOfDegitsInURL, url_len)

    # ----- 17. NoOfEqualsInURL -----
    NoOfEqualsInURL = float(url.count('='))

    # ----- 18. NoOfQMarkInURL -----
    NoOfQMarkInURL = float(url.count('?'))

    # ----- 19. NoOfAmpersandInURL -----
    NoOfAmpersandInURL = float(url.count('&'))

    # ----- 20. NoOfOtherSpecialCharsInURL -----
    special = sum(
        1 for c in url
        if not c.isalnum() and c not in '=?&./:-'
    )
    NoOfOtherSpecialCharsInURL = float(special)

    # ----- 21. SpacialCharRatioInURL -----
    SpacialCharRatioInURL = _safe_div(NoOfOtherSpecialCharsInURL, url_len)

    # ----- 22. IsHTTPS -----
    IsHTTPS = 1.0 if scheme == 'https' else 0.0

    # ----- 23. HasSocialNet -----
    HasSocialNet = 0.0
    # ----- 24. HasCopyrightInfo -----
    HasCopyrightInfo = 0.0
    # ----- 25. HasDescription -----
    HasDescription = 0.0

    try:
        resp = requests.get(
            url, timeout=6,
            headers={'User-Agent': 'EpiccSafeScanner/1.0'},
            allow_redirects=True,
        )
        if resp.status_code == 200 and resp.text:
            soup = BeautifulSoup(resp.text, 'lxml')

            page_text = soup.get_text(separator=' ', strip=True).lower()
            if '\u00a9' in page_text or 'copyright' in page_text:
                HasCopyrightInfo = 1.0

            meta_desc = soup.find('meta', attrs={'name': re.compile(r'description', re.I)})
            if meta_desc and meta_desc.get('content'):
                HasDescription = 1.0
            else:
                qs = parse_qs(query)
                if any(k in qs for k in {'desc', 'description', 'descricao', 'keterangan', 'info'}):
                    HasDescription = 1.0

            socials = {
                'facebook', 'twitter', 'instagram', 'tiktok', 'linkedin',
                'youtube', 'reddit', 'pinterest', 'snapchat', 'whatsapp',
            }
            footer = soup.find('footer')
            search_root = footer if footer else soup
            for a in search_root.find_all('a', href=True):
                href = a['href'].lower()
                if any(s in href for s in socials):
                    HasSocialNet = 1.0
                    break
    except Exception:
        if 'copyright' in full or '\u00a9' in url:
            HasCopyrightInfo = 1.0
        qs = parse_qs(query)
        if any(k in qs for k in {'desc', 'description', 'descricao', 'keterangan', 'info'}):
            HasDescription = 1.0
        socials = {
            'facebook', 'twitter', 'instagram', 'tiktok', 'linkedin',
            'youtube', 'reddit', 'pinterest', 'snapchat', 'whatsapp',
        }
        if any(s in netloc for s in socials):
            HasSocialNet = 1.0

    # ----- Build raw (unnormalised) feature vector -----
    return [
        URLLength, DomainLength, IsDomainIP, URLSimilarityIndex,
        CharContinuationRate, TLDLegitimateProb, URLCharProb, TLDLength,
        NoOfSubDomain, HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio,
        LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL,
        NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL,
        NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL,
        IsHTTPS, HasSocialNet, HasCopyrightInfo, HasDescription,
    ]


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
        raise HTTPException(status_code=500, detail=f"[SCAN][URL] Gagal memeriksa blacklist/whitelist untuk URL '{url}': {str(e)}")


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
        raise HTTPException(status_code=500, detail=f"[SCAN][EXTENSION] Gagal memindai URL '{url}' untuk extension: {str(e)}")


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
        raise HTTPException(status_code=500, detail=f"[SCAN][STATUS] Gagal menentukan status URL '{url}': {str(e)}")


@router.get("/api", response_model=ScanApiResponse)
async def call_scan_api_endpoint():
    """
    Dummy external‑scan API
    """
    try:
        risk_score, status = call_scan_api()
        return ScanApiResponse(risk_score=risk_score, status=status)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"[SCAN][API] Gagal memanggil scan API eksternal: {str(e)}")


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
        raise HTTPException(status_code=400, detail="[SCAN] URL tidak boleh kosong")

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

    # 3️⃣ Feature extraction (raw, unnormalised)
    raw_features = extract_features(url)
    if len(raw_features) != len(FITUR_URL_ONLY):
        raise HTTPException(
            status_code=500,
            detail=f"[SCAN][FEATURE] Ekstraksi fitur untuk URL '{url}' menghasilkan {len(raw_features)} fitur (diharapkan {len(FITUR_URL_ONLY)})"
        )

    # 4️⃣ Scale raw features with the MinMaxScaler
    if scaler_epiccsafe is None:
        raise HTTPException(status_code=500, detail="[SCAN][SCALER] Scaler tidak ditemukan. Pastikan scaler_epiccsafe.pkl ada.")

    try:
        features_2d = np.array([raw_features])
        features_scaled = scaler_epiccsafe.transform(features_2d)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"[SCAN][SCALER] Gagal scaling fitur: {str(e)}")

    # 5️⃣ Model prediction
    if model is None:
        raise HTTPException(status_code=500, detail=f"[SCAN][MODEL] Model ML tidak ditemukan atau gagal dimuat di path '{MODEL_PATH}'")

    try:
        probs = model.predict_proba(features_scaled)[0]
        prediction = int(model.predict(features_scaled)[0])
    except AttributeError:
        pred = model.predict(features_scaled)[0]
        prediction = int(pred)
        probs = [0.0, 0.0]
        if prediction == 1:
            probs = [0.0, 1.0]
        else:
            probs = [1.0, 0.0]

    # Convert phishing probability to 0‑100 score
    phishing_prob = probs[1] if len(probs) > 1 else float(prediction)
    score = int(round(phishing_prob * 100))

    conclusion = "PHISHING (Bahaya)" if prediction == 1 else "SAFE (Bukan Phishing)"

    # Build debug maps
    features_scaled_list = features_scaled[0].tolist()
    feature_map = {name: float(val) for name, val in zip(FITUR_URL_ONLY, features_scaled_list)}

    return ScanResponse(
        url=url,
        score=score,
        reason="model_prediction",
        prediction=prediction,
        predict_proba=probs,
        conclusion=conclusion,
        features=features_scaled_list,
        feature_map=feature_map
    )
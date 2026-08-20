#!/usr/bin/env python3
"""
PhishShield AI - Programmatic REST API Server
Exposes automated Threat Intelligence & Phishing Scan endpoints for integration with SIEMs, Chrome Extensions, and third-party security tools.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from app import detect_phishing_text, unshorten_url, whois_lookup, inspect_ssl_cert, inspect_webpage_meta, compute_threat_index

app = FastAPI(
    title="PhishShield AI Threat Intelligence API",
    description="RESTful Threat Scan API powered by Google Gemini AI & Multi-Vector Threat Intelligence Engine.",
    version="2.0.0"
)

class ScanRequest(BaseModel):
    content: str
    mode: Optional[str] = "text" # "text", "url", "batch"

class ScanResponse(BaseModel):
    verdict: str
    confidence: int
    threat_index: int
    risk_level: str
    explanation: str
    red_flags: List[str]
    recommendation: str

@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "PhishShield AI Engine",
        "version": "2.0.0",
        "endpoints": ["/api/v1/scan"]
    }

@app.post("/api/v1/scan", response_model=ScanResponse)
def scan_content(req: ScanRequest):
    if not req.content or not req.content.strip():
        raise HTTPException(status_code=400, detail="Content field cannot be empty")
    
    try:
        # Detect phishing via AI
        ai_res = detect_phishing_text(req.content)
        
        # Threat intel enrichment
        target_url = req.content if req.content.startswith(('http://', 'https://')) else None
        whois_info = None
        ssl_info = None
        meta_info = None

        if target_url:
            domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
            whois_info = whois_lookup(domain)
            ssl_info = inspect_ssl_cert(domain)
            meta_info = inspect_webpage_meta(target_url)

        threat_matrix = compute_threat_index(ai_res, whois_info, ssl_info, meta_info)

        return ScanResponse(
            verdict=ai_res.get("verdict", "Unknown"),
            confidence=ai_res.get("confidence", 0),
            threat_index=threat_matrix.get("threat_index", 0),
            risk_level=threat_matrix.get("risk_level", "Unknown"),
            explanation=ai_res.get("explanation", ""),
            red_flags=ai_res.get("red_flags", []),
            recommendation=ai_res.get("recommendation", "")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

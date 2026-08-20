# ================================
# PHISHSHIELD AI - Cybersecurity MVP
# Real-world phishing detection using AI
# FUTURISTIC 3D INTERACTIVE UI
# + IMAGE UPLOAD + SECURITY HARDENING
# ================================

import streamlit as st
from google import genai
from google.genai import types
import os
import json
import re
import time
import base64
import hashlib
import html
import secrets
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse
import urllib.request
import urllib.error
import socket
import ssl
import io
from io import BytesIO

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import cv2
    import numpy as np
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

try:
    from fpdf import FPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

load_dotenv_available = False
try:
    from dotenv import load_dotenv
    load_dotenv()
    load_dotenv_available = True
except ImportError:
    pass

# ================================
# 1. SECURITY CONFIGURATION
# ================================

# Security constants
MAX_TEXT_INPUT_LENGTH = 50000          # 50KB max text input
MAX_IMAGE_SIZE_MB = 10                 # 10MB max image
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/tiff"}
RATE_LIMIT_WINDOW = 60                 # 1 minute window
MAX_REQUESTS_PER_WINDOW = 15           # max 15 analyses per minute
SESSION_TIMEOUT_MINUTES = 30           # session expires after 30 min
MAX_SESSION_SCANS = 100                # max scans stored in session

# ================================
# 2. SECURITY UTILITY FUNCTIONS
# ================================

def init_security_session():
    """Initialize security-related session state variables."""
    defaults = {
        "scan_history": [],
        "request_timestamps": [],
        "session_id": secrets.token_hex(16),
        "session_start": datetime.now().isoformat(),
        "total_scans": 0,
        "blocked_attempts": 0,
        "input_type_counts": {"text": 0, "image": 0},
        "last_scan_time": None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

def sanitize_input(text: str) -> str:
    """Sanitize text input to prevent XSS and injection attacks."""
    if not isinstance(text, str):
        return ""
    # HTML escape
    text = html.escape(text)
    # Strip potential script tags (double-check after escape)
    text = re.sub(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', text, flags=re.DOTALL | re.IGNORECASE)
    # Strip event handlers
    text = re.sub(r'\bon\w+\s*=', '', text, flags=re.IGNORECASE)
    # Strip javascript: URIs
    text = re.sub(r'javascript\s*:', '', text, flags=re.IGNORECASE)
    # Strip data: URIs in suspicious contexts
    text = re.sub(r'data\s*:\s*text/html', '', text, flags=re.IGNORECASE)
    return text.strip()

def validate_input_length(text: str) -> tuple[bool, str]:
    """Validate input length is within safe bounds."""
    if len(text) > MAX_TEXT_INPUT_LENGTH:
        return False, f"Input too large ({len(text):,} chars). Maximum is {MAX_TEXT_INPUT_LENGTH:,} characters."
    return True, ""

def check_rate_limit() -> tuple[bool, str]:
    """Check if the user has exceeded the rate limit."""
    now = datetime.now()
    timestamps = st.session_state.get("request_timestamps", [])
    # Remove timestamps outside the window
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW)
    timestamps = [t for t in timestamps if datetime.fromisoformat(t) > cutoff]
    st.session_state["request_timestamps"] = timestamps

    if len(timestamps) >= MAX_REQUESTS_PER_WINDOW:
        st.session_state["blocked_attempts"] += 1
        remaining = RATE_LIMIT_WINDOW - (now - datetime.fromisoformat(timestamps[0])).seconds
        return False, f"Rate limit exceeded. Try again in {remaining} seconds."
    return True, ""

def record_request():
    """Record a successful request timestamp."""
    now = datetime.now()
    st.session_state["request_timestamps"].append(now.isoformat())
    st.session_state["total_scans"] += 1
    st.session_state["last_scan_time"] = now.strftime("%Y-%m-%d %H:%M:%S")

def validate_image_upload(uploaded_file) -> tuple[bool, str]:
    """Validate uploaded image file for security."""
    if uploaded_file is None:
        return False, "No file uploaded."

    # Check file size
    file_size_mb = uploaded_file.size / (1024 * 1024)
    if file_size_mb > MAX_IMAGE_SIZE_MB:
        return False, f"File too large ({file_size_mb:.1f}MB). Maximum is {MAX_IMAGE_SIZE_MB}MB."

    # Check MIME type
    file_type = uploaded_file.type
    if file_type not in ALLOWED_IMAGE_TYPES:
        return False, f"Invalid file type '{file_type}'. Allowed: PNG, JPEG, GIF, WebP, BMP, TIFF."

    # Check file extension matches MIME
    file_name = uploaded_file.name.lower()
    ext_to_mime = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
        ".tiff": "image/tiff", ".tif": "image/tiff",
    }
    file_ext = "." + file_name.rsplit(".", 1)[-1] if "." in file_name else ""
    expected_mime = ext_to_mime.get(file_ext)
    if expected_mime and expected_mime != file_type:
        return False, f"File extension '{file_ext}' doesn't match content type '{file_type}'."

    # Check magic bytes
    uploaded_file.seek(0)
    header = uploaded_file.read(16)
    uploaded_file.seek(0)

    magic_signatures = {
        b'\x89PNG': "image/png",
        b'\xff\xd8\xff': "image/jpeg",
        b'GIF87a': "image/gif",
        b'GIF89a': "image/gif",
        b'RIFF': "image/webp",     # WebP starts with RIFF
        b'BM': "image/bmp",
        b'II\x2a\x00': "image/tiff",
        b'MM\x00\x2a': "image/tiff",
    }
    detected_type = None
    for sig, mime in magic_signatures.items():
        if header.startswith(sig):
            detected_type = mime
            break

    if detected_type and detected_type != file_type:
        return False, f"File content appears to be {detected_type}, but declared as {file_type}."

    # Check for embedded scripts (basic check for HTML-in-image attacks)
    uploaded_file.seek(0)
    raw_content = uploaded_file.read()
    uploaded_file.seek(0)
    dangerous_patterns = [
        b'<script', b'javascript:', b'onerror=', b'onload=',
        b'<iframe', b'<object', b'<embed', b'<applet',
    ]
    for pattern in dangerous_patterns:
        if pattern in raw_content.lower():
            return False, f"Potentially dangerous content detected in image."

    return True, "Valid"

def secure_error_message(error: Exception) -> str:
    """Generate a safe error message that doesn't leak sensitive info."""
    error_str = str(error).lower()
    safe_messages = {
        "api_key": "Authentication error. Please check your API configuration.",
        "quota": "API quota exceeded. Please wait and try again.",
        "rate": "Rate limit hit. Please wait a moment and try again.",
        "unavailable": "AI service is temporarily busy. Retrying...",
        "503": "AI service is temporarily overloaded. Please try again in a moment.",
        "429": "Too many requests. Please wait a moment.",
        "timeout": "Request timed out. Please try again with shorter input.",
        "json": "Could not parse AI response. Please try again.",
        "connection": "Network error. Please check your connection.",
        "invalid": "Invalid input received. Please check your input.",
    }
    for keyword, msg in safe_messages.items():
        if keyword in error_str:
            return msg
    return "An unexpected error occurred. Please try again."

def log_scan_result(input_type: str, verdict: str, input_preview: str):
    """Securely log scan results to session (no sensitive data stored)."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": input_type,
        "verdict": verdict,
        "preview": input_preview[:80] + "..." if len(input_preview) > 80 else input_preview,
        "id": secrets.token_hex(4),
    }
    history = st.session_state.get("scan_history", [])
    history.insert(0, entry)
    # Keep only last MAX_SESSION_SCANS
    st.session_state["scan_history"] = history[:MAX_SESSION_SCANS]
    # Update type count
    counts = st.session_state.get("input_type_counts", {"text": 0, "image": 0})
    counts[input_type] = counts.get(input_type, 0) + 1
    st.session_state["input_type_counts"] = counts

def get_session_age() -> str:
    """Get human-readable session age."""
    start = st.session_state.get("session_start")
    if not start:
        return "N/A"
    elapsed = datetime.now() - datetime.fromisoformat(start)
    minutes = elapsed.total_seconds() / 60
    if minutes < 1:
        return "< 1 min"
    elif minutes < 60:
        return f"{int(minutes)} min"
    else:
        return f"{int(minutes // 60)}h {int(minutes % 60)}m"

# ================================
# 2b. ADVANCED SECURITY HARDENING
# ================================

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and injection attacks."""
    if not filename:
        return "unknown"
    # Remove path separators (path traversal prevention)
    filename = os.path.basename(filename)
    # Remove null bytes
    filename = filename.replace('\x00', '')
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)
    # Only allow safe characters
    filename = re.sub(r'[^a-zA-Z0-9._\- ]', '_', filename)
    # Limit length
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:190] + ext
    # Prevent double extensions (e.g., .php.jpg)
    parts = filename.split('.')
    if len(parts) > 2:
        filename = parts[0] + '.' + parts[-1]
    return filename or "unknown"

def check_path_traversal(input_text: str) -> bool:
    """Check if input contains path traversal attempts."""
    traversal_patterns = [
        r'\.\./', r'\.\.\\', r'%2e%2e/', r'%2e%2e\\',
        r'\.\.%2f', r'\.\.%5c', r'%252e%252e',
        r'/etc/passwd', r'/etc/shadow', r'c:\\windows',
        r'/proc/', r'/sys/', r'\\\\\\\\',
    ]
    for pattern in traversal_patterns:
        if re.search(pattern, input_text, re.IGNORECASE):
            return True
    return False

def check_ssti_attempt(input_text: str) -> bool:
    """Check if input contains Server-Side Template Injection attempts."""
    ssti_patterns = [
        r'\{\{.*\}\}', r'\{%.*%\}',           # Jinja2/Twig
        r'\$\{.*\}',                              # Expression Language
        r'<%=.*%>',                                  # ERB
        r'#\{.*\}',                                 # Ruby
        r'\{\{7.*\}\}',                           # Smarty
        r'{{config}}', r'{{self.__class__}}',       # Common payloads
        r'__class__', r'__subclasses__',             # Python introspection
        r'\.__import__', r'exec\(', r'eval\(',     # Code execution
    ]
    for pattern in ssti_patterns:
        if re.search(pattern, input_text, re.IGNORECASE):
            return True
    return False

def check_xxe_attempt(content: bytes) -> bool:
    """Check if file content contains XXE (XML External Entity) payloads."""
    if not content:
        return False
    text = content[:10000].decode('utf-8', errors='ignore').lower()
    xxe_patterns = [
        r'<!DOCTYPE', r'<!ENTITY', r'SYSTEM\s+["\']',
        r'file://', r'php://', r'smb://', r'ldap://',
        r'<!ELEMENT', r'<!ATTLIST',
        r'\[\s*<!\[CDATA\[',
        r'public\s+"\S+"',
    ]
    for pattern in xxe_patterns:
        if re.search(pattern, text):
            return True
    return False

def sanitize_for_ai(text: str) -> str:
    """Deep sanitize input before sending to AI model to prevent prompt injection."""
    if not isinstance(text, str):
        return ""
    # Remove potential prompt injection markers
    injection_markers = [
        'ignore previous instructions',
        'ignore all previous',
        'disregard previous',
        'forget everything',
        'new instructions:',
        'system prompt:',
        'you are now',
        'act as if',
        'pretend you are',
        'override:',
        '[SYSTEM]',
        '[INST]',
        '<<SYS>>',
    ]
    lower_text = text.lower()
    for marker in injection_markers:
        if marker in lower_text:
            # Replace the marker with safe text
            text = re.sub(re.escape(marker), '[FILTERED]', text, flags=re.IGNORECASE)
    # Limit line count to prevent prompt flooding
    lines = text.split('\n')
    if len(lines) > 200:
        text = '\n'.join(lines[:200]) + '\n[TRUNCATED]'
    return text.strip()

def secure_session_cleanup():
    """Clean up expired session data to prevent memory exhaustion attacks."""
    # Clean old request timestamps
    now = datetime.now()
    timestamps = st.session_state.get("request_timestamps", [])
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW * 2)
    st.session_state["request_timestamps"] = [
        t for t in timestamps
        if datetime.fromisoformat(t) > cutoff
    ]
    # Trim scan history to max
    history = st.session_state.get("scan_history", [])
    if len(history) > MAX_SESSION_SCANS:
        st.session_state["scan_history"] = history[:MAX_SESSION_SCANS]

def generate_csrf_token() -> str:
    """Generate a CSRF-like token for form validation."""
    if "csrf_token" not in st.session_state:
        st.session_state["csrf_token"] = secrets.token_hex(32)
    return st.session_state["csrf_token"]

def validate_request_integrity(user_input: str, uploaded_bytes: bytes = None) -> tuple[bool, str]:
    """Master validation function — runs all security checks on input."""
    # Path traversal check
    if user_input and check_path_traversal(user_input):
        st.session_state["blocked_attempts"] = st.session_state.get("blocked_attempts", 0) + 1
        return False, "Input rejected: suspicious path traversal detected."

    # SSTI check
    if user_input and check_ssti_attempt(user_input):
        st.session_state["blocked_attempts"] = st.session_state.get("blocked_attempts", 0) + 1
        return False, "Input rejected: template injection attempt detected."

    # XXE check on file uploads
    if uploaded_bytes and check_xxe_attempt(uploaded_bytes):
        st.session_state["blocked_attempts"] = st.session_state.get("blocked_attempts", 0) + 1
        return False, "File rejected: potential XML external entity payload."

    # Prompt injection check
    if user_input:
        cleaned = sanitize_for_ai(user_input)
        if cleaned != user_input.strip():
            # Don't reject, but log and use cleaned version
            st.session_state["blocked_attempts"] = st.session_state.get("blocked_attempts", 0) + 1

    return True, ""

# ================================
# 3. INITIALIZE SECURITY
# ================================
init_security_session()
secure_session_cleanup()

# ================================
# 4. CONFIGURE AI MODEL
# ================================
# Load API key — st.secrets for Streamlit Cloud, .env for local dev
try:
    _api_key = st.secrets["GEMINI_API_KEY"]
except Exception:
    _api_key = os.getenv("GEMINI_API_KEY", "")

if not _api_key:
    st.error("⚠️ API key not configured. Please add GEMINI_API_KEY to Streamlit Secrets or .env file.")
    st.stop()

client = genai.Client(api_key=_api_key)

# Primary + fallback models (tried in order)
AI_MODELS = ['gemini-3.6-flash', 'gemini-flash-latest', 'gemini-3.5-flash']

def ai_generate(model_name: str, contents) -> str:
    """Call Gemini with retry across multiple models on 503/429 errors."""
    models_to_try = [model_name] + [m for m in AI_MODELS if m != model_name]
    last_error = None
    for model in models_to_try:
        for attempt in range(3):  # 3 retries per model
            try:
                response = client.models.generate_content(model=model, contents=contents)
                return response.text
            except Exception as e:
                last_error = e
                err_str = str(e).lower()
                # Only retry on transient errors
                if any(code in err_str for code in ['503', '429', 'unavailable', 'overloaded', 'rate']):
                    time.sleep(1.5 * (attempt + 1))  # backoff: 1.5s, 3s, 4.5s
                    continue
                # Non-transient error, try next model
                break
    # All models failed — raise the last error so caller can handle it
    raise last_error

def normalize_verdict(result: dict) -> dict:
    """Normalize AI output to expected format."""
    if not isinstance(result, dict):
        return result
    verdict = str(result.get('verdict', 'Error')).strip().lower()
    verdict_map = {'safe': 'Safe', 'clean': 'Safe', 'legitimate': 'Safe', 'benign': 'Safe',
        'suspicious': 'Suspicious', 'suspect': 'Suspicious', 'possibly phishing': 'Suspicious',
        'malicious': 'Malicious', 'phishing': 'Malicious', 'scam': 'Malicious',
        'dangerous': 'Malicious', 'harmful': 'Malicious', 'threat': 'Malicious'}
    result['verdict'] = verdict_map.get(verdict, result.get('verdict', 'Error'))
    confidence = result.get('confidence', 0)
    if isinstance(confidence, str):
        conf_map = {'very high': 95, 'high': 85, 'medium': 60, 'low': 30, 'very low': 15,
            'certain': 95, 'likely': 75, 'possible': 50, 'unlikely': 25}
        confidence = conf_map.get(confidence.lower().strip(), 50)
    try:
        confidence = int(confidence)
    except (ValueError, TypeError):
        confidence = 50
    result['confidence'] = max(0, min(100, confidence))
    if not isinstance(result.get('red_flags'), list):
        result['red_flags'] = []
    for key in ['explanation', 'recommendation']:
        if not isinstance(result.get(key), str):
            result[key] = str(result.get(key, 'No information available.'))
    return result

# ================================
# 5. ANALYSIS FUNCTIONS
# ================================

def detect_phishing_text(user_input: str) -> dict:
    """Analyze text input for phishing indicators using AI."""
    # Security: validate length
    valid, msg = validate_input_length(user_input)
    if not valid:
        return {"verdict": "Error", "confidence": 0, "explanation": msg, "red_flags": [], "recommendation": "Please shorten your input and try again."}

    # Security: deep sanitize for prompt injection
    clean_input = sanitize_for_ai(user_input)
    # Security: HTML sanitize
    clean_input = sanitize_input(clean_input)

    prompt = f"""You are a senior cybersecurity analyst. Analyze the following input for phishing indicators.

Think step-by-step like a reasoning agent. Do NOT default to 'Safe'. Instead, critically evaluate every element.

INPUT:
{clean_input}

STEP 1 — WHAT IS THIS?
- Is this a URL? A full email? A chat message? A short link? Or something else?
- Determine the category first.

STEP 2 — THREAT ANALYSIS (check each):
1. Urgency / fear tactics ("Act NOW!", "Account suspended!")
2. Suspicious URLs (misspelled domains, unusual TLDs like .xyz .ru .tk, IP addresses, URL shorteners hiding destination)
3. Requests for credentials (passwords, credit cards, OTP, SSN)
4. Brand impersonation (fake PayPal, bank, Amazon, Microsoft, etc.)
5. Sender legitimacy (spoofed email, mismatched display name vs address)
6. Grammar/spelling errors common in phishing
7. Too-good-to-be-true offers (lottery, prize, inheritance)
8. Unusual attachments or encoding

STEP 3 — CONTEXT CHECK:
- Would a normal business or person send this?
- Does the tone match what it claims to be?
- Are there any inconsistencies?

STEP 4 — VERDICT:
Be honest and critical. If ANY red flag exists, lean toward Suspicious or Malicious.
- "Safe" = NO red flags, legitimate source, normal content
- "Suspicious" = 1-2 red flags, possibly phishing but not certain
- "Malicious" = 3+ red flags, clearly phishing or scam

Return ONLY valid JSON with these keys:
- "verdict": "Safe" | "Suspicious" | "Malicious"
- "confidence": 0-100
- "explanation": Plain-English summary (max 3 sentences)
- "red_flags": List of specific flags found (max 5 items)
- "recommendation": What the user should do next (1 sentence)"""
    try:
        result_text = ai_generate(AI_MODELS[0], prompt)
        result_text = re.sub(r'```json\s*', '', result_text)
        result_text = re.sub(r'```\s*', '', result_text)
        return normalize_verdict(json.loads(result_text))
    except Exception as e:
        return {"verdict": "Error", "confidence": 0, "explanation": secure_error_message(e), "red_flags": [], "recommendation": "Please try again."}

def detect_phishing_image(image_bytes: bytes, mime_type: str) -> dict:
    """Analyze uploaded image for phishing indicators using Gemini Vision."""
    prompt = """You are a senior cybersecurity analyst examining an image. Think critically and reason step-by-step.

STEP 1 — WHAT IS THIS IMAGE?
- Is this a screenshot of an email? A login page? A text message? A social media post?
- Or is it unrelated to cybersecurity (e.g., a photo of food, a landscape, an animal, random image)?
- If the image has NOTHING to do with phishing, emails, or security, set verdict to "Safe", confidence 95, explanation "This image is not related to email or phishing. It appears to be [describe what it is].", red_flags as empty list [], and recommendation "No action needed — this image is not a security concern."

STEP 2 — IF IT IS SECURITY-RELATED, check for:
1. Fake login pages or credential harvesting forms
2. Suspicious URLs visible in the image
3. Impersonation of trusted brands (fake bank, tech company, government)
4. Urgency tactics or threats ("Act now or lose access!")
5. Poor design quality, logo inconsistencies, wrong colors
6. Requests for sensitive info (passwords, credit cards, OTP)
7. Fake security warnings, virus alerts, account lockout messages
8. Suspicious email headers or spoofed sender addresses

STEP 3 — BE CRITICAL:
- Do NOT assume it is safe just because it looks professional
- Check for subtle red flags (slightly wrong logo, wrong URL, odd phrasing)
- If anything seems off, flag it

STEP 4 — VERDICT:
- "Safe" = No phishing indicators, or image is completely unrelated to security
- "Suspicious" = Some red flags, could be phishing
- "Malicious" = Clearly a phishing attempt, scam, or fake page

Return ONLY valid JSON with these keys:
- "verdict": "Safe" | "Suspicious" | "Malicious"
- "confidence": 0-100
- "explanation": Plain-English summary (max 3 sentences)
- "red_flags": List of specific flags found (max 5 items, empty [] if none)
- "recommendation": What the user should do next (1 sentence)"""

    try:
        # Encode image to base64 for the google-genai SDK
        image_b64 = base64.b64encode(image_bytes).decode('utf-8')
        # Use proper SDK types for image content
        blob = types.Blob(mime_type=mime_type, data=image_b64)
        image_part = types.Part(inline_data=blob)
        result_text = ai_generate(AI_MODELS[0], [prompt, image_part])
        result_text = re.sub(r'```json\s*', '', result_text)
        result_text = re.sub(r'```\s*', '', result_text)
        return normalize_verdict(json.loads(result_text))
    except Exception as e:
        return {"verdict": "Error", "confidence": 0, "explanation": secure_error_message(e), "red_flags": [], "recommendation": "Please try again."}

# ================================
# 5b. URL UNSHORTENER + REDIRECT CHAIN
# ================================

def unshorten_url(url: str) -> dict:
    """Follow URL redirects and return the full chain."""
    chain = []
    current = url
    max_redirects = 10
    try:
        parsed = urlparse(current)
        if not parsed.scheme:
            current = 'https://' + current
            parsed = urlparse(current)

        for i in range(max_redirects):
            chain.append({"hop": i + 1, "url": current})
            try:
                req = urllib.request.Request(current, method='HEAD', headers={'User-Agent': 'Mozilla/5.0'})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                next_url = resp.geturl()
                if next_url == current or next_url in [c["url"] for c in chain]:
                    break
                current = next_url
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308) and e.headers.get('Location'):
                    next_url = e.headers['Location']
                    if not next_url.startswith('http'):
                        next_url = urlparse(current)._replace(path=next_url).geturl()
                    current = next_url
                else:
                    break
            except Exception:
                break

        final_parsed = urlparse(current)
        return {
            "original": url,
            "final": current,
            "chain": chain,
            "hops": len(chain),
            "is_shortened": len(chain) > 1,
            "final_domain": final_parsed.netloc,
            "redirected": current != url,
        }
    except Exception:
        return {"original": url, "final": url, "chain": [{"hop": 1, "url": url}], "hops": 0, "is_shortened": False, "final_domain": "", "redirected": False}

# ================================
# 5c. EMAIL HEADER PARSER
# ================================

def parse_email_headers(raw_headers: str) -> dict:
    """Parse raw email headers and extract key fields."""
    result = {
        "from": "", "to": "", "subject": "", "reply_to": "",
        "date": "", "message_id": "", "received": [],
        "spf": "", "dkim": "", "dmarc": "",
        "x_mailer": "", "return_path": "", "headers_raw": raw_headers,
    }
    lines = raw_headers.strip().split('\n')
    current_key = ""
    current_val = ""

    for line in lines:
        if line.startswith((' ', '\t')) and current_key:
            result[current_key] += ' ' + line.strip()
        else:
            if current_key and current_val:
                _store_header(result, current_key, current_val)
            if ':' in line:
                current_key, current_val = line.split(':', 1)
                current_key = current_key.strip().lower()
                current_val = current_val.strip()
            else:
                current_key = ""
                current_val = ""
    if current_key and current_val:
        _store_header(result, current_key, current_val)

    # Check SPF/DKIM/DMARC from Authentication-Results
    for line in lines:
        lower = line.lower()
        if 'spf=' in lower:
            m = re.search(r'spf=([\w.]+)', lower)
            if m: result['spf'] = m.group(1)
        if 'dkim=' in lower:
            m = re.search(r'dkim=([\w.]+)', lower)
            if m: result['dkim'] = m.group(1)
        if 'dmarc=' in lower:
            m = re.search(r'dmarc=([\w.]+)', lower)
            if m: result['dmarc'] = m.group(1)

    # Extract domain from From
    if result['from']:
        m = re.search(r'@([\w.-]+)', result['from'])
        result['from_domain'] = m.group(1) if m else ""
    else:
        result['from_domain'] = ""

    return result

def _store_header(result: dict, key: str, val: str):
    key_lower = key.lower()
    if key_lower == 'from': result['from'] = val
    elif key_lower == 'to': result['to'] = val
    elif key_lower == 'subject': result['subject'] = val
    elif key_lower == 'reply-to': result['reply_to'] = val
    elif key_lower == 'date': result['date'] = val
    elif key_lower == 'message-id': result['message_id'] = val
    elif key_lower == 'received': result['received'].append(val)
    elif key_lower == 'x-mailer': result['x_mailer'] = val
    elif key_lower == 'return-path': result['return_path'] = val

def analyze_email_headers_ai(headers: dict) -> dict:
    """Use AI to analyze parsed email headers for phishing."""
    header_summary = f"""From: {headers.get('from', 'N/A')}\nTo: {headers.get('to', 'N/A')}\nSubject: {headers.get('subject', 'N/A')}\nReply-To: {headers.get('reply_to', 'N/A')}\nReturn-Path: {headers.get('return_path', 'N/A')}\nDate: {headers.get('date', 'N/A')}\nFrom Domain: {headers.get('from_domain', 'N/A')}\nSPF: {headers.get('spf', 'N/A')}\nDKIM: {headers.get('dkim', 'N/A')}\nDMARC: {headers.get('dmarc', 'N/A')}\nReceived Hops: {len(headers.get('received', []))}\nX-Mailer: {headers.get('x_mailer', 'N/A')}"""

    prompt = f"""You are a senior email security analyst. Analyze these email headers for phishing indicators.

EMAIL HEADERS:\n{header_summary}\n
Check specifically for:
1. From domain vs Reply-To domain mismatch (impersonation)
2. Return-Path mismatch with From address
3. Failed SPF/DKIM/DMARC authentication
4. Excessive Received hops (email forwarding/laundering)
5. Suspicious X-Mailer (mass-mailing tools)
6. From domain age/reputation (if you can tell)
7. Subject line urgency or deception tactics

Return ONLY valid JSON with:
- "verdict": "Safe" | "Suspicious" | "Malicious"
- "confidence": 0-100
- "explanation": Plain-English summary (max 3 sentences)
- "red_flags": List of specific flags found (max 5)
- "recommendation": What the user should do next (1 sentence)
- "header_summary": dict with key header fields for display"""

    try:
        result_text = ai_generate(AI_MODELS[0], prompt)
        result_text = re.sub(r'```json\s*', '', result_text)
        result_text = re.sub(r'```\s*', '', result_text)
        parsed = normalize_verdict(json.loads(result_text))
        parsed['header_data'] = headers
        return parsed
    except Exception as e:
        return {"verdict": "Error", "confidence": 0, "explanation": secure_error_message(e), "red_flags": [], "recommendation": "Please try again.", "header_data": headers}

# ================================
# 5d. DOMAIN WHOIS LOOKUP
# ================================

def whois_lookup(domain: str) -> dict:
    """Look up domain registration info."""
    if not WHOIS_AVAILABLE:
        return {"error": "WHOIS library not installed"}
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        age_days = 0
        if creation:
            age_days = (datetime.now() - creation).days

        return {
            "domain": domain,
            "registrar": str(w.registrar) if w.registrar else "Unknown",
            "creation_date": str(creation) if creation else "Unknown",
            "expiration_date": str(expiration) if expiration else "Unknown",
            "age_days": age_days,
            "name_servers": w.name_servers if w.name_servers else [],
            "registrant_country": str(w.country) if w.country else "Unknown",
            "registrant_org": str(w.org) if w.org else "Unknown",
            "is_young": age_days < 90,
            "is_expired": expiration and expiration < datetime.now() if expiration else False,
            "privacy_protected": not bool(w.name),
            "error": None,
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)[:100]}

def virustotal_lookup(target: str) -> dict:
    """Look up URL/domain threat intelligence on VirusTotal v3 API."""
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_key and hasattr(st, "secrets") and "VIRUSTOTAL_API_KEY" in st.secrets:
        vt_key = st.secrets["VIRUSTOTAL_API_KEY"]
    
    if not vt_key:
        return {"status": "unconfigured", "message": "API key not set"}

    try:
        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
        headers = {"x-apikey": vt_key}
        url = f"https://www.virustotal.com/api/v3/domains/{clean_target}"
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                "error": None
            }
        else:
            return {"status": "error", "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)[:100]}

def inspect_ssl_cert(domain: str) -> dict:
    """Inspect SSL Certificate details and validity for a target domain."""
    if not domain:
        return {"valid": False, "error": "No domain provided"}
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName') or issuer.get('commonName') or "Unknown Issuer"
                not_after = cert.get('notAfter')
                expiry_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z') if not_after else None
                days_left = (expiry_dt - datetime.now()).days if expiry_dt else 0
                return {
                    "valid": True,
                    "issuer": issuer_name,
                    "expires_in_days": days_left,
                    "is_free_cert": any(fc in issuer_name.lower() for fc in ["let's encrypt", "zero-ssl", "cpanel", "cloudflare"]),
                    "error": None
                }
    except Exception as e:
        return {"valid": False, "error": str(e)[:100]}

def inspect_webpage_meta(url: str) -> dict:
    """Fetch HTTP headers and webpage title to detect brand impersonation mismatches."""
    if not url or not url.startswith(('http://', 'https://')):
        return {"title": "", "status_code": 0, "server": "", "impersonation_risk": False}
    try:
        resp = requests.get(url, timeout=4, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
        page_title = title_match.group(1).strip() if title_match else ""
        
        brands = ["paypal", "microsoft", "apple", "netflix", "bank of america", "wellsfargo", "chase", "amazon", "google", "outlook"]
        domain = urlparse(url).netloc.lower()
        impersonated_brand = None
        for b in brands:
            if b in page_title.lower() and b not in domain:
                impersonated_brand = b
                break
                
        return {
            "title": page_title[:100],
            "status_code": resp.status_code,
            "server": resp.headers.get('Server', 'Unknown')[:50],
            "impersonated_brand": impersonated_brand,
            "impersonation_risk": bool(impersonated_brand),
            "error": None
        }
    except Exception as e:
        return {"title": "", "status_code": 0, "server": "", "impersonated_brand": None, "impersonation_risk": False, "error": str(e)[:100]}

def compute_threat_index(result: dict, whois_info: dict = None, ssl_info: dict = None, webpage_meta: dict = None, vt_info: dict = None) -> dict:
    """Compute a multi-vector PhishShield Threat Score Index (0-100) and weighted risk breakdown."""
    base_confidence = result.get('confidence', 50)
    verdict = result.get('verdict', 'Safe')
    
    ai_score = (base_confidence * 0.9) if verdict == 'Malicious' else (base_confidence * 0.5) if verdict == 'Suspicious' else (100 - base_confidence) * 0.2
    factors = [{"name": "AI Neural NLP Engine", "weight": "35%", "risk": "High" if ai_score > 60 else "Medium" if ai_score > 30 else "Low", "score": round(ai_score)}]

    domain_score = 20
    if whois_info and whois_info.get("is_young"):
        domain_score = 85
        factors.append({"name": "Domain Longevity (<90 days old)", "weight": "20%", "risk": "High", "score": 85})
    elif whois_info and whois_info.get("age_days", 999) > 365:
        domain_score = 10
        factors.append({"name": "Domain Longevity (Established)", "weight": "20%", "risk": "Low", "score": 10})

    ssl_score = 15
    if ssl_info:
        if not ssl_info.get("valid"):
            ssl_score = 90
            factors.append({"name": "SSL Certificate Invalid / Missing", "weight": "15%", "risk": "High", "score": 90})
        elif ssl_info.get("is_free_cert"):
            ssl_score = 45
            factors.append({"name": "Free / Short-Lived SSL Certificate", "weight": "15%", "risk": "Medium", "score": 45})

    meta_score = 10
    if webpage_meta and webpage_meta.get("impersonation_risk"):
        meta_score = 95
        factors.append({"name": f"Brand Impersonation ({webpage_meta.get('impersonated_brand','').title()})", "weight": "15%", "risk": "Critical", "score": 95})

    vt_score = 10
    if vt_info and vt_info.get("status") == "success":
        mal = vt_info.get("malicious", 0)
        if mal > 0:
            vt_score = min(100, 50 + (mal * 10))
            factors.append({"name": f"VirusTotal Blacklisted ({mal} engines)", "weight": "15%", "risk": "Critical", "score": vt_score})

    final_score = min(100, max(0, round((ai_score * 0.35) + (domain_score * 0.20) + (ssl_score * 0.15) + (meta_score * 0.15) + (vt_score * 0.15))))
    risk_level = "CRITICAL THREAT" if final_score >= 80 else "SUSPICIOUS THREAT" if final_score >= 50 else "LOW RISK / SAFE"
    risk_color = "#f43f5e" if final_score >= 80 else "#f59e0b" if final_score >= 50 else "#10b981"

    return {
        "threat_index": final_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "factors": factors
    }

# ================================
# 5e. QR CODE ANALYSIS
# ================================

def decode_qr_from_image(image_bytes: bytes) -> dict:
    """Decode QR code from uploaded image using OpenCV."""
    if not QR_AVAILABLE:
        return {"error": "QR library not installed", "urls": []}
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return {"urls": [], "texts": [], "count": 0, "error": "Could not decode image"}
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        urls = []
        texts = []
        count = 0
        if data:
            count = 1
            if data.startswith(('http://', 'https://')):
                urls.append(data)
            else:
                texts.append(data)
        return {"urls": urls, "texts": texts, "count": count, "error": None}
    except Exception as e:
        return {"urls": [], "texts": [], "count": 0, "error": str(e)[:100]}

# ================================
# 5f. BATCH URL ANALYSIS
# ================================

def extract_urls_from_text(text: str) -> list:
    """Extract all URLs from text."""
    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    urls = url_pattern.findall(text)
    # Also detect bare domains
    bare_pattern = re.compile(r'(?<![\w/])www\.[\w.-]+\.[a-z]{2,}[^\s<>"\']*', re.IGNORECASE)
    urls.extend(bare_pattern.findall(text))
    return list(dict.fromkeys(urls))  # dedupe preserving order

def batch_analyze_urls(urls: list) -> list:
    """Analyze multiple URLs at once using AI."""
    if not urls:
        return []
    urls_text = '\n'.join(f'{i+1}. {u}' for i, u in enumerate(urls[:20]))  # max 20
    prompt = f"""Analyze each URL below for phishing. For EACH URL provide a verdict.

URLS:\n{urls_text}\n
Return ONLY valid JSON as a list of objects, each with:
- "url": the URL\n- "verdict": "Safe" | "Suspicious" | "Malicious"
- "confidence": 0-100\n- "reason": Brief reason (max 10 words)

Return a JSON array: [{{}}, {{}}, ...]"""
    try:
        result_text = ai_generate(AI_MODELS[0], prompt)
        result_text = re.sub(r'```json\s*', '', result_text)
        result_text = re.sub(r'```\s*', '', result_text)
        return normalize_verdict(json.loads(result_text))
    except Exception:
        return [{"url": u, "verdict": "Error", "confidence": 0, "reason": "Analysis failed"} for u in urls]

# ================================
# 5g. PDF EXPORT
# ================================

def clean_pdf_text(text: str) -> str:
    """Sanitize Unicode and special characters so FPDF core fonts render cleanly without errors."""
    if not text:
        return ""
    replacements = {
        '“': '"', '”': '"', '‘': "'", '’': "'", '—': '-', '–': '-',
        '•': '*', '…': '...', '™': '(TM)', '®': '(R)', '©': '(C)',
        '🚨': '[!] ', '📧': '[Email] ', '🛡️': '[Shield] ', '⚠️': '[WARN] ',
        '✅': '[OK] ', '❌': '[X] ', '🔍': '[Search] '
    }
    for k, v in replacements.items():
        text = str(text).replace(k, v)
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(result: dict, input_text: str, input_type: str) -> bytes:
    """Generate a PDF report of the analysis with safety fallbacks."""
    if not PDF_AVAILABLE or not result:
        return None
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        usable_w = pdf.w - pdf.l_margin - pdf.r_margin

        # Title Header
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', 'B', 16)
        pdf.cell(usable_w, 12, 'PhishShield AI - Threat Analysis Report', ln=True, align='C')
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(usable_w, 8, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True, align='C')
        pdf.ln(6)

        # Verdict
        verdict = clean_pdf_text(result.get('verdict', 'Unknown'))
        confidence = result.get('confidence', 0)
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.cell(usable_w, 10, clean_pdf_text(f'Verdict: {verdict.upper()} (Confidence: {confidence}%)'), ln=True)
        pdf.ln(4)

        # Explanation
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(usable_w, 8, 'Explanation:', ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', '', 10)
        explanation_txt = clean_pdf_text(result.get('explanation', 'N/A'))
        pdf.multi_cell(usable_w, 6, explanation_txt)
        pdf.ln(4)

        # Red Flags
        flags = result.get('red_flags', [])
        if flags:
            pdf.set_x(pdf.l_margin)
            pdf.set_font('Helvetica', 'B', 11)
            pdf.cell(usable_w, 8, 'Red Flags Detected:', ln=True)
            pdf.set_font('Helvetica', '', 10)
            for i, f in enumerate(flags):
                pdf.set_x(pdf.l_margin)
                flag_txt = clean_pdf_text(f'  {i+1}. {f}')
                pdf.multi_cell(usable_w, 6, flag_txt)
            pdf.ln(4)

        # Recommendation
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(usable_w, 8, 'Recommendation:', ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', '', 10)
        rec_txt = clean_pdf_text(result.get('recommendation', 'N/A'))
        pdf.multi_cell(usable_w, 6, rec_txt)
        pdf.ln(4)

        # Input Content
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(usable_w, 8, clean_pdf_text(f'Analyzed Content ({input_type.upper()}):'), ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', '', 8)
        content_preview = clean_pdf_text(input_text[:2000] if input_text else 'Image / Binary Upload')
        pdf.multi_cell(usable_w, 5, content_preview)

        # Footer
        pdf.ln(8)
        pdf.set_x(pdf.l_margin)
        pdf.set_font('Helvetica', 'I', 8)
        pdf.cell(usable_w, 6, 'PhishShield AI | Powered by Google Gemini | For educational purposes', ln=True, align='C')

        return bytes(pdf.output())
    except Exception as e:
        # Log error quietly and return None so app never crashes
        print(f"PDF Generation error caught safely: {e}")
        return None

# ================================
# 5h. MULTILINGUAL SUPPORT
# ================================

def get_analysis_prompt(user_input: str, language: str = "en") -> str:
    """Get the analysis prompt with language instruction."""
    lang_map = {
        "en": "English", "hi": "Hindi", "es": "Spanish", "fr": "French",
        "de": "German", "pt": "Portuguese", "ja": "Japanese",
        "ko": "Korean", "ar": "Arabic", "zh": "Chinese",
        "ru": "Russian", "bn": "Bengali", "ur": "Urdu",
    }
    lang_name = lang_map.get(language, "English")
    return f"""You are a senior cybersecurity analyst. Analyze the following input for phishing indicators.

Think step-by-step like a reasoning agent. Do NOT default to 'Safe'. Instead, critically evaluate every element.

IMPORTANT: Respond in {lang_name} language.

INPUT:
{user_input}

STEP 1 — WHAT IS THIS?
- Is this a URL? A full email? A chat message? A short link? Or something else?
- Determine the category first.

STEP 2 — THREAT ANALYSIS (check each):
1. Urgency / fear tactics ("Act NOW!", "Account suspended!")
2. Suspicious URLs (misspelled domains, unusual TLDs like .xyz .ru .tk, IP addresses, URL shorteners hiding destination)
3. Requests for credentials (passwords, credit cards, OTP, SSN)
4. Brand impersonation (fake PayPal, bank, Amazon, Microsoft, etc.)
5. Sender legitimacy (spoofed email, mismatched display name vs address)
6. Grammar/spelling errors common in phishing
7. Too-good-to-be-true offers (lottery, prize, inheritance)
8. Unusual attachments or encoding

STEP 3 — CONTEXT CHECK:
- Would a normal business or person send this?
- Does the tone match what it claims to be?
- Are there any inconsistencies?

STEP 4 — VERDICT:
Be honest and critical. If ANY red flag exists, lean toward Suspicious or Malicious.
- "Safe" = NO red flags, legitimate source, normal content
- "Suspicious" = 1-2 red flags, possibly phishing but not certain
- "Malicious" = 3+ red flags, clearly phishing or scam

Return ONLY valid JSON with these keys:
- "verdict": "Safe" | "Suspicious" | "Malicious"
- "confidence": 0-100
- "explanation": Plain-English summary (max 3 sentences)
- "red_flags": List of specific flags found (max 5 items)
- "recommendation": What the user should do next (1 sentence)"""

# ================================
# 6. PAGE CONFIG
# ================================
st.set_page_config(
    page_title="PhishShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Google AdSense verification — inject into page head
import streamlit.components.v1 as components
components.html("""
<script>
// Inject meta tag + AdSense script into parent page head
(function() {
    // Meta tag for site verification
    var meta = document.createElement('meta');
    meta.name = 'google-adsense-account';
    meta.content = 'ca-pub-3382996367685285';
    document.head.appendChild(meta);

    // AdSense script
    var script = document.createElement('script');
    script.async = true;
    script.crossOrigin = 'anonymous';
    script.src = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-3382996367685285';
    document.head.appendChild(script);
})();
</script>
""", height=0)

# ================================
# 7. MASSIVE CSS — FUTURISTIC 3D + IMAGE + SECURITY
# ================================

st.markdown("""


<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&display=swap');

/* ========================================
COSMIC PURPLE — DARK MODE (DEFAULT)
Deep space, violet neon, cyberpunk gloom
======================================== */
:root {
--bg-base:   #060212;
--bg-deep:   #0a0420;
--bg-panel:  #0f0628;
--bg-card:   #140930;
--bg-input:  #07021a;
--accent:    #a855f7;
--accent2:   #7c3aed;
--hot:       #ec4899;
--cyan:      #06b6d4;
--green:     #10b981;
--amber:     #f59e0b;
--red:       #f43f5e;
--fg:        #f1f5f9;
--fg2:       #d8b4fe;
--fg3:       #9f7aea;
--border:    rgba(168,85,247,0.35);
--border2:   rgba(168,85,247,0.6);
--shadow:    0 8px 32px rgba(0,0,0,0.75);
--glow-sm:   0 0 14px rgba(168,85,247,0.4);
--glow-md:   0 0 28px rgba(168,85,247,0.55);
}

/* ===== NUCLEAR BACKGROUND RESET ===== */
html, body,
.stApp,
[data-testid="stAppViewContainer"],
[data-testid="stAppViewBlockContainer"],
[data-testid="stMain"],
[data-testid="stMainBlockContainer"],
[data-testid="stVerticalBlock"],
[data-testid="stVerticalBlockBorderWrapper"],
[data-testid="stHorizontalBlock"],
[data-testid="stColumn"],
[data-testid="column"],
[data-testid="stHeader"],
[data-testid="stDecoration"],
[data-testid="stBottom"],
[data-testid="stSidebarContent"],
section[data-testid="stSidebar"],
div.block-container, div.main,
.stTabs, [data-testid="stTabs"],
[data-testid="stTabsTabPanel"],
div[role="tabpanel"],
[data-testid="stForm"],
.element-container,
[data-testid="stMarkdownContainer"] {
background-color: var(--bg-base) !important;
background: var(--bg-base) !important;
color: var(--fg) !important;
}

/* ===== APP SHELL ===== */
.stApp {
font-family: 'Rajdhani', sans-serif !important;
min-height: 100vh;
}

/* Deep space nebula gradient */
.stApp::before {
content: '';
position: fixed; inset: 0;
background:
radial-gradient(ellipse 90% 55% at 50% -5%, rgba(139,92,246,0.38) 0%, transparent 60%),
radial-gradient(circle at 8%  50%, rgba(236,72,153,0.18) 0%, transparent 40%),
radial-gradient(circle at 92% 72%, rgba(99,102,241,0.22) 0%, transparent 45%),
radial-gradient(ellipse at 50% 115%, rgba(168,85,247,0.22) 0%, transparent 55%);
z-index: 0; pointer-events: none;
animation: nebulaPulse 12s ease-in-out infinite alternate;
}
@keyframes nebulaPulse { 0%{opacity:0.75} 100%{opacity:1.0} }

/* Purple hex grid */
.stApp::after {
content: '';
position: fixed; inset: 0;
background-image:
linear-gradient(rgba(168,85,247,0.055) 1px, transparent 1px),
linear-gradient(90deg, rgba(168,85,247,0.055) 1px, transparent 1px);
background-size: 50px 50px;
mask-image: radial-gradient(ellipse at center, rgba(0,0,0,0.65) 0%, transparent 78%);
-webkit-mask-image: radial-gradient(ellipse at center, rgba(0,0,0,0.65) 0%, transparent 78%);
z-index: 0; pointer-events: none;
animation: gridDrift 15s ease-in-out infinite alternate;
}
@keyframes gridDrift { 0%{background-position:0 0;opacity:0.45} 100%{background-position:14px 14px;opacity:0.85} }

/* ===== PARTICLES ===== */
.particles { position:fixed; inset:0; z-index:0; pointer-events:none; overflow:hidden; }
.particle {
position:absolute; width:3px; height:3px;
background: var(--accent); border-radius:50%;
box-shadow: 0 0 8px var(--accent), 0 0 16px var(--accent2);
animation: floatUp linear infinite;
}
.particle:nth-child(1)  { left:7%;  animation-duration:11s; animation-delay:0s;   }
.particle:nth-child(2)  { left:18%; animation-duration:14s; animation-delay:2.5s; background:var(--hot); box-shadow:0 0 8px var(--hot); }
.particle:nth-child(3)  { left:30%; animation-duration:9s;  animation-delay:4s;   }
.particle:nth-child(4)  { left:45%; animation-duration:16s; animation-delay:1s;   background:var(--cyan); box-shadow:0 0 8px var(--cyan); }
.particle:nth-child(5)  { left:60%; animation-duration:13s; animation-delay:3s;   }
.particle:nth-child(6)  { left:74%; animation-duration:10s; animation-delay:5.5s; background:var(--hot); box-shadow:0 0 8px var(--hot); }
.particle:nth-child(7)  { left:87%; animation-duration:15s; animation-delay:1.5s; }
.particle:nth-child(8)  { left:52%; animation-duration:12s; animation-delay:0.5s; background:var(--accent2); box-shadow:0 0 8px var(--accent2); }
.particle:nth-child(9)  { left:25%; animation-duration:17s; animation-delay:3.5s; }
.particle:nth-child(10) { left:68%; animation-duration:19s; animation-delay:2s;   background:var(--cyan); box-shadow:0 0 8px var(--cyan); }
@keyframes floatUp {
0%   { transform:translateY(104vh) scale(0.2); opacity:0; }
12%  { opacity:0.9; }
88%  { opacity:0.9; }
100% { transform:translateY(-8vh) scale(1.5); opacity:0; }
}

/* ===== HERO ZONE ===== */
.hero-zone { text-align:center; padding:40px 20px 24px; position:relative; z-index:1; }
.shield-3d {
font-size:6rem; display:inline-block;
animation: shieldFloat 4s ease-in-out infinite, shieldGlow 2.5s ease-in-out infinite alternate;
filter: drop-shadow(0 0 30px rgba(168,85,247,0.65));
}
.shield-3d::after {
content:''; position:absolute; bottom:-16px; left:50%;
transform:translateX(-50%); width:90px; height:13px;
background:radial-gradient(ellipse,rgba(168,85,247,0.45),transparent 70%);
border-radius:50%; animation:shadowPulse 4s ease-in-out infinite;
}
@keyframes shieldFloat {
0%,100% { transform:translateY(0) rotateX(0deg) rotateY(0deg); }
25% { transform:translateY(-13px) rotateX(7deg) rotateY(-7deg); }
50% { transform:translateY(-6px) rotateX(0deg) rotateY(5deg); }
75% { transform:translateY(-15px) rotateX(-5deg) rotateY(7deg); }
}
@keyframes shieldGlow {
0%   { filter:drop-shadow(0 0 22px rgba(168,85,247,0.5)) drop-shadow(0 0 40px rgba(124,58,237,0.3)); }
100% { filter:drop-shadow(0 0 48px rgba(168,85,247,0.9)) drop-shadow(0 0 75px rgba(236,72,153,0.5)); }
}
@keyframes shadowPulse {
0%,100% { transform:translateX(-50%) scale(1); opacity:0.4; }
50%     { transform:translateX(-50%) scale(0.6); opacity:0.15; }
}

.main-title {
font-family:'Orbitron',sans-serif;
font-size:3.6rem; font-weight:900; letter-spacing:7px; margin:14px 0 5px;
background:linear-gradient(135deg, #f3e8ff 0%, #d8b4fe 22%, #c084fc 48%, #ec4899 75%, #a855f7 100%);
background-size:300% 300%;
-webkit-background-clip:text; -webkit-text-fill-color:transparent;
animation:titleShine 5s ease infinite;
}
@keyframes titleShine {
0%  { background-position:0% 50%; }
50% { background-position:100% 50%; }
100%{ background-position:0% 50%; }
}
.main-subtitle {
font-family:'Share Tech Mono','Courier New',monospace;
font-size:1rem; color:var(--fg2); letter-spacing:4px; text-transform:uppercase;
margin-bottom:8px; opacity:0.9;
}
.status-line {
font-family:'Share Tech Mono','Courier New',monospace;
font-size:0.85rem; color:var(--fg2); letter-spacing:2px;
display:inline-flex; align-items:center; gap:12px;
background: var(--bg-deep);
border:1px solid var(--border);
border-radius:30px; padding:6px 20px; white-space:nowrap;
box-shadow: var(--glow-sm);
}
.status-line .online { color:var(--green); animation:blink 1.5s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.35} }

/* ===== HOLO DIVIDER ===== */
.holo-divider {
height:2px; margin:22px 0;
background:linear-gradient(90deg,transparent,rgba(168,85,247,0.25),#a855f7,#ec4899,#8b5cf6,rgba(168,85,247,0.25),transparent);
position:relative;
}
.holo-divider::after {
content:''; position:absolute; top:50%; left:50%;
width:13px; height:13px; background:#c084fc; border-radius:3px;
transform:translate(-50%,-50%) rotate(45deg);
box-shadow:0 0 14px #a855f7, 0 0 28px #ec4899;
animation:diamondRotate 4s linear infinite;
}
@keyframes diamondRotate {
0%   { transform:translate(-50%,-50%) rotate(45deg); }
50%  { transform:translate(-50%,-50%) rotate(225deg) scale(1.12); }
100% { transform:translate(-50%,-50%) rotate(405deg); }
}

/* ===== GLASS PANEL ===== */
.glass-panel {
background: var(--bg-panel);
border:1px solid var(--border); border-radius:20px; padding:24px;
position:relative; overflow:hidden;
box-shadow: var(--shadow), inset 0 1px 0 rgba(168,85,247,0.1), var(--glow-sm);
transition:all 0.3s ease; z-index:1;
}
.glass-panel::before {
content:''; position:absolute; top:0; left:0; right:0; height:1px;
background:linear-gradient(90deg,transparent,rgba(168,85,247,0.65),rgba(236,72,153,0.4),transparent);
}
.glass-panel:hover {
border-color:var(--border2);
box-shadow:var(--shadow),var(--glow-md);
transform:translateY(-2px);
}
.glass-panel *, .glass-panel p, .glass-panel span, .glass-panel div { color:var(--fg); }

.corner-decor { position:relative; }
.corner-decor::before,.corner-decor::after {
content:''; position:absolute; width:16px; height:16px;
border-color:var(--accent); border-style:solid; pointer-events:none;
}
.corner-decor::before { top:8px; left:8px; border-width:2px 0 0 2px; }
.corner-decor::after  { bottom:8px; right:8px; border-width:0 2px 2px 0; }

/* ===== SECTION TITLES ===== */
.section-title {
font-family:'Orbitron',sans-serif; font-size:1rem; font-weight:700;
color:var(--fg2); letter-spacing:3px; text-transform:uppercase;
margin-bottom:16px; display:flex; align-items:center; gap:10px;
}
.section-title .dot {
width:8px; height:8px; background:var(--accent);
border-radius:2px; transform:rotate(45deg); box-shadow:var(--glow-sm);
}
.section-title .line { flex:1; height:1px; background:linear-gradient(90deg,rgba(168,85,247,0.4),transparent); }

/* ===== TEXTAREA ===== */
.stTextArea, .stTextArea > div, .stTextArea > div > div, .stTextArea > label { background:transparent !important; }
.stTextArea textarea, textarea {
background:var(--bg-input) !important; background-color:var(--bg-input) !important;
border:1px solid var(--border) !important; border-radius:14px !important;
color:#e9d5ff !important; font-family:'Share Tech Mono','Courier New',monospace !important;
font-size:0.95rem !important; padding:16px !important;
box-shadow:inset 0 2px 10px rgba(0,0,0,0.65) !important;
transition:all 0.3s ease !important; caret-color:var(--accent) !important;
}
.stTextArea textarea:focus, textarea:focus {
border-color:var(--accent) !important;
box-shadow:var(--glow-sm), inset 0 2px 10px rgba(0,0,0,0.65) !important;
outline:none !important;
}
.stTextArea textarea::placeholder, textarea::placeholder {
color:rgba(192,132,252,0.45) !important; font-style:italic !important;
}

/* ===== BUTTONS ===== */
.stButton > button {
background:linear-gradient(135deg,rgba(124,58,237,0.25),rgba(236,72,153,0.15)) !important;
border:1px solid var(--border) !important; border-radius:12px !important;
padding:12px 24px !important; font-family:'Orbitron',sans-serif !important;
font-weight:700 !important; font-size:0.85rem !important; color:#e9d5ff !important;
letter-spacing:2px !important; text-transform:uppercase !important;
transition:all 0.3s cubic-bezier(0.25,0.46,0.45,0.94) !important;
position:relative !important; overflow:hidden !important;
box-shadow:0 4px 14px rgba(0,0,0,0.4), var(--glow-sm) !important;
}
.stButton > button:hover {
transform:translateY(-3px) scale(1.02) !important;
border-color:var(--accent) !important; color:#fff !important;
background:linear-gradient(135deg,rgba(168,85,247,0.4),rgba(236,72,153,0.3)) !important;
box-shadow:0 10px 28px rgba(0,0,0,0.4), var(--glow-md) !important;
}
.stButton > button[kind="primary"] {
background:linear-gradient(135deg,#7c3aed 0%,#a855f7 45%,#ec4899 100%) !important;
border:1px solid rgba(255,255,255,0.2) !important; color:#fff !important;
font-size:1.05rem !important; font-weight:800 !important;
padding:16px 36px !important; letter-spacing:3px !important;
box-shadow:0 8px 28px rgba(124,58,237,0.5), 0 0 45px rgba(236,72,153,0.25) !important;
}
.stButton > button[kind="primary"]:hover {
transform:translateY(-4px) scale(1.02) !important;
box-shadow:0 14px 42px rgba(168,85,247,0.7), 0 0 65px rgba(236,72,153,0.4) !important;
}

/* ===== RESULT PANELS ===== */
.verdict-safe {
background:linear-gradient(135deg,rgba(16,185,129,0.14) 0%,var(--bg-panel) 100%);
border:1px solid rgba(16,185,129,0.42);
box-shadow:0 14px 42px rgba(0,0,0,0.6), 0 0 38px rgba(16,185,129,0.18);
border-radius:20px; padding:28px; margin:18px 0; animation:resultReveal 0.6s ease;
}
.verdict-suspicious {
background:linear-gradient(135deg,rgba(245,158,11,0.14) 0%,var(--bg-panel) 100%);
border:1px solid rgba(245,158,11,0.48);
box-shadow:0 14px 42px rgba(0,0,0,0.6), 0 0 38px rgba(245,158,11,0.18);
border-radius:20px; padding:28px; margin:18px 0; animation:resultReveal 0.6s ease;
}
.verdict-malicious {
background:linear-gradient(135deg,rgba(244,63,94,0.18) 0%,var(--bg-panel) 100%);
border:1px solid rgba(244,63,94,0.58);
box-shadow:0 14px 48px rgba(0,0,0,0.65), 0 0 52px rgba(244,63,94,0.22);
border-radius:20px; padding:28px; margin:18px 0;
animation:resultReveal 0.6s ease, maliciousGlow 3s ease-in-out infinite;
}
@keyframes resultReveal { from{opacity:0;transform:translateY(30px) scale(0.96)} to{opacity:1;transform:none} }
@keyframes maliciousGlow {
0%,100% { border-color:rgba(244,63,94,0.5); box-shadow:0 0 40px rgba(244,63,94,0.2); }
50%     { border-color:rgba(244,63,94,0.9); box-shadow:0 0 68px rgba(244,63,94,0.45); }
}
.result-3d { border-radius:20px; padding:28px; margin:18px 0; animation:resultReveal 0.6s ease; }
.result-safe { background:linear-gradient(135deg,rgba(16,185,129,0.14) 0%,var(--bg-panel) 100%); border:1px solid rgba(16,185,129,0.42); box-shadow:0 14px 42px rgba(0,0,0,0.6); }
.result-suspicious { background:linear-gradient(135deg,rgba(245,158,11,0.14) 0%,var(--bg-panel) 100%); border:1px solid rgba(245,158,11,0.48); }
.result-malicious { background:linear-gradient(135deg,rgba(244,63,94,0.18) 0%,var(--bg-panel) 100%); border:1px solid rgba(244,63,94,0.58); animation:resultReveal 0.6s ease, maliciousGlow 3s ease-in-out infinite; }
.result-error { background:linear-gradient(135deg,rgba(100,100,120,0.12) 0%,var(--bg-panel) 100%); border:1px solid rgba(140,140,160,0.3); }
.verdict-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; }
.verdict-label { font-family:'Orbitron',sans-serif; font-size:0.85rem; font-weight:700; letter-spacing:4px; text-transform:uppercase; color:var(--fg2); }
.verdict-text { font-family:'Orbitron',sans-serif; font-size:2.8rem; font-weight:900; letter-spacing:3px; margin-bottom:18px; }
.result-safe .verdict-text, .verdict-safe .verdict-text   { color:#10b981; text-shadow:0 0 28px rgba(16,185,129,0.6); }
.result-suspicious .verdict-text, .verdict-suspicious .verdict-text { color:#f59e0b; text-shadow:0 0 28px rgba(245,158,11,0.6); }
.result-malicious .verdict-text, .verdict-malicious .verdict-text  { color:#f43f5e; text-shadow:0 0 32px rgba(244,63,94,0.7); }
.result-error .verdict-text { color:#94a3b8; }

/* ===== CONFIDENCE BAR ===== */
.confidence-wrap { margin:18px 0; }
.conf-header { display:flex; justify-content:space-between; font-family:'Share Tech Mono',monospace; font-size:0.85rem; color:var(--fg2); letter-spacing:2px; margin-bottom:8px; }
.conf-track { height:10px; background:rgba(255,255,255,0.06); border-radius:6px; overflow:hidden; }
.conf-fill { height:100%; border-radius:6px; position:relative; transition:width 1.5s cubic-bezier(0.25,0.46,0.45,0.94); }
.conf-fill::after { content:''; position:absolute; inset:0; background:linear-gradient(90deg,transparent,rgba(255,255,255,0.4),transparent); animation:barShimmer 2s ease-in-out infinite; }
@keyframes barShimmer { 0%{transform:translateX(-100%)} 100%{transform:translateX(200%)} }

/* ===== EXPLANATION & FLAGS ===== */
.explanation-block {
background:rgba(124,58,237,0.12); border-left:3px solid var(--accent);
padding:16px 20px; margin:18px 0; border-radius:0 12px 12px 0;
font-family:'Rajdhani',sans-serif; font-size:1.05rem; color:#f3e8ff; line-height:1.6;
}
.red-flag { display:flex; align-items:flex-start; gap:14px; padding:14px 18px; margin:8px 0; background:rgba(244,63,94,0.08); border:1px solid rgba(244,63,94,0.25); border-radius:12px; transition:all 0.3s ease; }
.red-flag:hover { background:rgba(244,63,94,0.14); border-color:rgba(244,63,94,0.5); transform:translateX(6px); }
.flag-num { font-family:'Orbitron',sans-serif; font-size:0.75rem; font-weight:700; color:#f43f5e; background:rgba(244,63,94,0.18); padding:4px 10px; border-radius:6px; }
.flag-text { font-family:'Rajdhani',sans-serif; font-size:1.05rem; color:#fce7f3; line-height:1.4; }
.rec-box { background:linear-gradient(135deg,rgba(168,85,247,0.1),rgba(99,102,241,0.06)); border:1px solid rgba(168,85,247,0.3); border-radius:14px; padding:20px 24px; margin:18px 0; }
.rec-label { font-family:'Orbitron',sans-serif; font-size:0.85rem; font-weight:700; color:var(--fg2); letter-spacing:3px; margin-bottom:8px; }
.rec-text { font-family:'Rajdhani',sans-serif; font-size:1.1rem; color:#f3e8ff; line-height:1.6; }

/* ===== STAT TILES ===== */
.stat-tile {
background:var(--bg-card); border:1px solid rgba(168,85,247,0.22);
border-radius:16px; padding:24px 18px; text-align:center;
position:relative; overflow:hidden; transition:all 0.4s ease; box-shadow:var(--shadow);
}
.stat-tile:hover { transform:translateY(-8px) scale(1.02); border-color:rgba(168,85,247,0.55); box-shadow:0 18px 40px rgba(0,0,0,0.6),var(--glow-md); }
.stat-tile::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,transparent,#a855f7,transparent); opacity:0; transition:opacity 0.3s; }
.stat-tile:hover::before { opacity:1; }
.stat-icon { font-size:2.2rem; margin-bottom:8px; display:block; }
.stat-number { font-family:'Orbitron',sans-serif; font-size:2.4rem; font-weight:900; background:linear-gradient(135deg,#f3e8ff,#c084fc,#ec4899); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:4px; }
.stat-label { font-family:'Share Tech Mono',monospace; font-size:0.8rem; color:rgba(216,180,254,0.7); letter-spacing:2px; text-transform:uppercase; }

/* ===== TIP CARDS — FULLY OPAQUE DARK ===== */
.tip-card-3d {
background: var(--bg-card);
border: 1px solid rgba(168,85,247,0.28);
border-radius:16px; padding:22px 18px; text-align:center;
height:195px; display:flex; flex-direction:column; align-items:center; justify-content:center;
transition:all 0.4s cubic-bezier(0.25,0.46,0.45,0.94);
box-shadow:var(--shadow), inset 0 1px 0 rgba(168,85,247,0.08);
position:relative; overflow:hidden;
}
.tip-card-3d::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,transparent,rgba(168,85,247,0.7),transparent); opacity:0; transition:opacity 0.3s; }
.tip-card-3d:hover { transform:translateY(-8px) perspective(600px) rotateX(4deg); border-color:rgba(168,85,247,0.6); box-shadow:0 16px 35px rgba(0,0,0,0.65),var(--glow-md); }
.tip-card-3d:hover::before { opacity:1; }
.tip-icon-3d { font-size:2.4rem; margin-bottom:12px; transition:transform 0.4s ease; }
.tip-card-3d:hover .tip-icon-3d { transform:scale(1.2) rotate(6deg); }
.tip-title-3d { font-family:'Orbitron',sans-serif; font-size:0.9rem; font-weight:700; color:#e9d5ff; letter-spacing:2px; margin-bottom:8px; }
.tip-desc-3d { font-family:'Rajdhani',sans-serif; font-size:0.95rem; color:rgba(216,180,254,0.78); line-height:1.4; }

/* ===== LOADER ===== */
.loader-3d { text-align:center; padding:50px 20px; }
.loader-radar { width:85px; height:85px; margin:0 auto 20px; border:3px solid transparent; border-top-color:#a855f7; border-right-color:#ec4899; border-radius:50%; animation:radarSpin 1s linear infinite; position:relative; box-shadow:0 0 28px rgba(168,85,247,0.4); }
.loader-radar::before { content:''; position:absolute; inset:8px; border:2px solid transparent; border-bottom-color:#8b5cf6; border-left-color:#06b6d4; border-radius:50%; animation:radarSpin 0.7s linear infinite reverse; }
.loader-radar::after { content:'🛡️'; position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); font-size:1.6rem; animation:radarPulse 1.5s ease-in-out infinite; }
@keyframes radarSpin  { from{transform:rotate(0deg)}   to{transform:rotate(360deg)} }
@keyframes radarPulse { 0%,100%{transform:translate(-50%,-50%) scale(1)} 50%{transform:translate(-50%,-50%) scale(1.2)} }
.loader-text { font-family:'Orbitron',sans-serif; font-size:1rem; color:var(--fg2); letter-spacing:4px; animation:pulseText 1.5s ease-in-out infinite; }
@keyframes pulseText { 0%,100%{opacity:1} 50%{opacity:0.4} }
.loader-subtext { font-family:'Share Tech Mono',monospace; font-size:0.8rem; color:rgba(216,180,254,0.5); letter-spacing:2px; margin-top:6px; }

/* ===== HISTORY ===== */
.history-row { display:flex; align-items:center; justify-content:space-between; padding:12px 16px; margin:6px 0; background:var(--bg-card); border:1px solid rgba(168,85,247,0.15); border-radius:10px; font-family:'Share Tech Mono',monospace; font-size:0.85rem; transition:all 0.2s ease; }
.history-row:hover { background:var(--bg-panel); border-color:rgba(168,85,247,0.42); }

/* ===== FOOTER ===== */
.footer-futuristic { text-align:center; padding:35px 20px 20px; }
.footer-brand { font-family:'Orbitron',sans-serif; font-size:1.25rem; font-weight:800; letter-spacing:4px; background:linear-gradient(135deg,#c084fc,#ec4899,#8b5cf6); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.footer-sub { font-family:'Share Tech Mono',monospace; font-size:0.8rem; color:rgba(216,180,254,0.4); letter-spacing:3px; margin-top:6px; }

/* ===== STREAMLIT WIDGET OVERRIDES ===== */
#MainMenu, footer, header { visibility:hidden !important; }
.stDeployButton { display:none !important; }
::-webkit-scrollbar { width:7px; }
::-webkit-scrollbar-track { background:var(--bg-base); }
::-webkit-scrollbar-thumb { background:rgba(168,85,247,0.3); border-radius:4px; }
::-webkit-scrollbar-thumb:hover { background:rgba(168,85,247,0.6); }

/* Expanders */
.streamlit-expanderHeader,[data-testid="stExpander"] summary,details summary {
font-family:'Orbitron',sans-serif !important; font-size:0.85rem !important;
color:var(--fg2) !important; letter-spacing:2px !important;
background:var(--bg-deep) !important; border:1px solid rgba(168,85,247,0.25) !important; border-radius:10px !important;
}
[data-testid="stExpander"] { background:var(--bg-deep) !important; border:1px solid rgba(168,85,247,0.2) !important; border-radius:12px !important; }

/* Selectbox */
[data-testid="stSelectbox"] > div > div, .stSelectbox > div > div, [data-testid="stSelectbox"] div[data-baseweb="select"] > div {
background:var(--bg-deep) !important; border:1px solid rgba(168,85,247,0.4) !important; border-radius:10px !important; color:#e9d5ff !important;
}
[data-baseweb="menu"],[data-baseweb="popover"],ul[data-baseweb="menu"] { background:var(--bg-deep) !important; border:1px solid rgba(168,85,247,0.4) !important; border-radius:12px !important; }
li[role="option"] { color:#e9d5ff !important; }
li[role="option"]:hover { background:rgba(168,85,247,0.18) !important; }

/* Radio */
[data-testid="stRadio"] label, .stRadio label { color:var(--fg2) !important; font-family:'Rajdhani',sans-serif !important; }
[data-testid="stRadio"] > div { background:transparent !important; gap:4px; }

/* File Uploader */
[data-testid="stFileUploader"],[data-testid="stFileUploadDropzone"] {
background:var(--bg-deep) !important; border:2px dashed rgba(168,85,247,0.35) !important; border-radius:16px !important; color:var(--fg2) !important;
}

/* Tabs */
[data-testid="stTabs"] [role="tablist"] { background:var(--bg-deep) !important; border-bottom:1px solid rgba(168,85,247,0.3) !important; border-radius:12px 12px 0 0 !important; gap:4px !important; padding:4px 6px !important; }
[data-testid="stTabs"] [role="tab"] { font-family:'Orbitron',sans-serif !important; font-size:0.78rem !important; font-weight:600 !important; letter-spacing:2px !important; color:rgba(192,132,252,0.65) !important; background:transparent !important; border:none !important; padding:10px 18px !important; border-radius:8px !important; transition:all 0.25s ease !important; }
[data-testid="stTabs"] [role="tab"]:hover { color:#e9d5ff !important; background:rgba(168,85,247,0.12) !important; }
[data-testid="stTabs"] [role="tab"][aria-selected="true"] { color:#fff !important; background:linear-gradient(135deg,rgba(124,58,237,0.4),rgba(168,85,247,0.28)) !important; border:1px solid rgba(168,85,247,0.55) !important; box-shadow:0 0 16px rgba(168,85,247,0.35) !important; }
[data-testid="stTabsTabPanel"] { background:transparent !important; padding:0 !important; }

/* Labels & Markdown */
label, .stLabel,
[data-testid="stWidgetLabel"] > div, [data-testid="stWidgetLabel"] p,
[data-testid="stMarkdownContainer"] > p, [data-testid="stMarkdownContainer"] > ul > li,
[data-testid="stMarkdownContainer"] > h1, [data-testid="stMarkdownContainer"] > h2, [data-testid="stMarkdownContainer"] > h3 {
color:var(--fg) !important;
}

/* Metric Cards */
[data-testid="stMetric"] { background:var(--bg-card) !important; border:1px solid rgba(168,85,247,0.2) !important; border-radius:12px !important; padding:12px !important; }
[data-testid="stMetricValue"] { color:#e9d5ff !important; }
[data-testid="stMetricDelta"] { color:#a855f7 !important; }
[data-testid="stMetricLabel"] { color:var(--fg2) !important; }

/* Checkbox/Toggle */
[data-testid="stCheckbox"] label,[data-testid="stToggle"] label { color:var(--fg2) !important; }

/* Number/Text Input */
[data-testid="stNumberInput"] input,[data-testid="stTextInput"] input {
background:var(--bg-input) !important; background-color:var(--bg-input) !important;
border:1px solid rgba(168,85,247,0.35) !important; border-radius:10px !important;
color:#f3e8ff !important; font-family:'Share Tech Mono','Courier New',monospace !important;
}
[data-testid="stNumberInput"] input:focus,[data-testid="stTextInput"] input:focus {
border-color:#a855f7 !important; box-shadow:0 0 14px rgba(168,85,247,0.25) !important;
}

/* Alerts */
[data-testid="stAlert"] { background:var(--bg-card) !important; border-radius:12px !important; color:var(--fg) !important; }
[data-testid="stInfo"]    { background:rgba(99,102,241,0.1)  !important; border-left:3px solid #6366f1 !important; }
[data-testid="stSuccess"] { background:rgba(16,185,129,0.09) !important; border-left:3px solid #10b981 !important; }
[data-testid="stWarning"] { background:rgba(245,158,11,0.09) !important; border-left:3px solid #f59e0b !important; }
[data-testid="stError"]   { background:rgba(244,63,94,0.09)  !important; border-left:3px solid #f43f5e !important; }
[data-testid="stTooltipIcon"] { color:#a855f7 !important; }
hr { border-color:rgba(168,85,247,0.2) !important; }
.block-container { padding-top:1rem !important; padding-bottom:2rem !important; max-width:1400px !important; }
</style>

<!-- Floating Particles -->
<div class="particles">
<div class="particle"></div><div class="particle"></div>
<div class="particle"></div><div class="particle"></div>
<div class="particle"></div><div class="particle"></div>
<div class="particle"></div><div class="particle"></div>
<div class="particle"></div><div class="particle"></div>
</div>

""", unsafe_allow_html=True)

# ================================
# 8. HERO SECTION
# ================================

st.markdown("""


<div class="hero-zone">
<div class="shield-3d">🛡️</div>
<div class="main-title">PHISHSHIELD AI</div>
<div class="main-subtitle">NEXT-GEN NEURAL THREAT DEFENSE PLATFORM</div>
<div style="margin-top: 10px;">
<div class="status-line">
<span class="online">● ONLINE</span>
&nbsp;|&nbsp; ENGINE: GEMINI-3.X &nbsp;|&nbsp; SHIELD: ARMED
</div>
</div>
</div>

""", unsafe_allow_html=True)

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

# ================================
# 9. TOP BAR — MODE + LANGUAGE
# ================================

top_c1, top_c2 = st.columns([3, 2], gap="large")

with top_c1:
    st.markdown("""


<div class="section-title" style="font-size:0.95rem; margin-bottom:6px;">
<span class="dot"></span> INPUT PROTOCOL
</div>

""", unsafe_allow_html=True)
    input_mode = st.radio(
        "", ["\U0001f4dd TEXT", "\U0001f5bc\ufe0f IMAGE", "\U0001f4e7 HEADERS", "\U0001f4f7 QR CODE", "\U0001f4cb BATCH URLs"],
        horizontal=True, label_visibility="collapsed", key="input_mode"
    )

with top_c2:
    st.markdown("""


<div class="section-title" style="font-size:0.95rem; margin-bottom:6px;">
<span class="dot"></span> LINGUISTIC ENGINE
</div>

""", unsafe_allow_html=True)
    analysis_language = st.selectbox(
        "", [
            ("en", "English"), ("hi", "Hindi"), ("es", "Spanish"),
            ("fr", "French"), ("de", "German"), ("pt", "Portuguese"),
            ("ja", "Japanese"), ("ko", "Korean"), ("ar", "Arabic"),
            ("zh", "Chinese"), ("ru", "Russian"), ("bn", "Bengali"), ("ur", "Urdu"),
        ],
        format_func=lambda x: x[1], label_visibility="collapsed", key="lang_select"
    )
    selected_lang = analysis_language[0]

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

# ================================
# 10. INPUT SECTION
# ================================

user_input = ""
uploaded_image = None
image_bytes = None
image_mime = None
header_text = ""
qr_image_bytes = None
batch_text = ""

if "TEXT" in input_mode:
    col_left, col_right = st.columns([5, 3], gap="large")

    with col_left:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> TEXT INPUT <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)

        user_input = st.text_area(
            "",
            height=200,
            placeholder=">> Paste suspicious URL or email content here...\n\n   Example: https://paypal-verify-account.xyz/confirm\n   Or paste a full phishing email...",
            label_visibility="collapsed",
            key="text_input"
        )

    with col_right:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> QUICK SIMULATION <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)

        if st.button("🔴  PHISHING URL", key="ex1", use_container_width=True):
            st.session_state['ui_input'] = "https://paypal-secure-verify.xyz/account/update?token=abc123"
            st.rerun()
        if st.button("📧  PHISHING EMAIL", key="ex2", use_container_width=True):
            st.session_state['ui_input'] = """Dear Customer,

We have detected unusual activity on your bank account. Your account has been temporarily restricted.

To restore access, verify your identity immediately:
https://secure-banking-login.ru/auth/update

WARNING: Failure to verify within 24 hours will result in permanent account closure.

Sincerely,
Customer Security Division"""
            st.rerun()
        if st.button("🟢  SAFE URL", key="ex3", use_container_width=True):
            st.session_state['ui_input'] = "https://github.com/trending"
            st.rerun()
        if st.button("🔗  NEUTRAL LINK", key="ex4", use_container_width=True):
            st.session_state['ui_input'] = "Hey check this out: https://www.wired.com/story/best-cybersecurity-practices-2024/"
            st.rerun()

    if 'ui_input' in st.session_state:
        user_input = st.session_state['ui_input']
        st.session_state['ui_input'] = ""

elif "IMAGE" in input_mode:
    col_img_left, col_img_right = st.columns([5, 3], gap="large")

    with col_img_left:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> IMAGE UPLOAD <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)

        uploaded_image = st.file_uploader(
            "",
            type=["png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff"],
            label_visibility="collapsed",
            help=f"Max {MAX_IMAGE_SIZE_MB}MB • PNG, JPEG, GIF, WebP, BMP, TIFF",
            key="image_upload"
        )

        if uploaded_image:
            # Validate the upload
            is_valid, validation_msg = validate_image_upload(uploaded_image)

            if is_valid:
                image_bytes = uploaded_image.read()
                image_mime = uploaded_image.type
                uploaded_image.seek(0)

                # Show preview
                st.markdown(f"""


<div class="image-preview-box">
<div class="image-preview-label">PREVIEW — {uploaded_image.name}</div>
</div>

""", unsafe_allow_html=True)
                st.image(uploaded_image, use_container_width=True)

                # Show file info
                file_size_kb = uploaded_image.size / 1024
                st.markdown(f"""


<div style="display:flex; gap:15px; margin-top:10px; font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:rgba(0,255,200,0.4);">
<span>📎 {uploaded_image.name}</span>
<span>📏 {file_size_kb:.1f} KB</span>
<span>🖼️ {image_mime}</span>
<span style="color:#00ffc8;">✓ VERIFIED</span>
</div>

""", unsafe_allow_html=True)
            else:
                st.markdown(f"""


<div class="sec-alert">
<div class="sec-alert-icon">⚠️</div>
<div class="sec-alert-text">Upload rejected: {html.escape(validation_msg)}</div>
</div>

""", unsafe_allow_html=True)

    with col_img_right:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> IMAGE ANALYSIS TIPS <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)

        st.markdown("""


<div style="font-family:'Rajdhani',sans-serif; color:rgba(0,255,200,0.5); line-height:1.8; font-size:0.95rem;">
<b style="color:#00ffc8;">📸 WHAT TO UPLOAD:</b><br><br>

• <b>Screenshots</b> of suspicious emails<br>
• <b>Phishing login pages</b><br>
• <b>Fake security alerts</b><br>
• <b>Suspicious text messages</b><br>
• <b>Social media scam posts</b><br><br>

<b style="color:#00ffc8;">🔍 AI WILL DETECT:</b><br><br>

• Fake login forms<br>
• Spoofed brand logos<br>
• Urgency tactics<br>
• Suspicious URLs<br>
• Credential harvesting<br>
</div>

""", unsafe_allow_html=True)

elif "HEADERS" in input_mode:
    # EMAIL HEADER MODE
    col_h1, col_h2 = st.columns([5, 3], gap="large")
    with col_h1:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> EMAIL HEADERS <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)
        header_text = st.text_area(
            "", height=250,
            placeholder=">> Paste raw email headers here...\n\n   Copy from: Gmail > Show Original > Copy to Clipboard\n   Or Outlook: File > Properties > Internet Headers",
            label_visibility="collapsed", key="header_input"
        )
    with col_h2:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> HEADER ANALYSIS <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)
        st.markdown("""


<div style="font-family:'Rajdhani',sans-serif; color:rgba(0,255,200,0.5); line-height:1.8; font-size:0.95rem;">
<b style="color:#00ffc8;">📧 HOW TO GET HEADERS:</b><br><br>
<b>Gmail:</b> Open email > ⋮ > Show Original > Copy<br>
<b>Outlook:</b> Open email > File > Properties > Internet Headers<br>
<b>Yahoo:</b> Open email > ⋮ > View Raw Message<br><br>
<b style="color:#00ffc8;">🔍 WE CHECK:</b><br><br>
• Sender vs Reply-To mismatch<br>
• SPF / DKIM / DMARC status<br>
• Email relay chain anomalies<br>
• Spoofed display names
</div>

""", unsafe_allow_html=True)

elif "QR" in input_mode:
    # QR CODE MODE
    col_q1, col_q2 = st.columns([5, 3], gap="large")
    with col_q1:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> QR CODE UPLOAD <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)
        qr_file = st.file_uploader("", type=["png","jpg","jpeg","gif","bmp"], label_visibility="collapsed", key="qr_upload")
        if qr_file:
            qr_image_bytes = qr_file.read()
            qr_file.seek(0)
            st.image(qr_file, use_container_width=True)
            # Try immediate decode
            if QR_AVAILABLE:
                qr_result = decode_qr_from_image(qr_image_bytes)
                if qr_result.get("urls"):
                    st.success(f"🔗 Found {len(qr_result['urls'])} URL(s): " + ", ".join(qr_result["urls"][:3]))
                elif qr_result.get("texts"):
                    st.info(f"📝 Found text: {qr_result['texts'][0][:100]}")
                elif qr_result.get("error"):
                    st.warning(f"No QR code detected: {qr_result['error']}")
                else:
                    st.warning("No QR code found in this image.")
            else:
                st.warning("QR library not available. Install pyzbar.")
    with col_q2:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> QR PHISHING (QUISHING) <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)
        st.markdown("""


<div style="font-family:'Rajdhani',sans-serif; color:rgba(0,255,200,0.5); line-height:1.8; font-size:0.95rem;">
<b style="color:#00ffc8;">⚠️ QR CODES ARE A GROWING THREAT</b><br><br>

Attackers place malicious QR codes on:<br>
• Restaurant menus<br>
• Parking meters<br>
• Public posters<br>
• Phishing emails<br><br>

<b style="color:#00ffc8;">🔍 WE WILL:</b><br><br>
• Decode the hidden URL<br>
• Check the destination<br>
• Analyze for phishing indicators
</div>

""", unsafe_allow_html=True)

elif "BATCH" in input_mode:
    # BATCH URL MODE
    col_b1, col_b2 = st.columns([5, 3], gap="large")
    with col_b1:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> BATCH URL INPUT <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)
        batch_text = st.text_area(
            "", height=250,
            placeholder=">> Paste multiple URLs (one per line) or paste email content to extract URLs:\n\n   https://example.com/link1\n   https://suspicious-site.xyz/verify\n   bit.ly/3xYzAbC",
            label_visibility="collapsed", key="batch_input"
        )
    with col_b2:
        st.markdown("""


<div class="glass-panel corner-decor">
<div class="section-title">
<span class="dot"></span> BATCH MODE <span class="line"></span>
</div>
</div>

""", unsafe_allow_html=True)
        st.markdown("""


<div style="font-family:'Rajdhani',sans-serif; color:rgba(0,255,200,0.5); line-height:1.8; font-size:0.95rem;">
<b style="color:#00ffc8;">📋 BATCH ANALYSIS</b><br><br>

Analyze up to <b>20 URLs</b> at once.<br><br>

<b style="color:#00ffc8;">💡 TIPS:</b><br><br>

• Paste email content — we'll extract URLs<br>
• One URL per line for best results<br>
• Results shown in a color-coded table<br>
• Great for checking email newsletters
</div>

""", unsafe_allow_html=True)

# ================================
# 11. ANALYZE BUTTON
# ================================

st.markdown('<div style="margin: 30px 0;"></div>', unsafe_allow_html=True)

col_btn1, col_btn2, col_btn3 = st.columns([2, 3, 2])
with col_btn2:
    analyze_clicked = st.button(
        "🔍  INITIATE THREAT ANALYSIS",
        type="primary",
        use_container_width=True,
        key="analyze"
    )

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

# ================================
# 12. ANALYSIS & RESULTS
# ================================

if analyze_clicked:
    # --- Security: Rate limit check ---
    rate_ok, rate_msg = check_rate_limit()
    if not rate_ok:
        st.markdown(f"""


<div class="sec-alert">
<div class="sec-alert-icon">🚫</div>
<div class="sec-alert-text">{html.escape(rate_msg)}</div>
</div>

""", unsafe_allow_html=True)
        st.stop()

    # --- Determine what to analyze ---
    has_text = "TEXT" in input_mode and user_input and user_input.strip()
    has_image = "IMAGE" in input_mode and image_bytes is not None
    has_headers = "HEADERS" in input_mode and header_text and header_text.strip()
    has_qr = "QR" in input_mode and qr_image_bytes is not None
    has_batch = "BATCH" in input_mode and batch_text and batch_text.strip()

    if not any([has_text, has_image, has_headers, has_qr, has_batch]):
        st.warning("⚠ Please provide input to analyze.")
        st.stop()

    # --- Security validation ---
    check_text = user_input if has_text else header_text if has_headers else batch_text if has_batch else ""
    sec_valid, sec_msg = validate_request_integrity(check_text, qr_image_bytes if has_qr else None)
    if not sec_valid:
        st.markdown(f"""


<div class="sec-alert">
<div class="sec-alert-icon">🚫</div>
<div class="sec-alert-text">{html.escape(sec_msg)}</div>
</div>

""", unsafe_allow_html=True)
        st.stop()

    # --- Loading ---
    loading_placeholder = st.empty()
    loading_placeholder.markdown("""
    <div class="loader-3d">
        <div class="loader-ring"></div>
        <div class="loader-text">SCANNING THREATS</div>
        <div class="loader-subtext">Neural networks analyzing input patterns...</div>
    </div>
    """, unsafe_allow_html=True)

    # --- Route to correct analysis ---
    result = None
    input_type = "text"
    preview = ""

    if has_text:
        input_type = "text"
        # Auto-detect URLs and unshorten
        urls_found = extract_urls_from_text(user_input)
        if urls_found:
            first_url = urls_found[0]
            if any(s in first_url for s in ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']):
                redirect = unshorten_url(first_url)
                if redirect.get("redirected"):
                    user_input += f"\n\n[Auto-unshortened: {first_url} -> {redirect['final']} (hops: {redirect['hops']})]"
        result = detect_phishing_text(user_input)
        preview = user_input

    elif has_image:
        input_type = "image"
        result = detect_phishing_image(image_bytes, image_mime)
        preview = uploaded_image.name if uploaded_image else "uploaded image"

    elif has_headers:
        input_type = "email_header"
        parsed = parse_email_headers(header_text)
        result = analyze_email_headers_ai(parsed)
        preview = f"From: {parsed.get('from', 'N/A')}"

    elif has_qr:
        input_type = "qr_code"
        qr_result = decode_qr_from_image(qr_image_bytes)
        if qr_result.get("urls"):
            qr_url = qr_result["urls"][0]
            # Unshorten + analyze
            redirect = unshorten_url(qr_url)
            analysis_url = redirect.get("final", qr_url)
            qr_input = f"QR Code URL: {qr_url}\nFinal destination: {analysis_url}\nRedirect hops: {redirect.get('hops', 0)}\nDomain: {redirect.get('final_domain', '')}"
            result = detect_phishing_text(qr_input)
            result["qr_data"] = qr_result
            result["redirect"] = redirect
            preview = f"QR -> {analysis_url}"
        elif qr_result.get("texts"):
            result = detect_phishing_text(f"QR Code content (not a URL): {qr_result['texts'][0]}")
            result["qr_data"] = qr_result
            preview = f"QR text: {qr_result['texts'][0][:60]}"
        else:
            result = {"verdict": "Safe", "confidence": 90, "explanation": "No URL found in QR code. It may contain plain text or be unreadable.", "red_flags": [], "recommendation": "Try uploading a clearer image of the QR code."}
            preview = "QR - no URL found"

    elif has_batch:
        input_type = "batch"
        urls = extract_urls_from_text(batch_text)
        if not urls:
            result = {"verdict": "Error", "confidence": 0, "explanation": "No URLs found in the input.", "red_flags": [], "recommendation": "Paste URLs one per line or paste email content containing URLs."}
            preview = batch_text[:80]
        else:
            batch_results = batch_analyze_urls(urls)
            # Count verdicts
            malicious_ct = sum(1 for r in batch_results if r.get("verdict") == "Malicious")
            suspicious_ct = sum(1 for r in batch_results if r.get("verdict") == "Suspicious")
            safe_ct = sum(1 for r in batch_results if r.get("verdict") == "Safe")
            if malicious_ct > 0:
                overall = "Malicious"
            elif suspicious_ct > 0:
                overall = "Suspicious"
            else:
                overall = "Safe"
            result = {
                "verdict": overall,
                "confidence": 85 if overall != "Safe" else 90,
                "explanation": f"Analyzed {len(urls)} URLs: {safe_ct} safe, {suspicious_ct} suspicious, {malicious_ct} malicious.",
                "red_flags": [f"{r.get('url','')} — {r.get('verdict','?')} ({r.get('reason','')})" for r in batch_results if r.get("verdict") != "Safe"][:5],
                "recommendation": f"Review the {malicious_ct + suspicious_ct} flagged URLs carefully.",
                "batch_results": batch_results,
                "batch_urls": urls,
            }
            preview = f"Batch: {len(urls)} URLs"

    time.sleep(0.5)
    loading_placeholder.empty()

    # --- Threat Intelligence Multi-Vector Enrichment ---
    whois_data = None
    ssl_data = None
    meta_data = None
    vt_data = None

    if result and input_type in ("text", "batch", "qr_code"):
        urls_check = extract_urls_from_text(preview if input_type == "text" else batch_text if input_type == "batch" else preview)
        if urls_check:
            try:
                target_url = urls_check[0]
                domain = urlparse(target_url).netloc or target_url.split('/')[0]
                if domain:
                    whois_data = whois_lookup(domain)
                    ssl_data = inspect_ssl_cert(domain)
                    meta_data = inspect_webpage_meta(target_url)
                    vt_data = virustotal_lookup(domain)
            except Exception:
                pass

    threat_matrix = compute_threat_index(result, whois_data, ssl_data, meta_data, vt_data)

    time.sleep(0.5)
    loading_placeholder.empty()

    # --- Record request ---
    record_request()
    log_scan_result(input_type, result.get("verdict", "Error"), preview)

    # --- Extract results ---
    verdict = result.get("verdict", "Error")
    confidence = result.get("confidence", 0)
    explanation = result.get("explanation", "No explanation provided.")
    red_flags = result.get("red_flags", [])
    recommendation = result.get("recommendation", "No recommendation available.")

    v_map = {
        "Safe": ("result-safe", "✅", "#10b981", "#10b981", "#059669"),
        "Suspicious": ("result-suspicious", "⚠️", "#f59e0b", "#f59e0b", "#d97706"),
        "Malicious": ("result-malicious", "🚨", "#f43f5e", "#f43f5e", "#dc2626"),
    }
    vc, icon, color, bar_from, bar_to = v_map.get(verdict, ("result-error", "❌", "#888", "#666", "#888"))

    # Mode badge
    mode_badge = f'<span style="font-family:Share Tech Mono,monospace;font-size:0.75rem;color:var(--text-secondary);letter-spacing:2px;">[ MODE: {input_type.upper()} ]</span>'

    # --- Main Result Panel ---
    st.markdown(f"""
<div class="result-3d {vc}">
<div style="display:flex; justify-content:space-between; align-items:center;">
<div class="verdict-label">ANALYSIS COMPLETE</div>
{mode_badge}
</div>
<div class="verdict-text">{icon} {verdict.upper()}</div>

<div class="confidence-wrap">
<div class="conf-header">
<span>PHISHSHIELD THREAT INDEX (MULTI-VECTOR SCORE)</span>
<span>{threat_matrix['threat_index']} / 100</span>
</div>
<div class="conf-track">
<div class="conf-fill" style="width: {threat_matrix['threat_index']}%; background: linear-gradient(90deg, {bar_from}, {bar_to});"></div>
</div>
<div class="conf-value" style="color: {threat_matrix['risk_color']}; font-weight: bold; margin-top: 6px;">STATUS: {threat_matrix['risk_level']}</div>
</div>

<div class="explanation-block">
<div class="conf-label" style="margin-bottom: 8px;">ANALYSIS SUMMARY</div>
{html.escape(explanation)}
</div>
</div>
""", unsafe_allow_html=True)

    # --- Multi-Vector Intelligence HUD Cards ---
    if ssl_data or whois_data or vt_data or meta_data:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            ssl_val = "Valid 🔐" if ssl_data and ssl_data.get("valid") else "Invalid / Missing ⚠️"
            st.metric("SSL Certificate", ssl_val, delta=f"{ssl_data.get('expires_in_days', 0)}d left" if ssl_data and ssl_data.get("valid") else "High Risk")
        with c2:
            age_val = f"{whois_data.get('age_days', 0)} days" if whois_data and whois_data.get('age_days') else "Unknown"
            st.metric("Domain Age", age_val, delta="Young Domain" if whois_data and whois_data.get("is_young") else "Established", delta_color="inverse" if whois_data and whois_data.get("is_young") else "normal")
        with c3:
            vt_val = f"{vt_data.get('malicious', 0)} Malicious" if vt_data and vt_data.get("status") == "success" else "Unconfigured"
            st.metric("VirusTotal Engine", vt_val, delta="Clean" if vt_data and vt_data.get("malicious", 0) == 0 else "Flagged", delta_color="normal" if vt_data and vt_data.get("malicious", 0) == 0 else "inverse")
        with c4:
            meta_val = "Impersonation Risk 🚨" if meta_data and meta_data.get("impersonation_risk") else "Clean Match ✅"
            st.metric("DOM Brand Match", meta_val, delta=meta_data.get("impersonated_brand", "").title() if meta_data and meta_data.get("impersonated_brand") else "Verified")

    # Red flags
    if red_flags:
        st.markdown(f"""
<div class="section-title" style="margin-top: 25px;">
<span class="dot" style="background: #f43f5e; box-shadow: 0 0 10px rgba(244,63,94,0.5);"></span>
RED FLAGS DETECTED ({len(red_flags)})
<span class="line" style="background: linear-gradient(90deg, rgba(244,63,94,0.3), transparent);"></span>
</div>
""", unsafe_allow_html=True)
        flags_html = ""
        for i, f in enumerate(red_flags):
            flags_html += f"""<div class="red-flag" style="animation-delay:{i*0.1}s;"><span class="flag-num">#{i+1}</span><span class="flag-text">{html.escape(str(f))}</span></div>"""
        st.markdown(flags_html, unsafe_allow_html=True)

    # Recommendation
    st.markdown(f"""
<div class="rec-box">
<div class="rec-label">💡 RECOMMENDED DEFENSIVE ACTION</div>
<div class="rec-text">{html.escape(recommendation)}</div>
</div>
""", unsafe_allow_html=True)

    # --- PDF Export ---
    if PDF_AVAILABLE and input_type != "batch":
        pdf_bytes = generate_pdf_report(result, preview, input_type)
        if pdf_bytes:
            st.download_button("📄 Download PDF Report", data=pdf_bytes, file_name=f"phishshield-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf", mime="application/pdf", key="pdf_download")

    # --- Batch Results Table ---
    if result.get("batch_results"):
        st.markdown("""


<div class="section-title" style="margin-top:20px;">
<span class="dot"></span> BATCH ANALYSIS RESULTS
<span class="line"></span>
</div>

""", unsafe_allow_html=True)
        batch_html = "<div style='overflow-x:auto;'>"
        for br in result["batch_results"]:
            bv = br.get("verdict", "?")
            bc = "#00ffc8" if bv == "Safe" else "#ffc107" if bv == "Suspicious" else "#ff3355"
            bd = "safe" if bv == "Safe" else "suspicious" if bv == "Suspicious" else "malicious"
            batch_html += f"""
            <div class="history-item" style="border-left: 3px solid {bc};">
                <div class="history-dot {bd}"></div>
                <div class="history-info">
                    <div class="history-verdict" style="color:{bc};">{bv.upper()}</div>
                    <div class="history-preview">{br.get('url','')[:70]}</div>
                    <div style="font-size:0.7rem;color:rgba(0,255,200,0.3);margin-top:2px;">{br.get('reason','')}</div>
                </div>
                <div class="history-time">{br.get('confidence',0)}%</div>
            </div>
            """
        batch_html += "</div>"
        st.markdown(batch_html, unsafe_allow_html=True)

    # --- Email Header Details ---
    if result.get("header_data"):
        hd = result["header_data"]
        st.markdown("""


<div class="section-title" style="margin-top:20px;">
<span class="dot"></span> EMAIL HEADER DETAILS
<span class="line"></span>
</div>

""", unsafe_allow_html=True)
        hdr_html = """
        <div class="sec-dash" style="padding:20px;">
        """
        for key, label in [("from", "FROM"), ("reply_to", "REPLY-TO"), ("return_path", "RETURN-PATH"), ("from_domain", "FROM DOMAIN"), ("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")]:
            val = hd.get(key, "N/A")
            color = "#00ffc8" if key in ("spf", "dkim", "dmarc") and val.lower() == "pass" else "#ffc107" if key in ("spf", "dkim", "dmarc") and val.lower() == "fail" else "rgba(0,255,200,0.5)"
            hdr_html += '<div class="sec-row"><span class="sec-key">' + label + '</span><span style="font-size:0.8rem;color:' + color + ';">' + html.escape(str(val)) + '</span></div>'
        hdr_html += "</div>"
        st.markdown(hdr_html, unsafe_allow_html=True)

    # --- WHOIS Data ---
    if whois_data and not whois_data.get("error"):
        with st.expander("🔍 DOMAIN WHOIS INFORMATION"):
            w_cols = st.columns(3)
            with w_cols[0]:
                st.markdown(f"**Domain:** {whois_data.get('domain', 'N/A')}")
                st.markdown(f"**Registrar:** {whois_data.get('registrar', 'N/A')}")
            with w_cols[1]:
                st.markdown(f"**Created:** {whois_data.get('creation_date', 'N/A')}")
                st.markdown(f"**Expires:** {whois_data.get('expiration_date', 'N/A')}")
            with w_cols[2]:
                age = whois_data.get('age_days', 0)
                color = "red" if age < 30 else "orange" if age < 90 else "green"
                st.markdown(f"**Age:** <span style='color:{color};font-weight:bold;'>{age} days</span>", unsafe_allow_html=True)
                if whois_data.get('is_young'):
                    st.warning("⚠ Domain registered less than 90 days ago — suspicious!")

    # --- Redirect Chain (for URL inputs) ---
    if input_type == "text" and user_input and "[Auto-unshortened" in user_input:
        with st.expander("🔗 REDIRECT CHAIN DETECTED"):
            st.info("This URL was shortened. The AI analysis includes the final destination.")
            st.code(user_input.split("[Auto-unshortened")[0], language="text")

    # --- Raw content ---
    with st.expander(f"📄 VIEW RAW {input_type.upper()} DATA"):
        if input_type == "text":
            st.code(user_input, language="text")
        elif input_type == "image":
            st.json({"input_type": "image", "filename": uploaded_image.name, "mime_type": image_mime, "size_kb": round(uploaded_image.size / 1024, 1)})
        elif input_type == "email_header":
            st.code(header_text[:3000], language="text")
        elif input_type == "batch":
            st.code(batch_text[:3000], language="text")
        elif input_type == "qr_code":
            st.json(result.get("qr_data", {}))

    # Stats
    st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""

<div class="stat-tile"><span class="stat-icon">📊</span><div class="stat-number">{confidence}%</div><div class="stat-label">Confidence</div></div>
""", unsafe_allow_html=True)
    with c2:
        fc = len(red_flags)
        st.markdown(f"""

<div class="stat-tile"><span class="stat-icon">🚩</span><div class="stat-number">{fc}</div><div class="stat-label">Red Flags</div></div>
""", unsafe_allow_html=True)
    with c3:
        status = "SECURE" if verdict == "Safe" else "ALERT" if verdict == "Suspicious" else "DANGER"
        sc = "#00ffc8" if verdict == "Safe" else "#ffc107" if verdict == "Suspicious" else "#ff3355"
        st.markdown(f"""

<div class="stat-tile"><span class="stat-icon">🛡️</span><div class="stat-number" style="background:linear-gradient(135deg,{sc},{sc}88);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">{status}</div><div class="stat-label">Security Level</div></div>
""", unsafe_allow_html=True)

# ================================
# 13. CYBERSECURITY TIPS
# ================================

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

st.markdown("""


<div class="section-title" style="justify-content:center; font-size:1.2rem;">
<span class="dot"></span>
INTEL BRIEFING — SECURITY PROTOCOLS
<span class="line" style="max-width:200px;"></span>
</div>

""", unsafe_allow_html=True)

r1c1, r1c2, r1c3 = st.columns(3)
for col, (ic, ti, de) in zip([r1c1, r1c2, r1c3], [
    ("🔗", "VERIFY LINKS", "Hover over every link before clicking. Check for misspellings and unusual domains."),
    ("🔐", "GUARD YOUR OTP", "No legitimate company will ever ask for your OTP, password, or PIN via email or SMS."),
    ("📧", "INSPECT SENDER", "Scammers spoof email addresses. Always verify the sender's actual email, not just the display name."),
]):
    with col:
        st.markdown(f"""

<div class="tip-card-3d" style="--tip-color:#00ffc8;"><div class="tip-icon-3d">{ic}</div><div class="tip-title-3d">{ti}</div><div class="tip-desc-3d">{de}</div></div>
""", unsafe_allow_html=True)

r2c1, r2c2, r2c3 = st.columns(3)
for col, (ic, ti, de) in zip([r2c1, r2c2, r2c3], [
    ("⏰", "RESIST URGENCY", "Phishing relies on panic. \"Act NOW!\" is a red flag. Always pause and verify."),
    ("🔍", "CHECK DOMAINS", "Look for subtle misspellings like \"paypa1\" or suspicious TLDs like .xyz, .ru, .tk."),
    ("🛡️", "ENABLE 2FA", "Two-factor authentication adds a critical second layer of defense against account takeovers."),
]):
    with col:
        st.markdown(f"""

<div class="tip-card-3d" style="--tip-color:#00b4ff;"><div class="tip-icon-3d">{ic}</div><div class="tip-title-3d">{ti}</div><div class="tip-desc-3d">{de}</div></div>
""", unsafe_allow_html=True)

# ================================
# 16. FOOTER
# ================================

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

st.markdown("""


<div class="footer-futuristic">
<div class="footer-brand">PHISHSHIELD AI</div>
<div class="footer-sub">POWERED BY GOOGLE GEMINI &nbsp;•&nbsp; STAY VIGILANT &nbsp;•&nbsp; STAY SAFE</div>
</div>

""", unsafe_allow_html=True)

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
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Primary + fallback models (tried in order)
AI_MODELS = ['gemini-3.6-flash', 'gemini-flash-latest', 'gemini-3.5-flash']

def ai_generate(model_name: str, contents) -> str:
    """Call Gemini with retry across multiple models on 503/429 errors."""
    last_error = None
    for model in AI_MODELS:
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
        return json.loads(result_text)
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
        return json.loads(result_text)
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
        parsed = json.loads(result_text)
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
        return json.loads(result_text)
    except Exception:
        return [{"url": u, "verdict": "Error", "confidence": 0, "reason": "Analysis failed"} for u in urls]

# ================================
# 5g. PDF EXPORT
# ================================

def generate_pdf_report(result: dict, input_text: str, input_type: str) -> bytes:
    """Generate a PDF report of the analysis."""
    if not PDF_AVAILABLE:
        return None
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 12, 'PhishShield AI - Threat Analysis Report', ln=True, align='C')
    pdf.set_font('Helvetica', '', 9)
    pdf.cell(0, 8, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True, align='C')
    pdf.ln(8)

    # Verdict
    verdict = result.get('verdict', 'Unknown')
    confidence = result.get('confidence', 0)
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, f'Verdict: {verdict.upper()} (Confidence: {confidence}%)', ln=True)
    pdf.ln(4)

    # Explanation
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, 'Explanation:', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.multi_cell(0, 6, result.get('explanation', 'N/A'))
    pdf.ln(4)

    # Red Flags
    flags = result.get('red_flags', [])
    if flags:
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(0, 8, 'Red Flags Detected:', ln=True)
        pdf.set_font('Helvetica', '', 10)
        for i, f in enumerate(flags):
            pdf.multi_cell(0, 6, f'  {i+1}. {f}')
        pdf.ln(4)

    # Recommendation
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, 'Recommendation:', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.multi_cell(0, 6, result.get('recommendation', 'N/A'))
    pdf.ln(4)

    # Input
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, f'Analyzed Content ({input_type.upper()}):', ln=True)
    pdf.set_font('Helvetica', '', 8)
    pdf.multi_cell(0, 5, input_text[:2000] if input_text else 'Image upload')

    # Footer
    pdf.ln(10)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.cell(0, 6, 'PhishShield AI | Powered by Google Gemini | For educational purposes', ln=True, align='C')

    return bytes(pdf.output())

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

# ================================
# 7. MASSIVE CSS — FUTURISTIC 3D + IMAGE + SECURITY
# ================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&display=swap');

/* ===== GLOBAL RESETS ===== */
.stApp { background: #050510 !important; font-family: 'Rajdhani', sans-serif !important; }
.stApp::before {
    content: ''; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse at 20% 50%, rgba(0,255,200,0.03) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 20%, rgba(0,180,255,0.04) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 80%, rgba(120,0,255,0.03) 0%, transparent 50%);
    z-index: -1; pointer-events: none;
}
.stApp::after {
    content: ''; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background-image: linear-gradient(rgba(0,255,200,0.03) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(0,255,200,0.03) 1px, transparent 1px);
    background-size: 60px 60px; animation: gridMove 20s linear infinite;
    z-index: -1; pointer-events: none;
}
@keyframes gridMove { 0%{transform:perspective(500px) rotateX(0deg)} 100%{transform:perspective(500px) rotateX(0deg) translateY(60px)} }

/* ===== PARTICLES ===== */
.particles { position:fixed; top:0; left:0; width:100%; height:100%; z-index:-1; pointer-events:none; overflow:hidden; }
.particle { position:absolute; width:3px; height:3px; background:rgba(0,255,200,0.6); border-radius:50%; animation:floatUp linear infinite; box-shadow:0 0 6px rgba(0,255,200,0.4); }
.particle:nth-child(1){left:5%;animation-duration:12s;animation-delay:0s}
.particle:nth-child(2){left:15%;animation-duration:15s;animation-delay:2s;background:rgba(0,180,255,0.6)}
.particle:nth-child(3){left:25%;animation-duration:10s;animation-delay:4s}
.particle:nth-child(4){left:40%;animation-duration:18s;animation-delay:1s;background:rgba(120,0,255,0.6)}
.particle:nth-child(5){left:55%;animation-duration:14s;animation-delay:3s}
.particle:nth-child(6){left:70%;animation-duration:11s;animation-delay:5s;background:rgba(0,255,200,0.6)}
.particle:nth-child(7){left:85%;animation-duration:16s;animation-delay:0.5s;background:rgba(0,180,255,0.6)}
.particle:nth-child(8){left:92%;animation-duration:13s;animation-delay:2.5s}
.particle:nth-child(9){left:33%;animation-duration:17s;animation-delay:4.5s;background:rgba(120,0,255,0.5)}
.particle:nth-child(10){left:62%;animation-duration:19s;animation-delay:1.5s}
@keyframes floatUp { 0%{transform:translateY(100vh) scale(0);opacity:0} 10%{opacity:1} 90%{opacity:1} 100%{transform:translateY(-10vh) scale(1.5);opacity:0} }

/* ===== HERO ===== */
.hero-zone { text-align:center; padding:50px 20px 30px; position:relative; }
.shield-3d { font-size:6rem; display:inline-block; animation: shieldFloat 3s ease-in-out infinite, shieldGlow 2s ease-in-out infinite alternate; filter: drop-shadow(0 0 30px rgba(0,255,200,0.5)); position:relative; }
.shield-3d::after { content:''; position:absolute; bottom:-15px; left:50%; transform:translateX(-50%); width:80px; height:12px; background:radial-gradient(ellipse,rgba(0,255,200,0.3),transparent); border-radius:50%; animation:shieldShadow 3s ease-in-out infinite; }
@keyframes shieldFloat { 0%,100%{transform:translateY(0) perspective(500px) rotateY(0deg)} 25%{transform:translateY(-12px) perspective(500px) rotateY(5deg)} 50%{transform:translateY(-8px) perspective(500px) rotateY(0deg)} 75%{transform:translateY(-15px) perspective(500px) rotateY(-5deg)} }
@keyframes shieldGlow { 0%{filter:drop-shadow(0 0 20px rgba(0,255,200,0.3))} 100%{filter:drop-shadow(0 0 40px rgba(0,255,200,0.7))} }
@keyframes shieldShadow { 0%,100%{transform:translateX(-50%) scale(1);opacity:0.3} 50%{transform:translateX(-50%) scale(0.7);opacity:0.15} }

.main-title { font-family:'Orbitron',sans-serif; font-size:4rem; font-weight:900; letter-spacing:8px; margin:15px 0 5px; background:linear-gradient(135deg,#00ffc8 0%,#00b4ff 30%,#7b2fff 60%,#00ffc8 100%); background-size:300% 300%; -webkit-background-clip:text; -webkit-text-fill-color:transparent; animation:titleGradient 4s ease infinite; }
@keyframes titleGradient { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }

.main-subtitle { font-family:'Share Tech Mono',monospace; font-size:1rem; color:rgba(0,255,200,0.5); letter-spacing:4px; text-transform:uppercase; margin-bottom:5px; }
.status-line { font-family:'Share Tech Mono',monospace; font-size:0.85rem; color:rgba(0,255,200,0.35); letter-spacing:2px; }
.status-line .online { color:#00ffc8; animation:blink 1.5s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

/* ===== HOLO DIVIDER ===== */
.holo-divider { height:1px; margin:25px 0; background:linear-gradient(90deg,transparent,#00ffc8,#00b4ff,#7b2fff,#00b4ff,#00ffc8,transparent); position:relative; }
.holo-divider::before { content:''; position:absolute; top:-3px; left:0; right:0; height:7px; background:linear-gradient(90deg,transparent,rgba(0,255,200,0.2),transparent); filter:blur(4px); }
.holo-divider::after { content:''; position:absolute; top:50%; left:50%; width:12px; height:12px; background:#00ffc8; border-radius:2px; transform:translate(-50%,-50%) rotate(45deg); box-shadow:0 0 15px rgba(0,255,200,0.5); animation:diamondPulse 2s ease-in-out infinite; }
@keyframes diamondPulse { 0%,100%{box-shadow:0 0 15px rgba(0,255,200,0.5)} 50%{box-shadow:0 0 25px rgba(0,255,200,0.8)} }

/* ===== GLASS PANEL ===== */
.glass-panel { background:linear-gradient(135deg,rgba(10,15,30,0.85),rgba(5,10,25,0.9)); border:1px solid rgba(0,255,200,0.15); border-radius:20px; padding:30px; position:relative; overflow:hidden; backdrop-filter:blur(20px); box-shadow:0 8px 32px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.05),0 0 60px rgba(0,255,200,0.03); }
.glass-panel::before { content:''; position:absolute; top:0; left:-100%; width:100%; height:100%; background:linear-gradient(90deg,transparent,rgba(0,255,200,0.03),transparent); animation:scanLine 6s linear infinite; }
@keyframes scanLine { 0%{left:-100%} 100%{left:100%} }

.corner-decor { position:relative; }
.corner-decor::before,.corner-decor::after { content:''; position:absolute; width:20px; height:20px; border-color:rgba(0,255,200,0.4); border-style:solid; }
.corner-decor::before { top:8px; left:8px; border-width:2px 0 0 2px; }
.corner-decor::after { bottom:8px; right:8px; border-width:0 2px 2px 0; }

/* ===== SECTION TITLES ===== */
.section-title { font-family:'Orbitron',sans-serif; font-size:1.1rem; font-weight:700; color:#00ffc8; letter-spacing:3px; text-transform:uppercase; margin-bottom:20px; display:flex; align-items:center; gap:12px; }
.section-title .dot { width:8px; height:8px; background:#00ffc8; border-radius:2px; transform:rotate(45deg); box-shadow:0 0 10px rgba(0,255,200,0.5); }
.section-title .line { flex:1; height:1px; background:linear-gradient(90deg,rgba(0,255,200,0.3),transparent); }

/* ===== TEXTAREA ===== */
.stTextArea textarea { background:rgba(5,10,25,0.9) !important; border:1px solid rgba(0,255,200,0.2) !important; border-radius:14px !important; color:#c8ffe8 !important; font-family:'Share Tech Mono',monospace !important; font-size:0.95rem !important; padding:18px !important; transition:all 0.4s cubic-bezier(.25,.46,.45,.94) !important; box-shadow:inset 0 2px 10px rgba(0,0,0,0.3) !important; }
.stTextArea textarea:focus { border-color:#00ffc8 !important; box-shadow:inset 0 2px 10px rgba(0,0,0,0.3),0 0 20px rgba(0,255,200,0.15),0 0 40px rgba(0,255,200,0.05) !important; }
.stTextArea textarea::placeholder { color:rgba(0,255,200,0.25) !important; font-style:italic; }

/* ===== BUTTONS ===== */
.stButton > button { background:linear-gradient(135deg,rgba(0,255,200,0.15),rgba(0,180,255,0.1)) !important; border:1px solid rgba(0,255,200,0.3) !important; border-radius:12px !important; padding:14px 28px !important; font-family:'Orbitron',sans-serif !important; font-weight:600 !important; font-size:0.85rem !important; color:#00ffc8 !important; letter-spacing:2px !important; text-transform:uppercase !important; transition:all 0.4s cubic-bezier(.25,.46,.45,.94) !important; position:relative !important; overflow:hidden !important; box-shadow:0 4px 15px rgba(0,255,200,0.1) !important; }
.stButton > button::before { content:'' !important; position:absolute !important; top:0 !important; left:-100% !important; width:100% !important; height:100% !important; background:linear-gradient(90deg,transparent,rgba(0,255,200,0.1),transparent) !important; transition:left 0.5s !important; }
.stButton > button:hover::before { left:100% !important; }
.stButton > button:hover { transform:translateY(-3px) !important; border-color:#00ffc8 !important; box-shadow:0 8px 25px rgba(0,255,200,0.2),0 0 40px rgba(0,255,200,0.08) !important; background:linear-gradient(135deg,rgba(0,255,200,0.25),rgba(0,180,255,0.15)) !important; }
.stButton > button:active { transform:translateY(-1px) !important; }
.stButton > button[kind="primary"] { background:linear-gradient(135deg,#00ffc8,#00b4ff) !important; border:none !important; color:#050510 !important; font-size:1rem !important; padding:18px 40px !important; font-weight:800 !important; box-shadow:0 5px 25px rgba(0,255,200,0.3),0 0 50px rgba(0,255,200,0.1) !important; }
.stButton > button[kind="primary"]:hover { box-shadow:0 8px 35px rgba(0,255,200,0.4),0 0 60px rgba(0,255,200,0.15) !important; transform:translateY(-3px) !important; }

/* ===== FILE UPLOADER ===== */
.stFileUploader { background:rgba(5,10,25,0.7) !important; border:2px dashed rgba(0,255,200,0.25) !important; border-radius:16px !important; padding:20px !important; transition:all 0.3s ease !important; }
.stFileUploader:hover { border-color:rgba(0,255,200,0.5) !important; box-shadow:0 0 30px rgba(0,255,200,0.08) !important; }
.stFileUploader [data-testid="stFileUploadDropzone"] { background:rgba(0,255,200,0.03) !important; border:1px solid rgba(0,255,200,0.15) !important; border-radius:12px !important; }
.stFileUploader label { color:rgba(0,255,200,0.7) !important; font-family:'Orbitron',sans-serif !important; font-size:0.8rem !important; letter-spacing:2px !important; }

/* ===== IMAGE PREVIEW ===== */
.image-preview-box { background:rgba(5,10,25,0.8); border:1px solid rgba(0,255,200,0.2); border-radius:14px; padding:15px; margin-top:15px; text-align:center; position:relative; overflow:hidden; }
.image-preview-box::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,transparent,#00ffc8,transparent); }
.image-preview-label { font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:rgba(0,255,200,0.4); letter-spacing:2px; text-transform:uppercase; margin-bottom:10px; }

/* ===== MODE TABS ===== */
.mode-tabs { display:flex; gap:12px; justify-content:center; margin:20px 0; }
.mode-tab { font-family:'Orbitron',sans-serif; font-size:0.9rem; font-weight:600; letter-spacing:2px; padding:12px 30px; border:1px solid rgba(0,255,200,0.2); border-radius:12px; background:rgba(10,15,30,0.8); color:rgba(0,255,200,0.5); cursor:pointer; transition:all 0.3s ease; text-transform:uppercase; }
.mode-tab.active { background:linear-gradient(135deg,rgba(0,255,200,0.15),rgba(0,180,255,0.1)); border-color:#00ffc8; color:#00ffc8; box-shadow:0 0 20px rgba(0,255,200,0.15); }
.mode-tab:hover { border-color:rgba(0,255,200,0.4); color:rgba(0,255,200,0.8); }

/* ===== RESULTS ===== */
.result-3d { border-radius:20px; padding:30px; margin:20px 0; position:relative; overflow:hidden; animation:resultReveal 0.7s cubic-bezier(.25,.46,.45,.94); }
@keyframes resultReveal { from{opacity:0;transform:translateY(40px) scale(0.96)} to{opacity:1;transform:translateY(0) scale(1)} }
.result-3d::before { content:''; position:absolute; top:0;left:0;right:0;bottom:0; border-radius:20px; padding:1px; background:linear-gradient(135deg,var(--glow-color),transparent 60%); -webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0); -webkit-mask-composite:xor; mask-composite:exclude; pointer-events:none; }
.result-safe { --glow-color:#00ffc8; background:linear-gradient(135deg,rgba(0,255,200,0.06),rgba(0,200,160,0.03)); box-shadow:0 10px 50px rgba(0,255,200,0.1),inset 0 0 80px rgba(0,255,200,0.02); }
.result-suspicious { --glow-color:#ffc107; background:linear-gradient(135deg,rgba(255,193,7,0.06),rgba(255,150,0,0.03)); box-shadow:0 10px 50px rgba(255,193,7,0.1),inset 0 0 80px rgba(255,193,7,0.02); }
.result-malicious { --glow-color:#ff3355; background:linear-gradient(135deg,rgba(255,51,85,0.06),rgba(220,30,60,0.03)); box-shadow:0 10px 50px rgba(255,51,85,0.1),inset 0 0 80px rgba(255,51,85,0.02); animation:resultReveal 0.7s cubic-bezier(.25,.46,.45,.94),dangerPulse 3s ease-in-out infinite; }
.result-error { --glow-color:#667; background:linear-gradient(135deg,rgba(100,100,120,0.06),rgba(80,80,100,0.03)); box-shadow:0 10px 50px rgba(100,100,120,0.1); }
@keyframes dangerPulse { 0%,100%{box-shadow:0 10px 50px rgba(255,51,85,0.1)} 50%{box-shadow:0 10px 70px rgba(255,51,85,0.2)} }

.verdict-label { font-family:'Orbitron',sans-serif; font-size:0.85rem; font-weight:600; letter-spacing:4px; text-transform:uppercase; opacity:0.6; margin-bottom:8px; }
.verdict-text { font-family:'Orbitron',sans-serif; font-size:2.5rem; font-weight:900; letter-spacing:3px; margin-bottom:20px; }
.verdict-safe .verdict-text { color:#00ffc8; text-shadow:0 0 30px rgba(0,255,200,0.4); }
.verdict-suspicious .verdict-text { color:#ffc107; text-shadow:0 0 30px rgba(255,193,7,0.4); }
.verdict-malicious .verdict-text { color:#ff3355; text-shadow:0 0 30px rgba(255,51,85,0.4); }
.verdict-error .verdict-text { color:#888; }

.confidence-wrap { margin:15px 0; }
.conf-label { font-family:'Share Tech Mono',monospace; font-size:0.8rem; color:rgba(0,255,200,0.5); letter-spacing:2px; text-transform:uppercase; margin-bottom:8px; }
.conf-track { height:8px; background:rgba(255,255,255,0.05); border-radius:4px; overflow:hidden; }
.conf-fill { height:100%; border-radius:4px; transition:width 1.5s cubic-bezier(.25,.46,.45,.94); position:relative; background:linear-gradient(90deg,var(--bar-from),var(--bar-to)); }
.conf-fill::after { content:''; position:absolute; top:0;left:0;right:0;bottom:0; background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,0.3) 50%,transparent 100%); animation:barShimmer 2.5s ease-in-out infinite; }
@keyframes barShimmer { 0%{transform:translateX(-100%)} 100%{transform:translateX(200%)} }
.conf-value { font-family:'Orbitron',sans-serif; font-size:2rem; font-weight:800; margin-top:10px; text-align:right; }

.explanation-block { background:rgba(255,255,255,0.02); border-left:2px solid rgba(0,255,200,0.3); padding:18px 22px; margin:20px 0; border-radius:0 12px 12px 0; font-family:'Rajdhani',sans-serif; font-size:1.05rem; color:rgba(230,241,255,0.85); line-height:1.7; }

.red-flag { display:flex; align-items:flex-start; gap:14px; padding:14px 18px; margin:8px 0; background:rgba(255,51,85,0.04); border:1px solid rgba(255,51,85,0.15); border-radius:12px; transition:all 0.3s ease; animation:flagSlide 0.5s ease-out backwards; }
.red-flag:hover { background:rgba(255,51,85,0.08); border-color:rgba(255,51,85,0.3); transform:translateX(6px); }
@keyframes flagSlide { from{opacity:0;transform:translateX(-20px)} to{opacity:1;transform:translateX(0)} }
.flag-num { font-family:'Orbitron',sans-serif; font-size:0.75rem; font-weight:700; color:#ff3355; background:rgba(255,51,85,0.15); padding:4px 10px; border-radius:6px; white-space:nowrap; }
.flag-text { font-family:'Rajdhani',sans-serif; font-size:1rem; color:rgba(230,241,255,0.8); line-height:1.5; }

.rec-box { background:linear-gradient(135deg,rgba(0,255,200,0.04),rgba(0,180,255,0.02)); border:1px solid rgba(0,255,200,0.15); border-radius:14px; padding:22px 26px; margin:20px 0; }
.rec-label { font-family:'Orbitron',sans-serif; font-size:0.85rem; font-weight:700; color:#00ffc8; letter-spacing:3px; margin-bottom:10px; }
.rec-text { font-family:'Rajdhani',sans-serif; font-size:1.05rem; color:rgba(230,241,255,0.85); line-height:1.6; }

/* ===== STAT TILES ===== */
.stat-tile { background:rgba(10,15,30,0.8); border:1px solid rgba(0,255,200,0.12); border-radius:16px; padding:25px 20px; text-align:center; position:relative; overflow:hidden; transition:all 0.4s cubic-bezier(.25,.46,.45,.94); }
.stat-tile:hover { transform:translateY(-8px) scale(1.02); border-color:rgba(0,255,200,0.3); box-shadow:0 15px 40px rgba(0,0,0,0.3),0 0 30px rgba(0,255,200,0.08); }
.stat-tile::before { content:''; position:absolute; top:0;left:0;right:0; height:2px; background:linear-gradient(90deg,transparent,#00ffc8,transparent); opacity:0; transition:opacity 0.3s; }
.stat-tile:hover::before { opacity:1; }
.stat-icon { font-size:2rem; margin-bottom:12px; display:block; }
.stat-number { font-family:'Orbitron',sans-serif; font-size:2.2rem; font-weight:800; background:linear-gradient(135deg,#00ffc8,#00b4ff); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:5px; }
.stat-label { font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:rgba(0,255,200,0.45); letter-spacing:2px; text-transform:uppercase; }

/* ===== TIPS ===== */
.tip-card-3d { background:rgba(10,15,30,0.7); border:1px solid rgba(0,255,200,0.1); border-radius:16px; padding:24px 20px; text-align:center; transition:all 0.4s cubic-bezier(.25,.46,.45,.94); position:relative; overflow:hidden; height:200px; display:flex; flex-direction:column; align-items:center; justify-content:center; }
.tip-card-3d:hover { transform:translateY(-8px) perspective(800px) rotateX(3deg); border-color:rgba(0,255,200,0.3); box-shadow:0 20px 40px rgba(0,0,0,0.3),0 0 25px rgba(0,255,200,0.06); }
.tip-card-3d::after { content:''; position:absolute; bottom:0;left:0;right:0; height:2px; background:linear-gradient(90deg,transparent,var(--tip-color,#00ffc8),transparent); opacity:0; transition:opacity 0.3s; }
.tip-card-3d:hover::after { opacity:1; }
.tip-icon-3d { font-size:2.5rem; margin-bottom:15px; display:inline-block; transition:transform 0.4s ease; }
.tip-card-3d:hover .tip-icon-3d { transform:scale(1.2) rotate(5deg); }
.tip-title-3d { font-family:'Orbitron',sans-serif; font-size:0.85rem; font-weight:700; color:#00ffc8; letter-spacing:2px; margin-bottom:10px; }
.tip-desc-3d { font-family:'Rajdhani',sans-serif; font-size:0.9rem; color:rgba(0,255,200,0.45); line-height:1.5; }

/* (Security internals hidden from UI for OPSEC) */

/* ===== LOADER ===== */
.loader-3d { text-align:center; padding:60px 20px; }
.loader-ring { width:80px; height:80px; margin:0 auto 25px; border:3px solid transparent; border-top-color:#00ffc8; border-right-color:#00b4ff; border-radius:50%; animation:spin3d 1s linear infinite; position:relative; }
.loader-ring::before { content:''; position:absolute; top:6px;left:6px;right:6px;bottom:6px; border:2px solid transparent; border-bottom-color:#7b2fff; border-left-color:#00ffc8; border-radius:50%; animation:spin3d 0.7s linear infinite reverse; }
.loader-ring::after { content:'🛡️'; position:absolute; top:50%;left:50%; transform:translate(-50%,-50%); font-size:1.5rem; animation:pulse 1.5s ease-in-out infinite; }
@keyframes spin3d { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
@keyframes pulse { 0%,100%{transform:translate(-50%,-50%) scale(1)} 50%{transform:translate(-50%,-50%) scale(1.2)} }
.loader-text { font-family:'Orbitron',sans-serif; font-size:0.9rem; color:#00ffc8; letter-spacing:4px; animation:blink 1.5s ease-in-out infinite; }
.loader-subtext { font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:rgba(0,255,200,0.3); letter-spacing:2px; margin-top:8px; }

/* ===== FOOTER ===== */
.footer-futuristic { text-align:center; padding:40px 20px; position:relative; }
.footer-brand { font-family:'Orbitron',sans-serif; font-size:1.2rem; font-weight:700; letter-spacing:4px; background:linear-gradient(135deg,#00ffc8,#00b4ff,#7b2fff); background-size:200% auto; -webkit-background-clip:text; -webkit-text-fill-color:transparent; animation:titleGradient 3s ease infinite; }
.footer-sub { font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:rgba(0,255,200,0.25); letter-spacing:3px; margin-top:8px; }

/* ===== SECURITY ALERT ===== */
.sec-alert { background:linear-gradient(135deg,rgba(255,193,7,0.08),rgba(255,150,0,0.04)); border:1px solid rgba(255,193,7,0.25); border-radius:12px; padding:16px 20px; margin:10px 0; display:flex; align-items:center; gap:12px; }
.sec-alert-icon { font-size:1.5rem; }
.sec-alert-text { font-family:'Rajdhani',sans-serif; font-size:0.95rem; color:rgba(255,193,7,0.9); }

/* ===== HIDE DEFAULTS ===== */
#MainMenu, footer, header { visibility:hidden !important; }
.stDeployButton { display:none !important; }
::-webkit-scrollbar { width:6px; }
::-webkit-scrollbar-track { background:#050510; }
::-webkit-scrollbar-thumb { background:rgba(0,255,200,0.2); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:rgba(0,255,200,0.4); }
.streamlit-expanderHeader { font-family:'Orbitron',sans-serif !important; font-size:0.8rem !important; color:rgba(0,255,200,0.5) !important; letter-spacing:2px !important; }
</style>

<!-- PARTICLES -->
<div class="particles">
    <div class="particle"></div><div class="particle"></div><div class="particle"></div>
    <div class="particle"></div><div class="particle"></div><div class="particle"></div>
    <div class="particle"></div><div class="particle"></div><div class="particle"></div>
    <div class="particle"></div>
</div>
""", unsafe_allow_html=True)

# ================================
# 8. HERO SECTION
# ================================

st.markdown("""
<div class="hero-zone">
    <div class="shield-3d">🛡️</div>
    <div class="main-title">PHISHSHIELD AI</div>
    <div class="main-subtitle">AUTOMATED THREAT DETECTION SYSTEM</div>
    <div class="status-line">
        SYS.STATUS: <span class="online">● ONLINE</span> &nbsp;|&nbsp;
        AI.ENGINE: GEMINI-3.6 &nbsp;|&nbsp;
        PROTOCOL: ACTIVE
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

# ================================
# 9. TOP BAR — MODE + LANGUAGE + THEME
# ================================

top_c1, top_c2, top_c3 = st.columns([3, 2, 2])

with top_c1:
    st.markdown("""
    <div class="section-title" style="font-size:1rem; margin-bottom:8px;">
        <span class="dot"></span> SELECT INPUT MODE
    </div>
    """, unsafe_allow_html=True)
    input_mode = st.radio(
        "", ["📝 TEXT", "🖼️ IMAGE", "📧 HEADERS", "📷 QR CODE", "📋 BATCH URLs"],
        horizontal=True, label_visibility="collapsed", key="input_mode"
    )

with top_c2:
    st.markdown("""
    <div class="section-title" style="font-size:1rem; margin-bottom:8px;">
        <span class="dot"></span> LANGUAGE
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

with top_c3:
    st.markdown("""
    <div class="section-title" style="font-size:1rem; margin-bottom:8px;">
        <span class="dot"></span> DISPLAY
    </div>
    """, unsafe_allow_html=True)
    theme_mode = st.radio("", ["🌙 DARK", "☀️ LIGHT"], horizontal=True, label_visibility="collapsed", key="theme")
    is_dark = "DARK" in theme_mode

# Apply light theme overrides
if not is_dark:
    st.markdown("""<style>
    .stApp { background: #f0f2f6 !important; }
    .main-title { background: linear-gradient(135deg,#0083b0,#00b4db,#7b2fff); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
    .glass-panel { background: rgba(255,255,255,0.9) !important; border-color: rgba(0,180,255,0.2) !important; }
    .section-title { color: #0083b0 !important; }
    .section-title .dot { background: #0083b0 !important; box-shadow: 0 0 10px rgba(0,131,176,0.5) !important; }
    .stTextArea textarea { background: rgba(255,255,255,0.95) !important; color: #1a1a2e !important; border-color: rgba(0,180,255,0.3) !important; }
    .stTextArea textarea::placeholder { color: rgba(0,131,176,0.4) !important; }
    .particle { display: none; }
    .verdict-safe { background: linear-gradient(135deg,rgba(0,200,150,0.1),rgba(0,180,130,0.05)); border: 1px solid rgba(0,200,150,0.3); }
    .verdict-suspicious { background: linear-gradient(135deg,rgba(255,193,7,0.1),rgba(255,150,0,0.05)); border: 1px solid rgba(255,193,7,0.3); }
    .verdict-malicious { background: linear-gradient(135deg,rgba(255,51,85,0.1),rgba(220,30,60,0.05)); border: 1px solid rgba(255,51,85,0.3); }
    .stat-tile { background: rgba(255,255,255,0.9) !important; border-color: rgba(0,180,255,0.15) !important; }
    .tip-card-3d { background: rgba(255,255,255,0.9) !important; border-color: rgba(0,180,255,0.15) !important; }
    .explanation-block { background: rgba(0,131,176,0.05); color: #1a1a2e; }
    .red-flag { background: rgba(255,51,85,0.06); border-color: rgba(255,51,85,0.2); }
    .flag-text { color: #1a1a2e; }
    .rec-text { color: #1a1a2e; }
    .tip-title-3d { color: #0083b0; }
    .tip-desc-3d { color: #555; }
    .footer-brand { background: linear-gradient(135deg,#0083b0,#00b4ff,#7b2fff); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
    </style>""", unsafe_allow_html=True)

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

    # --- WHOIS enrichment for URL-based inputs ---
    whois_data = None
    if result and input_type in ("text", "batch"):
        urls_check = extract_urls_from_text(preview if input_type == "text" else batch_text)
        if urls_check:
            try:
                domain = urlparse(urls_check[0]).netloc
                if domain:
                    whois_data = whois_lookup(domain)
            except Exception:
                pass

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
        "Safe": ("result-safe", "✅", "#00ffc8", "#00ffc8", "#00b4ff"),
        "Suspicious": ("result-suspicious", "⚠️", "#ffc107", "#ffc107", "#ff9800"),
        "Malicious": ("result-malicious", "🚨", "#ff3355", "#ff3355", "#cc0033"),
    }
    vc, icon, color, bar_from, bar_to = v_map.get(verdict, ("result-error", "❌", "#888", "#666", "#888"))

    # Mode badge
    mode_badge = f'<span style="font-family:Share Tech Mono,monospace;font-size:0.7rem;color:rgba(0,255,200,0.4);letter-spacing:2px;">[ MODE: {input_type.upper()} ]</span>'

    # --- Display results ---
    st.markdown(f"""
    <div class="result-3d {vc}">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <div class="verdict-label">ANALYSIS COMPLETE</div>
            {mode_badge}
        </div>
        <div class="verdict-text">{icon} {verdict.upper()}</div>

        <div class="confidence-wrap">
            <div class="conf-label">CONFIDENCE LEVEL</div>
            <div class="conf-track">
                <div class="conf-fill" style="width: {confidence}%; --bar-from: {bar_from}; --bar-to: {bar_to};"></div>
            </div>
            <div class="conf-value" style="color: {color};">{confidence}%</div>
        </div>

        <div class="explanation-block">
            <div class="conf-label" style="margin-bottom: 8px;">EXPLANATION</div>
            {html.escape(explanation)}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Red flags
    if red_flags:
        st.markdown(f"""
        <div class="section-title" style="margin-top: 25px;">
            <span class="dot" style="background: #ff3355; box-shadow: 0 0 10px rgba(255,51,85,0.5);"></span>
            RED FLAGS DETECTED ({len(red_flags)})
            <span class="line" style="background: linear-gradient(90deg, rgba(255,51,85,0.3), transparent);"></span>
        </div>
        """, unsafe_allow_html=True)
        flags_html = ""
        for i, f in enumerate(red_flags):
            flags_html += f"""<div class="red-flag" style="animation-delay:{i*0.1}s;"><span class="flag-num">#{i+1}</span><span class="flag-text">{html.escape(str(f))}</span></div>"""
        st.markdown(flags_html, unsafe_allow_html=True)

    # Recommendation
    st.markdown(f"""
    <div class="rec-box">
        <div class="rec-label">💡 RECOMMENDED ACTION</div>
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
        st.markdown(f"""<div class="stat-tile"><span class="stat-icon">📊</span><div class="stat-number">{confidence}%</div><div class="stat-label">Confidence</div></div>""", unsafe_allow_html=True)
    with c2:
        fc = len(red_flags)
        st.markdown(f"""<div class="stat-tile"><span class="stat-icon">🚩</span><div class="stat-number">{fc}</div><div class="stat-label">Red Flags</div></div>""", unsafe_allow_html=True)
    with c3:
        status = "SECURE" if verdict == "Safe" else "ALERT" if verdict == "Suspicious" else "DANGER"
        sc = "#00ffc8" if verdict == "Safe" else "#ffc107" if verdict == "Suspicious" else "#ff3355"
        st.markdown(f"""<div class="stat-tile"><span class="stat-icon">🛡️</span><div class="stat-number" style="background:linear-gradient(135deg,{sc},{sc}88);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">{status}</div><div class="stat-label">Security Level</div></div>""", unsafe_allow_html=True)

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
        st.markdown(f"""<div class="tip-card-3d" style="--tip-color:#00ffc8;"><div class="tip-icon-3d">{ic}</div><div class="tip-title-3d">{ti}</div><div class="tip-desc-3d">{de}</div></div>""", unsafe_allow_html=True)

r2c1, r2c2, r2c3 = st.columns(3)
for col, (ic, ti, de) in zip([r2c1, r2c2, r2c3], [
    ("⏰", "RESIST URGENCY", "Phishing relies on panic. \"Act NOW!\" is a red flag. Always pause and verify."),
    ("🔍", "CHECK DOMAINS", "Look for subtle misspellings like \"paypa1\" or suspicious TLDs like .xyz, .ru, .tk."),
    ("🛡️", "ENABLE 2FA", "Two-factor authentication adds a critical second layer of defense against account takeovers."),
]):
    with col:
        st.markdown(f"""<div class="tip-card-3d" style="--tip-color:#00b4ff;"><div class="tip-icon-3d">{ic}</div><div class="tip-title-3d">{ti}</div><div class="tip-desc-3d">{de}</div></div>""", unsafe_allow_html=True)

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

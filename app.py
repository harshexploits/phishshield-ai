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
    # Map known errors to safe messages
    safe_messages = {
        "api_key": "Authentication error. Please check your API configuration.",
        "quota": "API quota exceeded. Please wait and try again.",
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
        response = client.models.generate_content(model='gemini-flash-latest', contents=prompt)
        result_text = response.text
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
        response = client.models.generate_content(
            model='gemini-flash-latest',
            contents=[prompt, image_part]
        )
        result_text = response.text
        result_text = re.sub(r'```json\s*', '', result_text)
        result_text = re.sub(r'```\s*', '', result_text)
        return json.loads(result_text)
    except Exception as e:
        return {"verdict": "Error", "confidence": 0, "explanation": secure_error_message(e), "red_flags": [], "recommendation": "Please try again."}

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
        AI.ENGINE: GEMINI-FLASH &nbsp;|&nbsp;
        PROTOCOL: ACTIVE
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

# ================================
# 9. INPUT MODE SELECTOR (TEXT / IMAGE)
# ================================

st.markdown("""
<div class="section-title" style="justify-content:center; font-size:1.2rem;">
    <span class="dot"></span>
    SELECT INPUT MODE
    <span class="line" style="max-width:150px;"></span>
</div>
""", unsafe_allow_html=True)

mode_col1, mode_col2, mode_col3 = st.columns([2, 1, 2])
with mode_col2:
    input_mode = st.radio(
        "",
        ["📝 TEXT", "🖼️ IMAGE"],
        horizontal=True,
        label_visibility="collapsed",
        key="input_mode"
    )

is_text_mode = "TEXT" in input_mode

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

# ================================
# 10. INPUT SECTION
# ================================

user_input = ""
uploaded_image = None
image_bytes = None
image_mime = None

if is_text_mode:
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

else:
    # IMAGE MODE
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

    # --- Validate input ---
    has_text_input = is_text_mode and user_input and user_input.strip()
    has_image_input = not is_text_mode and image_bytes is not None

    if not has_text_input and not has_image_input:
        if is_text_mode:
            st.warning("⚠ Please enter a URL or email text to analyze.")
        else:
            st.warning("⚠ Please upload an image to analyze.")
        st.stop()

    # --- Security: Advanced validation ---
    check_text = user_input if has_text_input else ""
    check_bytes = image_bytes if has_image_input else None
    sec_valid, sec_msg = validate_request_integrity(check_text, check_bytes)
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

    # --- Run analysis ---
    if has_text_input:
        input_type = "text"
        result = detect_phishing_text(user_input)
        preview = user_input
    else:
        input_type = "image"
        result = detect_phishing_image(image_bytes, image_mime)
        preview = uploaded_image.name if uploaded_image else "uploaded image"

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

    # Raw content
    if is_text_mode:
        with st.expander("📄 VIEW RAW INPUT DATA"):
            st.code(user_input, language="text")
    else:
        with st.expander("📄 VIEW ANALYSIS METADATA"):
            st.json({"input_type": "image", "filename": uploaded_image.name, "mime_type": image_mime, "size_kb": round(uploaded_image.size / 1024, 1)})

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

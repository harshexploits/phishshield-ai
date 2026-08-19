# ================================
# PHISHSHIELD AI - Cybersecurity MVP
# Real-world phishing detection using AI
# FUTURISTIC 3D INTERACTIVE UI
# ================================

import streamlit as st
from google import genai
import os
import json
import requests
from dotenv import load_dotenv
import re
import time
import base64

# Load environment variables
load_dotenv()

# ================================
# 1. CONFIGURE AI MODEL
# ================================
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# ================================
# 2. PHISHING DETECTION FUNCTION
# ================================

def detect_phishing(user_input):
    prompt = f"""
You are a cybersecurity expert. Analyze the following URL or email content for phishing indicators.

INPUT:
{user_input}

Analyze for these red flags:
1. Urgent language (e.g., "Action required", "Your account will be suspended")
2. Suspicious links (e.g., misspelled domain names, unusual subdomains)
3. Requests for personal information (passwords, credit cards, OTP)
4. Impersonation of trusted organizations
5. Unusual sender email addresses
6. Grammar and spelling mistakes

Return your analysis as a JSON with these exact keys:
- "verdict": One of ["Safe", "Suspicious", "Malicious"]
- "confidence": A number between 0 and 100 (how sure are you?)
- "explanation": A brief, plain-English explanation for non-technical users (max 3 sentences)
- "red_flags": A list of specific red flags found (max 5 items)
- "recommendation": What the user should do next (1 sentence)

Return ONLY valid JSON, no other text.
"""
    try:
        response = client.models.generate_content(model='gemini-1.5-flash', contents=prompt)
        result_text = response.text
        result_text = re.sub(r'```json\s*', '', result_text)
        result_text = re.sub(r'```\s*', '', result_text)
        return json.loads(result_text)
    except Exception as e:
        return {
            "verdict": "Error",
            "confidence": 0,
            "explanation": f"Analysis failed: {str(e)}",
            "red_flags": [],
            "recommendation": "Please try again or contact support."
        }

# ================================
# 3. PAGE CONFIG
# ================================
st.set_page_config(
    page_title="PhishShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ================================
# 4. MASSIVE CSS REBUILD — FUTURISTIC 3D
# ================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&display=swap');

/* ===== GLOBAL RESETS ===== */
.stApp {
    background: #050510 !important;
    font-family: 'Rajdhani', sans-serif !important;
}

.stApp::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background:
        radial-gradient(ellipse at 20% 50%, rgba(0, 255, 200, 0.03) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 20%, rgba(0, 180, 255, 0.04) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 80%, rgba(120, 0, 255, 0.03) 0%, transparent 50%);
    z-index: -1;
    pointer-events: none;
}

/* ===== ANIMATED GRID BACKGROUND ===== */
.stApp::after {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image:
        linear-gradient(rgba(0, 255, 200, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 200, 0.03) 1px, transparent 1px);
    background-size: 60px 60px;
    animation: gridMove 20s linear infinite;
    z-index: -1;
    pointer-events: none;
}

@keyframes gridMove {
    0% { transform: perspective(500px) rotateX(0deg); }
    100% { transform: perspective(500px) rotateX(0deg) translateY(60px); }
}

/* ===== FLOATING PARTICLES (CSS-only) ===== */
.particles {
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    z-index: -1;
    pointer-events: none;
    overflow: hidden;
}

.particle {
    position: absolute;
    width: 3px;
    height: 3px;
    background: rgba(0, 255, 200, 0.6);
    border-radius: 50%;
    animation: floatUp linear infinite;
    box-shadow: 0 0 6px rgba(0, 255, 200, 0.4);
}

.particle:nth-child(1) { left: 5%; animation-duration: 12s; animation-delay: 0s; }
.particle:nth-child(2) { left: 15%; animation-duration: 15s; animation-delay: 2s; background: rgba(0, 180, 255, 0.6); }
.particle:nth-child(3) { left: 25%; animation-duration: 10s; animation-delay: 4s; }
.particle:nth-child(4) { left: 40%; animation-duration: 18s; animation-delay: 1s; background: rgba(120, 0, 255, 0.6); }
.particle:nth-child(5) { left: 55%; animation-duration: 14s; animation-delay: 3s; }
.particle:nth-child(6) { left: 70%; animation-duration: 11s; animation-delay: 5s; background: rgba(0, 255, 200, 0.6); }
.particle:nth-child(7) { left: 85%; animation-duration: 16s; animation-delay: 0.5s; background: rgba(0, 180, 255, 0.6); }
.particle:nth-child(8) { left: 92%; animation-duration: 13s; animation-delay: 2.5s; }
.particle:nth-child(9) { left: 33%; animation-duration: 17s; animation-delay: 4.5s; background: rgba(120, 0, 255, 0.5); }
.particle:nth-child(10) { left: 62%; animation-duration: 19s; animation-delay: 1.5s; }
.particle:nth-child(11) { left: 10%; animation-duration: 14s; animation-delay: 3.5s; background: rgba(0, 255, 200, 0.4); }
.particle:nth-child(12) { left: 78%; animation-duration: 12s; animation-delay: 0.8s; background: rgba(255, 0, 100, 0.3); }

@keyframes floatUp {
    0% { transform: translateY(100vh) scale(0); opacity: 0; }
    10% { opacity: 1; }
    90% { opacity: 1; }
    100% { transform: translateY(-10vh) scale(1.5); opacity: 0; }
}

/* ===== HEADER ZONE ===== */
.hero-zone {
    text-align: center;
    padding: 50px 20px 30px;
    position: relative;
}

.shield-3d {
    font-size: 6rem;
    display: inline-block;
    animation: shieldFloat 3s ease-in-out infinite, shieldGlow 2s ease-in-out infinite alternate;
    filter: drop-shadow(0 0 30px rgba(0, 255, 200, 0.5));
    position: relative;
}

.shield-3d::after {
    content: '';
    position: absolute;
    bottom: -15px;
    left: 50%;
    transform: translateX(-50%);
    width: 80px;
    height: 12px;
    background: radial-gradient(ellipse, rgba(0, 255, 200, 0.3), transparent);
    border-radius: 50%;
    animation: shieldShadow 3s ease-in-out infinite;
}

@keyframes shieldFloat {
    0%, 100% { transform: translateY(0) perspective(500px) rotateY(0deg); }
    25% { transform: translateY(-12px) perspective(500px) rotateY(5deg); }
    50% { transform: translateY(-8px) perspective(500px) rotateY(0deg); }
    75% { transform: translateY(-15px) perspective(500px) rotateY(-5deg); }
}

@keyframes shieldGlow {
    0% { filter: drop-shadow(0 0 20px rgba(0, 255, 200, 0.3)); }
    100% { filter: drop-shadow(0 0 40px rgba(0, 255, 200, 0.7)); }
}

@keyframes shieldShadow {
    0%, 100% { transform: translateX(-50%) scale(1); opacity: 0.3; }
    50% { transform: translateX(-50%) scale(0.7); opacity: 0.15; }
}

.main-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 4rem;
    font-weight: 900;
    letter-spacing: 8px;
    margin: 15px 0 5px;
    background: linear-gradient(135deg, #00ffc8 0%, #00b4ff 30%, #7b2fff 60%, #00ffc8 100%);
    background-size: 300% 300%;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: titleGradient 4s ease infinite;
    text-shadow: none;
    position: relative;
}

@keyframes titleGradient {
    0% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}

.main-subtitle {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    color: rgba(0, 255, 200, 0.5);
    letter-spacing: 4px;
    text-transform: uppercase;
    margin-bottom: 5px;
}

.status-line {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.85rem;
    color: rgba(0, 255, 200, 0.35);
    letter-spacing: 2px;
}

.status-line .online {
    color: #00ffc8;
    animation: blink 1.5s ease-in-out infinite;
}

@keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
}

/* ===== GLASS DIVIDER ===== */
.holo-divider {
    height: 1px;
    margin: 25px 0;
    background: linear-gradient(90deg, transparent, #00ffc8, #00b4ff, #7b2fff, #00b4ff, #00ffc8, transparent);
    position: relative;
    overflow: visible;
}

.holo-divider::before {
    content: '';
    position: absolute;
    top: -3px;
    left: 0;
    right: 0;
    height: 7px;
    background: linear-gradient(90deg, transparent, rgba(0, 255, 200, 0.2), transparent);
    filter: blur(4px);
}

.holo-divider::after {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 12px;
    height: 12px;
    background: #00ffc8;
    border-radius: 2px;
    transform: translate(-50%, -50%) rotate(45deg);
    box-shadow: 0 0 15px rgba(0, 255, 200, 0.5);
    animation: diamondPulse 2s ease-in-out infinite;
}

@keyframes diamondPulse {
    0%, 100% { box-shadow: 0 0 15px rgba(0, 255, 200, 0.5); }
    50% { box-shadow: 0 0 25px rgba(0, 255, 200, 0.8); }
}

/* ===== 3D GLASS PANEL ===== */
.glass-panel {
    background: linear-gradient(135deg, rgba(10, 15, 30, 0.85), rgba(5, 10, 25, 0.9));
    border: 1px solid rgba(0, 255, 200, 0.15);
    border-radius: 20px;
    padding: 30px;
    position: relative;
    overflow: hidden;
    backdrop-filter: blur(20px);
    box-shadow:
        0 8px 32px rgba(0, 0, 0, 0.4),
        inset 0 1px 0 rgba(255, 255, 255, 0.05),
        0 0 60px rgba(0, 255, 200, 0.03);
}

.glass-panel::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(0, 255, 200, 0.03), transparent);
    animation: scanLine 6s linear infinite;
}

@keyframes scanLine {
    0% { left: -100%; }
    100% { left: 100%; }
}

/* ===== CORNER DECORATIONS ===== */
.corner-decor {
    position: relative;
}

.corner-decor::before,
.corner-decor::after {
    content: '';
    position: absolute;
    width: 20px;
    height: 20px;
    border-color: rgba(0, 255, 200, 0.4);
    border-style: solid;
}

.corner-decor::before {
    top: 8px;
    left: 8px;
    border-width: 2px 0 0 2px;
}

.corner-decor::after {
    bottom: 8px;
    right: 8px;
    border-width: 0 2px 2px 0;
}

/* ===== SECTION TITLES ===== */
.section-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.1rem;
    font-weight: 700;
    color: #00ffc8;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 12px;
}

.section-title .dot {
    width: 8px;
    height: 8px;
    background: #00ffc8;
    border-radius: 2px;
    transform: rotate(45deg);
    box-shadow: 0 0 10px rgba(0, 255, 200, 0.5);
}

.section-title .line {
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, rgba(0, 255, 200, 0.3), transparent);
}

/* ===== TEXT AREA ===== */
.stTextArea textarea {
    background: rgba(5, 10, 25, 0.9) !important;
    border: 1px solid rgba(0, 255, 200, 0.2) !important;
    border-radius: 14px !important;
    color: #c8ffe8 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.95rem !important;
    padding: 18px !important;
    transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94) !important;
    box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.3) !important;
}

.stTextArea textarea:focus {
    border-color: #00ffc8 !important;
    box-shadow:
        inset 0 2px 10px rgba(0, 0, 0, 0.3),
        0 0 20px rgba(0, 255, 200, 0.15),
        0 0 40px rgba(0, 255, 200, 0.05) !important;
}

.stTextArea textarea::placeholder {
    color: rgba(0, 255, 200, 0.25) !important;
    font-style: italic;
}

/* ===== BUTTONS ===== */
.stButton > button {
    background: linear-gradient(135deg, rgba(0, 255, 200, 0.15), rgba(0, 180, 255, 0.1)) !important;
    border: 1px solid rgba(0, 255, 200, 0.3) !important;
    border-radius: 12px !important;
    padding: 14px 28px !important;
    font-family: 'Orbitron', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    color: #00ffc8 !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94) !important;
    position: relative !important;
    overflow: hidden !important;
    box-shadow: 0 4px 15px rgba(0, 255, 200, 0.1) !important;
}

.stButton > button::before {
    content: '' !important;
    position: absolute !important;
    top: 0 !important;
    left: -100% !important;
    width: 100% !important;
    height: 100% !important;
    background: linear-gradient(90deg, transparent, rgba(0, 255, 200, 0.1), transparent) !important;
    transition: left 0.5s !important;
}

.stButton > button:hover::before {
    left: 100% !important;
}

.stButton > button:hover {
    transform: translateY(-3px) !important;
    border-color: #00ffc8 !important;
    box-shadow:
        0 8px 25px rgba(0, 255, 200, 0.2),
        0 0 40px rgba(0, 255, 200, 0.08) !important;
    background: linear-gradient(135deg, rgba(0, 255, 200, 0.25), rgba(0, 180, 255, 0.15)) !important;
}

.stButton > button:active {
    transform: translateY(-1px) !important;
}

/* Primary Analyze Button */
.analyze-btn .stButton > button,
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #00ffc8, #00b4ff) !important;
    border: none !important;
    color: #050510 !important;
    font-size: 1rem !important;
    padding: 18px 40px !important;
    font-weight: 800 !important;
    box-shadow:
        0 5px 25px rgba(0, 255, 200, 0.3),
        0 0 50px rgba(0, 255, 200, 0.1) !important;
}

.stButton > button[kind="primary"]:hover {
    box-shadow:
        0 8px 35px rgba(0, 255, 200, 0.4),
        0 0 60px rgba(0, 255, 200, 0.15) !important;
    transform: translateY(-3px) !important;
}

/* Example buttons column */
.example-grid {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

/* ===== RESULT CARDS ===== */
.result-3d {
    border-radius: 20px;
    padding: 30px;
    margin: 20px 0;
    position: relative;
    overflow: hidden;
    animation: resultReveal 0.7s cubic-bezier(0.25, 0.46, 0.45, 0.94);
}

@keyframes resultReveal {
    from { opacity: 0; transform: translateY(40px) scale(0.96); }
    to { opacity: 1; transform: translateY(0) scale(1); }
}

.result-3d::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    border-radius: 20px;
    padding: 1px;
    background: linear-gradient(135deg, var(--glow-color), transparent 60%);
    -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    pointer-events: none;
}

.result-safe {
    --glow-color: #00ffc8;
    background: linear-gradient(135deg, rgba(0, 255, 200, 0.06), rgba(0, 200, 160, 0.03));
    box-shadow: 0 10px 50px rgba(0, 255, 200, 0.1), inset 0 0 80px rgba(0, 255, 200, 0.02);
}

.result-suspicious {
    --glow-color: #ffc107;
    background: linear-gradient(135deg, rgba(255, 193, 7, 0.06), rgba(255, 150, 0, 0.03));
    box-shadow: 0 10px 50px rgba(255, 193, 7, 0.1), inset 0 0 80px rgba(255, 193, 7, 0.02);
}

.result-malicious {
    --glow-color: #ff3355;
    background: linear-gradient(135deg, rgba(255, 51, 85, 0.06), rgba(220, 30, 60, 0.03));
    box-shadow: 0 10px 50px rgba(255, 51, 85, 0.1), inset 0 0 80px rgba(255, 51, 85, 0.02);
    animation: resultReveal 0.7s cubic-bezier(0.25, 0.46, 0.45, 0.94), dangerPulse 3s ease-in-out infinite;
}

.result-error {
    --glow-color: #667;
    background: linear-gradient(135deg, rgba(100, 100, 120, 0.06), rgba(80, 80, 100, 0.03));
    box-shadow: 0 10px 50px rgba(100, 100, 120, 0.1);
}

@keyframes dangerPulse {
    0%, 100% { box-shadow: 0 10px 50px rgba(255, 51, 85, 0.1), inset 0 0 80px rgba(255, 51, 85, 0.02); }
    50% { box-shadow: 0 10px 70px rgba(255, 51, 85, 0.2), inset 0 0 100px rgba(255, 51, 85, 0.04); }
}

.verdict-label {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.85rem;
    font-weight: 600;
    letter-spacing: 4px;
    text-transform: uppercase;
    opacity: 0.6;
    margin-bottom: 8px;
}

.verdict-text {
    font-family: 'Orbitron', sans-serif;
    font-size: 2.5rem;
    font-weight: 900;
    letter-spacing: 3px;
    margin-bottom: 20px;
}

.verdict-safe .verdict-text { color: #00ffc8; text-shadow: 0 0 30px rgba(0, 255, 200, 0.4); }
.verdict-suspicious .verdict-text { color: #ffc107; text-shadow: 0 0 30px rgba(255, 193, 7, 0.4); }
.verdict-malicious .verdict-text { color: #ff3355; text-shadow: 0 0 30px rgba(255, 51, 85, 0.4); }
.verdict-error .verdict-text { color: #888; }

/* Confidence Bar */
.confidence-wrap {
    margin: 15px 0;
}

.conf-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
    color: rgba(0, 255, 200, 0.5);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 8px;
}

.conf-track {
    height: 8px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 4px;
    overflow: hidden;
    position: relative;
}

.conf-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 1.5s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    position: relative;
    background: linear-gradient(90deg, var(--bar-from), var(--bar-to));
}

.conf-fill::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.3) 50%, transparent 100%);
    animation: barShimmer 2.5s ease-in-out infinite;
}

@keyframes barShimmer {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(200%); }
}

.conf-value {
    font-family: 'Orbitron', sans-serif;
    font-size: 2rem;
    font-weight: 800;
    margin-top: 10px;
    text-align: right;
}

/* Explanation */
.explanation-block {
    background: rgba(255, 255, 255, 0.02);
    border-left: 2px solid rgba(0, 255, 200, 0.3);
    padding: 18px 22px;
    margin: 20px 0;
    border-radius: 0 12px 12px 0;
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.05rem;
    color: rgba(230, 241, 255, 0.85);
    line-height: 1.7;
}

/* Red Flag Items */
.red-flag {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 14px 18px;
    margin: 8px 0;
    background: rgba(255, 51, 85, 0.04);
    border: 1px solid rgba(255, 51, 85, 0.15);
    border-radius: 12px;
    transition: all 0.3s ease;
    animation: flagSlide 0.5s ease-out backwards;
}

.red-flag:hover {
    background: rgba(255, 51, 85, 0.08);
    border-color: rgba(255, 51, 85, 0.3);
    transform: translateX(6px);
}

@keyframes flagSlide {
    from { opacity: 0; transform: translateX(-20px); }
    to { opacity: 1; transform: translateX(0); }
}

.flag-num {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.75rem;
    font-weight: 700;
    color: #ff3355;
    background: rgba(255, 51, 85, 0.15);
    padding: 4px 10px;
    border-radius: 6px;
    white-space: nowrap;
}

.flag-text {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1rem;
    color: rgba(230, 241, 255, 0.8);
    line-height: 1.5;
}

/* Recommendation */
.rec-box {
    background: linear-gradient(135deg, rgba(0, 255, 200, 0.04), rgba(0, 180, 255, 0.02));
    border: 1px solid rgba(0, 255, 200, 0.15);
    border-radius: 14px;
    padding: 22px 26px;
    margin: 20px 0;
}

.rec-label {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.85rem;
    font-weight: 700;
    color: #00ffc8;
    letter-spacing: 3px;
    margin-bottom: 10px;
}

.rec-text {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.05rem;
    color: rgba(230, 241, 255, 0.85);
    line-height: 1.6;
}

/* ===== STAT TILES ===== */
.stat-tile {
    background: rgba(10, 15, 30, 0.8);
    border: 1px solid rgba(0, 255, 200, 0.12);
    border-radius: 16px;
    padding: 25px 20px;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
}

.stat-tile:hover {
    transform: translateY(-8px) scale(1.02);
    border-color: rgba(0, 255, 200, 0.3);
    box-shadow: 0 15px 40px rgba(0, 0, 0, 0.3), 0 0 30px rgba(0, 255, 200, 0.08);
}

.stat-tile::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00ffc8, transparent);
    opacity: 0;
    transition: opacity 0.3s;
}

.stat-tile:hover::before {
    opacity: 1;
}

.stat-icon {
    font-size: 2rem;
    margin-bottom: 12px;
    display: block;
}

.stat-number {
    font-family: 'Orbitron', sans-serif;
    font-size: 2.2rem;
    font-weight: 800;
    background: linear-gradient(135deg, #00ffc8, #00b4ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 5px;
}

.stat-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: rgba(0, 255, 200, 0.45);
    letter-spacing: 2px;
    text-transform: uppercase;
}

/* ===== TIPS ===== */
.tip-card-3d {
    background: rgba(10, 15, 30, 0.7);
    border: 1px solid rgba(0, 255, 200, 0.1);
    border-radius: 16px;
    padding: 24px 20px;
    text-align: center;
    transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    position: relative;
    overflow: hidden;
    height: 200px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}

.tip-card-3d:hover {
    transform: translateY(-8px) perspective(800px) rotateX(3deg);
    border-color: rgba(0, 255, 200, 0.3);
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3), 0 0 25px rgba(0, 255, 200, 0.06);
}

.tip-card-3d::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--tip-color, #00ffc8), transparent);
    opacity: 0;
    transition: opacity 0.3s;
}

.tip-card-3d:hover::after {
    opacity: 1;
}

.tip-icon-3d {
    font-size: 2.5rem;
    margin-bottom: 15px;
    display: inline-block;
    transition: transform 0.4s ease;
}

.tip-card-3d:hover .tip-icon-3d {
    transform: scale(1.2) rotate(5deg);
}

.tip-title-3d {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.85rem;
    font-weight: 700;
    color: #00ffc8;
    letter-spacing: 2px;
    margin-bottom: 10px;
}

.tip-desc-3d {
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.9rem;
    color: rgba(0, 255, 200, 0.45);
    line-height: 1.5;
}

/* ===== FOOTER ===== */
.footer-futuristic {
    text-align: center;
    padding: 40px 20px;
    position: relative;
}

.footer-brand {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.2rem;
    font-weight: 700;
    letter-spacing: 4px;
    background: linear-gradient(135deg, #00ffc8, #00b4ff, #7b2fff);
    background-size: 200% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: titleGradient 3s ease infinite;
}

.footer-sub {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: rgba(0, 255, 200, 0.25);
    letter-spacing: 3px;
    margin-top: 8px;
}

/* ===== LOADING ===== */
.loader-3d {
    text-align: center;
    padding: 60px 20px;
}

.loader-ring {
    width: 80px;
    height: 80px;
    margin: 0 auto 25px;
    border: 3px solid transparent;
    border-top-color: #00ffc8;
    border-right-color: #00b4ff;
    border-radius: 50%;
    animation: spin3d 1s linear infinite;
    position: relative;
}

.loader-ring::before {
    content: '';
    position: absolute;
    top: 6px; left: 6px; right: 6px; bottom: 6px;
    border: 2px solid transparent;
    border-bottom-color: #7b2fff;
    border-left-color: #00ffc8;
    border-radius: 50%;
    animation: spin3d 0.7s linear infinite reverse;
}

.loader-ring::after {
    content: '🛡️';
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 1.5rem;
    animation: pulse 1.5s ease-in-out infinite;
}

@keyframes spin3d {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

@keyframes pulse {
    0%, 100% { transform: translate(-50%, -50%) scale(1); }
    50% { transform: translate(-50%, -50%) scale(1.2); }
}

.loader-text {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.9rem;
    color: #00ffc8;
    letter-spacing: 4px;
    animation: blink 1.5s ease-in-out infinite;
}

.loader-subtext {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: rgba(0, 255, 200, 0.3);
    letter-spacing: 2px;
    margin-top: 8px;
}

/* ===== HIDE STREAMLIT DEFAULTS ===== */
#MainMenu, footer, header { visibility: hidden !important; }
.stDeployButton { display: none !important; }

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #050510; }
::-webkit-scrollbar-thumb { background: rgba(0, 255, 200, 0.2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(0, 255, 200, 0.4); }

/* ===== EXPANDER ===== */
.streamlit-expanderHeader {
    font-family: 'Orbitron', sans-serif !important;
    font-size: 0.8rem !important;
    color: rgba(0, 255, 200, 0.5) !important;
    letter-spacing: 2px !important;
}

/* ===== DATA EDITOR / INFO ===== */
.stAlert, .stInfo, .stWarning, .stSuccess, .stError {
    border-radius: 12px !important;
}
</style>

<!-- FLOATING PARTICLES -->
<div class="particles">
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
    <div class="particle"></div>
</div>
""", unsafe_allow_html=True)

# ================================
# 5. HERO SECTION
# ================================

st.markdown("""
<div class="hero-zone">
    <div class="shield-3d">🛡️</div>
    <div class="main-title">PHISHSHIELD AI</div>
    <div class="main-subtitle">AUTOMATED THREAT DETECTION SYSTEM</div>
    <div class="status-line">
        SYS.STATUS: <span class="online">● ONLINE</span> &nbsp;|&nbsp; AI.ENGINE: GEMINI-1.5 &nbsp;|&nbsp; PROTOCOL: ACTIVE
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

# ================================
# 6. INPUT SECTION
# ================================

col_left, col_right = st.columns([5, 3], gap="large")

with col_left:
    st.markdown("""
    <div class="glass-panel corner-decor">
        <div class="section-title">
            <span class="dot"></span>
            THREAT INPUT
            <span class="line"></span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    user_input = st.text_area(
        "",
        height=200,
        placeholder=">> Paste suspicious URL or email content here...\n\n   Example: https://paypal-verify-account.xyz/confirm\n   Or paste a full phishing email...",
        label_visibility="collapsed"
    )

with col_right:
    st.markdown("""
    <div class="glass-panel corner-decor">
        <div class="section-title">
            <span class="dot"></span>
            QUICK SIMULATION
            <span class="line"></span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("🔴  PHISHING URL", key="ex1", use_container_width=True):
        st.session_state['ui_input'] = "https://paypal-secure-verify.xyz/account/update?token=abc123"
        st.rerun()

    if st.button("📧  PHISHING EMAIL", key="ex2", use_container_width=True):
        st.session_state['ui_input'] = """Dear Customer,

We have detected unusual activity on your bank account. Your account has been temporarily restricted for your protection.

To restore full access, please verify your identity immediately:

https://secure-banking-login.ru/auth/update

⚠ WARNING: Failure to verify within 24 hours will result in permanent account closure.

Never share this email with anyone.

Sincerely,
Customer Security Division
"""
        st.rerun()

    if st.button("🟢  SAFE URL", key="ex3", use_container_width=True):
        st.session_state['ui_input'] = "https://github.com/trending"
        st.rerun()

    if st.button("🔗  NEUTRAL LINK", key="ex4", use_container_width=True):
        st.session_state['ui_input'] = "Hey check this out: https://www.wired.com/story/best-cybersecurity-practices-2024/"
        st.rerun()

# Session state sync
if 'ui_input' in st.session_state:
    user_input = st.session_state['ui_input']
    st.session_state['ui_input'] = ""

# ================================
# 7. ANALYZE BUTTON
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
# 8. RESULTS
# ================================

if analyze_clicked:
    if not user_input or user_input.strip() == "":
        st.warning("⚠ Please enter a URL or email text to analyze.")
    else:
        # Loading
        loading_placeholder = st.empty()
        loading_placeholder.markdown("""
        <div class="loader-3d">
            <div class="loader-ring"></div>
            <div class="loader-text">SCANNING THREATS</div>
            <div class="loader-subtext">Neural networks analyzing input patterns...</div>
        </div>
        """, unsafe_allow_html=True)

        result = detect_phishing(user_input)
        time.sleep(1)
        loading_placeholder.empty()

        # Extract
        verdict = result.get("verdict", "Error")
        confidence = result.get("confidence", 0)
        explanation = result.get("explanation", "No explanation provided.")
        red_flags = result.get("red_flags", [])
        recommendation = result.get("recommendation", "No recommendation available.")

        # Verdict class mapping
        v_map = {
            "Safe": ("result-safe", "✅", "#00ffc8", "#00ffc8", "#00b4ff"),
            "Suspicious": ("result-suspicious", "⚠️", "#ffc107", "#ffc107", "#ff9800"),
            "Malicious": ("result-malicious", "🚨", "#ff3355", "#ff3355", "#cc0033"),
        }
        vc, icon, color, bar_from, bar_to = v_map.get(verdict, ("result-error", "❌", "#888", "#666", "#888"))

        # Results
        st.markdown(f"""
        <div class="result-3d {vc}">
            <div class="verdict-label">ANALYSIS COMPLETE</div>
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
                {explanation}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Red Flags
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
                delay = i * 0.1
                flags_html += f"""
                <div class="red-flag" style="animation-delay: {delay}s;">
                    <span class="flag-num">#{i+1}</span>
                    <span class="flag-text">{f}</span>
                </div>
                """
            st.markdown(flags_html, unsafe_allow_html=True)

        # Recommendation
        st.markdown(f"""
        <div class="rec-box">
            <div class="rec-label">💡 RECOMMENDED ACTION</div>
            <div class="rec-text">{recommendation}</div>
        </div>
        """, unsafe_allow_html=True)

        # Expand raw content
        with st.expander("📄 VIEW RAW INPUT DATA"):
            st.code(user_input, language="text")

        # Stats row
        st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"""
            <div class="stat-tile">
                <span class="stat-icon">📊</span>
                <div class="stat-number">{confidence}%</div>
                <div class="stat-label">Confidence</div>
            </div>
            """, unsafe_allow_html=True)
        with c2:
            flag_count = len(red_flags)
            st.markdown(f"""
            <div class="stat-tile">
                <span class="stat-icon">🚩</span>
                <div class="stat-number">{flag_count}</div>
                <div class="stat-label">Red Flags</div>
            </div>
            """, unsafe_allow_html=True)
        with c3:
            status = "SECURE" if verdict == "Safe" else "ALERT" if verdict == "Suspicious" else "DANGER"
            s_color = "#00ffc8" if verdict == "Safe" else "#ffc107" if verdict == "Suspicious" else "#ff3355"
            st.markdown(f"""
            <div class="stat-tile">
                <span class="stat-icon">🛡️</span>
                <div class="stat-number" style="background: linear-gradient(135deg, {s_color}, {s_color}88); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">{status}</div>
                <div class="stat-label">Security Level</div>
            </div>
            """, unsafe_allow_html=True)

# ================================
# 9. CYBERSECURITY TIPS
# ================================

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

st.markdown("""
<div class="section-title" style="justify-content: center; font-size: 1.2rem;">
    <span class="dot"></span>
    INTEL BRIEFING — SECURITY PROTOCOLS
    <span class="line" style="max-width: 200px;"></span>
</div>
""", unsafe_allow_html=True)

r1c1, r1c2, r1c3 = st.columns(3)
tips = [
    ("🔗", "VERIFY LINKS", "Hover over every link before clicking. Check for misspellings and unusual domains."),
    ("🔐", "GUARD YOUR OTP", "No legitimate company will ever ask for your OTP, password, or PIN via email or SMS."),
    ("📧", "INSPECT SENDER", "Scammers spoof email addresses. Always verify the sender's actual email, not just the display name."),
]

for col, (icon, title, desc) in zip([r1c1, r1c2, r1c3], tips):
    with col:
        st.markdown(f"""
        <div class="tip-card-3d" style="--tip-color: #00ffc8;">
            <div class="tip-icon-3d">{icon}</div>
            <div class="tip-title-3d">{title}</div>
            <div class="tip-desc-3d">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

r2c1, r2c2, r2c3 = st.columns(3)
tips2 = [
    ("⏰", "RESIST URGENCY", "Phishing relies on panic. \"Act NOW!\" is a red flag. Always pause and verify."),
    ("🔍", "CHECK DOMAINS", "Look for subtle misspellings like \"paypa1\" or suspicious TLDs like .xyz, .ru, .tk."),
    ("🛡️", "ENABLE 2FA", "Two-factor authentication adds a critical second layer of defense against account takeovers."),
]

for col, (icon, title, desc) in zip([r2c1, r2c2, r2c3], tips2):
    with col:
        st.markdown(f"""
        <div class="tip-card-3d" style="--tip-color: #00b4ff;">
            <div class="tip-icon-3d">{icon}</div>
            <div class="tip-title-3d">{title}</div>
            <div class="tip-desc-3d">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

# ================================
# 10. FOOTER
# ================================

st.markdown('<div class="holo-divider"></div>', unsafe_allow_html=True)

st.markdown("""
<div class="footer-futuristic">
    <div class="footer-brand">PHISHSHIELD AI</div>
    <div class="footer-sub">POWERED BY GOOGLE GEMINI &nbsp;•&nbsp; STAY VIGILANT &nbsp;•&nbsp; STAY SAFE</div>
</div>
""", unsafe_allow_html=True)

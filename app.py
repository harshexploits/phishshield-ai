# ================================
# PHISHSHIELD AI - Cybersecurity MVP
# Real-world phishing detection using AI
# Upgraded with 3D Graphics & Modern UI
# ================================

import streamlit as st
from google import genai
import os
import json
import requests
from dotenv import load_dotenv
import re
import time

# Load environment variables
load_dotenv()

# ================================
# 1. CONFIGURE AI MODEL
# ================================

# Initialize Gemini client
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
model = client.models.get_model('gemini-1.5-flash')

# ================================
# 2. PHISHING DETECTION FUNCTION
# ================================

def detect_phishing(user_input):
    """
    Analyze URL or email text for phishing indicators using AI.
    Returns verdict, confidence, and explanation.
    """
    
    # Build the prompt for the AI
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
        # Call the Gemini API
        response = client.models.generate_content(model='gemini-1.5-flash', contents=prompt)
        
        # Parse the response
        result_text = response.text
        # Remove markdown code blocks if present
        result_text = re.sub(r'```json\s*', '', result_text)
        result_text = re.sub(r'```\s*', '', result_text)
        
        result = json.loads(result_text)
        return result
        
    except Exception as e:
        return {
            "verdict": "Error",
            "confidence": 0,
            "explanation": f"Analysis failed: {str(e)}",
            "red_flags": [],
            "recommendation": "Please try again or contact support."
        }

# ================================
# 3. ADDITIONAL CHECK: URL REPUTATION
# ================================

def check_url_reputation(url):
    """
    Optional: Check URL against VirusTotal or Google Safe Browsing.
    """
    return None

# ================================
# 4. STREAMLIT UI - UPGRADED WITH 3D GRAPHICS
# ================================

# Page configuration
st.set_page_config(
    page_title="PhishShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ================================
# CUSTOM CSS WITH 3D EFFECTS & MODERN DESIGN
# ================================

st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Orbitron:wght@400;500;600;700&display=swap');
    
    /* Global Styles */
    .stApp {
        background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3e 50%, #0d1f2d 100%);
    }
    
    /* Main Header with 3D Effect */
    .main-header {
        font-family: 'Orbitron', sans-serif;
        font-size: 3.5rem;
        font-weight: 800;
        text-align: center;
        margin-bottom: 10px;
        background: linear-gradient(135deg, #00d4ff 0%, #00ff88 50%, #00d4ff 100%);
        background-size: 200% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: gradientShift 3s ease infinite;
        text-shadow: 0 0 30px rgba(0, 212, 255, 0.5);
        letter-spacing: 2px;
    }
    
    @keyframes gradientShift {
        0% { background-position: 0% center; }
        50% { background-position: 100% center; }
        100% { background-position: 0% center; }
    }
    
    /* Subtitle */
    .subtitle {
        font-family: 'Inter', sans-serif;
        font-size: 1.2rem;
        color: #8892b0;
        text-align: center;
        margin-bottom: 30px;
        font-weight: 300;
    }
    
    /* Shield Icon Container */
    .shield-container {
        display: flex;
        justify-content: center;
        margin-bottom: 20px;
    }
    
    .shield-icon {
        font-size: 5rem;
        animation: pulse 2s ease-in-out infinite;
        filter: drop-shadow(0 0 20px rgba(0, 212, 255, 0.6));
    }
    
    @keyframes pulse {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.1); opacity: 0.8; }
    }
    
    /* Input Container */
    .input-container {
        background: linear-gradient(145deg, rgba(26, 26, 62, 0.8), rgba(13, 31, 45, 0.9));
        border: 1px solid rgba(0, 212, 255, 0.3);
        border-radius: 20px;
        padding: 25px;
        margin: 20px 0;
        box-shadow: 
            0 10px 40px rgba(0, 0, 0, 0.5),
            0 0 60px rgba(0, 212, 255, 0.1),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
    }
    
    /* Section Headers */
    .section-header {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.4rem;
        font-weight: 600;
        color: #00d4ff;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    /* Text Area Styling */
    .stTextArea textarea {
        background: rgba(10, 10, 26, 0.8) !important;
        border: 2px solid rgba(0, 212, 255, 0.3) !important;
        border-radius: 12px !important;
        color: #e6f1ff !important;
        font-family: 'Inter', sans-serif !important;
        padding: 15px !important;
        transition: all 0.3s ease !important;
    }
    
    .stTextArea textarea:focus {
        border-color: #00d4ff !important;
        box-shadow: 0 0 20px rgba(0, 212, 255, 0.3) !important;
    }
    
    .stTextArea textarea::placeholder {
        color: #5a6a8a !important;
    }
    
    /* Button Styling */
    .stButton button {
        background: linear-gradient(135deg, #00d4ff 0%, #00ff88 100%) !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 12px 30px !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 600 !important;
        color: #0a0a1a !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4) !important;
    }
    
    .stButton button:hover {
        transform: translateY(-3px) !important;
        box-shadow: 0 8px 30px rgba(0, 212, 255, 0.6) !important;
    }
    
    .stButton button:active {
        transform: translateY(-1px) !important;
    }
    
    /* Example Buttons */
    .example-button {
        background: rgba(0, 212, 255, 0.1) !important;
        border: 1px solid rgba(0, 212, 255, 0.3) !important;
        border-radius: 8px !important;
        padding: 10px 20px !important;
        color: #00d4ff !important;
        font-family: 'Inter', sans-serif !important;
        font-weight: 500 !important;
        transition: all 0.3s ease !important;
        width: 100% !important;
        margin: 5px 0 !important;
    }
    
    .example-button:hover {
        background: rgba(0, 212, 255, 0.2) !important;
        transform: translateX(5px) !important;
    }
    
    /* Verdict Cards with 3D Effect */
    .verdict-safe {
        background: linear-gradient(145deg, rgba(0, 255, 136, 0.15), rgba(0, 200, 100, 0.1));
        border: 2px solid #00ff88;
        border-radius: 20px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 
            0 10px 40px rgba(0, 255, 136, 0.2),
            0 0 80px rgba(0, 255, 136, 0.1),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
        animation: slideIn 0.5s ease-out;
    }
    
    .verdict-suspicious {
        background: linear-gradient(145deg, rgba(255, 193, 7, 0.15), rgba(255, 150, 0, 0.1));
        border: 2px solid #ffc107;
        border-radius: 20px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 
            0 10px 40px rgba(255, 193, 7, 0.2),
            0 0 80px rgba(255, 193, 7, 0.1),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
        animation: slideIn 0.5s ease-out;
    }
    
    .verdict-malicious {
        background: linear-gradient(145deg, rgba(255, 71, 87, 0.15), rgba(220, 53, 69, 0.1));
        border: 2px solid #ff4757;
        border-radius: 20px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 
            0 10px 40px rgba(255, 71, 87, 0.2),
            0 0 80px rgba(255, 71, 87, 0.1),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
        animation: slideIn 0.5s ease-out;
    }
    
    .verdict-error {
        background: linear-gradient(145deg, rgba(108, 117, 125, 0.15), rgba(100, 100, 100, 0.1));
        border: 2px solid #6c757d;
        border-radius: 20px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 
            0 10px 40px rgba(108, 117, 125, 0.2),
            inset 0 1px 0 rgba(255, 255, 255, 0.1);
        animation: slideIn 0.5s ease-out;
    }
    
    @keyframes slideIn {
        from { 
            opacity: 0; 
            transform: translateY(30px) scale(0.95); 
        }
        to { 
            opacity: 1; 
            transform: translateY(0) scale(1); 
        }
    }
    
    /* Verdict Title */
    .verdict-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.8rem;
        font-weight: 700;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 15px;
    }
    
    /* Confidence Bar */
    .confidence-container {
        background: rgba(10, 10, 26, 0.6);
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    
    .confidence-label {
        font-family: 'Inter', sans-serif;
        font-size: 0.9rem;
        color: #8892b0;
        margin-bottom: 8px;
    }
    
    .confidence-bar {
        height: 12px;
        background: rgba(0, 0, 0, 0.3);
        border-radius: 6px;
        overflow: hidden;
        position: relative;
    }
    
    .confidence-fill {
        height: 100%;
        border-radius: 6px;
        transition: width 1s ease-out;
        position: relative;
    }
    
    .confidence-fill::after {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
        animation: shimmer 2s infinite;
    }
    
    @keyframes shimmer {
        0% { transform: translateX(-100%); }
        100% { transform: translateX(100%); }
    }
    
    /* Red Flags */
    .red-flag-item {
        background: rgba(255, 71, 87, 0.1);
        border-left: 3px solid #ff4757;
        padding: 12px 15px;
        margin: 8px 0;
        border-radius: 0 8px 8px 0;
        font-family: 'Inter', sans-serif;
        color: #e6f1ff;
        transition: all 0.3s ease;
    }
    
    .red-flag-item:hover {
        background: rgba(255, 71, 87, 0.15);
        transform: translateX(5px);
    }
    
    /* Recommendation Box */
    .recommendation-box {
        background: linear-gradient(145deg, rgba(0, 212, 255, 0.1), rgba(0, 150, 200, 0.05));
        border: 1px solid rgba(0, 212, 255, 0.3);
        border-radius: 12px;
        padding: 20px;
        margin: 15px 0;
    }
    
    .recommendation-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.1rem;
        color: #00d4ff;
        margin-bottom: 10px;
    }
    
    /* Tips Section */
    .tips-container {
        background: linear-gradient(145deg, rgba(26, 26, 62, 0.6), rgba(13, 31, 45, 0.7));
        border: 1px solid rgba(0, 212, 255, 0.2);
        border-radius: 15px;
        padding: 20px;
        margin: 20px 0;
    }
    
    .tip-card {
        background: rgba(10, 10, 26, 0.5);
        border: 1px solid rgba(0, 212, 255, 0.2);
        border-radius: 12px;
        padding: 15px;
        margin: 10px 0;
        transition: all 0.3s ease;
    }
    
    .tip-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 30px rgba(0, 212, 255, 0.2);
    }
    
    .tip-icon {
        font-size: 2rem;
        margin-bottom: 10px;
    }
    
    .tip-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 1rem;
        color: #00d4ff;
        margin-bottom: 8px;
    }
    
    .tip-text {
        font-family: 'Inter', sans-serif;
        font-size: 0.9rem;
        color: #8892b0;
        line-height: 1.5;
    }
    
    /* Footer */
    .footer {
        text-align: center;
        padding: 30px;
        margin-top: 40px;
        border-top: 1px solid rgba(0, 212, 255, 0.2);
    }
    
    .footer-text {
        font-family: 'Inter', sans-serif;
        font-size: 0.9rem;
        color: #5a6a8a;
    }
    
    .footer-brand {
        font-family: 'Orbitron', sans-serif;
        font-weight: 600;
        background: linear-gradient(135deg, #00d4ff, #00ff88);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    /* Loading Animation */
    .loading-container {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 40px;
    }
    
    .loading-shield {
        font-size: 4rem;
        animation: rotate 2s linear infinite;
    }
    
    @keyframes rotate {
        from { transform: rotateY(0deg); }
        to { transform: rotateY(360deg); }
    }
    
    /* Stats Cards */
    .stat-card {
        background: linear-gradient(145deg, rgba(26, 26, 62, 0.8), rgba(13, 31, 45, 0.9));
        border: 1px solid rgba(0, 212, 255, 0.3);
        border-radius: 15px;
        padding: 20px;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .stat-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 15px 40px rgba(0, 212, 255, 0.3);
    }
    
    .stat-value {
        font-family: 'Orbitron', sans-serif;
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #00d4ff, #00ff88);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .stat-label {
        font-family: 'Inter', sans-serif;
        font-size: 0.9rem;
        color: #8892b0;
        margin-top: 5px;
    }
    
    /* Divider */
    .glow-divider {
        height: 2px;
        background: linear-gradient(90deg, transparent, #00d4ff, transparent);
        margin: 30px 0;
        box-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
    }
    
    /* Streamlit Overrides */
    .stMarkdown {
        color: #e6f1ff;
    }
    
    .stSubheader {
        font-family: 'Orbitron', sans-serif !important;
        color: #00d4ff !important;
    }
    
    .stInfo {
        background: rgba(0, 212, 255, 0.1) !important;
        border-left-color: #00d4ff !important;
        border-radius: 10px !important;
    }
    
    .stWarning {
        background: rgba(255, 193, 7, 0.1) !important;
        border-left-color: #ffc107 !important;
        border-radius: 10px !important;
    }
    
    .stSpinner > div {
        border-top-color: #00d4ff !important;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ================================
# MAIN UI LAYOUT
# ================================

# Animated Shield Icon
st.markdown("""
<div class="shield-container">
    <div class="shield-icon">🛡️</div>
</div>
""", unsafe_allow_html=True)

# Main Header
st.markdown('<h1 class="main-header">PHISHSHIELD AI</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">AI-Powered Cybersecurity • Real-Time Phishing Detection • Instant Protection</p>', unsafe_allow_html=True)

# Glow Divider
st.markdown('<div class="glow-divider"></div>', unsafe_allow_html=True)

# ================================
# INPUT SECTION - 3D CONTAINER
# ================================

st.markdown("""
<div class="input-container">
    <div class="section-header">
        📎 ANALYZE THREATS
    </div>
</div>
""", unsafe_allow_html=True)

# Two columns for input
col1, col2 = st.columns([3, 2])

with col1:
    st.markdown("""
    <div class="input-container">
        <div class="section-header">Paste URL or Email Content</div>
    </div>
    """, unsafe_allow_html=True)
    
    user_input = st.text_area(
        "",
        height=180,
        placeholder="https://suspicious-link.xyz/verify\n\nOR\n\nPaste suspicious email content here...",
        label_visibility="collapsed"
    )

with col2:
    st.markdown("""
    <div class="input-container">
        <div class="section-header">Quick Test Examples</div>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("🔴 Suspicious URL", key="suspicious_url", use_container_width=True):
        st.session_state['user_input'] = "https://paypal-verify-account.xyz/confirm"
        st.rerun()
    
    if st.button("📧 Phishing Email", key="phishing_email", use_container_width=True):
        st.session_state['user_input'] = """Dear valued customer,

Your account has been flagged for suspicious activity. 
Please verify your identity immediately by clicking the link below:

https://bank-secure-verify.xyz/update

Failure to verify within 24 hours will result in account suspension.

Sincerely,
Your Bank Support Team
"""
        st.rerun()
    
    if st.button("🟢 Safe URL", key="safe_url", use_container_width=True):
        st.session_state['user_input'] = "https://www.google.com"
        st.rerun()
    
    if st.button("🔗 Neutral Link", key="neutral_link", use_container_width=True):
        st.session_state['user_input'] = "Check out this article about cybersecurity: https://www.wired.com/story/phishing-attacks-2024/"
        st.rerun()

# Update input from session state
if 'user_input' in st.session_state:
    user_input = st.session_state['user_input']
    st.session_state['user_input'] = ""

# ================================
# ANALYZE BUTTON - 3D EFFECT
# ================================

st.markdown('<div style="margin: 30px 0;"></div>', unsafe_allow_html=True)

col_center1, col_center2, col_center3 = st.columns([1, 2, 1])
with col_center2:
    analyze_clicked = st.button(
        "🔍 ANALYZE FOR THREATS",
        type="primary",
        use_container_width=True
    )

# ================================
# RESULTS SECTION
# ================================

if analyze_clicked:
    if not user_input or user_input.strip() == "":
        st.warning("⚠️ Please enter a URL or email text to analyze.")
    else:
        # Loading animation
        with st.spinner(""):
            st.markdown("""
            <div class="loading-container">
                <div class="loading-shield">🛡️</div>
            </div>
            <p style="text-align: center; color: #00d4ff; font-family: 'Orbitron', sans-serif;">
                Analyzing with AI Neural Networks...
            </p>
            """, unsafe_allow_html=True)
            result = detect_phishing(user_input)
            time.sleep(0.5)  # Brief pause for animation effect
        
        # Clear loading and show results
        st.empty()
        
        # Results Header
        st.markdown('<div class="glow-divider"></div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="section-header" style="font-size: 1.6rem; justify-content: center;">
            📊 ANALYSIS RESULTS
        </div>
        """, unsafe_allow_html=True)
        
        # Extract results
        verdict = result.get("verdict", "Error")
        confidence = result.get("confidence", 0)
        explanation = result.get("explanation", "No explanation provided.")
        red_flags = result.get("red_flags", [])
        recommendation = result.get("recommendation", "No recommendation provided.")
        
        # Determine verdict styling
        if verdict == "Safe":
            verdict_class = "verdict-safe"
            icon = "✅"
            color = "#00ff88"
            color_name = "safe"
        elif verdict == "Suspicious":
            verdict_class = "verdict-suspicious"
            icon = "⚠️"
            color = "#ffc107"
            color_name = "suspicious"
        elif verdict == "Malicious":
            verdict_class = "verdict-malicious"
            icon = "🚨"
            color = "#ff4757"
            color_name = "malicious"
        else:
            verdict_class = "verdict-error"
            icon = "❌"
            color = "#6c757d"
            color_name = "error"
        
        # Display Verdict Card
        st.markdown(f"""
        <div class="{verdict_class}">
            <div class="verdict-title" style="color: {color};">
                {icon} VERDICT: {verdict.upper()}
            </div>
            
            <div class="confidence-container">
                <div class="confidence-label">Confidence Level</div>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: {confidence}%; background: linear-gradient(90deg, {color}, {color}88);"></div>
                </div>
                <div style="text-align: right; font-family: 'Orbitron', sans-serif; font-size: 1.5rem; color: {color}; margin-top: 10px;">
                    {confidence}%
                </div>
            </div>
            
            <div style="margin-top: 20px;">
                <div class="confidence-label">EXPLANATION</div>
                <p style="font-family: 'Inter', sans-serif; font-size: 1.1rem; color: #e6f1ff; line-height: 1.6; margin-top: 10px;">
                    {explanation}
                </p>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Red Flags Section
        if red_flags and len(red_flags) > 0:
            st.markdown("""
            <div style="margin-top: 25px;">
                <div class="section-header" style="font-size: 1.3rem;">
                    🚩 RED FLAGS DETECTED ({len(red_flags)})
                </div>
            </div>
            """.format(len=len(red_flags)), unsafe_allow_html=True)
            
            for i, flag in enumerate(red_flags):
                st.markdown(f"""
                <div class="red-flag-item" style="animation-delay: {i * 0.1}s;">
                    <strong>#{i+1}</strong> {flag}
                </div>
                """, unsafe_allow_html=True)
        
        # Recommendation Section
        if recommendation:
            st.markdown(f"""
            <div class="recommendation-box">
                <div class="recommendation-title">💡 RECOMMENDATION</div>
                <p style="font-family: 'Inter', sans-serif; font-size: 1.05rem; color: #e6f1ff; line-height: 1.6; margin-top: 10px;">
                    {recommendation}
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        # View Analyzed Content
        with st.expander("📄 View Analyzed Content", expanded=False):
            st.code(user_input, language="text")
        
        # Stats Row
        st.markdown('<div class="glow-divider"></div>', unsafe_allow_html=True)
        
        col_stat1, col_stat2, col_stat3 = st.columns(3)
        
        with col_stat1:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-value">{confidence}%</div>
                <div class="stat-label">Confidence Score</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col_stat2:
            flags_count = len(red_flags) if red_flags else 0
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-value">{flags_count}</div>
                <div class="stat-label">Red Flags Found</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col_stat3:
            status = "PROTECTED" if verdict != "Malicious" else "DANGER"
            status_color = "#00ff88" if verdict != "Malicious" else "#ff4757"
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-value" style="background: linear-gradient(135deg, {status_color}, {status_color}88); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                    {status}
                </div>
                <div class="stat-label">Security Status</div>
            </div>
            """, unsafe_allow_html=True)

# ================================
# CYBERSECURITY TIPS SECTION
# ================================

st.markdown('<div class="glow-divider"></div>', unsafe_allow_html=True)

st.markdown("""
<div class="tips-container">
    <div class="section-header" style="justify-content: center; font-size: 1.5rem;">
        🧠 CYBERSECURITY TIPS
    </div>
</div>
""", unsafe_allow_html=True)

tip_col1, tip_col2, tip_col3 = st.columns(3)

with tip_col1:
    st.markdown("""
    <div class="tip-card">
        <div class="tip-icon">🔗</div>
        <div class="tip-title">CHECK BEFORE CLICKING</div>
        <div class="tip-text">Always hover over links to see the actual URL before clicking. Scammers use URL shorteners and lookalike domains.</div>
    </div>
    """, unsafe_allow_html=True)

with tip_col2:
    st.markdown("""
    <div class="tip-card">
        <div class="tip-icon">🔐</div>
        <div class="tip-title">NEVER SHARE OTP</div>
        <div class="tip-text">Legitimate organizations will NEVER ask for your OTP, password, or PIN via email, SMS, or phone.</div>
    </div>
    """, unsafe_allow_html=True)

with tip_col3:
    st.markdown("""
    <div class="tip-card">
        <div class="tip-icon">📧</div>
        <div class="tip-title">VERIFY SENDER</div>
        <div class="tip-text">Check the sender's email address carefully. Scammers use fake but similar addresses to trick you.</div>
    </div>
    """, unsafe_allow_html=True)

# Additional Tips Row
tip_col4, tip_col5, tip_col6 = st.columns(3)

with tip_col4:
    st.markdown("""
    <div class="tip-card">
        <div class="tip-icon">⏰</div>
        <div class="tip-title">WATCH FOR URGENCY</div>
        <div class="tip-text">Phishing emails often create false urgency: "Act now!" "Your account will be deleted!" Think before you act.</div>
    </div>
    """, unsafe_allow_html=True)

with tip_col5:
    st.markdown("""
    <div class="tip-card">
        <div class="tip-icon">🔍</div>
        <div class="tip-title">INSPECT DOMAIN NAMES</div>
        <div class="tip-text">Look for misspellings like "paypa1" instead of "paypal" or unusual domains like ".xyz", ".ru", ".cn".</div>
    </div>
    """, unsafe_allow_html=True)

with tip_col6:
    st.markdown("""
    <div class="tip-card">
        <div class="tip-icon">🛡️</div>
        <div class="tip-title">USE 2FA</div>
        <div class="tip-text">Enable Two-Factor Authentication on all important accounts. It adds an extra layer of security.</div>
    </div>
    """, unsafe_allow_html=True)

# ================================
# FOOTER
# ================================

st.markdown('<div class="glow-divider"></div>', unsafe_allow_html=True)

st.markdown("""
<div class="footer">
    <p class="footer-text">
        <span class="footer-brand">PhishShield AI</span> | 
        Built with ❤️ for Cybersecurity Awareness | 
        Powered by Google Gemini AI
    </p>
    <p class="footer-text" style="margin-top: 10px; font-size: 0.8rem;">
        © 2024 PhishShield AI | Stay Safe Online 🛡️
    </p>
</div>
""", unsafe_allow_html=True)

# ================================
# RUN COMMAND
# ================================
# To run: streamlit run app.py

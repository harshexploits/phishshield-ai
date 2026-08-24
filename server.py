"""
PhishShield AI — Render deployment
Streamlit runs directly on Render's PORT. No proxy.
ads.txt is served separately via Vercel.
"""
import subprocess, sys, os

PORT = os.environ.get("PORT", "8501")

# Run Streamlit directly on Render's PORT
os.execvp(sys.executable, [
    sys.executable, "-m", "streamlit", "run", "app.py",
    "--server.port", str(PORT),
    "--server.headless", "true",
    "--server.address", "0.0.0.0",
    "--server.enableXsrfProtection", "false",
    "--server.enableCORS", "false",
    "--browser.gatherUsageStats", "false",
])

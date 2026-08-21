"""
PhishShield AI — Render deployment
Run Streamlit directly on Render's assigned PORT.
No proxy needed — Render handles HTTP+WebSocket natively.
"""
import subprocess, sys, os

PORT = os.environ.get("PORT", "8501")

# Run Streamlit directly on Render's port
os.execvp(sys.executable, [
    sys.executable, "-m", "streamlit", "run", "app.py",
    "--server.port", PORT,
    "--server.headless", "true",
    "--server.address", "0.0.0.0",
    "--server.enableXsrfProtection", "false",
    "--server.enableCORS", "false",
    "--browser.gatherUsageStats", "false",
])

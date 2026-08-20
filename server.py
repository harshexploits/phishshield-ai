"""
PhishShield AI — Render deployment
Proxy server: serves ads.txt + forwards everything to Streamlit
"""
import subprocess, sys, time, os, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.error import URLError

PORT = int(os.environ.get("PORT", 10000))
ST_PORT = 8501

# Start Streamlit in background
def run_streamlit():
    subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", "app.py",
        "--server.port", str(ST_PORT),
        "--server.headless", "true",
        "--server.address", "127.0.0.1",
        "--browser.gatherUsageStats", "false",
    ])

t = threading.Thread(target=run_streamlit, daemon=True)
t.start()

# Wait for Streamlit to be ready
for i in range(30):
    try:
        urlopen(f"http://127.0.0.1:{ST_PORT}/healthz", timeout=2)
        break
    except Exception:
        time.sleep(1)

ADS_TXT = b"google.com, pub-3382996367685285, DIRECT, f08c47fec0942fa0\n"

class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.rstrip("?") == "/ads.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(ADS_TXT)
            return

        try:
            target = f"http://127.0.0.1:{ST_PORT}{self.path}"
            req = Request(target)
            req.add_header("User-Agent", self.headers.get("User-Agent", ""))
            resp = urlopen(req, timeout=60)
            self.send_response(resp.status)
            skip = {"transfer-encoding", "content-encoding", "content-security-policy"}
            for k, v in resp.headers.items():
                if k.lower() not in skip:
                    self.send_header(k, v)
            self.end_headers()
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except URLError:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Backend starting...")
        except Exception:
            self.send_response(502)
            self.end_headers()

    def do_POST(self):
        self.do_GET()

    def log_message(self, *a):
        pass

print(f"PhishShield AI proxy on port {PORT}")
HTTPServer(("0.0.0.0", PORT), ProxyHandler).serve_forever()

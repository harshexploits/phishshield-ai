"""
PhishShield AI — Render deployment with ads.txt serving
Tiny aiohttp proxy: serves /ads.txt directly, forwards everything else to Streamlit.
"""
import subprocess, sys, os, threading, time, asyncio
from aiohttp import web

PORT = int(os.environ.get("PORT", "8501"))
STREAMLIT_PORT = 8502  # internal Streamlit port

# ── Start Streamlit on internal port ──
threading.Thread(target=lambda: os.execvp(sys.executable, [
    sys.executable, "-m", "streamlit", "run", "app.py",
    "--server.port", str(STREAMLIT_PORT),
    "--server.headless", "true",
    "--server.address", "127.0.0.1",
    "--server.enableXsrfProtection", "false",
    "--server.enableCORS", "false",
    "--browser.gatherUsageStats", "false",
]), daemon=True).start()

# Wait for Streamlit to be ready
time.sleep(3)

# ── ads.txt content ──
ADS_TXT = b"google.com, pub-3382996367685285, DIRECT, f08c47fec0942fa0\n"

# ── aiohttp handler ──
async def handler(request):
    # Serve ads.txt directly
    if request.path == "/ads.txt":
        return web.Response(text=ADS_TXT.decode(), content_type="text/plain")

    # Proxy everything else to Streamlit
    import aiohttp
    target_url = f"http://127.0.0.1:{STREAMLIT_PORT}{request.path_qs}"

    # Handle WebSocket upgrade (Streamlit needs this)
    if request.headers.get("Upgrade", "").lower() == "websocket":
        # Forward WebSocket to Streamlit
        ws_target = f"ws://127.0.0.1:{STREAMLIT_PORT}{request.path_qs}"
        ws_server = web.WebSocketResponse()
        await ws_server.prepare(request)

        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(ws_target, headers=request.headers) as ws_client:
                async def fwd(src, dst):
                    async for msg in src:
                        await dst.send_bytes(msg.data) if msg.type == aiohttp.WSMsgType.TEXT else None
                await asyncio.gather(fwd(ws_server, ws_client), fwd(ws_client, ws_server))
        return ws_server

    # Regular HTTP proxy
    async with aiohttp.ClientSession() as session:
        body = await request.read()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "transfer-encoding")}
        async with session.request(request.method, target_url, headers=headers, data=body) as resp:
            resp_body = await resp.read()
            resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in ("transfer-encoding", "content-encoding")}
            return web.Response(status=resp.status, body=resp_body, headers=resp_headers)

app = web.Application()
app.router.add_route("*", "/{path_info:.*}", handler)

if __name__ == "__main__":
    print(f"PhishShield proxy running on port {PORT}")
    web.run_app(app, host="0.0.0.0", port=PORT)

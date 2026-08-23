"""
PhishShield AI — Render deployment with ads.txt serving
Starts Streamlit in background, aiohttp proxy in foreground.
"""
import subprocess, sys, os, time
from aiohttp import web

PORT = int(os.environ.get("PORT", "8501"))
STREAMLIT_PORT = 8502

# Start Streamlit in background
subprocess.Popen([
    sys.executable, "-m", "streamlit", "run", "app.py",
    "--server.port", str(STREAMLIT_PORT),
    "--server.headless", "true",
    "--server.address", "127.0.0.1",
    "--server.enableXsrfProtection", "false",
    "--server.enableCORS", "false",
    "--browser.gatherUsageStats", "false",
])

# Wait for Streamlit to be ready
time.sleep(5)

# ads.txt content
ADS_TXT = b"google.com, pub-3382996367685285, DIRECT, f08c47fec0942fa0\n"

# aiohttp handler
async def handler(request):
    if request.path == "/ads.txt":
        return web.Response(text=ADS_TXT.decode(), content_type="text/plain")

    import aiohttp as aio
    target = f"http://127.0.0.1:{STREAMLIT_PORT}{request.path_qs}"

    # WebSocket proxy
    if request.headers.get("Upgrade", "").lower() == "websocket":
        ws_server = web.WebSocketResponse()
        await ws_server.prepare(request)
        async with aio.ClientSession() as session:
            async with session.ws_connect(target) as ws_client:
                async def fwd(src, dst):
                    async for msg in src:
                        if msg.type in (aio.WSMsgType.TEXT, aio.WSMsgType.BINARY):
                            await dst.send_bytes(msg.data)
                        elif msg.type == aio.WSMsgType.CLOSE:
                            break
                await asyncio.gather(fwd(ws_server, ws_client), fwd(ws_client, ws_server))
        return ws_server

    # HTTP proxy
    async with aio.ClientSession() as session:
        body = await request.read()
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in ("host", "transfer-encoding")}
        async with session.request(request.method, target, headers=headers, data=body) as resp:
            resp_body = await resp.read()
            resp_headers = {k: v for k, v in resp.headers.items()
                           if k.lower() not in ("transfer-encoding", "content-encoding")}
            return web.Response(status=resp.status, body=resp_body, headers=resp_headers)

import asyncio
app = web.Application()
app.router.add_route("*", "/{path_info:.*}", handler)

if __name__ == "__main__":
    print(f"PhishShield proxy on port {PORT}")
    web.run_app(app, host="0.0.0.0", port=PORT)

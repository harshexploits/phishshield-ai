"""
PhishShield AI — Render deployment
/ads.txt served directly.
HTTP + WebSocket proxied to Streamlit.
Key fix: Sec-WebSocket-Protocol sent via extra_headers (protocols param deprecated).
"""
import subprocess, sys, os, time, asyncio
import aiohttp
from aiohttp import web

PORT = int(os.environ.get("PORT", "8501"))
STREAMLIT_PORT = 8502
STREAMLIT_HOST = "127.0.0.1"

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

# Health-check loop
print("Waiting for Streamlit...")
for i in range(60):
    time.sleep(2)
    try:
        import urllib.request
        urllib.request.urlopen(f"http://{STREAMLIT_HOST}:{STREAMLIT_PORT}/_stcore/health", timeout=3)
        print(f"Ready ({(i+1)*2}s)")
        break
    except Exception:
        if i % 5 == 0:
            print(f"  waiting... ({(i+1)*2}s)")
else:
    print("WARNING: Streamlit not ready in 120s")

ADS_TXT = b"google.com, pub-3382996367685285, DIRECT, f08c47fec0942fa0\n"


async def proxy_ws(request):
    """Forward WebSocket to Streamlit, manually sending subprotocol."""
    ws_server = web.WebSocketResponse()
    await ws_server.prepare(request)

    target = f"ws://{STREAMLIT_HOST}:{STREAMLIT_PORT}{request.path_qs}"

    # Get subprotocols from client and send via extra_headers
    subprotocol_header = request.headers.get("Sec-WebSocket-Protocol", "")
    extra_headers = {}
    if subprotocol_header:
        extra_headers["Sec-WebSocket-Protocol"] = subprotocol_header

    try:
        session = aiohttp.ClientSession()
        ws_client = await session.ws_connect(
            target,
            headers=extra_headers,  # This forces the header to be sent
        )
        print(f"WS connected to Streamlit (proto: {subprotocol_header})")
    except Exception as e:
        print(f"WS connect error: {e}")
        try:
            await ws_server.close()
        except Exception:
            pass
        return ws_server

    async def forward(src, dst):
        try:
            async for msg in src:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await dst.send_str(msg.data)
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    await dst.send_bytes(msg.data)
                elif msg.type in (aiohttp.WSMsgType.CLOSE,
                                  aiohttp.WSMsgType.CLOSING,
                                  aiohttp.WSMsgType.ERROR):
                    break
        except Exception:
            pass

    try:
        await asyncio.gather(
            forward(ws_server, ws_client),
            forward(ws_client, ws_server),
        )
    except Exception:
        pass
    finally:
        try:
            await ws_client.close()
        except Exception:
            pass
        try:
            await session.close()
        except Exception:
            pass

    return ws_server


async def proxy_http(request):
    """Forward HTTP to Streamlit."""
    target = f"http://{STREAMLIT_HOST}:{STREAMLIT_PORT}{request.path_qs}"
    try:
        async with aiohttp.ClientSession() as session:
            body = await request.read()
            headers = {
                k: v for k, v in request.headers.items()
                if k.lower() not in ("host", "transfer-encoding")
            }
            async with session.request(
                request.method, target, headers=headers, data=body
            ) as resp:
                resp_body = await resp.read()
                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in ("transfer-encoding", "content-encoding")
                }
                return web.Response(
                    status=resp.status, body=resp_body, headers=resp_headers
                )
    except Exception as e:
        return web.Response(status=502, text=f"Backend unavailable: {e}")


async def handler(request):
    if request.path == "/ads.txt":
        return web.Response(text=ADS_TXT.decode(), content_type="text/plain")

    if request.headers.get("Upgrade", "").lower() == "websocket":
        return await proxy_ws(request)

    return await proxy_http(request)


app = web.Application()
app.router.add_route("*", "/{path_info:.*}", handler)

if __name__ == "__main__":
    print(f"PhishShield proxy on port {PORT}")
    web.run_app(app, host="0.0.0.0", port=PORT)

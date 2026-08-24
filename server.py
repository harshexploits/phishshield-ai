"""
PhishShield AI — Render deployment
Serves /ads.txt for AdSense, proxies everything else to Streamlit (incl. WebSocket).
"""
import subprocess, sys, os, time, asyncio
import aiohttp
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

# Wait for Streamlit to fully start
time.sleep(8)

ADS_TXT = b"google.com, pub-3382996367685285, DIRECT, f08c47fec0942fa0\n"


async def proxy_ws(request):
    """Forward WebSocket connections to Streamlit."""
    ws_server = web.WebSocketResponse()
    await ws_server.prepare(request)

    target = f"ws://127.0.0.1:{STREAMLIT_PORT}{request.path_qs}"
    try:
        session = aiohttp.ClientSession()
        ws_client = await session.ws_connect(target)
    except Exception as e:
        await ws_server.close()
        return ws_server

    async def forward(src, dst):
        try:
            async for msg in src:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await dst.send_str(msg.data)
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    await dst.send_bytes(msg.data)
                elif msg.type == aiohttp.WSMsgType.CLOSE:
                    break
                elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSING):
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
    """Forward HTTP requests to Streamlit."""
    target = f"http://127.0.0.1:{STREAMLIT_PORT}{request.path_qs}"
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
    # Serve ads.txt directly
    if request.path == "/ads.txt":
        return web.Response(text=ADS_TXT.decode(), content_type="text/plain")

    # WebSocket upgrade → proxy WS
    if request.headers.get("Upgrade", "").lower() == "websocket":
        return await proxy_ws(request)

    # Everything else → proxy HTTP
    return await proxy_http(request)


app = web.Application()
app.router.add_route("*", "/{path_info:.*}", handler)

if __name__ == "__main__":
    print(f"PhishShield proxy on port {PORT}")
    web.run_app(app, host="0.0.0.0", port=PORT)

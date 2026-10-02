"""Live stream.

* Auth happens on the first message (not the URL) so tokens never land in access logs or browser history.
* The Origin header, when present, must be an allowed origin (defence in depth against cross-site
  WebSocket hijacking; the token requirement is the primary control).
* The connection is closed when the token expires, so a stream cannot outlive the session.
"""

import asyncio
import json
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import get_settings
from app.core.security import decode_token
from app.services.bus import bus

router = APIRouter(tags=["live"])
AUTH_TIMEOUT_S = 5


@router.websocket("/ws/stream")
async def stream(ws: WebSocket) -> None:
    origin = ws.headers.get("origin")
    if origin and origin not in get_settings().cors_origin_list:
        await ws.close(code=4403)
        return
    await ws.accept()
    try:
        msg = json.loads(await asyncio.wait_for(ws.receive_text(), AUTH_TIMEOUT_S))
        payload = decode_token(str(msg.get("token", ""))) if msg.get("type") == "auth" else None
        if not payload:
            await ws.close(code=4401)
            return
    except (TimeoutError, ValueError, AttributeError, WebSocketDisconnect):
        await ws.close(code=4401)
        return

    expires_at = float(payload["exp"])
    await ws.send_json({"type": "ready"})
    async with bus.subscribe() as queue:
        try:
            while True:
                remaining = expires_at - time.time()
                if remaining <= 0:
                    await ws.close(code=4401)
                    return
                try:
                    await ws.send_json(await asyncio.wait_for(queue.get(), timeout=min(remaining, 30)))
                except TimeoutError:
                    continue
        except (WebSocketDisconnect, RuntimeError):
            return

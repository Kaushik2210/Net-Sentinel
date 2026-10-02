"""Live stream. Auth happens on the first message (not the URL) so tokens never land in
access logs or browser history."""

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.security import decode_token
from app.services.bus import bus

router = APIRouter(tags=["live"])
AUTH_TIMEOUT_S = 5


@router.websocket("/ws/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    try:
        msg = json.loads(await asyncio.wait_for(ws.receive_text(), AUTH_TIMEOUT_S))
        if msg.get("type") != "auth" or not decode_token(str(msg.get("token", ""))):
            await ws.close(code=4401)
            return
    except (TimeoutError, ValueError, WebSocketDisconnect):
        await ws.close(code=4401)
        return

    await ws.send_json({"type": "ready"})
    async with bus.subscribe() as queue:
        try:
            while True:
                await ws.send_json(await queue.get())
        except (WebSocketDisconnect, RuntimeError):
            return

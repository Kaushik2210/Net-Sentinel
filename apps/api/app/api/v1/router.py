from fastapi import APIRouter

from app.api.v1 import analytics, auth, devices, events, network, ws

api_router = APIRouter(prefix="/api/v1")
for module in (auth, devices, events, network, analytics, ws):
    api_router.include_router(module.router)

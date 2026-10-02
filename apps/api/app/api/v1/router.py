from fastapi import APIRouter

from app.api.v1 import alerts, analytics, auth, detections, devices, events, incidents, ml, network, ws

api_router = APIRouter(prefix="/api/v1")
for module in (auth, devices, events, network, analytics, ml, alerts, incidents, detections, ws):
    api_router.include_router(module.router)

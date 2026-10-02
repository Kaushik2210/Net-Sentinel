from fastapi import APIRouter

from app.api.v1 import alerts, analytics, auth, detections, devices, events, incidents, mitre, ml, network, replay, ws

api_router = APIRouter(prefix="/api/v1")
for module in (auth, devices, events, network, analytics, ml, alerts, incidents, mitre, replay, detections, ws):
    api_router.include_router(module.router)

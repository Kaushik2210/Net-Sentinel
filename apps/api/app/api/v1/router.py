from fastapi import APIRouter

from app.api.v1 import alerts, analyst, analytics, auth, detections, devices, events, incidents, investigations, mitre, ml, network, public, replay, research, response, threat_intel, ws

api_router = APIRouter(prefix="/api/v1")
for module in (auth, public, devices, events, network, analytics, ml, alerts, incidents, mitre, replay, investigations, analyst, research, response, threat_intel, detections, ws):
    api_router.include_router(module.router)

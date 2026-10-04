"""Unauthenticated endpoints for the public playground.

Safe to expose because nothing here accepts uploaded content or touches stored data: scenarios are generated
server-side from fixed recipes, results are computed in memory and never persisted, thresholds are clamped to
fixed ranges, and every route is rate limited.
"""

import asyncio
from functools import lru_cache

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.ratelimit import limiter
from app.detection.base import registry
from app.ingest.pcap import parse_pcap
from app.ingest.sample import STAGES, build_sample_pcap
from app.replay.engine import build_replay

router = APIRouter(prefix="/public", tags=["public"])

SCENARIOS: dict[str, dict] = {
    "full": {"label": "Full attack chain", "stages": STAGES, "blurb": "Sweep, port scan, SSH brute force, access, lateral movement, DNS tunnelling and exfiltration from one host."},
    "recon": {"label": "Reconnaissance only", "stages": ("sweep", "portscan"), "blurb": "A host sweep followed by a port scan. No access is gained."},
    "bruteforce": {"label": "Brute force and access", "stages": ("bruteforce", "access"), "blurb": "Repeated SSH logins, then a successful long session and lateral SSH."},
    "exfil": {"label": "DNS tunnelling and exfiltration", "stages": ("dns", "exfil"), "blurb": "Encoded DNS lookups followed by a large upload to an external host."},
    "benign": {"label": "Normal traffic only", "stages": (), "blurb": "Six workstations doing ordinary DNS and HTTPS. Use it to check the detectors stay quiet."},
}

# detector -> parameter -> (default, min, max, label). Bounds keep a visitor from making the run expensive or meaningless.
TUNABLES: dict[str, dict[str, tuple[int, int, int, str]]] = {
    "PortScanDetector": {"min_ports": (15, 3, 200, "Ports probed on one host"), "min_hosts": (10, 3, 100, "Hosts probed by one source")},
    "BruteForceDetector": {"min_failures": (10, 3, 200, "Failed logins in the window")},
    "LateralMovementDetector": {"min_hosts": (3, 2, 10, "Internal hosts reached over admin ports")},
    "DNSAnomalyDetector": {"min_queries": (200, 10, 1000, "DNS queries in the window")},
    "DataExfiltrationDetector": {"min_bytes": (3_000_000, 500_000, 50_000_000, "Bytes sent to one external host")},
}


ABOUT = {
    "PortScanDetector": "One source touching many ports on a host, or many hosts, with unanswered or rejected connections.",
    "SuspiciousProtocolDetector": "Repeated use of ports rarely legitimate here, such as telnet, IRC, Tor relay or common backdoor ports.",
    "BruteForceDetector": "Many failed logins from one source to one service inside a short window.",
    "LateralMovementDetector": "One internal host logging in to several other internal hosts over admin protocols.",
    "CredentialCompromiseDetector": "A run of failed logins followed by a success from the same source.",
    "DNSAnomalyDetector": "High-volume, high-entropy, long-label DNS lookups that look like data encoded in names.",
    "ConnectionAnomalyDetector": "One internal host contacting an unusually large number of external destinations.",
    "DataExfiltrationDetector": "Large volume of bytes sent from an internal host to one external destination.",
}


class PlaygroundRequest(BaseModel):
    scenario: str = "full"
    thresholds: dict[str, dict[str, int]] = Field(default_factory=dict)


@lru_cache(maxsize=len(SCENARIOS))
def _events(scenario: str):
    events, stats = parse_pcap(build_sample_pcap(stages=SCENARIOS[scenario]["stages"]))
    return events, stats


def _overrides(thresholds: dict[str, dict[str, int]]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for det, params in thresholds.items():
        allowed = TUNABLES.get(det)
        if allowed is None:
            raise HTTPException(422, f"Unknown detector '{det[:40]}'")
        for key, value in params.items():
            if key not in allowed:
                raise HTTPException(422, f"Unknown threshold '{key[:40]}' for {det}")
            _, lo, hi, _ = allowed[key]
            out.setdefault(det, {})[key] = max(lo, min(hi, int(value)))
    return out


@router.get("/playground")
@limiter.limit("60/minute")
def options(request: Request) -> dict:
    return {
        "guest_access": get_settings().guest_access,
        "scenarios": [{"id": k, "label": v["label"], "blurb": v["blurb"]} for k, v in SCENARIOS.items()],
        "tunables": [{"detector": d, "params": [{"key": k, "default": v[0], "min": v[1], "max": v[2], "label": v[3]} for k, v in p.items()]} for d, p in TUNABLES.items()],
        "detectors": [{"name": n, "class": c.detection_class, "mitre": list(c.mitre), "about": ABOUT[n]} for n, c in sorted(registry().items()) if n in ABOUT],
    }


@router.post("/playground")
@limiter.limit("12/minute")
async def run(request: Request, body: PlaygroundRequest) -> dict:
    if body.scenario not in SCENARIOS:
        raise HTTPException(422, "Unknown scenario")
    overrides = {"DataExfiltrationDetector": {"min_bytes": TUNABLES["DataExfiltrationDetector"]["min_bytes"][0]}}
    for det, params in _overrides(body.thresholds).items():
        overrides.setdefault(det, {}).update(params)
    events, stats = await asyncio.to_thread(_events, body.scenario)
    result = await asyncio.to_thread(build_replay, events, overrides)
    result["ingest"] = {
        "packets": stats.packets, "flows": stats.flows, "events": len(events),
        "heuristics": "Synthetic traffic generated on the server; authentication outcomes are inferred from flow shape.",
    }
    return {"scenario": body.scenario, "result": result}

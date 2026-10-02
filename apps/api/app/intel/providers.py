"""Threat-intelligence adapters.

``ThreatIntelProvider`` is the seam for external feeds (commercial or open). None is implemented: the only
provider is the local indicator store, whose contents are whatever analysts add. Nothing is fetched from the
network and no indicator is invented. A future provider would read its credentials from environment variables
(never from code) and be registered in ``PROVIDERS``.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ThreatIndicator

Kind = Literal["ip", "domain", "hash", "url"]
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


class IndicatorError(ValueError):
    pass


def normalize(kind: str, value: str) -> str:
    """Validate and canonicalize an indicator so lookups and de-duplication are reliable."""
    v = value.strip()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise IndicatorError("not a valid IP address") from exc
    if kind == "domain":
        v = v.lower().rstrip(".")
        if not _DOMAIN.match(v):
            raise IndicatorError("not a valid domain name")
        return v
    if kind == "hash":
        v = v.lower()
        if len(v) not in _HASH_LEN or not re.fullmatch(r"[0-9a-f]+", v):
            raise IndicatorError("hash must be hex MD5, SHA-1 or SHA-256")
        return v
    if kind == "url":
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise IndicatorError("URL must be http(s) with a host")
        return v[:512]
    raise IndicatorError("unknown indicator kind")


@dataclass
class Hit:
    kind: str
    value: str
    source: str
    confidence: int
    description: str


class ThreatIntelProvider(Protocol):
    name: str

    def lookup(self, kind: str, value: str) -> list[Hit]: ...


class LocalStoreProvider:
    name = "local-store"

    def __init__(self, db: Session):
        self._db = db

    def lookup(self, kind: str, value: str) -> list[Hit]:
        try:
            v = normalize(kind, value)
        except IndicatorError:
            return []
        rows = self._db.scalars(select(ThreatIndicator).where(ThreatIndicator.kind == kind, ThreatIndicator.value == v)).all()
        return [Hit(r.kind, r.value, r.source, r.confidence, r.description) for r in rows]


def providers(db: Session) -> list[ThreatIntelProvider]:
    """Registered providers. Add external adapters here; each must read secrets from the environment."""
    return [LocalStoreProvider(db)]

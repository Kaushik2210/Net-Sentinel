"""Adapter interface for an optional language model.

Not implemented on purpose: NetSentinel ships with deterministic answers only. A provider would receive
the evidence package (and nothing else) and return an ``Answer``; the API passes every provider answer
through ``answers.validate`` and falls back to the deterministic answer if validation fails. No provider
name or key appears in the UI unless one is actually configured.
"""

from typing import Protocol

from app.analyst.answers import Answer
from app.analyst.evidence import DevicePackage, IncidentPackage


class AnalystProvider(Protocol):
    name: str

    def answer(self, question: str, package: IncidentPackage | DevicePackage) -> Answer: ...

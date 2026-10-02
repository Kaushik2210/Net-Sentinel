import logging
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator

from app.analyst.answers import DEVICE_QUESTIONS, INCIDENT_QUESTIONS, Answer, answer_device, answer_incident, validate
from app.analyst.evidence import build_device_package, build_incident_package
from app.core.deps import CurrentUser, DbSession
from app.schemas.common import ORM

router = APIRouter(prefix="/analyst", tags=["analyst"])
log = logging.getLogger("netsentinel.app")

Question = Literal[
    "explain", "what_changed", "timeline", "evidence", "next_steps", "related_events", "exfiltration", "report", "why_suspicious", "related_alerts",
]


class AskIn(BaseModel):
    question: Question
    incident_id: str | None = Field(default=None, max_length=40)
    device_id: str | None = Field(default=None, max_length=40)

    @model_validator(mode="after")
    def _one_target(self):
        if bool(self.incident_id) == bool(self.device_id):
            raise ValueError("provide exactly one of incident_id or device_id")
        allowed = INCIDENT_QUESTIONS if self.incident_id else DEVICE_QUESTIONS
        if self.question not in allowed:
            raise ValueError(f"question '{self.question}' is not available for this target")
        return self


class ClaimOut(ORM):
    text: str
    cites: list[str]


class AnswerOut(ORM):
    question: str
    mode: str
    insufficient: bool
    claims: list[ClaimOut]
    citations: list[str]
    notice: str = "Generated from stored NetSentinel evidence only. No language model was used."


def _out(a: Answer) -> AnswerOut:
    return AnswerOut(question=a.question, mode=a.mode, insufficient=a.insufficient, claims=[ClaimOut(text=c.text, cites=c.cites) for c in a.claims], citations=a.citations)


@router.get("/questions")
def questions(_: CurrentUser) -> dict:
    return {"incident": list(INCIDENT_QUESTIONS), "device": list(DEVICE_QUESTIONS)}


@router.post("/ask", response_model=AnswerOut)
def ask(body: AskIn, _: CurrentUser, db: DbSession):
    if body.incident_id:
        pkg = build_incident_package(db, body.incident_id)
        if pkg is None:
            raise HTTPException(404, "Incident not found")
        answer = answer_incident(body.question, pkg)
    else:
        pkg = build_device_package(db, body.device_id or "")
        if pkg is None:
            raise HTTPException(404, "Device not found")
        answer = answer_device(body.question, pkg)
    # Safety net: an answer may only cite identifiers that exist in the evidence package.
    try:
        validate(answer, pkg.ids)
    except ValueError:
        log.exception("analyst answer failed citation validation")
        raise HTTPException(500, "Answer rejected: it cited evidence that does not exist") from None
    return _out(answer)

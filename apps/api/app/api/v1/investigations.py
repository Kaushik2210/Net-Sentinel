from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.deps import Analyst, CurrentUser, DbSession, client_ip
from app.models import AuditLog, Incident, InvestigationNote, User
from app.schemas.common import ORM, UTCDatetime
from app.services import audit

router = APIRouter(prefix="/investigations", tags=["investigations"])

Status = Literal["open", "investigating", "resolved", "false_positive", "escalated"]


class NoteIn(BaseModel):
    body: Annotated[str, Field(min_length=1, max_length=4000)]


class NoteOut(ORM):
    id: str
    author: str
    body: str
    created_at: UTCDatetime


class AuditOut(ORM):
    ts: UTCDatetime
    actor: str
    action: str
    detail: dict


class AnalystOut(ORM):
    username: str
    display_name: str
    role: str


class WorkflowPatch(BaseModel):
    status: Status | None = None
    # Present-with-null means "unassign"; absent means "leave unchanged".
    assignee: Annotated[str | None, Field(max_length=48)] = None


def _incident(db, incident_id: str) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found")
    return inc


@router.get("/analysts", response_model=list[AnalystOut])
def analysts(_: CurrentUser, db: DbSession):
    rows = db.scalars(select(User).where(User.is_active, User.role.in_(["ANALYST", "ADMIN"])).order_by(User.username)).all()
    return [AnalystOut(username=u.username, display_name=u.display_name, role=u.role) for u in rows]


@router.get("/{incident_id}/notes", response_model=list[NoteOut])
def list_notes(incident_id: str, _: CurrentUser, db: DbSession):
    _incident(db, incident_id)
    rows = db.execute(
        select(InvestigationNote, User.username).join(User, User.id == InvestigationNote.author_id)
        .where(InvestigationNote.incident_id == incident_id).order_by(InvestigationNote.created_at.desc())
    ).all()
    return [NoteOut(id=n.id, author=name, body=n.body, created_at=n.created_at) for n, name in rows]


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=201)
def add_note(incident_id: str, body: NoteIn, request: Request, user: Analyst, db: DbSession):
    _incident(db, incident_id)
    note = InvestigationNote(incident_id=incident_id, author_id=user.id, body=body.body.strip())
    db.add(note)
    db.commit()
    audit.record(db, user.username, "incident.note", incident_id, client_ip(request), note_id=note.id, length=len(note.body))
    return NoteOut(id=note.id, author=user.username, body=note.body, created_at=note.created_at)


@router.patch("/{incident_id}")
def update_workflow(incident_id: str, patch: WorkflowPatch, request: Request, user: Analyst, db: DbSession) -> dict:
    inc = _incident(db, incident_id)
    ip = client_ip(request)
    if patch.status is not None and patch.status != inc.status:
        old, inc.status = inc.status, patch.status
        db.commit()
        audit.record(db, user.username, "incident.status", incident_id, ip, **{"from": old, "to": patch.status})
    if "assignee" in patch.model_fields_set:
        new = None
        if patch.assignee:
            new = db.scalar(select(User).where(User.username == patch.assignee, User.is_active))
            if new is None or new.role == "VIEWER":
                raise HTTPException(422, "Assignee must be an active analyst or admin")
        old_id = inc.assignee_id
        inc.assignee_id = new.id if new else None
        db.commit()
        if old_id != inc.assignee_id:
            audit.record(db, user.username, "incident.assign", incident_id, ip, assignee=new.username if new else None)
    assignee = db.get(User, inc.assignee_id).username if inc.assignee_id else None
    return {"id": inc.id, "status": inc.status, "assignee": assignee}


@router.get("/{incident_id}/audit", response_model=list[AuditOut])
def audit_trail(incident_id: str, _: CurrentUser, db: DbSession):
    _incident(db, incident_id)
    rows = db.scalars(
        select(AuditLog).where(AuditLog.target == incident_id, AuditLog.action.like("incident.%")).order_by(AuditLog.ts.desc()).limit(200)
    ).all()
    return [AuditOut(ts=r.ts, actor=r.actor, action=r.action, detail=r.detail or {}) for r in rows]

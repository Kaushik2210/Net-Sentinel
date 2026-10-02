import logging

from sqlalchemy.orm import Session

from app.models import AuditLog

_log = logging.getLogger("netsentinel.audit")


def record(db: Session, actor: str, action: str, target: str = "", ip: str = "", **detail) -> None:
    """Persist an audit entry and mirror it to the audit logger (never raises into callers)."""
    try:
        db.add(AuditLog(actor=actor, action=action, target=target, ip=ip, detail=detail))
        db.commit()
    except Exception:  # pragma: no cover - audit failure must not break the request path
        db.rollback()
        _log.exception("failed to persist audit entry %s", action)
    _log.info("actor=%s action=%s target=%s ip=%s", actor, action, target, ip)

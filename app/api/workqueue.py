"""Work-queue route: what is waiting on a human, for the caller's org."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_authenticated_org
from app.db.models import Org
from app.db.session import get_db
from app.schemas import WorkQueueOut
from app.services.workqueue import build_workqueue

router = APIRouter(prefix="/v1/workqueue", tags=["workqueue"])


@router.get("", response_model=WorkQueueOut)
def get_workqueue(
    org: Org = Depends(get_authenticated_org),
    db: Session = Depends(get_db),
) -> WorkQueueOut:
    """Pending approvals (with the decision they gate), flags still awaiting
    a fix, and verified rewrites needing a human's confirmation."""
    return WorkQueueOut(**build_workqueue(db, org.id))

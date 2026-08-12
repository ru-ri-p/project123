"""One-shot production diagnosis, for the Render shell.

Every authenticated route (/v1/gate, /v1/event, /v1/traces) does exactly three
things before it looks at your key: open a database session, hash the key, query
Org. Only the first of those can fail, so a 500 on an INVALID key is a database
problem by elimination. This says which one, and whether the pilot key is even
right, in a single run.

    python scripts/diagnose_prod.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

TRADEEASY_ORG = os.environ.get("PILOT_ORG", "org_tradeeasy_ck")
# Never defaulted in code — an API key is a credential and this file is
# committed. Pass it for the run only:  PILOT_KEY=... python scripts/diagnose_prod.py
TRADEEASY_KEY = os.environ.get("PILOT_KEY")


def main() -> int:
    print("=" * 62)

    # 1. Can this process reach the database at all?
    try:
        from sqlalchemy import text

        from app.db.session import engine

        with engine.connect() as c:
            c.execute(text("select 1"))
        print("database reachable   : YES")
    except Exception as exc:
        print("database reachable   : NO")
        print(f"  {type(exc).__name__}: {str(exc)[:300]}")
        print()
        print("VERDICT: the database is unreachable from this process. Every")
        print("authenticated route will 500 before it validates a key, while")
        print("/health keeps answering 200 because it never touches the database.")
        print("Check attest-db in the Render dashboard. If it is up, the web")
        print("service is holding a stale connection string or an exhausted pool")
        print("— restart attest-api.")
        return 1

    # 2. Which schema version is live?
    from sqlalchemy import text

    from app.db.session import SessionLocal, engine

    with engine.connect() as c:
        version = c.execute(text("select version_num from alembic_version")).scalar()
    print(f"alembic version      : {version}")

    # 3. Is the data there?
    from app.auth import resolve_org
    from app.db.models import Event, Org

    db = SessionLocal()
    try:
        orgs = db.query(Org).count()
        events = db.query(Event).count()
        print(f"orgs / events        : {orgs} / {events}")

        org = db.query(Org).filter(Org.id == TRADEEASY_ORG).one_or_none()
        print(f"{TRADEEASY_ORG:<21}: {'present' if org else 'MISSING'}")

        # Does the pilot key actually resolve? Never prints the key itself.
        if not TRADEEASY_KEY:
            resolved = None
            print("pilot key resolves   : not checked (set PILOT_KEY to test one)")
        else:
            resolved = resolve_org(db, TRADEEASY_KEY)
            if resolved is None:
                print("pilot key resolves   : NO — the key does not match any org")
            else:
                print(f"pilot key resolves   : YES -> {resolved.id}")
                print(f"  requires_profile   : {resolved.requires_profile}")
    finally:
        db.close()

    print()
    if orgs == 0:
        print("VERDICT: the database is reachable but EMPTY. This is a different")
        print("database from the one the pilot was set up in — most likely it was")
        print("recreated, which issues a new connection string. Data from before")
        print("is in the old instance, if it still exists.")
        return 1

    if TRADEEASY_KEY and resolved is None:
        print("VERDICT: database fine, but that key matches no org. Rotate the")
        print("org's key and send the new one, or re-create the org with it.")
        return 1

    print("VERDICT: database, schema and the pilot key are all fine FROM THIS")
    print("SHELL. If the web service still 500s, it is that process specifically")
    print("— a stale connection string or an exhausted pool. Restart attest-api.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

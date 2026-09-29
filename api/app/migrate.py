"""Idempotent, additive schema upkeep for existing databases.

`Base.metadata.create_all` only creates missing tables; on a table that already exists it adds neither new
columns nor new indexes. `upgrade()` runs right after every `create_all` (hooked in db.py) and:
  * adds columns declared on a model but missing from the table (nullable / server-default only),
  * creates indexes declared on a model but missing from the database,
  * on SQLite, maintains `research_fts`, an FTS5 trigram index over research id + search_text kept in sync by
    triggers, so global search does not scan the wide `research` rows (which carry the full record JSON),
  * encrypts legacy plaintext secrets in the `setting` table.
There is no Alembic in this build; anything beyond additive changes needs a real migration.
"""

from __future__ import annotations

import logging

from sqlalchemy import MetaData, inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

log = logging.getLogger("threatlens.migrate")


def _add_missing_columns(conn: Connection, metadata: MetaData) -> list[str]:
    insp = inspect(conn)
    added = []
    existing_tables = set(insp.get_table_names())
    for table in metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            ddl_type = col.type.compile(dialect=conn.dialect)
            default = ""
            if col.server_default is not None and hasattr(col.server_default, "arg"):
                arg = col.server_default.arg
                default = f" DEFAULT {arg.text if hasattr(arg, 'text') else repr(arg)}"
            q = conn.dialect.identifier_preparer
            conn.execute(text(f"ALTER TABLE {q.quote(table.name)} ADD COLUMN {q.quote(col.name)} {ddl_type}{default}"))
            added.append(f"{table.name}.{col.name}")
    return added


def _create_missing_indexes(conn: Connection, metadata: MetaData) -> list[str]:
    insp = inspect(conn)
    existing_tables = set(insp.get_table_names())
    made = []
    for table in metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        have = {i["name"] for i in insp.get_indexes(table.name)}
        for idx in table.indexes:
            if idx.name and idx.name not in have:
                idx.create(conn, checkfirst=True)
                made.append(idx.name)
    return made


FTS_TABLE = "research_fts"
_FTS_DDL = [
    f"CREATE VIRTUAL TABLE {FTS_TABLE} USING fts5(id, search_text, content='research', content_rowid='rowid', "
    "tokenize='trigram')",
    f"CREATE TRIGGER IF NOT EXISTS research_fts_ai AFTER INSERT ON research BEGIN "
    f"INSERT INTO {FTS_TABLE}(rowid, id, search_text) VALUES (new.rowid, new.id, new.search_text); END",
    f"CREATE TRIGGER IF NOT EXISTS research_fts_ad AFTER DELETE ON research BEGIN "
    f"INSERT INTO {FTS_TABLE}({FTS_TABLE}, rowid, id, search_text) VALUES ('delete', old.rowid, old.id, old.search_text); END",
    f"CREATE TRIGGER IF NOT EXISTS research_fts_au AFTER UPDATE OF id, search_text ON research BEGIN "
    f"INSERT INTO {FTS_TABLE}({FTS_TABLE}, rowid, id, search_text) VALUES ('delete', old.rowid, old.id, old.search_text); "
    f"INSERT INTO {FTS_TABLE}(rowid, id, search_text) VALUES (new.rowid, new.id, new.search_text); END",
]
_fts_ok: dict[str, bool] = {}


def _ensure_research_fts(conn: Connection) -> bool:
    if conn.dialect.name != "sqlite":
        return False
    try:
        exists = conn.execute(text("SELECT 1 FROM sqlite_master WHERE name = :n"), {"n": FTS_TABLE}).first()
        if not exists:
            for ddl in _FTS_DDL:
                conn.execute(text(ddl))
            conn.execute(text(f"INSERT INTO {FTS_TABLE}({FTS_TABLE}) VALUES ('rebuild')"))
            log.info("Built %s (trigram full-text index for global search)", FTS_TABLE)
        else:
            for ddl in _FTS_DDL[1:]:
                conn.execute(text(ddl))
        return True
    except Exception:  # noqa: BLE001 - SQLite without FTS5/trigram: search falls back to LIKE
        log.warning("SQLite FTS5 trigram unavailable; global search will use LIKE scans", exc_info=True)
        return False


def research_fts_available(conn_or_session) -> bool:
    """True when `research_fts` exists on this database (SQLite with FTS5 trigram)."""
    bind = conn_or_session.get_bind() if hasattr(conn_or_session, "get_bind") else conn_or_session.engine
    key = str(bind.url)
    if key not in _fts_ok:
        if bind.dialect.name != "sqlite":
            _fts_ok[key] = False
        else:
            _fts_ok[key] = conn_or_session.execute(
                text("SELECT 1 FROM sqlite_master WHERE name = :n"), {"n": FTS_TABLE}).first() is not None
    return _fts_ok[key]


def upgrade(conn: Connection, metadata: MetaData) -> None:
    cols = _add_missing_columns(conn, metadata)
    idx = _create_missing_indexes(conn, metadata)
    if "research" in inspect(conn).get_table_names():
        _fts_ok[str(conn.engine.url)] = _ensure_research_fts(conn)
    if cols or idx:
        log.info("Schema upgrade: added columns %s; created indexes %s", cols or "-", idx or "-")
    try:
        from . import secrets
        with Session(bind=conn) as db:
            secrets.migrate_plaintext(db)
    except Exception:  # noqa: BLE001 - never block startup on this
        log.exception("Could not encrypt legacy plaintext secrets")

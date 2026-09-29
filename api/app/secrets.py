"""Secrets at rest (spec section 13: "secrets (OSINT keys) in a vault").

Values kept in the `setting` table are Fernet-encrypted and stored as `enc:v1:<token>`. The key comes from
env `THREATLENS_SECRET_KEY` (any string; non-Fernet strings are stretched with SHA-256), else from
`<data_dir>/.secret_key`, which is generated on first use with a warning. Plaintext values written by older
builds are encrypted in place at startup (`migrate_plaintext`) and on first read.

The API never returns a stored key: callers get `mask()` plus a `configured` flag.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import threading

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .config import get_settings

log = logging.getLogger("threatlens.secrets")

PREFIX = "enc:v1:"
OSINT_SETTING = "osint_keys"

_lock = threading.Lock()
_fernet: Fernet | None = None


def _load_key() -> bytes:
    s = get_settings()
    raw = (s.threatlens_secret_key or os.environ.get("THREATLENS_SECRET_KEY", "")).strip()
    if not raw:
        path = s.data_dir / ".secret_key"
        if path.exists():
            raw = path.read_text(encoding="utf-8").strip()
        else:
            new = Fernet.generate_key().decode()
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(new)
                log.warning("THREATLENS_SECRET_KEY is not set; generated a local key at %s. Back it up (losing it makes "
                            "stored OSINT keys unreadable) or set THREATLENS_SECRET_KEY / use a vault in production.", path)
            except FileExistsError:  # another worker won the race
                pass
            raw = path.read_text(encoding="utf-8").strip()
    try:
        Fernet(raw.encode())
        return raw.encode()
    except (ValueError, TypeError):
        return base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())


def fernet() -> Fernet:
    global _fernet
    with _lock:
        if _fernet is None:
            _fernet = Fernet(_load_key())
        return _fernet


def reset() -> None:
    """Forget the cached key (tests, key rotation)."""
    global _fernet
    with _lock:
        _fernet = None


def is_encrypted(v: str | None) -> bool:
    return isinstance(v, str) and v.startswith(PREFIX)


def encrypt(plain: str) -> str:
    return PREFIX + fernet().encrypt(plain.encode()).decode()


def decrypt(v: str | None) -> str:
    """Decrypt a stored value. Plaintext (legacy) passes through; an undecryptable value yields ''."""
    if not v:
        return ""
    if not is_encrypted(v):
        return v
    try:
        return fernet().decrypt(v[len(PREFIX):].encode()).decode()
    except InvalidToken:
        log.error("A stored secret could not be decrypted with the current key (was THREATLENS_SECRET_KEY changed?). "
                  "Treating it as not configured; re-enter it in Settings.")
        return ""


def mask(v: str | None) -> str:
    if not v:
        return ""
    return "••••" + (v[-4:] if len(v) >= 12 else "")


# ------------------------------------------------------------------ OSINT keys

def _provider_env() -> dict[str, str]:
    from .osint import PROVIDERS
    return {p["id"]: p["env"] for p in PROVIDERS}


def stored_osint_keys(db: Session) -> dict[str, str]:
    """Decrypted keys saved in Settings (not env). Encrypts any legacy plaintext values it finds."""
    from .models import Setting
    row = db.get(Setting, OSINT_SETTING)
    val = dict((row.value if row else None) or {})
    if any(v and not is_encrypted(v) for v in val.values()):
        row.value = {k: (v if is_encrypted(v) or not v else encrypt(v)) for k, v in val.items()}
        db.commit()
    return {k: d for k, v in val.items() if (d := decrypt(v))}


def set_osint_keys(db: Session, changes: dict[str, str | None]) -> None:
    from .models import Setting
    allowed = _provider_env()
    row = db.get(Setting, OSINT_SETTING) or Setting(key=OSINT_SETTING, value={})
    val = dict(row.value or {})
    for k, v in changes.items():
        if k not in allowed:
            continue
        if v and v.strip():
            val[k] = encrypt(v.strip())
        else:
            val.pop(k, None)
    row.value = val
    db.merge(row)
    db.commit()


def get_osint_keys(db: Session) -> dict[str, str]:
    """Drop-in for `osint.get_keys`: provider id -> usable key (Settings first, then env)."""
    s = get_settings()
    stored = stored_osint_keys(db)
    return {pid: stored.get(pid) or getattr(s, env, "") for pid, env in _provider_env().items()}


def get_secret(name: str, db: Session | None = None) -> str:
    """One OSINT provider key by id (e.g. 'virustotal'), Settings first then env."""
    from .db import SessionLocal
    if db is not None:
        return get_osint_keys(db).get(name, "")
    with SessionLocal() as own:
        return get_osint_keys(own).get(name, "")


def migrate_plaintext(db: Session) -> int:
    """Encrypt legacy plaintext OSINT keys in place. Returns how many were converted."""
    from .models import Setting
    row = db.get(Setting, OSINT_SETTING)
    if row is None or not row.value:
        return 0
    n = sum(1 for v in row.value.values() if v and not is_encrypted(v))
    if n:
        stored_osint_keys(db)
        log.info("Encrypted %d plaintext OSINT key(s) at rest.", n)
    return n


def install() -> None:
    """Route `osint.get_keys` (used by the pipeline and the library re-enrich endpoint) through decryption until
    osint.py calls `get_osint_keys` itself. Safe to call more than once."""
    from . import osint
    osint.get_keys = get_osint_keys

"""CVE enrichment and validation (spec section 5 `vulnerabilities[]`, section 12 deterministic post-checks).

Sources, all public reference data; only CVE ids are ever sent (never client names or record content):
- NVD CVE API 2.0: CVSS base score/vector/severity, description, affected CPEs, analysis status.
- CISA Known Exploited Vulnerabilities catalogue (one JSON feed): dateAdded, dueDate, requiredAction,
  knownRansomwareCampaignUse.
- FIRST EPSS API: exploitation probability and percentile.

Responses are cached in `external_cache` for `cve_cache_hours` (24 h). A network failure never fails a caller:
a stale cache entry is used if there is one, otherwise the existing values on the vulnerability are kept and the
field is reported as unavailable.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx
from sqlalchemy.orm import Session

from .config import get_settings
from .db import SessionLocal
from .models import ExternalCache, Vulnerability

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MAX_CVES = 30          # per enrichment call
MAX_CPES = 40          # kept per CVE
USER_AGENT = "ThreatLens/1.0 (CVE enrichment)"

# NVD allows 5 requests / 30 s without a key and 50 / 30 s with one.
NVD_INTERVAL = {"anonymous": 6.2, "key": 0.7}
_nvd_lock = threading.Lock()
_nvd_last = [0.0]
_kev_mem: dict = {"at": None, "data": None}

LogF = Callable[..., None]


class Unavailable(Exception):
    """The upstream service could not be reached or returned an error."""


def now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def normalize_cve(cve: str) -> str:
    return (cve or "").strip().upper().replace("‑", "-").replace("–", "-")


def valid_format(cve: str) -> bool:
    return bool(CVE_RE.match(normalize_cve(cve)))


# ------------------------------------------------------------------ cache

def _cache_get(db: Session, key: str) -> tuple[dict | None, bool]:
    """Returns (value, fresh)."""
    row = db.get(ExternalCache, key)
    if row is None:
        return None, False
    ttl = timedelta(hours=get_settings().cve_cache_hours)
    return row.value, (now() - _aware(row.fetched_at)) < ttl


def _cache_put(db: Session, key: str, value: dict) -> None:
    row = db.get(ExternalCache, key)
    if row is None:
        db.add(ExternalCache(key=key, value=value, fetched_at=now()))
    else:
        row.value = value
        row.fetched_at = now()
    db.flush()


# ------------------------------------------------------------------ HTTP

def _client() -> httpx.Client:
    return httpx.Client(timeout=get_settings().enrichment_timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


def _get_json(client: httpx.Client, url: str, **kw) -> dict:
    try:
        r = client.get(url, **kw)
    except httpx.HTTPError as e:
        raise Unavailable(f"{type(e).__name__}: {e}") from e
    if r.status_code != 200:
        raise Unavailable(f"HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError as e:
        raise Unavailable("invalid JSON") from e


def _nvd_throttle() -> None:
    interval = NVD_INTERVAL["key" if get_settings().nvd_api_key else "anonymous"]
    with _nvd_lock:
        wait = interval - (time.monotonic() - _nvd_last[0])
        if wait > 0:
            time.sleep(wait)
        _nvd_last[0] = time.monotonic()


# ------------------------------------------------------------------ parsers

def _cpe_product(criteria: str) -> str:
    """cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:enterprise:*:*:* -> 'Microsoft SharePoint Server 2016 enterprise'."""
    parts = criteria.split(":")
    if len(parts) < 6:
        return criteria
    vendor, product, version = parts[3], parts[4], parts[5]
    sw_edition = parts[9] if len(parts) > 9 else "*"
    words = [vendor.replace("_", " ").title(), product.replace("_", " ").title()]
    if version not in ("*", "-", ""):
        words.append(version)
    if sw_edition not in ("*", "-", ""):
        words.append(sw_edition.replace("_", " "))
    name = " ".join(words)
    return name.replace("Microsoft Sharepoint", "Microsoft SharePoint")


def parse_nvd(data: dict) -> dict:
    """Reduce an NVD 2.0 response for one CVE to the fields ThreatLens keeps. `exists` False if NVD has no such CVE."""
    items = data.get("vulnerabilities") or []
    if not items:
        return {"exists": False}
    c = items[0].get("cve") or {}
    desc = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = c.get("metrics") or {}
    best = None
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            best = next((m for m in rows if m.get("type") == "Primary"), rows[0])
            break
    cvss = None
    if best:
        d = best.get("cvssData") or {}
        cvss = {"score": d.get("baseScore"), "vector": d.get("vectorString"), "version": d.get("version"),
                "severity": d.get("baseSeverity") or best.get("baseSeverity"), "source": best.get("source")}
    cpes: list[dict] = []
    for conf in c.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                row = {"criteria": m.get("criteria", "")}
                for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
                    if m.get(k):
                        row[k] = m[k]
                if row not in cpes:
                    cpes.append(row)
    return {"exists": True, "id": c.get("id"), "status": c.get("vulnStatus"), "published": c.get("published"),
            "last_modified": c.get("lastModified"), "description": desc, "cvss": cvss, "cpes": cpes[:MAX_CPES],
            "cwes": sorted({d.get("value") for w in c.get("weaknesses") or [] for d in w.get("description") or []
                            if str(d.get("value", "")).startswith("CWE-")})}


def parse_kev(data: dict) -> dict:
    out = {}
    for v in data.get("vulnerabilities") or []:
        cid = normalize_cve(v.get("cveID", ""))
        if cid:
            out[cid] = {"date_added": v.get("dateAdded"), "due_date": v.get("dueDate"), "required_action": v.get("requiredAction"),
                        "ransomware": v.get("knownRansomwareCampaignUse"), "name": v.get("vulnerabilityName"),
                        "vendor": v.get("vendorProject"), "product": v.get("product")}
    return {"catalog_version": data.get("catalogVersion"), "released": data.get("dateReleased"), "items": out}


def parse_epss(data: dict) -> dict:
    out = {}
    for row in data.get("data") or []:
        cid = normalize_cve(row.get("cve", ""))
        try:
            out[cid] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date")}
        except (KeyError, TypeError, ValueError):
            continue
    return out


# ------------------------------------------------------------------ fetchers (cache first)

def nvd_lookup(db: Session, cve: str, client: httpx.Client) -> tuple[dict | None, str]:
    """Returns (parsed NVD entry or None, status) with status live | cache | stale | unavailable."""
    key = f"nvd:{cve}"
    cached, fresh = _cache_get(db, key)
    if cached is not None and fresh:
        return cached, "cache"
    headers = {"apiKey": get_settings().nvd_api_key} if get_settings().nvd_api_key else {}
    try:
        _nvd_throttle()
        parsed = parse_nvd(_get_json(client, NVD_URL, params={"cveId": cve}, headers=headers))
    except Unavailable as e:
        log.warning("NVD lookup for %s failed: %s", cve, e)
        return (cached, "stale") if cached is not None else (None, "unavailable")
    _cache_put(db, key, parsed)
    return parsed, "live"


def kev_catalog(db: Session, client: httpx.Client) -> tuple[dict | None, str]:
    ttl = timedelta(hours=get_settings().cve_cache_hours)
    if _kev_mem["data"] is not None and now() - _kev_mem["at"] < ttl:
        return _kev_mem["data"], "cache"
    cached, fresh = _cache_get(db, "kev:catalog")
    if cached is not None and fresh:
        row = db.get(ExternalCache, "kev:catalog")
        _kev_mem.update(at=_aware(row.fetched_at), data=cached)
        return cached, "cache"
    try:
        parsed = parse_kev(_get_json(client, KEV_URL))
    except Unavailable as e:
        log.warning("CISA KEV feed fetch failed: %s", e)
        return (cached, "stale") if cached is not None else (None, "unavailable")
    if not parsed["items"]:
        log.warning("CISA KEV feed returned no entries; ignoring it")
        return (cached, "stale") if cached is not None else (None, "unavailable")
    _cache_put(db, "kev:catalog", parsed)
    _kev_mem.update(at=now(), data=parsed)
    return parsed, "live"


def epss_lookup(db: Session, cves: list[str], client: httpx.Client) -> tuple[dict[str, dict | None], str]:
    """Returns ({cve: {epss, percentile, date} | None}, status). None means FIRST has no score for it (yet)."""
    out: dict[str, dict | None] = {}
    stale: dict[str, dict | None] = {}
    todo = []
    for c in cves:
        cached, fresh = _cache_get(db, f"epss:{c}")
        if cached is not None and fresh:
            out[c] = cached.get("score")
        else:
            todo.append(c)
            if cached is not None:
                stale[c] = cached.get("score")
    if not todo:
        return out, "cache"
    try:
        parsed = parse_epss(_get_json(client, EPSS_URL, params={"cve": ",".join(todo)}))
    except Unavailable as e:
        log.warning("EPSS lookup failed: %s", e)
        for c in todo:
            if c in stale:
                out[c] = stale[c]
        return out, "stale" if stale else "unavailable"
    for c in todo:
        out[c] = parsed.get(c)
        _cache_put(db, f"epss:{c}", {"score": parsed.get(c)})
    return out, "live"


# ------------------------------------------------------------------ enrichment

def _merge(v: dict, nvd: dict | None, kev: dict | None, kev_ok: bool, epss: dict | None, epss_ok: bool) -> dict:
    v = dict(v)
    if nvd is not None:
        if not nvd.get("exists"):
            v["validation"] = "not_found"
        else:
            v["validation"] = "rejected" if (nvd.get("status") or "").lower() == "rejected" else "verified"
            v["nvd_status"] = nvd.get("status")
            v["published"] = nvd.get("published")
            cv = nvd.get("cvss") or {}
            if cv.get("score") is not None:
                v["cvss"] = float(cv["score"])
                v["cvss_vector"] = cv.get("vector")
                v["cvss_version"] = cv.get("version")
                v["cvss_severity"] = (cv.get("severity") or "").lower() or None
                v["cvss_source"] = cv.get("source")
            if nvd.get("description"):
                v["description"] = nvd["description"]
            if nvd.get("cwes"):
                v["cwes"] = nvd["cwes"]
            cpes = nvd.get("cpes") or []
            if cpes:
                v["affected_cpes"] = cpes
                if not v.get("affected_products"):
                    v["affected_products"] = list(dict.fromkeys(_cpe_product(c["criteria"]) for c in cpes))[:15]
    if kev_ok:
        v["kev_added"] = (kev or {}).get("date_added")
        v["kev_due_date"] = (kev or {}).get("due_date")
        v["kev_required_action"] = (kev or {}).get("required_action")
        v["kev_ransomware"] = (kev or {}).get("ransomware")
    else:
        v.setdefault("kev_added", None)
    if epss_ok:
        v["epss"] = (epss or {}).get("epss")
        v["epss_percentile"] = (epss or {}).get("percentile")
        v["epss_date"] = (epss or {}).get("date")
    else:
        v.setdefault("epss", None)
    return v


def enrich(vulns: list[dict], db: Session | None = None, client: httpx.Client | None = None,
           logf: LogF | None = None) -> tuple[list[dict], dict]:
    """Return (enriched copies of `vulns`, summary). Never raises for network problems.

    Adds to each vulnerability: cvss, cvss_vector, cvss_version, cvss_severity, description, affected_cpes, cwes,
    nvd_status, published, kev_added, kev_due_date, kev_required_action, kev_ransomware, epss, epss_percentile,
    epss_date, validation (verified | not_found | rejected | invalid_format | unchecked) and enrichment
    ({checked_at, nvd, kev, epss} statuses).
    """
    logf = logf or (lambda m, level="info": None)
    summary = {"checked": 0, "enriched": 0, "not_found": [], "invalid": [], "rejected": [],
               "sources": {"nvd": "skipped", "kev": "skipped", "epss": "skipped"}}
    out = [dict(v, cve=normalize_cve(v.get("cve", ""))) for v in vulns]
    if not out or not get_settings().cve_enrichment:
        return out, summary
    own_db = db is None
    db = db or SessionLocal()
    own_client = client is None
    client = client or _client()
    try:
        cves = list(dict.fromkeys(v["cve"] for v in out if valid_format(v["cve"])))[:MAX_CVES]
        kev, kev_st = kev_catalog(db, client)
        epss, epss_st = epss_lookup(db, cves, client) if cves else ({}, "skipped")
        nvd_rows: dict[str, dict | None] = {}
        nvd_by: dict[str, str] = {}
        for c in cves:
            nvd_rows[c], st = nvd_lookup(db, c, client)
            nvd_by[c] = st
        nvd_states = list(nvd_by.values())
        nvd_st = ("unavailable" if all(s == "unavailable" for s in nvd_states) else
                  "partial" if "unavailable" in nvd_states else
                  "live" if "live" in nvd_states else "stale" if "stale" in nvd_states else "cache") if nvd_states else "skipped"
        summary["sources"] = {"nvd": nvd_st, "kev": kev_st, "epss": epss_st}
        checked_at = now().isoformat()
        kev_items = (kev or {}).get("items", {})
        for i, v in enumerate(out):
            c = v["cve"]
            if not valid_format(c):
                out[i] = {**v, "validation": "invalid_format"}
                summary["invalid"].append(c)
                continue
            if c not in nvd_rows:  # over MAX_CVES
                out[i] = {**v, "validation": v.get("validation") or "unchecked"}
                continue
            summary["checked"] += 1
            nvd = nvd_rows[c]
            ep_known = epss_st != "unavailable" and c in epss
            nv = _merge(v, nvd, kev_items.get(c), kev is not None, epss.get(c), ep_known)
            if nvd is None:
                nv["validation"] = v.get("validation") or "unchecked"
            nv["enrichment"] = {"checked_at": checked_at, "nvd": nvd_by[c],
                                "kev": kev_st, "epss": epss_st if ep_known else "unavailable"}
            if nv["validation"] == "not_found":
                summary["not_found"].append(c)
            elif nv["validation"] == "rejected":
                summary["rejected"].append(c)
            if nvd is not None or kev is not None or ep_known:
                summary["enriched"] += 1
            out[i] = nv
        db.commit()
    except Exception as e:  # noqa: BLE001 - enrichment must never break a run or a request
        log.warning("CVE enrichment failed: %s", e, exc_info=True)
        db.rollback()
        summary["error"] = str(e)[:200]
        logf(f"CVE enrichment failed ({type(e).__name__}); keeping existing values", "warn")
        return [dict(v, cve=normalize_cve(v.get("cve", ""))) for v in vulns], summary
    finally:
        if own_client:
            client.close()
        if own_db:
            db.close()

    down = [k.upper() for k, s in summary["sources"].items() if s == "unavailable"]
    if down:
        logf(f"CVE enrichment: {', '.join(down)} unavailable; kept existing values", "warn")
    for c in summary["invalid"]:
        logf(f"{c} is not a valid CVE id", "warn")
    for c in summary["not_found"]:
        logf(f"{c} was not found in NVD; check the id against the sources", "warn")
    for c in summary["rejected"]:
        logf(f"{c} is REJECTED in NVD", "warn")
    if summary["checked"]:
        kev_n = sum(1 for v in out if v.get("kev_added"))
        logf(f"CVE enrichment: {summary['checked']} checked (NVD {summary['sources']['nvd']}, KEV {summary['sources']['kev']}, "
             f"EPSS {summary['sources']['epss']}); {kev_n} in CISA KEV")
    return out, summary


def update_library(db: Session, vulns: list[dict]) -> None:
    """Copy enrichment onto the shared `vulnerability` library rows (sync_library only copies cvss/epss/kev/products)."""
    for v in vulns:
        if not v.get("enrichment"):
            continue
        row = db.get(Vulnerability, v.get("cve"))
        if row is None:
            continue
        if v.get("cvss") is not None:
            row.cvss = v["cvss"]
        if v.get("epss") is not None:
            row.epss = v["epss"]
        if v.get("kev_added"):
            row.kev_added = v["kev_added"]
        if v.get("description"):
            row.description = v["description"]

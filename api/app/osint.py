"""OSINT enrichment and verdict logic (spec section 9).

Providers are enabled by API key (env or Settings > OSINT API keys). abuse.ch lookups
need an Auth-Key too. Only public indicators are ever sent; client names never are.
Results are cached on the Ioc row for 24 hours.
"""

from __future__ import annotations

import base64
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Setting

log = logging.getLogger(__name__)

PROVIDERS = [
    {"id": "virustotal", "name": "VirusTotal", "types": ["sha256", "sha1", "md5", "ipv4", "domain", "url"], "env": "virustotal_api_key"},
    {"id": "abuseipdb", "name": "AbuseIPDB", "types": ["ipv4", "ipv6"], "env": "abuseipdb_api_key"},
    {"id": "greynoise", "name": "GreyNoise", "types": ["ipv4"], "env": "greynoise_api_key"},
    {"id": "abusech", "name": "URLhaus / ThreatFox / MalwareBazaar", "types": ["url", "domain", "sha256", "md5", "ipv4"], "env": "abusech_auth_key"},
    {"id": "shodan", "name": "Shodan", "types": ["ipv4"], "env": "shodan_api_key"},
    {"id": "otx", "name": "AlienVault OTX", "types": ["ipv4", "domain", "url", "sha256", "md5", "sha1"], "env": "otx_api_key"},
    {"id": "urlscan", "name": "urlscan.io", "types": ["url", "domain"], "env": "urlscan_api_key"},
]
CACHE_TTL = timedelta(hours=24)

# ---------- expiry (spec 9: "Expired: infrastructure IoC older than a configurable age") ----------
# Age in days per IoC type, counted from the indicator's *intel* first-seen (earliest vendor source publication date,
# or the earliest first-seen an OSINT provider reports), never from when ThreatLens stored it. None = never expires.
# Editable in Settings > OSINT (Setting "ioc_expiry_days"). Types not listed never expire.
EXPIRY_DEFAULTS: dict[str, int | None] = {"ipv4": 90, "ipv6": 90, "domain": 180, "url": 90, "sha256": None, "sha1": None, "md5": None}
EXPIRY_DAYS = EXPIRY_DEFAULTS  # backwards-compatible name
EXPIRY_SETTING = "ioc_expiry_days"


def get_expiry(db: Session) -> dict[str, int | None]:
    row = db.get(Setting, EXPIRY_SETTING)
    stored = (row.value or {}) if row else {}
    out = dict(EXPIRY_DEFAULTS)
    for k, v in stored.items():
        if k in out:
            out[k] = int(v) if v not in (None, "", 0) else None
    return out


def set_expiry(db: Session, days: dict[str, int | None]) -> dict[str, int | None]:
    cur = get_expiry(db)
    for k, v in days.items():
        if k not in EXPIRY_DEFAULTS:
            continue
        if v is not None and (int(v) < 1 or int(v) > 3650):
            raise ValueError(f"{k}: expiry must be between 1 and 3650 days, or never")
        cur[k] = int(v) if v else None
    row = db.get(Setting, EXPIRY_SETTING)
    if row is None:
        row = Setting(key=EXPIRY_SETTING, value={})
        db.add(row)
    row.value = cur
    db.flush()
    return cur


def _as_dt(v) -> datetime | None:
    """Parse the date shapes providers and sources use: epoch seconds, ISO date/datetime strings, datetimes."""
    if v in (None, "", 0):
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(v).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def intel_first_seen(reputation: dict | None, published: list | None = None) -> datetime | None:
    """Earliest intel date for an indicator: source publication dates and provider first-seen values (e.g. VT
    first_submission_date). Future dates are ignored."""
    cands = [_as_dt(p) for p in (published or [])]
    for r in (reputation or {}).values():
        if isinstance(r, dict):
            cands.append(_as_dt(r.get("first_seen")))
    now_ = datetime.now(timezone.utc)
    cands = [c for c in cands if c and c <= now_ + timedelta(days=1)]
    return min(cands) if cands else None


def expires_at(t: str, first_seen: datetime | None, expiry: dict[str, int | None] | None = None) -> datetime | None:
    days = (expiry or EXPIRY_DEFAULTS).get(t)
    fs = _as_dt(first_seen)
    if not days or fs is None:
        return None
    return fs + timedelta(days=days)


def is_expired(t: str, first_seen: datetime | None, expiry: dict[str, int | None] | None = None,
               now: datetime | None = None) -> bool:
    exp = expires_at(t, first_seen, expiry)
    return bool(exp and (now or datetime.now(timezone.utc)) >= exp)

_last_call: dict[str, float] = {}
_rate_lock = threading.Lock()
MIN_INTERVAL = {"virustotal": 15.5, "abuseipdb": 1.0, "greynoise": 1.0, "abusech": 0.5, "shodan": 1.1, "otx": 0.5, "urlscan": 1.0}


def get_keys(db: Session) -> dict[str, str]:
    s = get_settings()
    stored = (db.get(Setting, "osint_keys") or Setting(value={})).value or {}
    return {p["id"]: stored.get(p["id"]) or getattr(s, p["env"], "") for p in PROVIDERS}


def _throttle(provider: str) -> None:
    with _rate_lock:
        wait = MIN_INTERVAL.get(provider, 1.0) - (time.monotonic() - _last_call.get(provider, 0))
        if wait > 0:
            time.sleep(wait)
        _last_call[provider] = time.monotonic()


def _get(client: httpx.Client, provider: str, url: str, **kw) -> httpx.Response:
    for attempt in range(3):
        _throttle(provider)
        r = client.get(url, **kw)
        if r.status_code == 429:
            time.sleep(min(60, 5 * (2**attempt)))
            continue
        return r
    return r


def _post(client: httpx.Client, provider: str, url: str, **kw) -> httpx.Response:
    for attempt in range(3):
        _throttle(provider)
        r = client.post(url, **kw)
        if r.status_code == 429:
            time.sleep(min(60, 5 * (2**attempt)))
            continue
        return r
    return r


def _vt(client: httpx.Client, key: str, t: str, v: str) -> dict | None:
    if t in ("sha256", "sha1", "md5"):
        path = f"files/{v}"
    elif t == "ipv4":
        path = f"ip_addresses/{v}"
    elif t == "domain":
        path = f"domains/{v}"
    else:
        path = "urls/" + base64.urlsafe_b64encode(v.encode()).decode().strip("=")
    r = _get(client, "virustotal", f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key})
    if r.status_code == 404:
        return {"found": False, "summary": "Not found"}
    r.raise_for_status()
    a = r.json()["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    total = sum(stats.values()) or 0
    mal = stats.get("malicious", 0)
    return {
        "found": True, "malicious": mal, "suspicious": stats.get("suspicious", 0), "total": total,
        "summary": f"{mal}/{total}", "tags": a.get("tags", [])[:8],
        "first_seen": a.get("first_submission_date"), "last_seen": a.get("last_analysis_date"),
        "flagged": mal >= 3,
    }


def _abuseipdb(client: httpx.Client, key: str, t: str, v: str) -> dict | None:
    r = _get(client, "abuseipdb", "https://api.abuseipdb.com/api/v2/check",
             params={"ipAddress": v, "maxAgeInDays": 90}, headers={"Key": key, "Accept": "application/json"})
    r.raise_for_status()
    d = r.json()["data"]
    score = d.get("abuseConfidenceScore", 0)
    return {"score": score, "reports": d.get("totalReports", 0), "isp": d.get("isp"), "country": d.get("countryCode"),
            "summary": f"{score}", "flagged": score >= 50}


def _greynoise(client: httpx.Client, key: str, t: str, v: str) -> dict | None:
    r = _get(client, "greynoise", f"https://api.greynoise.io/v3/community/{v}", headers={"key": key})
    if r.status_code == 404:
        return {"classification": "unknown", "summary": "Not observed", "flagged": False}
    r.raise_for_status()
    d = r.json()
    cls = d.get("classification", "unknown")
    return {"classification": cls, "name": d.get("name"), "riot": d.get("riot", False), "summary": cls,
            "flagged": cls == "malicious", "benign": cls == "benign" or d.get("riot", False)}


def _abusech(client: httpx.Client, key: str, t: str, v: str) -> dict | None:
    headers = {"Auth-Key": key}
    if t in ("sha256", "md5"):
        r = _post(client, "abusech", "https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": v}, headers=headers)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok":
            return {"found": False, "summary": "Not in MalwareBazaar", "flagged": False}
        item = d["data"][0]
        return {"found": True, "family": item.get("signature"), "summary": f"MalwareBazaar: {item.get('signature') or 'known'}", "flagged": True}
    if t in ("url", "domain", "ipv4"):
        if t == "url":
            r = _post(client, "abusech", "https://urlhaus-api.abuse.ch/v1/url/", data={"url": v}, headers=headers)
        else:
            r = _post(client, "abusech", "https://urlhaus-api.abuse.ch/v1/host/", data={"host": v}, headers=headers)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") not in ("ok",):
            tf = _post(client, "abusech", "https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": v}, headers=headers)
            if tf.status_code == 200 and tf.json().get("query_status") == "ok":
                item = tf.json()["data"][0]
                return {"found": True, "family": item.get("malware_printable"), "summary": f"ThreatFox: {item.get('malware_printable')}", "flagged": True}
            return {"found": False, "summary": "Not listed", "flagged": False}
        status = d.get("url_status") or ("listed" if d.get("urls") else "unknown")
        return {"found": True, "status": status, "summary": f"URLhaus: {status}", "flagged": True}
    return None


def _shodan(client: httpx.Client, key: str, t: str, v: str) -> dict | None:
    r = _get(client, "shodan", f"https://api.shodan.io/shodan/host/{v}", params={"key": key, "minify": "true"})
    if r.status_code == 404:
        return {"found": False, "summary": "No data"}
    r.raise_for_status()
    d = r.json()
    ports = d.get("ports", [])
    return {"ports": ports[:20], "org": d.get("org"), "country": d.get("country_code"),
            "summary": f"{len(ports)} open ports · {d.get('org') or 'unknown org'}"}


def _otx(client: httpx.Client, key: str, t: str, v: str) -> dict | None:
    section = {"ipv4": "IPv4", "domain": "domain", "url": "url", "sha256": "file", "md5": "file", "sha1": "file"}[t]
    r = _get(client, "otx", f"https://otx.alienvault.com/api/v1/indicators/{section}/{v}/general", headers={"X-OTX-API-KEY": key})
    if r.status_code == 404:
        return {"pulses": 0, "summary": "0 pulses", "flagged": False}
    r.raise_for_status()
    n = r.json().get("pulse_info", {}).get("count", 0)
    return {"pulses": n, "summary": f"{n} pulses", "flagged": n >= 3}


def _urlscan(client: httpx.Client, key: str, t: str, v: str) -> dict | None:
    q = f'page.domain:"{v}"' if t == "domain" else f'page.url:"{v}"'
    r = _get(client, "urlscan", "https://urlscan.io/api/v1/search/", params={"q": q, "size": 5}, headers={"API-Key": key})
    r.raise_for_status()
    results = r.json().get("results", [])
    mal = any(x.get("verdicts", {}).get("overall", {}).get("malicious") for x in results)
    return {"scans": len(results), "malicious": mal, "summary": f"{len(results)} scans" + (" · malicious" if mal else ""), "flagged": mal}


_FUNCS = {"virustotal": _vt, "abuseipdb": _abuseipdb, "greynoise": _greynoise, "abusech": _abusech,
          "shodan": _shodan, "otx": _otx, "urlscan": _urlscan}


def enrich(t: str, value: str, keys: dict[str, str]) -> dict:
    """Query every configured provider that supports this IoC type."""
    out: dict = {}
    with httpx.Client(timeout=20) as client:
        for p in PROVIDERS:
            key = keys.get(p["id"])
            if not key or t not in p["types"]:
                continue
            try:
                res = _FUNCS[p["id"]](client, key, t, value)
                if res is not None:
                    out[p["id"]] = res
            except httpx.HTTPStatusError as e:
                out[p["id"]] = {"error": f"HTTP {e.response.status_code}", "summary": f"Error {e.response.status_code}"}
            except httpx.HTTPError as e:
                out[p["id"]] = {"error": str(e)[:120], "summary": "Unreachable"}
    return out


def verdict(t: str, reputation: dict, vendor_named_malicious: bool, vendor_reliability: str | None,
            first_seen: datetime | None = None, expiry: dict[str, int | None] | None = None,
            known_good: bool = False) -> str:
    """Spec 9 verdict logic. `first_seen` is the intel first-seen (see intel_first_seen); `expiry` the per-type ages
    (get_expiry); `known_good` = on the well-known tool hash allow-list."""
    if known_good or reputation.get("greynoise", {}).get("benign"):
        return "benign"
    flags = sum(1 for r in reputation.values() if isinstance(r, dict) and r.get("flagged"))
    reliable_vendor = vendor_named_malicious and (vendor_reliability or "C")[0] in "AB"
    if flags >= 2 or reliable_vendor:
        v = "malicious"
    elif flags == 1 or vendor_named_malicious:
        v = "suspicious"
    else:
        v = "unknown"
    if first_seen and is_expired(t, first_seen, expiry):
        return "expired"
    return v


def reputation_summary(rep: dict) -> str:
    names = {"virustotal": "VT", "abuseipdb": "AbuseIPDB", "greynoise": "GreyNoise", "abusech": "abuse.ch",
             "shodan": "Shodan", "otx": "OTX", "urlscan": "urlscan"}
    return " · ".join(f"{names.get(k, k)} {v.get('summary', '')}" for k, v in rep.items() if isinstance(v, dict))

"""One view model for every export, so the page, email, PDF and deck never drift apart."""

from __future__ import annotations

from datetime import datetime, timezone

from ..config import get_settings
from ..detection import PLATFORM_BY_ID
from ..models import Research, User, Workspace
from ..records import tactic_rail

SEV = {
    "critical": {"label": "Critical", "solid": "#B4233F", "text": "#9A1C35", "soft": "#FBEAEE"},
    "high": {"label": "High", "solid": "#BD5A2A", "text": "#9C4516", "soft": "#FBEEE6"},
    "medium": {"label": "Medium", "solid": "#B8870B", "text": "#735600", "soft": "#FAF3DC"},
    "low": {"label": "Low", "solid": "#3A6EA8", "text": "#2B5A8C", "soft": "#E9F0F8"},
    "informational": {"label": "Informational", "solid": "#8A93A3", "text": "#525B6B", "soft": "#F0F2F5"},
}
TLP_SQUARE = {"RED": "#B4233F", "AMBER": "#B8870B", "AMBER+STRICT": "#B8870B", "GREEN": "#2E7D4F", "CLEAR": "#FFFFFF"}
RESULT = {
    "confirmed": {"label": "Confirmed compromise", "text": "#9A1C35", "soft": "#FBEAEE"},
    "suspicious": {"label": "Suspicious", "text": "#8F5A00", "soft": "#FFF4DB"},
    "no_evidence": {"label": "No evidence", "text": "#1E7F4F", "soft": "#E7F5EE"},
    "not_applicable": {"label": "Not applicable", "text": "#525B6B", "soft": "#F0F2F5"},
    "pending": {"label": "Pending", "text": "#1F66B5", "soft": "#E8F1FC"},
}
HORIZON = {"immediate": "Immediate (0–48 h)", "short_term": "Short term (≤ 30 days)", "strategic": "Strategic"}
RAIL_FILL = {0: "#E3E6EB", 1: "#C9C5EC", 2: "#857CCB", 3: "#857CCB"}
QTYPE = {"ioc": "IoC", "ioa": "IoA", "vuln": "Vulnerability", "ttp": "TTP"}


def rail_fill(n: int) -> str:
    return RAIL_FILL.get(n, "#433B8E")


def fmt_utc(dt: datetime | str | None) -> str:
    if not dt:
        return "—"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build(db, r: Research, workspace_id: str | None, sections: dict | None = None) -> dict:
    rec = r.record or {}
    ws = db.get(Workspace, workspace_id) if workspace_id else None
    sev = SEV.get(rec.get("severity") or r.severity, SEV["medium"])
    results = {x["workspace_id"]: x for x in rec.get("results", [])}
    result = results.get(workspace_id) if workspace_id else None
    author = db.get(User, r.created_by) if r.created_by else None
    reviewer = db.get(User, r.reviewed_by) if r.reviewed_by else None
    recs = rec.get("recommendations", [])
    grouped = [(HORIZON[h], [x for x in recs if x["horizon"] == h]) for h in ("immediate", "short_term", "strategic")]
    queries = [q for q in rec.get("hunts", {}).get("queries", []) if q.get("origin") != "reference"]
    q_by_type = {t: len([q for q in queries if q["type"] == t]) for t in QTYPE}
    gaps = [g for g in rec.get("coverage_gaps", []) if not workspace_id or g["workspace_id"] == workspace_id]
    sources = {s["id"]: s for s in rec.get("sources", [])}
    rail = tactic_rail(rec)
    s = {"iocs": True, "queries": True, "sources": True, "study": False, **(sections or {})}
    return {
        "r": r, "rec": rec, "ws": ws, "sev": sev, "result": result,
        "result_style": RESULT.get((result or {}).get("status", "pending"), RESULT["pending"]),
        "tlp": rec.get("tlp", r.tlp), "tlp_square": TLP_SQUARE.get(rec.get("tlp", r.tlp), "#B8870B"),
        "author": author, "reviewer": reviewer, "grouped_recs": grouped, "queries": queries, "q_by_type": q_by_type,
        "platform_name": lambda p: PLATFORM_BY_ID.get(p, {}).get("name", p), "qtype": QTYPE,
        "gaps": gaps, "sources": sources, "rail": rail, "rail_fill": rail_fill,
        "top_ttps": rec.get("mitre", [])[:8], "key_iocs": [i for i in rec.get("iocs", []) if i.get("verdict") in ("malicious", "suspicious")][:10],
        "now": fmt_utc(datetime.now(timezone.utc)), "fmt": fmt_utc, "RESULT": RESULT,
        "report_url": f"{get_settings().web_base_url}/research/{r.id}" + (f"?ws={workspace_id}" if workspace_id else ""),
        "client": ws.name if ws else "All workspaces", "branding": (ws.branding if ws else {}) or {}, "sections": s,
        "industries": ", ".join(i["industry"] for i in rec.get("industries", [])) or "—",
        "platform_names": ", ".join(PLATFORM_BY_ID.get(p, {}).get("name", p) for p in rec.get("hunts", {}).get("platforms", [])) or "—",
    }

"""One view model for every export, so the page, email, PDF and deck never drift apart."""

from __future__ import annotations

from datetime import datetime, timezone

from ..config import get_settings
from ..detection import PLATFORM_BY_ID, map_query
from ..models import Research, Result, User, Workspace
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


def mapped_queries(rec: dict, ws: Workspace | None) -> list[dict]:
    """The record's hunt queries as exported for a workspace: its field mappings applied server-side (token-aware, see
    detection.apply_mappings) and lint re-run on the mapped text. `original_body` keeps the unmapped text."""
    out = []
    for q in (rec.get("hunts") or {}).get("queries", []):
        if ws is None:
            out.append(dict(q))
            continue
        m = map_query(q, ws.field_mappings or {})
        out.append({**q, "body": m["mapped_body"], "lint": m["mapped_lint"], "original_body": q.get("body", ""),
                    "mapping_applied": m["mapping_applied"]})
    return out


def queries_run_by_type(rec: dict, queries_run: list[str]) -> dict[str, int]:
    """Count the entries of a workspace result's `queries_run` by query type. Entries may be query ids (Q-0001),
    detection opportunity ids (DO-1) or query group ids (DET-1, IOC-IPV4, VULN-1, TTP-1, VREF-1); anything that cannot
    be resolved is counted as "other"."""
    queries = (rec.get("hunts") or {}).get("queries", [])
    by_id = {q["id"]: q.get("type") for q in queries}
    by_group = {q.get("group"): q.get("type") for q in queries if q.get("group")}
    by_opp = {o["id"]: o.get("type") for o in rec.get("detection_opportunities", []) if o.get("id")}
    by_opp.update({q["opportunity_id"]: q.get("type") for q in queries if q.get("opportunity_id")})
    counts = {t: 0 for t in QTYPE}
    counts["other"] = 0
    for entry in dict.fromkeys(queries_run or []):
        t = by_id.get(entry) or by_opp.get(entry) or by_group.get(entry)
        counts[t if t in QTYPE else "other"] += 1
    return counts


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
    hunt_queries = mapped_queries(rec, ws)
    queries = [q for q in hunt_queries if q.get("origin") != "reference"]
    q_by_type = {t: len([q for q in queries if q["type"] == t]) for t in QTYPE}
    # Deck slide 2 "# queries run by type": from this workspace's recorded result; when nothing was recorded, fall back
    # to the generated counts, labelled as such.
    run_row = db.query(Result).filter_by(research_id=r.id, workspace_id=workspace_id).first() if workspace_id else None
    queries_run = list(run_row.queries_run or []) if run_row else list((result or {}).get("queries_run") or [])
    if queries_run:
        q_run_by_type, q_run_label, q_run_source = queries_run_by_type(rec, queries_run), "Queries run by type", "result"
    else:
        q_run_by_type = {**q_by_type, "other": 0}
        q_run_label, q_run_source = "Queries generated by type (none recorded as run)", "generated"
    branding = (ws.branding if ws else {}) or {}
    brand_color = branding.get("primary") or (ws.color if ws else None) or "#5249A8"
    gaps = [g for g in rec.get("coverage_gaps", []) if not workspace_id or g["workspace_id"] == workspace_id]
    sources = {s["id"]: s for s in rec.get("sources", [])}
    rail = tactic_rail(rec)
    s = {"iocs": True, "queries": True, "sources": True, "study": False, **(sections or {})}
    return {
        "r": r, "rec": rec, "ws": ws, "sev": sev, "result": result,
        "result_style": RESULT.get((result or {}).get("status", "pending"), RESULT["pending"]),
        "tlp": rec.get("tlp", r.tlp), "tlp_square": TLP_SQUARE.get(rec.get("tlp", r.tlp), "#B8870B"),
        "author": author, "reviewer": reviewer, "grouped_recs": grouped, "queries": queries, "q_by_type": q_by_type,
        "hunt_queries": hunt_queries, "queries_run": queries_run, "q_run_by_type": q_run_by_type, "q_run_label": q_run_label,
        "q_run_source": q_run_source, "mapping_workspace": ws.name if ws and ws.field_mappings else None,
        "brand_color": brand_color,
        "platform_name": lambda p: PLATFORM_BY_ID.get(p, {}).get("name", p), "qtype": QTYPE,
        "gaps": gaps, "sources": sources, "rail": rail, "rail_fill": rail_fill,
        "top_ttps": rec.get("mitre", [])[:8], "key_iocs": [i for i in rec.get("iocs", []) if i.get("verdict") in ("malicious", "suspicious")][:10],
        "now": fmt_utc(datetime.now(timezone.utc)), "fmt": fmt_utc, "RESULT": RESULT,
        "report_url": f"{get_settings().web_base_url}/research/{r.id}" + (f"?ws={workspace_id}" if workspace_id else ""),
        "client": ws.name if ws else "All workspaces", "branding": branding, "sections": s,
        "industries": ", ".join(i["industry"] for i in rec.get("industries", [])) or "—",
        "platform_names": ", ".join(PLATFORM_BY_ID.get(p, {}).get("name", p) for p in rec.get("hunts", {}).get("platforms", [])) or "—",
    }

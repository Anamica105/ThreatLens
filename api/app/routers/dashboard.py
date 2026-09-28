from __future__ import annotations

import statistics
from collections import Counter as Cnt
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import attack
from ..db import get_db
from ..deps import iso
from ..models import Research, Result, Workspace

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def period_bounds(period: str, date_from: str | None, date_to: str | None) -> tuple[datetime, datetime, str]:
    today = datetime.now(timezone.utc).date()
    if period == "custom" and date_from and date_to:
        start, end = date.fromisoformat(date_from), date.fromisoformat(date_to)
        label = f"{start:%d %b} – {end:%d %b %Y}"
    elif period == "week":
        start = today - timedelta(days=today.weekday())
        end = today
        label = "This week"
    elif period == "month":
        start = today.replace(day=1)
        end = today
        label = "This month"
    elif period == "last_quarter":
        q = (today.month - 1) // 3
        y, q = (today.year, q - 1) if q > 0 else (today.year - 1, 3)
        start = date(y, 3 * q + 1, 1)
        end = (date(y + (3 * q + 3) // 12, (3 * q + 3) % 12 + 1, 1) - timedelta(days=1))
        label = "Last quarter"
    elif period == "year":
        start, end, label = today.replace(month=1, day=1), today, "Year to date"
    else:
        q = (today.month - 1) // 3
        start, end, label = date(today.year, 3 * q + 1, 1), today, "This quarter"
    return (datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc),
            datetime.combine(end, datetime.max.time(), tzinfo=timezone.utc), label)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _scope(db: Session, ws: str | None) -> list[Research]:
    rows = db.query(Research).all()
    if ws and ws != "all":
        rows = [r for r in rows if ws in (r.workspace_ids or [])]
    return rows


def _kpis(rows: list[Research], results: list[Result], start: datetime, end: datetime) -> dict:
    created = [r for r in rows if start <= _aware(r.created_at) <= end and r.status not in ("running", "failed")]
    published = [r for r in rows if r.published_at and start <= _aware(r.published_at) <= end]
    ttp = [(_aware(r.published_at) - _aware(r.created_at)).total_seconds() / 3600 for r in published]
    ids = {r.id for r in rows}
    findings = [x for x in results if x.research_id in ids and x.status in ("suspicious", "confirmed") and start <= _aware(x.updated_at) <= end]
    return {
        "runs": len(created), "published": len(published),
        "median_hours_to_publish": round(statistics.median(ttp), 1) if ttp else None,
        "findings": len(findings),
        "iocs": sum(len((r.record or {}).get("iocs", [])) for r in created),
        "queries": sum(len([q for q in (r.record or {}).get("hunts", {}).get("queries", []) if q.get("origin") != "reference"]) for r in created),
    }


@router.get("")
def dashboard(db: Session = Depends(get_db), ws: str | None = None, period: str = "quarter", date_from: str | None = None,
              date_to: str | None = None):
    start, end, label = period_bounds(period, date_from, date_to)
    span = end - start
    prev_start, prev_end = start - span - timedelta(seconds=1), start - timedelta(seconds=1)
    rows = _scope(db, ws)
    results = db.query(Result).all()
    if ws and ws != "all":
        results = [x for x in results if x.workspace_id == ws]
    cur, prev = _kpis(rows, results, start, end), _kpis(rows, results, prev_start, prev_end)
    in_period = [r for r in rows if start <= _aware(r.created_at) <= end and r.status not in ("running",)]
    ids = {r.id for r in in_period}

    # Runs over time (weekly buckets)
    buckets: dict[str, int] = {}
    d = start.date() - timedelta(days=start.date().weekday())
    while d <= end.date():
        buckets[d.isoformat()] = 0
        d += timedelta(days=7)
    for r in in_period:
        c = _aware(r.created_at).date()
        wk = (c - timedelta(days=c.weekday())).isoformat()
        if wk in buckets:
            buckets[wk] += 1

    res_counts = Cnt(x.status for x in results if x.research_id in ids)
    sev_counts = Cnt(r.severity for r in in_period)

    # ATT&CK coverage heatmap: tactics x techniques, value = number of research mapping it
    tech_counts: Cnt = Cnt()
    for r in in_period:
        for tid in {m["technique_id"] for m in (r.record or {}).get("mitre", [])}:
            tech_counts[tid] += 1
    heat = []
    for t in attack.TACTICS:
        cells = []
        for tid, n in tech_counts.items():
            info = attack.technique(tid)
            if info and t["id"] in info["tactic_ids"]:
                cells.append({"id": tid, "name": info["name"], "count": n})
        cells.sort(key=lambda c: (-c["count"], c["id"]))
        heat.append({**t, "techniques": cells})

    actors: Cnt = Cnt()
    cves: Cnt = Cnt()
    cvss: dict[str, float] = {}
    for r in in_period:
        for a in (r.record or {}).get("threat_actors", []):
            actors[a["name"]] += 1
        for v in (r.record or {}).get("vulnerabilities", []):
            cves[v["cve"]] += 1
            cvss[v["cve"]] = v.get("cvss") or 0

    per_client = []
    for w in db.query(Workspace).order_by(Workspace.name).all():
        if ws and ws != "all" and w.id != ws:
            continue
        wr = [r for r in in_period if w.id in (r.workspace_ids or [])]
        wres = [x for x in db.query(Result).filter_by(workspace_id=w.id).all() if x.research_id in {r.id for r in wr}]
        last = max((r for r in wr if r.status == "published"), key=lambda r: _aware(r.published_at or r.created_at), default=None)
        per_client.append({"id": w.id, "name": w.name, "color": w.color, "industry": w.industry, "runs": len(wr),
                           "findings": sum(1 for x in wres if x.status in ("suspicious", "confirmed")),
                           "pending": sum(1 for x in wres if x.status == "pending"),
                           "last_report": {"id": last.id, "title": last.title, "published_at": iso(last.published_at)} if last else None})

    recent = sorted(rows, key=lambda r: iso(r.updated_at) or "", reverse=True)[:6]
    return {
        "period": {"label": label, "from": start.date().isoformat(), "to": end.date().isoformat()},
        "kpis": cur, "previous": prev,
        "runs_over_time": [{"week": k, "count": v} for k, v in buckets.items()],
        "results_by_status": [{"status": s, "count": res_counts.get(s, 0)} for s in ("confirmed", "suspicious", "no_evidence", "not_applicable", "pending")],
        "severity_mix": [{"severity": s, "count": sev_counts.get(s, 0)} for s in ("critical", "high", "medium", "low")],
        "heatmap": heat,
        "top_actors": [{"name": n, "count": c} for n, c in actors.most_common(5)],
        "top_cves": [{"cve": n, "count": c, "cvss": cvss.get(n)} for n, c in cves.most_common(5)],
        "per_client": per_client,
        "recent": [{"id": r.id, "title": r.title, "status": r.status, "severity": r.severity, "updated_at": iso(r.updated_at)} for r in recent],
    }

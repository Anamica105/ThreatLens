"""Daily emerging-threat digest.

Once a day the scheduler:
1. pulls every allow-listed vendor RSS feed (sources.VENDORS) and keeps what was published in the lookback window,
2. tags each article with the CVEs, actors and malware it names and clusters articles that share one, so the same
   threat reported by three vendors becomes one item,
3. ranks the clusters (vendor corroboration, CVE, government advisory, named actor/malware, recency) and drops the ones
   already sent in the last SEEN_DAYS,
4. optionally runs the normal research pipeline on the top few for the digest workspace (same code path as
   POST /api/research, so each becomes an ordinary draft research record with sources, ATT&CK, IoCs and queries),
5. emails one HTML digest (summary, key IoCs, the workspace's hunt queries, link to the full report) with an IoC CSV
   per researched threat, over SMTP, or saves it as an .eml when SMTP is not configured.

Feed text is untrusted third-party content: it is only regex-scanned and shown back (auto-escaped); nothing in it is
followed or fetched here. The pipeline applies its own guardrails when it reads the linked articles.

State lives in the `setting` table: ``digest_state`` (last run) and ``digest_seen`` (cluster keys already sent).
"""

from __future__ import annotations

import html
import logging
import re
import smtplib
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import make_msgid
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from . import attack, intake, ioc, llm, sources
from .config import get_settings
from .db import SessionLocal
from .detection import PLATFORM_BY_ID
from .models import Research, Run, Setting, User, Workspace
from .records import log_activity

log = logging.getLogger(__name__)

STATE_KEY = "digest_state"
SEEN_KEY = "digest_seen"
SEEN_DAYS = 7
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_TAGS = re.compile(r"<[^>]+>")

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "exports" / "templates"), autoescape=select_autoescape(["html"]))
_lock = threading.Lock()


def now() -> datetime:
    return datetime.now(timezone.utc)


def _setting(db: Session, key: str) -> dict:
    row = db.get(Setting, key)
    return dict(row.value or {}) if row else {}


def _put(db: Session, key: str, value: dict) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value  # reassign: JSON columns are not mutation-tracked


def _norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()[:80]


# ------------------------------------------------------------------ 1-3: collect, cluster, rank


def feed_articles(db: Session, pulled, since: datetime) -> list[dict]:
    """Articles from parsed feeds published after `since`, each tagged with the entities it names."""
    out, seen = [], set()
    for v, feed, err in pulled:
        if err is not None or feed is None:
            log.warning("digest: %s feed unavailable (%s)", v["name"], type(err).__name__)
            continue
        for e in feed.entries[:60]:
            link, title = e.get("link", ""), (e.get("title") or "").strip()
            if not re.match(r"https?://", link, re.I) or not title or not e.get("published_parsed"):
                continue
            pub = datetime(*e.published_parsed[:6], tzinfo=timezone.utc)
            key = sources.canonical(link)
            if pub < since or key in seen:
                continue
            seen.add(key)
            summary = " ".join(html.unescape(_TAGS.sub(" ", e.get("summary") or "")).split())[:600]
            text = f"{title} {summary} {' '.join(t.get('term', '') for t in e.get('tags', []))}"
            actors, malware = intake._names(db, text)
            out.append({"url": link, "title": title, "summary": summary, "published": pub, "publisher": v["name"],
                        "vendor_id": v["id"], "reliability": v["reliability"],
                        "cves": sorted({c.upper() for c in CVE_RE.findall(text)}), "actors": actors, "malware": malware})
    return out


def _keys(a: dict) -> set[str]:
    ks = {f"cve:{c}" for c in a["cves"]} | {f"actor:{x.lower()}" for x in a["actors"]} | {f"malware:{x.lower()}" for x in a["malware"]}
    return ks or {f"title:{_norm_title(a['title'])}"}


def cluster(articles: list[dict], at: datetime | None = None) -> list[dict]:
    """Group articles that share a CVE, actor or malware name (union-find), then score and rank the groups."""
    at = at or now()
    parent = list(range(len(articles)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, a in enumerate(articles):
        for k in _keys(a):
            if k in owner:
                parent[find(i)] = find(owner[k])
            else:
                owner[k] = i
    groups: dict[int, list[dict]] = {}
    for i, a in enumerate(articles):
        groups.setdefault(find(i), []).append(a)

    out = []
    for arts in groups.values():
        arts.sort(key=lambda a: (a["reliability"], a["published"]))  # A before B, then earliest first
        cves = sorted({c for a in arts for c in a["cves"]})
        actors = list(dict.fromkeys(x for a in arts for x in a["actors"]))
        malware = list(dict.fromkeys(x for a in arts for x in a["malware"]))
        publishers = list(dict.fromkeys(a["publisher"] for a in arts))
        newest = max(a["published"] for a in arts)
        why = []
        score = 3 * len(publishers)
        if len(publishers) > 1:
            why.append(f"reported by {len(publishers)} publishers")
        if cves:
            score += 2
            why.append("names a CVE")
        if any(a["reliability"] == "A" for a in arts):
            score += 2
            why.append("government advisory")
        if actors or malware:
            score += 1
            why.append("named actor or malware")
        if at - newest <= timedelta(hours=12):
            score += 1
            why.append("published in the last 12 h")
        label = " · ".join((cves[:2] + actors[:1] + malware[:1])) or arts[0]["title"]
        out.append({"key": sorted(set().union(*(_keys(a) for a in arts))), "title": arts[0]["title"], "label": label,
                    "score": score, "why": why, "cves": cves, "actors": actors, "malware": malware,
                    "publishers": publishers, "newest": newest, "articles": arts})
    out.sort(key=lambda c: (c["score"], c["newest"]), reverse=True)
    return out


def pick(db: Session, clusters: list[dict], limit: int, at: datetime | None = None) -> list[dict]:
    """Top `limit` clusters none of whose keys went out in the last SEEN_DAYS."""
    at = at or now()
    cutoff = (at - timedelta(days=SEEN_DAYS)).isoformat()
    seen = {k for k, ts in _setting(db, SEEN_KEY).items() if ts >= cutoff}
    return [c for c in clusters if not seen.intersection(c["key"])][:limit]


def remember(db: Session, threats: list[dict], at: datetime | None = None) -> None:
    at = at or now()
    cutoff = (at - timedelta(days=SEEN_DAYS)).isoformat()
    seen = {k: ts for k, ts in _setting(db, SEEN_KEY).items() if ts >= cutoff}
    seen.update({k: at.isoformat() for t in threats for k in t["key"]})
    _put(db, SEEN_KEY, seen)


# ------------------------------------------------------------------ 4: research


def digest_workspace(db: Session) -> Workspace | None:
    wid = get_settings().digest_workspace_id
    return (db.get(Workspace, wid) if wid else None) or db.query(Workspace).order_by(Workspace.created_at, Workspace.id).first()


def _system_user(db: Session) -> User | None:
    return (db.query(User).filter(User.role.in_(["admin", "lead"])).order_by(User.id).first()
            or db.query(User).order_by(User.id).first())


def research(threat: dict, ws: Workspace) -> str | None:
    """Run the full pipeline on one threat (synchronously, in this thread). Returns the research id."""
    from .pipeline import runner
    from .routers import research as research_router
    from .routers.intake import _platforms_for

    s = get_settings()
    with SessionLocal() as db:
        user = _system_user(db)
        if user is None:
            return None
        lines = [threat["title"]]
        if threat["cves"] or threat["actors"] or threat["malware"]:
            lines.append("Entities: " + ", ".join(threat["cves"] + threat["actors"] + threat["malware"]))
        lines += [f"- {a['publisher']}: {a['title']}" for a in threat["articles"][:5]]
        body = research_router.NewRun(
            seed="\n".join(lines), seed_urls=[a["url"] for a in threat["articles"][:10]], workspace_ids=[ws.id],
            platforms=_platforms_for(db, [ws.id]), depth=s.digest_depth if s.digest_depth in sources.DEPTH_SOURCES else "quick",
            tlp=ws.default_tlp or "AMBER", draft=True)
        out = research_router.create_research(body, db=db, user=user)
        log_activity(db, out["id"], "created", f"Created by the daily emerging-threat digest ({threat['label']})", user.id)
        db.commit()
    runner.execute_run(out["run_id"])
    return out["id"]


# ------------------------------------------------------------------ 5: render and send


def _threat_view(db: Session, t: dict, ws: Workspace | None, max_queries: int) -> dict:
    from .exports import context as export_ctx

    view = {**t, "newest": export_ctx.fmt_utc(t["newest"]), "research": None}
    rid = t.get("research_id")
    r = db.get(Research, rid) if rid else None
    if r is None or not r.record:
        view["failed"] = bool(rid)
        view["report_url"] = f"{get_settings().web_base_url}/research/{rid}" if rid else None
        return view
    vm = export_ctx.build(db, r, ws.id if ws else None)
    view["report_url"] = vm["report_url"]
    run = db.query(Run).filter_by(research_id=r.id).order_by(Run.started_at.desc().nullslast()).first()
    if vm["tlp"] == "RED":  # never email TLP:RED content; point at the report instead
        view["research"] = {"id": r.id, "tlp": "RED", "redacted": True}
        return view
    rec = vm["rec"]
    queries = [q for q in vm["hunt_queries"] if q.get("origin") != "reference"]
    view["research"] = {
        "id": r.id, "tlp": vm["tlp"], "redacted": False, "sev": vm["sev"], "confidence": rec.get("confidence") or r.confidence,
        "status": r.status, "offline": bool(run and run.mode == "offline"),
        "summary": [p for p in (rec.get("executive_summary") or "").split("\n\n") if p.strip()][:3],
        "ttps": [{"id": tid, "name": (attack.technique(tid) or {}).get("name", "")}
                 for tid in dict.fromkeys(m["technique_id"] for m in vm["top_ttps"])],
        "iocs": [{"type": i["type"], "value": ioc.defang(i["value"], i["type"]), "verdict": i.get("verdict") or "unknown"}
                 for i in vm["key_iocs"]],
        "n_iocs": len(rec.get("iocs", [])),
        "queries": [{"title": q.get("title") or q["id"], "type": q.get("type", ""), "platform": PLATFORM_BY_ID.get(q["platform"], {}).get("name", q["platform"]),
                     "body": q.get("body", "")} for q in queries[:max_queries]],
        "n_queries": len(queries),
        "recs": [x["action"] for x in rec.get("recommendations", []) if x.get("horizon") == "immediate"][:4],
        "csv": _iocs_csv(vm) if rec.get("iocs") else None,
    }
    return view


def _iocs_csv(vm: dict) -> bytes:
    from .exports import render

    return render.iocs_csv(vm)


def render(db: Session, threats: list[dict], ws: Workspace | None, at: datetime | None = None) -> tuple[str, str, str, list[dict]]:
    """(subject, html, text, per-threat views) for the digest email."""
    s = get_settings()
    at = at or now()
    views = [_threat_view(db, t, ws, s.digest_max_queries) for t in threats]
    day = at.strftime("%d %b %Y")
    subject = f"[ThreatLens] Emerging threats · {day} · {len(views)} item{'s' if len(views) != 1 else ''}"
    body = _env.get_template("digest.html").render(threats=views, day=day, client=ws.name if ws else "All workspaces",
                                                    lookback=s.digest_lookback_hours, web=s.web_base_url, researched=s.digest_auto_research)
    text = [f"ThreatLens emerging-threat digest, {day}", ""]
    if not views:
        text.append("Nothing new in the vendor feeds that has not already been sent in the last week.")
    for i, v in enumerate(views, 1):
        text += [f"{i}. {v['title']}", f"   {v['label']} | {', '.join(v['publishers'])} | why: {', '.join(v['why'])}"]
        if v["report_url"]:
            text.append(f"   Report: {v['report_url']}")
        text += [f"   - {a['url']}" for a in v["articles"][:5]] + [""]
    text.append("Automated research drafts are unreviewed. Verify against the sources before any client use.")
    return subject, body, "\n".join(text), views


def build_message(subject: str, body_html: str, body_text: str, views: list[dict]) -> EmailMessage:
    s = get_settings()
    msg = EmailMessage(policy=SMTP)
    msg["Subject"] = subject
    msg["From"] = s.smtp_from
    msg["To"] = ", ".join(recipients())
    msg["Message-ID"] = make_msgid(domain="threatlens.local")
    msg.set_content(body_text)
    msg.add_alternative(body_html, subtype="html")
    for v in views:
        r = v.get("research") or {}
        if r.get("csv"):
            msg.add_attachment(r["csv"], maintype="text", subtype="csv", filename=f"{r['id']}-iocs.csv")
    return msg


def recipients() -> list[str]:
    return [x.strip() for x in get_settings().digest_recipients.split(",") if x.strip()]


def send(msg: EmailMessage) -> str:
    """Send over SMTP; with no SMTP_HOST (or no recipients) save an .eml instead. Returns where it went."""
    s = get_settings()
    if not s.smtp_host or not recipients():
        folder = s.data_dir / "exports" / "digests"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"digest-{now().strftime('%Y%m%d-%H%M%S')}.eml"
        path.write_bytes(bytes(msg))
        return f"saved {path}"
    ctx = ssl.create_default_context()
    if s.smtp_port == 465:
        server = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=30, context=ctx)
    else:
        server = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30)
    with server:
        if s.smtp_port != 465 and s.smtp_starttls:
            server.starttls(context=ctx)
        if s.smtp_user:
            server.login(s.smtp_user, s.smtp_password)
        server.send_message(msg)
    return f"sent to {len(recipients())} recipient(s)"


# ------------------------------------------------------------------ orchestration and scheduler


def run_digest(dry_run: bool = False, pulled=None, at: datetime | None = None) -> dict:
    """One digest end to end. `dry_run` skips research and sending and returns the rendered email for preview.
    `pulled` (tests) replaces the live feed pull."""
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "A digest is already running"}
    s = get_settings()
    at = at or now()
    started = now()
    try:
        if pulled is None:
            pulled = sources.pull_feeds(sources.VENDORS)
        with SessionLocal() as db:
            articles = feed_articles(db, pulled, at - timedelta(hours=s.digest_lookback_hours))
            threats = pick(db, cluster(articles, at), max(1, s.digest_max_threats), at)
            ws = digest_workspace(db)
        if s.digest_auto_research and not dry_run and ws is not None:
            for t in threats:
                try:
                    t["research_id"] = research(t, ws)
                except Exception:  # noqa: BLE001 - one failed run must not stop the digest
                    log.exception("digest: research failed for %s", t["label"])
                    t["research_id"] = None
        with SessionLocal() as db:
            ws = db.get(Workspace, ws.id) if ws else None
            subject, body_html, body_text, views = render(db, threats, ws, at)
            result = {"ok": True, "at": at.isoformat(), "articles": len(articles), "subject": subject,
                      "threats": [{"label": t["label"], "title": t["title"], "score": t["score"], "why": t["why"],
                                   "publishers": t["publishers"], "research_id": t.get("research_id")} for t in threats]}
            if dry_run:
                return {**result, "html": body_html, "text": body_text, "dry_run": True}
            result["delivery"] = send(build_message(subject, body_html, body_text, views))
            remember(db, threats, at)
            result["seconds"] = round((now() - started).total_seconds(), 1)
            _put(db, STATE_KEY, {**_setting(db, STATE_KEY), "last_date": at.date().isoformat(), "last_run": result})
            db.commit()
            log.info("digest: %s (%d threat(s))", result["delivery"], len(threats))
            return result
    except Exception as e:  # noqa: BLE001
        log.exception("digest failed")
        if not dry_run:
            with SessionLocal() as db:
                _put(db, STATE_KEY, {**_setting(db, STATE_KEY), "last_error": {"at": at.isoformat(), "error": str(e)[:400]}})
                db.commit()
        return {"ok": False, "error": str(e)[:400]}
    finally:
        _lock.release()


def due(at: datetime, last_date: str | None) -> bool:
    hh, _, mm = (get_settings().digest_time_utc or "06:30").partition(":")
    slot = at.replace(hour=int(hh), minute=int(mm or 0), second=0, microsecond=0)
    return at >= slot and last_date != at.date().isoformat()


def _loop() -> None:
    while True:
        try:
            with SessionLocal() as db:
                last = _setting(db, STATE_KEY).get("last_date")
            if due(now(), last):
                run_digest()
        except Exception:  # noqa: BLE001 - keep the scheduler alive
            log.exception("digest scheduler tick failed")
        time.sleep(60)


_started = False


def start_scheduler() -> None:
    """Start the once-a-day scheduler thread (single API process only; see README)."""
    global _started
    if _started or not get_settings().digest_enabled:
        return
    _started = True
    threading.Thread(target=_loop, name="digest-scheduler", daemon=True).start()
    log.info("digest: scheduled daily at %s UTC for %s (LLM %s)", get_settings().digest_time_utc,
             ", ".join(recipients()) or "no recipients (saving .eml)", "on" if llm.available() else "off, offline mode")


def status(db: Session) -> dict:
    s = get_settings()
    ws = digest_workspace(db)
    return {"enabled": s.digest_enabled, "time_utc": s.digest_time_utc, "recipients": recipients(),
            "workspace": {"id": ws.id, "name": ws.name} if ws else None, "max_threats": s.digest_max_threats,
            "lookback_hours": s.digest_lookback_hours, "auto_research": s.digest_auto_research, "depth": s.digest_depth,
            "smtp_configured": bool(s.smtp_host), "llm": llm.available(), **_setting(db, STATE_KEY)}

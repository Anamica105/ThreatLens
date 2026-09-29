"""Daily emerging-threat digest: clustering, ranking, de-duplication, rendering and delivery (no network)."""

import email
import os
import tempfile
from datetime import datetime, timedelta, timezone
from email import policy
from pathlib import Path

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tempfile.mkdtemp()) / 'digest.db').as_posix()}"
os.environ["ANTHROPIC_API_KEY"] = ""

import feedparser  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import digest  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Setting  # noqa: E402

AT = datetime(2026, 9, 29, 7, 0, tzinfo=timezone.utc)


def _rss(items: list[tuple[str, str, str, datetime]]) -> str:
    rows = "".join(f"<item><title>{t}</title><link>{u}</link><description>{d}</description>"
                   f"<pubDate>{p.strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate></item>" for t, u, d, p in items)
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>{rows}</channel></rss>'


def _pulled():
    v = {x["id"]: x for x in digest.sources.VENDORS}
    h = lambda n: AT - timedelta(hours=n)  # noqa: E731
    return [
        (v["microsoft"], feedparser.parse(_rss([
            ("Storm-2603 exploits SharePoint CVE-2025-53770", "https://www.microsoft.com/security/blog/toolshell", "<p>Active exploitation.</p>", h(3)),
            ("Old post", "https://www.microsoft.com/security/blog/old", "CVE-2020-0001", h(200)),
        ])), None),
        (v["unit42"], feedparser.parse(_rss([
            ("ToolShell: more on CVE-2025-53770", "https://unit42.paloaltonetworks.com/toolshell", "Warlock ransomware seen.", h(5)),
            ("Bad link", "javascript:alert(1)", "CVE-2025-99999", h(2)),
        ])), None),
        (v["cisa"], feedparser.parse(_rss([
            ("CISA adds CVE-2025-53770 to KEV", "https://www.cisa.gov/news/kev-53770", "", h(8)),
            ("Phishing trends this week", "https://www.cisa.gov/news/phishing", "General advice.", h(20)),
        ])), None),
        (v["talos"], None, RuntimeError("feed down")),
    ]


@pytest.fixture(autouse=True)
def _db(monkeypatch, tmp_path):
    with TestClient(app):  # runs startup: schema + seed
        pass
    with SessionLocal() as db:
        for k in (digest.SEEN_KEY, digest.STATE_KEY):
            row = db.get(Setting, k)
            if row:
                db.delete(row)
        db.commit()
    s = get_settings()
    monkeypatch.setattr(s, "data_dir", tmp_path)
    monkeypatch.setattr(s, "smtp_host", "")
    monkeypatch.setattr(s, "digest_recipients", "soc@example.com, lead@example.com")
    monkeypatch.setattr(s, "digest_lookback_hours", 36)
    monkeypatch.setattr(s, "digest_max_threats", 3)


def test_cluster_and_rank():
    with SessionLocal() as db:
        arts = digest.feed_articles(db, _pulled(), AT - timedelta(hours=36))
    urls = {a["url"] for a in arts}
    assert "https://www.microsoft.com/security/blog/old" not in urls  # outside the window
    assert not any(u.startswith("javascript:") for u in urls)  # only http(s) links
    ranked = digest.cluster(arts, AT)
    top = ranked[0]
    assert top["cves"] == ["CVE-2025-53770"]
    assert set(top["publishers"]) == {"Microsoft Threat Intelligence", "Palo Alto Unit 42", "CISA"}
    assert "government advisory" in top["why"] and top["articles"][0]["publisher"] == "CISA"  # reliability A first
    assert any(c["title"] == "Phishing trends this week" for c in ranked[1:])


def test_digest_researches_renders_and_dedupes(monkeypatch):
    calls = []

    def fake_research(threat, ws):
        calls.append(threat["label"])
        return "TR-2026-0142" if "CVE-2025-53770" in threat["cves"] else None

    monkeypatch.setattr(digest, "research", fake_research)
    out = digest.run_digest(pulled=_pulled(), at=AT)
    assert out["ok"], out
    assert len(out["threats"]) == 2 and out["threats"][0]["research_id"] == "TR-2026-0142"
    assert out["delivery"].startswith("saved ")

    msg = email.message_from_bytes(Path(out["delivery"][6:]).read_bytes(), policy=policy.default)
    assert msg["To"] == "soc@example.com, lead@example.com"
    body = msg.get_body(("html",)).get_content()
    assert "Hunt queries for" in body and "Unreviewed draft" in body and "/research/TR-2026-0142" in body
    assert "Not researched automatically" in body  # the second item had no research
    assert [p.get_filename() for p in msg.iter_attachments()] == ["TR-2026-0142-iocs.csv"]

    # Same feeds again: everything was already sent, so the next digest is empty.
    again = digest.run_digest(pulled=_pulled(), at=AT + timedelta(days=1))
    assert again["ok"] and again["threats"] == []


def test_dry_run_sends_nothing(monkeypatch):
    monkeypatch.setattr(digest, "research", lambda *a: pytest.fail("dry run must not research"))
    out = digest.run_digest(dry_run=True, pulled=_pulled(), at=AT)
    assert out["dry_run"] and "Emerging threats" in out["html"]
    with SessionLocal() as db:
        assert db.get(Setting, digest.SEEN_KEY) is None and db.get(Setting, digest.STATE_KEY) is None


def test_due(monkeypatch):
    monkeypatch.setattr(get_settings(), "digest_time_utc", "06:30")
    assert not digest.due(AT.replace(hour=6, minute=0), None)
    assert digest.due(AT, None)
    assert not digest.due(AT, AT.date().isoformat())


def test_send_now_needs_lead():
    c = TestClient(app)
    assert c.post("/api/digest/run", headers={"X-User": "averma"}).status_code == 403
    assert c.get("/api/digest", headers={"X-User": "averma"}).json()["recipients"] == ["soc@example.com", "lead@example.com"]

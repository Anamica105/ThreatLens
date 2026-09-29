"""WP4: CVE enrichment (NVD / CISA KEV / EPSS), run budget, view audit. No live network: every HTTP call is mocked."""

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tempfile.mkdtemp()) / 'wp4.db').as_posix()}"
os.environ["ANTHROPIC_API_KEY"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app import audit, vulns  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AuditEvent, ExternalCache, Research, Run, RunLog  # noqa: E402
from app.pipeline import runner  # noqa: E402

NVD_53770 = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": "CVE-2025-53770", "vulnStatus": "Analyzed", "published": "2025-07-20T01:15:24.093",
    "lastModified": "2025-07-23T10:00:00.000",
    "descriptions": [{"lang": "en", "value": "Deserialization of untrusted data in on-premises Microsoft SharePoint Server."},
                     {"lang": "es", "value": "Deserializacion"}],
    "metrics": {"cvssMetricV31": [
        {"source": "secure@microsoft.com", "type": "Secondary",
         "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:enterprise:*:*:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}],
}}]}
KEV = {"catalogVersion": "2026.09.01", "dateReleased": "2026-09-01T00:00:00Z", "vulnerabilities": [
    {"cveID": "CVE-2025-53770", "vendorProject": "Microsoft", "product": "SharePoint", "dateAdded": "2025-07-20",
     "dueDate": "2025-07-21", "requiredAction": "Disconnect public-facing versions of SharePoint Server that have reached EOL.",
     "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "Microsoft SharePoint Deserialization Vulnerability"}]}
EPSS = {"status": "OK", "data": [{"cve": "CVE-2025-53770", "epss": "0.90123", "percentile": "0.99567", "date": "2026-09-27"}]}


def mock_client(calls: list, fail: set[str] = frozenset()) -> httpx.Client:
    def handler(req: httpx.Request) -> httpx.Response:
        host = req.url.host
        calls.append(str(req.url))
        if any(f in host for f in fail):
            raise httpx.ConnectError("offline", request=req)
        if "nvd.nist.gov" in host:
            cve = req.url.params.get("cveId")
            return httpx.Response(200, json=NVD_53770 if cve == "CVE-2025-53770" else {"totalResults": 0, "vulnerabilities": []})
        if "cisa.gov" in host:
            return httpx.Response(200, json=KEV)
        if "first.org" in host:
            wanted = set(req.url.params.get("cve", "").split(","))
            return httpx.Response(200, json={"data": [d for d in EPSS["data"] if d["cve"] in wanted]})
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setattr(vulns, "NVD_INTERVAL", {"anonymous": 0.0, "key": 0.0})
    vulns._kev_mem.update(at=None, data=None)
    audit.reset_cache()
    with TestClient(app):  # runs startup (create_all + seed)
        pass
    with SessionLocal() as db:
        db.query(ExternalCache).delete()
        db.commit()
    yield
    vulns._kev_mem.update(at=None, data=None)


# ------------------------------------------------------------------ B06 CVE enrichment

def test_enrich_live_values_and_validation():
    calls: list = []
    out, summary = vulns.enrich(
        [{"cve": "cve-2025-53770", "cvss": 0.0, "affected_products": [], "source_ids": ["S1"]},
         {"cve": "CVE-2099-99999", "cvss": 0.0, "affected_products": ["X"], "source_ids": []},
         {"cve": "CVE-12", "cvss": 0.0}],
        client=mock_client(calls))
    a, b, c = out
    assert a["cve"] == "CVE-2025-53770" and a["cvss"] == 9.8 and a["cvss_version"] == "3.1"
    assert a["cvss_vector"].startswith("CVSS:3.1/AV:N") and a["cvss_severity"] == "critical"
    assert a["kev_added"] == "2025-07-20" and a["kev_ransomware"] == "Known" and a["kev_required_action"]
    assert a["epss"] == pytest.approx(0.90123) and a["epss_percentile"] == pytest.approx(0.99567)
    assert a["validation"] == "verified" and a["cwes"] == ["CWE-502"]
    assert a["description"].startswith("Deserialization")
    assert len(a["affected_cpes"]) == 2  # non-vulnerable CPE dropped
    assert "Microsoft SharePoint Server 2016 enterprise" in a["affected_products"]
    assert a["source_ids"] == ["S1"] and a["enrichment"]["nvd"] == "live"
    assert b["validation"] == "not_found" and b["kev_added"] is None and b["epss"] is None and b["affected_products"] == ["X"]
    assert c["validation"] == "invalid_format"
    assert summary["not_found"] == ["CVE-2099-99999"] and summary["invalid"] == ["CVE-12"]
    assert not any("CVE-12" in u for u in calls), "invalid ids are never sent"
    # second call is served from the 24 h cache: no HTTP at all
    calls2: list = []
    out2, s2 = vulns.enrich([{"cve": "CVE-2025-53770", "cvss": 0.0}], client=mock_client(calls2))
    assert calls2 == [] and out2[0]["cvss"] == 9.8 and s2["sources"] == {"nvd": "cache", "kev": "cache", "epss": "cache"}


def test_enrich_offline_fallback_keeps_existing_values():
    logs = []
    before = [{"cve": "CVE-2025-53770", "cvss": 9.8, "kev_added": "2025-07-20", "epss": None, "affected_products": ["SP"]}]
    out, summary = vulns.enrich(before, client=mock_client([], fail={"nvd", "cisa", "first"}),
                                logf=lambda m, level="info": logs.append((level, m)))
    v = out[0]
    assert v["cvss"] == 9.8 and v["kev_added"] == "2025-07-20" and v["affected_products"] == ["SP"]
    assert v["validation"] == "unchecked"
    assert summary["sources"] == {"nvd": "unavailable", "kev": "unavailable", "epss": "unavailable"}
    assert any(level == "warn" and "unavailable" in m for level, m in logs)


def test_enrich_stale_cache_used_when_offline():
    vulns.enrich([{"cve": "CVE-2025-53770", "cvss": 0.0}], client=mock_client([]))
    with SessionLocal() as db:  # age every cache row past the TTL
        for row in db.query(ExternalCache).all():
            row.fetched_at = datetime.now(timezone.utc) - timedelta(hours=30)
        db.commit()
    vulns._kev_mem.update(at=None, data=None)
    out, summary = vulns.enrich([{"cve": "CVE-2025-53770", "cvss": 0.0}], client=mock_client([], fail={"nvd", "cisa", "first"}))
    assert out[0]["cvss"] == 9.8 and out[0]["kev_added"] == "2025-07-20" and out[0]["epss"] == pytest.approx(0.90123)
    assert summary["sources"] == {"nvd": "stale", "kev": "stale", "epss": "stale"}


def test_enrich_disabled_and_unexpected_error(monkeypatch):
    monkeypatch.setattr(get_settings(), "cve_enrichment", False)
    out, s = vulns.enrich([{"cve": "CVE-2025-53770", "cvss": 1.0}], client=mock_client([]))
    assert out[0]["cvss"] == 1.0 and s["checked"] == 0
    monkeypatch.setattr(get_settings(), "cve_enrichment", True)
    monkeypatch.setattr(vulns, "kev_catalog", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    out, s = vulns.enrich([{"cve": "CVE-2025-53770", "cvss": 1.0}], client=mock_client([]))
    assert out[0]["cvss"] == 1.0 and "boom" in s["error"]


def test_enrich_cves_endpoint(monkeypatch):
    monkeypatch.setattr(vulns, "_client", lambda: mock_client([]))
    with TestClient(app) as c:
        v0 = c.get("/api/research/TR-2026-0142").json()["version"]
        r = c.post("/api/research/TR-2026-0142/enrich-cves", headers={"X-User": "averma"})
        assert r.status_code == 200, r.text
        body = r.json()
        by = {v["cve"]: v for v in body["vulnerabilities"]}
        assert by["CVE-2025-53770"]["epss"] == pytest.approx(0.90123) and by["CVE-2025-53770"]["validation"] == "verified"
        assert by["CVE-2025-49704"]["validation"] == "not_found"  # the mock only knows 53770
        assert body["changed"] and body["version"] == v0 + 1
        rec = c.get("/api/research/TR-2026-0142").json()["record"]
        assert {v["cve"]: v for v in rec["vulnerabilities"]}["CVE-2025-53770"]["kev_ransomware"] == "Known"
        lib = c.get("/api/library/cves/CVE-2025-53770").json()
        assert lib["epss"] == pytest.approx(0.90123) and lib["description"].startswith("Deserialization")
        # nothing new upstream: no new version
        again = c.post("/api/research/TR-2026-0142/enrich-cves").json()
        assert not again["changed"] and again["version"] == v0 + 1
        assert c.post("/api/research/NOPE/enrich-cves").status_code == 404


# ------------------------------------------------------------------ B13 run budget

def test_budget_state_math(monkeypatch):
    monkeypatch.setattr(get_settings(), "run_budgets", {"standard": {"max_minutes": 10, "max_tokens": 1000},
                                                        "quick": {"max_minutes": 5, "max_tokens": 500}})
    b = runner.budget_state("standard", 4 * 60, 100)
    assert (b["max_minutes"], b["max_tokens"], b["elapsed_minutes"], b["pct_time"], b["pct_tokens"], b["state"]) == \
           (10.0, 1000, 4.0, 40.0, 10.0, "ok")
    assert runner.budget_state("standard", 8 * 60, 0)["state"] == "warning"       # 80 % of time
    assert runner.budget_state("standard", 60, 850)["state"] == "warning"          # 85 % of tokens
    b = runner.budget_state("standard", 11 * 60, 0)
    assert b["state"] == "over" and b["pct_time"] == 110.0
    assert runner.budget_state("quick", 5 * 60, 0)["state"] == "over"
    assert runner.budget_state("unknown-depth", 60, 0)["max_minutes"] == 10.0     # falls back to standard
    assert runner.budget_state(None, 0, 0)["state"] == "ok"


def test_elapsed_is_union_of_stage_intervals():
    t0 = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
    iso = lambda m: (t0 + timedelta(minutes=m)).isoformat()  # noqa: E731
    run = SimpleNamespace(started_at=t0, finished_at=None, stage_status={
        "intake": {"state": "done", "started_at": iso(0), "finished_at": iso(1)},
        "synthesis": {"state": "done", "started_at": iso(1), "finished_at": iso(4)},
        "iocs": {"state": "done", "started_at": iso(2), "finished_at": iso(5)},        # parallel with synthesis
        "report": {"state": "done", "started_at": iso(30), "finished_at": iso(31)},    # retried later: gap not counted
        "export": {"state": "running", "started_at": iso(31)},
        "_budget": {"state": "warning"},
    })
    assert runner.elapsed_seconds(run, at=t0 + timedelta(minutes=32)) == pytest.approx(7 * 60)
    empty = SimpleNamespace(started_at=t0, finished_at=t0 + timedelta(minutes=3), stage_status={})
    assert runner.elapsed_seconds(empty) == pytest.approx(180)


def _make_run(run_id: str, minutes_used: float, tokens: int) -> None:
    t0 = datetime.now(timezone.utc) - timedelta(minutes=minutes_used)
    with SessionLocal() as db:
        db.query(Run).filter_by(id=run_id).delete()
        db.add(Run(id=run_id, research_id="TR-2026-0142", status="running", mode="offline", config={"depth": "standard"},
                   cost_tokens=tokens, started_at=t0,
                   stage_status={"intake": {"state": "done", "started_at": t0.isoformat(),
                                            "finished_at": datetime.now(timezone.utc).isoformat()}}))
        db.commit()


def test_budget_check_logs_once_and_enforces(monkeypatch):
    monkeypatch.setattr(get_settings(), "run_budgets", {"standard": {"max_minutes": 10, "max_tokens": 1_000_000}})
    _make_run("RUN-WP4-B1", 8.5, 0)
    assert runner._check_budget("RUN-WP4-B1", "synthesis") is True
    assert runner._check_budget("RUN-WP4-B1", "attack") is True
    with SessionLocal() as db:
        logs = db.query(RunLog).filter_by(run_id="RUN-WP4-B1").all()
        assert [(l.level, "budget at 85%" in l.message) for l in logs] == [("warn", True)]
        assert db.get(Run, "RUN-WP4-B1").stage_status["_budget"]["state"] == "warning"
    # over budget, not enforced: error logged once, run continues
    _make_run("RUN-WP4-B2", 12, 0)
    assert runner._check_budget("RUN-WP4-B2", "queries") is True
    assert runner._check_budget("RUN-WP4-B2", "report") is True
    with SessionLocal() as db:
        logs = db.query(RunLog).filter_by(run_id="RUN-WP4-B2").all()
        assert [l.level for l in logs] == ["error"] and "continues" in logs[0].message
    # enforced: stops
    monkeypatch.setattr(get_settings(), "budget_enforce", True)
    _make_run("RUN-WP4-B3", 12, 0)
    assert runner._check_budget("RUN-WP4-B3", "queries") is False
    with SessionLocal() as db:
        run = db.get(Run, "RUN-WP4-B3")
        assert run.stage_status["_budget"]["stopped"] is True
        assert runner.run_budget(run)["stopped"] is True
    with TestClient(app) as c:
        b = c.get("/api/runs/RUN-WP4-B3").json()["budget"]
        assert b["state"] == "over" and b["flagged"] == "over" and b["enforced"] is True and b["pct_time"] >= 100
        assert set(b) >= {"max_minutes", "max_tokens", "elapsed_minutes", "tokens", "pct_time", "pct_tokens", "state"}
        assert c.get("/api/runs/RUN-WP4-B1/budget").json()["state"] == "warning"


# ------------------------------------------------------------------ B14 view audit

def test_record_view_dedupe():
    t = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.query(AuditEvent).delete()
        db.commit()
    assert audit.record_view("jchen", "research", "TR-X", "/api/research/TR-X", at=t) is True
    assert audit.record_view("jchen", "research", "TR-X", "/api/research/TR-X", at=t + timedelta(minutes=3)) is False
    assert audit.record_view("riyer", "research", "TR-X", "/api/research/TR-X", at=t + timedelta(minutes=3)) is True
    assert audit.record_view("jchen", "actor", "TR-X", "/api/library/actors/TR-X", at=t + timedelta(minutes=3)) is True
    audit.reset_cache()  # DB check still dedupes after a restart
    assert audit.record_view("jchen", "research", "TR-X", "/api/research/TR-X", at=t + timedelta(minutes=5)) is False
    assert audit.record_view("jchen", "research", "TR-X", "/api/research/TR-X", at=t + timedelta(minutes=11)) is True
    with SessionLocal() as db:
        assert db.query(AuditEvent).filter_by(entity_id="TR-X").count() == 4


def test_view_audit_middleware_and_api():
    assert audit.match_view("GET", "/api/research/TR-2026-0142") == ("research", "TR-2026-0142")
    assert audit.match_view("GET", "/api/library/cves/cve-2025-53770") == ("cve", "CVE-2025-53770")
    assert audit.match_view("GET", "/api/research/TR-2026-0142/versions") is None
    assert audit.match_view("GET", "/api/library/actors") is None
    assert audit.match_view("PATCH", "/api/research/TR-2026-0142/record") is None
    with SessionLocal() as db:
        db.query(AuditEvent).delete()
        db.commit()
    with TestClient(app) as c:
        for _ in range(3):
            assert c.get("/api/research/TR-2026-0142", headers={"X-User": "jchen"}).status_code == 200
        c.get("/api/research/TR-2026-0142", headers={"X-User": "riyer"})
        c.get("/api/research/DOES-NOT-EXIST", headers={"X-User": "jchen"})  # 404: not audited
        actor = c.get("/api/library/actors").json()["items"][0]["id"]
        c.get(f"/api/library/actors/{actor}", headers={"X-User": "jchen"})
        c.get("/api/research", headers={"X-User": "jchen"})  # list views are not audited
        assert c.get("/api/audit", headers={"X-User": "jchen"}).status_code == 403  # hunter
        a = c.get("/api/audit", headers={"X-User": "skapoor"}).json()  # lead
        assert a["total"] == 3
        r = c.get("/api/audit", params={"entity": "TR-2026-0142"}, headers={"X-User": "skapoor"}).json()
        assert r["total"] == 2 and {x["user"]["id"] for x in r["items"]} == {"jchen", "riyer"}
        r = c.get("/api/audit", params={"entity": "TR-2026-0142", "user": "jchen", "limit": 1}, headers={"X-User": "skapoor"}).json()
        assert r["total"] == 1 and r["items"][0]["path"] == "/api/research/TR-2026-0142" and r["items"][0]["action"] == "view"
        r = c.get("/api/audit", params={"entity": f"actor:{actor}"}, headers={"X-User": "skapoor"}).json()
        assert r["total"] == 1 and r["items"][0]["entity_type"] == "actor"

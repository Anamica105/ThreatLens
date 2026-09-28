"""End-to-end smoke tests against a throwaway SQLite database (offline pipeline, no network needed for most checks)."""

import os
import tempfile
import time
from pathlib import Path

_tmp = Path(tempfile.mkdtemp())
os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"
os.environ["ANTHROPIC_API_KEY"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def client() -> TestClient:
    return TestClient(app)


def test_seed_and_reads():
    with client() as c:
        assert c.get("/api/health").json()["ok"]
        meta = c.get("/api/meta").json()
        assert len(meta["tactics"]) == 14 and meta["llm"]["available"] is False
        lst = c.get("/api/research").json()
        assert lst["total"] >= 5
        d = c.get("/api/research/TR-2026-0142?ws=northwind").json()
        rec = d["record"]
        assert len({m["technique_id"] for m in rec["mitre"]}) == 21
        assert rec["hunts"]["queries"], "queries generated"
        assert d["result"]["status"] == "no_evidence"
        assert any(g["workspace_id"] == "acme" for g in rec["coverage_gaps"])  # Acme has no IIS logs
        assert c.get("/api/library/actors").json()["items"]
        assert c.get("/api/library/queries").json()["total"] > 10
        assert c.get("/api/library/iocs").json()["total"] >= 10
        assert c.get("/api/dashboard?period=quarter").json()["kpis"]["runs"] >= 1
        s = c.get("/api/search", params={"q": "104.238.159[.]149"}).json()
        assert s["jump"] and s["jump"]["kind"] == "ioc"
        dup = c.post("/api/research/check-duplicates", json={"seed": "New wave hitting CVE-2025-53770"}).json()
        assert dup["matches"][0]["id"] == "TR-2026-0142"


def test_lint_and_translate():
    from app import detection
    for p in detection.PLATFORM_IDS:
        if p == "sigma":
            continue
        body = detection.translate({"category": "process_creation", "conditions": [
            {"field": "parent_image", "op": "endswith", "values": ["\\w3wp.exe"]},
            {"field": "image", "op": "endswith", "values": ["\\cmd.exe"]}]}, p, 30, "t")
        assert body, p
        assert detection.lint(p, body) == [], (p, detection.lint(p, body), body)


def test_iocs():
    from app.ioc import defang, extract, refang
    items = extract("C2 at hxxps://update[.]updatemicfosoft[.]com/x and 104.238.159[.]149 plus 10.0.0.1 and microsoft.com; "
                    "hash 92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514")
    kinds = {(i.type, i.value) for i in items}
    assert ("ipv4", "104.238.159.149") in kinds
    assert not any(v == "10.0.0.1" for _, v in kinds)
    assert not any("microsoft.com" == v for _, v in kinds)
    assert ("url", "https://update.updatemicfosoft.com/x") in kinds
    assert defang("https://a.b.com/x", "url") == "hxxps://a[.]b[.]com/x"
    assert refang("104.238.159[.]149") == "104.238.159.149"


def test_exports_and_workflow():
    with client() as c:
        rid = "TR-2026-0142"
        for fmt in ("html", "email", "json", "iocs_csv", "queries_csv", "pptx", "eml"):
            r = c.get(f"/api/research/{rid}/export/{fmt}?ws=northwind")
            assert r.status_code == 200, (fmt, r.text[:300])
            assert len(r.content) > 500
        r = c.post("/api/exports/period", json={"period": "quarter", "format": "xlsx"})
        assert r.status_code == 200 and r.content[:2] == b"PK"
        # edit -> back to review -> hunter cannot publish, reviewer can
        r = c.patch(f"/api/research/{rid}/record", json={"changes": {"title": "ToolShell: edited title"}}, headers={"X-User": "averma"})
        assert r.status_code == 200
        assert c.get(f"/api/research/{rid}").json()["status"] == "in_review"
        assert c.post(f"/api/research/{rid}/status", json={"action": "publish"}, headers={"X-User": "averma"}).status_code == 403
        assert c.post(f"/api/research/{rid}/status", json={"action": "publish"}, headers={"X-User": "riyer"}).status_code == 200
        r = c.put(f"/api/research/{rid}/results/acme", json={"status": "no_evidence", "summary": "ok"})
        assert r.status_code == 200


def test_offline_run_from_seed_text():
    with client() as c:
        seed = ("Threat brief: attackers exploited CVE-2025-53770 in SharePoint.\n" +
                "The attackers used w3wp.exe to spawn cmd.exe and powershell -enc to write spinstall0.aspx web shell. "
                "They used Mimikatz against LSASS and deployed ransomware through group policy. "
                "C2 traffic went to 65.38.121[.]198 and update[.]updatemicfosoft[.]com. Organizations should patch and rotate machinekey. " * 3)
        r = c.post("/api/research", json={"seed": seed, "workspace_ids": ["northwind"], "platforms": ["kql_defender", "spl", "sigma"],
                                          "vendors": ["cisa"], "open_web": False, "depth": "quick", "offline": True})
        assert r.status_code == 200, r.text
        run_id, rid = r.json()["run_id"], r.json()["id"]
        for _ in range(240):
            run = c.get(f"/api/runs/{run_id}").json()
            if run["status"] in ("done", "failed"):
                break
            time.sleep(0.5)
        states = {s["id"]: s["state"] for s in run["stages"]}
        assert run["status"] == "done", (states, [l["message"] for l in run["logs"] if l["level"] in ("error", "warn")])
        d = c.get(f"/api/research/{rid}").json()
        rec = d["record"]
        assert d["status"] == "draft"
        assert any(m["technique_id"] == "T1505.003" for m in rec["mitre"])
        assert any(i["value"] == "65.38.121[.]198" for i in rec["iocs"]), (rec["iocs"], run["logs"])
        assert rec["hunts"]["queries"]
        # re-run just query generation for a new platform
        r = c.post(f"/api/research/{rid}/rerun", json={"from_stage": "queries", "platforms": ["kql_defender", "spl", "cql", "sigma"]})
        assert r.status_code == 200, r.text
        for _ in range(120):
            run = c.get(f"/api/runs/{run_id}").json()
            if run["status"] in ("done", "failed") and not run["active"]:
                break
            time.sleep(0.5)
        rec = c.get(f"/api/research/{rid}").json()["record"]
        assert any(q["platform"] == "cql" for q in rec["hunts"]["queries"])

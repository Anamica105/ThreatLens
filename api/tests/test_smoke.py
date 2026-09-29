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
        _assert_query_contract(rec)
        assert {q["platform"] for q in rec["hunts"]["queries"]} <= {"kql_defender", "spl", "cql", "sigma"}
        assert not any(q["provenance"] == "generic" for q in rec["hunts"]["queries"])
        # opt in to generic TTP hunts on a re-run: they appear, capped, with provenance "generic"
        r = c.post(f"/api/research/{rid}/rerun", json={"from_stage": "queries", "include_generic_hunts": True})
        assert r.status_code == 200, r.text
        for _ in range(120):
            run = c.get(f"/api/runs/{run_id}").json()
            if run["status"] in ("done", "failed") and not run["active"]:
                break
            time.sleep(0.5)
        rec = c.get(f"/api/research/{rid}").json()["record"]
        _assert_query_contract(rec)
        generic = {q["group"] for q in rec["hunts"]["queries"] if q["provenance"] == "generic"}
        assert 1 <= len(generic) <= 5, generic


# ------------------------------------------------------------------ source trail + query volume contract

MAX_TOOLSHELL_VARIANTS = 50
PROVENANCE_KEYS = {"research_id", "research_title", "source_id", "publisher", "title", "url", "quote"}


def _assert_query_contract(rec: dict) -> None:
    qs = rec["hunts"]["queries"]
    source_ids = {s["id"] for s in rec.get("sources", [])}
    for q in qs:
        assert isinstance(q.get("group"), str) and q["group"], q["id"]
        assert isinstance(q.get("source_ids"), list), q["id"]
        assert q.get("provenance") in ("vendor", "derived", "generic"), q["id"]
        if source_ids:
            assert set(q["source_ids"]) <= source_ids, (q["id"], q["source_ids"])
        if q["provenance"] == "vendor":
            assert q["origin"] == "reference"
    for o in rec["detection_opportunities"]:
        assert isinstance(o.get("source_ids"), list), o["id"]
    # every platform variant of a group shares the same title and source trail, one variant per platform
    by_group: dict[str, list[dict]] = {}
    for q in qs:
        by_group.setdefault(q["group"], []).append(q)
    for g, variants in by_group.items():
        assert len({v["title"] for v in variants}) == 1, g
        assert len({tuple(v["source_ids"]) for v in variants}) == 1, g
        assert len({v["platform"] for v in variants}) == len(variants), (g, "duplicate platform in group")


def test_toolshell_query_contract_and_volume():
    with client() as c:
        rec = c.get("/api/research/TR-2026-0142").json()["record"]
        _assert_query_contract(rec)
        qs = rec["hunts"]["queries"]
        groups = {q["group"] for q in qs}
        assert len(qs) < MAX_TOOLSHELL_VARIANTS, len(qs)
        assert 8 <= len(groups) <= 15, sorted(groups)
        assert {q["platform"] for q in qs} <= set(rec["hunts"]["platforms"])
        assert len(rec["hunts"]["platforms"]) <= 5
        assert not any(q["provenance"] == "generic" for q in qs), "generic hunts are opt-in"
        # one IoC retro-hunt group per indicator type, one vulnerability group
        assert {g for g in groups if g.startswith("IOC-")} == {"IOC-IPV4", "IOC-DOMAIN", "IOC-SHA256"}
        assert {q["group"] for q in qs if q["type"] == "vuln"} == {"VULN-1"}
        # every opportunity group has a Sigma rule (neutral source of truth) and a source trail
        for o in rec["detection_opportunities"]:
            assert o["source_ids"], o["id"]
            variants = [q for q in qs if q["opportunity_id"] == o["id"]]
            assert any(q["platform"] == "sigma" for q in variants), o["id"]
            assert all(q["source_ids"] == o["source_ids"] for q in variants)
        do2 = next(o for o in rec["detection_opportunities"] if o["id"] == "DO-2")
        assert do2["source_ids"] == ["S1", "S3"]  # from attack-path step AP-1.2
        ipv4 = [q for q in qs if q["group"] == "IOC-IPV4"]
        assert ipv4[0]["source_ids"] == ["S1", "S2", "S3", "S5"]


def test_generate_queries_rules():
    from app.db import SessionLocal
    from app.pipeline.stages import generate_queries, select_opportunities

    xd = {"category": "process_creation", "conditions": [{"field": "image", "op": "endswith", "values": ["\\xd.exe"]}]}
    paths = [{"id": "AP-1", "steps": [{"ref": "AP-1.1", "technique_id": "T1090", "source_ids": ["S2"]},
                                      {"ref": "AP-1.2", "technique_id": "T1059.001", "source_ids": []}]}]
    mitre = [{"technique_id": "T1059.001", "source_ids": ["S4"]}, {"technique_id": "T1003.001", "source_ids": ["S1"]}]
    raw = [
        {"behaviour_ref": "AP-1.1", "title": "a", "type": "ioa", "techniques": ["T1090"], "fp_notes": "", "spec": xd},
        {"behaviour_ref": "AP-1.1", "title": "a duplicate", "type": "ioa", "techniques": ["T1090"], "fp_notes": "", "spec": xd},
    ] + [{"behaviour_ref": "AP-1.2", "title": f"c{i}", "type": "ioa", "techniques": ["T1059.001"], "fp_notes": "",
          "spec": {"category": "process_creation", "conditions": [{"field": "command_line", "op": "contains", "values": [f"x{i}"]}]}}
         for i in range(4)]
    opps = select_opportunities(raw, paths, mitre)
    assert len(opps) == 3  # duplicate logic merged, AP-1.2 capped at 2
    assert opps[0]["source_ids"] == ["S2"]  # from the attack-path step
    assert opps[1]["source_ids"] == ["S4"]  # step has none -> MITRE rows of its technique
    with SessionLocal() as db:
        vq = [{"platform": "kql_defender", "title": "MS hunt", "query": "DeviceProcessEvents | take 1", "source_id": "S1"},
              {"platform": "kql_defender", "title": "MS hunt again", "query": "DeviceProcessEvents  |  take 1", "source_id": "S3"}]
        base = dict(opps=opps, platforms=["sigma", "spl", "kql_defender"], days=30,
                    ioc_values={"ipv4": {"1.2.3.4": ["S1"], "5.6.7.8": ["S2", "S1"]}, "domain": {}, "sha256": {}},
                    cves=[{"cve": "CVE-2025-1", "source_ids": ["S3"]}], techniques=["T1003.001"], vendor_queries=vq)
        qs = generate_queries(db, **base, mitre=mitre)
        assert {q["platform"] for q in qs} <= {"sigma", "spl", "kql_defender"}
        assert not any(q["provenance"] == "generic" for q in qs)
        ioc = [q for q in qs if q["type"] == "ioc"]
        assert {q["group"] for q in ioc} == {"IOC-IPV4"} and ioc[0]["source_ids"] == ["S1", "S2"]
        vuln = [q for q in qs if q["type"] == "vuln"]
        assert vuln and all(q["group"] == "VULN-1" and q["source_ids"] == ["S3"] for q in vuln)
        vendor = [q for q in qs if q["provenance"] == "vendor"]
        assert len(vendor) == 1 and vendor[0]["source_ids"] == ["S1"] and vendor[0]["group"].startswith("VREF-")
        gen = generate_queries(db, **base, mitre=mitre, include_generic=True, max_generic=1)
        generic = [q for q in gen if q["provenance"] == "generic"]
        assert generic and len({q["group"] for q in generic}) == 1
        assert all(q["source_ids"] == ["S1"] for q in generic)  # MITRE rows of T1003.001
        db.rollback()


def test_library_provenance():
    with client() as c:
        actors = c.get("/api/library/actors").json()["items"]
        storm = next(a for a in actors if a["name"] == "Storm-2603")
        assert storm["source_count"] == 3 and "Microsoft Threat Intelligence" in storm["publishers"]
        d = c.get(f"/api/library/actors/{storm['id']}").json()
        assert {p["source_id"] for p in d["provenance"]} == {"S1", "S2", "S4"}
        assert all(set(p) == PROVENANCE_KEYS for p in d["provenance"])
        assert all(p["research_id"] == "TR-2026-0142" and p["url"].startswith("https://") for p in d["provenance"])

        mal = c.get("/api/library/malware").json()["items"]
        warlock = next(m for m in mal if m["name"] == "Warlock")
        assert warlock["source_count"] == 2
        md = c.get(f"/api/library/malware/{warlock['id']}").json()
        assert {p["source_id"] for p in md["provenance"]} == {"S1", "S4"}
        assert any(p["quote"] for p in md["provenance"])

        ql = c.get("/api/library/queries", params={"page_size": 500}).json()
        assert ql["items"] and all(q["group"] and q["group_id"] and q["provenance_kind"] for q in ql["items"])
        q0 = next(q for q in ql["items"] if q["title"].startswith("IIS worker spawns a shell"))
        qd = c.get(f"/api/library/queries/{q0['id']}").json()
        assert {p["source_id"] for p in qd["provenance"]} == {"S1", "S3"}
        assert all(set(p) == PROVENANCE_KEYS for p in qd["provenance"])
        assert len(qd["siblings"]) >= 2 and all(s["platform"] != qd["platform"] for s in qd["siblings"])
        grp = c.get("/api/library/queries", params={"group_id": q0["group_id"]}).json()
        assert grp["total"] == len(qd["siblings"]) + 1

        il = c.get("/api/library/iocs", params={"q": "104.238.159"}).json()["items"]
        assert il and il[0]["source_count"] == 4
        idt = c.get(f"/api/library/iocs/{il[0]['id']}").json()
        assert {p["source_id"] for p in idt["provenance"]} == {"S1", "S2", "S3", "S5"}
        assert idt["provenance"][0]["quote"]

"""W2: pySigma backends (spec 8 step 3), query `engine` provenance, read-time coverage gaps."""

import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp())
os.environ.setdefault("DATABASE_URL", f"sqlite:///{(_tmp / 'test.db').as_posix()}")
os.environ["ANTHROPIC_API_KEY"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import detection, sigma_backends  # noqa: E402
from app.main import app  # noqa: E402
from app.records import compute_coverage_gaps, coverage_gaps  # noqa: E402
from app.seed import OPPORTUNITIES  # noqa: E402

DO2 = OPPORTUNITIES[1]  # w3wp -> cmd -> encoded PowerShell (process_creation)
DO3 = OPPORTUNITIES[2]  # .aspx written under TEMPLATE\LAYOUTS (file_event)
DO1 = OPPORTUNITIES[0]  # ToolPane.aspx POST (webserver)


def _sigma(o, rid="DO-2"):
    return detection.to_sigma(o["title"], o["spec"], rid, o["techniques"], o["fp_notes"])


def test_generated_sigma_is_valid_pysigma():
    for i, o in enumerate(OPPORTUNITIES, 1):
        coll = sigma_backends.parse(_sigma(o, f"DO-{i}"))
        assert len(coll.rules) == 1
    # Titles/notes with YAML-special characters and literal backslashes before wildcards survive.
    spec = {"category": "network", "conditions": [{"field": "dst_ip", "op": "equals", "values": ["1.2.3.4"]}]}
    y = detection.to_sigma("Retro-hunt: 1 IPV4 indicator(s)", spec, "IOC-IPV4", [], "Shared infra: check 'timestamps'")
    rule = sigma_backends.parse(y).rules[0]
    assert rule.title == "Retro-hunt: 1 IPV4 indicator(s)"
    assert str(rule.id) == detection.sigma_uuid("IOC-IPV4") and "IOC-IPV4" in y
    wmi = sigma_backends.parse(_sigma(OPPORTUNITIES[5], "DO-6")).rules[0]
    vals = [str(v) for d in wmi.detection.detections.values() for item in d.detection_items for v in item.value]
    assert any("\\\\127.0.0.1\\ADMIN$\\__" in v for v in vals)


def test_pysigma_spl_kql_esql_for_toolshell():
    spl = detection.render_query(DO2["spec"], "spl", 30, DO2["title"], _sigma(DO2))
    assert spl["engine"] == "pysigma:splunk"
    assert spl["body"].startswith('index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1')
    assert "earliest=-30d" in spl["body"] and 'Image IN ("*\\\\powershell.exe", "*\\\\pwsh.exe")' in spl["body"]
    assert "| stats count" in spl["body"] and detection.lint("spl", spl["body"]) == []

    kql = detection.render_query(DO2["spec"], "kql_defender", 30, DO2["title"], _sigma(DO2))
    assert kql["engine"] == "pysigma:kusto_xdr"
    assert kql["body"].startswith("DeviceProcessEvents\n| where Timestamp > ago(30d)")
    # A file-NAME column never ends with "\w3wp.exe": post-processing compares the base name.
    assert 'InitiatingProcessParentFileName =~ "w3wp.exe"' in kql["body"]
    assert detection.lint("kql_defender", kql["body"]) == []

    raw = sigma_backends.translate_sigma(_sigma(DO3, "DO-3"), "esql")
    assert raw and "file.path" in raw
    esql = detection.render_query(DO3["spec"], "esql", 14, DO3["title"], _sigma(DO3, "DO-3"))
    assert esql["engine"] == "pysigma:esql"
    assert esql["body"].startswith("FROM logs-endpoint.events.file-*\n| WHERE @timestamp > NOW() - 14 days")
    assert "| KEEP" in esql["body"] and detection.lint("esql", esql["body"]) == []

    sent = detection.render_query(DO3["spec"], "kql_sentinel", 30, DO3["title"], _sigma(DO3, "DO-3"))
    assert sent["engine"] == "pysigma:kusto_asim" and sent["body"].startswith("imFileEvent\n| where TimeGenerated > ago(30d)")
    assert sent["log_sources"] and "ASIM" in sent["log_sources"][0]
    assert detection.lint("kql_sentinel", sent["body"]) == []


def test_fallback_to_builtin():
    # Platforms without a pySigma backend.
    for p in ("cql", "s1ql", "xql", "yaral", "aql"):
        assert sigma_backends.translate_sigma(_sigma(DO2), p) is None
        r = detection.render_query(DO3["spec"], p, 30, DO3["title"])
        assert r["engine"] == "builtin" and r["body"] == detection.translate(DO3["spec"], p, 30, DO3["title"])
    # Log source the pipeline does not map (IIS webserver fields) -> built-in.
    web = detection.render_query(DO1["spec"], "spl", 30, DO1["title"], _sigma(DO1, "DO-1"))
    assert web["engine"] == "builtin" and "cs_method" in web["body"]
    # Backend error (Defender pipeline rejects Hashes|contains) -> built-in.
    h = detection.render_ioc_query("kql_defender", "file_hash", ["a" * 64])
    assert h["engine"] == "builtin" and "SHA256" in h["body"]
    # Neither engine -> None (caller asks the LLM).
    assert detection.render_query(DO2["spec"], "esql", 30, DO2["title"]) is None
    assert sigma_backends.translate_sigma("title: [broken", "spl") is None
    # use_pysigma=False forces the built-in translator.
    assert detection.render_query(DO3["spec"], "spl", 30, "t", use_pysigma=False)["engine"] == "builtin"


def test_mappings_and_lint_apply_to_pysigma_output():
    r = detection.render_query(DO3["spec"], "spl", 30, DO3["title"])
    m = detection.map_query({"body": r["body"], "platform": "spl"}, {"spl": {"index=endpoint": "index=edr_sysmon"}})
    assert m["mapping_applied"] and m["mapped_body"].startswith("index=edr_sysmon ") and m["mapped_lint"] == []


def test_engine_field_in_generation_and_regeneration():
    from app.db import SessionLocal
    from app.pipeline.stages import generate_queries, regenerate_detection_queries

    with TestClient(app):
        pass
    opps = [{**o, "id": f"DO-{i}", "data_sources": [o["spec"]["category"]]} for i, o in enumerate(OPPORTUNITIES[:3], 1)]
    with SessionLocal() as db:
        qs = generate_queries(db, opps, ["sigma", "spl", "kql_defender", "cql"], 30,
                              {"ipv4": {"1.2.3.4": ["S1"]}, "domain": {}, "sha256": {}}, ["CVE-2025-53770"], [], [],
                              llm_fill=lambda missing: [{"opportunity_id": m["opportunity"]["id"], "platform": m["platform"],
                                                         "query": "DeviceProcessEvents | take 1"} for m in missing],
                              )
        db.rollback()
    by = {(q["opportunity_id"], q["platform"]): q for q in qs if q["opportunity_id"]}
    assert by[("DO-2", "sigma")]["engine"] == "builtin"
    assert by[("DO-2", "spl")]["engine"] == "pysigma:splunk"
    assert by[("DO-2", "kql_defender")]["engine"] == "pysigma:kusto_xdr"
    assert by[("DO-2", "cql")]["engine"] == "builtin"
    assert by[("DO-1", "spl")]["engine"] == "builtin"  # webserver
    assert by[("DO-1", "kql_defender")]["engine"] == "llm"  # no telemetry either way -> LLM fill
    ioc = {q["platform"]: q for q in qs if q["type"] == "ioc"}
    assert ioc["kql_defender"]["engine"] == "pysigma:kusto_xdr" and "RemoteIP" in ioc["kql_defender"]["body"]
    assert all(q["engine"] == "builtin" for q in qs if q["type"] == "vuln")
    assert all(q.get("engine") for q in qs)

    # Regeneration: auto-status builtin query -> pySigma; reviewed and LLM queries untouched.
    old_spl = detection.translate(DO2["spec"], "spl", 30, DO2["title"])
    rec = {"detection_opportunities": opps, "hunts": {"lookback_days": 30, "queries": [
        {"id": "Q-1", "group": "DET-2", "type": "ioa", "platform": "sigma", "origin": "generated", "opportunity_id": "DO-2",
         "body": "title: x", "status": "syntax_checked", "engine": None},
        {"id": "Q-2", "group": "DET-2", "type": "ioa", "platform": "spl", "origin": "generated", "opportunity_id": "DO-2",
         "body": old_spl, "status": "syntax_checked"},
        {"id": "Q-3", "group": "DET-2", "type": "ioa", "platform": "kql_defender", "origin": "generated",
         "opportunity_id": "DO-2", "body": "DeviceProcessEvents", "status": "reviewed"},
        {"id": "Q-4", "group": "DET-1", "type": "ioa", "platform": "kql_defender", "origin": "generated",
         "opportunity_id": "DO-1", "body": "W3CIISLog | take 1", "status": "generated", "engine": "llm"}]}}
    changed = regenerate_detection_queries(rec)
    q = {x["id"]: x for x in rec["hunts"]["queries"]}
    assert set(changed) == {"Q-1", "Q-2"}
    assert q["Q-2"]["engine"] == "pysigma:splunk" and "earliest=-30d" in q["Q-2"]["body"]
    assert q["Q-1"]["body"].startswith("title: ") and "id: " + detection.sigma_uuid("DO-2") in q["Q-1"]["body"]
    assert q["Q-3"]["body"] == "DeviceProcessEvents" and q["Q-4"]["engine"] == "llm"


def _rec():
    return {
        "detection_opportunities": [{"id": "DO-1", "behaviour_ref": "AP-1.1", "type": "ioa", "data_sources": ["web"]},
                                    {"id": "DO-2", "behaviour_ref": "AP-1.2", "type": "ioa", "data_sources": ["process_creation"]}],
        "hunts": {"queries": [
            {"id": "Q-1", "group": "DET-1", "type": "ioa", "opportunity_id": "DO-1", "data_sources": ["web"]},
            {"id": "Q-2", "group": "IOC-IPV4", "type": "ioc", "data_sources": ["network"]},
            {"id": "Q-3", "group": "IOC-IPV4", "type": "ioc", "data_sources": ["network"]},
            {"id": "Q-4", "group": "IOC-SHA256", "type": "ioc", "data_sources": ["file_hash"]},
            {"id": "Q-5", "group": "VULN-1", "type": "vuln", "data_sources": ["vuln_mgmt"]},
            {"id": "Q-6", "group": "VREF-1", "type": "ioa", "origin": "reference", "data_sources": ["dns"]}]}}


def test_coverage_gaps_cover_all_query_types_and_follow_workspace_settings():
    ws = {"id": "acme", "name": "Acme", "log_sources": ["process_creation", "network"]}
    gaps = compute_coverage_gaps(_rec(), [ws])
    key = {(g["kind"], g["data_source"], g["opportunity_id"] or g["group"]) for g in gaps}
    assert key == {("detection", "web", "DO-1"), ("ioc", "file_hash", "IOC-SHA256"), ("vuln", "vuln_mgmt", "VULN-1")}
    assert all(g["workspace_id"] == "acme" and "Acme has no" in g["detail"] for g in gaps)

    # Workspace adds IIS + vulnerability data and drops network telemetry -> gaps change on the next read.
    ws2 = {**ws, "log_sources": ["process_creation", "web", "file_hash", "vuln_mgmt"]}
    gaps2 = compute_coverage_gaps(_rec(), [ws2])
    assert {(g["kind"], g["data_source"], g["group"]) for g in gaps2} == {("ioc", "network", "IOC-IPV4")}

    # Several workspaces; the one-workspace wrapper keeps working with ORM-like objects.
    class W:
        id, name, log_sources = "nw", "Northwind", ["web", "process_creation", "network", "file_hash", "vuln_mgmt"]
    assert compute_coverage_gaps(_rec(), [ws, W()]) == gaps
    assert coverage_gaps(_rec(), W()) == []


def test_refresh_coverage_gaps_reads_current_workspace():
    from app.db import SessionLocal
    from app.models import Workspace
    from app.records import refresh_coverage_gaps

    with TestClient(app):
        pass
    with SessionLocal() as db:
        ws = db.query(Workspace).first()
        if ws is None:
            pytest.skip("no seeded workspace")
        before = list(ws.log_sources or [])
        try:
            ws.log_sources = ["process_creation"]
            db.flush()
            rec = refresh_coverage_gaps(db, _rec(), [ws.id])
            assert {g["data_source"] for g in rec["coverage_gaps"]} == {"web", "network", "file_hash", "vuln_mgmt"}
            ws.log_sources = ["process_creation", "web", "network", "file_hash", "vuln_mgmt"]
            db.flush()
            assert refresh_coverage_gaps(db, rec)["coverage_gaps"] == []  # ids default to the referenced workspaces
        finally:
            ws.log_sources = before
            db.rollback()

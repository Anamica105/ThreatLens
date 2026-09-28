"""R1: grounding gate (B03) and reviewer editing of MITRE rows, attack paths and title (B04)."""

import copy
import os
import tempfile
from pathlib import Path

if "DATABASE_URL" not in os.environ:  # standalone run; under a full pytest run another module may have set it
    _tmp = Path(tempfile.mkdtemp())
    os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"
os.environ["ANTHROPIC_API_KEY"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import guardrails  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import ActivityEvent, Ioc, Research, ResearchLink, ResearchVersion  # noqa: E402

REVIEWER = {"X-User": "riyer"}
LEAD = {"X-User": "skapoor"}
HUNTER = {"X-User": "averma"}
_n = [0]


@pytest.fixture()
def c():
    with TestClient(app) as cl:
        yield cl


def make_research(status: str = "in_review", mutate=None) -> str:
    """A copy of the fully sourced ToolShell record under a new id (without IoCs and queries, so the shared libraries
    other modules assert on are untouched). Removed again by `cleanup`."""
    _n[0] += 1
    rid = f"TR-2099-{_n[0]:04d}"
    with SessionLocal() as db:
        src = db.get(Research, "TR-2026-0142")
        rec = copy.deepcopy(src.record)
        rec["run"] = {"id": f"RUN-{rid}", "mode": "llm", "tokens": 0}
        rec["review"], rec["_edited"] = {}, []
        rec["iocs"], rec["hunts"] = [], {**rec["hunts"], "queries": []}
        if mutate:
            mutate(rec)
        db.add(Research(id=rid, title=rec["title"], status=status, created_by="averma", workspace_ids=src.workspace_ids,
                        seed="test", tlp="AMBER", record=rec, search_text="r1 test", version=1))
        db.commit()
    return rid


def cleanup(rid: str) -> None:
    with SessionLocal() as db:
        for model in (ResearchLink, ResearchVersion, ActivityEvent):
            db.query(model).filter_by(research_id=rid).delete()
        for row in db.query(Ioc).all():
            if any(x.get("research_id") == rid for x in row.context or []):
                row.context = [x for x in row.context if x.get("research_id") != rid]
        db.delete(db.get(Research, rid))
        db.commit()


# ------------------------------------------------------------------ unit: quote matching

def test_quote_matching_is_whitespace_case_and_ellipsis_tolerant():
    text = "The actor  uploaded\n a web shell named “spinstall0.aspx” to the LAYOUTS folder, then ran PowerShell."
    assert guardrails.quote_in_text('uploaded a web shell named "spinstall0.aspx"', text)
    assert guardrails.quote_in_text("the actor uploaded a web shell named spinstall0.aspx to the layouts folder ... ran powershell", text)
    assert not guardrails.quote_in_text("the actor exfiltrated the NTDS database over DNS tunnelling", text)


def test_quote_check_uses_stored_articles(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "data_dir", tmp_path)
    (tmp_path / "articles" / "RUN-X").mkdir(parents=True)
    (tmp_path / "articles" / "RUN-X" / "S1.txt").write_text("Attackers ran whoami and then dumped LSASS memory.", encoding="utf-8")
    rec = {"sources": [{"id": "S1"}, {"id": "S2"}], "run": {"id": "RUN-X"}, "mitre": [
        {"technique_id": "T1033", "evidence_quote": "Attackers ran whoami", "source_ids": ["S1"]},
        {"technique_id": "T1003.001", "evidence_quote": "used Mimikatz against domain controllers", "source_ids": ["S1"]},
        {"technique_id": "T1082", "evidence_quote": "no article on disk for S2", "source_ids": ["S2"]}]}
    issues = guardrails.check(rec)
    assert [(i["index"], i["kind"], i["severity"]) for i in issues] == [(1, "quote_not_found", "block")]
    # Without the article text the check is skipped, not failed.
    assert guardrails.check({**rec, "run": {"id": "RUN-MISSING"}}) == []


# ------------------------------------------------------------------ B03 gate

def test_gate_blocks_publish_until_fixed(c):
    def unsupported(rec):
        rec["claims"] = [{"statement": "The actor is state sponsored.", "source_ids": [], "status": "stated"}]
        rec["threat_actors"][0]["source_ids"] = ["S99"]
    rid = make_research(mutate=unsupported)
    try:
        rd = c.get(f"/api/research/{rid}/readiness").json()
        kinds = {(i["section"], i["kind"]) for i in rd["issues"]}
        assert not rd["ready"] and rd["blocking"] == 2
        assert kinds == {("claims", "missing_source"), ("threat_actors", "unknown_source")}
        r = c.post(f"/api/research/{rid}/status", json={"action": "publish"}, headers=REVIEWER)
        assert r.status_code == 409 and r.json()["blocking"] == 2 and "Cannot publish" in r.json()["detail"]
        assert c.get(f"/api/research/{rid}").json()["status"] == "in_review"

        rec = c.get(f"/api/research/{rid}").json()["record"]
        actors = rec["threat_actors"]
        actors[0]["source_ids"] = ["S1"]
        claims = [{"statement": "The actor is state sponsored.", "source_ids": ["S1"], "status": "stated"}]
        assert c.patch(f"/api/research/{rid}/record", json={"changes": {"threat_actors": actors, "claims": claims}},
                       headers=REVIEWER).status_code == 200
        rd = c.get(f"/api/research/{rid}/readiness").json()
        assert rd["ready"] and rd["blocking"] == 0
        r = c.post(f"/api/research/{rid}/status", json={"action": "publish"}, headers=REVIEWER)
        assert r.status_code == 200 and r.json()["status"] == "published"
        # Publishing no longer bulk-approves sections (that would silently waive the gate after later edits).
        assert "mitre" not in (c.get(f"/api/research/{rid}").json()["record"].get("review") or {}) or \
            c.get(f"/api/research/{rid}").json()["record"]["review"]["mitre"] != "approved"
    finally:
        cleanup(rid)


def test_edited_or_approved_items_downgrade_to_warn(c):
    rid = make_research(mutate=lambda rec: rec["mitre"][0].update(source_ids=[]))
    try:
        assert c.get(f"/api/research/{rid}/readiness").json()["blocking"] == 1
        # A hunter-written recommendation without a source is flagged but does not block (it was edited).
        recs = c.get(f"/api/research/{rid}").json()["record"]["recommendations"]
        recs.append({"horizon": "strategic", "action": "Review IIS module inventory monthly.", "owner_role": "IT", "source_ids": []})
        c.patch(f"/api/research/{rid}/record", json={"changes": {"recommendations": recs}}, headers=REVIEWER)
        rd = c.get(f"/api/research/{rid}/readiness").json()
        assert rd["blocking"] == 1 and rd["warnings"] == 1
        assert next(i for i in rd["issues"] if i["section"] == "recommendations")["severity"] == "warn"
        # Explicit reviewer approval of the MITRE section downgrades its unsupported row.
        assert c.post(f"/api/research/{rid}/review", json={"section": "mitre"}, headers=REVIEWER).status_code == 200
        rd = c.get(f"/api/research/{rid}/readiness").json()
        assert rd["ready"] and rd["warnings"] == 2
    finally:
        cleanup(rid)


# ------------------------------------------------------------------ B04 editing

def test_mitre_add_edit_delete_validates_and_versions(c):
    rid = make_research()
    try:
        v0 = c.get(f"/api/research/{rid}").json()["version"]
        bad = c.post(f"/api/research/{rid}/mitre", json={"technique_id": "T9999", "source_ids": ["S1"]}, headers=REVIEWER)
        assert bad.status_code == 422 and "T9999" in bad.json()["detail"]
        bad = c.post(f"/api/research/{rid}/mitre", json={"technique_id": "T1046", "source_ids": ["S42"]}, headers=REVIEWER)
        assert bad.status_code == 422 and "S42" in bad.json()["detail"]
        bad = c.post(f"/api/research/{rid}/mitre", json={"technique_id": "T1046", "tactic_id": "TA0040"}, headers=REVIEWER)
        assert bad.status_code == 422

        r = c.post(f"/api/research/{rid}/mitre", json={"technique_id": "t1046", "procedure": "Scanned internal hosts",
                                                         "evidence_quote": "scanned", "source_ids": ["S1"], "confidence": "high"}, headers=REVIEWER)
        assert r.status_code == 200, r.text
        body = r.json()
        row = next(m for m in body["record"]["mitre"] if m["technique_id"] == "T1046")
        assert row["tactic_id"] == "TA0007" and row["tactic"] == "Discovery" and row["_edited"] is True
        assert body["version"] == v0 + 1 and "mitre" in body["record"]["_edited"] and body["readiness"]["ready"]
        assert c.post(f"/api/research/{rid}/mitre", json={"technique_id": "T1046", "source_ids": ["S1"]}, headers=REVIEWER).status_code == 409

        idx = body["record"]["mitre"].index(row)
        r = c.put(f"/api/research/{rid}/mitre/{idx}?expect=T1018", json={"technique_id": "T1018", "source_ids": ["S1"]}, headers=REVIEWER)
        assert r.status_code == 409  # stale row guard
        r = c.put(f"/api/research/{rid}/mitre/{idx}?expect=T1046", json={"technique_id": "T1018", "source_ids": ["S1"], "confidence": "low"},
                  headers=REVIEWER)
        assert r.status_code == 200 and any(m["technique_id"] == "T1018" for m in r.json()["record"]["mitre"])
        idx = next(i for i, m in enumerate(r.json()["record"]["mitre"]) if m["technique_id"] == "T1018")
        r = c.delete(f"/api/research/{rid}/mitre/{idx}?expect=T1018", headers=REVIEWER)
        assert r.status_code == 200 and not any(m["technique_id"] == "T1018" for m in r.json()["record"]["mitre"])
        versions = c.get(f"/api/research/{rid}/versions").json()
        assert [v["summary"] for v in versions[:3]] == ["Removed T1018 from MITRE ATT&CK", "Edited MITRE row T1046 → T1018",
                                                         "Added T1046 to MITRE ATT&CK"]
    finally:
        cleanup(rid)


def test_attack_path_edit_is_versioned_and_keeps_refs(c):
    rid = make_research()
    try:
        d = c.get(f"/api/research/{rid}").json()
        path = d["record"]["attack_paths"][0]
        steps = [{"ref": s["ref"], "behaviour": s["behaviour"], "technique_id": s["technique_id"], "source_ids": s["source_ids"]}
                 for s in path["steps"]]
        steps.reverse()                      # reorder
        steps.pop()                          # remove the (originally) first step
        steps.append({"behaviour": "Operator deploys Warlock ransomware", "technique_id": "T1486", "source_ids": ["S1"]})
        bad = c.put(f"/api/research/{rid}/attack-paths/{path['id']}", json={"steps": steps[:-1] + [{**steps[-1], "technique_id": "T0000"}]},
                    headers=REVIEWER)
        assert bad.status_code == 422
        r = c.put(f"/api/research/{rid}/attack-paths/{path['id']}", json={"name": "Renamed path", "steps": steps}, headers=REVIEWER)
        assert r.status_code == 200, r.text
        new = r.json()["record"]["attack_paths"][0]
        assert new["name"] == "Renamed path"
        assert [s["ref"] for s in new["steps"][:-1]] == [s["ref"] for s in reversed(path["steps"])][:-1]
        assert new["steps"][-1]["ref"] not in {s["ref"] for s in path["steps"]} and new["steps"][-1]["_edited"]
        assert r.json()["version"] == d["version"] + 1
        v = c.get(f"/api/research/{rid}/versions").json()[0]
        assert v["summary"].startswith(f"Attack path {path['id']} renamed; steps edited, removed {path['steps'][0]['ref']}")
        assert "attack_paths" in v["diff"]["changed_sections"]
        # A new step without sources is edited, so it warns rather than blocks.
        steps.append({"behaviour": "Hunter note: lateral movement suspected", "technique_id": "", "source_ids": []})
        r = c.put(f"/api/research/{rid}/attack-paths/{path['id']}", json={"steps": steps}, headers=REVIEWER)
        rd = r.json()["readiness"]
        assert rd["ready"] and any(i["section"] == "attack_paths" and i["severity"] == "warn" for i in rd["issues"])
    finally:
        cleanup(rid)


def test_role_rules(c):
    rid = make_research(status="in_review")
    draft = make_research(status="draft")
    try:
        # Hunters cannot edit once in review; reviewers and leads can.
        assert c.patch(f"/api/research/{rid}/title", json={"title": "Hunter title"}, headers=HUNTER).status_code == 403
        assert c.post(f"/api/research/{rid}/mitre", json={"technique_id": "T1046", "source_ids": ["S1"]}, headers=HUNTER).status_code == 403
        r = c.patch(f"/api/research/{rid}/title", json={"title": "  Lead   title  "}, headers=LEAD)
        assert r.status_code == 200 and r.json()["record"]["title"] == "Lead title"
        assert c.get(f"/api/research/{rid}").json()["title"] == "Lead title"
        # Hunters may edit their drafts.
        assert c.patch(f"/api/research/{draft}/title", json={"title": "Draft title"}, headers=HUNTER).status_code == 200
        pid = c.get(f"/api/research/{draft}").json()["record"]["attack_paths"][0]["id"]
        assert c.put(f"/api/research/{draft}/attack-paths/{pid}", json={"name": "Hunter path"}, headers=HUNTER).status_code == 200
        # Only reviewers publish; editing a published record moves it back to review.
        assert c.post(f"/api/research/{rid}/status", json={"action": "publish"}, headers=HUNTER).status_code == 403
        assert c.post(f"/api/research/{rid}/status", json={"action": "publish"}, headers=REVIEWER).status_code == 200
        r = c.patch(f"/api/research/{rid}/title", json={"title": "Post-publish fix"}, headers=REVIEWER)
        assert r.json()["status"] == "in_review"
        assert c.post(f"/api/research/{rid}/status", json={"action": "archive"}, headers=REVIEWER).status_code == 200
        assert c.patch(f"/api/research/{rid}/title", json={"title": "Archived"}, headers=REVIEWER).status_code == 409
    finally:
        cleanup(rid)
        cleanup(draft)

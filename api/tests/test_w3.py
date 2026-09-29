"""W3: section comments + mentions + notifications (B19), version diff (B27), SQL-side research list filters (B15)."""

import os
import tempfile
from pathlib import Path

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tempfile.mkdtemp()) / 'w3.db').as_posix()}"
os.environ["ANTHROPIC_API_KEY"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

RID = "TR-2026-0142"


def _as(user: str) -> dict:
    return {"X-User": user}


def test_section_threads_mentions_and_notifications():
    with TestClient(app) as c:
        before = c.get("/api/research/notifications", headers=_as("riyer")).json()["unread"]
        r = c.post(f"/api/research/{RID}/comments", headers=_as("skapoor"),
                   json={"message": "@R. Iyer can you check horizon on item 3?", "section": "recommendations"})
        assert r.status_code == 200, r.text
        root = r.json()["comment"]
        assert root["section"] == "recommendations" and [m["id"] for m in root["mentions"]] == ["riyer"]
        assert r.json()["notified"] == ["riyer"]

        n = c.get("/api/research/notifications", headers=_as("riyer")).json()
        assert n["unread"] == before + 1
        top = n["items"][0]
        assert top["by"]["name"] == "S. Kapoor" and top["section_label"] == "Recommendations" and top["research_id"] == RID
        assert top["kind"] == "mention" and not top["read"] and top["thread_id"] == root["id"]
        # Other users do not see it
        assert all(i["comment_id"] != root["id"] for i in c.get("/api/research/notifications", headers=_as("jchen")).json()["items"])

        # Reply joins the thread and section; the root author hears about it; explicit mentions list works too
        rep = c.post(f"/api/research/{RID}/comments", headers=_as("riyer"),
                     json={"message": "Done, updated.", "parent_id": root["id"], "section": "iocs", "mentions": ["jchen"]}).json()
        assert rep["comment"]["parent_id"] == root["id"] and rep["comment"]["section"] == "recommendations"
        assert rep["notified"] == ["jchen", "skapoor"]
        sk = c.get("/api/research/notifications", headers=_as("skapoor")).json()["items"][0]
        assert sk["kind"] == "reply" and sk["by"]["id"] == "riyer"

        # Threads + counts
        th = c.get(f"/api/research/{RID}/comments", params={"section": "recommendations"}).json()
        t = next(x for x in th["threads"] if x["id"] == root["id"])
        assert [x["id"] for x in t["replies"]] == [rep["comment"]["id"]]
        assert th["counts"]["recommendations"]["open"] >= 1

        # Resolve via a reply id, then reopen by replying
        res = c.post(f"/api/research/{RID}/comments/{rep['comment']['id']}/resolve", headers=_as("riyer"), json={"resolved": True}).json()
        assert res["resolved"] and res["resolved_by"]["id"] == "riyer" and res["id"] == root["id"]
        cnt = c.get(f"/api/research/{RID}/comments").json()["counts"]["recommendations"]
        assert cnt["open"] == cnt["threads"] - 1
        c.post(f"/api/research/{RID}/comments", headers=_as("skapoor"), json={"message": "One more thing", "parent_id": root["id"]})
        t = next(x for x in c.get(f"/api/research/{RID}/comments").json()["threads"] if x["id"] == root["id"])
        assert not t["resolved"] and len(t["replies"]) == 2
        c.post(f"/api/research/{RID}/comments/{root['id']}/resolve", json={"resolved": False})
        assert c.post(f"/api/research/{RID}/comments/999999/resolve", json={}).status_code == 404
        assert c.post(f"/api/research/{RID}/comments", json={"message": "x", "parent_id": 999999}).status_code == 404

        # Activity keeps comments but not the notification rows; resolve is logged
        ev = c.get(f"/api/research/{RID}/activity").json()["events"]
        assert not any(e["type"] == "mention" for e in ev)
        assert any(e["type"] == "comment_status" for e in ev)

        # Mark read
        assert c.post("/api/research/notifications/read", headers=_as("riyer"), json={"ids": [top["id"]]}).json()["marked"] == 1
        # riyer still has the reply notification from "One more thing" (thread participant)
        n = c.get("/api/research/notifications", headers=_as("riyer")).json()
        assert n["unread"] == before + 1 and n["items"][0]["kind"] == "reply"
        c.post("/api/research/notifications/read", headers=_as("skapoor"), json={})
        assert c.get("/api/research/notifications", headers=_as("skapoor")).json()["unread"] == 0
        # Self-mention does not notify; global comment still works (legacy body)
        assert c.post(f"/api/research/{RID}/comments", headers=_as("skapoor"), json={"message": "@S. Kapoor note to self"}).json()["notified"] == []
        assert c.post(f"/api/research/{RID}/comments", json={"message": "plain"}).json()["ok"]


def test_version_diff_structured():
    with TestClient(app) as c:
        # Baseline edit so the starting version has a stored snapshot (seeded records can have version gaps)
        base = c.get(f"/api/research/{RID}").json()["record"]
        assert c.patch(f"/api/research/{RID}/record", json={"changes": {"tags": base["tags"] + ["w3"]}}).status_code == 200
        d = c.get(f"/api/research/{RID}").json()
        rec = d["record"]
        v0 = d["version"]
        iocs = rec["iocs"][1:] + [{"type": "domain", "value": "w3-new.example", "role": "c2", "context": "", "source_ids": []},
                                  {"type": "ipv4", "value": "203.0.113.77", "role": "c2", "context": "", "source_ids": []}]
        recs = [dict(x) for x in rec["recommendations"]]
        recs[2]["action"] = recs[2]["action"] + " Rotate machine keys afterwards."
        mitre = rec["mitre"][:-1]
        r = c.patch(f"/api/research/{RID}/record", headers=_as("skapoor"),
                    json={"changes": {"iocs": iocs, "recommendations": recs, "mitre": mitre,
                                      "executive_summary": rec["executive_summary"] + " Patch now."}, "summary": "w3 diff"})
        assert r.status_code == 200, r.text
        v1 = r.json()["version"]
        assert v1 == v0 + 1

        out = c.get(f"/api/research/{RID}/diff", params={"from": v0, "to": v1}).json()
        assert out["from"] == v0 and out["to"] == v1
        by = {s["section"]: s for s in out["sections"]}
        assert by["iocs"]["summary"] == "+2 IoCs, −1 IoC"
        assert {a["label"] for a in by["iocs"]["added"]} == {"domain: w3-new.example", "ipv4: 203.0.113.77"}
        assert by["mitre"]["summary"] == "−1 technique" and by["mitre"]["removed"][0]["label"].startswith(rec["mitre"][-1]["technique_id"])
        assert by["recommendations"]["summary"] == "recommendation 3 changed"
        ch = by["recommendations"]["changed"][0]
        assert ch["index"] == 3 and ch["fields"][0]["field"] == "action"
        assert {"op": "add", "text": " Rotate machine keys afterwards."} in ch["fields"][0]["ops"] or any(
            o["op"] == "add" and "Rotate" in o["text"] for o in ch["fields"][0]["ops"])
        es = by["executive_summary"]
        assert es["kind"] == "text" and any(o["op"] == "add" and "Patch now." in o["text"] for o in es["ops"])
        assert "review" not in by and "version" not in by
        # Defaults: previous -> current; reversed direction swaps added / removed
        assert c.get(f"/api/research/{RID}/diff").json()["from"] == v0
        back = {s["section"]: s for s in c.get(f"/api/research/{RID}/diff", params={"from": v1, "to": v0}).json()["sections"]}
        assert back["iocs"]["summary"] == "+1 IoC, −2 IoCs"
        assert c.get(f"/api/research/{RID}/diff", params={"from": 999}).status_code == 404


def test_list_filters_in_sql_match_reference():
    with TestClient(app) as c:
        allr = c.get("/api/research", params={"page_size": 500}).json()
        assert allr["total"] == len(allr["items"]) and allr["pages"] >= 1
        ids = {x["id"] for x in allr["items"]}
        assert RID in ids
        # Pagination is stable and complete
        p1 = c.get("/api/research", params={"page_size": 2, "page": 1, "sort": "id"}).json()
        p2 = c.get("/api/research", params={"page_size": 2, "page": 2, "sort": "id"}).json()
        assert p1["total"] == allr["total"] and [x["id"] for x in p1["items"]] == sorted(ids)[:2]
        assert [x["id"] for x in p2["items"]] == sorted(ids)[2:4]
        # Sorting by severity puts critical first; iocs sort still works
        sev = [x["severity"] for x in c.get("/api/research", params={"sort": "-severity", "page_size": 500}).json()["items"]]
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        assert [rank.get(s, 0) for s in sev] == sorted([rank.get(s, 0) for s in sev], reverse=True)
        io = [x["counts"]["iocs"] for x in c.get("/api/research", params={"sort": "-iocs", "page_size": 500}).json()["items"]]
        assert io == sorted(io, reverse=True)
        # JSON-derived filters
        d = c.get(f"/api/research/{RID}").json()["record"]
        actor = d["threat_actors"][0]
        for params in ({"actor": actor["name"]}, {"actor": (actor.get("aliases") or [actor["name"]])[0].upper()},
                       {"cve": d["vulnerabilities"][0]["cve"].lower()}, {"technique": d["mitre"][0]["technique_id"]},
                       {"tactic": d["mitre"][0]["tactic_id"]}, {"industry": d["industries"][0]["industry"].upper()},
                       {"platform": d["hunts"]["platforms"][0]}, {"ws": "northwind"}, {"classification": d["classification"][0]},
                       {"result": "no_evidence", "ws": "northwind"}, {"q": "sharepoint"}):
            got = {x["id"] for x in c.get("/api/research", params={**params, "page_size": 500}).json()["items"]}
            assert RID in got, params
        assert c.get("/api/research", params={"actor": "no-such-actor-w3"}).json()["total"] == 0
        assert c.get("/api/research", params={"industry": "%"}).json()["total"] == 0  # LIKE wildcards are escaped
        assert c.get("/api/research", params={"ws": "no_such_ws"}).json()["total"] == 0
        assert c.get("/api/research", params={"page_size": 100000}).json()["page_size"] == 500

"""W5: email intake (forward-to-run, spec 3 P1) and STIX 2.1 export (spec 3 P2)."""

import os
import tempfile
from email.message import EmailMessage
from pathlib import Path

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tempfile.mkdtemp()) / 'w5.db').as_posix()}"
os.environ["ANTHROPIC_API_KEY"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import intake  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.exports import stix  # noqa: E402
from app.main import app  # noqa: E402
from app.models import ExportLog, Research, Run, User  # noqa: E402

ORIGINAL_HTML = """<html><head><style>p{color:red}</style><script>alert(1)</script></head><body>
<p>TLP:GREEN</p><p>Storm-2603 is exploiting <b>CVE-2025-53770</b> in SharePoint and dropping Warlock ransomware.</p>
<p>Read the analysis: <a href="https://www.bleepingcomputer.com/news/security/sharepoint-toolshell-attacks/?utm_source=nl">here</a>
and the vendor post <a href="https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.microsoft.com%2Fen-us%2Fsecurity%2Fblog%2F2025%2F07%2F22%2Fdisrupting-active-exploitation%2F&data=x">Microsoft</a>.</p>
<p>C2: 45.77.201[.]11 and hxxps://evil-updates[.]top/gate.php</p>
<p>Hash 5f2c3a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b</p>
<p><a href="https://www.microsoft.com/">Microsoft home</a> | <a href="https://news.example-vendor.com/unsubscribe?u=1">Unsubscribe</a>
| <a href="https://click.mailer.example-vendor.com/ls/click?upn=abc">Track</a> | <a href="https://twitter.com/msftsecurity">X</a></p>
</body></html>"""


def _original() -> EmailMessage:
    m = EmailMessage()
    m["From"] = "Threat Intel <newsletter@intel-vendor.com>"
    m["To"] = "analyst@northwind.example"
    m["Subject"] = "ToolShell: active SharePoint exploitation"
    m["Message-ID"] = "<orig-1@intel-vendor.com>"
    m.set_content("Plain version: Storm-2603 exploits CVE-2025-53770.")
    m.add_alternative(ORIGINAL_HTML, subtype="html")
    return m


def forwarded_attachment(mid: str = "<fwd-1@northwind.example>", to: str = "intake+northwind@threatlens.example") -> bytes:
    outer = EmailMessage()
    outer["From"] = "Pat Hunter <pat@northwind.example>"
    outer["To"] = to
    outer["Subject"] = "Fwd: ToolShell: active SharePoint exploitation"
    outer["Message-ID"] = mid
    outer.set_content("Have we looked at this? Please check our farms.\n\n-- \nPat\nSOC Lead")
    outer.add_attachment(_original())
    pdf = b"%PDF-1.4 ignored"
    outer.add_attachment(pdf, maintype="application", subtype="pdf", filename="report.pdf")
    return bytes(outer)


INLINE = b"""From: Sam <sam@contoso.example>
To: intake@threatlens.example
Subject: FW: Akira campaign targeting VPNs
Message-ID: <inline-1@contoso.example>
Content-Type: text/plain; charset=utf-8

FYI - worth a hunt.

---------- Forwarded message ---------
From: Vendor Alerts <alerts@vendor.example>
Date: Mon, 1 Sep 2026 10:00:00 +0000
Subject: Akira campaign targeting VPNs
To: sam@contoso.example

Akira affiliates are exploiting CVE-2024-40766 in SonicWall SSL VPN.
Full write-up: https://www.huntress.com/blog/akira-sonicwall-campaign-2026
Infrastructure: 185.220.101[.]45
Unsubscribe: https://vendor.example/unsubscribe?id=1
"""


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def test_parse_forwarded_attachment():
    p = intake.parse_email(forwarded_attachment())
    assert p["subject"].startswith("Fwd:")
    assert p["original"]["subject"] == "ToolShell: active SharePoint exploitation"
    assert p["original"]["from"] == "newsletter@intel-vendor.com"
    assert p["seed"].startswith("ToolShell: active SharePoint exploitation")
    assert "Have we looked at this" in p["seed"] and "SOC Lead" not in p["seed"]
    assert "alert(1)" not in p["seed"] and "color:red" not in p["seed"]
    assert p["cves"] == ["CVE-2025-53770"]
    assert "Storm-2603" in p["actors"]
    assert p["tlp"] == "GREEN"
    urls = {u["url"]: u for u in p["urls"]}
    articles = [u for u in p["urls"] if u["include"]]
    # utm stripped, Safe Links unwrapped; homepage, unsubscribe, tracking and social links dropped.
    assert "https://www.bleepingcomputer.com/news/security/sharepoint-toolshell-attacks/" in urls
    assert any(u["url"].startswith("https://www.microsoft.com/en-us/security/blog/2025/07/22/") for u in articles)
    assert all("unsubscribe" not in u["url"] and "click" not in u["host"] and u["host"] != "twitter.com" for u in articles)
    assert urls["https://www.microsoft.com/"]["include"] is False
    assert urls["https://evil-updates.top/gate.php"]["kind"] == "indicator"
    types = {(i["type"], i["value"]) for i in p["iocs"]}
    assert ("ipv4", "45.77.201.11") in types
    assert ("sha256", "5f2c3a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b") in types
    assert not any(t == "email" for t, _ in types)  # sender / recipient addresses are not indicators
    assert not any(v.startswith("https://www.bleepingcomputer.com") for _, v in types)


def test_parse_inline_forward():
    p = intake.parse_email(INLINE)
    assert p["original"]["subject"] == "Akira campaign targeting VPNs"
    assert p["original"]["from"] == "alerts@vendor.example"
    assert p["cves"] == ["CVE-2024-40766"]
    assert "Akira" in p["actors"]
    inc = [u["url"] for u in p["urls"] if u["include"]]
    assert inc == ["https://www.huntress.com/blog/akira-sonicwall-campaign-2026"]
    assert ("ipv4", "185.220.101.45") in {(i["type"], i["value"]) for i in p["iocs"]}
    assert "FYI - worth a hunt" in p["seed"]
    assert "From: Vendor Alerts" not in p["seed"]


def test_upload_creates_draft_and_dedups(c):
    raw = forwarded_attachment("<fwd-dedup@northwind.example>")
    r = c.post("/api/intake/email", files={"file": ("fwd.eml", raw, "message/rfc822")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["duplicate"] is False
    item = body["item"]
    assert item["suggested_workspace"]["id"] == "northwind"  # +northwind tag == workspace id
    assert item["status"] == "draft_created" and body["draft"]["id"] == item["research_id"]
    with SessionLocal() as db:
        res = db.get(Research, item["research_id"])
        assert res.status == "draft" and res.workspace_ids == ["northwind"] and res.tlp == "GREEN"
        run = db.query(Run).filter_by(research_id=res.id).one()
        assert run.status == "queued" and run.started_at is None  # saved, not started
        assert any("bleepingcomputer" in u for u in run.config["seed_urls"])
    # Same Message-ID again (raw body this time): no new item, no new draft.
    r2 = c.post("/api/intake/email", content=raw, headers={"Content-Type": "message/rfc822"})
    assert r2.status_code == 200 and r2.json()["duplicate"] is True and r2.json()["item"]["id"] == item["id"]
    listed = c.get("/api/intake").json()["items"]
    assert sum(1 for x in listed if x["id"] == item["id"]) == 1


def test_preview_then_draft_and_routing(c):
    # Unknown sender, no tag: preview only, then the hunter picks a workspace and trims URLs.
    r = c.post("/api/intake/email?create=false", content=INLINE, headers={"Content-Type": "message/rfc822"})
    assert r.status_code == 200, r.text
    item = r.json()["item"]
    assert item["status"] == "parsed" and item["suggested_workspace"] is None and item["research_id"] is None
    d = c.post(f"/api/intake/{item['id']}/draft", json={"workspace_ids": ["northwind"], "seed_urls": []})
    assert d.status_code == 200, d.text
    assert c.get(f"/api/intake/{item['id']}").json()["status"] == "draft_created"
    assert c.post(f"/api/intake/{item['id']}/draft", json={"workspace_ids": ["northwind"]}).status_code == 409
    # Routing by sender domain.
    ws = c.get("/api/workspaces").json()
    other = next(w["id"] for w in ws if w["id"] != "northwind")
    with SessionLocal() as db:
        lead = db.query(User).filter(User.role.in_(["lead", "admin"])).first().id
    rr = c.put("/api/intake/routing", json={"domains": {"contoso.example": other}, "tags": {}}, headers={"X-User": lead})
    assert rr.status_code == 200, rr.text
    raw = INLINE.replace(b"<inline-1@contoso.example>", b"<inline-2@contoso.example>")
    item2 = c.post("/api/intake/email?create=false", content=raw, headers={"Content-Type": "message/rfc822"}).json()["item"]
    assert item2["suggested_workspace"]["id"] == other
    assert c.put("/api/intake/routing", json={"domains": {"x.example": "nope"}}, headers={"X-User": lead}).status_code == 422


def test_bad_email_rejected(c):
    assert c.post("/api/intake/email", content=b"", headers={"Content-Type": "message/rfc822"}).status_code == 422


def test_webhook_secret_and_postmark(c, monkeypatch):
    payload = {"From": "pat@northwind.example", "To": "intake+northwind@threatlens.example",
               "OriginalRecipient": "intake+northwind@threatlens.example", "Subject": "Fwd: LockBit returns",
               "MessageID": "pm-123", "TextBody": "LockBit 5.0 is exploiting CVE-2025-1234. See https://www.sophos.com/en-us/blog/lockbit-5",
               "HtmlBody": "", "Headers": [{"Name": "Message-ID", "Value": "<pm-123@mail.example>"}]}
    monkeypatch.delenv("INTAKE_WEBHOOK_SECRET", raising=False)
    assert c.post("/api/intake/inbound", json=payload).status_code == 503
    monkeypatch.setenv("INTAKE_WEBHOOK_SECRET", "s3cret")
    assert c.post("/api/intake/inbound", json=payload).status_code == 401
    assert c.post("/api/intake/inbound", json=payload, headers={"X-Intake-Secret": "wrong"}).status_code == 401
    r = c.post("/api/intake/inbound", json=payload, headers={"X-Intake-Secret": "s3cret"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["duplicate"] is False and out["status"] == "draft_created" and out["research_id"]
    item = c.get(f"/api/intake/{out['id']}").json()
    assert item["via"] == "webhook:postmark" and item["cves"] == ["CVE-2025-1234"]
    # Basic auth (password = secret) works too, and the same MessageID is deduplicated.
    r2 = c.post("/api/intake/inbound", json=payload, auth=("intake", "s3cret"))
    assert r2.status_code == 200 and r2.json()["duplicate"] is True


def test_webhook_sendgrid_form(c, monkeypatch):
    monkeypatch.setenv("INTAKE_WEBHOOK_SECRET", "s3cret")
    form = {"from": "x@unknown.example", "to": "intake@threatlens.example", "subject": "Volt Typhoon update",
            "text": "Volt Typhoon living off the land.", "headers": "Message-ID: <sg-1@unknown.example>\nDate: Mon, 1 Sep 2026 10:00:00 +0000"}
    r = c.post("/api/intake/inbound", data=form, headers={"X-Intake-Secret": "s3cret"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "needs_workspace"


# ------------------------------------------------------------------ STIX

def _record() -> dict:
    return {
        "title": "ToolShell exploitation", "tlp": "AMBER+STRICT", "executive_summary": "Storm-2603 exploits SharePoint.",
        "confidence": "high", "classification": ["cve"], "tags": ["sharepoint"],
        "sources": [{"id": "S1", "url": "https://www.microsoft.com/en-us/security/blog/x/", "publisher": "Microsoft", "title": "Blog",
                     "published": "2025-07-22", "included": True}],
        "threat_actors": [{"name": "Storm-2603", "aliases": ["CL-CRI-1040"], "motivation": ["financial"], "attribution_confidence": "high",
                           "source_ids": ["S1"]}],
        "malware_tools": [{"name": "Warlock", "type": "ransomware", "role": "Encrypts", "source_ids": ["S1"]},
                          {"name": "PsExec", "type": "tool", "role": "Lateral movement"}],
        "vulnerabilities": [{"cve": "CVE-2025-53770", "description": "Deserialization", "source_ids": ["S1"]}],
        "mitre": [{"tactic": "Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application", "source_ids": ["S1"]},
                  {"tactic": "Persistence", "technique_id": "T1505.003", "technique": "Server Software Component", "sub_technique": "Web Shell"}],
        "industries": [{"industry": "Government"}],
        "iocs": [
            {"type": "ipv4", "value": "107.191.58[.]76", "role": "Exploitation source", "verdict": "malicious", "source_ids": ["S1"]},
            {"type": "domain", "value": "evil-updates[.]top", "role": "Warlock C2", "verdict": "suspicious"},
            {"type": "url", "value": "hxxps://evil[.]top/a'b.php", "verdict": "malicious"},
            {"type": "sha256", "value": "5F2C3A1B9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A2F1E0D9C8B7A6F5E4D3C2B", "verdict": "malicious"},
            {"type": "email", "value": "ops[@]evil[.]top", "verdict": "unknown"},
            {"type": "ipv4", "value": "8.8.8[.]8", "verdict": "false_positive"},
            {"type": "domain", "value": "login.microsoftonline[.]com", "verdict": "malicious", "excluded": True},
            {"type": "domain", "value": "cdn.example[.]net", "verdict": "benign"},
        ],
        "ioc_review": {"decisions": {"ipv4|107.191.58.76": {"verdict": "malicious", "by": "u"},
                                     "domain|cdn2.bad.top": {"verdict": "false_positive", "by": "u"},
                                     "domain|login.microsoftonline.com": {"excluded": True, "by": "u"}}},
    }


def test_stix_bundle_valid_tlp_and_fp_exclusion(c):
    rec = _record()
    rec["iocs"].append({"type": "domain", "value": "cdn2.bad[.]top", "verdict": "malicious"})  # analyst FP via ioc_review
    with SessionLocal() as db:
        db.add(Research(id="TR-2099-0001", title="ToolShell exploitation", status="in_review", tlp="AMBER+STRICT",
                        workspace_ids=["northwind"], record=rec))
        db.commit()
    r = c.get("/api/research/TR-2099-0001/export/stix")
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"] == 'attachment; filename="TR-2099-0001-stix.json"'
    b = r.json()
    assert stix.validate(b) == []
    import stix2  # installed in the venv; parse is the authoritative check
    stix2.parse(b, allow_custom=False)
    by = {}
    for o in b["objects"]:
        by.setdefault(o["type"], []).append(o)
    tlp_id = stix.TLP2["AMBER+STRICT"]
    assert {m["name"] for m in by["marking-definition"]} >= {"TLP:AMBER+STRICT", "TLP:CLEAR", "TLP:RED"}
    assert all(o.get("object_marking_refs") == [tlp_id] for t, os_ in by.items() if t not in ("marking-definition", "identity") for o in os_)
    rep = by["report"][0]
    assert rep["name"] == "ToolShell exploitation" and len(rep["object_refs"]) > 5
    assert by["intrusion-set"][0]["aliases"] == ["CL-CRI-1040"] and by["intrusion-set"][0]["primary_motivation"] == "personal-gain"
    assert {m["name"] for m in by["malware"]} == {"Warlock"} and {t["name"] for t in by["tool"]} == {"PsExec"}
    assert by["vulnerability"][0]["external_references"][0] == {"source_name": "cve", "external_id": "CVE-2025-53770",
                                                              "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-53770"}
    ap = {a["external_references"][0]["external_id"]: a for a in by["attack-pattern"]}
    assert set(ap) == {"T1190", "T1505.003"} and ap["T1505.003"]["kill_chain_phases"][0]["phase_name"] == "persistence"
    pats = {i["pattern"] for i in by["indicator"]}
    assert pats == {"[ipv4-addr:value = '107.191.58.76']", "[domain-name:value = 'evil-updates.top']",
                    "[url:value = 'https://evil.top/a\\'b.php']",
                    "[file:hashes.'SHA-256' = '5f2c3a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b']",
                    "[email-addr:value = 'ops@evil.top']"}
    assert not any("8.8.8.8" in p or "microsoftonline" in p or "cdn.example" in p or "cdn2.bad" in p for p in pats)
    rels = {(o["relationship_type"]) for o in by["relationship"]}
    assert rels >= {"uses", "targets", "indicates"}
    ids = {o["id"] for o in b["objects"]}
    warlock = by["malware"][0]["id"]
    c2 = next(i for i in by["indicator"] if "evil-updates" in i["pattern"])
    assert any(o["source_ref"] == c2["id"] and o["target_ref"] == warlock for o in by["relationship"])
    assert all(o["source_ref"] in ids and o["target_ref"] in ids for o in by["relationship"])
    # Export is logged like the other formats; a second export keeps stable object ids.
    with SessionLocal() as db:
        assert db.query(ExportLog).filter_by(research_id="TR-2099-0001", format="stix").count() == 1
    b2 = c.get("/api/research/TR-2099-0001/export/stix").json()
    assert {o["id"] for o in b2["objects"]} == ids


def test_stix_other_export_formats_unaffected(c):
    assert c.get("/api/research/TR-2099-0001/export/nope").status_code == 404
    assert c.get("/api/research/TR-2099-0404/export/stix").status_code == 404


def test_pattern_escaping():
    assert stix.pattern_for("url", "hxxp://a[.]b/x\\y'z") == "[url:value = 'http://a.b/x\\\\y\\'z']"
    assert stix.pattern_for("ja3", "abc") is None

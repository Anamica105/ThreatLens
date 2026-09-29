"""R2: per-record IoC false-positive removal (spec §2 step 8, §9), library overrides in runs, new IoC types, expiry."""

import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tempfile.mkdtemp()) / 'r2.db').as_posix()}"
os.environ["ANTHROPIC_API_KEY"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app import osint  # noqa: E402
from app.ioc import defang, detect_type, extract, known_good_hash, refang  # noqa: E402
from app.main import app  # noqa: E402

IPS = ["45.77.201.11", "45.77.201.12", "45.77.201.13"]
SEED = ("Threat brief: attackers exploited CVE-2025-53770 in SharePoint. The attackers used w3wp.exe to spawn cmd.exe and "
        "powershell -enc to write spinstall0.aspx web shell. "
        f"C2 traffic went to {IPS[0].replace('.11', '[.]11')}, {IPS[1]} and {IPS[2]} and r2-evil-updates[.]top. "
        "The dropped payload hash was 5f2c3a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b. ") * 3


def _run(c: TestClient) -> str:
    r = c.post("/api/research", json={"seed": SEED, "workspace_ids": ["northwind"], "platforms": ["kql_defender", "spl", "sigma"],
                                      "vendors": ["cisa"], "open_web": False, "depth": "quick", "offline": True})
    assert r.status_code == 200, r.text
    run_id, rid = r.json()["run_id"], r.json()["id"]
    for _ in range(240):
        run = c.get(f"/api/runs/{run_id}").json()
        if run["status"] in ("done", "failed") and not run.get("active"):
            break
        time.sleep(0.5)
    assert run["status"] == "done", [lg["message"] for lg in run["logs"] if lg["level"] in ("error", "warn")]
    return rid


def _group(rec: dict, g: str) -> list[dict]:
    return [q for q in rec["hunts"]["queries"] if q.get("group") == g]


def _snapshot(rec: dict, skip: str) -> list[tuple]:
    return [(q["id"], q["group"], q["platform"], q["body"]) for q in rec["hunts"]["queries"] if q.get("group") != skip]


def test_new_regex_types_and_known_good_hashes():
    text = ('C2 at 2001:4860:4860::8888 and 2606:4700:4700[:]:1111 but not fe80::1, 2001:db8::1, 12:30:45 or std::string. '
            "The implant used User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\n"
            'Another beacon sent "curl/8.4.0". The user agent is unknown. Mozilla/5.0 unquoted is not taken.\n'
            "TLS JA3: 72a589da586844d7f0818ce684948eea and JA3S hash 8d9f7747675e24454cd9b7ed35c58707. "
            "JA4 t13d1516h2_8daaf6152771_b186095e22b6 seen. "
            'It creates the mutex "Gl0b4lMtx_77" and Global\\QakMutex01; also mutex: abc123XY. A mutex is created. '
            'It listens on \\\\.\\pipe\\msagent_12 and named pipe "postex_ssh_1234".')
    got = {(i.type, i.value) for i in extract(text)}
    assert ("ipv6", "2001:4860:4860::8888") in got and ("ipv6", "2606:4700:4700::1111") in got
    assert not any(t == "ipv6" and v.startswith(("fe80", "2001:db8")) for t, v in got)
    assert ("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") in got
    assert ("user_agent", "curl/8.4.0") in got
    assert sum(1 for t, _ in got if t == "user_agent") == 2
    assert ("ja3", "72a589da586844d7f0818ce684948eea") in got and ("ja3", "8d9f7747675e24454cd9b7ed35c58707") in got
    assert not any(t == "md5" for t, _ in got)  # the labelled JA3 values are not also reported as MD5 hashes
    assert ("ja4", "t13d1516h2_8daaf6152771_b186095e22b6") in got
    assert {v for t, v in got if t == "mutex"} == {"Gl0b4lMtx_77", "Global\\QakMutex01", "abc123XY"}
    assert {v for t, v in got if t == "named_pipe"} == {"\\\\.\\pipe\\msagent_12", "\\\\.\\pipe\\postex_ssh_1234"}
    # refang / defang
    assert refang("2001[:]4860:4860::8888") == "2001:4860:4860::8888"
    assert defang("2001:4860:4860::8888", "ipv6") == "2001[:]4860:4860::8888"
    for t, v in [("ja3", "72a589da586844d7f0818ce684948eea"), ("ja4", "t13d1516h2_8daaf6152771_b186095e22b6"),
                 ("mutex", "Global\\QakMutex01"), ("named_pipe", "\\\\.\\pipe\\x"), ("user_agent", "curl/8.4.0")]:
        assert defang(v, t) == v
    assert detect_type("\\\\.\\pipe\\x") == "named_pipe" and detect_type("2001:4860::1") == "ipv6"
    assert detect_type("t13d1516h2_8daaf6152771_b186095e22b6") == "ja4"
    # well-known hashes are benign, never malicious
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert known_good_hash(empty.upper()) and known_good_hash("ab" * 32) is None
    assert known_good_hash("ab" * 32, {"ab" * 32: "PsExec"}) == "PsExec"
    assert osint.verdict("sha256", {}, True, "A", known_good=True) == "benign"


def test_expiry_math():
    now = datetime.now(timezone.utc)
    cfg = dict(osint.EXPIRY_DEFAULTS)
    assert cfg["ipv4"] == 90 and cfg["domain"] == 180 and cfg["url"] == 90 and cfg["sha256"] is None
    fs = now - timedelta(days=100)
    assert osint.expires_at("ipv4", fs, cfg) == fs + timedelta(days=90)
    assert osint.is_expired("ipv4", fs, cfg) and not osint.is_expired("domain", fs, cfg)
    assert osint.expires_at("sha256", fs, cfg) is None and not osint.is_expired("sha256", now - timedelta(days=5000), cfg)
    assert osint.expires_at("ipv4", None, cfg) is None
    # intel first-seen = earliest of source publication dates and provider first-seen (VT epoch seconds)
    vt_epoch = int((now - timedelta(days=400)).timestamp())
    got = osint.intel_first_seen({"virustotal": {"first_seen": vt_epoch}}, ["2026-01-02", None, (now - timedelta(days=10)).isoformat()])
    assert abs((got - datetime.fromtimestamp(vt_epoch, timezone.utc)).total_seconds()) < 1
    assert osint.intel_first_seen({}, ["2026-01-02"]) == datetime(2026, 1, 2, tzinfo=timezone.utc)
    assert osint.intel_first_seen({}, [(now + timedelta(days=30)).isoformat()]) is None  # future dates ignored
    # verdict: infra older than its configured age is expired; a custom age applies
    assert osint.verdict("ipv4", {}, True, "A", now - timedelta(days=91), cfg) == "expired"
    assert osint.verdict("ipv4", {}, True, "A", now - timedelta(days=91), {**cfg, "ipv4": 120}) == "malicious"
    assert osint.verdict("sha256", {}, True, "A", now - timedelta(days=3000), cfg) == "malicious"

    with TestClient(app) as c:
        d = c.get("/api/settings/ioc-expiry").json()
        assert d["days"]["ipv4"] == 90 and d["defaults"]["domain"] == 180
        assert c.put("/api/settings/ioc-expiry", json={"days": {"ipv4": 30}}, headers={"X-User": "nobody-analyst"}).status_code in (200, 403)
        h = {"X-User": "skapoor"}  # seeded lead
        r = c.put("/api/settings/ioc-expiry", json={"days": {"ipv4": 30, "sha256": None}}, headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["days"]["ipv4"] == 30
        assert c.put("/api/settings/ioc-expiry", json={"days": {"ipv4": 0 - 5}}, headers=h).status_code == 422
        assert c.put("/api/settings/ioc-expiry", json={"days": {"ipv4": 90}}, headers=h).json()["days"]["ipv4"] == 90


def test_fp_removal_regenerates_only_ioc_group_and_library_override_respected():
    with TestClient(app) as c:
        rid = _run(c)
        rec = c.get(f"/api/research/{rid}").json()["record"]
        ipq = _group(rec, "IOC-IPV4")
        assert ipq and all(ip in ipq[0]["body"] for ip in IPS), ipq[0]["body"]
        assert _group(rec, "IOC-DOMAIN")
        before_other = _snapshot(rec, "IOC-IPV4")
        v0 = rec["version"]

        # 1. Mark one IP a false positive: the IPv4 retro-hunt is rebuilt without it; every other group is unchanged.
        r = c.patch(f"/api/research/{rid}/iocs", json={"items": [
            {"type": "ipv4", "value": IPS[1].replace(".12", "[.]12"), "verdict": "false_positive", "note": "Shared CDN edge"}]})
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["changes"] == [{"group": "IOC-IPV4", "before": 3, "after": 2}]
        assert out["hidden_count"] >= 1 and out["version"] > v0
        rec = c.get(f"/api/research/{rid}").json()["record"]
        new_ip = _group(rec, "IOC-IPV4")
        assert new_ip and all(IPS[1] not in q["body"] for q in new_ip) and all(IPS[0] in q["body"] for q in new_ip)
        assert {q["platform"] for q in new_ip} == {q["platform"] for q in ipq}
        assert not {q["id"] for q in new_ip} & {q["id"] for q in ipq}
        assert _snapshot(rec, "IOC-IPV4") == before_other
        assert set(rec["hunts"]["ioc_queries"]) == {q["id"] for q in rec["hunts"]["queries"] if q["type"] == "ioc"}
        fp = next(i for i in rec["iocs"] if refang(i["value"]) == IPS[1])
        assert fp["verdict"] == "false_positive" and fp["hidden_from_hunts"] and fp["verdict_source"] == "analyst"
        assert fp["analyst"]["note"] == "Shared CDN edge" and fp["analyst"]["by"] and fp["analyst"]["at"]
        assert fp["pipeline_verdict"] != "false_positive"
        acts = c.get(f"/api/research/{rid}/activity").json()["events"]
        assert any("IOC-IPV4 3→2" in (a.get("message") or "") for a in acts)
        # the library keeps the pipeline verdict (no propagation asked)
        lib = c.get("/api/library/iocs", params={"q": IPS[1]}).json()["items"][0]
        assert lib["verdict"] != "false_positive" and lib["verdict_override"] is None

        # 2. Excluding the rest removes the group entirely; nothing else moves.
        r = c.patch(f"/api/research/{rid}/iocs", json=[{"type": "ipv4", "value": IPS[0], "excluded": True},
                                                       {"type": "ipv4", "value": IPS[2], "excluded": True}])
        assert r.status_code == 200, r.text
        assert r.json()["changes"] == [{"group": "IOC-IPV4", "before": 2, "after": 0}]
        rec = c.get(f"/api/research/{rid}").json()["record"]
        assert not _group(rec, "IOC-IPV4") and _snapshot(rec, "IOC-IPV4") == before_other

        # 3. Restore brings indicators back; a no-op decision regenerates nothing.
        r = c.patch(f"/api/research/{rid}/iocs", json={"items": [{"type": "ipv4", "value": IPS[0], "restore": True},
                                                                 {"type": "ipv4", "value": IPS[2], "restore": True}]})
        assert r.json()["changes"] == [{"group": "IOC-IPV4", "before": 0, "after": 2}]
        r = c.patch(f"/api/research/{rid}/iocs", json={"items": [{"type": "domain", "value": "r2-evil-updates.top", "verdict": "malicious"}]})
        assert r.status_code == 200 and r.json()["changes"] == []
        assert c.patch(f"/api/research/{rid}/iocs", json={"items": [{"type": "ipv4", "value": "9.9.9.9", "verdict": "benign"}]}).status_code == 404
        assert c.patch(f"/api/research/{rid}/iocs", json={"items": [{"type": "ipv4", "value": IPS[0], "verdict": "nope"}]}).status_code == 422

        # 4. Propagate: the verdict becomes a library override, which a fresh run respects when building retro-hunts.
        r = c.patch(f"/api/research/{rid}/iocs", json={"propagate": True, "items": [
            {"type": "ipv4", "value": IPS[2], "verdict": "benign", "note": "Company egress"}]})
        assert r.json()["propagated"] == 1
        lib = c.get("/api/library/iocs", params={"q": IPS[2]}).json()["items"][0]
        assert lib["verdict"] == "benign" and lib["verdict_override"]["verdict"] == "benign"
        assert lib["verdict_override"]["note"] == "Company egress"
        # and a library-only override set from the IoC library page
        lib0 = c.get("/api/library/iocs", params={"q": IPS[0]}).json()["items"][0]
        assert c.patch(f"/api/library/iocs/{lib0['id']}", json={"verdict": "false_positive"}).status_code == 200
        try:
            rid2 = _run(c)
            rec2 = c.get(f"/api/research/{rid2}").json()["record"]
            ip2 = _group(rec2, "IOC-IPV4")
            assert ip2 and all(IPS[0] not in q["body"] and IPS[2] not in q["body"] for q in ip2)
            assert all(IPS[1] in q["body"] for q in ip2)  # the per-record FP of the first research does not leak
            i0 = next(i for i in rec2["iocs"] if refang(i["value"]) == IPS[0])
            assert i0["verdict"] == "false_positive" and i0["verdict_source"] == "library" and i0["hidden_from_hunts"]
        finally:
            for ip in (IPS[0], IPS[2]):
                row = c.get("/api/library/iocs", params={"q": ip}).json()["items"][0]
                c.patch(f"/api/library/iocs/{row['id']}", json={"clear_override": True})
        assert c.get("/api/library/iocs", params={"q": IPS[2]}).json()["items"][0]["verdict_override"] is None

        # 5. Expired infrastructure is left out unless the hunter opts in.
        r = c.patch(f"/api/research/{rid}/iocs", json={"include_expired": True})
        assert r.status_code == 200
        assert c.get(f"/api/research/{rid}").json()["record"]["ioc_review"]["include_expired"] is True

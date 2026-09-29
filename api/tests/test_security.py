"""Security fixes: workspace writes need lead/admin; outbound fetches connect only to the address that passed the SSRF
check (DNS-rebinding safe), including every redirect hop."""

import os
import socket
import tempfile
from pathlib import Path

if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tempfile.mkdtemp()) / 'sec.db').as_posix()}"
os.environ["ANTHROPIC_API_KEY"] = ""

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import sources  # noqa: E402
from app.main import app  # noqa: E402

WS = {"name": "Sec Test Co", "industry": "Retail", "color": "#5249A8", "platforms": ["sigma"], "field_mappings": {},
      "log_sources": [], "products": [], "branding": {"logo_data_uri": "http://169.254.169.254/x.png"}, "default_tlp": "AMBER"}


def test_workspace_writes_need_lead_or_admin():
    with TestClient(app) as c:
        hunter, lead = {"X-User": "averma"}, {"X-User": "skapoor"}
        assert c.post("/api/workspaces", json=WS, headers=hunter).status_code == 403
        assert c.put("/api/workspaces/acme", json={**WS, "name": "Acme Bank"}, headers=hunter).status_code == 403
        files = {"file": ("l.png", b"\x89PNG\r\n\x1a\n", "image/png")}
        assert c.post("/api/workspaces/acme/logo", files=files, headers=hunter).status_code == 403
        r = c.post("/api/workspaces", json=WS, headers=lead)
        assert r.status_code == 200 and r.json()["branding"]["has_logo"] is False  # client-supplied logo URI dropped


def _dns(monkeypatch, answers: dict[str, str]):
    def fake(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers[host], port))]
    monkeypatch.setattr(sources.socket, "getaddrinfo", fake)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_request_goes_to_the_checked_ip(monkeypatch):
    _dns(monkeypatch, {"vendor.example": "93.184.216.34"})
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        return httpx.Response(200, text="ok")

    r, final = sources.guarded_get(_client(handler), "https://vendor.example/post?a=1")
    assert r.text == "ok" and final == "https://vendor.example/post?a=1"
    req = seen[0]
    assert req.url.host == "93.184.216.34" and req.url.path == "/post" and req.url.query == b"a=1"
    assert req.headers["host"] == "vendor.example"
    assert req.extensions["sni_hostname"] == "vendor.example"  # TLS still verified against the real name


def test_private_answers_and_redirects_are_blocked(monkeypatch):
    _dns(monkeypatch, {"rebind.example": "127.0.0.1", "vendor.example": "93.184.216.34", "meta.example": "169.254.169.254"})
    calls = []

    def handler(req: httpx.Request):
        calls.append(req.headers["host"])
        return httpx.Response(302, headers={"location": "http://meta.example/latest/meta-data/"})

    with pytest.raises(sources.BlockedAddress):
        sources.guarded_get(_client(handler), "http://rebind.example/")
    assert calls == []  # never connected
    with pytest.raises(sources.BlockedAddress):
        sources.guarded_get(_client(handler), "http://vendor.example/")
    assert calls == ["vendor.example"]  # the redirect hop to the metadata address was never sent


def test_browser_requests_are_pinned_too(monkeypatch):
    import asyncio

    _dns(monkeypatch, {"cdn.example": "93.184.216.34", "internal.example": "10.0.0.5"})
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.url.host, req.headers["host"]))
        return httpx.Response(200, text="ok")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            r = await sources.pinned_request_async(c, "GET", "https://cdn.example/app.js", headers={"Host": "evil", "Accept": "*/*"})
            assert r.text == "ok"
            with pytest.raises(sources.BlockedAddress):
                await sources.pinned_request_async(c, "GET", "http://internal.example/")

    asyncio.run(go())
    assert seen == [("93.184.216.34", "cdn.example")]  # page-supplied Host header is replaced

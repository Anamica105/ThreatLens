"""Source discovery and fetching (pipeline stages 2 and 3 input).

Discovery = seed URLs + allow-listed vendor RSS feeds matched against the seed
entities + (optional) Brave web search. Fetching = httpx + trafilatura, with a
headless Chromium fallback (Playwright) for JavaScript-rendered pages such as
Check Point Research. Fetchers never submit forms or log in.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

import feedparser
import httpx
import trafilatura

from .config import get_settings

log = logging.getLogger(__name__)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatLens/1.0 (+internal threat research)"

# Admiralty reliability defaults per publisher (A = completely reliable ... F = cannot be judged).
VENDORS: list[dict] = [
    {"id": "microsoft", "name": "Microsoft Threat Intelligence", "domains": ["microsoft.com"], "feed": "https://www.microsoft.com/en-us/security/blog/feed/", "reliability": "B"},
    {"id": "mandiant", "name": "Google Threat Intelligence / Mandiant", "domains": ["cloud.google.com", "mandiant.com"], "feed": "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "reliability": "B"},
    {"id": "unit42", "name": "Palo Alto Unit 42", "domains": ["unit42.paloaltonetworks.com"], "feed": "https://unit42.paloaltonetworks.com/feed/", "reliability": "B"},
    {"id": "talos", "name": "Cisco Talos", "domains": ["talosintelligence.com"], "feed": "https://blog.talosintelligence.com/rss/", "reliability": "B"},
    {"id": "crowdstrike", "name": "CrowdStrike", "domains": ["crowdstrike.com"], "feed": "https://www.crowdstrike.com/en-us/blog/feed", "reliability": "B"},
    {"id": "sentinellabs", "name": "SentinelLabs", "domains": ["sentinelone.com"], "feed": "https://www.sentinelone.com/labs/feed/", "reliability": "B"},
    {"id": "checkpoint", "name": "Check Point Research", "domains": ["research.checkpoint.com"], "feed": "https://research.checkpoint.com/feed/", "reliability": "B"},
    {"id": "securelist", "name": "Kaspersky Securelist", "domains": ["securelist.com"], "feed": "https://securelist.com/feed/", "reliability": "B"},
    {"id": "eset", "name": "ESET Research", "domains": ["welivesecurity.com"], "feed": "https://www.welivesecurity.com/en/rss/feed/", "reliability": "B"},
    {"id": "sophos", "name": "Sophos X-Ops", "domains": ["news.sophos.com"], "feed": "https://news.sophos.com/en-us/category/threat-research/feed/", "reliability": "B"},
    {"id": "trendmicro", "name": "Trend Micro Research", "domains": ["trendmicro.com"], "feed": "https://feeds.trendmicro.com/TrendMicroResearch", "reliability": "B"},
    {"id": "proofpoint", "name": "Proofpoint", "domains": ["proofpoint.com"], "feed": "https://www.proofpoint.com/us/threat-insight-blog.xml", "reliability": "B"},
    {"id": "huntress", "name": "Huntress", "domains": ["huntress.com"], "feed": "https://www.huntress.com/blog/rss.xml", "reliability": "B"},
    {"id": "rapid7", "name": "Rapid7", "domains": ["rapid7.com"], "feed": "https://www.rapid7.com/blog/rss/", "reliability": "B"},
    {"id": "eyesecurity", "name": "Eye Security", "domains": ["eye.security"], "feed": "https://research.eye.security/rss/", "reliability": "B"},
    {"id": "cisa", "name": "CISA", "domains": ["cisa.gov"], "feed": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "reliability": "A"},
    {"id": "ncsc", "name": "NCSC (UK)", "domains": ["ncsc.gov.uk"], "feed": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "reliability": "A"},
    {"id": "certeu", "name": "CERT-EU", "domains": ["cert.europa.eu"], "feed": "", "reliability": "A"},
    {"id": "dfirreport", "name": "The DFIR Report", "domains": ["thedfirreport.com"], "feed": "https://thedfirreport.com/feed/", "reliability": "B"},
]
DEPTH_SOURCES = {"quick": 5, "standard": 10, "deep": 15}


def vendor_for_url(url: str) -> dict | None:
    host = urlparse(url).netloc.lower()
    for v in VENDORS:
        if any(host == d or host.endswith("." + d) for d in v["domains"]):
            return v
    return None


def canonical(url: str) -> str:
    p = urlparse(url.strip())
    path = re.sub(r"/+$", "", p.path) or "/"
    return urlunparse((p.scheme.lower() or "https", p.netloc.lower().removeprefix("www."), path, "", "", ""))


def _keywords(entities: dict) -> list[tuple[str, int]]:
    """(term, weight): CVEs 4, actors 3, malware 2, free keywords 1."""
    out: dict[str, int] = {}
    for key, w in (("cves", 4), ("actors", 3), ("malware", 2), ("keywords", 1)):
        for k in entities.get(key, []):
            if k and len(k) > 2:
                out[k] = max(out.get(k, 0), w)
    return list(out.items())


def _score(text: str, kws: list[tuple[str, int]]) -> int:
    t = text.lower()
    return sum(w for k, w in kws if re.search(rf"(?<![\w-]){re.escape(k.lower())}(?![\w-])", t))


def pull_feeds(vendors: list[dict]) -> list[tuple[dict, object, Exception | None]]:
    """Fetch and parse each vendor's RSS feed in parallel: [(vendor, parsed feed or None, error or None)]."""
    def pull(v: dict):
        try:
            with guarded_client(12) as client:
                r, _ = guarded_get(client, v["feed"])
                r.raise_for_status()
                return v, feedparser.parse(r.content), None
        except Exception as e:  # noqa: BLE001 - one bad feed must not stop discovery
            return v, None, e

    with ThreadPoolExecutor(max_workers=8) as ex:
        return list(ex.map(pull, [v for v in vendors if v["feed"]]))


MIN_FEED_SCORE = 3  # one CVE or actor, or several weaker terms together


def discover(entities: dict, seed_urls: list[str], vendor_ids: list[str] | None, open_web: bool, depth: str,
             logf=lambda m, level="info": None) -> list[dict]:
    """Return ranked candidate sources: [{url, title, publisher, published, reliability, origin, score}]."""
    limit = DEPTH_SOURCES.get(depth, 10)
    kws = _keywords(entities)
    cands: dict[str, dict] = {}

    for u in seed_urls:
        v = vendor_for_url(u)
        cands[canonical(u)] = {"url": u, "title": "", "publisher": v["name"] if v else urlparse(u).netloc,
                               "published": None, "reliability": v["reliability"] if v else "C", "origin": "seed", "score": 100}
    logf(f"{len(seed_urls)} seed URL(s) included")

    enabled = [v for v in VENDORS if (not vendor_ids or v["id"] in vendor_ids) and v["feed"]]
    if kws:
        for v, feed, err in pull_feeds(enabled):
            if err is not None or feed is None:
                logf(f"{v['name']} feed unavailable ({type(err).__name__})", "warn")
                continue
            if True:
                hits = 0
                for e in feed.entries[:60]:
                    text = f"{e.get('title', '')} {e.get('summary', '')} {' '.join(t.get('term', '') for t in e.get('tags', []))}"
                    s = _score(text, kws)
                    if s < MIN_FEED_SCORE:
                        continue
                    link = e.get("link", "")
                    if not link:
                        continue
                    pub = None
                    if e.get("published_parsed"):
                        pub = datetime(*e.published_parsed[:6], tzinfo=timezone.utc).date().isoformat()
                    key = canonical(link)
                    if key not in cands:
                        cands[key] = {"url": link, "title": e.get("title", ""), "publisher": v["name"], "published": pub,
                                      "reliability": v["reliability"], "origin": "vendor_feed", "score": 10 + s}
                        hits += 1
                if hits:
                    logf(f"{v['name']}: {hits} matching article(s)")

    key = get_settings().brave_search_api_key
    if key and kws:
        top = [k for k, _ in sorted(kws, key=lambda x: -x[1])[:5]]
        q = " ".join(f'"{k}"' if " " in k else k for k in top)
        queries = [q + " threat intelligence"]
        if not open_web:
            sites = " OR ".join(f"site:{d}" for v in enabled for d in v["domains"][:1])
            queries = [f"{q} ({sites})"]
        with httpx.Client(timeout=15) as client:
            for query in queries:
                try:
                    r = client.get("https://api.search.brave.com/res/v1/web/search",
                                   params={"q": query[:380], "count": 20},
                                   headers={"X-Subscription-Token": key, "Accept": "application/json"})
                    r.raise_for_status()
                    results = r.json().get("web", {}).get("results", [])
                except Exception as e:  # noqa: BLE001
                    logf(f"Web search failed ({type(e).__name__})", "warn")
                    continue
                for res in results:
                    link = res.get("url", "")
                    ck = canonical(link)
                    if not link or ck in cands:
                        continue
                    v = vendor_for_url(link)
                    if not v and not open_web:
                        continue
                    s = _score(f"{res.get('title', '')} {res.get('description', '')}", kws)
                    cands[ck] = {"url": link, "title": res.get("title", ""), "publisher": v["name"] if v else urlparse(link).netloc,
                                 "published": (res.get("page_age") or "")[:10] or None, "reliability": v["reliability"] if v else "C",
                                 "origin": "web_search", "score": s + (8 if v else 0)}
                logf(f"Web search returned {len(results)} result(s)")
    elif not key:
        logf("Open-web search not configured (BRAVE_SEARCH_API_KEY); using seed URLs and vendor feeds", "info")

    # De-duplicate near-identical titles (syndicated copies).
    ranked = sorted(cands.values(), key=lambda c: (c["score"], c["published"] or ""), reverse=True)
    seen_titles: set[str] = set()
    out = []
    for c in ranked:
        norm = re.sub(r"[^a-z0-9]+", " ", (c["title"] or "").lower()).strip()[:80]
        if norm and norm in seen_titles:
            continue
        if norm:
            seen_titles.add(norm)
        out.append(c)
    return out[:limit]


class BlockedAddress(httpx.RequestError):
    pass


def _public_ip(url: str) -> str | None:
    """SSRF guard: the one address to connect to for an http(s) URL, or None unless its host resolves exclusively to
    public (globally routable) addresses. Seed URLs come from users and inbound email, so without this a fetch could
    reach cloud metadata or internal services."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except (ValueError, OSError):
        return None
    first = None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            return None
        first = first or str(ip)
    return first


def is_public_url(url: str) -> bool:
    return _public_ip(url) is not None


_HOP_HEADERS = {"host", "connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization",
                "proxy-connection", "content-length"}


def _pin(url: str, headers: dict | None) -> tuple[str, dict, dict]:
    """(target URL with the checked IP as host, headers with the real Host, request extensions with the TLS SNI name)."""
    ip = _public_ip(url)
    if ip is None:
        raise BlockedAddress(f"Blocked non-public address {urlparse(url).hostname}")
    p = urlparse(url)
    host_ip = f"[{ip}]" if ":" in ip else ip
    port = f":{p.port}" if p.port else ""
    target = urlunparse(p._replace(netloc=host_ip + port))
    hdrs = {k: v for k, v in (headers or {}).items() if k.lower() not in _HOP_HEADERS}
    hdrs["Host"] = p.hostname + port
    return target, hdrs, ({"sni_hostname": p.hostname} if p.scheme == "https" else {})


def pinned_request(client: httpx.Client, method: str, url: str, headers: dict | None = None,
                   content: bytes | None = None) -> httpx.Response:
    """One request (no redirects) sent to the address that passed the SSRF check, not to a second DNS answer: the URL
    host is swapped for the checked IP and the name goes in the Host header and TLS SNI, so certificates are still
    verified against the real hostname. This closes the check-then-resolve-again (DNS rebinding) gap."""
    target, hdrs, ext = _pin(url, headers)
    return client.request(method, target, headers=hdrs, content=content, extensions=ext, follow_redirects=False)


async def pinned_request_async(client: httpx.AsyncClient, method: str, url: str, headers: dict | None = None,
                               content: bytes | None = None) -> httpx.Response:
    target, hdrs, ext = await asyncio.to_thread(_pin, url, headers)  # getaddrinfo blocks
    return await client.request(method, target, headers=hdrs, content=content, extensions=ext, follow_redirects=False)


def guarded_get(client: httpx.Client, url: str, max_redirects: int = 5) -> tuple[httpx.Response, str]:
    """GET following redirects by hand, every hop checked and pinned. Returns (response, final URL)."""
    for _ in range(max_redirects + 1):
        r = pinned_request(client, "GET", url)
        if r.is_redirect and r.headers.get("location"):
            url = urljoin(url, r.headers["location"])
            continue
        return r, url
    raise httpx.TooManyRedirects(f"More than {max_redirects} redirects", request=r.request)


# trust_env=False: an environment proxy would do its own DNS lookup and bypass the pinning.
def guarded_client(timeout: float) -> httpx.Client:
    return httpx.Client(timeout=timeout, headers={"User-Agent": UA}, follow_redirects=False, trust_env=False)


def _guarded_async_client(timeout: float) -> httpx.AsyncClient:
    # Short connect timeout: pages pull in trackers and CDNs that may be unreachable, and each would hold "networkidle".
    return httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=min(5.0, timeout)), headers={"User-Agent": UA}, follow_redirects=False, trust_env=False)


TEXT_ONLY_SKIP = frozenset({"image", "media", "font", "stylesheet"})  # not needed to extract article text
_WIRE_HEADERS = ("content-encoding", "content-length", "transfer-encoding")  # httpx already decoded the body


def run_guarded_page(work, *, user_agent: str | None = None, skip_types: frozenset[str] = frozenset(),
                     timeout: float = 30.0):
    """Run `await work(page)` in headless Chromium that fetches nothing itself: every request is replayed through
    `pinned_request_async` (concurrently) and the response handed back, so Chromium never resolves or connects to a
    host on its own. Service workers are blocked (they bypass routing) and WebSockets are closed.
    Call from a thread without a running event loop (pipeline workers, sync FastAPI endpoints)."""
    async def main():
        from playwright.async_api import async_playwright  # optional dependency

        async with async_playwright() as p, _guarded_async_client(timeout) as client:
            browser = await p.chromium.launch(headless=True)
            try:
                page = await (await browser.new_context(user_agent=user_agent, service_workers="block")).new_page()

                async def handle(route):
                    req = route.request
                    if req.url.startswith("data:"):
                        return await route.continue_()
                    if req.resource_type in skip_types:
                        return await route.abort()
                    try:
                        r = await pinned_request_async(client, req.method, req.url, headers=req.headers,
                                                       content=req.post_data_buffer)
                    except Exception:  # noqa: BLE001 - blocked address or network error: the page misses that resource
                        return await route.abort()
                    await route.fulfill(status=r.status_code, body=r.content,
                                        headers={k: v for k, v in r.headers.items() if k.lower() not in _WIRE_HEADERS})

                async def close_ws(ws):
                    await ws.close()

                await page.route("**/*", handle)
                await page.route_web_socket("**/*", close_ws)
                return await work(page)
            finally:
                await browser.close()

    return asyncio.run(main())


def _playwright_text(url: str) -> tuple[str, str]:
    async def work(page):
        await page.goto(url, wait_until="networkidle", timeout=45000)
        return await page.content(), await page.title()

    return run_guarded_page(work, user_agent=UA, skip_types=TEXT_ONLY_SKIP, timeout=get_settings().fetch_timeout)


_ERROR_MARKERS = re.compile(
    r"(NoSuchKey|AccessDenied|This XML file does not appear to have any style information|404 (?:-\s*)?Not Found|"
    r"Page not found|Just a moment\.\.\.|Attention Required! \| Cloudflare|Enable JavaScript and cookies to continue)", re.I)


def _looks_like_error(text: str) -> bool:
    head = text[:1500]
    return len(text) < 300 or bool(_ERROR_MARKERS.search(head)) and len(text) < 4000


def relevance(text: str, entities: dict) -> int:
    """How many seed entities the article mentions (CVE/actor weigh more)."""
    return _score(text, _keywords(entities))


def fetch(url: str, logf=lambda m, level="info": None) -> dict:
    """Fetch an article and extract its main text. Returns {text, title, published, last_modified, content_hash, method}."""
    html, title, last_modified, method = "", "", None, "httpx"
    if not is_public_url(url):
        logf(f"Skipped {url}: not a public http(s) address", "warn")
        return {"text": "", "title": "", "published": None, "last_modified": None,
                "content_hash": "", "method": method}
    try:
        with guarded_client(get_settings().fetch_timeout) as client:
            r, _ = guarded_get(client, url)
            r.raise_for_status()
            # Decode from the declared charset, else UTF-8 (httpx's fallback guesses mangle many vendor blogs).
            # Try strict UTF-8 first: many servers send a wrong ISO-8859-1 header for UTF-8 pages.
            try:
                html = r.content.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    html = r.content.decode(r.charset_encoding or "cp1252")
                except (LookupError, UnicodeDecodeError):
                    html = r.content.decode("utf-8", errors="replace")
            last_modified = r.headers.get("last-modified")
    except httpx.HTTPError as e:
        logf(f"HTTP fetch failed for {url} ({type(e).__name__}); trying headless browser", "warn")

    text = ""
    meta = None
    if html:
        text = trafilatura.extract(html, include_tables=True, include_comments=False, favor_recall=True) or ""
        meta = trafilatura.extract_metadata(html)
    if len(text) < 800:
        try:
            html2, title2 = _playwright_text(url)
            text2 = trafilatura.extract(html2, include_tables=True, favor_recall=True) or ""
            if len(text2) > len(text):
                text, html, title, method = text2, html2, title2, "headless"
                meta = trafilatura.extract_metadata(html2)
        except Exception as e:  # noqa: BLE001 - browser not installed or page blocked
            if not text:
                logf(f"Headless render unavailable for {url} ({type(e).__name__})", "warn")
    if text and _looks_like_error(text):
        logf(f"{url} returned an error page, not an article", "warn")
        text = ""
    if meta is not None:
        title = meta.title or title
    published = getattr(meta, "date", None) if meta is not None else None
    return {
        "text": text,
        "title": title,
        "published": published,
        "last_modified": last_modified,
        "content_hash": hashlib.sha256(text.encode()).hexdigest()[:16] if text else "",
        "method": method,
    }

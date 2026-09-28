"""Source discovery and fetching (pipeline stages 2 and 3 input).

Discovery = seed URLs + allow-listed vendor RSS feeds matched against the seed
entities + (optional) Brave web search. Fetching = httpx + trafilatura, with a
headless Chromium fallback (Playwright) for JavaScript-rendered pages such as
Check Point Research. Fetchers never submit forms or log in.
"""

from __future__ import annotations

import hashlib
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

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
        def pull(v: dict):
            try:
                with httpx.Client(timeout=12, headers={"User-Agent": UA}, follow_redirects=True) as client:
                    r = client.get(v["feed"])
                    r.raise_for_status()
                    return v, feedparser.parse(r.content), None
            except Exception as e:  # noqa: BLE001 - one bad feed must not stop discovery
                return v, None, e

        with ThreadPoolExecutor(max_workers=8) as ex:
            pulled = list(ex.map(pull, enabled))
        for v, feed, err in pulled:
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


def _playwright_text(url: str) -> tuple[str, str]:
    from playwright.sync_api import sync_playwright  # optional dependency

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(user_agent=UA)
            page.goto(url, wait_until="networkidle", timeout=45000)
            html = page.content()
            title = page.title()
        finally:
            browser.close()
    return html, title


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
    try:
        with httpx.Client(timeout=get_settings().fetch_timeout, headers={"User-Agent": UA}, follow_redirects=True) as client:
            r = client.get(url)
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

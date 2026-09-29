"""Email intake (spec section 2 step 1, section 3 P1 "forward-to-run").

Turns a forwarded vendor advisory / newsletter / colleague's "have we looked at this?" email into a draft run config:
subject + body become the seed, article links become seed URLs, and CVEs, actors, malware and indicators are detected
for the preview. Nothing here fetches a link or follows an instruction in the mail: all email content is untrusted data
and is only parsed, size-capped and shown back to the hunter.

Storage (no dedicated table): each intake item is a row in the `setting` table keyed ``intake:<IN-YYYY-NNNN>``; the
routing map (sender domain / ``+tag`` -> workspace) is the Setting ``intake_routing``.
"""

from __future__ import annotations

import base64
import email
import hashlib
import json
import re
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage, Message
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlencode, urlsplit, urlunsplit

from sqlalchemy.orm import Session

from . import ioc
from .models import Actor, MalwareTool, Setting, Workspace
from .records import next_id

MAX_RAW_BYTES = 10 * 1024 * 1024
MAX_BODY_CHARS = 60_000   # text we scan for entities
MAX_SEED_CHARS = 6_000    # text that becomes the run seed
MAX_NESTED = 5            # forwarded-inside-forwarded depth
ITEM_PREFIX = "intake:"
ROUTING_KEY = "intake_routing"

# ------------------------------------------------------------------ HTML -> text


class _HtmlText(HTMLParser):
    _BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "pre", "hr", "section",
              "article", "ul", "ol"}
    _SKIP = {"script", "style", "head", "title", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.links: list[tuple[str, str]] = []  # (href, anchor text)
        self._skip = 0
        self._href: str | None = None
        self._anchor: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip += 1
        elif tag in self._BLOCK:
            self.out.append("\n")
        if tag == "a":
            self._href = dict(attrs).get("href") or None
            self._anchor = []

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip:
            self._skip -= 1
        elif tag in self._BLOCK:
            self.out.append("\n")
        if tag == "a" and self._href:
            self.links.append((self._href, " ".join("".join(self._anchor).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.out.append(data)
        if self._href is not None:
            self._anchor.append(data)


def html_to_text(markup: str) -> tuple[str, list[tuple[str, str]]]:
    p = _HtmlText()
    try:
        p.feed(markup)
        p.close()
    except Exception:  # noqa: BLE001 - malformed HTML still yields what was parsed
        pass
    text = "".join(p.out).replace("\xa0", " ")
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip(), p.links


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁠-⁤﻿]")


def _clean(text: str) -> str:
    """Strip control / zero-width / bidi characters (used to hide text from a human reviewer)."""
    return _CTRL.sub("", text or "").replace("\r\n", "\n").replace("\r", "\n")


# ------------------------------------------------------------------ MIME walk

_FWD_MARKER = re.compile(
    r"^[ >]*(?:-{3,}\s*(?:Forwarded message|Original Message|Weitergeleitete Nachricht|Message transféré)\s*-{3,}"
    r"|Begin forwarded message:)[ \t]*$", re.I | re.M)
_OUTLOOK_HDR = re.compile(r"^[ >]*From:[^\n]+\n(?:[ >]*(?:Sent|Date|To|Cc|Subject):[^\n]*\n){2,6}", re.I | re.M)
_HDR_LINE = re.compile(r"^[ >]*(From|Sent|Date|To|Cc|Subject|Reply-To):[ \t]*(.*)$", re.I)
_SUBJ_PREFIX = re.compile(r"^\s*(?:(?:re|fw|fwd|aw|wg|tr)\s*(?:\[\d+\])?\s*:\s*)+", re.I)


def _decode_part(part: Message) -> str:
    try:
        return part.get_content() if hasattr(part, "get_content") else part.get_payload(decode=True).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - unknown charset or broken transfer-encoding
        raw = part.get_payload(decode=True) or b""
        return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def _addr(v: str | None) -> str:
    return (parseaddr(str(v or ""))[1] or "").strip().lower()


def _walk(msg: Message, depth: int = 0) -> dict:
    """Body text, html links and nested messages of one message (attachments other than emails are ignored)."""
    plain: list[str] = []
    htmls: list[str] = []
    nested: list[dict] = []

    def visit(part: Message) -> None:
        ctype = part.get_content_type()
        if ctype == "message/rfc822":
            if depth < MAX_NESTED:
                payload = part.get_payload()
                inner = payload[0] if isinstance(payload, list) and payload else payload
                if isinstance(inner, Message):
                    nested.append(_message(inner, depth + 1))
            return
        if part.is_multipart():
            for sub in part.iter_parts() if hasattr(part, "iter_parts") else part.get_payload():
                visit(sub)
            return
        disp = (part.get_content_disposition() or "").lower()
        fname = (part.get_filename() or "").lower()
        if ctype == "application/octet-stream" and fname.endswith(".eml") and depth < MAX_NESTED:
            data = part.get_payload(decode=True) or b""
            nested.append(_message(email.message_from_bytes(data[:MAX_RAW_BYTES], policy=policy.default), depth + 1))
            return
        if disp == "attachment":
            return
        if ctype == "text/plain":
            plain.append(_decode_part(part))
        elif ctype == "text/html":
            htmls.append(_decode_part(part))

    visit(msg)
    links: list[tuple[str, str]] = []
    html_text = ""
    for h in htmls:
        t, ls = html_to_text(h)
        html_text += ("\n\n" if html_text else "") + t
        links += ls
    text = "\n\n".join(p.strip() for p in plain if p.strip())
    # Newsletters often ship a stub plain-text part; use the HTML rendering when it carries clearly more content.
    if len(html_text) > 1.5 * len(text):
        text = html_text
    return {"text": _clean(text)[:MAX_BODY_CHARS], "links": links, "nested": nested}


def _message(msg: Message, depth: int = 0) -> dict:
    body = _walk(msg, depth)
    return {
        "from": _addr(msg.get("From")), "from_name": parseaddr(str(msg.get("From") or ""))[0][:120],
        "to": [a.lower() for _, a in getaddresses([str(v) for v in (msg.get_all("To") or []) + (msg.get_all("Cc") or [])]) if a][:20],
        "subject": _clean(str(msg.get("Subject") or "")).strip()[:300],
        "date": str(msg.get("Date") or "")[:80],
        "message_id": str(msg.get("Message-ID") or "").strip()[:300],
        **body,
    }


def _split_inline_forward(text: str) -> tuple[str, dict | None]:
    """Split "note from forwarder" / "forwarded original" for inline forwards (Gmail/Outlook/Apple Mail)."""
    m = _FWD_MARKER.search(text)
    start = m.start() if m else None
    if start is None:
        h = _OUTLOOK_HDR.search(text)
        if h and h.start() > 0:
            start = h.start()
    if start is None:
        return text, None
    note, rest = text[:start].strip(), text[m.end() if m else start:].lstrip("\n")
    hdrs: dict[str, str] = {}
    lines = rest.split("\n")
    i = 0
    while i < len(lines) and i < 12:
        hm = _HDR_LINE.match(lines[i])
        if hm:
            hdrs.setdefault(hm.group(1).lower(), hm.group(2).strip())
        elif lines[i].strip() and hdrs:
            break
        i += 1
    body = "\n".join(ln[1:].lstrip() if ln.startswith(">") else ln for ln in lines[i:]).strip()
    return note, {"from": _addr(hdrs.get("from", "").replace("[mailto:", " <").replace("]", ">")) or hdrs.get("from", "")[:200],
                  "subject": hdrs.get("subject", "")[:300], "date": (hdrs.get("date") or hdrs.get("sent") or "")[:80], "text": body}


def _strip_noise(text: str) -> str:
    """Drop signatures, unsubscribe footers and quoted header lines from the seed text."""
    out = []
    for ln in text.split("\n"):
        if ln.strip() in ("--", "-- "):
            break
        if re.search(r"unsubscribe|manage (?:your )?(?:email )?preferences|you (?:are )?receiv(?:ed|ing) this|view (?:this email )?in "
                     r"(?:your )?browser|confidentiality notice|this e-?mail (?:and any attachments )?(?:is|are) (?:intended|confidential)",
                     ln, re.I):
            continue
        if _HDR_LINE.match(ln):
            continue
        out.append(ln)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


# ------------------------------------------------------------------ URLs

_TRACK_DOMAINS = {"list-manage.com", "mailchimp.com", "mcusercontent.com", "sendgrid.net", "hubspotemail.net", "hs-sites.com",
                  "mktossl.com", "exacttarget.com", "pardot.com", "mailgun.org", "constantcontact.com", "cmail19.com", "cmail20.com",
                  "createsend.com", "substackcdn.com", "doubleclick.net", "google-analytics.com", "eloqua.com", "t.co", "lnkd.in",
                  "bit.ly", "safelinks.protection.outlook.com", "urldefense.com", "mimecastprotect.com"}
_TRACK_PREFIX = ("click.", "clicks.", "links.", "link.", "email.", "e.", "em.", "trk.", "track.", "mkt.")
_TRACK_PATH = re.compile(r"unsubscribe|opt-?out|optout|email-?preferences|manage-?preferences|subscription|/track/|/click|/open\?"
                         r"|/wf/click|/ls/click|/e2t/|/pixel|beacon|webview|view-in-browser|forward-to-a-friend|mailto:", re.I)
_SOCIAL = {"twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com", "instagram.com", "t.me", "mastodon.social",
           "bsky.app", "threads.net", "tiktok.com"}
_ASSET = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|ico|css|js|woff2?|ttf)(?:\?|$)", re.I)
_BOILERPLATE_PATH = re.compile(r"^/?(?:[a-z]{2}(?:-[a-z]{2})?/?)?(?:index\.html?|home|about(?:-us)?|contact(?:-us)?|privacy[\w-]*|legal|"
                               r"terms[\w-]*|careers|cookies?[\w-]*|subscribe|newsletter|blog|security|support|products?)?/?$", re.I)
_UTM = re.compile(r"^(?:utm_\w+|mc_cid|mc_eid|_hsenc|_hsmi|mkt_tok|ref|fbclid|gclid|trk|sc_channel|cmp|campaign)$", re.I)
_URL_TEXT = ioc.PATTERNS["url"]


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def _host_in(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _unwrap(url: str) -> str:
    """Undo Microsoft Safe Links, Proofpoint URL Defense, Google redirect and Mimecast wrappers."""
    for _ in range(3):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        q = parse_qs(parts.query)
        if host.endswith("safelinks.protection.outlook.com") and q.get("url"):
            url = q["url"][0]
        elif host.endswith("urldefense.com") and "/v3/__" in parts.path:
            url = unquote(parts.path.split("/v3/__", 1)[1].split("__;", 1)[0].rstrip("_"))
        elif host.endswith("urldefense.proofpoint.com") and q.get("u"):
            url = q["u"][0].replace("-", "%").replace("_", "/")
            url = unquote(url)
        elif host in ("www.google.com", "google.com") and parts.path == "/url" and (q.get("q") or q.get("url")):
            url = (q.get("q") or q.get("url"))[0]
        else:
            break
    return url


def _normalise_url(url: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, vs in parse_qs(parts.query, keep_blank_values=True).items() for v in vs if not _UTM.match(k)]
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", urlencode(query), ""))


def classify_url(raw: str, defanged: bool = False) -> dict | None:
    """{url, host, kind: article|indicator|noise, include, reason}. None when the string is not an http(s) URL."""
    url = ioc.refang(raw).strip().strip("<>\"'").rstrip(".,;:)]")
    if not re.match(r"^https?://", url, re.I):
        return None
    url = _unwrap(url)
    if not re.match(r"^https?://", url, re.I) or len(url) > 2000:
        return None
    try:
        url = _normalise_url(url)
        host = _host(url)
    except ValueError:
        return None
    if not host:
        return None
    path = urlsplit(url).path
    base = {"url": url, "host": host}
    if defanged:
        # A defanged link in a threat email is an indicator, never something to fetch.
        return {**base, "kind": "indicator", "include": False, "reason": "Defanged in the email, treated as an indicator"}
    if _ASSET.search(path):
        return {**base, "kind": "noise", "include": False, "reason": "Image or asset"}
    if _host_in(host, _SOCIAL):
        return {**base, "kind": "noise", "include": False, "reason": "Social profile link"}
    if _host_in(host, _TRACK_DOMAINS) or host.startswith(_TRACK_PREFIX):
        return {**base, "kind": "noise", "include": False, "reason": "Mailing-list tracking link"}
    if _TRACK_PATH.search(url):
        return {**base, "kind": "noise", "include": False, "reason": "Tracking, unsubscribe or preferences link"}
    if _BOILERPLATE_PATH.match(path) and not urlsplit(url).query:
        return {**base, "kind": "noise", "include": False, "reason": "Homepage or boilerplate page"}
    return {**base, "kind": "article", "include": True, "reason": "Article link"}


def extract_urls(text: str, links: list[tuple[str, str]]) -> list[dict]:
    seen: dict[str, dict] = {}
    cands: list[tuple[str, bool]] = [(h, False) for h, _ in links]
    for m in _URL_TEXT.finditer(text):
        raw = m.group(0)
        cands.append((raw, bool(re.search(r"hxxp|\[\.\]|\(\.\)|\[:\]|\[dot\]", raw, re.I))))
    for raw, defanged in cands:
        c = classify_url(raw, defanged)
        if c is None:
            continue
        prev = seen.get(c["url"])
        if prev is None or (prev["kind"] == "article" and c["kind"] == "indicator"):
            seen[c["url"]] = c
    order = {"article": 0, "indicator": 1, "noise": 2}
    return sorted(seen.values(), key=lambda x: order[x["kind"]])[:60]


# ------------------------------------------------------------------ entities

_ACTOR_PATS = [r"\bStorm-\d{4}\b", r"\bAPT ?\d{1,3}\b", r"\bUNC\d{3,5}\b", r"\bTA\d{3,4}\b", r"\bFIN\d{1,2}\b", r"\bCL-[A-Z]{3}-\d{4}\b",
               r"\b[A-Z][a-z]+ (?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Hail|Rain|Dust|Cyclone|Flood|Tsunami)\b",
               r"\b[A-Z][a-z]+ (?:Panda|Bear|Kitten|Chollima|Spider|Jackal|Tiger|Buffalo)\b",
               r"\b(?:Lazarus|Kimsuky|Sandworm|Turla|Scattered Spider|Volt Typhoon|Salt Typhoon|LockBit|BlackCat|ALPHV|Cl0p|Akira)\b"]
_TLP = re.compile(r"\bTLP\s*[:\-]?\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)\b", re.I)


def _names(db: Session | None, text: str) -> tuple[list[str], list[str]]:
    actors: dict[str, str] = {}
    malware: dict[str, str] = {}
    if db is not None:
        for a in db.query(Actor).all():
            for n in [a.name, *(a.aliases or [])]:
                if n and len(n) >= 3 and re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", text, re.I):
                    actors.setdefault(a.name.lower(), a.name)
                    break
        for m in db.query(MalwareTool).all():
            if m.name and len(m.name) >= 4 and re.search(rf"(?<![\w-]){re.escape(m.name)}(?![\w-])", text, re.I):
                malware.setdefault(m.name.lower(), m.name)
    for p in _ACTOR_PATS:
        for hit in re.findall(p, text):
            if not any(hit.lower() == k or hit.lower() in k for k in actors):
                actors.setdefault(hit.lower(), hit)
    return list(actors.values())[:20], list(malware.values())[:20]


def detect_tlp(*texts: str) -> str | None:
    for t in texts:
        m = _TLP.search(t or "")
        if m:
            v = m.group(1).upper()
            return "CLEAR" if v == "WHITE" else v
    return None


# ------------------------------------------------------------------ parse


def dedup_key(message_id: str, raw: bytes) -> str:
    mid = message_id.strip().strip("<>").strip().lower()
    return f"mid:{mid}" if mid else "sha256:" + hashlib.sha256(raw).hexdigest()


def parse_email(raw: bytes, db: Session | None = None) -> dict:
    """Parse RFC 822 bytes into an intake preview. Pure apart from the actor/malware name lookup."""
    if len(raw) > MAX_RAW_BYTES:
        raise ValueError(f"Email is larger than {MAX_RAW_BYTES // (1024 * 1024)} MB")
    msg = email.message_from_bytes(raw, policy=policy.default)
    top = _message(msg)
    if not (top["subject"] or top["text"] or top["nested"]) or (not msg.keys() and not top["text"]):
        raise ValueError("This does not look like an email (no headers or body)")
    warnings: list[str] = []

    # The "original" is the innermost forwarded message: attached message/rfc822 first, else an inline forward block.
    note = top["text"]
    original: dict | None = None
    links = list(top["links"])
    chain = top
    while chain["nested"]:
        chain = chain["nested"][0]
        original = chain
        links += chain["links"]
    if original is None:
        note, inline = _split_inline_forward(top["text"])
        if inline:
            original = {**inline, "links": [], "nested": []}
            # A forward of a forward: keep splitting while there is another marker.
            for _ in range(MAX_NESTED):
                _, deeper = _split_inline_forward(original["text"])
                if not deeper:
                    break
                original = {**deeper, "links": [], "nested": []}
    else:
        note, _ = _split_inline_forward(note)

    subject = _SUBJ_PREFIX.sub("", (original or {}).get("subject") or top["subject"]).strip() or top["subject"]
    body = (original or {}).get("text") or top["text"]
    body_clean = _strip_noise(body)
    note_clean = _strip_noise(note if original else "")
    seed_parts = [subject, body_clean]
    if note_clean and note_clean != body_clean:
        seed_parts.insert(1, f"Forwarded with note: {note_clean[:800]}")
    seed = "\n\n".join(p for p in seed_parts if p).strip()
    if len(seed) > MAX_SEED_CHARS:
        seed = seed[:MAX_SEED_CHARS].rsplit(" ", 1)[0] + " …"
        warnings.append(f"The body was truncated to {MAX_SEED_CHARS:,} characters for the seed.")

    scan = f"{subject}\n{note}\n{body}"[:MAX_BODY_CHARS]
    urls = extract_urls(scan, links)
    cves = sorted({c.upper() for c in ioc.PATTERNS["cve"].findall(scan)})
    actors, malware = _names(db, scan)

    # Indicators: scan the body without header lines (From:/To: addresses of the forward chain are not IoCs).
    body_only = "\n".join(ln for ln in scan.split("\n") if not _HDR_LINE.match(ln))
    people = {top["from"], (original or {}).get("from", ""), *top["to"]}
    people_domains = {p.split("@")[-1] for p in people if p and "@" in p}
    article_hosts = {u["host"] for u in urls if u["kind"] != "indicator"}
    article_urls = {u["url"] for u in urls if u["kind"] != "indicator"}
    iocs = []
    for x in ioc.extract(body_only):
        if x.type == "cve":
            continue
        if x.type == "email" and (x.value.lower() in people or x.value.split("@")[-1].lower() in people_domains):
            continue
        if x.type == "domain" and (x.value.lower() in article_hosts or x.value.lower() in people_domains
                                   or _host_in(x.value.lower(), people_domains)):
            continue
        if x.type == "url":
            try:
                if _normalise_url(_unwrap(x.value)) in article_urls or _host(x.value) in article_hosts:
                    continue
            except ValueError:
                continue
        iocs.append({"type": x.type, "value": x.value, "display": ioc.defang(x.value, x.type)})
        if len(iocs) >= 200:
            warnings.append("Only the first 200 indicators are shown.")
            break

    return {
        "message_id": top["message_id"], "dedup_key": dedup_key(top["message_id"], raw),
        "from": top["from"], "from_name": top["from_name"], "to": top["to"], "subject": top["subject"], "date": top["date"],
        "original": ({"from": original.get("from", ""), "subject": original.get("subject", ""), "date": original.get("date", "")}
                     if original else None),
        "note": note_clean[:2000] if original else "",
        "seed": seed or subject or "(empty email)", "urls": urls, "cves": cves, "actors": actors, "malware": malware,
        "iocs": iocs, "tlp": detect_tlp(top["subject"], subject, body[:3000]), "warnings": warnings,
        "size": len(raw),
    }


# ------------------------------------------------------------------ inbound webhooks

def _b64(s: str) -> bytes:
    try:
        return base64.b64decode(s or "", validate=False)
    except (ValueError, TypeError):
        return b""


def webhook_to_mime(payload: dict) -> tuple[bytes, str]:
    """Normalise an inbound-mail webhook payload to RFC 822 bytes. Returns (raw, provider).

    Postmark Inbound (JSON; best supported): RawEmail when "include raw email content" is on, else From/To/Cc/Subject/
      MessageID/Date/TextBody/HtmlBody/Headers[] and Attachments[] (message/rfc822 attachments become nested emails).
    SendGrid Inbound Parse: `email` (raw MIME, "POST the raw, full MIME message") else from/to/subject/text/html/headers.
    Mailgun routes: `body-mime` (the /mime variant) else sender|from/recipient|To/subject/body-plain/body-html/Message-Id.
    """
    for key, provider in (("RawEmail", "postmark"), ("email", "sendgrid"), ("body-mime", "mailgun"), ("raw", "raw")):
        v = payload.get(key)
        if isinstance(v, str) and len(v) > 20 and re.search(r"^[\w-]+:", v, re.M):
            return v.encode("utf-8", "replace"), provider
    if any(k in payload for k in ("TextBody", "HtmlBody", "MessageID", "FromFull")):
        provider = "postmark"
        hdr = {h.get("Name", ""): h.get("Value", "") for h in payload.get("Headers") or [] if isinstance(h, dict)}
        frm, to, cc, subj = payload.get("From"), payload.get("To"), payload.get("Cc"), payload.get("Subject")
        mid = payload.get("MessageID") or hdr.get("Message-ID")
        text, htm, date = payload.get("TextBody"), payload.get("HtmlBody"), payload.get("Date")
        orig_rcpt = payload.get("OriginalRecipient")
        atts = payload.get("Attachments") or []
    elif any(k in payload for k in ("body-plain", "body-html", "stripped-text")):
        provider = "mailgun"
        hdrs = payload.get("message-headers")
        hdr = {}
        if isinstance(hdrs, str):
            try:
                hdrs = json.loads(hdrs)
            except ValueError:
                hdrs = []
        for pair in hdrs or []:
            if isinstance(pair, list) and len(pair) == 2:
                hdr.setdefault(pair[0], pair[1])
        frm, to, cc, subj = payload.get("from") or payload.get("sender"), payload.get("To") or payload.get("recipient"), None, payload.get("subject")
        mid = payload.get("Message-Id") or hdr.get("Message-Id")
        text, htm, date, orig_rcpt, atts = payload.get("body-plain"), payload.get("body-html"), payload.get("Date"), payload.get("recipient"), []
    else:
        provider = "sendgrid"
        hdr = {}
        for ln in str(payload.get("headers") or "").splitlines():
            if ":" in ln and not ln.startswith((" ", "\t")):
                k, _, v = ln.partition(":")
                hdr.setdefault(k.strip(), v.strip())
        env = payload.get("envelope")
        try:
            env = json.loads(env) if isinstance(env, str) else env or {}
        except ValueError:
            env = {}
        frm, to, cc, subj = payload.get("from"), payload.get("to"), payload.get("cc"), payload.get("subject")
        mid = hdr.get("Message-ID") or hdr.get("Message-Id")
        text, htm, date = payload.get("text"), payload.get("html"), hdr.get("Date")
        orig_rcpt = ",".join(env.get("to") or []) if isinstance(env, dict) else None
        atts = []
    if not (text or htm or subj):
        raise ValueError("Webhook payload has no email content (expected Postmark, SendGrid or Mailgun inbound fields)")
    m = EmailMessage()
    for k, v in (("From", frm), ("To", to), ("Cc", cc), ("Subject", subj), ("Message-ID", mid), ("Date", date),
                 ("X-Original-To", orig_rcpt)):
        if v:
            try:
                m[k] = str(v).replace("\n", " ").replace("\r", " ")[:2000]
            except (ValueError, TypeError):
                pass
    m.set_content(str(text or ""))
    if htm:
        m.add_alternative(str(htm), subtype="html")
    for a in atts[:10]:
        if isinstance(a, dict) and (a.get("ContentType") == "message/rfc822" or str(a.get("Name", "")).lower().endswith(".eml")):
            inner = email.message_from_bytes(_b64(a.get("Content", ""))[:MAX_RAW_BYTES], policy=policy.default)
            m.make_mixed()
            m.attach(_rfc822(inner))
    return bytes(m), provider


def _rfc822(inner: Message) -> Message:
    from email.mime.message import MIMEMessage
    return MIMEMessage(inner)


# ------------------------------------------------------------------ routing (sender domain / +tag -> workspace)

def get_routing(db: Session) -> dict:
    row = db.get(Setting, ROUTING_KEY)
    v = dict(row.value or {}) if row else {}
    return {"domains": dict(v.get("domains") or {}), "tags": dict(v.get("tags") or {}), "user_id": v.get("user_id")}


def set_routing(db: Session, domains: dict[str, str], tags: dict[str, str], user_id: str | None = None) -> dict:
    ws_ids = {w.id for w in db.query(Workspace).all()}
    bad = sorted({v for v in [*domains.values(), *tags.values()] if v not in ws_ids})
    if bad:
        raise ValueError(f"Unknown workspace(s): {', '.join(bad)}")
    clean_d = {k.strip().lower().lstrip("@"): v for k, v in domains.items() if k.strip()}
    clean_t = {k.strip().lower().lstrip("+"): v for k, v in tags.items() if k.strip()}
    row = db.get(Setting, ROUTING_KEY) or Setting(key=ROUTING_KEY, value={})
    row.value = {"domains": clean_d, "tags": clean_t, "user_id": user_id}
    db.merge(row)
    db.commit()
    return get_routing(db)


def _plus_tags(addresses: list[str]) -> list[str]:
    return [a.split("@")[0].split("+", 1)[1].lower() for a in addresses if "+" in a.split("@")[0]]


def suggest_workspace(db: Session, parsed: dict, extra_recipients: list[str] | None = None) -> dict | None:
    """{id, name, reason} from the routing map: a +tag on a recipient wins, then the forwarder's then the original sender's
    domain (subdomains match their parent). A +tag equal to a workspace id works without a mapping."""
    routing = get_routing(db)
    ws = {w.id: w for w in db.query(Workspace).all()}
    rcpts = [*(parsed.get("to") or []), *(extra_recipients or [])]
    for tag in _plus_tags(rcpts):
        wid = routing["tags"].get(tag) or (tag if tag in ws else None)
        if wid in ws:
            return {"id": wid, "name": ws[wid].name, "reason": f"Recipient tag +{tag}"}
    for who, label in ((parsed.get("from"), "Sender"), (((parsed.get("original") or {}).get("from")), "Original sender")):
        dom = (who or "").split("@")[-1].lower() if who and "@" in who else ""
        while dom:
            wid = routing["domains"].get(dom)
            if wid in ws:
                return {"id": wid, "name": ws[wid].name, "reason": f"{label} domain {dom}"}
            dom = dom.split(".", 1)[1] if "." in dom else ""
    return None


# ------------------------------------------------------------------ items (setting rows)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_duplicate(db: Session, key: str) -> dict | None:
    for row in db.query(Setting).filter(Setting.key.like(ITEM_PREFIX + "%")).all():
        if (row.value or {}).get("dedup_key") == key:
            return dict(row.value)
    return None


def save_item(db: Session, parsed: dict, via: str, suggested: dict | None) -> dict:
    iid = next_id(db, "intake", "IN", yearly=True)
    item = {**parsed, "id": iid, "via": via, "received_at": _now(), "suggested_workspace": suggested,
            "status": "parsed", "research_id": None, "run_id": None, "error": None}
    db.add(Setting(key=ITEM_PREFIX + iid, value=item))
    db.commit()
    return item


def get_item(db: Session, iid: str) -> dict | None:
    row = db.get(Setting, ITEM_PREFIX + iid)
    return dict(row.value) if row else None


def update_item(db: Session, iid: str, **changes) -> dict:
    row = db.get(Setting, ITEM_PREFIX + iid)
    row.value = {**(row.value or {}), **changes, "updated_at": _now()}
    db.commit()
    return dict(row.value)


def list_items(db: Session, limit: int = 50) -> list[dict]:
    rows = [dict(r.value or {}) for r in db.query(Setting).filter(Setting.key.like(ITEM_PREFIX + "%")).all()]
    rows.sort(key=lambda x: x.get("received_at") or "", reverse=True)
    return rows[:limit]


def item_summary(item: dict) -> dict:
    keys = ("id", "status", "via", "received_at", "from", "subject", "original", "research_id", "run_id", "suggested_workspace",
            "error", "message_id")
    return {k: item.get(k) for k in keys} | {"counts": {"urls": len([u for u in item.get("urls", []) if u.get("include")]),
                                                        "cves": len(item.get("cves", [])), "iocs": len(item.get("iocs", []))}}

"""IoC extraction, normalisation, refang/defang and false-positive filtering (spec section 9)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# ---------- refang / defang ----------

_REFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[@\]|\[at\]", re.I), "@"),
]


def refang(value: str) -> str:
    v = value.strip()
    for pat, rep in _REFANG:
        v = pat.sub(rep, v)
    return v


def defang(value: str, ioc_type: str | None = None) -> str:
    v = refang(value)
    if ioc_type in ("sha256", "sha1", "md5", "file_name", "file_path", "registry", "mutex", "user_agent", "ja3", "cve", "wallet"):
        return v
    v = re.sub(r"^http", "hxxp", v, flags=re.I)
    if ioc_type == "email":
        return v.replace("@", "[@]").replace(".", "[.]")
    if ioc_type == "ipv6":
        return v.replace(":", "[:]", 1)
    if ioc_type == "ipv4" or (ioc_type is None and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v)):
        head, _, tail = v.rpartition(".")
        return f"{head}[.]{tail}"
    # Defang the dots in the host part only for URLs.
    if ioc_type == "url" or "://" in v:
        m = re.match(r"^(hxxps?://)([^/]+)(.*)$", v, re.I)
        if m:
            return m.group(1) + m.group(2).replace(".", "[.]") + m.group(3)
    return v.replace(".", "[.]")


# ---------- patterns ----------

_TLDS = (
    "com|net|org|info|biz|io|co|ru|cn|top|xyz|app|dev|online|site|club|live|me|tk|ml|ga|cf|gq|pw|cc|su|in|uk|de|fr|nl|"
    "br|ir|kp|us|eu|jp|kr|tw|hk|sg|au|ca|link|click|shop|store|cloud|tech|pro|space|website|fun|icu|buzz|work|zip|mov|"
    "ngrok-free\\.app|ngrok\\.io|onion"
)

PATTERNS: dict[str, re.Pattern] = {
    "url": re.compile(r"\b(?:hxxps?|https?|ftp)(?:\[:\]|:)//(?:\[\.\]|\(\.\)|\[dot\]|[^\s\"'<>()\[\]])+", re.I),
    "email": re.compile(r"\b[a-z0-9._%+-]+(?:@|\[@\]|\[at\])[a-z0-9-]+(?:(?:\.|\[\.\])[a-z0-9-]+)*(?:\.|\[\.\])[a-z]{2,}\b", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|\[\.\]|\(\.\))){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]|\(\.\)))+(?:" + _TLDS + r")\b", re.I
    ),
    "file_path": re.compile(r"\b[A-Z]:\\(?:[^\\/:*?\"<>|\r\n\s]+\\)*[^\\/:*?\"<>|\r\n\s]+\.[a-z0-9]{2,4}\b", re.I),
    "registry": re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKU|HKCR)\\[^\s\"'<>]+", re.I),
    "file_name": re.compile(r"\b[\w\-]+\.(?:aspx|asp|jsp|php|exe|dll|ps1|bat|vbs|js|hta|lnk|sys|scr|msi|jar)\b", re.I),
    "wallet": re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
}

# ---------- allow-lists (drop false positives) ----------

ALLOW_DOMAINS = {
    "microsoft.com", "msft.net", "windows.net", "windowsupdate.com", "office.com", "live.com", "azure.com", "google.com",
    "googleapis.com", "gstatic.com", "mandiant.com", "cloud.google.com", "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "talosintelligence.com", "cisco.com", "cisa.gov", "crowdstrike.com", "sentinelone.com", "checkpoint.com",
    "research.checkpoint.com", "eye.security", "research.eye.security", "kaspersky.com", "securelist.com", "eset.com",
    "welivesecurity.com", "sophos.com", "trendmicro.com", "proofpoint.com", "huntress.com", "rapid7.com", "ncsc.gov.uk",
    "cert.europa.eu", "thedfirreport.com", "mitre.org", "attack.mitre.org", "nvd.nist.gov", "github.com", "virustotal.com",
    "example.com", "example.org", "example.net", "twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com",
    "w3.org", "schema.org", "wikipedia.org", "abuse.ch", "shodan.io", "greynoise.io", "abuseipdb.com", "first.org",
    "gov.uk", "cloudflare.com", "amazonaws.com", "akamai.net", "apple.com", "mozilla.org",
}
TECH_NAMES = {"asp.net", "node.js", "next.js", "vue.js", "react.js", "express.js", "angular.js", "d3.js", "three.js", "chart.js",
              "socket.io", "microsoft.net", "vb.net", "ado.net", "system.web", "system.io", "system.net", "web.config", "readme.md"}
BENIGN_FILE_NAMES = {"cmd.exe", "powershell.exe", "pwsh.exe", "w3wp.exe", "rundll32.exe", "svchost.exe", "explorer.exe",
                     "lsass.exe", "wmic.exe", "csc.exe", "conhost.exe", "services.exe", "msiexec.exe", "regsvr32.exe",
                     "mshta.exe", "schtasks.exe", "net.exe", "whoami.exe", "iisreset.exe", "signout.aspx", "toolpane.aspx",
                     "start.aspx", "default.aspx"}
# File names that look like domains (".js", ".exe" aren't TLDs, but ".zip"/".mov" are).
_FILE_EXT_TLDS = {"zip", "mov", "app", "sh", "py", "pl", "rs"}


def _in_allow_list(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == a or d.endswith("." + a) for a in ALLOW_DOMAINS)


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_link_local or addr.is_unspecified)


@dataclass
class Extracted:
    type: str
    value: str  # refanged
    contexts: list[str] = field(default_factory=list)


def _sentence_around(text: str, start: int, end: int, width: int = 160) -> str:
    s = max(0, text.rfind(".", 0, start - 1) + 1, start - width)
    e = text.find(".", end)
    e = min(len(text), e + 1 if e != -1 else end + width, end + width)
    return re.sub(r"\s+", " ", text[s:e]).strip()


def extract(text: str) -> list[Extracted]:
    """Extract indicators from free text. Returns refanged, de-duplicated values with context."""
    found: dict[tuple[str, str], Extracted] = {}
    consumed: list[tuple[int, int]] = []

    def overlaps(a: int, b: int) -> bool:
        return any(a < e and b > s for s, e in consumed)

    def add(t: str, v: str, m: re.Match) -> None:
        key = (t, v.lower() if t not in ("url", "file_path", "registry") else v)
        ctx = _sentence_around(text, m.start(), m.end())
        if key in found:
            if ctx not in found[key].contexts and len(found[key].contexts) < 5:
                found[key].contexts.append(ctx)
        else:
            found[key] = Extracted(t, v, [ctx])

    order = ["url", "email", "sha256", "sha1", "md5", "cve", "ipv4", "registry", "file_path", "domain", "file_name", "wallet"]
    for t in order:
        for m in PATTERNS[t].finditer(text):
            if overlaps(m.start(), m.end()):
                continue
            raw = m.group(0).rstrip(".,;:")
            v = refang(raw)
            if t == "url":
                host = re.sub(r"^[a-z]+://", "", v, flags=re.I).split("/")[0].split(":")[0]
                if _in_allow_list(host):
                    consumed.append((m.start(), m.end()))
                    continue
            elif t == "email":
                if _in_allow_list(v.split("@")[-1]):
                    continue
            elif t == "ipv4":
                if not _is_public_ip(v):
                    continue
            elif t == "domain":
                if _in_allow_list(v) or v.lower() in TECH_NAMES or re.match(r"^system\.", v, re.I):
                    continue
                tld = v.rsplit(".", 1)[-1].lower()
                if tld in _FILE_EXT_TLDS and "\\" in text[max(0, m.start() - 2):m.start()]:
                    continue
                if v.count(".") == 1 and v.split(".")[0].lower() in ("e", "i", "etc", "vs", "fig"):
                    continue
            elif t == "file_name":
                if v.lower() in BENIGN_FILE_NAMES:
                    continue
            elif t == "cve":
                v = v.upper()
            elif t in ("sha256", "sha1", "md5"):
                v = v.lower()
                # Skip long hex runs embedded in bigger tokens.
                if (m.start() > 0 and text[m.start() - 1].isalnum()) or (m.end() < len(text) and text[m.end()].isalnum()):
                    continue
            elif t == "wallet":
                if not re.search(r"(bitcoin|btc|wallet|ransom)", text[max(0, m.start() - 200):m.end() + 200], re.I):
                    continue
            consumed.append((m.start(), m.end()))
            add(t, v, m)
    return list(found.values())


def detect_type(value: str) -> str:
    v = refang(value)
    for t in ("url", "email", "sha256", "sha1", "md5", "cve", "ipv4", "registry", "file_path", "domain", "file_name"):
        if PATTERNS[t].fullmatch(v):
            return t
    try:
        ip = ipaddress.ip_address(v)
        return "ipv6" if ip.version == 6 else "ipv4"
    except ValueError:
        pass
    return "other"


SR_TYPE_NAMES = {
    "ipv4": "IP address", "ipv6": "IP address", "domain": "Domain", "url": "URL", "sha256": "SHA-256 hash",
    "sha1": "SHA-1 hash", "md5": "MD5 hash", "file_name": "File name", "file_path": "File path", "email": "Email",
    "registry": "Registry key", "user_agent": "User agent", "wallet": "Crypto wallet", "mutex": "Mutex", "cve": "CVE",
}

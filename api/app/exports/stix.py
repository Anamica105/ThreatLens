"""STIX 2.1 bundle export of a research record (spec section 3 P2 "STIX 2.1 export").

Objects: identity (producer), report, intrusion-set (actors, with aliases), malware / tool, vulnerability (CVE external
refs), attack-pattern (ATT&CK external refs + kill chain phases), indicator (STIX patterns; values refanged), identity
(targeted sectors), relationship (uses / targets / indicates) and the TLP 2.0 marking definitions (OASIS TLP 2.0
extension). Indicators an analyst hid from hunts (false positive, benign, excluded, expired) are not exported.

IDs are deterministic (UUIDv5) so re-exporting the same research updates rather than duplicates objects in a TIP;
entities that exist outside one report (actors, CVEs, techniques, malware) use a global key so exports merge.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from .. import ioc as ioc_mod
from ..records import hidden_from_hunts

NS = uuid.UUID("7c6b1b4e-3f55-4b0e-9d5f-6d1e7a8b9c01")  # ThreatLens STIX namespace

# OASIS TLP 2.0 marking definitions (https://github.com/oasis-open/cti-stix-common-objects, extension-definition--60a3c5c5...)
TLP2_EXTENSION = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
TLP2_CREATOR = "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01"
TLP2 = {
    "CLEAR": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "GREEN": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "AMBER": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "AMBER+STRICT": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "RED": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}

CONFIDENCE = {"low": 15, "moderate": 50, "medium": 50, "high": 85, "confirmed": 95}
MOTIVATION = {"financial": "personal-gain", "espionage": "organizational-gain", "hacktivism": "ideology", "ideology": "ideology",
              "destruction": "dominance", "sabotage": "dominance", "notoriety": "notoriety", "revenge": "revenge",
              "coercion": "coercion"}
MALWARE_TYPES = {"webshell": "webshell", "ransomware": "ransomware", "backdoor": "backdoor", "loader": "downloader",
                 "downloader": "downloader", "dropper": "dropper", "rat": "remote-access-trojan", "wiper": "wiper",
                 "rootkit": "rootkit", "bootkit": "bootkit", "keylogger": "keylogger", "spyware": "spyware", "worm": "worm",
                 "botnet": "bot", "bot": "bot", "trojan": "trojan", "stealer": "spyware", "infostealer": "spyware"}
TOOL_KINDS = {"tool", "lolbin", "rmm", "framework", "utility", "offensive_tool"}
INDICATOR_TYPES = {"malicious": ["malicious-activity"], "suspicious": ["anomalous-activity"]}


def _ts(v) -> str:
    if isinstance(v, str) and v:
        try:
            v = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            try:
                v = datetime.strptime(v[:10], "%Y-%m-%d")
            except ValueError:
                v = None
    if not isinstance(v, datetime):
        v = datetime.now(timezone.utc)
    if v.tzinfo is None:
        v = v.replace(tzinfo=timezone.utc)
    return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{v.microsecond // 1000:03d}Z"


def _id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, f'{kind}|{key}')}"


def _q(v: str) -> str:
    """Escape a value for a STIX pattern string literal."""
    return v.replace("\\", "\\\\").replace("'", "\\'")


def pattern_for(t: str, value: str) -> str | None:
    v = ioc_mod.refang(value or "").strip()
    if not v:
        return None
    if t == "ipv4":
        return f"[ipv4-addr:value = '{_q(v)}']"
    if t == "ipv6":
        return f"[ipv6-addr:value = '{_q(v)}']"
    if t == "domain":
        return f"[domain-name:value = '{_q(v.lower())}']"
    if t == "url":
        return f"[url:value = '{_q(v)}']"
    if t == "email":
        return f"[email-addr:value = '{_q(v.lower())}']"
    if t in ("md5", "sha1", "sha256"):
        algo = {"md5": "MD5", "sha1": "'SHA-1'", "sha256": "'SHA-256'"}[t]
        return f"[file:hashes.{algo} = '{_q(v.lower())}']"
    if t == "file_name":
        return f"[file:name = '{_q(v)}']"
    if t == "registry":
        return f"[windows-registry-key:key = '{_q(v)}']"
    if t == "mutex":
        return f"[mutex:name = '{_q(v)}']"
    return None


def exportable_iocs(rec: dict) -> list[dict]:
    """IoCs that may leave ThreatLens: never false positives / benign / analyst-excluded / expired (hidden from hunts)."""
    include_expired = bool((rec.get("ioc_review") or {}).get("include_expired"))
    out = []
    for i in rec.get("iocs", []) or []:
        hidden = i.get("hidden_from_hunts")
        if hidden is None:
            hidden = hidden_from_hunts(i.get("verdict"), bool(i.get("excluded")), include_expired)
        if hidden or i.get("verdict") in ("false_positive", "benign") or i.get("excluded") or i.get("hidden"):
            continue
        out.append(i)
    return out


def _tlp_objects() -> list[dict]:
    created = "2022-10-01T00:00:00.000Z"
    return [{
        "type": "marking-definition", "spec_version": "2.1", "id": mid, "created": created, "created_by_ref": TLP2_CREATOR,
        "name": f"TLP:{name}",
        "extensions": {TLP2_EXTENSION: {"extension_type": "property-extension", "tlp_2_0": name.lower()}},
    } for name, mid in TLP2.items()]


def build_bundle(r, rec: dict, producer: str = "ThreatLens", base_url: str = "") -> dict:
    """Build a STIX 2.1 bundle (a plain dict) from a Research row + its record."""
    rid = r.id
    tlp = (rec.get("tlp") or r.tlp or "AMBER").upper()
    tlp = "CLEAR" if tlp == "WHITE" else tlp
    marking = TLP2.get(tlp, TLP2["AMBER"])
    created = _ts(getattr(r, "created_at", None))
    modified = _ts(rec.get("updated_at") or getattr(r, "updated_at", None))
    if modified < created:
        modified = created
    identity_id = _id("identity", producer)
    common = {"spec_version": "2.1", "created_by_ref": identity_id, "object_marking_refs": [marking]}

    sources = {s.get("id"): s for s in rec.get("sources", []) or [] if s.get("id")}

    def src_refs(ids) -> list[dict]:
        refs = []
        for sid in ids or []:
            s = sources.get(sid)
            if s and s.get("url"):
                ref = {"source_name": (s.get("publisher") or "source")[:200], "url": s["url"]}
                if s.get("title"):
                    ref["description"] = s["title"][:500]
                refs.append(ref)
        return refs

    def sdo(kind: str, key: str, **props) -> dict:
        o = {"type": kind, "id": _id(kind, key), "created": created, "modified": modified, **common}
        o.update({k: v for k, v in props.items() if v not in (None, "", [], {})})
        return o

    objects: list[dict] = []
    rels: list[dict] = []

    def rel(src: dict, kind: str, dst: dict, description: str = "") -> None:
        key = f"{rid}|{src['id']}|{kind}|{dst['id']}"
        o = {"type": "relationship", "id": _id("relationship", key), "created": created, "modified": modified,
             "relationship_type": kind, "source_ref": src["id"], "target_ref": dst["id"], **common}
        if description:
            o["description"] = description
        rels.append(o)

    # Actors -> intrusion-set
    actors = []
    for a in rec.get("threat_actors", []) or []:
        name = (a.get("name") or "").strip()
        if not name:
            continue
        aliases = [x for x in a.get("aliases") or [] if x and x != name]
        motives = [MOTIVATION[m.lower()] for m in a.get("motivation") or [] if m and m.lower() in MOTIVATION]
        desc = "; ".join(x for x in [f"Origin: {a['origin']}" if a.get("origin") else "",
                                     f"Attribution confidence: {a['attribution_confidence']}" if a.get("attribution_confidence") else ""] if x)
        o = sdo("intrusion-set", name.lower(), name=name, aliases=aliases, description=desc,
                primary_motivation=motives[0] if motives else None, secondary_motivations=motives[1:],
                confidence=CONFIDENCE.get((a.get("attribution_confidence") or "").lower()),
                external_references=src_refs(a.get("source_ids")))
        actors.append(o)

    # Malware / tools
    malware = []
    for m in rec.get("malware_tools", []) or []:
        name = (m.get("name") or "").strip()
        if not name:
            continue
        kind = (m.get("type") or "malware").lower()
        refs = src_refs(m.get("source_ids"))
        if kind in TOOL_KINDS:
            o = sdo("tool", name.lower(), name=name, description=m.get("role"), external_references=refs)
        else:
            o = sdo("malware", name.lower(), name=name, is_family=True, description=m.get("role"),
                    malware_types=[MALWARE_TYPES.get(kind, "unknown")], external_references=refs)
        malware.append(o)

    # Vulnerabilities
    vulns = []
    for v in rec.get("vulnerabilities", []) or []:
        cve = (v.get("cve") or "").strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            continue
        refs = [{"source_name": "cve", "external_id": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}] + src_refs(v.get("source_ids"))
        vulns.append(sdo("vulnerability", cve, name=cve, description=v.get("description"), external_references=refs))

    # ATT&CK techniques
    patterns: dict[str, dict] = {}
    for t in rec.get("mitre", []) or []:
        tid = (t.get("technique_id") or "").strip().upper()
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid):
            continue
        phase = re.sub(r"[^a-z0-9]+", "-", (t.get("tactic") or "").lower()).strip("-")
        if tid in patterns:
            if phase and {"kill_chain_name": "mitre-attack", "phase_name": phase} not in patterns[tid].get("kill_chain_phases", []):
                patterns[tid].setdefault("kill_chain_phases", []).append({"kill_chain_name": "mitre-attack", "phase_name": phase})
            continue
        name = t.get("technique") or tid
        if t.get("sub_technique"):
            name = f"{name}: {t['sub_technique']}"
        url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        patterns[tid] = sdo("attack-pattern", tid, name=name, description=t.get("procedure"),
                            kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": phase}] if phase else [],
                            external_references=[{"source_name": "mitre-attack", "external_id": tid, "url": url}]
                            + src_refs(t.get("source_ids")))

    # Targeted sectors
    sectors = []
    for ind in rec.get("industries", []) or []:
        name = (ind.get("industry") if isinstance(ind, dict) else str(ind or "")).strip()
        if name:
            sectors.append(sdo("identity", f"sector|{name.lower()}", name=name, identity_class="class",
                               sectors=[re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")]))

    # Indicators
    valid_from = _ts((next((s.get("published") for s in sources.values() if s.get("published")), None)) or getattr(r, "created_at", None))
    indicators = []
    for i in exportable_iocs(rec):
        t = i.get("type", "")
        pat = pattern_for(t, i.get("value", ""))
        if not pat:
            continue
        value = ioc_mod.refang(i.get("value", ""))
        desc = i.get("role") or i.get("context") or ""
        o = sdo("indicator", f"{rid}|{t}|{value.lower()}", name=value, description=desc, pattern=pat, pattern_type="stix",
                pattern_version="2.1", valid_from=valid_from, indicator_types=INDICATOR_TYPES.get(i.get("verdict"), ["unknown"]),
                labels=[f"threatlens-verdict:{i.get('verdict') or 'unknown'}"], external_references=src_refs(i.get("source_ids")))
        indicators.append(o)
        text = f"{desc} {' '.join(i.get('contexts') or [])}".lower()
        hit = [m for m in malware if m["name"].lower() in text]
        hit_actors = [a for a in actors if a["name"].lower() in text or any(x.lower() in text for x in a.get("aliases", []))]
        for target in hit or hit_actors or actors:
            rel(o, "indicates", target, "" if (hit or hit_actors) else f"Reported together in {rid}")

    # Relationships
    for a in actors:
        for m in malware:
            rel(a, "uses", m)
        for p in patterns.values():
            rel(a, "uses", p)
        for v in vulns:
            rel(a, "targets", v)
        for s in sectors:
            rel(a, "targets", s)
    if not actors:
        for m in malware:
            if m["type"] == "malware":
                for v in vulns:
                    rel(m, "targets", v)

    content = [*actors, *malware, *vulns, *patterns.values(), *sectors, *indicators, *rels]
    report_refs = [identity_id] + [o["id"] for o in content]
    labels = [re.sub(r"[^a-z0-9-]+", "-", str(x).lower()).strip("-") for x in [*(rec.get("classification") or []), *(rec.get("tags") or [])]]
    report_ext = [{"source_name": producer, "external_id": rid, **({"url": f"{base_url.rstrip('/')}/research/{rid}"} if base_url else {})}]
    report_ext += [ref for s in sources.values() if s.get("included", True) for ref in src_refs([s["id"]])]
    published = _ts(getattr(r, "published_at", None) or rec.get("updated_at") or getattr(r, "updated_at", None))
    report = sdo("report", rid, name=rec.get("title") or r.title or rid, description=rec.get("executive_summary"),
                 report_types=["threat-report"], published=published, object_refs=report_refs,
                 confidence=CONFIDENCE.get((rec.get("confidence") or "").lower()), labels=[x for x in dict.fromkeys(labels) if x],
                 external_references=report_ext)
    identity = {"type": "identity", "spec_version": "2.1", "id": identity_id, "created": "2025-01-01T00:00:00.000Z",
                "modified": "2025-01-01T00:00:00.000Z", "name": producer, "identity_class": "organization"}
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [*_tlp_objects(), identity, report, *content]}


# ------------------------------------------------------------------ validation

_ID = re.compile(r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_REQUIRED = {
    "report": ("name", "published", "object_refs"), "intrusion-set": ("name",), "malware": ("name", "is_family"), "tool": ("name",),
    "vulnerability": ("name",), "attack-pattern": ("name",), "identity": ("name",),
    "indicator": ("pattern", "pattern_type", "valid_from"), "relationship": ("relationship_type", "source_ref", "target_ref"),
    "marking-definition": ("created",),
}


def validate(bundle: dict) -> list[str]:
    """Schema-level checks (ids, required properties, resolvable refs), plus the `stix2` library's parser when installed.
    Returns a list of problems (empty = valid)."""
    errs: list[str] = []
    if bundle.get("type") != "bundle" or not _ID.match(bundle.get("id", "")):
        errs.append("bundle type/id")
    objs = bundle.get("objects") or []
    ids = {o.get("id") for o in objs}
    if len(ids) != len(objs):
        errs.append("duplicate object ids")
    for o in objs:
        oid = o.get("id", "")
        if not _ID.match(oid) or not oid.startswith(o.get("type", "") + "--"):
            errs.append(f"bad id {oid}")
        if o.get("spec_version") != "2.1":
            errs.append(f"{oid}: spec_version")
        errs += [f"{oid}: missing {p}" for p in _REQUIRED.get(o.get("type"), ()) if p not in o]
        refs = [*o.get("object_refs", []), *o.get("object_marking_refs", []),
                *[o[k] for k in ("source_ref", "target_ref", "created_by_ref") if k in o]]
        errs += [f"{oid}: unresolved ref {x}" for x in refs if x not in ids and x != TLP2_CREATOR]
    try:
        import stix2  # type: ignore[import-not-found]
    except ImportError:
        return errs
    try:
        stix2.parse(bundle, allow_custom=False)
    except Exception as e:  # noqa: BLE001 - surface any stix2 validation error as a message
        errs.append(f"stix2: {e}")
    return errs

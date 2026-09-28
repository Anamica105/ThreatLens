"""Agent guardrails: grounding gate (spec §12).

"A statement without a supporting source quote is flagged 'unsupported' in the draft and cannot be published unedited."

`check(record, run_ids)` scans every sourced section of a research record and returns issues:

    {section, index, step?, ref?, field, kind, text, severity, anchor}

kind:
  missing_source    - the item cites no source
  unknown_source    - the item cites a source id that is not in record.sources
  quote_not_found   - a MITRE row's evidence quote does not appear in the stored article text of its sources
                      (only checked when the fetched article text is on disk: data/articles/<run id>/<source id>.txt)
  disputed_conflict - a claim conflict is still marked disputed (a reviewer must pick a status)

severity: "block" stops publishing. An item the hunter has edited (item `_edited` flag, or a section saved wholesale
before item flags existed) or a section a reviewer explicitly approved downgrades to "warn": a person has taken
responsibility for the statement.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from .config import get_settings

# section key -> (UI anchor, text of an item)
SECTIONS: dict[str, tuple[str, callable]] = {
    "claims": ("impact", lambda x: x.get("statement", "")),
    "recommendations": ("recommendations", lambda x: x.get("action", "")),
    "mitre": ("mitre", lambda x: f"{x.get('technique_id', '')} {x.get('sub_technique') or x.get('technique', '')}".strip()),
    "industries": ("industries", lambda x: x.get("industry", "")),
    "threat_actors": ("actors", lambda x: x.get("name", "")),
    "malware_tools": ("tools", lambda x: x.get("name", "")),
    "vulnerabilities": ("vulnerabilities", lambda x: x.get("cve", "")),
}
SECTION_LABELS = {
    "claims": "Claims", "recommendations": "Recommendations", "mitre": "MITRE ATT&CK", "industries": "Industries",
    "threat_actors": "Threat actors", "malware_tools": "Malware and tools", "vulnerabilities": "Vulnerabilities",
    "attack_paths": "Attack paths", "conflicts": "Claim conflicts",
}

# ------------------------------------------------------------------ text matching

_QUOTES = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", " ": " "})


def normalise(s: str) -> str:
    """Lower-case, unify quotes/dashes, keep letters and digits only, collapse whitespace."""
    s = unicodedata.normalize("NFKC", s or "").translate(_QUOTES).lower()
    s = re.sub(r"\[\.\]|\(\.\)|\[dot\]", ".", s)  # defanged indicators match their fanged form
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", s)).strip()


def _grams(words: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(words[i:i + n]) for i in range(max(len(words) - n + 1, 0))}


def quote_in_text(quote: str, text: str, threshold: float = 0.75) -> bool:
    """True when `quote` appears in `text` after normalisation, or when most of its word trigrams do
    (tolerates ellipses, dropped words and small paraphrase)."""
    q, t = normalise(quote), normalise(text)
    if not q:
        return True
    if q in t:
        return True
    qw, tw = q.split(), t.split()
    n = 3 if len(qw) >= 6 else 2 if len(qw) >= 3 else 1
    qg = _grams(qw, n)
    if not qg:
        return False
    tg = _grams(tw, n)
    return len(qg & tg) / len(qg) >= threshold


# ------------------------------------------------------------------ article text

def article_texts(run_ids: list[str], source_ids: set[str]) -> dict[str, str]:
    """Stored article text per source id, from the first run directory that has it. Missing files are skipped."""
    base = get_settings().data_dir / "articles"
    out: dict[str, str] = {}
    for rid in [r for r in run_ids if r]:
        d = base / rid
        if not d.is_dir():
            continue
        for sid in source_ids - set(out):
            p: Path = d / f"{sid}.txt"
            try:
                out[sid] = p.read_text(encoding="utf-8")
            except OSError:
                continue
    return out


# ------------------------------------------------------------------ the gate

def _downgraded(rec: dict, section: str, items: list[dict], item: dict) -> bool:
    if (rec.get("review") or {}).get(section) == "approved":
        return True
    if item.get("_edited"):
        return True
    # Legacy: section saved wholesale before item-level flags existed.
    return section in (rec.get("_edited") or []) and not any("_edited" in x for x in items if isinstance(x, dict))


def _source_issues(base: dict, sids, known: set[str]) -> list[dict]:
    sids = [s for s in (sids or []) if s]
    if not sids:
        return [{**base, "field": "source_ids", "kind": "missing_source"}]
    unknown = [s for s in sids if s not in known]
    if unknown:
        return [{**base, "field": "source_ids", "kind": "unknown_source", "unknown_ids": unknown}]
    return []


def check(rec: dict, run_ids: list[str] | None = None) -> list[dict]:
    rec = rec or {}
    known = {s.get("id") for s in rec.get("sources", []) or [] if s.get("id")}
    issues: list[dict] = []

    def add(found: list[dict], down: bool):
        for i in found:
            i["severity"] = "warn" if down else "block"
            issues.append(i)

    for section, (anchor, text_of) in SECTIONS.items():
        items = [x for x in rec.get(section, []) or [] if isinstance(x, dict)]
        for idx, item in enumerate(items):
            base = {"section": section, "index": idx, "anchor": anchor, "text": text_of(item)}
            if section == "mitre":
                base["ref"] = item.get("technique_id", "")
            add(_source_issues(base, item.get("source_ids"), known), _downgraded(rec, section, items, item))

    paths = [p for p in rec.get("attack_paths", []) or [] if isinstance(p, dict)]
    for pi, p in enumerate(paths):
        steps = [s for s in p.get("steps", []) or [] if isinstance(s, dict)]
        for si, st in enumerate(steps):
            base = {"section": "attack_paths", "index": pi, "step": si, "anchor": "attack-paths",
                    "ref": st.get("ref") or f"AP-{pi + 1}.{si + 1}", "text": st.get("behaviour", "")}
            # Only the step's own flag counts: renaming or reordering a path does not vouch for its steps.
            down = _downgraded(rec, "attack_paths", paths + steps, st)
            add(_source_issues(base, st.get("source_ids"), known), down)

    # Evidence quotes: only where the fetched article text is available.
    mitre = [m for m in rec.get("mitre", []) or [] if isinstance(m, dict)]
    wanted = {s for m in mitre if m.get("evidence_quote") for s in m.get("source_ids", []) or [] if s in known}
    run_ids = list(run_ids or [])
    if (rec.get("run") or {}).get("id"):
        run_ids.insert(0, rec["run"]["id"])
    texts = article_texts(run_ids, wanted) if wanted else {}
    if texts:
        for idx, m in enumerate(mitre):
            q = (m.get("evidence_quote") or "").strip()
            have = [texts[s] for s in m.get("source_ids", []) or [] if s in texts]
            if not q or not have:
                continue  # no quote to check, or none of this row's articles are on disk
            if not any(quote_in_text(q, t) for t in have):
                add([{"section": "mitre", "index": idx, "anchor": "mitre", "ref": m.get("technique_id", ""),
                      "field": "evidence_quote", "kind": "quote_not_found", "text": q}],
                    _downgraded(rec, "mitre", mitre, m))

    for idx, c in enumerate(rec.get("conflicts", []) or []):
        if isinstance(c, dict) and c.get("status") == "disputed":
            issues.append({"section": "conflicts", "index": idx, "anchor": "impact", "field": "status",
                           "kind": "disputed_conflict", "text": c.get("topic", ""), "severity": "block"})
    return issues


def readiness(rec: dict, run_ids: list[str] | None = None) -> dict:
    issues = check(rec, run_ids)
    blocking = sum(1 for i in issues if i["severity"] == "block")
    return {"ready": blocking == 0, "blocking": blocking, "warnings": len(issues) - blocking, "issues": issues}


def blocking_message(r: dict) -> str:
    n = r["blocking"]
    kinds = {}
    for i in r["issues"]:
        if i["severity"] == "block":
            kinds[i["kind"]] = kinds.get(i["kind"], 0) + 1
    parts = []
    if kinds.get("missing_source"):
        parts.append(f"{kinds['missing_source']} unsupported statement(s) cite no source")
    if kinds.get("unknown_source"):
        parts.append(f"{kinds['unknown_source']} item(s) cite a source that is not in the report")
    if kinds.get("quote_not_found"):
        parts.append(f"{kinds['quote_not_found']} evidence quote(s) were not found in the source article")
    if kinds.get("disputed_conflict"):
        parts.append(f"{kinds['disputed_conflict']} disputed claim(s) need a status")
    return f"Cannot publish: {n} blocking issue{'s' if n != 1 else ''}. " + "; ".join(parts) + \
        ". Edit, cite a source, or have a reviewer approve the section."

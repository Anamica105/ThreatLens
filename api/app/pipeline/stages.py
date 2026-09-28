"""The ten pipeline stages (spec section 2). Each returns (artifact, badge).

Every stage has an LLM path (Claude, structured outputs) and an offline path
(regex + heuristics + canned templates) so the product works without an API key.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .. import attack, detection, llm, osint
from ..config import get_settings
from ..db import SessionLocal
from ..ioc import defang, extract as extract_iocs, refang
from ..models import Actor, Ioc, MalwareTool, Research, Workspace
from ..records import (applicability, coverage_gaps, ensure_results, log_activity, next_id, save_record)
from ..sources import VENDORS, discover, fetch, relevance, vendor_for_url
from .runner import STAGES, Ctx, StageWarning
from . import schemas as SC
from .templates import TECHNIQUE_OPPORTUNITIES

ACTOR_PATTERNS = [
    r"\bStorm-\d{4}\b", r"\bAPT ?\d{1,3}\b", r"\bUNC\d{3,5}\b", r"\bTA\d{3,4}\b", r"\bFIN\d{1,2}\b", r"\bCL-[A-Z]{3}-\d{4}\b",
    r"\b[A-Z][a-z]+ (?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Hail|Rain|Flood|Cyclone|Tsunami|Dust)\b",
    r"\b[A-Z][a-z]+ (?:Panda|Bear|Kitten|Chollima|Spider|Jackal|Buffalo|Tiger)\b",
    r"\bLazarus\b", r"\bScattered Spider\b", r"\bVolt Typhoon\b",
]
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
MAX_SOURCE_CHARS = 150_000


def _use_llm(ctx: Ctx) -> bool:
    return ctx.mode == "llm" and llm.available()


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])", re.sub(r"\s+", " ", text)) if 20 < len(s.strip()) < 600]


def _clip_quote(s: str, words: int = 25) -> str:
    w = s.split()
    return " ".join(w[:words]) + ("…" if len(w) > words else "")


# --------------------------------------------------------------------------- 1. Intake

def stage_intake(ctx: Ctx):
    seed = ctx.config.get("seed", "")
    cves = sorted({m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,7}", seed, re.I)})
    urls = list(dict.fromkeys(ctx.config.get("seed_urls", []) + re.findall(r"https?://[^\s<>\"')\]]+", seed)))
    actors = []
    for p in ACTOR_PATTERNS:
        actors += re.findall(p, seed)
    malware = []
    with SessionLocal() as db:
        for a in db.query(Actor).all():
            for n in [a.name] + list(a.aliases or []):
                if n and re.search(rf"\b{re.escape(n)}\b", seed, re.I):
                    actors.append(a.name)
        for m in db.query(MalwareTool).all():
            if len(m.name) > 3 and re.search(rf"\b{re.escape(m.name)}\b", seed, re.I):
                malware.append(m.name)
    first_line = next((ln.strip() for ln in seed.splitlines() if ln.strip()), "Untitled threat")
    first_line = re.split(r"(?<=[.!?])\s", first_line, maxsplit=1)[0].rstrip(".")
    out = {"title_guess": first_line[:120], "cves": cves, "actors": sorted(set(actors)), "malware": sorted(set(malware)),
           "products": [], "keywords": [], "urls": urls}

    if _use_llm(ctx) and seed.strip():
        res, tok = llm.structured(
            SC.IntakeOut,
            "Identify the threat described in this seed (a headline, email or note from a threat hunter). "
            "Return the entities it names and 3-8 distinctive search keywords for finding vendor coverage.",
            context=f"<seed>\n{seed[:20000]}\n</seed>", effort="low", max_tokens=4000)
        ctx.tokens += tok
        out["title_guess"] = res.title_guess or out["title_guess"]
        out["cves"] = sorted(set(out["cves"]) | {c.upper() for c in res.cves if re.match(r"CVE-\d{4}-\d{4,}", c, re.I)})
        out["actors"] = sorted(set(out["actors"]) | set(res.actors))
        out["malware"] = sorted(set(out["malware"]) | set(res.malware))
        out["products"] = res.products
        out["keywords"] = res.keywords
    elif not out["keywords"]:
        # Offline: distinctive tokens only — product names, mixed-case or hyphenated terms, not ordinary sentence words.
        stop = {"the", "fresh", "new", "attackers", "attacker", "threat", "exploitation", "exploited", "active", "actively", "update",
                "critical", "vulnerability", "vulnerabilities", "campaign", "report", "security", "against", "using", "patch", "urgent"}
        words = [w for w in re.findall(r"\b[A-Z][A-Za-z0-9]*[A-Z0-9][A-Za-z0-9]*\b|\b[A-Z][a-z]{4,}\b", first_line) if w.lower() not in stop]
        out["keywords"] = [w for w in dict.fromkeys(words) if w not in out["cves"] + out["actors"]][:4]

    n = len(out["cves"]) + len(out["actors"]) + len(out["malware"]) + len(urls)
    ctx.log(f"Seed entities: {', '.join(out['cves'] + out['actors'] + out['malware']) or 'none'}; {len(urls)} URL(s)")
    return out, f"{n} entities"


# --------------------------------------------------------------------------- 2. Source discovery

def stage_discovery(ctx: Ctx):
    intake = ctx.artifacts.get("intake", {})
    entities = {"cves": intake.get("cves", []), "actors": intake.get("actors", []), "malware": intake.get("malware", []),
                "keywords": intake.get("keywords", []) + intake.get("products", [])}
    cands = discover(entities, intake.get("urls", []), ctx.config.get("vendors"), ctx.config.get("open_web", True),
                     ctx.config.get("depth", "standard"), logf=ctx.log)
    sources = []
    for i, c in enumerate(cands, 1):
        sources.append({**c, "id": f"S{i}"})
    seed = ctx.config.get("seed", "")
    if len(seed) > 150:
        sources.append({"id": f"S{len(sources) + 1}", "url": "", "title": "Seed text (pasted by hunter)", "publisher": "Hunter seed",
                        "published": datetime.now(timezone.utc).date().isoformat(), "reliability": "C", "origin": "seed_text", "score": 0})
    if not sources:
        raise RuntimeError("No sources found. Add a seed URL, or configure BRAVE_SEARCH_API_KEY for open-web search.")
    for s in sources:
        ctx.log(f"{s['id']} · {s['publisher']} · {s.get('title') or s['url']}")
    return {"sources": sources}, f"{len(sources)} sources"


# --------------------------------------------------------------------------- 3. Extraction

def _offline_notes(text: str) -> dict:
    sents = _sentences(text)
    ttps, seen = [], set()
    for s in sents:
        for pat, tid in attack.KEYWORD_HINTS:
            if tid not in seen and re.search(pat, s, re.I):
                seen.add(tid)
                ttps.append({"technique_id": tid, "behaviour": _clip_quote(s, 30), "evidence_quote": _clip_quote(s)})
    actors = []
    for p in ACTOR_PATTERNS:
        for m in dict.fromkeys(re.findall(p, text)):
            actors.append({"name": m, "aliases": [], "origin": "", "motivation": [], "attribution_confidence": "low"})
    ioas = [s for s in sents if re.search(r"(spawn|child process|w3wp|POST /|GET /|-enc|\.aspx)", s, re.I)][:8]
    return {
        "summary": " ".join(sents[:4]),
        "claims": [{"statement": s, "evidence_quote": _clip_quote(s)} for s in sents[:6]],
        "ttps": ttps,
        "cves": sorted({c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)}),
        "actors": actors[:6], "malware": [], "iocs": [], "ioas": ioas, "timeline": [],
        "industries": [i for i in ["Government", "Education", "Healthcare", "Finance", "Energy", "Telecommunications",
                                   "Manufacturing", "Retail", "Technology"] if re.search(rf"\b{i}\b", text, re.I)],
        "regions": [], "vendor_queries": [], "recommendations": [s for s in sents if re.search(r"\b(patch|update|rotate|disable|apply|upgrade)\b", s, re.I)][:5],
    }


def _extract_one(ctx: Ctx, src: dict, seed: str) -> dict:
    if src.get("origin") == "seed_text":
        doc = {"text": seed, "title": src["title"], "published": src.get("published"), "last_modified": None, "content_hash": "", "method": "seed"}
    else:
        doc = fetch(src["url"], logf=ctx.log)
    text = doc["text"] or ""
    if not text:
        ctx.log(f"{src['id']}: no readable text at {src['url']}", "warn")
        return {"id": src["id"], "ok": False, "fetch": {k: v for k, v in doc.items() if k != "text"}}
    if len(text) > MAX_SOURCE_CHARS:
        ctx.log(f"{src['id']}: article is {len(text):,} chars; only the first {MAX_SOURCE_CHARS:,} are analysed", "warn")
        text = text[:MAX_SOURCE_CHARS]
    art_dir = get_settings().data_dir / "articles" / ctx.run_id
    art_dir.mkdir(parents=True, exist_ok=True)
    (art_dir / f"{src['id']}.txt").write_text(text, encoding="utf-8")

    intake = ctx.artifacts.get("intake", {})
    rel = relevance(text, {"cves": intake.get("cves", []), "actors": intake.get("actors", []),
                           "malware": intake.get("malware", []), "keywords": intake.get("keywords", []) + intake.get("products", [])})
    if rel == 0 and src.get("origin") not in ("seed", "seed_text"):
        ctx.log(f"{src['id']}: does not mention the seed's CVEs, actors or keywords; skipped as not relevant", "warn")
        return {"id": src["id"], "ok": False, "irrelevant": True, "fetch": {k: v for k, v in doc.items() if k != "text"}}
    regex_iocs = [{"type": e.type, "value": e.value, "contexts": e.contexts[:3]} for e in extract_iocs(text)]
    if _use_llm(ctx):
        res, tok = llm.structured(
            SC.SourceNotes,
            f"Read source {src['id']} and write structured research notes. Capture every ATT&CK-relevant behaviour with the "
            "most specific technique ID, every indicator exactly as written (keep defanging as-is), CVEs, actors with aliases "
            "and the source's own confidence wording, malware/tools and their role, behavioural IoAs, dated events, targeted "
            "industries/regions, any hunting queries the vendor published (verbatim), and the vendor's recommendations.",
            sources=[{"id": src["id"], "publisher": src.get("publisher"), "url": src.get("url"), "published": doc.get("published") or src.get("published"), "text": text}],
            effort="medium", max_tokens=16000)
        ctx.tokens += tok
        notes = res.model_dump()
    else:
        notes = _offline_notes(text)
    ctx.log(f"{src['id']}: {len(notes['ttps'])} behaviours, {len(regex_iocs) + len(notes['iocs'])} indicators, {len(notes['claims'])} claims")
    return {"id": src["id"], "ok": True, "notes": notes, "regex_iocs": regex_iocs, "relevance": rel,
            "fetch": {k: v for k, v in doc.items() if k != "text"}, "chars": len(text)}


def stage_extraction(ctx: Ctx):
    sources = ctx.artifacts["discovery"]["sources"]
    seed = ctx.config.get("seed", "")
    results: dict[str, dict] = {}
    done = [0]

    def work(src):
        cfg = ctx.refresh_config()
        if src["id"] in cfg.get("excluded_sources", []):
            ctx.log(f"{src['id']} excluded by hunter")
            return {"id": src["id"], "ok": False, "excluded": True}
        ctx.check_cancel()
        try:
            r = _extract_one(ctx, src, seed)
        except (llm.LLMUnavailable, llm.LLMRefused):
            raise
        except Exception as e:  # noqa: BLE001 - one bad source should not fail the run
            ctx.log(f"{src['id']}: extraction failed ({e})", "warn")
            r = {"id": src["id"], "ok": False, "error": str(e)[:200]}
        done[0] += 1
        ctx.progress(f"{done[0]} of {len(sources)} read")
        return r

    with ThreadPoolExecutor(max_workers=4) as ex:
        for r in ex.map(work, sources):
            results[r["id"]] = r
    ok = [r for r in results.values() if r.get("ok")]
    if not ok:
        if any(r.get("irrelevant") for r in results.values()):
            raise RuntimeError("None of the sources mention the seed's CVEs, actors or keywords. Add a seed URL, paste the article "
                               "text into the seed, or configure BRAVE_SEARCH_API_KEY for open-web search.")
        raise RuntimeError("None of the sources could be read. Check the URLs or network access, then retry.")
    badge = f"{len(ok)} of {len(sources)} read"
    if len(ok) < len([s for s in sources if s["id"] not in ctx.config.get("excluded_sources", [])]):
        w = StageWarning(badge, f"{len(sources) - len(ok)} source(s) could not be read; synthesis uses the rest")
        w.data = {"results": results}
        raise w
    return {"results": results}, badge


def _notes(ctx: Ctx) -> list[tuple[dict, dict]]:
    """[(source, notes)] for sources read successfully and not excluded."""
    excluded = set(ctx.refresh_config().get("excluded_sources", []))
    res = ctx.artifacts["extraction"]["results"]
    out = []
    for s in ctx.artifacts["discovery"]["sources"]:
        r = res.get(s["id"], {})
        if r.get("ok") and s["id"] not in excluded:
            out.append((s, r["notes"]))
    return out


def _notes_context(pairs: list[tuple[dict, dict]], keys: list[str] | None = None) -> str:
    blocks = []
    for s, n in pairs:
        d = n if keys is None else {k: n.get(k) for k in keys}
        blocks.append(f'<notes source="{s["id"]}" publisher="{s["publisher"]}" published="{s.get("published") or ""}" '
                      f'reliability="{s.get("reliability", "C")}">\n{json.dumps(d, ensure_ascii=False)}\n</notes>')
    return "\n".join(blocks)


# --------------------------------------------------------------------------- 4. Synthesis

def _source_text(ctx: Ctx, sid: str) -> str:
    p = get_settings().data_dir / "articles" / ctx.run_id / f"{sid}.txt"
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def _offline_synthesis(ctx: Ctx, pairs) -> tuple[dict, dict]:
    """Heuristic synthesis: keep only sentences that mention the seed's entities, so unrelated parts of an article don't leak in."""
    intake = ctx.artifacts["intake"]
    terms = [t for t in intake.get("cves", []) + intake.get("actors", []) + intake.get("malware", []) + intake.get("keywords", [])
             + intake.get("products", []) if len(t) > 2]
    term_re = re.compile("|".join(re.escape(t) for t in terms), re.I) if terms else None
    seed_sents = _sentences(ctx.config.get("seed", ""))
    scored: list[tuple[int, str, str]] = []
    texts: dict[str, str] = {}
    for s, _ in pairs:
        texts[s["id"]] = ctx.config.get("seed", "") if s.get("origin") == "seed_text" else _source_text(ctx, s["id"])
        if s.get("origin") == "seed_text":
            continue
        for sent in _sentences(texts[s["id"]]):
            hits = len(term_re.findall(sent)) if term_re else 0
            if hits:
                scored.append((hits, s["id"], sent))
    scored.sort(key=lambda x: -x[0])
    picked, seen_s = [], set()
    for sent in seed_sents[:3] + [x[2] for x in scored]:
        key = sent.lower()[:80]
        if key not in seen_s:
            seen_s.add(key)
            picked.append(sent)
        if len(" ".join(picked).split()) > 200:
            break
    summary = " ".join(" ".join(picked).split()[:230])
    relevant_sents = seed_sents + [x[2] for x in scored]
    # Entities: those named in the seed, plus ones that co-occur with a seed entity in the same sentence.
    cves = set(intake.get("cves", []))
    for sent in relevant_sents:
        cves |= {c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", sent, re.I)}
    cves = sorted(cves)
    ttps = []
    seen = set()
    for s, n in pairs:
        for t in n["ttps"]:
            if t["technique_id"] not in seen and (not term_re or term_re.search(t["behaviour"]) or s.get("origin") == "seed_text"
                                                  or any(t["behaviour"][:40] in rs for rs in relevant_sents)):
                seen.add(t["technique_id"])
                ttps.append({**t, "source_ids": [s["id"]]})
    tactic_idx = {t["id"]: i for i, t in enumerate(attack.TACTICS)}
    ttps.sort(key=lambda t: min([tactic_idx.get(x, 99) for x in (attack.technique(t["technique_id"]) or {}).get("tactic_ids", [])] or [99]))
    exploited = any(t["technique_id"] == "T1190" for t in ttps)
    sev = "critical" if cves and exploited else "high" if cves or exploited else "medium"
    classification = (["vulnerability_exploitation"] if cves else []) + (["campaign"] if len(pairs) > 1 else ["ttp_trend"])
    actors = {a: {"name": a, "aliases": [], "origin": "", "motivation": [], "attribution_confidence": "low", "source_ids": []}
              for a in intake.get("actors", [])}
    for s, n in pairs:
        for a in n["actors"]:
            if a["name"] in actors or any(a["name"] in rs for rs in relevant_sents):
                actors.setdefault(a["name"], {**a, "source_ids": []})["source_ids"].append(s["id"])
    rec_re = re.compile(r"\b(patch|update|upgrade|rotate|disable|apply|restrict|block|enable|hunt|monitor|isolate|reset|install)\b", re.I)
    advice_re = re.compile(r"(\bshould\b|\brecommend|\bmust\b|\badvise|\bmitigat|to protect|immediately|^\s*(apply|rotate|patch|enable|disable|restrict|block|install|upgrade|isolate|reset|monitor|hunt)\b)", re.I)
    recs = []
    for s, _ in pairs:
        for sent in _sentences(texts.get(s["id"], "")):
            if len(sent) > 400 or not rec_re.search(sent) or not advice_re.search(sent):
                continue
            if len(recs) < 8 and not any(sent[:60] == r["action"][:60] for r in recs):
                recs.append({"horizon": "immediate" if re.search(r"\b(patch|rotate|isolate|disable|block)\b", sent, re.I) else "short_term",
                             "action": sent, "owner_role": "IT operations", "source_ids": [s["id"]]})
    narrative = {
        "title": intake.get("title_guess", "Untitled threat")[:120],
        "executive_summary": summary or "No summary could be generated offline. Review the sources.",
        "classification": classification, "confidence": "low",
        "impact": {"severity": sev, "business_impact": "Assess against the affected technology in each workspace.",
                   "cia": {"confidentiality": True, "integrity": exploited, "availability": any(t["technique_id"] in ("T1486", "T1490") for t in ttps)},
                   "blast_radius": "Systems running the affected technology and anything reachable from them."},
        "patching_insufficient": False,
        "recommendations": recs,
        "claims": [{"statement": x[2], "source_ids": [x[1]], "status": "confirmed"} for x in scored[:8]],
        "conflicts": [],
        "industries": [{"industry": i, "evidence": "observed", "source_ids": [s["id"]]} for s, n in pairs for i in n["industries"]],
        "geography": sorted({r for _, n in pairs for r in n["regions"]}),
        "timeline": [], "study": {"background": summary, "how_it_works": "", "kill_chain_narrative": "", "remember": []},
    }
    # de-duplicate industries
    ind = {}
    for i in narrative["industries"]:
        ind.setdefault(i["industry"], i)
    narrative["industries"] = list(ind.values())
    entities = {
        "vulnerabilities": [{"cve": c, "cvss": 0.0, "affected_products": intake.get("products", []), "fixed_versions": [], "patch_kb": [],
                             "source_ids": [s["id"] for s, n in pairs if c in n["cves"]]} for c in cves],
        "threat_actors": list(actors.values()),
        "malware_tools": [],
        "attack_paths": [{"name": "Observed behaviour chain", "steps": [
            {"behaviour": t["behaviour"], "technique_id": t["technique_id"], "source_ids": t["source_ids"]} for t in ttps[:10]]}] if ttps else [],
        "ioas": [{"description": i, "kind": "other", "source_ids": [s["id"]]} for s, n in pairs for i in n["ioas"][:3]
                 if s.get("origin") == "seed_text" or (term_re and term_re.search(i))],
    }
    return narrative, entities


def stage_synthesis(ctx: Ctx):
    pairs = _notes(ctx)
    if not pairs:
        raise RuntimeError("All sources are excluded or unreadable.")
    if not _use_llm(ctx):
        narrative, entities = _offline_synthesis(ctx, pairs)
        ctx.log("Offline mode: heuristic synthesis (set ANTHROPIC_API_KEY for full synthesis)", "warn")
        return {"narrative": narrative, "entities": entities}, "draft ready (offline)"

    context = _notes_context(pairs)
    workspaces = []
    with SessionLocal() as db:
        for wid in ctx.config.get("workspace_ids", []):
            ws = db.get(Workspace, wid)
            if ws:
                workspaces.append(f"- industry: {ws.industry}; technology in scope: {', '.join(ws.products or []) or 'unknown'}")
    narrative, tok1 = llm.structured(
        SC.NarrativeOut,
        "Synthesise these per-source notes into one research record. Reconcile the sources: when they disagree (for example "
        "a vendor later corrected which CVE was exploited, or raised attribution confidence), record a conflict with each "
        "dated statement and mark superseded/disputed/confirmed. Every claim and recommendation must cite source ids. "
        "Group recommendations as immediate (0-48 h), short_term (<= 30 days) and strategic, and set patching_insufficient "
        "when sources say patching alone does not remediate (e.g. key rotation needed). The executive summary explains what "
        "it is, how it works, who is behind it and why it matters, in plain language with no indicators. The study section "
        "is a long-form digest a hunter reads instead of the articles.",
        context=context + ("\n<client_context>\n" + "\n".join(workspaces) + "\n</client_context>" if workspaces else ""),
        effort="high", max_tokens=16000)
    ctx.log(f"Narrative drafted: {len(narrative.claims)} claims, {len(narrative.conflicts)} conflict(s)")
    entities, tok2 = llm.structured(
        SC.EntitiesOut,
        "From these notes, produce the de-duplicated entities: vulnerabilities (with CVSS, affected products, fixed versions, "
        "patch KBs), threat actors (merge aliases such as vendor cluster names that sources say overlap, keep the stated "
        "confidence), malware and tools with their role in the chain, attack paths (ordered, concrete behaviours, one ATT&CK "
        "technique per step; separate distinct paths such as initial exploitation vs. post-exploitation to ransomware), and "
        "behavioural IoAs (process chains, HTTP request patterns, file writes) separate from IoCs.",
        context=context, effort="high", max_tokens=16000)
    ctx.tokens += tok1 + tok2
    ctx.log(f"Entities: {len(entities.vulnerabilities)} CVEs, {len(entities.threat_actors)} actors, "
            f"{len(entities.malware_tools)} malware/tools, {len(entities.attack_paths)} attack paths")
    return {"narrative": narrative.model_dump(), "entities": entities.model_dump()}, \
        f"{len(entities.attack_paths)} attack paths"


# --------------------------------------------------------------------------- 5. ATT&CK mapping

def _finish_mitre(ctx: Ctx, rows: list[dict]) -> tuple[list[dict], list[str]]:
    out, dropped, seen = [], [], set()
    for m in rows:
        tid = m["technique_id"].strip().upper()
        t = attack.technique(tid)
        if not t:
            dropped.append(tid)
            continue
        tactic_id = m.get("tactic_id") if m.get("tactic_id") in t["tactic_ids"] else (t["tactic_ids"] or [""])[0]
        key = (tid, tactic_id)
        if key in seen:
            continue
        seen.add(key)
        tactic = attack.TACTIC_BY_ID.get(tactic_id, {})
        name = t["name"]
        technique, sub = (name.split(": ", 1) + [""])[:2] if "." in tid else (name, "")
        out.append({"tactic_id": tactic_id, "tactic": tactic.get("name", ""), "technique_id": tid, "technique": technique,
                    "sub_technique": sub, "procedure": m.get("procedure", ""), "evidence_quote": m.get("evidence_quote", ""),
                    "source_ids": m.get("source_ids", []), "confidence": m.get("confidence", "moderate")})
    order = {t["id"]: i for i, t in enumerate(attack.TACTICS)}
    out.sort(key=lambda x: (order.get(x["tactic_id"], 99), x["technique_id"]))
    return out, dropped


def stage_attack(ctx: Ctx):
    pairs = _notes(ctx)
    syn = ctx.artifacts["synthesis"]
    if _use_llm(ctx):
        res, tok = llm.structured(
            SC.MitreList,
            "Map every attacker behaviour to MITRE ATT&CK Enterprise. Use the most specific sub-technique supported by the "
            "evidence, give the tactic the procedure serves, a one-sentence procedure in this threat's terms, a verbatim "
            "evidence quote (max 25 words) and the source ids. Confidence reflects how directly the source describes it. "
            "Do not add techniques the sources do not support.",
            context=_notes_context(pairs, ["ttps", "ioas", "claims"]) + "\n<attack_paths>\n" +
            json.dumps(syn["entities"]["attack_paths"], ensure_ascii=False) + "\n</attack_paths>",
            effort="medium", max_tokens=16000)
        ctx.tokens += tok
        rows = [m.model_dump() for m in res.mitre]
    else:
        rows = []
        for s, n in pairs:
            for t in n["ttps"]:
                rows.append({"technique_id": t["technique_id"], "tactic_id": "", "procedure": t["behaviour"],
                             "evidence_quote": t["evidence_quote"], "source_ids": [s["id"]], "confidence": "low"})
        merged: dict[str, dict] = {}
        for r in rows:
            m = merged.setdefault(r["technique_id"], {**r, "source_ids": []})
            m["source_ids"] = sorted(set(m["source_ids"]) | set(r["source_ids"]))
        rows = list(merged.values())
    mitre, dropped = _finish_mitre(ctx, rows)
    if dropped:
        ctx.log(f"Dropped technique IDs not in the current ATT&CK catalog: {', '.join(sorted(set(dropped)))}", "warn")
    techs = len({m["technique_id"] for m in mitre})
    ctx.log(f"{techs} techniques across {len({m['tactic_id'] for m in mitre})} tactics")
    return {"mitre": mitre}, f"{techs} TTPs"


# --------------------------------------------------------------------------- 6. Detection reasoning

def stage_detection(ctx: Ctx):
    syn = ctx.artifacts["synthesis"]
    mitre = ctx.artifacts["attack"]["mitre"]
    paths = syn["entities"]["attack_paths"]
    opps: list[dict] = []
    if _use_llm(ctx):
        numbered = [{"ref": f"AP-{i}.{j}", "path": p["name"], "behaviour": s["behaviour"], "technique_id": s["technique_id"]}
                    for i, p in enumerate(paths, 1) for j, s in enumerate(p["steps"], 1)]
        res, tok = llm.structured(
            SC.OpportunityList,
            "For each attack-path step below, write the behavioural detection opportunities a hunter can act on. Prefer "
            "behaviours that survive indicator rotation (process lineage, HTTP request shape, file writes in unusual paths). "
            "For each, express the logic as a neutral detection spec using only these fields: parent_image, grandparent_image, "
            "image, command_line (process_creation); target_filename (file_event); http_method, url_path, referer, user_agent, "
            "src_ip (web); dst_ip (network); domain (dns); sha256 (file_hash). Image fields hold paths ending in the binary, e.g. "
            "'\\\\w3wp.exe'. Include false-positive notes. Skip steps with no observable signal.",
            context="<steps>\n" + json.dumps(numbered, ensure_ascii=False) + "\n</steps>\n<ioas>\n" +
            json.dumps(syn["entities"]["ioas"], ensure_ascii=False) + "\n</ioas>",
            effort="high", max_tokens=16000)
        ctx.tokens += tok
        opps = [o.model_dump() for o in res.opportunities]
    else:
        step_ref = {}
        for i, p in enumerate(paths, 1):
            for j, s in enumerate(p["steps"], 1):
                step_ref.setdefault(s["technique_id"], f"AP-{i}.{j}")
        for tid in dict.fromkeys(m["technique_id"] for m in mitre):
            for t in TECHNIQUE_OPPORTUNITIES.get(tid, []):
                if t["type"] == "ioa":
                    opps.append({**t, "behaviour_ref": step_ref.get(tid, ""), "techniques": [tid]})
    for i, o in enumerate(opps, 1):
        o["id"] = f"DO-{i}"
        o["data_sources"] = [o["spec"]["category"]]
    ctx.log(f"{len(opps)} detection opportunities")
    return {"opportunities": opps}, f"{len(opps)} opportunities"


# --------------------------------------------------------------------------- 7. Query generation

def _vuln_queries(cves: list[str], platforms: list[str], days: int) -> list[dict]:
    out = []
    cl = ", ".join(f'"{c}"' for c in cves)
    if "kql_defender" in platforms or "kql_sentinel" in platforms:
        body = (f"DeviceTvmSoftwareVulnerabilities\n| where CveId in ({cl})\n"
                "| summarize Devices = dcount(DeviceId), DeviceNames = make_set(DeviceName, 50) by CveId, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel")
        for p in [x for x in ("kql_defender", "kql_sentinel") if x in platforms]:
            out.append({"platform": p, "body": body, "log_sources": ["DeviceTvmSoftwareVulnerabilities"]})
    if "spl" in platforms:
        spl_list = " OR ".join(f'cve="{c}"' for c in cves)
        out.append({"platform": "spl", "body": f"index=vuln_scans ({spl_list})\n| stats latest(_time) as last_scan values(dest) as hosts by cve, severity\n| convert ctime(last_scan)",
                    "log_sources": ["Vulnerability scanner data"]})
    if "cql" in platforms:
        out.append({"platform": "cql", "body": f"#repo=spotlight\n| in(field=\"CveId\", values=[{cl}])\n| groupBy([CveId, ComputerName])",
                    "log_sources": ["Falcon Spotlight"]})
    return out


def stage_queries(ctx: Ctx):
    cfg = ctx.refresh_config()
    platforms = [p for p in cfg.get("platforms", ["spl", "kql_defender"]) if p in detection.PLATFORM_IDS]
    days = int(cfg.get("lookback_days", 30))
    ext = ctx.artifacts["extraction"]["results"]
    ioc_values: dict[str, set] = {"ipv4": set(), "domain": set(), "sha256": set()}
    vendor_queries = []
    for r in ext.values():
        if not r.get("ok"):
            continue
        for i in r.get("regex_iocs", []) + [{"type": x["type"], "value": x["value"]} for x in r["notes"].get("iocs", [])]:
            if i["type"] in ioc_values:
                ioc_values[i["type"]].add(refang(i["value"]).lower())
        for vq in r["notes"].get("vendor_queries", []):
            vendor_queries.append({**vq, "source_id": r["id"]})

    def llm_fill(missing: list[dict]) -> list[dict]:
        fields = {p: {cat: detection.F.get(cat, {}).get(p) for cat in detection.F} for p in {m["platform"] for m in missing}}
        res, tok = llm.structured(
            SC.QueryList,
            "Write a hunt query for each (opportunity, platform) pair below, from its Sigma rule. Use the platform's native "
            f"syntax and the field dictionary, with a {days}-day look-back. If the platform has no telemetry for this data "
            "source, still write the closest equivalent and say so in a comment line. Return only valid query text.",
            context="<pairs>\n" + json.dumps([{"opportunity_id": m["opportunity"]["id"], "platform": m["platform"], "sigma": m["sigma"]}
                                              for m in missing], ensure_ascii=False) + "\n</pairs>\n<field_dictionary>\n" +
            json.dumps(fields) + "\n</field_dictionary>", effort="medium", max_tokens=16000)
        ctx.tokens += tok
        return [q.model_dump() for q in res.queries]

    with SessionLocal() as db:
        queries = generate_queries(
            db, ctx.artifacts["detection"]["opportunities"], platforms, days,
            {k: sorted(v) for k, v in ioc_values.items()},
            [v["cve"] for v in ctx.artifacts["synthesis"]["entities"]["vulnerabilities"]],
            [m["technique_id"] for m in ctx.artifacts["attack"]["mitre"]], vendor_queries,
            llm_fill if _use_llm(ctx) else None, ctx.log)
        db.commit()
    lint_fail = sum(1 for q in queries if q["lint"])
    ctx.log(f"{len(queries)} queries ({sum(1 for q in queries if q['origin'] == 'reference')} vendor reference); {lint_fail} failed lint")
    return {"queries": queries}, f"{len(queries)} queries"


def generate_queries(db, opps: list[dict], platforms: list[str], days: int, ioc_values: dict[str, list[str]], cves: list[str],
                     techniques: list[str], vendor_queries: list[dict], llm_fill=None, logf=lambda m, level="info": None) -> list[dict]:
    """Sigma first, then per-platform translation, plus IoC, vulnerability, TTP and vendor reference queries."""
    queries: list[dict] = []
    missing: list[dict] = []
    if True:
        def qid() -> str:
            return next_id(db, "query", "Q")

        def add(type_, title, platform, body, opp=None, techniques=(), fp="", data_sources=(), origin="generated", log_sources=None, sigma_ref=None):
            issues = detection.lint(platform, body) if origin == "generated" else []
            queries.append({
                "id": qid(), "type": type_, "title": title, "platform": platform, "body": body,
                "opportunity_id": opp, "techniques": list(techniques), "fp_notes": fp, "data_sources": list(data_sources),
                "log_sources": log_sources if log_sources is not None else [detection.LOG_SOURCES.get(c, {}).get(platform, c) for c in data_sources],
                "status": "reference" if origin == "reference" else ("syntax_checked" if not issues else "generated"),
                "lint": issues, "origin": origin, "sigma_ref": sigma_ref,
            })

        # IoA / TTP queries from detection opportunities (Sigma first, then per platform)
        for o in opps:
            sigma = detection.to_sigma(o["title"], o["spec"], o["id"], o.get("techniques", []), o.get("fp_notes", ""))
            add(o["type"], o["title"], "sigma", sigma, o["id"], o.get("techniques", []), o.get("fp_notes", ""), o["data_sources"])
            sig_id = queries[-1]["id"]
            for p in platforms:
                if p == "sigma":
                    continue
                body = detection.translate(o["spec"], p, days, o["title"])
                if body is None:
                    missing.append({"opportunity": o, "platform": p, "sigma": sigma, "sigma_ref": sig_id})
                    continue
                add(o["type"], o["title"], p, body, o["id"], o.get("techniques", []), o.get("fp_notes", ""), o["data_sources"], sigma_ref=sig_id)

        if missing and llm_fill:
            by_pair = {(m["opportunity"]["id"], m["platform"]): m for m in missing}
            for q in llm_fill(missing):
                m = by_pair.get((q["opportunity_id"], q["platform"]))
                if m:
                    o = m["opportunity"]
                    add(o["type"], o["title"], q["platform"], q["query"], o["id"], o.get("techniques", []), o.get("fp_notes", ""),
                        o["data_sources"], sigma_ref=m["sigma_ref"])
        elif missing:
            gaps = sorted({f"{detection.PLATFORM_BY_ID[m['platform']]['short']} ({detection.CATEGORIES[m['opportunity']['spec']['category']]})" for m in missing})
            logf(f"No native telemetry for: {', '.join(gaps)}", "warn")

        # IoC retro-hunt queries
        cat_for = {"ipv4": "network", "domain": "dns", "sha256": "file_hash"}
        for t, vs in ioc_values.items():
            vs = sorted(vs)[:200]
            if not vs:
                continue
            for p in platforms:
                if p == "sigma":
                    continue
                body = detection.ioc_query(p, cat_for[t], vs, days)
                if body:
                    add("ioc", f"Retro-hunt: {len(vs)} {t.upper() if t != 'domain' else 'domain'} indicator(s)", p, body,
                        data_sources=[cat_for[t]])

        # Vulnerability exposure queries
        if cves:
            for v in _vuln_queries(cves, platforms, days):
                add("vuln", f"Exposure to {', '.join(cves[:4])}{' +' + str(len(cves) - 4) if len(cves) > 4 else ''}", v["platform"], v["body"],
                    data_sources=["vuln_mgmt"], log_sources=v["log_sources"])

        # Wider TTP hunts (not threat-specific)
        used = {o["title"] for o in opps}
        for tid in dict.fromkeys(techniques):
            for t in TECHNIQUE_OPPORTUNITIES.get(tid, []):
                if t["type"] != "ttp" or t["title"] in used:
                    continue
                used.add(t["title"])
                for p in platforms:
                    if p == "sigma":
                        continue
                    body = detection.translate(t["spec"], p, days, t["title"])
                    if body:
                        add("ttp", t["title"], p, body, None, [tid], t["fp_notes"], [t["spec"]["category"]])

        # Vendor-supplied reference queries, stored next to generated ones
        for vq in vendor_queries:
            plat = vq["platform"] if vq["platform"] in detection.PLATFORM_IDS else "kql_defender" if "kql" in vq["platform"].lower() else vq["platform"]
            add("ioa", f"{vq['title']} (vendor, {vq.get('source_id', '')})".replace(", )", ")"), plat, vq["query"], origin="reference", log_sources=[])
    return queries


# --------------------------------------------------------------------------- 8. IoC extraction + enrichment

ROLE_MALICIOUS = re.compile(r"(c2|command|payload|malicious|exploit|attacker|dropp|web ?shell|ransom|backdoor|stag|download)", re.I)


def stage_iocs(ctx: Ctx):
    sources = {s["id"]: s for s in ctx.artifacts["discovery"]["sources"]}
    ext = ctx.artifacts["extraction"]["results"]
    merged: dict[tuple[str, str], dict] = {}
    for sid, r in ext.items():
        if not r.get("ok"):
            continue
        for i in r["notes"].get("iocs", []):
            v = refang(i["value"])
            k = (i["type"], v.lower())
            m = merged.setdefault(k, {"type": i["type"], "value": v, "roles": set(), "source_ids": set(), "contexts": []})
            m["source_ids"].add(sid)
            if i.get("role"):
                m["roles"].add(i["role"])
        for i in r.get("regex_iocs", []):
            if i["type"] == "cve":
                continue
            k = (i["type"], i["value"].lower())
            m = merged.setdefault(k, {"type": i["type"], "value": i["value"], "roles": set(), "source_ids": set(), "contexts": []})
            m["source_ids"].add(sid)
            for c in i.get("contexts", []):
                if c not in m["contexts"] and len(m["contexts"]) < 3:
                    m["contexts"].append(c)
    ctx.log(f"{len(merged)} unique indicators after refang + dedupe")

    with SessionLocal() as db:
        keys = osint.get_keys(db)
        enabled = [p["name"] for p in osint.PROVIDERS if keys.get(p["id"])]
        if not enabled:
            ctx.log("No OSINT API keys configured; verdicts use vendor context only (Settings > OSINT API keys)", "warn")
        out = []
        enrich_budget = 150
        done = 0
        for m in sorted(merged.values(), key=lambda x: -len(x["source_ids"])):
            ctx.check_cancel()
            cached = db.query(Ioc).filter_by(type=m["type"], value=m["value"]).first()
            rep = {}
            if cached and cached.enriched_at and (datetime.now(timezone.utc) - cached.enriched_at.replace(tzinfo=timezone.utc)) < osint.CACHE_TTL:
                rep = cached.reputation or {}
            elif enabled and enrich_budget > 0 and m["type"] in ("ipv4", "domain", "url", "sha256", "sha1", "md5"):
                rep = osint.enrich(m["type"], m["value"], keys)
                enrich_budget -= 1
                if cached is None:
                    cached = Ioc(type=m["type"], value=m["value"], first_seen=datetime.now(timezone.utc))
                    db.add(cached)
                cached.reputation = rep
                cached.enriched_at = datetime.now(timezone.utc)
                db.commit()
            done += 1
            if done % 5 == 0:
                ctx.progress(f"{done} of {len(merged)} enriched")
            vendor_sids = [s for s in m["source_ids"] if sources.get(s, {}).get("origin") != "seed_text"]
            best_rel = min((sources.get(s, {}).get("reliability", "C") for s in vendor_sids), default="C")
            # "Named as C2/payload by a vendor": the role, or the sentence the indicator came from, says what it is.
            named = any(ROLE_MALICIOUS.search(r) for r in m["roles"]) or any(ROLE_MALICIOUS.search(c) for c in m["contexts"])
            listed = bool(vendor_sids)  # appears in a vendor's indicator list without a stated role
            if named and vendor_sids:
                v = osint.verdict(m["type"], rep, True, best_rel, cached.first_seen if cached else None)
            else:
                v = osint.verdict(m["type"], rep, listed and m["type"] not in ("file_name", "file_path"), "C", cached.first_seen if cached else None)
            role = "; ".join(sorted(m["roles"]))
            out.append({
                "type": m["type"], "value": defang(m["value"], m["type"]), "role": role,
                "context": m["contexts"][0] if m["contexts"] else role,
                "contexts": m["contexts"], "source_ids": sorted(m["source_ids"]), "reputation": rep,
                "reputation_summary": osint.reputation_summary(rep), "verdict": v,
            })
    counts = {}
    for i in out:
        counts[i["verdict"]] = counts.get(i["verdict"], 0) + 1
    ctx.log("Verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    return {"iocs": out, "providers": enabled}, f"{len(out)} IoCs"


# --------------------------------------------------------------------------- 9. Report build

def stage_report(ctx: Ctx):
    arts = ctx.artifacts
    syn = arts["synthesis"]
    nar, ent = syn["narrative"], syn["entities"]
    ext = arts["extraction"]["results"]
    with SessionLocal() as db:
        r = db.get(Research, ctx.research_id)
        prev = r.record or {}
        edited = set(prev.get("_edited", []))
        from ..models import Run  # local import to avoid cycle at module import
        run = db.get(Run, ctx.run_id)
        stage_status = run.stage_status or {}

        sources = []
        for s in arts["discovery"]["sources"]:
            e = ext.get(s["id"], {})
            f = e.get("fetch", {})
            notes = e.get("notes", {}) if e.get("ok") else {}
            sources.append({
                "id": s["id"], "url": s["url"], "title": f.get("title") or s.get("title") or s["url"], "publisher": s["publisher"],
                "published": f.get("published") or s.get("published"), "last_modified": f.get("last_modified"),
                "last_fetched": datetime.now(timezone.utc).date().isoformat(), "reliability": s.get("reliability", "C"),
                "credibility": 2 if s.get("reliability") in ("A", "B") else 3, "origin": s.get("origin"),
                "content_hash": f.get("content_hash"), "fetch_method": f.get("method"),
                "included": e.get("ok", False) and s["id"] not in ctx.config.get("excluded_sources", []),
                "status": "read" if e.get("ok") else ("excluded" if e.get("excluded") else "unreadable"),
                "summary": notes.get("summary", ""), "counts": {
                    "claims": len(notes.get("claims", [])), "techniques": len(notes.get("ttps", [])),
                    "iocs": len(notes.get("iocs", [])) + len(e.get("regex_iocs", [])), "queries": len(notes.get("vendor_queries", []))},
            })

        attack_paths = []
        for i, p in enumerate(ent["attack_paths"], 1):
            attack_paths.append({"id": f"AP-{i}", "name": p["name"],
                                 "steps": [{**s, "ref": f"AP-{i}.{j}"} for j, s in enumerate(p["steps"], 1)]})
        opps = arts["detection"]["opportunities"]
        queries = arts["queries"]["queries"]
        for o in opps:
            o["queries"] = [q["id"] for q in queries if q.get("opportunity_id") == o["id"]]

        hunts = {
            "queries": queries,
            "ioc_queries": [q["id"] for q in queries if q["type"] == "ioc"],
            "ioa_queries": [q["id"] for q in queries if q["type"] == "ioa"],
            "vulnerability_queries": [q["id"] for q in queries if q["type"] == "vuln"],
            "ttp_queries": [q["id"] for q in queries if q["type"] == "ttp"],
            "platforms": ctx.config.get("platforms", []), "lookback_days": ctx.config.get("lookback_days", 30),
        }
        log_sources_required = []
        for q in queries:
            for cat in q.get("data_sources", []):
                row = {"data_source": cat, "label": detection.CATEGORIES.get(cat, cat), **detection.LOG_SOURCES.get(cat, {})}
                if row not in log_sources_required:
                    log_sources_required.append(row)

        workflow = []
        for sid, label in STAGES:
            st = stage_status.get(sid, {})
            if sid in ("report", "export"):
                continue
            workflow.append({"step": label, "actor": "agent", "started_at": st.get("started_at"), "finished_at": st.get("finished_at"),
                             "notes": st.get("badge") or ""})
        workflow.append({"step": "Hunter review", "actor": "hunter", "started_at": None, "finished_at": None, "notes": "Pending"})

        providers = arts.get("iocs", {}).get("providers", [])
        tools_used = [{"name": "ThreatLens pipeline agents", "category": "platform", "detail": f"{'Claude ' + get_settings().llm_model if _use_llm(ctx) else 'Offline heuristics'}"}]
        tools_used += [{"name": p, "category": "osint", "detail": "IoC reputation"} for p in providers]
        tools_used += [{"name": "MITRE ATT&CK", "category": "reference", "detail": "Technique validation"}]

        record = {
            "title": nar["title"], "status": r.status, "tlp": ctx.config.get("tlp", r.tlp), "classification": nar["classification"],
            "severity": nar["impact"]["severity"], "confidence": nar["confidence"],
            "executive_summary": nar["executive_summary"], "impact": nar["impact"],
            "patching_insufficient": nar.get("patching_insufficient", False),
            "recommendations": nar["recommendations"], "results": [], "mitre": arts["attack"]["mitre"],
            "tools_used": tools_used, "workflow": workflow, "hunts": hunts, "industries": nar["industries"],
            "vulnerabilities": [{**v, "kev_added": None, "epss": None} for v in ent["vulnerabilities"]],
            "threat_actors": ent["threat_actors"], "malware_tools": ent["malware_tools"], "attack_paths": attack_paths,
            "ioas": [{**x, "id": f"IOA-{i}"} for i, x in enumerate(ent["ioas"], 1)],
            "iocs": arts.get("iocs", {}).get("iocs", []),
            "detection_opportunities": opps, "log_sources_required": log_sources_required,
            "timeline": nar["timeline"], "sources": sources, "claims": nar["claims"], "conflicts": nar["conflicts"],
            "geography": nar["geography"], "study": nar["study"], "tags": [], "related_research_ids": prev.get("related_research_ids", []),
            "affected_technologies": sorted({p for v in ent["vulnerabilities"] for p in v.get("affected_products", [])}),
            "run": {"id": ctx.run_id, "mode": ctx.mode, "tokens": run.cost_tokens},
            "review": {k: "generated" for k in ("executive_summary", "impact", "recommendations", "mitre", "hunts", "iocs", "study", "attack_paths")},
            "_edited": sorted(edited),
        }
        # Keep hunter edits made to an earlier version of this record.
        for k in edited:
            if k in prev:
                record[k] = prev[k]
                record["review"][k] = "edited"

        applic, gaps = [], []
        for wid in ctx.config.get("workspace_ids", []):
            ws = db.get(Workspace, wid)
            if ws:
                applic.append(applicability(record, ws))
                gaps += coverage_gaps(record, ws)
        record["applicability"] = applic
        record["coverage_gaps"] = gaps

        # Related research: shared CVEs or actors.
        keys = {v["cve"] for v in record["vulnerabilities"]} | {a["name"].lower() for a in record["threat_actors"]}
        related = []
        for other in db.query(Research).filter(Research.id != r.id).all():
            orec = other.record or {}
            okeys = {v.get("cve") for v in orec.get("vulnerabilities", [])} | {a.get("name", "").lower() for a in orec.get("threat_actors", [])}
            if keys & okeys:
                related.append(other.id)
        record["related_research_ids"] = sorted(set(record["related_research_ids"]) | set(related))

        first = not prev
        r.workspace_ids = ctx.config.get("workspace_ids", r.workspace_ids)
        save_record(db, r, record, r.created_by, "Run completed" if first else "Pipeline re-run", bump=not first)
        ensure_results(db, r)
        # Mirror results into the record for exports.
        from ..models import Result
        r.record = {**r.record, "results": [
            {"workspace_id": x.workspace_id, "status": x.status, "summary": x.summary, "hunt_window": x.hunt_window,
             "queries_run": x.queries_run, "analyst": x.analyst_id} for x in db.query(Result).filter_by(research_id=r.id).all()]}
        started = run.started_at.replace(tzinfo=timezone.utc) if run.started_at and run.started_at.tzinfo is None else run.started_at
        dur = (datetime.now(timezone.utc) - started).total_seconds() if started else 0
        read = sum(1 for s in sources if s["status"] == "read")
        log_activity(db, r.id, "run_completed", f"Run completed · {read} sources · {int(dur // 60)} min {int(dur % 60)} s",
                     run_id=ctx.run_id)
        db.commit()
    return {"record_version": r.version}, f"v{r.version}"


# --------------------------------------------------------------------------- 10. Export readiness

def stage_export(ctx: Ctx):
    with SessionLocal() as db:
        r = db.get(Research, ctx.research_id)
        rec = r.record or {}
    issues = []
    unsupported = [c for c in rec.get("claims", []) if not c.get("source_ids")]
    if unsupported:
        issues.append(f"{len(unsupported)} unsupported claim(s) must be edited before publishing")
    disputed = [c for c in rec.get("conflicts", []) if c.get("status") == "disputed"]
    if disputed:
        issues.append(f"{len(disputed)} disputed claim(s) need a reviewer decision")
    lint = [q for q in rec.get("hunts", {}).get("queries", []) if q.get("lint")]
    if lint:
        issues.append(f"{len(lint)} quer{'y' if len(lint) == 1 else 'ies'} failed syntax lint")
    if rec.get("tlp") == "RED":
        issues.append("TLP:RED — email export disabled")
    for i in issues:
        ctx.log(i, "warn")
    if issues:
        w = StageWarning(f"{len(issues)} to review", "; ".join(issues))
        w.data = {"issues": issues}
        raise w
    ctx.log("Draft ready for review and export")
    return {"issues": []}, "ready"

"""pySigma translation (spec 8, generation step 3: "pySigma backends where they exist").

`translate_sigma(sigma_yaml, platform)` converts a Sigma rule with the pySigma backend + processing pipeline for that
platform and returns the backend's raw query (or None when the platform has no backend, the rule's log source is not
covered by the pipeline's field mappings, or the backend errors). `detection.render_query` wraps it with ThreatLens'
index/table, look-back window and projection and falls back to the built-in translator.

Backends (see requirements.txt for pins):
    spl           pySigma-backend-splunk   SplunkBackend  + splunk_windows pipeline (Sysmon field names as-is)
    kql_defender  pySigma-backend-kusto    KustoBackend   + microsoft_xdr_pipeline (Device* tables)
    kql_sentinel  pySigma-backend-kusto    KustoBackend   + sentinel_asim pipeline (ASIM im* parsers). The
                  azure_monitor pipeline was rejected: it maps Sysmon categories onto SecurityEvent columns that do not
                  exist there and mangles `contains` values ending in a backslash.
    esql          pySigma-backend-elasticsearch  ESQLBackend + ecs_windows pipeline (ECS / Elastic Defend fields)
QRadar AQL: pySigma-backend-QRadar-AQL pins pysigma<0.12 and regex<2024 (breaks dateparser/trafilatura), so AQL stays
on the built-in translator, as do CQL, S1QL, XQL and YARA-L (no maintained pySigma backends; LLM or built-in).
"""

from __future__ import annotations

import logging
import re

log = logging.getLogger(__name__)

# Sigma logsource categories whose fields each pipeline actually maps. Others (e.g. webserver: IIS W3C field names)
# would come out as raw Sigma field names, so they go to the built-in translator instead.
SUPPORTED: dict[str, set[str]] = {
    "spl": {"process_creation", "file_event", "network_connection", "dns_query"},
    "kql_defender": {"process_creation", "file_event", "network_connection"},
    "kql_sentinel": {"process_creation", "file_event", "network_connection"},
    "esql": {"process_creation", "file_event", "network_connection", "dns_query"},
}
BACKEND_NAME = {"spl": "splunk", "kql_defender": "kusto_xdr", "kql_sentinel": "kusto_asim", "esql": "esql"}


def _backend(platform: str):
    """A fresh backend + pipeline (pipelines keep per-conversion state, so never share one)."""
    if platform == "spl":
        from sigma.backends.splunk import SplunkBackend
        from sigma.pipelines.splunk import splunk_windows_pipeline
        return SplunkBackend(splunk_windows_pipeline())
    if platform == "kql_defender":
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
        return KustoBackend(microsoft_xdr_pipeline())
    if platform == "kql_sentinel":
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
        return KustoBackend(sentinel_asim_pipeline())
    if platform == "esql":
        from sigma.backends.elasticsearch import ESQLBackend
        from sigma.pipelines.elasticsearch import ecs_windows
        return ESQLBackend(ecs_windows())
    return None


def available() -> bool:
    try:
        import sigma.collection  # noqa: F401
        return True
    except Exception:  # pragma: no cover - pySigma not installed
        return False


def engine_name(platform: str) -> str | None:
    b = BACKEND_NAME.get(platform)
    return f"pysigma:{b}" if b else None


def parse(sigma_yaml: str):
    """SigmaCollection for the YAML; raises on an invalid rule (pySigma collects rule errors, re-raised here)."""
    from sigma.collection import SigmaCollection
    coll = SigmaCollection.from_yaml(sigma_yaml)
    errors = [e for r in coll.rules for e in (getattr(r, "errors", None) or [])]
    if errors:
        raise errors[0]
    if not coll.rules:
        raise ValueError("No Sigma rule in document")
    return coll


# Raw-field leaks that mean the pipeline did not map the rule to the target schema.
_LEAKS: dict[str, re.Pattern] = {
    "esql": re.compile(r"winlog\.event_data\.|`[A-Za-z-]+`"),
}


def translate_sigma(sigma_yaml: str, platform: str) -> str | None:
    """Raw pySigma output for one platform, or None (no backend / unsupported log source / backend error)."""
    if platform not in BACKEND_NAME or not available():
        return None
    try:
        coll = parse(sigma_yaml)
        cat = coll.rules[0].logsource.category
        if cat not in SUPPORTED[platform]:
            return None
        out = _backend(platform).convert(coll)
    except Exception as e:  # backend or pipeline rejected the rule: caller falls back
        log.debug("pySigma %s failed: %s", platform, e)
        return None
    q = "\n".join(str(x) for x in out).strip() if isinstance(out, list) else str(out or "").strip()
    if not q:
        return None
    leak = _LEAKS.get(platform)
    if leak and leak.search(q):
        return None
    return q


# ---- post-processing: pySigma gives the filter only; add ThreatLens' index/table, look-back and projection ----

# KQL columns that hold a file NAME (not a path): `endswith "\\x.exe"` there never matches, compare the base name.
_KQL_NAME_COLS = ("InitiatingProcessParentFileName", "InitiatingProcessFileName", "FileName", "ParentProcessName",
                  "ActingProcessName", "TargetProcessName")
_KQL_NAME_EW = re.compile(r"\b(" + "|".join(_KQL_NAME_COLS) + r')\s+endswith\s+"((?:\x5c.|[^"\x5c])*)"')

# ASIM parsers and a projection per parser (pySigma picks the parser from the rule's category).
ASIM_PROJECT = {
    "imProcessCreate": "| project TimeGenerated, DvcHostname, ActorUsername, ParentProcessName, TargetProcessName, TargetProcessCommandLine",
    "imFileEvent": "| project TimeGenerated, DvcHostname, ActorUsername, ActingProcessName, TargetFilePath",
    "imNetworkSession": "| project TimeGenerated, DvcHostname, SrcIpAddr, DstIpAddr, DstPortNumber, NetworkProtocol",
}
ASIM_LOG_SOURCE = {
    "imProcessCreate": "ASIM imProcessCreate (SecurityEvent 4688 / Sysmon 1 / MDE)",
    "imFileEvent": "ASIM imFileEvent (Sysmon 11 / MDE)",
    "imNetworkSession": "ASIM imNetworkSession (Sysmon 3 / firewall / MDE)",
}


def _kql_name_fix(cond: str) -> str:
    def sub(m):
        val = m.group(2)  # KQL string text: a literal backslash is written as two
        if "\\\\" not in val:
            return m.group(0)
        return f'{m.group(1)} =~ "{val.split(chr(92) * 2)[-1]}"'
    return _KQL_NAME_EW.sub(sub, cond)


def finish(platform: str, raw: str, category: str, days: int, base: dict, project: dict) -> tuple[str, dict]:
    """Wrap a raw pySigma query into a runnable hunt: returns (body, extra) where extra may carry `log_sources`.
    `base`/`project` are detection.BASE / detection.PROJECT (passed in to avoid an import cycle)."""
    extra: dict = {}
    proj = project.get(platform, {}).get(category, "")
    if platform == "spl":
        prefix = base.get(category, {}).get("spl", "")
        body = f"{prefix} earliest=-{days}d latest=now {raw}".strip()
        return body + (f"\n{proj}" if proj else ""), extra
    if platform in ("kql_defender", "kql_sentinel"):
        table, _, rest = raw.partition("\n")
        cond = re.sub(r"^\|\s*where\s+", "", rest.strip())
        cond = _kql_name_fix(cond)
        ts = "Timestamp" if platform == "kql_defender" else "TimeGenerated"
        lines = [table.strip(), f"| where {ts} > ago({days}d)"]
        if platform == "kql_defender" and table.strip() == "DeviceFileEvents":
            lines.append('| where ActionType == "FileCreated"')
        lines.append(f"| where {cond}")
        if platform == "kql_sentinel":
            p = ASIM_PROJECT.get(table.strip(), "")
            if table.strip() in ASIM_LOG_SOURCE:
                extra["log_sources"] = [ASIM_LOG_SOURCE[table.strip()]]
        else:
            p = proj
        return "\n".join(lines) + (f"\n{p}" if p else ""), extra
    if platform == "esql":
        cond = re.split(r"\|\s*where\s+", raw, maxsplit=1, flags=re.I)[-1].strip()
        prefix = base.get(category, {}).get("esql", "FROM logs-*\n| WHERE @timestamp > NOW() - {days} days").replace("{days}", str(days))
        return f"{prefix}\n| WHERE {cond}" + (f"\n{proj}" if proj else ""), extra
    return raw, extra


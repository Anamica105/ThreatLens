"""Detection engineering (spec section 8).

A detection opportunity is expressed as a neutral spec (a small subset of Sigma):
    {"category": "process_creation", "conditions": [{"field": "parent_image", "op": "endswith", "values": ["\\w3wp.exe"]}, ...]}
From it we render a Sigma rule (the source of truth) and translate it per platform
with a field-mapping dictionary. In LLM mode the query agent writes the queries
itself but is given the same field dictionary; every query then goes through lint.
"""

from __future__ import annotations

import re
import textwrap

PLATFORMS: list[dict] = [
    {"id": "spl", "name": "Splunk SPL", "short": "SPL", "vendor": "Splunk"},
    {"id": "kql_sentinel", "name": "Microsoft Sentinel KQL", "short": "KQL", "vendor": "Microsoft Sentinel"},
    {"id": "kql_defender", "name": "Defender XDR KQL", "short": "KQL (MDE)", "vendor": "Microsoft Defender XDR"},
    {"id": "cql", "name": "CrowdStrike CQL", "short": "CQL", "vendor": "CrowdStrike"},
    {"id": "s1ql", "name": "SentinelOne S1QL / PowerQuery", "short": "S1QL", "vendor": "SentinelOne"},
    {"id": "xql", "name": "Cortex XQL", "short": "XQL", "vendor": "Palo Alto Cortex"},
    {"id": "esql", "name": "Elastic ES|QL", "short": "ES|QL", "vendor": "Elastic"},
    {"id": "yaral", "name": "Google SecOps YARA-L", "short": "YARA-L", "vendor": "Google SecOps"},
    {"id": "aql", "name": "QRadar AQL", "short": "AQL", "vendor": "IBM QRadar"},
    {"id": "sigma", "name": "Sigma", "short": "Sigma", "vendor": "Sigma"},
]
PLATFORM_IDS = [p["id"] for p in PLATFORMS]
PLATFORM_BY_ID = {p["id"]: p for p in PLATFORMS}

CATEGORIES = {
    "process_creation": "Process creation",
    "file_event": "File creation",
    "web": "Web server requests",
    "network": "Network connections",
    "dns": "DNS",
    "registry": "Registry",
    "scheduled_task": "Scheduled task / GPO",
    "file_hash": "File hashes",
    "vuln_mgmt": "Vulnerability / asset inventory",
    "auth": "Authentication",
}

# Required log source per data-source category and platform (spec 8, "Required log sources").
LOG_SOURCES: dict[str, dict[str, str]] = {
    "process_creation": {"windows": "4688 (with command line), Sysmon 1", "spl": "Sysmon EID 1 / Endpoint.Processes",
                         "kql_sentinel": "SecurityEvent 4688", "kql_defender": "DeviceProcessEvents", "cql": "ProcessRollup2",
                         "s1ql": "Process Creation", "xql": "xdr_data (PROCESS)", "esql": "logs-endpoint.events.process",
                         "yaral": "PROCESS_LAUNCH", "aql": "Sysmon / 4688 events", "sigma": "category: process_creation"},
    "file_event": {"windows": "Sysmon 11", "spl": "Sysmon EID 11 / Endpoint.Filesystem", "kql_sentinel": "DeviceFileEvents",
                   "kql_defender": "DeviceFileEvents", "cql": "NewScriptWritten, PeFileWritten", "s1ql": "File Creation",
                   "xql": "xdr_data (FILE)", "esql": "logs-endpoint.events.file", "yaral": "FILE_CREATION",
                   "aql": "Sysmon EID 11", "sigma": "category: file_event"},
    "web": {"windows": "IIS W3C logs (Referer, UA enabled)", "spl": "ms:iis:auto / Web", "kql_sentinel": "W3CIISLog",
            "kql_defender": "— (needs IIS log ingestion)", "cql": "— (needs log ingestion)", "s1ql": "— (needs log ingestion)",
            "xql": "— (needs log ingestion)", "esql": "logs-iis.access", "yaral": "NETWORK_HTTP", "aql": "IIS DSM",
            "sigma": "category: webserver"},
    "network": {"windows": "Sysmon 3", "spl": "Sysmon EID 3 / Network_Traffic", "kql_sentinel": "CommonSecurityLog",
                "kql_defender": "DeviceNetworkEvents", "cql": "NetworkConnectIP4", "s1ql": "IP Connect",
                "xql": "xdr_data (NETWORK)", "esql": "logs-endpoint.events.network", "yaral": "NETWORK_CONNECTION",
                "aql": "Firewall / flow events", "sigma": "category: network_connection"},
    "dns": {"windows": "Sysmon 22", "spl": "Sysmon EID 22 / Network_Resolution", "kql_sentinel": "DnsEvents",
            "kql_defender": "DeviceNetworkEvents (RemoteUrl)", "cql": "DnsRequest", "s1ql": "DNS Resolved",
            "xql": "xdr_data (NETWORK dns)", "esql": "logs-endpoint.events.network (dns)", "yaral": "NETWORK_DNS",
            "aql": "DNS events", "sigma": "category: dns_query"},
    "registry": {"windows": "Sysmon 13", "spl": "Sysmon EID 13 / Endpoint.Registry", "kql_sentinel": "DeviceRegistryEvents",
                 "kql_defender": "DeviceRegistryEvents", "cql": "RegGenericValueUpdate", "s1ql": "Registry Value Modified",
                 "xql": "xdr_data (REGISTRY)", "esql": "logs-endpoint.events.registry", "yaral": "REGISTRY_MODIFICATION",
                 "aql": "Sysmon EID 13", "sigma": "category: registry_set"},
    "scheduled_task": {"windows": "4698, 5136", "spl": "WinEventLog 4698/5136 / Change", "kql_sentinel": "SecurityEvent 4698/5136",
                       "kql_defender": "DeviceEvents", "cql": "ScheduledTaskRegistered", "s1ql": "Task Register",
                       "xql": "xdr_data (EVENT_LOG)", "esql": "logs-system.security", "yaral": "SCHEDULED_TASK_CREATION",
                       "aql": "Windows 4698", "sigma": "service: security"},
    "file_hash": {"windows": "Sysmon 1/11 (Hashes)", "spl": "Sysmon EID 1 Hashes", "kql_sentinel": "DeviceFileEvents",
                  "kql_defender": "DeviceFileEvents / DeviceProcessEvents", "cql": "ProcessRollup2 SHA256HashData",
                  "s1ql": "tgt.file.sha256", "xql": "xdr_data action_file_sha256", "esql": "file.hash.sha256",
                  "yaral": "target.file.sha256", "aql": "SHA256 Hash property", "sigma": "category: process_creation (Hashes)"},
    "vuln_mgmt": {"windows": "Software inventory", "spl": "Vulnerability scanner index", "kql_sentinel": "DeviceTvmSoftwareVulnerabilities",
                  "kql_defender": "DeviceTvmSoftwareVulnerabilities", "cql": "Spotlight vulnerabilities", "s1ql": "Application inventory",
                  "xql": "Host inventory", "esql": "Vulnerability index", "yaral": "Asset context", "aql": "QRadar Vulnerability Manager",
                  "sigma": "n/a"},
}

# ---- field dictionaries for translation ----

F = {
    "process_creation": {
        "sigma": {"parent_image": "ParentImage", "image": "Image", "command_line": "CommandLine", "grandparent_image": "GrandParentImage"},
        "spl": {"parent_image": "ParentImage", "image": "Image", "command_line": "CommandLine", "grandparent_image": "GrandParentImage"},
        "kql_sentinel": {"parent_image": "ParentProcessName", "image": "NewProcessName", "command_line": "CommandLine"},
        "kql_defender": {"parent_image": "InitiatingProcessFileName", "image": "FileName", "command_line": "ProcessCommandLine",
                         "grandparent_image": "InitiatingProcessParentFileName"},
        "cql": {"parent_image": "ParentBaseFileName", "image": "FileName", "command_line": "CommandLine", "grandparent_image": "GrandParentBaseFileName"},
        "s1ql": {"parent_image": "src.process.name", "image": "tgt.process.name", "command_line": "tgt.process.cmdline", "grandparent_image": "src.process.parent.name"},
        "xql": {"parent_image": "actor_process_image_name", "image": "action_process_image_name", "command_line": "action_process_image_command_line", "grandparent_image": "causality_actor_process_image_name"},
        "esql": {"parent_image": "process.parent.name", "image": "process.name", "command_line": "process.command_line"},
        "yaral": {"parent_image": "principal.process.file.full_path", "image": "target.process.file.full_path", "command_line": "target.process.command_line"},
        "aql": {"parent_image": "\"ParentImage\"", "image": "\"Image\"", "command_line": "\"Process CommandLine\""},
    },
    "file_event": {
        "sigma": {"target_filename": "TargetFilename", "image": "Image"},
        "spl": {"target_filename": "TargetFilename", "image": "Image"},
        "kql_sentinel": {"target_filename": "FolderPath", "image": "InitiatingProcessFileName"},
        "kql_defender": {"target_filename": "FolderPath", "image": "InitiatingProcessFileName"},
        "cql": {"target_filename": "TargetFileName", "image": "ContextBaseFileName"},
        "s1ql": {"target_filename": "tgt.file.path", "image": "src.process.name"},
        "xql": {"target_filename": "action_file_path", "image": "actor_process_image_name"},
        "esql": {"target_filename": "file.path", "image": "process.name"},
        "yaral": {"target_filename": "target.file.full_path", "image": "principal.process.file.full_path"},
        "aql": {"target_filename": "\"Filename\"", "image": "\"Image\""},
    },
    "web": {
        "sigma": {"http_method": "cs-method", "url_path": "cs-uri-stem", "referer": "cs-referer", "user_agent": "cs-user-agent", "src_ip": "c-ip"},
        "spl": {"http_method": "cs_method", "url_path": "cs_uri_stem", "referer": "cs_Referer", "user_agent": "cs_User_Agent", "src_ip": "c_ip"},
        "kql_sentinel": {"http_method": "csMethod", "url_path": "csUriStem", "referer": "csReferer", "user_agent": "csUserAgent", "src_ip": "cIP"},
        "esql": {"http_method": "http.request.method", "url_path": "url.path", "referer": "http.request.referrer", "user_agent": "user_agent.original", "src_ip": "source.ip"},
        "yaral": {"http_method": "network.http.method", "url_path": "target.url", "referer": "network.http.referral_url", "user_agent": "network.http.user_agent", "src_ip": "principal.ip"},
        "aql": {"http_method": "\"HTTP Method\"", "url_path": "URL", "referer": "\"HTTP Referer\"", "user_agent": "\"User Agent\"", "src_ip": "sourceip"},
    },
    "network": {
        "sigma": {"dst_ip": "DestinationIp"}, "spl": {"dst_ip": "DestinationIp"}, "kql_sentinel": {"dst_ip": "DestinationIP"},
        "kql_defender": {"dst_ip": "RemoteIP"}, "cql": {"dst_ip": "RemoteAddressIP4"}, "s1ql": {"dst_ip": "dst.ip.address"},
        "xql": {"dst_ip": "action_remote_ip"}, "esql": {"dst_ip": "destination.ip"}, "yaral": {"dst_ip": "target.ip"}, "aql": {"dst_ip": "destinationip"},
    },
    "dns": {
        "sigma": {"domain": "QueryName"}, "spl": {"domain": "QueryName"}, "kql_sentinel": {"domain": "Name"},
        "kql_defender": {"domain": "RemoteUrl"}, "cql": {"domain": "DomainName"}, "s1ql": {"domain": "event.dns.request"},
        "xql": {"domain": "dns_query_name"}, "esql": {"domain": "dns.question.name"}, "yaral": {"domain": "network.dns.questions.name"}, "aql": {"domain": "\"DNS Query\""},
    },
    "file_hash": {
        "sigma": {"sha256": "Hashes"}, "spl": {"sha256": "Hashes"}, "kql_sentinel": {"sha256": "SHA256"},
        "kql_defender": {"sha256": "SHA256"}, "cql": {"sha256": "SHA256HashData"}, "s1ql": {"sha256": "tgt.file.sha256"},
        "xql": {"sha256": "action_file_sha256"}, "esql": {"sha256": "file.hash.sha256"}, "yaral": {"sha256": "target.file.sha256"}, "aql": {"sha256": "\"SHA256 Hash\""},
    },
}

BASE = {
    "process_creation": {
        "spl": 'index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1',
        "kql_sentinel": "SecurityEvent\n| where TimeGenerated > ago({days}d)\n| where EventID == 4688",
        "kql_defender": "DeviceProcessEvents\n| where Timestamp > ago({days}d)",
        "cql": "#event_simpleName=ProcessRollup2 event_platform=Win",
        "s1ql": "event.type = 'Process Creation'",
        "xql": "config timeframe = {days}d\n| dataset = xdr_data\n| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START",
        "esql": "FROM logs-endpoint.events.process-*\n| WHERE @timestamp > NOW() - {days} days AND event.type == \"start\"",
        "yaral": '$e.metadata.event_type = "PROCESS_LAUNCH"',
        "aql": "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS time, sourceip, username, \"Image\", \"Process CommandLine\" FROM events WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%sysmon%'",
    },
    "file_event": {
        "spl": 'index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11',
        "kql_sentinel": "DeviceFileEvents\n| where TimeGenerated > ago({days}d)\n| where ActionType == \"FileCreated\"",
        "kql_defender": "DeviceFileEvents\n| where Timestamp > ago({days}d)\n| where ActionType == \"FileCreated\"",
        "cql": "#event_simpleName=/^(NewScriptWritten|PeFileWritten|NewExecutableWritten)$/",
        "s1ql": "event.type = 'File Creation'",
        "xql": "config timeframe = {days}d\n| dataset = xdr_data\n| filter event_type = ENUM.FILE and event_sub_type = ENUM.FILE_CREATE_NEW",
        "esql": "FROM logs-endpoint.events.file-*\n| WHERE @timestamp > NOW() - {days} days AND event.type == \"creation\"",
        "yaral": '$e.metadata.event_type = "FILE_CREATION"',
        "aql": "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS time, sourceip, \"Filename\" FROM events WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%sysmon%'",
    },
    "web": {
        "spl": 'index=web sourcetype="ms:iis:auto"',
        "kql_sentinel": "W3CIISLog\n| where TimeGenerated > ago({days}d)",
        "esql": "FROM logs-iis.access-*\n| WHERE @timestamp > NOW() - {days} days",
        "yaral": '$e.metadata.event_type = "NETWORK_HTTP"',
        "aql": "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS time, sourceip, URL FROM events WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%IIS%'",
    },
    "network": {
        "spl": 'index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3',
        "kql_sentinel": "CommonSecurityLog\n| where TimeGenerated > ago({days}d)",
        "kql_defender": "DeviceNetworkEvents\n| where Timestamp > ago({days}d)",
        "cql": "#event_simpleName=NetworkConnectIP4",
        "s1ql": "event.type = 'IP Connect'",
        "xql": "config timeframe = {days}d\n| dataset = xdr_data\n| filter event_type = ENUM.NETWORK",
        "esql": "FROM logs-endpoint.events.network-*\n| WHERE @timestamp > NOW() - {days} days",
        "yaral": '$e.metadata.event_type = "NETWORK_CONNECTION"',
        "aql": "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS time, sourceip, destinationip, destinationport FROM flows",
    },
    "dns": {
        "spl": 'index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22',
        "kql_sentinel": "DnsEvents\n| where TimeGenerated > ago({days}d)",
        "kql_defender": "DeviceNetworkEvents\n| where Timestamp > ago({days}d)",
        "cql": "#event_simpleName=DnsRequest",
        "s1ql": "event.type = 'DNS Resolved'",
        "xql": "config timeframe = {days}d\n| dataset = xdr_data\n| filter event_type = ENUM.NETWORK and dns_query_name != null",
        "esql": "FROM logs-endpoint.events.network-*\n| WHERE @timestamp > NOW() - {days} days AND dns.question.name IS NOT NULL",
        "yaral": '$e.metadata.event_type = "NETWORK_DNS"',
        "aql": "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS time, sourceip, \"DNS Query\" FROM events",
    },
    "file_hash": {
        "spl": 'index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=11)',
        "kql_sentinel": "DeviceFileEvents\n| where TimeGenerated > ago({days}d)",
        "kql_defender": "union DeviceFileEvents, DeviceProcessEvents\n| where Timestamp > ago({days}d)",
        "cql": "#event_simpleName=/^(ProcessRollup2|NewScriptWritten|PeFileWritten)$/",
        "s1ql": "event.type in ('File Creation', 'Process Creation')",
        "xql": "config timeframe = {days}d\n| dataset = xdr_data\n| filter event_type in (ENUM.FILE, ENUM.PROCESS)",
        "esql": "FROM logs-endpoint.events.*\n| WHERE @timestamp > NOW() - {days} days",
        "yaral": '$e.metadata.event_type = "FILE_CREATION"',
        "aql": "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS time, sourceip, \"Filename\", \"SHA256 Hash\" FROM events",
    },
}

PROJECT = {
    "spl": {"process_creation": "| stats count min(_time) as first_seen max(_time) as last_seen values(CommandLine) as cmdlines by host, ParentImage, Image\n| convert ctime(first_seen) ctime(last_seen)",
            "file_event": "| stats count min(_time) as first_seen by host, Image, TargetFilename\n| convert ctime(first_seen)",
            "web": "| stats count by c_ip, s_computername, cs_User_Agent",
            "network": "| stats count min(_time) as first_seen by host, Image, DestinationIp, DestinationPort\n| convert ctime(first_seen)",
            "dns": "| stats count by host, Image, QueryName",
            "file_hash": "| stats count by host, Image, Hashes"},
    "kql_sentinel": {"process_creation": "| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine",
                     "file_event": "| project TimeGenerated, DeviceName, InitiatingProcessFileName, FolderPath",
                     "web": "| project TimeGenerated, cIP, sSiteName, csMethod, csUriStem, csReferer, csUserAgent",
                     "network": "| project TimeGenerated, DeviceName, SourceIP, DestinationIP, DestinationPort",
                     "dns": "| project TimeGenerated, Computer, ClientIP, Name",
                     "file_hash": "| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256"},
    "kql_defender": {"process_creation": "| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine",
                     "file_event": "| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, SHA256",
                     "network": "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl",
                     "dns": "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP",
                     "file_hash": "| project Timestamp, DeviceName, FileName, FolderPath, SHA256"},
    "cql": {"process_creation": "| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])",
            "file_event": "| table([@timestamp, ComputerName, ContextBaseFileName, TargetFileName])",
            "network": "| table([@timestamp, ComputerName, RemoteAddressIP4, RemotePort])",
            "dns": "| table([@timestamp, ComputerName, DomainName])",
            "file_hash": "| table([@timestamp, ComputerName, FileName, SHA256HashData])"},
    "xql": {"process_creation": "| fields _time, agent_hostname, actor_process_image_name, action_process_image_name, action_process_image_command_line",
            "file_event": "| fields _time, agent_hostname, actor_process_image_name, action_file_path",
            "network": "| fields _time, agent_hostname, actor_process_image_name, action_remote_ip, action_remote_port",
            "dns": "| fields _time, agent_hostname, actor_process_image_name, dns_query_name",
            "file_hash": "| fields _time, agent_hostname, action_file_name, action_file_sha256"},
    "esql": {"process_creation": "| KEEP @timestamp, host.name, user.name, process.parent.name, process.name, process.command_line",
             "file_event": "| KEEP @timestamp, host.name, process.name, file.path",
             "web": "| STATS count = COUNT(*) BY source.ip, user_agent.original",
             "network": "| KEEP @timestamp, host.name, process.name, destination.ip, destination.port",
             "dns": "| KEEP @timestamp, host.name, process.name, dns.question.name",
             "file_hash": "| KEEP @timestamp, host.name, file.name, file.hash.sha256"},
}


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"')


def _basename(v: str) -> str:
    return v.replace("/", "\\").split("\\")[-1]


def _cond(platform: str, category: str, c: dict) -> str | None:
    field = F.get(category, {}).get(platform, {}).get(c["field"])
    if not field:
        return None
    op, vals = c.get("op", "equals"), c["values"]
    # EDR tables that hold file names (not paths) compare base names.
    name_fields = {"InitiatingProcessFileName", "FileName", "ParentBaseFileName", "GrandParentBaseFileName", "InitiatingProcessParentFileName",
                   "src.process.name", "tgt.process.name", "src.process.parent.name", "actor_process_image_name", "action_process_image_name",
                   "causality_actor_process_image_name", "process.parent.name", "process.name", "ContextBaseFileName"}
    if field in name_fields and op == "endswith":
        vals, op = [_basename(v) for v in vals], "equals"

    if platform in ("spl",):
        def one(v):
            v = v.replace('"', '\\"')
            return {"endswith": f'{field}="*{v}"', "contains": f'{field}="*{v}*"', "startswith": f'{field}="{v}*"'}.get(op, f'{field}="{v}"')
    elif platform in ("kql_sentinel", "kql_defender"):
        if op == "equals":
            return f"{field} in~ ({', '.join(chr(34) + _esc(v) + chr(34) for v in vals)})" if len(vals) > 1 else f'{field} =~ "{_esc(vals[0])}"'
        kop = {"endswith": "endswith", "contains": "has", "startswith": "startswith"}[op]
        if op == "contains" and len(vals) > 1:
            return f"{field} has_any ({', '.join(chr(34) + _esc(v) + chr(34) for v in vals)})"
        def one(v):
            return f'{field} {kop} "{_esc(v)}"'
    elif platform == "cql":
        def one(v):
            r = re.escape(v).replace("/", "\\/")
            return {"endswith": f"{field}=/{r}$/i", "contains": f"{field}=/{r}/i", "startswith": f"{field}=/^{r}/i"}.get(op, f"{field}=/^{r}$/i")
    elif platform == "s1ql":
        if op == "equals":
            return f"{field} in:anycase ({', '.join(repr(v) for v in vals)})"
        if op == "contains":
            return f"{field} contains:anycase ({', '.join(repr(v) for v in vals)})"
        def one(v):
            return f"{field} {'endswith' if op == 'endswith' else 'startswith'}:anycase '{v}'"
    elif platform == "xql":
        def one(v):
            v2 = v.lower().replace('"', '\\"')
            return {"endswith": f'lowercase({field}) ~= ".*{re.escape(v2)}$"', "contains": f'lowercase({field}) contains "{v2}"',
                    "startswith": f'lowercase({field}) ~= "^{re.escape(v2)}"'}.get(op, f'lowercase({field}) = "{v2}"')
    elif platform == "esql":
        def one(v):
            v2 = _esc(v)
            return {"endswith": f'{field} LIKE "*{v2}"', "contains": f'{field} LIKE "*{v2}*"', "startswith": f'{field} LIKE "{v2}*"'}.get(op, f'{field} == "{v2}"')
    elif platform == "yaral":
        def one(v):
            r = re.escape(v).replace("/", "\\/")
            return {"endswith": f"re.regex($e.{field}, `(?i){r}$`)", "contains": f"re.regex($e.{field}, `(?i){r}`)",
                    "startswith": f"re.regex($e.{field}, `(?i)^{r}`)"}.get(op, f'$e.{field} = "{_esc(v)}" nocase')
    elif platform == "aql":
        def one(v):
            v2 = v.replace("'", "''")
            return {"endswith": f"{field} ILIKE '%{v2}'", "contains": f"{field} ILIKE '%{v2}%'", "startswith": f"{field} ILIKE '{v2}%'"}.get(op, f"{field} = '{v2}'")
    else:
        return None
    parts = [one(v) for v in vals]
    return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"


def to_sigma(title: str, spec: dict, rule_id: str, techniques: list[str], fp_notes: str, level: str = "high") -> str:
    cat = spec.get("category", "process_creation")
    logsource = {
        "process_creation": "  category: process_creation\n  product: windows",
        "file_event": "  category: file_event\n  product: windows",
        "web": "  category: webserver",
        "network": "  category: network_connection\n  product: windows",
        "dns": "  category: dns_query\n  product: windows",
        "file_hash": "  category: process_creation\n  product: windows",
    }.get(cat, f"  category: {cat}")
    lines = []
    for c in spec.get("conditions", []):
        field = F.get(cat, {}).get("sigma", {}).get(c["field"], c["field"])
        mod = {"endswith": "|endswith", "contains": "|contains", "startswith": "|startswith"}.get(c.get("op", "equals"), "")
        if cat == "file_hash":
            field, mod = "Hashes", "|contains"
        vals = c["values"]
        if len(vals) == 1:
            lines.append(f"    {field}{mod}: '{vals[0]}'")
        else:
            lines.append(f"    {field}{mod}:\n" + "\n".join(f"      - '{v}'" for v in vals))
    tags = "\n".join(f"  - attack.{t.lower()}" for t in techniques) or "  - attack.execution"
    return textwrap.dedent(f"""\
title: {title}
id: {rule_id}
status: experimental
description: Generated by ThreatLens from a detection opportunity. Review before deployment.
tags:
{tags}
logsource:
{logsource}
detection:
  selection:
{chr(10).join(lines)}
  condition: selection
falsepositives:
  - {fp_notes or 'Unknown'}
level: {level}
""")


def translate(spec: dict, platform: str, days: int = 30, title: str = "") -> str | None:
    """Render a neutral detection spec into one platform's query. None = platform lacks that telemetry."""
    cat = spec.get("category", "process_creation")
    if platform == "sigma":
        return None
    base = BASE.get(cat, {}).get(platform)
    if base is None:
        return None
    conds = [_cond(platform, cat, c) for c in spec.get("conditions", [])]
    if any(c is None for c in conds):
        return None
    base = base.replace("{days}", str(days))
    proj = PROJECT.get(platform, {}).get(cat, "")
    if platform == "spl":
        return f"{base} " + " ".join(conds) + (f"\n{proj}" if proj else "")
    if platform in ("kql_sentinel", "kql_defender"):
        return base + "".join(f"\n| where {c}" for c in conds) + (f"\n{proj}" if proj else "")
    if platform == "cql":
        return base + "\n| " + " ".join(conds) + (f"\n{proj}" if proj else "")
    if platform == "s1ql":
        return base + " and " + " and ".join(conds)
    if platform == "xql":
        return base + "".join(f"\n| filter {c}" for c in conds) + (f"\n{proj}" if proj else "")
    if platform == "esql":
        return base + "".join(f"\n| WHERE {c}" for c in conds) + (f"\n{proj}" if proj else "")
    if platform == "yaral":
        name = re.sub(r"[^a-z0-9_]+", "_", (title or "threatlens_hunt").lower()).strip("_")[:60]
        body = "\n    ".join([base] + conds)
        return f"rule {name} {{\n  meta:\n    author = \"ThreatLens\"\n  events:\n    {body}\n  condition:\n    $e\n}}"
    if platform == "aql":
        return base + " AND " + " AND ".join(conds) + f" LAST {days} DAYS"
    return None


def ioc_query(platform: str, category: str, values: list[str], days: int = 30) -> str | None:
    field = {"network": "dst_ip", "dns": "domain", "file_hash": "sha256"}[category]
    op = "contains" if category in ("file_hash",) and platform in ("spl",) else "equals"
    return translate({"category": category, "conditions": [{"field": field, "op": op, "values": values}]}, platform, days, "ioc_retrohunt")


# ---- query status lifecycle (spec 8.5) ----
# Generated -> Syntax-checked -> Reviewed -> Lab-tested (P2) -> Deployed. Vendor-supplied queries start as "reference";
# "deprecated" retires a query (kept as history in the library).
QUERY_STATUS_FLOW = ["generated", "syntax_checked", "reviewed", "lab_tested", "deployed"]
QUERY_STATUSES = QUERY_STATUS_FLOW + ["reference", "deprecated"]
QUERY_STATUS_LABELS = {"generated": "Generated", "syntax_checked": "Syntax-checked", "reviewed": "Reviewed",
                       "lab_tested": "Lab-tested", "deployed": "Deployed", "reference": "Reference", "deprecated": "Deprecated"}
_STATUS_RANK = {"reference": 0, **{s: i for i, s in enumerate(QUERY_STATUS_FLOW)}, "deprecated": len(QUERY_STATUS_FLOW)}


def status_rank(status: str | None) -> int:
    return _STATUS_RANK.get(status or "", -1)


def more_advanced_status(a: str | None, b: str | None) -> str | None:
    """The later of two lifecycle statuses (deprecated counts as the end of the lifecycle)."""
    return a if status_rank(a) >= status_rank(b) else b


def check_status_change(new: str, *, origin: str = "generated", lint_issues: list[str] | None = None) -> str | None:
    """Why a query cannot be moved to `new` (None = allowed). Moving backwards (demoting) is allowed."""
    if new not in QUERY_STATUSES:
        return f"Unknown query status '{new}'. Use one of: {', '.join(QUERY_STATUSES)}."
    if new == "reference" and origin != "reference":
        return "Only vendor-supplied queries can have status 'reference'."
    if origin == "reference" and new in ("generated", "syntax_checked"):
        return "Vendor reference queries are not linted; use reference, reviewed, lab_tested, deployed or deprecated."
    if origin != "reference" and lint_issues and new in ("syntax_checked", "reviewed", "lab_tested", "deployed"):
        return f"Fix the lint findings before marking the query {QUERY_STATUS_LABELS[new]}: " + "; ".join(lint_issues)
    return None


# ---- workspace field mappings (spec 8.4) ----
#
# Workspace.field_mappings = {platform: {from: to}} (a "*" platform key applies to every platform). Entries are matched
# as tokens, not raw substrings:
#   * `key=value` (index=endpoint, sourcetype="XmlWinEventLog:...", #event_simpleName=ProcessRollup2): matches that
#     assignment, with or without quotes and spaces around '=', and only as a whole value (index=endpoint never hits
#     index=endpoint_old). The replacement is inserted as written.
#   * a bare identifier (table name, field name, dotted ECS/UDM path, index pattern such as logs-endpoint.events.process-*):
#     replaced as a whole token outside string literals, so a field rename never rewrites a searched value.
#   * a quoted identifier ("Process CommandLine" in AQL) is replaced literally.
#   * anything else falls back to a literal replace.

_IDENT = r"[A-Za-z_@#$][\w.@$:*-]*"
_ASSIGN_RE = re.compile(r"""^\s*(#?[A-Za-z_][\w.]*)\s*=\s*(["']?)(.+?)\2\s*$""")
_IDENT_RE = re.compile(rf"^{_IDENT}$")
_LITERAL_RE = re.compile(r""""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`""")
_CQL_REGEX_RE = re.compile(r"(?<==)/(?:\\.|[^/\n])+/[a-z]*")


def _literal_spans(body: str, platform: str) -> list[tuple[int, int]]:
    """Spans of string literals (and CQL regex literals), which identifier mappings must not touch."""
    spans = [m.span() for m in _LITERAL_RE.finditer(body)]
    if platform == "cql":
        spans += [m.span() for m in _CQL_REGEX_RE.finditer(body)]
    return spans


def _outside(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return not any(a < end and start < b for a, b in spans)


def _map_one(body: str, platform: str, src: str, dst: str) -> str:
    m = _ASSIGN_RE.match(src)
    if m:
        key, val = m.group(1), m.group(3)
        rx = re.compile(rf"""(?<![\w.#]){re.escape(key)}\s*=\s*(["']?){re.escape(val)}\1(?![\w.*:/-])""", re.I)
        spans = _literal_spans(body, platform)
        return rx.sub(lambda hit: dst if _outside(spans, hit.start(), hit.start() + 1) else hit.group(0), body)
    s = src.strip()
    if _IDENT_RE.match(s):
        rx = re.compile(rf"(?<![\w.@#$]){re.escape(s)}(?![\w*-])(?!\.\w)")
        spans = _literal_spans(body, platform)
        out, last = [], 0
        for hit in rx.finditer(body):
            if _outside(spans, *hit.span()):
                out += [body[last:hit.start()], dst]
                last = hit.end()
        return "".join(out) + body[last:]
    return body.replace(src, dst)


def workspace_mappings(mappings: dict | None, platform: str) -> dict[str, str]:
    m = mappings or {}
    return {**(m.get("*") or {}), **(m.get(platform) or {})}


def apply_mappings(body: str, platform: str, mappings: dict | None) -> str:
    """Apply a workspace's field mappings ({platform: {from: to}}) to one query body, token-aware (see above).
    Longer `from` keys are applied first so `index=endpoint_raw` wins over `index=endpoint`."""
    for src, dst in sorted(workspace_mappings(mappings, platform).items(), key=lambda kv: -len(kv[0])):
        if src and src.strip() and dst is not None:
            body = _map_one(body, platform, src, str(dst))
    return body


def map_query(q: dict, mappings: dict | None) -> dict:
    """{mapped_body, mapped_lint, mapping_applied} for a record query under a workspace's mappings. Lint re-runs on the
    mapped text (vendor reference queries are never linted)."""
    body = q.get("body", "")
    mapped = apply_mappings(body, q.get("platform", ""), mappings)
    issues = [] if q.get("origin") == "reference" else lint(q.get("platform", ""), mapped, q.get("techniques"))
    return {"mapped_body": mapped, "mapped_lint": issues, "mapping_applied": mapped != body}


_TECH_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_SIGMA_ATTACK_TAG_RE = re.compile(r"^\s*-\s*['\"]?attack\.([A-Za-z0-9_.-]+)['\"]?\s*$", re.M)


def attack_lint(techniques=None, body: str = "", platform: str = "") -> list[str]:
    """ATT&CK tag check (spec 8.5): the query's `techniques` and, for Sigma, its `attack.*` tags must exist in the
    ATT&CK catalog (app.attack, bundled or synced). Sigma tactic tags (attack.execution, attack.initial_access) must name
    a real tactic; group/software tags (attack.g0016, attack.s0002) are accepted as-is."""
    from . import attack

    issues: list[str] = []
    seen: set[str] = set()

    def check(tid: str, where: str):
        t = tid.strip().upper()
        if t in seen:
            return
        seen.add(t)
        if not _TECH_ID_RE.match(t):
            issues.append(f"Malformed ATT&CK technique id '{tid}'{where}")
        elif not attack.valid_technique(t):
            issues.append(f"Unknown ATT&CK technique {t}{where} (not in the ATT&CK catalog)")

    for tid in techniques or []:
        check(str(tid), "")
    if platform == "sigma" and body:
        tactics = {t["shortname"].replace("-", "_") for t in attack.TACTICS}
        for tag in _SIGMA_ATTACK_TAG_RE.findall(body):
            low = tag.lower()
            if re.match(r"^t\d", low):
                check(tag, " in Sigma tags")
            elif re.match(r"^[gs]\d{4}$", low):
                continue
            elif low.replace("-", "_") not in tactics:
                issues.append(f"Unknown ATT&CK tactic tag 'attack.{tag}' in Sigma tags")
    return issues


def lint(platform: str, body: str, techniques=None) -> list[str]:
    """Cheap syntax checks per platform plus the ATT&CK tag check. Returns a list of problems (empty = passed)."""
    issues: list[str] = []
    b = body.strip()
    if not b:
        return ["Query is empty"]
    issues += attack_lint(techniques, b, platform)
    stripped = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`[^`]*`|/(?:\\.|[^/\n])+/[a-z]*', "", b)
    for o, c in ("()", "[]", "{}"):
        if stripped.count(o) != stripped.count(c):
            issues.append(f"Unbalanced {o}{c}")
    if re.sub(r"\\.", "", b).count('"') % 2:
        issues.append("Unbalanced double quotes")
    if platform in ("kql_sentinel", "kql_defender"):
        if not re.match(r"^(let\s|union\s|[A-Z][A-Za-z0-9_]+)", b):
            issues.append("KQL should start with a table name, let or union")
        if re.search(r"\bindex\s*=", b):
            issues.append("SPL syntax (index=) in a KQL query")
        if re.search(r"\|\s*stats\s", b):
            issues.append("Use summarize instead of stats in KQL")
    elif platform == "spl":
        if re.search(r"\|\s*where\s+\w+\s*=~", b):
            issues.append("=~ is KQL syntax; use like() or match() in SPL")
        if re.search(r"\|\s*project\s", b):
            issues.append("project is KQL; use table or fields in SPL")
    elif platform == "cql":
        if re.search(r"\|\s*where\s", b, re.I):
            issues.append("CQL filters are bare field=value expressions, not 'where'")
        if re.search(r"\bindex\s*=", b):
            issues.append("SPL syntax (index=) in a CQL query")
    elif platform == "xql":
        if "dataset" not in b and "preset" not in b:
            issues.append("XQL query should select a dataset or preset")
    elif platform == "esql":
        if not re.match(r"^(FROM|ROW|SHOW)\s", b, re.I):
            issues.append("ES|QL must start with FROM")
    elif platform == "yaral":
        if not re.search(r"\brule\s+\w+\s*\{", b) or "condition:" not in b:
            issues.append("YARA-L rule needs 'rule name {', events and condition sections")
    elif platform == "aql":
        if not re.match(r"^SELECT\s", b, re.I):
            issues.append("AQL must start with SELECT")
    elif platform == "sigma":
        for key in ("title:", "logsource:", "detection:", "condition:"):
            if key not in b:
                issues.append(f"Sigma rule missing '{key}'")
    return issues

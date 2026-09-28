"""Demo data: three client workspaces, four users and the ToolShell dry-run record (spec section 4).

The ToolShell indicators are the publicly reported ones; OSINT reputation is left
empty (add API keys and re-enrich). Evidence quotes are short paraphrases for the
demo and must be checked against the linked articles before any client use.
Additional records are tagged "sample" and contain no indicators.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from . import attack, detection
from .ioc import defang
from .models import ActivityEvent, ExportLog, Research, Result, Run, User, Workspace
from .pipeline.stages import _finish_mitre, generate_queries, select_opportunities, workspace_platforms
from .records import applicability, coverage_gaps, log_activity, save_record

NOW = datetime.now(timezone.utc)


def _d(days_ago: float, hour: int = 9, minute: int = 0) -> datetime:
    return (NOW - timedelta(days=days_ago)).replace(hour=hour, minute=minute, second=0, microsecond=0)


USERS = [
    {"id": "averma", "name": "A. Verma", "email": "a.verma@threatlens.local", "role": "hunter", "initials": "AV"},
    {"id": "riyer", "name": "R. Iyer", "email": "r.iyer@threatlens.local", "role": "reviewer", "initials": "RI"},
    {"id": "skapoor", "name": "S. Kapoor", "email": "s.kapoor@threatlens.local", "role": "lead", "initials": "SK"},
    {"id": "jchen", "name": "J. Chen", "email": "j.chen@threatlens.local", "role": "hunter", "initials": "JC"},
]

WORKSPACES = [
    {"id": "acme", "name": "Acme Bank", "industry": "Banking", "color": "#5249A8", "platforms": ["spl", "cql", "sigma"],
     "log_sources": ["process_creation", "file_event", "network", "dns", "file_hash", "scheduled_task"],
     "products": ["Microsoft 365 (SharePoint Online)", "Citrix NetScaler ADC", "Windows Server 2022", "CrowdStrike Falcon"],
     "field_mappings": {"spl": {"index=endpoint": "index=acme_edr", "index=web": "index=acme_web"}},
     "branding": {"primary": "#5249A8", "disclaimer": "Prepared for Acme Bank. Handle according to the TLP marking."}, "default_tlp": "AMBER"},
    {"id": "northwind", "name": "Northwind Health", "industry": "Healthcare", "color": "#2F8580",
     "platforms": ["kql_defender", "sigma"],
     "log_sources": ["process_creation", "file_event", "network", "dns", "file_hash", "vuln_mgmt", "registry"],
     "products": ["SharePoint Server 2019", "Exchange Server 2019", "Microsoft Defender for Endpoint", "Epic EHR"],
     "field_mappings": {}, "branding": {"primary": "#2F8580", "disclaimer": "Northwind Health — internal security use only."},
     "default_tlp": "AMBER"},
    {"id": "contoso", "name": "Contoso Energy", "industry": "Energy", "color": "#B8790F", "platforms": ["spl", "sigma"],
     "log_sources": ["process_creation", "file_event", "network", "dns", "web"],
     "products": ["SharePoint Server Subscription Edition", "SentinelOne Singularity", "Fortinet FortiGate"],
     "field_mappings": {"spl": {"index=endpoint": "index=contoso_sysmon", "index=web": "index=contoso_iis"}},
     "branding": {"primary": "#B8790F", "disclaimer": "Contoso Energy — TLP applies."}, "default_tlp": "AMBER"},
]

S = {
    "S1": {"url": "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/",
           "publisher": "Microsoft Threat Intelligence", "title": "Disrupting active exploitation of on-premises SharePoint vulnerabilities",
           "published": "2025-07-22", "last_modified": "2025-07-29", "reliability": "B", "credibility": 2, "type": "Vendor TI blog",
           "summary": "Attribution to Linen Typhoon, Violet Typhoon and Storm-2603; the full Storm-2603 chain from web shell to Warlock "
                      "ransomware; about 20 ATT&CK techniques, indicators, KQL/ASIM hunting queries and patch KBs.",
           "counts": {"claims": 12, "techniques": 20, "iocs": 32, "queries": 10}},
    "S2": {"url": "https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/",
           "publisher": "Palo Alto Unit 42", "title": "Active Exploitation of Microsoft SharePoint Vulnerabilities: Threat Brief",
           "published": "2025-07-31", "last_modified": "2025-09-18", "reliability": "B", "credibility": 2, "type": "Threat brief",
           "summary": "CVSS table for the four CVEs, reconnaissance with python-requests through SPN exit nodes, overlap between "
                      "CL-CRI-1040 and Storm-2603 (raised from moderate to high), 4L4MD4R ransomware and Cortex XQL queries.",
           "counts": {"claims": 9, "techniques": 11, "iocs": 31, "queries": 3}},
    "S3": {"url": "https://research.eye.security/sharepoint-under-siege/", "publisher": "Eye Security",
           "title": "SharePoint Under Siege: ToolShell Exploit", "published": "2025-07-19", "last_modified": "2025-10-25",
           "reliability": "B", "credibility": 2, "type": "First-responder research",
           "summary": "First in-the-wild detection; IIS log lines, the ToolPane.aspx POST with a SignOut.aspx Referer, MachineKey "
                      "theft leading to ViewState RCE, dated attack waves and hunting queries for CrowdStrike, MDE and SentinelOne.",
           "counts": {"claims": 10, "techniques": 7, "iocs": 12, "queries": 3}},
    "S4": {"url": "https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/",
           "publisher": "Check Point Research", "title": "Before ToolShell: Exploring Storm-2603's Previous Ransomware Operations",
           "published": "2025-07-31", "last_modified": "2025-07-31", "reliability": "B", "credibility": 3, "type": "Actor deep-dive",
           "summary": "Storm-2603 history: the AK47 C2 framework (HTTP and DNS clients), a BYOVD antivirus killer, LockBit Black and "
                      "Warlock deployments, LATAM and APAC targeting. Page renders with JavaScript (headless fetch needed).",
           "counts": {"claims": 7, "techniques": 6, "iocs": 14, "queries": 0}},
    "S5": {"url": "https://www.cisa.gov/news-events/alerts/2025/07/20/update-microsoft-releases-guidance-exploitation-sharepoint-vulnerabilities",
           "publisher": "CISA", "title": "UPDATE: Microsoft Releases Guidance on Exploitation of SharePoint Vulnerabilities",
           "published": "2025-07-20", "last_modified": "2025-08-06", "reliability": "A", "credibility": 2, "type": "Government advisory",
           "summary": "KEV dates, rotate-patch-rotate guidance, applicationHost.config persistence warning, .dll payloads and "
                      "monitoring recommendations.",
           "counts": {"claims": 8, "techniques": 5, "iocs": 10, "queries": 0}},
}

MITRE_ROWS = [
    ("T1595.002", "TA0043", "Scanning for vulnerable SharePoint servers with python-requests via commercial VPN exit nodes.", "reconnaissance traffic used the python-requests user agent", ["S2"], "moderate"),
    ("T1190", "TA0001", "Unauthenticated POST to /_layouts/15/ToolPane.aspx with a SignOut.aspx Referer bypasses authentication.", "a crafted POST to ToolPane.aspx with the Referer set to SignOut.aspx", ["S1", "S2", "S3", "S5"], "high"),
    ("T1059.001", "TA0002", "IIS worker launches cmd.exe which runs Base64-encoded PowerShell.", "w3wp.exe spawning cmd.exe and encoded PowerShell", ["S1", "S3"], "high"),
    ("T1059.003", "TA0002", "cmd.exe used by the web shell and by batch scripts during hands-on-keyboard activity.", "cmd.exe launched by the IIS worker process", ["S1"], "high"),
    ("T1047", "TA0002", "Impacket WMI execution for remote commands.", "Impacket used for remote execution through WMI", ["S1"], "moderate"),
    ("T1569.002", "TA0002", "PsExec used to run commands on remote hosts.", "PsExec used to execute commands remotely", ["S1"], "moderate"),
    ("T1505.003", "TA0003", "spinstall0.aspx written to the LAYOUTS folder as a key-stealing web shell.", "uploading a malicious script named spinstall0.aspx", ["S1", "S2", "S3"], "high"),
    ("T1505.004", "TA0003", "Malicious IIS modules registered in applicationHost.config for persistence.", "malicious IIS modules loaded via applicationHost.config", ["S1", "S5"], "moderate"),
    ("T1053.005", "TA0003", "Scheduled tasks created for persistence and payload execution.", "scheduled tasks created for persistence", ["S1"], "moderate"),
    ("T1484.001", "TA0004", "Group Policy modified to distribute Warlock ransomware.", "Group Policy used to distribute the ransomware", ["S1"], "high"),
    ("T1562.001", "TA0005", "Microsoft Defender protections disabled through registry changes; BYOVD AV killer in earlier operations.", "tampering with Microsoft Defender protections", ["S1", "S4"], "high"),
    ("T1112", "TA0005", "Registry edits to weaken Defender and enable follow-on tooling.", "modifying registry settings to disable protections", ["S1"], "moderate"),
    ("T1027", "TA0005", "Base64-encoded PowerShell and packed .NET payloads.", "encoded PowerShell commands", ["S1", "S3"], "moderate"),
    ("T1552", "TA0006", "spinstall0.aspx reads the ASP.NET MachineKey (ValidationKey, DecryptionKey).", "the script extracts the MachineKey configuration", ["S1", "S3", "S5"], "high"),
    ("T1003.001", "TA0006", "Mimikatz used against LSASS to harvest credentials.", "Mimikatz used to target LSASS memory", ["S1"], "high"),
    ("T1033", "TA0007", "whoami and similar commands run through the web shell.", "discovery commands such as whoami", ["S1"], "moderate"),
    ("T1021.002", "TA0008", "Lateral movement using admin shares with PsExec and Impacket.", "lateral movement using PsExec and Impacket", ["S1"], "moderate"),
    ("T1570", "TA0008", "Tools copied between hosts ahead of ransomware deployment.", "tools staged on additional hosts", ["S1"], "low"),
    ("T1071.001", "TA0011", "AK47HTTP backdoor communicates over HTTP.", "the AK47 C2 framework includes HTTP and DNS clients", ["S4"], "moderate"),
    ("T1090", "TA0011", "fast reverse proxy (xd.exe) tunnels access to internal hosts.", "fast reverse proxy used for tunnelling", ["S1"], "moderate"),
    ("T1486", "TA0040", "Warlock and LockBit Black ransomware encrypt files across the domain.", "deploying Warlock ransomware", ["S1", "S2", "S4"], "high"),
]

OPPORTUNITIES = [
    {"behaviour_ref": "AP-1.1", "title": "ToolPane.aspx POST with SignOut.aspx Referer", "type": "ioa", "techniques": ["T1190"],
     "logic": "Exploit request: POST to ToolPane.aspx whose Referer is the SharePoint sign-out page.",
     "fp_notes": "No legitimate workflow posts to ToolPane.aspx from the sign-out page.",
     "spec": {"category": "web", "conditions": [
         {"field": "http_method", "op": "equals", "values": ["POST"]},
         {"field": "url_path", "op": "endswith", "values": ["/ToolPane.aspx"]},
         {"field": "referer", "op": "endswith", "values": ["/_layouts/SignOut.aspx"]}]}},
    {"behaviour_ref": "AP-1.2", "title": "IIS worker spawns a shell that runs encoded PowerShell", "type": "ioa", "techniques": ["T1505.003", "T1059.001"],
     "logic": "w3wp.exe → cmd.exe → powershell.exe with -EncodedCommand.",
     "fp_notes": "Rare on SharePoint; check admin scripts run through IIS.",
     "spec": {"category": "process_creation", "conditions": [
         {"field": "grandparent_image", "op": "endswith", "values": ["\\w3wp.exe"]},
         {"field": "parent_image", "op": "endswith", "values": ["\\cmd.exe"]},
         {"field": "image", "op": "endswith", "values": ["\\powershell.exe", "\\pwsh.exe"]},
         {"field": "command_line", "op": "contains", "values": ["-enc", "-ec ", "-EncodedCommand"]}]}},
    {"behaviour_ref": "AP-1.2", "title": "New .aspx file in SharePoint LAYOUTS", "type": "ioa", "techniques": ["T1505.003"],
     "logic": ".aspx written under TEMPLATE\\LAYOUTS outside a patch window.",
     "fp_notes": "SharePoint updates write here; correlate with patch windows.",
     "spec": {"category": "file_event", "conditions": [
         {"field": "target_filename", "op": "contains", "values": ["\\TEMPLATE\\LAYOUTS\\"]},
         {"field": "target_filename", "op": "endswith", "values": [".aspx"]}]}},
    {"behaviour_ref": "AP-1.3", "title": "Request to the spinstall key-dumper page", "type": "ioa", "techniques": ["T1552"],
     "logic": "GET to spinstall*.aspx returns ValidationKey|DecryptionKey.",
     "fp_notes": "None expected; any hit is an incident.",
     "spec": {"category": "web", "conditions": [
         {"field": "url_path", "op": "contains", "values": ["/_layouts/15/spinstall", "/_layouts/16/spinstall"]}]}},
    {"behaviour_ref": "AP-2.3", "title": "Defender protections disabled from the command line", "type": "ioa", "techniques": ["T1562.001"],
     "logic": "Set-MpPreference or registry changes that switch off real-time protection.",
     "fp_notes": "Troubleshooting by the endpoint team; confirm with change records.",
     "spec": {"category": "process_creation", "conditions": [
         {"field": "command_line", "op": "contains", "values": ["DisableRealtimeMonitoring", "Set-MpPreference -Disable", "DisableAntiSpyware"]}]}},
    {"behaviour_ref": "AP-2.4", "title": "Remote execution through Impacket WMI", "type": "ioa", "techniques": ["T1047"],
     "logic": "wmiprvse.exe spawning cmd.exe with output redirected to ADMIN$ (wmiexec pattern).",
     "fp_notes": "Inventory tools use WMI; the \\\\127.0.0.1\\ADMIN$ redirect is Impacket-specific.",
     "spec": {"category": "process_creation", "conditions": [
         {"field": "parent_image", "op": "endswith", "values": ["\\wmiprvse.exe"]},
         {"field": "command_line", "op": "contains", "values": ["\\\\127.0.0.1\\ADMIN$\\__"]}]}},
    {"behaviour_ref": "AP-2.6", "title": "Group Policy scheduled task pushes a payload", "type": "ioa", "techniques": ["T1484.001"],
     "logic": "ScheduledTasks.xml or scripts written into SYSVOL policy folders.",
     "fp_notes": "Domain admins edit GPOs; correlate with change tickets.",
     "spec": {"category": "file_event", "conditions": [
         {"field": "target_filename", "op": "contains", "values": ["\\SYSVOL\\"]},
         {"field": "target_filename", "op": "endswith", "values": ["ScheduledTasks.xml", ".bat", ".ps1"]}]}},
    {"behaviour_ref": "AP-3.3", "title": "fast reverse proxy client on a server", "type": "ioa", "techniques": ["T1090"],
     "logic": "xd.exe (frp) or frpc configuration on SharePoint or domain servers.",
     "fp_notes": "Not expected on servers.",
     "spec": {"category": "process_creation", "conditions": [
         {"field": "image", "op": "endswith", "values": ["\\xd.exe", "\\frpc.exe"]}]}},
]

IOCS = [
    ("ipv4", "107.191.58.76", "Exploitation source, first wave (18 Jul)", ["S1", "S3"]),
    ("ipv4", "104.238.159.149", "Exploitation source, second wave (19 Jul)", ["S1", "S2", "S3", "S5"]),
    ("ipv4", "96.9.125.147", "Exploitation source", ["S1", "S3"]),
    ("ipv4", "131.226.2.6", "Post-exploitation C2 / exploitation source", ["S1", "S2"]),
    ("ipv4", "134.199.202.205", "Exploitation source", ["S1", "S2"]),
    ("ipv4", "188.130.206.168", "Exploitation source", ["S1", "S2"]),
    ("ipv4", "65.38.121.198", "Storm-2603 C2", ["S1"]),
    ("domain", "c34718cbb4c6.ngrok-free.app", "Storm-2603 C2 used to deliver PowerShell", ["S1"]),
    ("domain", "update.updatemicfosoft.com", "Storm-2603 C2 (typosquat)", ["S1", "S4"]),
    ("sha256", "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514", "spinstall0.aspx MachineKey dumper", ["S1", "S2", "S3", "S5"]),
    ("file_name", "spinstall0.aspx", "Web shell that dumps the ASP.NET MachineKey", ["S1", "S2", "S3", "S5"]),
    ("file_name", "spinstall.aspx", "Web shell variant", ["S1", "S2"]),
    ("file_name", "spinstall1.aspx", "Web shell variant", ["S1", "S2"]),
    ("file_name", "debug_dev.js", "Dropped script containing MachineKey data", ["S1", "S5"]),
    ("file_name", "xd.exe", "fast reverse proxy client", ["S1"]),
    ("file_name", "IIS_Server_dll.dll", "Malicious IIS module (.NET backdoor)", ["S1", "S5"]),
    ("file_path", "C:\\PROGRA~1\\COMMON~1\\MICROS~1\\WEBSER~1\\16\\TEMPLATE\\LAYOUTS\\spinstall0.aspx", "Web shell location", ["S1", "S3"]),
]


VULNERABILITIES = [
    {"cve": "CVE-2025-53770", "cvss": 9.8, "epss": None, "kev_added": "2025-07-20", "description": "Deserialization of untrusted data (ToolShell); variant of CVE-2025-49704.",
     "affected_products": ["SharePoint Server 2016", "SharePoint Server 2019", "SharePoint Server Subscription Edition"],
     "fixed_versions": ["July 2025 security updates"], "patch_kb": ["KB5002768", "KB5002754", "KB5002760"], "source_ids": ["S1", "S2", "S5"]},
    {"cve": "CVE-2025-53771", "cvss": 6.5, "epss": None, "kev_added": "2025-07-22", "description": "Spoofing / path traversal; bypass of CVE-2025-49706.",
     "affected_products": ["SharePoint Server 2016", "SharePoint Server 2019", "SharePoint Server Subscription Edition"],
     "fixed_versions": ["July 2025 security updates"], "patch_kb": ["KB5002768", "KB5002754", "KB5002760"], "source_ids": ["S1", "S2"]},
    {"cve": "CVE-2025-49704", "cvss": 8.8, "epss": None, "kev_added": "2025-07-22", "description": "Code injection leading to remote code execution.",
     "affected_products": ["SharePoint Server 2016", "SharePoint Server 2019", "SharePoint Server Subscription Edition"],
     "fixed_versions": ["July 2025 Patch Tuesday"], "patch_kb": [], "source_ids": ["S2", "S3", "S5"]},
    {"cve": "CVE-2025-49706", "cvss": 6.5, "epss": None, "kev_added": "2025-07-22", "description": "Improper authentication (spoofing) via the Referer header.",
     "affected_products": ["SharePoint Server 2016", "SharePoint Server 2019", "SharePoint Server Subscription Edition"],
     "fixed_versions": ["July 2025 Patch Tuesday"], "patch_kb": [], "source_ids": ["S2", "S3", "S5"]},
]

ATTACK_PATHS = [
    {"id": "AP-1", "name": "Exploit → MachineKey theft → ViewState RCE", "steps": [
        {"ref": "AP-1.1", "behaviour": "POST /_layouts/15/ToolPane.aspx with Referer /_layouts/SignOut.aspx", "technique_id": "T1190", "source_ids": ["S1", "S3"]},
        {"ref": "AP-1.2", "behaviour": "w3wp.exe → cmd.exe → powershell -EncodedCommand writes spinstall0.aspx", "technique_id": "T1505.003", "source_ids": ["S1", "S3"]},
        {"ref": "AP-1.3", "behaviour": "GET spinstall0.aspx returns ValidationKey|DecryptionKey", "technique_id": "T1552", "source_ids": ["S1", "S3"]},
        {"ref": "AP-1.4", "behaviour": "Forged __VIEWSTATE payloads run code as the IIS worker", "technique_id": "T1059.001", "source_ids": ["S3"]}]},
    {"id": "AP-2", "name": "Web shell → hands-on-keyboard → Warlock via GPO", "steps": [
        {"ref": "AP-2.1", "behaviour": "whoami and host discovery through the web shell", "technique_id": "T1033", "source_ids": ["S1"]},
        {"ref": "AP-2.2", "behaviour": "Scheduled tasks and IIS modules for persistence", "technique_id": "T1053.005", "source_ids": ["S1"]},
        {"ref": "AP-2.3", "behaviour": "Defender disabled through registry changes", "technique_id": "T1562.001", "source_ids": ["S1"]},
        {"ref": "AP-2.4", "behaviour": "Impacket and PsExec for remote execution", "technique_id": "T1047", "source_ids": ["S1"]},
        {"ref": "AP-2.5", "behaviour": "Mimikatz dumps LSASS credentials", "technique_id": "T1003.001", "source_ids": ["S1"]},
        {"ref": "AP-2.6", "behaviour": "Group Policy pushes Warlock ransomware domain-wide", "technique_id": "T1484.001", "source_ids": ["S1"]},
        {"ref": "AP-2.7", "behaviour": "Files encrypted with Warlock / LockBit Black", "technique_id": "T1486", "source_ids": ["S1", "S4"]}]},
    {"id": "AP-3", "name": ".NET module in-memory payloads", "steps": [
        {"ref": "AP-3.1", "behaviour": "IIS_Server_dll.dll registered as an IIS module", "technique_id": "T1505.004", "source_ids": ["S1", "S5"]},
        {"ref": "AP-3.2", "behaviour": "AK47HTTP beacons over HTTP", "technique_id": "T1071.001", "source_ids": ["S4"]},
        {"ref": "AP-3.3", "behaviour": "fast reverse proxy (xd.exe) tunnels internal access", "technique_id": "T1090", "source_ids": ["S1"]}]},
]


def _toolshell_record(db: Session, research_id: str, workspace_ids: list[str]) -> dict:
    mitre, _ = _finish_mitre(None, [
        {"technique_id": t, "tactic_id": ta, "procedure": p, "evidence_quote": q, "source_ids": s, "confidence": c}
        for t, ta, p, q, s, c in MITRE_ROWS])
    # Same selection as the pipeline: de-duplicated, best 1-2 per attack-path step, source trail from the step.
    opps = select_opportunities([dict(o) for o in OPPORTUNITIES], ATTACK_PATHS, mitre)
    # Only the platforms the dry-run workspaces actually use (their defaults), Sigma as the neutral source of truth.
    platforms = workspace_platforms(db, workspace_ids)
    queries = generate_queries(
        db, opps, platforms, 30,
        {t: {v: s for tt, v, _, s in IOCS if tt == t} for t in ("ipv4", "domain", "sha256")},
        VULNERABILITIES,
        [m["technique_id"] for m in mitre], [], mitre=mitre, include_generic=False)
    for q in queries:
        if q["opportunity_id"] in ("DO-1", "DO-2", "DO-3") and q["status"] == "syntax_checked":
            q["status"] = "reviewed"
    for o in opps:
        o["queries"] = [q["id"] for q in queries if q.get("opportunity_id") == o["id"]]

    iocs = [{"type": t, "value": defang(v, t), "role": role, "context": role, "contexts": [], "source_ids": s,
             "reputation": {}, "reputation_summary": "", "verdict": "malicious" if t in ("ipv4", "domain", "sha256") or "shell" in role.lower() else "suspicious"}
            for t, v, role, s in IOCS]

    log_sources_required = []
    for q in queries:
        for cat in q.get("data_sources", []):
            row = {"data_source": cat, "label": detection.CATEGORIES.get(cat, cat), **detection.LOG_SOURCES.get(cat, {})}
            if row not in log_sources_required:
                log_sources_required.append(row)

    return {
        "title": "ToolShell: SharePoint on-prem RCE exploited for key theft and ransomware",
        "status": "published", "tlp": "AMBER", "classification": ["vulnerability_exploitation", "campaign"],
        "severity": "critical", "confidence": "high",
        "executive_summary": (
            "Unauthenticated attackers are chaining an authentication bypass and a deserialization flaw in on-premises "
            "SharePoint Server 2016, 2019 and Subscription Edition to run code as the IIS worker process. The first thing "
            "most intruders do is drop a small page, spinstall0.aspx, that reads the server's ASP.NET MachineKey. With that "
            "key they can forge signed requests and keep running code even after the server is patched.\n\n"
            "Microsoft attributes exploitation to two China-based espionage groups, Linen Typhoon and Violet Typhoon, and to "
            "Storm-2603, a financially motivated cluster that has gone on to deploy Warlock and LockBit Black ransomware "
            "through Group Policy. Palo Alto Unit 42 tracks overlapping activity as CL-CRI-1040 and now rates that overlap "
            "with Storm-2603 as high confidence.\n\n"
            "This matters because SharePoint servers often hold sensitive documents and sit close to identity "
            "infrastructure. Patching alone is not enough: organisations must rotate the MachineKey, restart IIS and hunt "
            "for web shells and malicious IIS modules. SharePoint Online in Microsoft 365 is not affected."),
        "impact": {"severity": "critical",
                   "business_impact": "Full compromise of on-prem SharePoint farms, theft of documents and credentials, and "
                                      "domain-wide ransomware deployment through Group Policy.",
                   "cia": {"confidentiality": True, "integrity": True, "availability": True},
                   "blast_radius": "Every internet-facing SharePoint 2016/2019/SE server, then the Active Directory domain it joins."},
        "patching_insufficient": True,
        "recommendations": [
            {"horizon": "immediate", "action": "Apply the July 2025 security updates for SharePoint 2016, 2019 and Subscription Edition (KB5002768, KB5002754, KB5002760).", "owner_role": "IT operations", "source_ids": ["S1", "S5"]},
            {"horizon": "immediate", "action": "Rotate the ASP.NET MachineKey on every farm server, then restart IIS; rotate again after patching.", "owner_role": "SharePoint admin", "source_ids": ["S1", "S3", "S5"]},
            {"horizon": "immediate", "action": "Disconnect internet-facing SharePoint servers that cannot be patched today.", "owner_role": "Network team", "source_ids": ["S5"]},
            {"horizon": "short_term", "action": "Enable AMSI in Full Mode on SharePoint and deploy Defender Antivirus on all farm servers.", "owner_role": "Endpoint team", "source_ids": ["S1", "S5"]},
            {"horizon": "short_term", "action": "Hunt for spinstall*.aspx, new .aspx files in LAYOUTS and unknown modules in applicationHost.config.", "owner_role": "Threat hunting", "source_ids": ["S1", "S3", "S5"]},
            {"horizon": "short_term", "action": "Ingest IIS W3C logs with Referer and User-Agent fields into the SIEM.", "owner_role": "Detection engineering", "source_ids": ["S3"]},
            {"horizon": "strategic", "action": "Move SharePoint behind an authenticating reverse proxy or retire on-prem farms in favour of SharePoint Online.", "owner_role": "Architecture", "source_ids": ["S1"]},
            {"horizon": "strategic", "action": "Alert on Group Policy changes that create scheduled tasks or startup scripts.", "owner_role": "Identity team", "source_ids": ["S1"]},
        ],
        "results": [], "mitre": mitre,
        "tools_used": [
            {"name": "ThreatLens pipeline agents", "category": "platform", "detail": "Manual dry run of every stage"},
            {"name": "MITRE ATT&CK", "category": "reference", "detail": "Technique validation"},
            {"name": "CISA KEV catalog", "category": "reference", "detail": "KEV dates"},
            {"name": "Headless browser fetch", "category": "platform", "detail": "Check Point page (JavaScript-rendered)"},
        ],
        "workflow": [
            {"step": "Intake", "actor": "hunter", "started_at": _d(2, 8, 0).isoformat(), "finished_at": _d(2, 8, 1).isoformat(), "notes": "Seed: CVE-2025-53770 headline"},
            {"step": "Source discovery", "actor": "agent", "started_at": _d(2, 8, 1).isoformat(), "finished_at": _d(2, 8, 2).isoformat(), "notes": "5 sources"},
            {"step": "Per-article extraction", "actor": "agent", "started_at": _d(2, 8, 2).isoformat(), "finished_at": _d(2, 8, 5).isoformat(), "notes": "5 of 5 read"},
            {"step": "Synthesis", "actor": "agent", "started_at": _d(2, 8, 5).isoformat(), "finished_at": _d(2, 8, 7).isoformat(), "notes": "3 attack paths"},
            {"step": "ATT&CK mapping", "actor": "agent", "started_at": _d(2, 8, 7).isoformat(), "finished_at": _d(2, 8, 8).isoformat(), "notes": "21 TTPs"},
            {"step": "Query generation", "actor": "agent", "started_at": _d(2, 8, 8).isoformat(), "finished_at": _d(2, 8, 9).isoformat(), "notes": f"{len(queries)} queries"},
            {"step": "Hunter review", "actor": "hunter", "started_at": _d(2, 8, 40).isoformat(), "finished_at": _d(0, 9, 14).isoformat(), "notes": "Published by R. Iyer"},
        ],
        "hunts": {"queries": queries, "ioc_queries": [q["id"] for q in queries if q["type"] == "ioc"],
                  "ioa_queries": [q["id"] for q in queries if q["type"] == "ioa"],
                  "vulnerability_queries": [q["id"] for q in queries if q["type"] == "vuln"],
                  "ttp_queries": [q["id"] for q in queries if q["type"] == "ttp"], "platforms": platforms, "lookback_days": 30},
        "industries": [{"industry": i, "evidence": "observed", "source_ids": ["S1", "S3"]} for i in ("Government", "Education", "Healthcare", "Energy")]
                      + [{"industry": "Financial services", "evidence": "assessed", "source_ids": ["S2"]}],
        "vulnerabilities": VULNERABILITIES,
        "threat_actors": [
            {"name": "Storm-2603", "aliases": ["CL-CRI-1040"], "origin": "China (moderate)", "motivation": ["financial"], "attribution_confidence": "high", "source_ids": ["S1", "S2", "S4"]},
            {"name": "Linen Typhoon", "aliases": ["APT27", "Emissary Panda"], "origin": "China", "motivation": ["espionage"], "attribution_confidence": "high", "source_ids": ["S1"]},
            {"name": "Violet Typhoon", "aliases": ["APT31", "Zirconium"], "origin": "China", "motivation": ["espionage"], "attribution_confidence": "high", "source_ids": ["S1"]},
        ],
        "malware_tools": [
            {"name": "spinstall0.aspx", "type": "webshell", "role": "Reads and returns the ASP.NET MachineKey", "source_ids": ["S1", "S3"]},
            {"name": "IIS_Server_dll.dll", "type": "malware", "role": "Malicious IIS module backdoor", "source_ids": ["S1", "S5"]},
            {"name": "AK47HTTP", "type": "malware", "role": "HTTP C2 client of the AK47 framework", "source_ids": ["S4"]},
            {"name": "AK47DNS", "type": "malware", "role": "DNS C2 client of the AK47 framework", "source_ids": ["S4"]},
            {"name": "Warlock", "type": "ransomware", "role": "Ransomware deployed via Group Policy", "source_ids": ["S1", "S4"]},
            {"name": "LockBit Black", "type": "ransomware", "role": "Ransomware in earlier Storm-2603 operations", "source_ids": ["S4"]},
            {"name": "4L4MD4R", "type": "ransomware", "role": "Ransomware variant linked to CL-CRI-1040", "source_ids": ["S2"]},
            {"name": "Mimikatz", "type": "tool", "role": "LSASS credential theft", "source_ids": ["S1"]},
            {"name": "PsExec", "type": "tool", "role": "Remote execution", "source_ids": ["S1"]},
            {"name": "Impacket", "type": "tool", "role": "Remote execution through WMI and SMB", "source_ids": ["S1"]},
            {"name": "SharpHostInfo", "type": "tool", "role": "Host discovery", "source_ids": ["S1"]},
            {"name": "fast reverse proxy (xd.exe)", "type": "tool", "role": "Tunnelling into the network", "source_ids": ["S1"]},
        ],
        "attack_paths": ATTACK_PATHS,
        "ioas": [
            {"id": "IOA-1", "description": "w3wp.exe → cmd.exe → powershell -EncodedCommand", "kind": "process_chain", "source_ids": ["S1", "S3"]},
            {"id": "IOA-2", "description": "POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit with Referer /_layouts/SignOut.aspx", "kind": "http_request", "source_ids": ["S3"]},
            {"id": "IOA-3", "description": ".aspx files written under TEMPLATE\\LAYOUTS", "kind": "file_write", "source_ids": ["S1", "S3"]},
            {"id": "IOA-4", "description": "New <add> module entries in applicationHost.config", "kind": "file_write", "source_ids": ["S5"]},
        ],
        "iocs": iocs, "detection_opportunities": opps, "log_sources_required": log_sources_required,
        "timeline": [
            {"date": "2025-07-08", "event": "Microsoft patches CVE-2025-49704 and CVE-2025-49706", "source_ids": ["S2"]},
            {"date": "2025-07-18", "event": "Eye Security detects the first in-the-wild exploitation wave", "source_ids": ["S3"]},
            {"date": "2025-07-19", "event": "Microsoft publishes CVE-2025-53770 / 53771 as a patch bypass", "source_ids": ["S1"]},
            {"date": "2025-07-20", "event": "CISA adds CVE-2025-53770 to the KEV catalog", "source_ids": ["S5"]},
            {"date": "2025-07-22", "event": "Microsoft attributes activity to Linen Typhoon, Violet Typhoon and Storm-2603", "source_ids": ["S1"]},
            {"date": "2025-07-29", "event": "Eye Security corrects the first waves to the patched 49706/49704 chain", "source_ids": ["S3"]},
            {"date": "2025-07-31", "event": "Check Point and Unit 42 link Storm-2603 to earlier ransomware operations", "source_ids": ["S2", "S4"]},
        ],
        "sources": [{"id": k, **v, "last_fetched": _d(2).date().isoformat(), "origin": "vendor_feed", "included": True, "status": "read",
                     "stale": k in ("S2", "S3")} for k, v in S.items()],
        "claims": [
            {"statement": "Exploitation began on 18 July 2025 against internet-facing SharePoint servers.", "source_ids": ["S3"], "status": "confirmed"},
            {"statement": "Storm-2603 deployed Warlock ransomware through Group Policy.", "source_ids": ["S1"], "status": "confirmed"},
            {"statement": "CL-CRI-1040 overlaps with Storm-2603 with high confidence.", "source_ids": ["S2"], "status": "confirmed"},
            {"statement": "Patching without rotating the MachineKey leaves stolen keys usable.", "source_ids": ["S1", "S3", "S5"], "status": "confirmed"},
            {"statement": "The 17–19 July waves exploited CVE-2025-53770 as a zero-day.", "source_ids": ["S3"], "status": "superseded"},
        ],
        "conflicts": [
            {"topic": "Which CVE the first waves exploited", "status": "superseded",
             "resolution": "Later statement accepted: the waves used the already-patched CVE-2025-49706/49704 chain.",
             "statements": [
                 {"text": "First waves exploited CVE-2025-53770 as a zero-day.", "source_id": "S3", "date": "2025-07-19"},
                 {"text": "Waves used the patched CVE-2025-49706/49704 chain.", "source_id": "S3", "date": "2025-07-29"},
                 {"text": "Exploitation of CVE-2025-49704 and 49706 confirmed; 53770 is a variant.", "source_id": "S5", "date": "2025-07-22"}]},
            {"topic": "Confidence of the CL-CRI-1040 ↔ Storm-2603 overlap", "status": "superseded",
             "resolution": "Unit 42 raised its assessment from moderate to high.",
             "statements": [
                 {"text": "Overlap with Storm-2603 assessed with moderate confidence.", "source_id": "S2", "date": "2025-07-31"},
                 {"text": "Overlap with Storm-2603 assessed with high confidence.", "source_id": "S2", "date": "2025-09-18"}]},
        ],
        "geography": ["North America", "Europe", "LATAM", "APAC"],
        "study": {
            "background": "SharePoint Server is Microsoft's on-premises collaboration platform. In July 2025 Microsoft patched two "
                          "flaws (CVE-2025-49704, CVE-2025-49706). Within days, attackers were exploiting a bypass of those fixes, "
                          "published as CVE-2025-53770 and CVE-2025-53771 and nicknamed ToolShell.",
            "how_it_works": "An unauthenticated POST to /_layouts/15/ToolPane.aspx with the Referer set to /_layouts/SignOut.aspx "
                            "skips authentication (49706/53771). The request carries a serialized payload that SharePoint "
                            "deserializes, running attacker code as w3wp.exe (49704/53770). The first payload typically writes "
                            "spinstall0.aspx, whose only job is to print the farm's MachineKey. With the ValidationKey and "
                            "DecryptionKey, an attacker can forge signed __VIEWSTATE payloads and run code at will, even after "
                            "patching, until the keys are rotated.",
            "kill_chain_narrative": "Espionage groups (Linen Typhoon, Violet Typhoon) used access for data theft. Storm-2603 went "
                                    "further: encoded PowerShell from the web shell, discovery with whoami, persistence through "
                                    "scheduled tasks and IIS modules, Defender disabled via the registry, credentials from LSASS "
                                    "with Mimikatz, lateral movement with Impacket and PsExec, and finally Warlock ransomware "
                                    "pushed to every machine through Group Policy.",
            "remember": [
                "Patching is not remediation: rotate the MachineKey and restart IIS, then rotate again after patching.",
                "The exploit request has a unique shape: POST ToolPane.aspx with a SignOut.aspx Referer. Hunt IIS logs for it.",
                "w3wp.exe spawning cmd.exe and encoded PowerShell is the most durable detection.",
                "Check applicationHost.config for unknown modules; CISA warns they survive web shell cleanup.",
                "SharePoint Online is not affected; only 2016, 2019 and Subscription Edition on-prem.",
            ]},
        "tags": ["sharepoint", "toolshell", "ransomware", "dry-run"],
        "related_research_ids": [],
        "affected_technologies": ["SharePoint Server 2016", "SharePoint Server 2019", "SharePoint Server Subscription Edition"],
        "run": {"id": None, "mode": "manual", "tokens": 0},
        "review": {k: "approved" for k in ("executive_summary", "impact", "recommendations", "mitre", "hunts", "iocs", "study", "attack_paths")},
        "_edited": [],
        "demo_note": "Dry-run record from the MVP spec. Indicators are as publicly reported; evidence quotes are paraphrased and "
                     "OSINT reputation is not yet enriched. Verify against the linked articles before client use.",
    }


SAMPLES = [
    {"days": 5, "status": "in_review", "severity": "high", "tlp": "AMBER", "author": "jchen", "ws": ["acme", "northwind", "contoso"],
     "title": "Citrix Bleed 2: NetScaler memory overread exposes session tokens (CVE-2025-5777)",
     "classification": ["vulnerability_exploitation"], "cves": [("CVE-2025-5777", 9.3, ["Citrix NetScaler ADC", "Citrix NetScaler Gateway"])],
     "actors": [], "techs": [("T1190", "TA0001"), ("T1539", "TA0006"), ("T1078", "TA0001"), ("T1133", "TA0001")],
     "summary": "An out-of-bounds read in NetScaler ADC and Gateway configured as a gateway or AAA virtual server lets unauthenticated "
                "attackers read memory, including session tokens, and hijack authenticated sessions. Patching must be followed by "
                "terminating all active ICA and PCoIP sessions."},
    {"days": 12, "status": "published", "severity": "high", "tlp": "GREEN", "author": "averma", "ws": ["acme"],
     "title": "Scattered Spider: help-desk social engineering against retail and insurance",
     "classification": ["actor_profile", "campaign"], "cves": [],
     "actors": [("Scattered Spider", ["UNC3944", "Octo Tempest"], "Western Europe / North America", ["financial"])],
     "techs": [("T1566.004", "TA0001"), ("T1078", "TA0001"), ("T1621", "TA0006"), ("T1219", "TA0011"), ("T1486", "TA0040"), ("T1098", "TA0003")],
     "summary": "The group phones IT help desks posing as employees to reset passwords and MFA, then uses remote-access tools and "
                "cloud identity access to deploy ransomware. Verification of caller identity before resets is the key control."},
    {"days": 26, "status": "published", "severity": "medium", "tlp": "CLEAR", "author": "averma", "ws": ["northwind"],
     "title": "Encoded PowerShell from Office processes: TTP trend review",
     "classification": ["ttp_trend"], "cves": [], "actors": [],
     "techs": [("T1566.001", "TA0001"), ("T1204.002", "TA0002"), ("T1059.001", "TA0002"), ("T1027", "TA0005")],
     "summary": "Office applications spawning PowerShell with encoded commands remain a common first-stage pattern. This review "
                "consolidates hunts across clients and the tuning notes from the last quarter."},
    {"days": 41, "status": "archived", "severity": "low", "tlp": "GREEN", "author": "jchen", "ws": ["contoso"],
     "title": "Legacy RDP exposure review for OT jump hosts",
     "classification": ["ttp_trend"], "cves": [], "actors": [], "techs": [("T1133", "TA0001"), ("T1021.001", "TA0008"), ("T1110.003", "TA0006")],
     "summary": "Review of internet-exposed RDP on operational-technology jump hosts and password-spraying attempts against them."},
    {"days": 1, "status": "draft", "severity": "medium", "tlp": "AMBER", "author": "averma", "ws": ["northwind"],
     "title": "Suspicious OAuth consent grants in Microsoft 365 tenants",
     "classification": ["ttp_trend"], "cves": [], "actors": [], "techs": [("T1528", "TA0006"), ("T1098", "TA0003")],
     "summary": "Draft review of illicit consent-grant activity: third-party apps requesting mail and file scopes shortly after "
                "phishing lures."},
]


def _sample_record(s: dict) -> dict:
    mitre, _ = _finish_mitre(None, [{"technique_id": t, "tactic_id": ta, "procedure": "", "evidence_quote": "", "source_ids": [],
                                     "confidence": "moderate"} for t, ta in s["techs"]])
    return {
        "title": s["title"], "status": s["status"], "tlp": s["tlp"], "classification": s["classification"], "severity": s["severity"],
        "confidence": "moderate", "executive_summary": s["summary"],
        "impact": {"severity": s["severity"], "business_impact": "", "cia": {"confidentiality": True, "integrity": False, "availability": False}, "blast_radius": ""},
        "patching_insufficient": False, "recommendations": [], "results": [], "mitre": mitre, "tools_used": [], "workflow": [],
        "hunts": {"queries": [], "ioc_queries": [], "ioa_queries": [], "vulnerability_queries": [], "ttp_queries": [], "platforms": [], "lookback_days": 30},
        "industries": [], "vulnerabilities": [{"cve": c, "cvss": sc, "epss": None, "kev_added": None, "affected_products": p, "fixed_versions": [], "patch_kb": [], "source_ids": []}
                                              for c, sc, p in s["cves"]],
        "threat_actors": [{"name": n, "aliases": al, "origin": o, "motivation": mo, "attribution_confidence": "moderate", "source_ids": []}
                          for n, al, o, mo in s["actors"]],
        "malware_tools": [], "attack_paths": [], "ioas": [], "iocs": [], "detection_opportunities": [], "log_sources_required": [],
        "timeline": [], "sources": [], "claims": [], "conflicts": [], "geography": [], "study": {"background": s["summary"], "how_it_works": "", "kill_chain_narrative": "", "remember": []},
        "tags": ["sample"], "related_research_ids": [], "affected_technologies": [p for _, _, ps in s["cves"] for p in ps],
        "review": {}, "_edited": [], "demo_note": "Sample record for demonstration; not full research.",
    }


def seed(db: Session) -> bool:
    if db.query(User).count():
        return False
    for u in USERS:
        db.add(User(**u))
    for w in WORKSPACES:
        db.add(Workspace(**w))
    db.flush()
    attack.load_catalog(db)

    # ToolShell
    r = Research(id="TR-2026-0142", title="ToolShell", status="published", created_by="averma", reviewed_by="riyer",
                 created_at=_d(2, 8, 0), published_at=_d(0, 9, 14), workspace_ids=["acme", "northwind", "contoso"],
                 seed="CVE-2025-53770 SharePoint ToolShell actively exploited — Microsoft, Unit 42, Eye Security, Check Point, CISA", tlp="AMBER")
    db.add(r)
    db.flush()
    from .models import Counter
    db.merge(Counter(name=f"research-{NOW.year}", value=142))
    rec = _toolshell_record(db, r.id, r.workspace_ids)
    ws_rows = {w.id: w for w in db.query(Workspace).all()}
    rec["applicability"] = [applicability(rec, ws_rows[w]) for w in r.workspace_ids]
    rec["coverage_gaps"] = [g for w in r.workspace_ids for g in coverage_gaps(rec, ws_rows[w])]
    save_record(db, r, rec, "averma", "Run completed", bump=False)
    r.version = 3
    r.record = {**r.record, "version": 3}
    results = [
        Result(research_id=r.id, workspace_id="acme", status="not_applicable", summary="No on-prem SharePoint in scope (SharePoint Online only).",
               hunt_window="", analyst_id="averma", updated_at=_d(1, 11)),
        Result(research_id=r.id, workspace_id="northwind", status="no_evidence", summary="SharePoint 2019 farm patched 21 Jul; MachineKey rotated. No hits for IoCs or IoA queries.",
               hunt_window="2025-07-01 – 2026-09-24", queries_run=["DO-1", "DO-2", "DO-3"], analyst_id="averma", updated_at=_d(0, 9, 5)),
        Result(research_id=r.id, workspace_id="contoso", status="suspicious", summary="One .aspx write under LAYOUTS on SPSE-02 outside a patch window; triage in progress.",
               hunt_window="2025-07-01 – 2026-09-24", queries_run=["DO-3"], analyst_id="jchen", updated_at=_d(0, 8, 40)),
    ]
    db.add_all(results)
    db.flush()
    r.record = {**r.record, "results": [{"workspace_id": x.workspace_id, "status": x.status, "summary": x.summary, "hunt_window": x.hunt_window,
                                         "queries_run": x.queries_run, "analyst": x.analyst_id} for x in results]}
    db.add(Run(id="RUN-TR-2026-0142-1", research_id=r.id, seed=r.seed, status="done", stage="export", mode="manual",
               config={"platforms": rec["hunts"]["platforms"], "workspace_ids": r.workspace_ids, "depth": "standard", "lookback_days": 30,
                       "include_generic_hunts": False, "tlp": "AMBER"},
               stage_status={s: {"state": "done"} for s in ["intake", "discovery", "extraction", "synthesis", "attack", "detection", "queries", "iocs", "report", "export"]},
               started_at=_d(2, 8, 0), finished_at=_d(2, 8, 9)))
    for t, msg, u, when in [
        ("created", "Research started", "averma", _d(2, 8, 0)),
        ("run_completed", "Run completed · 5 sources · 7 min 42 s", None, _d(2, 8, 8)),
        ("status", "Review requested by A. Verma", "averma", _d(0, 8, 40)),
        ("edited", "v3 · 4 sections changed", "riyer", _d(0, 9, 10)),
        ("status", "Published by R. Iyer", "riyer", _d(0, 9, 14)),
        ("result", "Hunt result for Contoso Energy: suspicious", "jchen", _d(0, 8, 41)),
        ("exported", "Exported TR-2026-0142 as PDF (Northwind Health)", "averma", _d(0, 9, 20)),
    ]:
        db.add(ActivityEvent(research_id=r.id, type=t, message=msg, user_id=u, created_at=when))
    db.add(ExportLog(research_id=r.id, workspace_id="northwind", format="pdf", user_id="averma", created_at=_d(0, 9, 20),
                     file_name="TR-2026-0142-northwind.pdf"))

    # Samples
    for i, s in enumerate(SAMPLES):
        sid = f"TR-2026-{135 + i:04d}"
        created = _d(s["days"], 10)
        rr = Research(id=sid, title=s["title"], status=s["status"], created_by=s["author"], created_at=created,
                      published_at=created + timedelta(days=1) if s["status"] in ("published", "archived") else None,
                      reviewed_by="riyer" if s["status"] in ("published", "archived") else None,
                      workspace_ids=s["ws"], seed=s["title"], tlp=s["tlp"])
        db.add(rr)
        db.flush()
        rec = _sample_record(s)
        save_record(db, rr, rec, s["author"], "Sample record", bump=False)
        for w in s["ws"]:
            status = {"published": "no_evidence", "archived": "no_evidence", "in_review": "pending", "draft": "pending"}[s["status"]]
            db.add(Result(research_id=sid, workspace_id=w, status=status, updated_at=created))
        log_activity(db, sid, "created", "Research started (sample)", s["author"])
    db.commit()
    return True

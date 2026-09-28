"""MITRE ATT&CK Enterprise reference data.

A bundled subset keeps the app usable offline. `sync_from_mitre()` replaces it with
the full, current Enterprise matrix from MITRE's STIX bundle (spec: synced weekly).
The tactic rail always reads tactics from here, never from hard-coded UI strings.
"""

from __future__ import annotations

import logging

import httpx
from sqlalchemy.orm import Session

from .models import AttackTechnique, Setting

log = logging.getLogger(__name__)

STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# Kill-chain order. short = label under the rail segment.
TACTICS: list[dict] = [
    {"id": "TA0043", "name": "Reconnaissance", "short": "Recon", "shortname": "reconnaissance"},
    {"id": "TA0042", "name": "Resource Development", "short": "ResDev", "shortname": "resource-development"},
    {"id": "TA0001", "name": "Initial Access", "short": "InitAcc", "shortname": "initial-access"},
    {"id": "TA0002", "name": "Execution", "short": "Exec", "shortname": "execution"},
    {"id": "TA0003", "name": "Persistence", "short": "Persist", "shortname": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "short": "PrivEsc", "shortname": "privilege-escalation"},
    {"id": "TA0005", "name": "Defense Evasion", "short": "DefEva", "shortname": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access", "short": "CredAcc", "shortname": "credential-access"},
    {"id": "TA0007", "name": "Discovery", "short": "Disc", "shortname": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "short": "LatMov", "shortname": "lateral-movement"},
    {"id": "TA0009", "name": "Collection", "short": "Coll", "shortname": "collection"},
    {"id": "TA0011", "name": "Command and Control", "short": "C2", "shortname": "command-and-control"},
    {"id": "TA0010", "name": "Exfiltration", "short": "Exfil", "shortname": "exfiltration"},
    {"id": "TA0040", "name": "Impact", "short": "Impact", "shortname": "impact"},
]
TACTIC_BY_ID = {t["id"]: t for t in TACTICS}
TACTIC_BY_SHORTNAME = {t["shortname"]: t for t in TACTICS}

# id: (name, [tactic ids])
_BUNDLED: dict[str, tuple[str, list[str]]] = {
    "T1595": ("Active Scanning", ["TA0043"]),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", ["TA0043"]),
    "T1592": ("Gather Victim Host Information", ["TA0043"]),
    "T1589": ("Gather Victim Identity Information", ["TA0043"]),
    "T1583": ("Acquire Infrastructure", ["TA0042"]),
    "T1583.001": ("Acquire Infrastructure: Domains", ["TA0042"]),
    "T1587.001": ("Develop Capabilities: Malware", ["TA0042"]),
    "T1588.002": ("Obtain Capabilities: Tool", ["TA0042"]),
    "T1190": ("Exploit Public-Facing Application", ["TA0001"]),
    "T1133": ("External Remote Services", ["TA0001", "TA0003"]),
    "T1566": ("Phishing", ["TA0001"]),
    "T1566.001": ("Phishing: Spearphishing Attachment", ["TA0001"]),
    "T1566.002": ("Phishing: Spearphishing Link", ["TA0001"]),
    "T1566.004": ("Phishing: Spearphishing Voice", ["TA0001"]),
    "T1539": ("Steal Web Session Cookie", ["TA0006"]),
    "T1621": ("Multi-Factor Authentication Request Generation", ["TA0006"]),
    "T1528": ("Steal Application Access Token", ["TA0006"]),
    "T1550.004": ("Use Alternate Authentication Material: Web Session Cookie", ["TA0005", "TA0008"]),
    "T1078": ("Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1195.002": ("Supply Chain Compromise: Compromise Software Supply Chain", ["TA0001"]),
    "T1189": ("Drive-by Compromise", ["TA0001"]),
    "T1059": ("Command and Scripting Interpreter", ["TA0002"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["TA0002"]),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", ["TA0002"]),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ["TA0002"]),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", ["TA0002"]),
    "T1059.006": ("Command and Scripting Interpreter: Python", ["TA0002"]),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", ["TA0002"]),
    "T1047": ("Windows Management Instrumentation", ["TA0002"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ["TA0002", "TA0003", "TA0004"]),
    "T1569.002": ("System Services: Service Execution", ["TA0002"]),
    "T1203": ("Exploitation for Client Execution", ["TA0002"]),
    "T1204.002": ("User Execution: Malicious File", ["TA0002"]),
    "T1106": ("Native API", ["TA0002"]),
    "T1505.003": ("Server Software Component: Web Shell", ["TA0003"]),
    "T1505.004": ("Server Software Component: IIS Components", ["TA0003"]),
    "T1543.003": ("Create or Modify System Process: Windows Service", ["TA0003", "TA0004"]),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", ["TA0003", "TA0004"]),
    "T1136.001": ("Create Account: Local Account", ["TA0003"]),
    "T1098": ("Account Manipulation", ["TA0003", "TA0004"]),
    "T1574.002": ("Hijack Execution Flow: DLL Side-Loading", ["TA0003", "TA0004", "TA0005"]),
    "T1068": ("Exploitation for Privilege Escalation", ["TA0004"]),
    "T1484.001": ("Domain or Tenant Policy Modification: Group Policy Modification", ["TA0004", "TA0005"]),
    "T1134": ("Access Token Manipulation", ["TA0004", "TA0005"]),
    "T1055": ("Process Injection", ["TA0004", "TA0005"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["TA0005"]),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", ["TA0005"]),
    "T1112": ("Modify Registry", ["TA0005"]),
    "T1027": ("Obfuscated Files or Information", ["TA0005"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["TA0005"]),
    "T1070.004": ("Indicator Removal: File Deletion", ["TA0005"]),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ["TA0005"]),
    "T1036": ("Masquerading", ["TA0005"]),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", ["TA0005"]),
    "T1218": ("System Binary Proxy Execution", ["TA0005"]),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", ["TA0005"]),
    "T1620": ("Reflective Code Loading", ["TA0005"]),
    "T1211": ("Exploitation for Defense Evasion", ["TA0005"]),
    "T1003": ("OS Credential Dumping", ["TA0006"]),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["TA0006"]),
    "T1003.002": ("OS Credential Dumping: Security Account Manager", ["TA0006"]),
    "T1003.003": ("OS Credential Dumping: NTDS", ["TA0006"]),
    "T1552": ("Unsecured Credentials", ["TA0006"]),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", ["TA0006"]),
    "T1555": ("Credentials from Password Stores", ["TA0006"]),
    "T1110": ("Brute Force", ["TA0006"]),
    "T1110.003": ("Brute Force: Password Spraying", ["TA0006"]),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ["TA0006"]),
    "T1212": ("Exploitation for Credential Access", ["TA0006"]),
    "T1082": ("System Information Discovery", ["TA0007"]),
    "T1033": ("System Owner/User Discovery", ["TA0007"]),
    "T1087.002": ("Account Discovery: Domain Account", ["TA0007"]),
    "T1018": ("Remote System Discovery", ["TA0007"]),
    "T1016": ("System Network Configuration Discovery", ["TA0007"]),
    "T1046": ("Network Service Discovery", ["TA0007"]),
    "T1057": ("Process Discovery", ["TA0007"]),
    "T1083": ("File and Directory Discovery", ["TA0007"]),
    "T1482": ("Domain Trust Discovery", ["TA0007"]),
    "T1518.001": ("Software Discovery: Security Software Discovery", ["TA0007"]),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", ["TA0008"]),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", ["TA0008"]),
    "T1021.006": ("Remote Services: Windows Remote Management", ["TA0008"]),
    "T1570": ("Lateral Tool Transfer", ["TA0008"]),
    "T1210": ("Exploitation of Remote Services", ["TA0008"]),
    "T1005": ("Data from Local System", ["TA0009"]),
    "T1560.001": ("Archive Collected Data: Archive via Utility", ["TA0009"]),
    "T1114": ("Email Collection", ["TA0009"]),
    "T1071": ("Application Layer Protocol", ["TA0011"]),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ["TA0011"]),
    "T1071.004": ("Application Layer Protocol: DNS", ["TA0011"]),
    "T1090": ("Proxy", ["TA0011"]),
    "T1105": ("Ingress Tool Transfer", ["TA0011"]),
    "T1572": ("Protocol Tunneling", ["TA0011"]),
    "T1573": ("Encrypted Channel", ["TA0011"]),
    "T1219": ("Remote Access Software", ["TA0011"]),
    "T1041": ("Exfiltration Over C2 Channel", ["TA0010"]),
    "T1567.002": ("Exfiltration Over Web Service: Exfiltration to Cloud Storage", ["TA0010"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["TA0010"]),
    "T1486": ("Data Encrypted for Impact", ["TA0040"]),
    "T1490": ("Inhibit System Recovery", ["TA0040"]),
    "T1489": ("Service Stop", ["TA0040"]),
    "T1485": ("Data Destruction", ["TA0040"]),
    "T1498": ("Network Denial of Service", ["TA0040"]),
    "T1657": ("Financial Theft", ["TA0040"]),
}

# Keyword hints used by offline-mode mapping (behaviour text -> technique).
KEYWORD_HINTS: list[tuple[str, str]] = [
    (r"exploit(ed|ation|ing)?\b.*\b(public|internet|web|server|sharepoint|exchange|vpn|gateway|cve)", "T1190"),
    (r"vulnerability scan|mass scan|scann(ed|ing) for", "T1595.002"),
    (r"web ?shell|\.aspx|\.jsp\b|\.php\b.*shell", "T1505.003"),
    (r"iis module|applicationhost\.config|native module", "T1505.004"),
    (r"powershell|-enc(odedcommand)?\b", "T1059.001"),
    (r"cmd\.exe|command shell", "T1059.003"),
    (r"bash|/bin/sh", "T1059.004"),
    (r"\bwmi\b|wmic|impacket", "T1047"),
    (r"psexec|service execution", "T1569.002"),
    (r"scheduled task|schtasks", "T1053.005"),
    (r"group policy|\bgpo\b", "T1484.001"),
    (r"mimikatz|lsass", "T1003.001"),
    (r"machinekey|validationkey|decryptionkey", "T1552"),
    (r"ntds\.dit", "T1003.003"),
    (r"disable.*(defender|antivirus|edr|av)\b|byovd|av killer", "T1562.001"),
    (r"registry", "T1112"),
    (r"obfuscat|base64", "T1027"),
    (r"rdp|remote desktop", "T1021.001"),
    (r"smb|admin\$|c\$", "T1021.002"),
    (r"reverse proxy|\bfrp\b|ngrok|tunnel", "T1090"),
    (r"\bc2\b|command and control|beacon", "T1071.001"),
    (r"dns (c2|tunnel)", "T1071.004"),
    (r"ransomware|encrypt(ed|s)? files", "T1486"),
    (r"shadow cop|vssadmin|bcdedit", "T1490"),
    (r"exfiltrat", "T1041"),
    (r"phishing|spearphish", "T1566"),
    (r"valid accounts|stolen credentials", "T1078"),
    (r"whoami|user discovery", "T1033"),
    (r"systeminfo|host ?info", "T1082"),
    (r"download(ed|s)? (payload|tool)|ingress tool", "T1105"),
    (r"side-?load", "T1574.002"),
    (r"deserializ", "T1190"),
]

_catalog: dict[str, tuple[str, list[str]]] = dict(_BUNDLED)


def load_catalog(db: Session) -> None:
    """Load the synced catalog from the DB if present, else keep the bundled subset."""
    global _catalog
    rows = db.query(AttackTechnique).all()
    if rows:
        _catalog = {r.id: (r.name, list(r.tactic_ids)) for r in rows}
    else:
        for tid, (name, tactics) in _BUNDLED.items():
            db.add(AttackTechnique(id=tid, name=name, tactic_ids=tactics, attack_version="bundled"))
        db.commit()


def technique(tid: str) -> dict | None:
    tid = tid.strip().upper()
    hit = _catalog.get(tid)
    if not hit:
        return None
    return {"id": tid, "name": hit[0], "tactic_ids": hit[1]}


def valid_technique(tid: str) -> bool:
    return tid.strip().upper() in _catalog


def all_techniques() -> list[dict]:
    return [{"id": k, "name": v[0], "tactic_ids": v[1]} for k, v in sorted(_catalog.items())]


def sync_from_mitre(db: Session) -> dict:
    """Download the current Enterprise ATT&CK STIX bundle and replace the catalog."""
    resp = httpx.get(STIX_URL, timeout=120, follow_redirects=True)
    resp.raise_for_status()
    bundle = resp.json()
    version = ""
    rows: dict[str, tuple[str, list[str]]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", "")
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tactic_ids = [
            TACTIC_BY_SHORTNAME[p["phase_name"]]["id"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name") in TACTIC_BY_SHORTNAME
        ]
        rows[ext["external_id"]] = (obj.get("name", ""), tactic_ids)
    # Sub-technique names are prefixed with their parent's, as in the ATT&CK site.
    for tid, (name, tactics) in list(rows.items()):
        if "." in tid:
            parent = rows.get(tid.split(".")[0])
            if parent and not name.startswith(parent[0]):
                rows[tid] = (f"{parent[0]}: {name}", tactics)
    db.query(AttackTechnique).delete()
    for tid, (name, tactics) in rows.items():
        db.add(AttackTechnique(id=tid, name=name, tactic_ids=tactics, attack_version=version))
    setting = db.get(Setting, "attack_sync") or Setting(key="attack_sync", value={})
    setting.value = {"version": version, "count": len(rows)}
    db.merge(setting)
    db.commit()
    load_catalog(db)
    return {"version": version, "techniques": len(rows)}


def tactic_counts(mitre: list[dict]) -> dict[str, int]:
    """Number of distinct techniques mapped per tactic, for the tactic rail."""
    seen: dict[str, set[str]] = {t["id"]: set() for t in TACTICS}
    for m in mitre:
        tid = m.get("technique_id", "")
        tactic_ids = [m["tactic_id"]] if m.get("tactic_id") else (technique(tid) or {}).get("tactic_ids", [])
        for ta in tactic_ids:
            if ta in seen:
                seen[ta].add(tid)
    return {k: len(v) for k, v in seen.items()}

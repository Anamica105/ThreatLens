"""Canned detection logic per ATT&CK technique.

Used in offline mode (no LLM) and as wider, not threat-specific "TTP hunts" in every
mode. Each entry is a neutral detection spec (see detection.py).
"""

TECHNIQUE_OPPORTUNITIES: dict[str, list[dict]] = {
    "T1505.003": [
        {"title": "IIS worker spawns a command shell", "type": "ioa",
         "logic": "The IIS worker process (w3wp.exe) starting cmd.exe or PowerShell is a strong web-shell signal.",
         "fp_notes": "Rare on web servers; some admin tooling and health checks launch scripts. Baseline per host.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "parent_image", "op": "endswith", "values": ["\\w3wp.exe"]},
             {"field": "image", "op": "endswith", "values": ["\\cmd.exe", "\\powershell.exe", "\\pwsh.exe"]}]}},
        {"title": "New script file written under a web root", "type": "ttp",
         "logic": "Creation of .aspx/.ashx/.jsp files in web directories outside deployment windows.",
         "fp_notes": "Legitimate deployments and patches write these files; correlate with change windows.",
         "spec": {"category": "file_event", "conditions": [
             {"field": "target_filename", "op": "contains", "values": ["\\inetpub\\", "\\TEMPLATE\\LAYOUTS\\"]},
             {"field": "target_filename", "op": "endswith", "values": [".aspx", ".ashx", ".asmx"]}]}},
    ],
    "T1059.001": [
        {"title": "Encoded PowerShell command line", "type": "ioa",
         "logic": "PowerShell started with -EncodedCommand hides its payload from casual review.",
         "fp_notes": "Some management agents (SCCM, RMM) use encoded commands; exclude signed parent processes.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "image", "op": "endswith", "values": ["\\powershell.exe", "\\pwsh.exe"]},
             {"field": "command_line", "op": "contains", "values": [" -enc ", " -ec ", "-EncodedCommand"]}]}},
    ],
    "T1003.001": [
        {"title": "LSASS memory access via comsvcs or Mimikatz keywords", "type": "ttp",
         "logic": "Credential dumping through comsvcs.dll MiniDump or Mimikatz command keywords.",
         "fp_notes": "Very rare legitimately; crash-dump tooling may call MiniDump.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "command_line", "op": "contains", "values": ["comsvcs.dll, MiniDump", "comsvcs.dll MiniDump", "sekurlsa::", "lsadump::"]}]}},
    ],
    "T1047": [
        {"title": "WMI provider host spawns a shell", "type": "ttp",
         "logic": "wmiprvse.exe launching cmd.exe or PowerShell indicates remote WMI execution (e.g. Impacket wmiexec).",
         "fp_notes": "Some inventory and patching tools do this; baseline by command line.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "parent_image", "op": "endswith", "values": ["\\wmiprvse.exe"]},
             {"field": "image", "op": "endswith", "values": ["\\cmd.exe", "\\powershell.exe"]}]}},
    ],
    "T1569.002": [
        {"title": "PsExec service execution", "type": "ttp",
         "logic": "PSEXESVC.exe running on a host shows remote service-based execution.",
         "fp_notes": "IT admins use PsExec; confirm against approved admin hosts.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "parent_image", "op": "endswith", "values": ["\\PSEXESVC.exe"]}]}},
    ],
    "T1053.005": [
        {"title": "Scheduled task created from a command line", "type": "ttp",
         "logic": "schtasks.exe /create, especially from scripts or remote sessions, is a common persistence and execution method.",
         "fp_notes": "Software installers create tasks; focus on tasks running from temp or user-writable paths.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "image", "op": "endswith", "values": ["\\schtasks.exe"]},
             {"field": "command_line", "op": "contains", "values": ["/create"]}]}},
    ],
    "T1562.001": [
        {"title": "Defender real-time protection disabled", "type": "ttp",
         "logic": "Commands that disable Microsoft Defender protections ahead of payload deployment.",
         "fp_notes": "Rare outside troubleshooting; validate with the endpoint team.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "command_line", "op": "contains", "values": ["DisableRealtimeMonitoring", "Set-MpPreference -Disable", "DisableAntiSpyware"]}]}},
    ],
    "T1490": [
        {"title": "Shadow copies deleted", "type": "ttp",
         "logic": "vssadmin/wmic shadow copy deletion is a near-universal ransomware precursor.",
         "fp_notes": "Backup software may prune shadow copies; check the parent process.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "command_line", "op": "contains", "values": ["delete shadows", "shadowcopy delete", "resize shadowstorage"]}]}},
    ],
    "T1486": [
        {"title": "Mass file rename to a ransomware extension", "type": "ttp",
         "logic": "Many files written with the same unusual extension in a short window.",
         "fp_notes": "Archive and sync tools; tune by extension list from the report.",
         "spec": {"category": "file_event", "conditions": [
             {"field": "target_filename", "op": "endswith", "values": [".locked", ".encrypted", ".x2anylock", ".warlock"]}]}},
    ],
    "T1552": [
        {"title": "ASP.NET MachineKey read by a web shell", "type": "ioa",
         "logic": "PowerShell or .NET code reading machineKey values (ValidationKey/DecryptionKey) on a web server.",
         "fp_notes": "Configuration management may read web.config; MachineKey extraction by w3wp children is rare.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "command_line", "op": "contains", "values": ["MachineKey", "ValidationKey", "DecryptionKey"]}]}},
    ],
    "T1484.001": [
        {"title": "Group Policy used to push scheduled tasks or scripts", "type": "ttp",
         "logic": "Scripts or scheduled tasks written into SYSVOL policy folders deploy payloads domain-wide.",
         "fp_notes": "Domain admins edit GPOs; correlate with change tickets.",
         "spec": {"category": "file_event", "conditions": [
             {"field": "target_filename", "op": "contains", "values": ["\\SYSVOL\\", "\\Policies\\"]},
             {"field": "target_filename", "op": "endswith", "values": ["ScheduledTasks.xml", ".bat", ".ps1"]}]}},
    ],
    "T1090": [
        {"title": "Reverse proxy or tunnelling tool executed", "type": "ttp",
         "logic": "Execution of frp, ngrok or similar tunnelling clients on servers.",
         "fp_notes": "Developers may use ngrok on workstations; servers should not.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "command_line", "op": "contains", "values": ["frpc", "ngrok", "tunnel --url", "chisel"]}]}},
    ],
    "T1021.002": [
        {"title": "Remote command execution over admin shares", "type": "ttp",
         "logic": "Processes started from ADMIN$ or C$ paths indicate SMB-based lateral movement.",
         "fp_notes": "Software deployment tools copy to admin shares; baseline source hosts.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "command_line", "op": "contains", "values": ["\\ADMIN$\\", "\\C$\\"]}]}},
    ],
    "T1112": [
        {"title": "Registry changes weakening security", "type": "ttp",
         "logic": "reg.exe modifying Defender, LSA or RDP settings from the command line.",
         "fp_notes": "Hardening scripts touch the same keys; review direction of change.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "image", "op": "endswith", "values": ["\\reg.exe"]},
             {"field": "command_line", "op": "contains", "values": ["Windows Defender", "DisableRestrictedAdmin", "fDenyTSConnections"]}]}},
    ],
    "T1033": [
        {"title": "Discovery commands from a server process", "type": "ttp",
         "logic": "whoami, nltest or net group run by service accounts right after exploitation.",
         "fp_notes": "Common in admin sessions; alert when the parent is a web or database process.",
         "spec": {"category": "process_creation", "conditions": [
             {"field": "parent_image", "op": "endswith", "values": ["\\w3wp.exe", "\\sqlservr.exe", "\\java.exe"]},
             {"field": "image", "op": "endswith", "values": ["\\whoami.exe", "\\nltest.exe", "\\net.exe"]}]}},
    ],
}

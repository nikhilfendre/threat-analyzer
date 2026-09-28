"""Keyword-based mapping of report text to MITRE ATT&CK techniques.

This is a transparent, explainable first pass: each technique carries the
keywords that trigger it. A production system would replace/augment this
with a trained classifier, but for a college project this mapping is
auditable and easy to extend.
"""

TECHNIQUES = [
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access",
     "keywords": ["phishing", "spearphishing", "spear phishing", "malicious email",
                  "email attachment", "lure document"]},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
     "keywords": ["exploit", "exploited", "vulnerability", "cve-", "zero-day", "zero day",
                  "unpatched"]},
    {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access",
     "keywords": ["rdp", "remote desktop", "vpn", "exposed service", "brute force",
                  "credential stuffing"]},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Persistence",
     "keywords": ["compromised credentials", "stolen credentials", "valid account",
                  "credential theft", "password spray"]},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution",
     "keywords": ["powershell", "cmd.exe", "wscript", "malicious script", "macro"]},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access",
     "keywords": ["credential dumping", "mimikatz", "lsass", "hash dumping",
                  "dumped credentials"]},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact",
     "keywords": ["ransomware", "encrypted", "encryption", "ransom note", "decryptor",
                  "double extortion"]},
    {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact",
     "keywords": ["deleted backups", "shadow copies", "vssadmin", "recovery disabled"]},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
     "keywords": ["exfiltrat", "data theft", "stole data", "leaked data"]},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
     "keywords": ["c2", "command and control", "c&c", "beacon", "callback",
                  "malicious domain"]},
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement",
     "keywords": ["lateral movement", "psexec", "wmi", "smb", "moved laterally"]},
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact",
     "keywords": ["ddos", "denial of service", "botnet", "traffic flood"]},
    {"id": "T1204", "name": "User Execution", "tactic": "Execution",
     "keywords": ["clicked", "opened the attachment", "enabled macros",
                  "user executed", "social engineering"]},
    {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion",
     "keywords": ["process injection", "hollowing", "injected into"]},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
     "keywords": ["brute force", "brute-force", "bruteforced"]},
]


def map_techniques(text: str) -> list[dict]:
    """Return matched techniques sorted by number of keyword hits."""
    lowered = text.lower()
    hits = []
    for tech in TECHNIQUES:
        matched = [kw for kw in tech["keywords"] if kw in lowered]
        if matched:
            hits.append({**tech, "matched_keywords": matched,
                         "hits": len(matched)})
    hits.sort(key=lambda t: t["hits"], reverse=True)
    return hits

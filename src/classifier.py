"""Threat-type and severity classification.

Rule-based scoring on curated keyword sets. This is deliberately
transparent (every decision lists its triggering keywords) because the
project has no labeled training set — an honest limitation documented in
the README. With labeled data, these would become sklearn classifiers.
"""

THREAT_TYPES = {
    "Ransomware": ["ransomware", "ransom note", "encrypted", "decryptor",
                   "double extortion", "data encrypted for impact"],
    "Phishing": ["phishing", "spearphishing", "malicious email", "lure",
                 "spoofed", "credential harvesting"],
    "Trojan / Malware": ["trojan", "malware", "backdoor", "remote access trojan",
                         "rootkit", "dropper", "loader"],
    "Vulnerability Exploitation": ["cve-", "exploit", "zero-day", "zero day",
                                   "unpatched", "vulnerability"],
    "Data Breach / Exfiltration": ["data breach", "exfiltrat", "leaked",
                                   "stole data", "data theft"],
    "DDoS": ["ddos", "denial of service", "botnet", "traffic flood"],
    "Credential Attack": ["credential", "brute force", "password spray",
                          "mimikatz", "lsass", "dumping"],
    "APT / Targeted Intrusion": ["apt", "advanced persistent", "espionage",
                                 "nation-state", "lateral movement"],
}

_SEVERITY_RULES = [
    ("Critical", ["ransomware", "zero-day", "zero day", "actively exploited",
                  "data encrypted", "widespread", "critical infrastructure",
                  "double extortion"]),
    ("High", ["exploit", "cve-", "backdoor", "data breach", "exfiltrat",
              "privilege escalation", "remote code execution"]),
    ("Medium", ["phishing", "malware", "trojan", "suspicious", "vulnerability",
                "brute force"]),
]

_SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def classify_threat_type(text: str) -> tuple[str, dict[str, int]]:
    """Score each threat type by keyword hits; return best label + scores."""
    lowered = text.lower()
    scores = {}
    for label, keywords in THREAT_TYPES.items():
        scores[label] = sum(1 for kw in keywords if kw in lowered)
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return "Unknown / Other", scores
    return best, scores


def classify_severity(text: str, iocs: dict) -> tuple[str, list[str]]:
    """Severity from keyword rules + indicator signals. Returns label + reasons."""
    lowered = text.lower()
    level, reasons = "Low", []
    for sev, keywords in _SEVERITY_RULES:
        hits = [kw for kw in keywords if kw in lowered]
        if hits and _SEVERITY_ORDER[sev] > _SEVERITY_ORDER[level]:
            level = sev
            reasons.append(f"keywords: {', '.join(hits[:4])}")
    # indicator-based bumps
    if iocs.get("cves"):
        reasons.append(f"{len(iocs['cves'])} CVE(s) referenced")
        if _SEVERITY_ORDER[level] < _SEVERITY_ORDER["High"]:
            level = "High"
    n_ioc = sum(len(v) for k, v in iocs.items() if k != "domains")
    if n_ioc >= 5:
        reasons.append(f"{n_ioc} indicators of compromise found")
        if _SEVERITY_ORDER[level] < _SEVERITY_ORDER["High"]:
            level = "High"
    if not reasons:
        reasons.append("no high-impact keywords or indicators found")
    return level, reasons


RECOMMENDATIONS = {
    "Ransomware": ["Isolate affected hosts from the network immediately",
                   "Restore from clean offline backups; do not pay the ransom",
                   "Block all identified C2 domains/IPs at the perimeter",
                   "Hunt for lateral movement across the domain"],
    "Phishing": ["Reset credentials for targeted users; enforce MFA",
                 "Block sender domains and malicious URLs",
                 "Run awareness refresher for affected teams"],
    "Trojan / Malware": ["Quarantine infected endpoints",
                         "Block file hashes at the email gateway and EDR",
                         "Check for persistence mechanisms and scheduled tasks"],
    "Vulnerability Exploitation": ["Patch affected software on priority",
                                   "Scan the estate for the listed CVEs",
                                   "Review logs for exploitation attempts"],
    "Data Breach / Exfiltration": ["Engage incident response; preserve logs",
                                   "Identify scope of exfiltrated data",
                                   "Notify stakeholders per compliance requirements"],
    "DDoS": ["Engage DDoS mitigation / scrubbing service",
             "Rate-limit and block attacking botnet IPs"],
    "Credential Attack": ["Force password resets; enforce MFA everywhere",
                          "Audit privileged account usage"],
    "APT / Targeted Intrusion": ["Full incident-response engagement",
                                 "Threat-hunt across the estate for related IOCs"],
    "Unknown / Other": ["Manually review the report",
                        "Collect additional indicators before responding"],
}


def recommend_actions(threat_type: str, severity: str) -> list[str]:
    actions = list(RECOMMENDATIONS.get(threat_type, RECOMMENDATIONS["Unknown / Other"]))
    if severity == "Critical":
        actions.insert(0, "Treat as an active incident: escalate to the SOC lead now")
    return actions

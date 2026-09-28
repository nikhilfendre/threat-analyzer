"""Cybersecurity entity extraction.

Two layers:
1. Deterministic regex extractors for well-formed indicators (CVE, IP,
   domain, URL, email, file hashes) — these are far more reliable than any
   ML model for this job.
2. spaCy NER + a custom EntityRuler for malware families, threat actors
   and security products. Falls back to a blank English pipeline if the
   pretrained model is not installed.
"""

import re

import spacy
from spacy.pipeline import EntityRuler

# ---------------------------------------------------------------- regex IOCs

_PATTERNS = {
    "cves": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "urls": re.compile(r"\bhttps?://[^\s)\"'<>]+", re.IGNORECASE),
    "emails": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    # loose domain matcher; filtered below to drop obvious non-domains
    "domains": re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|online|site|club|pw|su|ir|in)\b",
        re.IGNORECASE,
    ),
}


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for i in items:
        key = i.lower()
        if key not in seen:
            seen.add(key)
            out.append(i)
    return out


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract indicators of compromise with regex. Returns label -> values."""
    iocs: dict[str, list[str]] = {}
    for label, pattern in _PATTERNS.items():
        iocs[label] = _dedupe(pattern.findall(text))
    # strip trailing punctuation accidentally captured with URLs
    iocs["urls"] = [u.rstrip(".,;:!?)\\]\"'") for u in iocs["urls"]]
    # a bare domain that is part of a URL/email is not a separate indicator
    url_text = " ".join(iocs["urls"] + iocs["emails"]).lower()
    iocs["domains"] = [d for d in iocs["domains"] if d.lower() not in url_text]
    return iocs


# ------------------------------------------------- spaCy NER + EntityRuler

_MALWARE_FAMILIES = [
    "wannacry", "notpetya", "emotet", "trickbot", "ryuk", "conti", "lockbit",
    "maze", "revil", "sodinokibi", "blackcat", "alphv", "cobalt strike",
    "mimikatz", "qakbot", "dridex", "zeus", "stuxnet", "duqu", "flame",
    "apt28", "apt29", "lazarus", "cozy bear", "fancy bear",
]

_SECURITY_PRODUCTS = [
    "windows", "windows server", "linux", "macos", "android", "ios",
    "apache", "nginx", "microsoft exchange", "active directory",
    "vmware", "cisco", "fortinet", "palo alto",
]


def _ruler_patterns() -> list[dict]:
    # token patterns on LOWER => case-insensitive matching
    patterns = []
    for name in _MALWARE_FAMILIES:
        patterns.append({"label": "MALWARE",
                         "pattern": [{"LOWER": t} for t in name.split()]})
    for name in _SECURITY_PRODUCTS:
        patterns.append({"label": "PRODUCT",
                         "pattern": [{"LOWER": t} for t in name.split()]})
    return patterns


_nlp = None


def get_nlp():
    """Load spaCy pipeline once; fall back to blank English + sentencizer."""
    global _nlp
    if _nlp is not None:
        return _nlp
    try:
        _nlp = spacy.load("en_core_web_sm")
    except OSError:
        _nlp = spacy.blank("en")
        _nlp.add_pipe("sentencizer")
    # custom cybersecurity ruler (runs after the statistical NER and
    # overwrites it — e.g. "Emotet" is ORG to the generic model)
    if "entity_ruler" not in _nlp.pipe_names:
        if "ner" in _nlp.pipe_names:
            ruler = _nlp.add_pipe("entity_ruler", after="ner",
                                  config={"overwrite_ents": True})
        else:
            ruler = _nlp.add_pipe("entity_ruler",
                                  config={"overwrite_ents": True})
        ruler.add_patterns(_ruler_patterns())
    return _nlp


# entities that are really IOCs (CVE ids, IPs, domains) should not be
# reported as organizations/products — they already live in the IOC section
_IOC_NOISE = re.compile(
    r"^(CVE-\d{4}-\d|(\d{1,3}\.){3}\d{1,3}|[a-z0-9-]+\.(com|net|org|io|ru|cn|tk|xyz|top|info|biz))$",
    re.IGNORECASE,
)


def extract_ml_entities(text: str, nlp=None) -> dict[str, list[str]]:
    """Named entities from spaCy: malware, products, orgs, locations."""
    nlp = nlp or get_nlp()
    doc = nlp(text[:200000])  # guard against pathological inputs
    buckets: dict[str, list[str]] = {
        "malware": [], "products": [], "organizations": [], "locations": [],
    }
    for ent in doc.ents:
        label = ent.label_
        val = ent.text.strip()
        if _IOC_NOISE.match(val):
            continue  # handled by the IOC extractors
        if label == "MALWARE":
            buckets["malware"].append(val)
        elif label == "PRODUCT":
            buckets["products"].append(val)
        elif label == "ORG":
            buckets["organizations"].append(val)
        elif label == "GPE":
            buckets["locations"].append(val)
    return {k: _dedupe(v) for k, v in buckets.items()}

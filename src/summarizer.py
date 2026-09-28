"""Extractive summarization: score sentences by security-keyword density
and positional weight, return the top-N in original order."""

from .classifier import THREAT_TYPES, _SEVERITY_RULES
from .mitre import TECHNIQUES

_KEYWORDS = set()
for _kws in THREAT_TYPES.values():
    _KEYWORDS.update(k.lower() for k in _kws)
for _sev, _kws in _SEVERITY_RULES:
    _KEYWORDS.update(k.lower() for k in _kws)
for _t in TECHNIQUES:
    _KEYWORDS.update(k.lower() for k in _t["keywords"])
_KEYWORDS.update(["cve-", "ip ", "domain", "hash", "malware", "attack"])


def summarize(text: str, nlp, n_sentences: int = 4) -> str:
    from .preprocessor import get_sentences
    sentences = get_sentences(text, nlp)
    if len(sentences) <= n_sentences:
        return " ".join(sentences)
    scored = []
    total = len(sentences)
    for i, sent in enumerate(sentences):
        lowered = sent.lower()
        kw_hits = sum(1 for kw in _KEYWORDS if kw in lowered)
        words = max(len(sent.split()), 1)
        if words < 5 or words > 60:  # skip fragments and walls of text
            continue
        position_bonus = 1.5 if i < 3 else (1.2 if i > total - 4 else 1.0)
        scored.append((kw_hits / words * 100 * position_bonus, i, sent))
    scored.sort(reverse=True)
    top = sorted(scored[:n_sentences], key=lambda x: x[1])
    return " ".join(s for _, _, s in top)

"""Attack-timeline extraction: pull DATE entities with their sentences
to reconstruct the incident sequence in order of appearance."""

import re

_DATE_RE = re.compile(
    r"\b(?:\d{1,2}\s+(?:January|February|March|April|May|June|July|August|"
    r"September|October|November|December)\s+\d{4}"
    r"|(?:January|February|March|April|May|June|July|August|"
    r"September|October|November|December)\s+\d{1,2},?\s+\d{4}"
    r"|\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})\b",
    re.IGNORECASE,
)


def extract_timeline(text: str, nlp, max_events: int = 8) -> list[dict]:
    """[{date, event}] — event is the sentence mentioning the date."""
    from .preprocessor import get_sentences
    sentences = get_sentences(text, nlp)
    events, seen = [], set()
    for sent in sentences:
        dates = set(_DATE_RE.findall(sent))
        if not dates and nlp is not None:
            try:
                doc = nlp(sent)
                dates.update(e.text.strip() for e in doc.ents
                             if e.label_ == "DATE" and len(e.text.strip()) > 3)
            except Exception:
                pass
        for d in dates:
            if re.fullmatch(r"\d{4}", d):
                continue  # bare year (e.g. "Windows Server 2019") is not an event
            key = (d.lower(), sent[:60].lower())
            if key in seen:
                continue
            seen.add(key)
            event = sent if len(sent) <= 220 else sent[:217] + "..."
            events.append({"date": d, "event": event})
        if len(events) >= max_events:
            break
    return events

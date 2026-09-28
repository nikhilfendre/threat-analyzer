"""Basic NLP preprocessing: cleaning + sentence segmentation."""

import re


def clean_text(text: str) -> str:
    """Normalize whitespace and strip control characters."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def refang(text: str) -> str:
    """Normalize defanged indicators ([.] -> ., hxxp -> http) so the
    regex extractors catch IOCs as analysts actually write them."""
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = re.sub(r"\bhxxps\b", "https", text, flags=re.IGNORECASE)
    text = re.sub(r"\bhxxp\b", "http", text, flags=re.IGNORECASE)
    return text


def get_sentences(text: str, nlp) -> list[str]:
    """Split text into sentences using the spaCy pipeline."""
    doc = nlp(text)
    return [s.text.strip() for s in doc.sents if s.text.strip()]


def word_count(text: str) -> int:
    return len(re.findall(r"\w+", text))

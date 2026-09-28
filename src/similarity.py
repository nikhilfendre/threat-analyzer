"""Similar-incident search: TF-IDF cosine similarity over previously
analyzed reports stored in SQLite."""

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from . import database


def find_similar_incidents(query_text: str, top_n: int = 3,
                           exclude_id: int | None = None) -> list[dict]:
    """Rank stored reports by similarity to the query text.

    Returns [{id, filename, threat_type, severity, score}] sorted by score.
    """
    reports = database.get_reports(limit=100)
    candidates = []
    for r in reports:
        if exclude_id is not None and r["id"] == exclude_id:
            continue
        full = database.get_report(r["id"])
        excerpt = (full["result"].get("text_excerpt") or "").strip()
        if len(excerpt) > 100:
            candidates.append((r, excerpt))
    if not candidates:
        return []

    docs = [query_text[:6000]] + [ex for _, ex in candidates]
    try:
        vec = TfidfVectorizer(stop_words="english", max_features=3000,
                              ngram_range=(1, 2)).fit_transform(docs)
        sims = cosine_similarity(vec[0:1], vec[1:]).flatten()
    except ValueError:
        return []

    ranked = sorted(zip(candidates, sims), key=lambda x: x[1], reverse=True)
    return [{"id": r["id"], "filename": r["filename"],
             "threat_type": r["threat_type"], "severity": r["severity"],
             "score": round(float(s), 3)}
            for (r, _), s in ranked[:top_n] if s > 0.01]

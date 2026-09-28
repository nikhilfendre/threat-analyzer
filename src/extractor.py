"""Text extraction from uploaded PDF / TXT files."""

import pymupdf


def extract_text_from_pdf_bytes(data: bytes) -> str:
    """Extract raw text from PDF bytes."""
    text_parts = []
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        for page in doc:
            text_parts.append(page.get_text())
    return "\n".join(text_parts)


def extract_text_from_txt_bytes(data: bytes) -> str:
    """Extract text from TXT bytes (tries utf-8, falls back to latin-1)."""
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def extract_text(filename: str, data: bytes) -> str:
    """Dispatch on file extension. Raises ValueError for unsupported types."""
    name = filename.lower()
    if name.endswith(".pdf"):
        return extract_text_from_pdf_bytes(data)
    if name.endswith(".txt"):
        return extract_text_from_txt_bytes(data)
    raise ValueError(f"Unsupported file type: {filename} (use .pdf or .txt)")

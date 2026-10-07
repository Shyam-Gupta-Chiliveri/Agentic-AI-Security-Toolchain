"""Security of AI: prompt-injection filter and source allow-list for RAG."""

from __future__ import annotations

import re

INJECTION_PATTERNS = (
    r"ignore (all )?(previous|prior|above) instructions",
    r"disregard (your|the) (system|safety) (prompt|rules)",
    r"you are now ",
    r"mark all findings as (info|informational|false positive)",
    r"do not (report|flag) (any )?(vulnerabilit|cwe)",
    r"override critic",
)

ALLOWED_RAG_STEMS = {
    "cwe",
    "cve",
    "iso21434_concepts",
}


def looks_like_injection(text: str) -> bool:
    blob = (text or "").lower()
    return any(re.search(p, blob) for p in INJECTION_PATTERNS)


def rag_source_allowed(path_name: str) -> bool:
    stem = path_name.rsplit(".", 1)[0].lower()
    return any(stem.startswith(ok) or ok in stem for ok in ALLOWED_RAG_STEMS)

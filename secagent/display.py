"""Full names shown on the desk. Short forms stay in brackets."""

import hashlib

CWE_NAMES = {
    "CWE-787": "Out-of-bounds Write",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-20": "Improper Input Validation",
    "CWE-476": "NULL Pointer Dereference",
}

SOURCE_NAMES = {
    "builtin_sast": "Static Application Security Testing (SAST) — built-in C checkers",
    "semgrep": "Static Application Security Testing (SAST) — Semgrep",
    "codeql": "Static Application Security Testing (SAST) — CodeQL",
    "afl": "American Fuzzy Lop plus plus (AFL++) fuzzing",
    "llm_review": "Large Language Model (LLM) code review",
}

TECHNIQUE_GUIDE = {
    "sast": {
        "full": "Static Application Security Testing (SAST)",
        "kid": "The computer reads the C files. It does not start the car. It looks for dangerous patterns, like using a bus byte as an array index.",
    },
    "fuzz": {
        "full": "Fuzzing with American Fuzzy Lop plus plus (AFL++)",
        "kid": "The computer throws many random Controller Area Network (CAN) frames at a small test program and watches for a crash.",
    },
    "llm": {
        "full": "Large Language Model (LLM) review",
        "kid": "A language model reads a chunk of C and says if it looks unsafe. It can be wrong. You still label it.",
    },
    "rag": {
        "full": "Retrieval-Augmented Generation (RAG)",
        "kid": "Each finding is matched to a Common Weakness Enumeration (CWE) page from MITRE, not invented from memory.",
    },
    "critic": {
        "full": "Critic agent",
        "kid": "A second pass that drops noisy matches, sets severity, writes a fix, and cites the Common Weakness Enumeration (CWE).",
    },
}


def short_id(*parts: str) -> str:
    """Stable finding id. Not a password hash."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def cwe_label(cwe_id: str) -> str:
    name = CWE_NAMES.get(cwe_id.upper(), "Weakness")
    return f"{cwe_id} · {name}"


def source_label(source: str) -> str:
    return SOURCE_NAMES.get(source, source)

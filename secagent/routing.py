"""Router: which analysis agents to run for this input."""

from __future__ import annotations

from pathlib import Path

SAST_HINTS = ("sast", "semgrep", "codeql", "static")
FUZZ_HINTS = ("fuzz", "afl", "crash", "harness")
LLM_HINTS = ("llm", "review", "gpt", "groq")
ALL_HINTS = ("all", "full", "everything")


def route_agents(
    query: str = "",
    *,
    target: Path | None = None,
    has_sarif: bool = False,
    has_crashes: bool = False,
) -> list[str]:
    """Return ordered agent names. Always includes critic after producers."""
    q = (query or "").lower()
    agents: list[str] = []

    want_all = not q or any(h in q for h in ALL_HINTS)
    want_sast = want_all or any(h in q for h in SAST_HINTS)
    want_fuzz = want_all or any(h in q for h in FUZZ_HINTS) or has_crashes
    want_llm = want_all or any(h in q for h in LLM_HINTS)

    if target and target.suffix in {".c", ".h"}:
        want_sast = True

    if want_sast:
        agents.append("semgrep")
        if has_sarif:
            agents.append("codeql")
        agents.append("builtin_sast")
    if want_fuzz:
        agents.append("afl")
    if want_llm:
        agents.append("llm_review")

    if not agents:
        agents.extend(["semgrep", "builtin_sast"])

    agents.append("critic")
    return agents

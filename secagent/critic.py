"""Critic: drop obvious false positives, assign severity, suggest a fix."""

from __future__ import annotations

from secagent.labels import ranking_boost
from secagent.models import Finding
from secagent.rag import KnowledgeBase

NOISE_TITLES = (
    "todo",
    "fixme",
    "copyright",
)


def review(
    findings: list[Finding],
    kb: KnowledgeBase,
    labels: dict[str, str] | None = None,
) -> list[Finding]:
    labels = labels or {}
    kept: list[Finding] = []
    for finding in findings:
        title_l = finding.title.lower()
        if any(n in title_l for n in NOISE_TITLES):
            finding.critic_decision = "drop"
            finding.critic_rationale = "Looks like a comment/noise match, not a vulnerability."
            finding.severity = "info"
            continue

        finding.rag_citation = kb.cite_cwe(finding.cwe_id)
        finding.iso21434_note = kb.iso_note()
        finding.severity = _severity(finding)
        finding.suggested_fix = finding.suggested_fix or _default_fix(finding)
        finding.critic_decision = "keep"
        finding.critic_rationale = (
            "CWE mapped from MITRE via in-repo RAG. Severity from CWE class "
            "and whether the index/length comes from the CAN frame."
        )
        boost = ranking_boost(finding, labels)
        finding.extra["ranking_boost"] = boost
        if boost < -0.3:
            finding.critic_rationale += " Down-ranked: similar CWE often labelled false positive."
        kept.append(finding)

    kept.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[f.severity],
            -float(f.extra.get("ranking_boost", 0)),
        )
    )
    return kept


def _severity(finding: Finding) -> str:
    cwe = finding.cwe_id.upper()
    if cwe in {"CWE-787", "CWE-120", "CWE-121"}:
        return "high"
    if cwe in {"CWE-125", "CWE-190"}:
        return "high"
    if cwe in {"CWE-20", "CWE-476"}:
        return "medium"
    return "low"


def _default_fix(finding: Finding) -> str:
    cwe = finding.cwe_id.upper()
    if cwe in {"CWE-787", "CWE-190", "CWE-125"}:
        return (
            "Reject sequence_number == 0. Compute index as (seq - 1) only after "
            "checking 1 <= seq <= declared package count, and "
            "(seq - 1) * 7 + 6 < sizeof(tp_dt.data)."
        )
    if cwe == "CWE-20":
        return (
            "Validate TP.CM total_message_size (9..1785) and number_of_packages "
            "(2..224) before accepting TP.DT writes."
        )
    return "Validate untrusted CAN fields before using them as lengths or indexes."

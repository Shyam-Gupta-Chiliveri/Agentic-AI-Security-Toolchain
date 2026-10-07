from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Severity = Literal["critical", "high", "medium", "low", "info"]
Triage = Literal["true_positive", "false_positive", "unreviewed"]
CriticDecision = Literal["keep", "drop", "uncertain"]


@dataclass
class Finding:
    id: str
    source: str
    file: str
    line: int
    cwe_id: str
    title: str
    evidence: str
    suggested_fix: str = ""
    rag_citation: str = ""
    iso21434_note: str = ""
    severity: Severity = "medium"
    critic_decision: CriticDecision = "uncertain"
    critic_rationale: str = ""
    triage: Triage = "unreviewed"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)

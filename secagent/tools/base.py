from __future__ import annotations

from pathlib import Path
from typing import Protocol

from secagent.models import Finding


class ToolAgent(Protocol):
    """Plug-in contract. Add a class, register it — no orchestrator rewrite."""

    name: str
    kind: str

    def run(self, target: Path, context: dict) -> list[Finding]:
        ...

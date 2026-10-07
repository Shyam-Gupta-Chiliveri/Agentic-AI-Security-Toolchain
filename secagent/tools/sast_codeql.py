"""Parse a CodeQL SARIF file from CI. Does not require a local CodeQL install."""

from __future__ import annotations

import json
import os
from pathlib import Path

from secagent.models import Finding


class CodeqlAgent:
    name = "codeql"
    kind = "sast"

    def run(self, target: Path, context: dict) -> list[Finding]:
        raw = context.get("sarif") or os.getenv("CODEQL_SARIF") or ""
        if not raw:
            return []
        sarif_path = Path(raw)
        if not sarif_path.is_file():
            return []
        payload = json.loads(sarif_path.read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for run in payload.get("runs", []):
            for result in run.get("results", []):
                rule = result.get("ruleId", "codeql")
                msg = (result.get("message") or {}).get("text", rule)
                locs = result.get("locations") or [{}]
                phys = (locs[0].get("physicalLocation") or {})
                art = phys.get("artifactLocation") or {}
                region = phys.get("region") or {}
                path = art.get("uri", "")
                line = int(region.get("startLine") or 0)
                props = result.get("properties") or {}
                cwe = "CWE-20"
                tags = props.get("tags") or []
                for tag in tags:
                    if "cwe-" in str(tag).lower():
                        num = "".join(ch for ch in str(tag) if ch.isdigit())
                        if num:
                            cwe = f"CWE-{num}"
                            break
                findings.append(
                    Finding(
                        id=f"codeql-{hash((path, line, rule)) & 0xFFFFFFFF:x}",
                        source="codeql",
                        file=path,
                        line=line,
                        cwe_id=cwe,
                        title=msg[:180],
                        evidence=rule,
                    )
                )
        return findings

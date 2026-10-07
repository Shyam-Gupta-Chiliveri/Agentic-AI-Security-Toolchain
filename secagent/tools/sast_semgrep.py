from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from secagent.models import Finding

ROOT = Path(__file__).resolve().parent.parent.parent
RULES = ROOT / "rules" / "embedded-c.yml"
CWE_FROM_RULE = {
    "cwe-787-tp-dt-index": "CWE-787",
    "cwe-20-tp-cm-packages": "CWE-20",
    "cwe-120-memcpy": "CWE-120",
}


class SemgrepAgent:
    name = "semgrep"
    kind = "sast"

    def run(self, target: Path, context: dict) -> list[Finding]:
        if shutil.which("semgrep") is None:
            return []
        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--config",
            str(RULES if RULES.exists() else "p/c"),
            str(target),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if not proc.stdout.strip():
            return []
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for item in payload.get("results", []):
            extra = item.get("extra", {})
            check_id = str(item.get("check_id", "semgrep")).split(".")[-1]
            path = item.get("path", "")
            line = int(item.get("start", {}).get("line", 0))
            cwe = CWE_FROM_RULE.get(check_id, "CWE-20")
            meta = extra.get("metadata") or {}
            if isinstance(meta.get("cwe"), list) and meta["cwe"]:
                cwe = str(meta["cwe"][0]).split(":")[0].replace("CWE-", "CWE-")
                if not cwe.startswith("CWE-"):
                    cwe = f"CWE-{cwe}"
            evidence = extra.get("lines") or extra.get("message") or check_id
            fid = hashlib.sha1(f"{path}:{line}:{check_id}".encode()).hexdigest()[:12]
            findings.append(
                Finding(
                    id=fid,
                    source="semgrep",
                    file=path,
                    line=line,
                    cwe_id=cwe,
                    title=extra.get("message", check_id),
                    evidence=str(evidence).strip()[:500],
                )
            )
        return findings

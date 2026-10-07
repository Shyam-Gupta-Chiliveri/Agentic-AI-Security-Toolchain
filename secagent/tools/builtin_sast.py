"""Always-on C checkers so a demo run works without Semgrep installed."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from secagent.models import Finding

C_GLOB = ("*.c", "*.h")


def _fid(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


class BuiltinSastAgent:
    name = "builtin_sast"
    kind = "sast"

    def run(self, target: Path, context: dict) -> list[Finding]:
        files = _c_files(target)
        findings: list[Finding] = []
        for path in files:
            try:
                rel = str(path.relative_to(target))
            except ValueError:
                rel = str(path)
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            findings.extend(_tp_index(rel, lines))
            findings.extend(_tp_cm_unchecked(rel, lines))
        return findings


def _c_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    files: list[Path] = []
    for pat in C_GLOB:
        files.extend(p for p in target.rglob(pat) if ".git" not in p.parts)
    return files


def _tp_index(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines, start=1):
        if re.search(r"index\s*=\s*data\[0\]\s*-\s*1", line):
            out.append(
                Finding(
                    id=_fid("tp-index", rel, str(i)),
                    source="builtin_sast",
                    file=rel,
                    line=i,
                    cwe_id="CWE-787",
                    title="TP.DT sequence index from frame byte without a lower bound",
                    evidence=line.strip(),
                    suggested_fix=(
                        "If data[0] is 0, uint8_t index wraps to 255 and "
                        "data[index*7] writes past MAX_TP_DT."
                    ),
                )
            )
        if re.search(r"data\[index\s*\*\s*7", line) and "MAX_TP" not in line:
            # Annotate the write site when the index came from the frame.
            if i > 1 and "data[0]" in "\n".join(lines[max(0, i - 4) : i]):
                out.append(
                    Finding(
                        id=_fid("tp-write", rel, str(i)),
                        source="builtin_sast",
                        file=rel,
                        line=i,
                        cwe_id="CWE-787",
                        title="Write into TP.DT buffer using untrusted sequence index",
                        evidence=line.strip(),
                    )
                )
    return out


def _tp_cm_unchecked(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    joined_prev = ""
    for i, line in enumerate(lines, start=1):
        joined_prev = (joined_prev[-200:] + line)
        if "number_of_packages_being_transmitted = data[3]" in line:
            out.append(
                Finding(
                    id=_fid("tp-cm", rel, str(i)),
                    source="builtin_sast",
                    file=rel,
                    line=i,
                    cwe_id="CWE-20",
                    title="TP.CM package count taken from CAN payload without range check",
                    evidence=line.strip(),
                )
            )
    return out

"""Always-on C checkers so a demo run works without Semgrep installed."""

from __future__ import annotations

import re
from pathlib import Path

from secagent.display import short_id
from secagent.models import Finding

C_GLOB = ("*.c", "*.h")

LESSON_INDEX = (
    "What happened: the code takes the first payload byte of a Transport Protocol "
    "Data Transfer (TP.DT) frame, subtracts 1, and uses that as an array index. "
    "That byte comes from the Controller Area Network (CAN) bus, so an attacker can choose it."
)
LESSON_WRAP = (
    "If that byte is 0, an unsigned 8-bit value wraps to 255 (Integer Overflow or "
    "Wraparound, Common Weakness Enumeration CWE-190). The write then lands past the "
    "end of the buffer (Out-of-bounds Write, CWE-787)."
)
LESSON_VEHICLE = (
    "In a vehicle, another Electronic Control Unit (ECU) or a compromised gateway "
    "can send this frame on the bus. The stack may corrupt nearby memory. That is a "
    "cybersecurity weakness on a communication item, in ISO/SAE 21434 language."
)
FIX_INDEX = (
    "Reject sequence number 0. Only compute index = sequence - 1 after checking "
    "1 ≤ sequence ≤ declared package count, and (sequence - 1) × 7 + 6 < size of "
    "the Transport Protocol Data Transfer (TP.DT) buffer (MAX_TP_DT = 1785)."
)
LESSON_CM = (
    "What happened: Transport Protocol Connection Management (TP.CM) copies payload "
    "byte 3 as “how many packages will arrive” and never checks the legal range "
    "(2 to 224 packages, matching at most 1785 bytes)."
)
FIX_CM = (
    "After reading the Connection Management (CM) frame, accept it only if "
    "total message size is 9–1785 bytes and package count is 2–224. Otherwise send "
    "abort and ignore following Data Transfer (DT) writes."
)


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
                    id=short_id("tp-index", rel, str(i)),
                    source="builtin_sast",
                    file=rel,
                    line=i,
                    cwe_id="CWE-787",
                    title="Transport Protocol Data Transfer (TP.DT) sequence index has no lower bound",
                    evidence=line.strip(),
                    suggested_fix=FIX_INDEX,
                    extra=_teach(
                        recommended="true_positive",
                        why_label="The tool is right. Byte 0 is attacker-controlled and 0 wraps the index.",
                        what=LESSON_INDEX + " " + LESSON_WRAP,
                        vehicle=LESSON_VEHICLE,
                    ),
                )
            )
        if re.search(r"data\[index\s*\*\s*7", line) and "MAX_TP" not in line:
            if i > 1 and "data[0]" in "\n".join(lines[max(0, i - 4) : i]):
                out.append(
                    Finding(
                        id=short_id("tp-write", rel, str(i)),
                        source="builtin_sast",
                        file=rel,
                        line=i,
                        cwe_id="CWE-787",
                        title="Write into the Transport Protocol Data Transfer (TP.DT) buffer with that untrusted index",
                        evidence=line.strip(),
                        suggested_fix=FIX_INDEX,
                        extra=_teach(
                            recommended="true_positive",
                            why_label="Same real bug, one line later: this is the actual write past the buffer.",
                            what="This line stores seven payload bytes at index×7. If index wrapped, the write is outside the array.",
                            vehicle=LESSON_VEHICLE,
                        ),
                    )
                )
    return out


def _tp_cm_unchecked(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines, start=1):
        if "number_of_packages_being_transmitted = data[3]" in line:
            out.append(
                Finding(
                    id=short_id("tp-cm", rel, str(i)),
                    source="builtin_sast",
                    file=rel,
                    line=i,
                    cwe_id="CWE-20",
                    title="Transport Protocol Connection Management (TP.CM) package count is not range-checked",
                    evidence=line.strip(),
                    suggested_fix=FIX_CM,
                    extra=_teach(
                        recommended="true_positive",
                        why_label="The tool is right. Byte 3 is trusted as a count with no 2–224 check.",
                        what=LESSON_CM,
                        vehicle=(
                            "A bad Connection Management (CM) frame can announce hundreds of packages. "
                            "Later Data Transfer (DT) writes then follow that lie."
                        ),
                    ),
                )
            )
    return out


def _teach(*, recommended: str, why_label: str, what: str, vehicle: str) -> dict:
    return {
        "recommended_label": recommended,
        "why_this_label": why_label,
        "what_happened": what,
        "why_in_vehicle": vehicle,
        "technique_full": "Static Application Security Testing (SAST)",
    }

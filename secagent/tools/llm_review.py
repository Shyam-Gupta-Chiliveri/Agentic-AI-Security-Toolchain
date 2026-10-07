"""LLM reviewer over C chunks. Skips cleanly if GROQ_API_KEY is missing."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from secagent.display import short_id
from secagent.models import Finding

PROMPT = """You are reviewing embedded C for an automotive CAN/J1939 stack.
Return JSON only: {{"findings":[{{"file":"...","line":0,"cwe_id":"CWE-787","title":"...","evidence":"...","suggested_fix":"..."}}]}}
Only report likely memory-safety or input-validation issues. If none, {{"findings":[]}}.
Code:
{code}
"""


class LlmReviewAgent:
    name = "llm_review"
    kind = "llm"

    def run(self, target: Path, context: dict) -> list[Finding]:
        key = os.getenv("GROQ_API_KEY", "").strip()
        if not key:
            return []
        chunks = _chunks(target)
        if not chunks:
            return []
        try:
            from groq import Groq
        except ImportError:
            return []
        client = Groq(api_key=key)
        findings: list[Finding] = []
        for label, code in chunks[:4]:
            try:
                resp = client.chat.completions.create(
                    model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
                    messages=[{"role": "user", "content": PROMPT.format(code=code[:8000])}],
                    temperature=0,
                )
                text = resp.choices[0].message.content or "{}"
            except Exception:
                text = ""
            if text:
                findings.extend(_parse(text, fallback_file=label))
        return findings


def _chunks(target: Path) -> list[tuple[str, str]]:
    files = [target] if target.is_file() else list(target.rglob("*.c"))
    interesting = [
        p
        for p in files
        if any(
            s in p.name
            for s in (
                "Transport_Protocol",
                "Listen_For_Messages",
                "DM16",
                "Request_Proprietary",
            )
        )
    ]
    out = []
    for path in interesting[:4]:
        out.append((path.name, path.read_text(encoding="utf-8", errors="replace")))
    return out


def _parse(text: str, fallback_file: str) -> list[Finding]:
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return []
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for item in payload.get("findings") or []:
        line = int(item.get("line") or 0)
        cwe = str(item.get("cwe_id") or "CWE-20")
        if not cwe.upper().startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        path = str(item.get("file") or fallback_file)
        fid = short_id("llm", path, str(line), cwe)
        findings.append(
            Finding(
                id=fid,
                source="llm_review",
                file=path,
                line=line,
                cwe_id=cwe.upper(),
                title=str(item.get("title") or "LLM flagged issue"),
                evidence=str(item.get("evidence") or "")[:500],
                suggested_fix=str(item.get("suggested_fix") or ""),
            )
        )
    return findings

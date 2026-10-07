"""Local RAG over CWE / CVE / 21434 concept notes. Optional Qdrant later."""

from __future__ import annotations

import json
from pathlib import Path

from secagent.security import looks_like_injection, rag_source_allowed

ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE = ROOT / "rag" / "knowledge"


class KnowledgeBase:
    def __init__(self, knowledge_dir: Path = KNOWLEDGE, *, allow_untrusted: bool = False):
        self.dir = knowledge_dir
        self.allow_untrusted = allow_untrusted
        self.docs: list[dict] = []
        self.reload()

    def reload(self) -> None:
        self.docs = []
        if not self.dir.exists():
            return
        for path in sorted(self.dir.iterdir()):
            if not path.is_file():
                continue
            if not self.allow_untrusted and not rag_source_allowed(path.name):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if looks_like_injection(text) and not self.allow_untrusted:
                continue
            if path.suffix == ".json":
                payload = json.loads(text)
                if isinstance(payload, list):
                    for item in payload:
                        item = dict(item)
                        item["_source"] = path.name
                        self.docs.append(item)
            else:
                self.docs.append(
                    {
                        "id": path.stem,
                        "summary": text,
                        "url": "",
                        "_source": path.name,
                    }
                )

    def cite_cwe(self, cwe_id: str) -> str:
        cwe_id = cwe_id.upper().replace("CWE-", "CWE-")
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        for doc in self.docs:
            if str(doc.get("id", "")).upper() == cwe_id:
                url = doc.get("url") or "https://cwe.mitre.org/"
                name = doc.get("name", "")
                auto = doc.get("automotive", "")
                return f"{cwe_id} {name}. Source: {url}. {auto}".strip()
        return f"{cwe_id}. Source: https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html"

    def iso_note(self) -> str:
        for doc in self.docs:
            if "iso21434" in str(doc.get("_source", "")).lower():
                return (
                    "Mapped as a candidate weakness on a J1939 communication item "
                    "(original 21434 *concept* notes in-repo — not the ISO text)."
                )
        return ""

    def search(self, query: str, k: int = 3) -> list[dict]:
        tokens = {t.lower() for t in query.replace("-", " ").split() if len(t) > 2}
        scored: list[tuple[int, dict]] = []
        for doc in self.docs:
            blob = json.dumps(doc).lower()
            score = sum(1 for t in tokens if t in blob)
            if score:
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [d for _, d in scored[:k]]

"""Closed-loop triage labels stored as JSON."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from secagent.models import Finding

ROOT = Path(__file__).resolve().parent.parent
LABELS_PATH = ROOT / "data" / "labels.json"


def load_labels(path: Path = LABELS_PATH) -> dict[str, str]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_labels(labels: dict[str, str], path: Path = LABELS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(labels, indent=2), encoding="utf-8")


def apply_labels(findings: list[Finding], labels: dict[str, str]) -> list[Finding]:
    for finding in findings:
        key = _key(finding)
        if key in labels:
            finding.triage = labels[key]  # type: ignore[assignment]
    return findings


def record(finding: Finding, triage: str, path: Path = LABELS_PATH) -> None:
    labels = load_labels(path)
    labels[_key(finding)] = triage
    save_labels(labels, path)


def _key(finding: Finding) -> str:
    return f"{finding.file}:{finding.line}:{finding.cwe_id}"


def ranking_boost(finding: Finding, labels: dict[str, str]) -> float:
    """Down-rank CWE/file pairs that were often false positives."""
    cwe = finding.cwe_id
    counts: Counter[str] = Counter()
    for key, value in labels.items():
        if key.endswith(f":{cwe}"):
            counts[value] += 1
    fp = counts.get("false_positive", 0)
    tp = counts.get("true_positive", 0)
    if fp + tp == 0:
        return 0.0
    return (tp - fp) / (tp + fp)

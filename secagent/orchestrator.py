from __future__ import annotations

import os
import time
from pathlib import Path

from secagent.critic import review
from secagent.labels import apply_labels, load_labels
from secagent.models import Finding
from secagent.observability import LOG, setup_logging, write_run
from secagent.rag import KnowledgeBase
from secagent.routing import route_agents
from secagent.tools import AGENTS

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = ROOT / "vendor" / "Open-SAE-J1939" / "Src"
RUNS = ROOT / "data" / "runs"


def run_scan(
    query: str = "full",
    target: Path | None = None,
    *,
    allow_untrusted_rag: bool = False,
) -> dict:
    setup_logging()
    target = target or DEFAULT_TARGET
    kb = KnowledgeBase(allow_untrusted=allow_untrusted_rag)
    labels = load_labels()
    planned = route_agents(
        query,
        target=target,
        has_sarif=Path(os.getenv("CODEQL_SARIF") or "").is_file(),
        has_crashes=(ROOT / "fuzz" / "out").exists(),
    )
    LOG.info("router planned=%s target=%s", planned, target)

    raw: list[Finding] = []
    producer_counts: dict[str, int] = {}
    context = {"query": query}
    for name in planned:
        if name == "critic":
            continue
        agent = AGENTS.get(name)
        if agent is None:
            continue
        started = time.perf_counter()
        try:
            batch = agent.run(target, context)
        except Exception as exc:  # tool failure must not kill the run
            LOG.exception("agent %s failed: %s", name, exc)
            batch = []
        producer_counts[name] = len(batch)
        LOG.info("agent=%s findings=%s elapsed_s=%.3f", name, len(batch), time.perf_counter() - started)
        raw.extend(batch)

    before = len(raw)
    criticised = review(raw, kb, labels)
    apply_labels(criticised, labels)
    dropped = before - len(criticised)

    report = {
        "target": str(target),
        "planned_agents": planned,
        "producer_counts": producer_counts,
        "findings_before_critic": before,
        "findings_after_critic": len(criticised),
        "dropped_as_noise": dropped,
        "untrusted_rag": allow_untrusted_rag,
        "findings": [f.to_dict() for f in criticised],
    }
    write_run(RUNS / "latest.json", report)
    return report

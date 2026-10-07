from __future__ import annotations

import json
import logging
import time
from pathlib import Path

LOG = logging.getLogger("secagent")


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def timed(name: str):
    def deco(fn):
        def wrap(*args, **kwargs):
            start = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                LOG.info("agent=%s elapsed_s=%.3f", name, time.perf_counter() - start)

        return wrap

    return deco


def write_run(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    LOG.info("wrote run report %s", path)

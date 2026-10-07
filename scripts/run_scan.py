#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from secagent.orchestrator import DEFAULT_TARGET, run_scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the J1939 security toolchain")
    parser.add_argument("--query", default="full")
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--untrusted-rag", action="store_true")
    args = parser.parse_args()
    report = run_scan(args.query, args.target, allow_untrusted_rag=args.untrusted_rag)
    print(json.dumps({k: report[k] for k in report if k != "findings"}, indent=2))
    print(f"findings={len(report['findings'])} written to data/runs/latest.json")


if __name__ == "__main__":
    main()

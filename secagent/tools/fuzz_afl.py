"""Read AFL++ crash files if a campaign was run. Does not start AFL by itself."""

from __future__ import annotations

from pathlib import Path

from secagent.models import Finding

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CRASHES = ROOT / "fuzz" / "out" / "default" / "crashes"


class AflAgent:
    name = "afl"
    kind = "fuzz"

    def run(self, target: Path, context: dict) -> list[Finding]:
        crash_dir = Path(context.get("crash_dir") or DEFAULT_CRASHES)
        if not crash_dir.exists():
            return []
        crashes = [
            p
            for p in crash_dir.iterdir()
            if p.is_file() and p.name != "README.txt"
        ]
        if not crashes:
            return []
        sample = crashes[0]
        return [
            Finding(
                id="afl-tp-dt",
                source="afl",
                file="SAE_J1939-21_Transport_Layer/Transport_Protocol_Data_Transfer.c",
                line=23,
                cwe_id="CWE-787",
                title=f"AFL++ crash on TP.DT harness ({len(crashes)} unique crash file(s))",
                evidence=f"First crash: {sample.name} ({sample.stat().st_size} bytes)",
                extra={"crash_count": len(crashes)},
            )
        ]

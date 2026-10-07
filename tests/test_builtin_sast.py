from pathlib import Path

from secagent.tools.builtin_sast import BuiltinSastAgent

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "vendor" / "Open-SAE-J1939" / "Src"


def test_finds_tp_dt_index():
    findings = BuiltinSastAgent().run(TARGET, {})
    cwes = {f.cwe_id for f in findings}
    files = " ".join(f.file for f in findings)
    assert "CWE-787" in cwes
    assert "Transport_Protocol_Data_Transfer.c" in files

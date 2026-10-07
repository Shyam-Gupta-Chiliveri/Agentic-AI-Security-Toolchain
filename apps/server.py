from __future__ import annotations

import json
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

from secagent.injection_demo import run_demo
from secagent.labels import load_labels, record
from secagent.models import Finding
from secagent.orchestrator import DEFAULT_TARGET, run_scan

STATIC = Path(__file__).resolve().parent / "static"
RUNS = ROOT / "data" / "runs" / "latest.json"

app = FastAPI(title="J1939 security desk", version="0.1.0")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class ScanRequest(BaseModel):
    query: str = "sast"


class LabelRequest(BaseModel):
    file: str
    line: int
    cwe_id: str
    title: str = ""
    source: str = "builtin_sast"
    evidence: str = ""
    triage: str = Field(pattern="^(unreviewed|true_positive|false_positive)$")


def _load_report() -> dict | None:
    if not RUNS.exists():
        return None
    return json.loads(RUNS.read_text(encoding="utf-8"))


@app.get("/")
def home() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "j1939-security-desk"}


@app.get("/api/report")
def api_report() -> dict:
    report = _load_report()
    if report is None:
        return {"findings": [], "planned_agents": []}
    return report


@app.post("/api/scan")
def api_scan(body: ScanRequest) -> dict:
    return run_scan(query=body.query, target=DEFAULT_TARGET)


@app.post("/api/label")
def api_label(body: LabelRequest) -> dict:
    finding = Finding(
        id=f"{body.file}:{body.line}:{body.cwe_id}",
        source=body.source,
        file=body.file,
        line=body.line,
        cwe_id=body.cwe_id,
        title=body.title or body.cwe_id,
        evidence=body.evidence,
    )
    record(finding, body.triage)
    return {"ok": True, "labels": load_labels()}


@app.get("/api/injection")
def api_injection() -> dict:
    raw = run_demo()
    return {
        **raw,
        "plain": {
            "filter_saw_attack": (
                "Yes. The text asked the model to ignore previous instructions."
                if raw["malicious_text_detected"]
                else "No attack phrase found."
            ),
            "without_filter": (
                "Without the allow-list, the poisoned document is loaded into Retrieval-Augmented Generation (RAG)."
                if raw["poison_loaded_without_filter"]
                else "The poisoned document was not loaded."
            ),
            "with_filter": (
                "With the allow-list, poison.md is skipped. Only Common Weakness Enumeration (CWE), "
                "Common Vulnerabilities and Exposures (CVE), and ISO/SAE 21434 concept notes are trusted."
                if not raw["poison_loaded_with_filter"]
                else "The filter failed — poison was still loaded."
            ),
        },
    }


@app.get("/api/labels")
def api_labels() -> dict:
    return load_labels()

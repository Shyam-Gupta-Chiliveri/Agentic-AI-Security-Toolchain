from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from secagent.injection_demo import run_demo
from secagent.labels import LABELS_PATH, load_labels, record
from secagent.models import Finding
from secagent.orchestrator import DEFAULT_TARGET, run_scan

st.set_page_config(
    page_title="J1939 security desk",
    page_icon=":material/security:",
    layout="wide",
)


def _latest_report() -> dict | None:
    path = ROOT / "data" / "runs" / "latest.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


st.title("Automotive AI security desk")
st.caption(
    "Agentic toolchain for Open-SAE-J1939 (MIT). "
    "Finds weaknesses in open-source C — research/portfolio, not a 21434 CSMS."
)

with st.container(horizontal=True):
    query = st.text_input(
        "What should the router run?",
        value="full",
        help="Examples: full, sast, fuzz, llm review",
    )
    run_clicked = st.button("Run scan", type="primary", icon=":material/play_arrow:")

if run_clicked:
    with st.spinner("Router is dispatching tool agents…"):
        report = run_scan(query=query, target=DEFAULT_TARGET)
        st.session_state["report"] = report
else:
    report = st.session_state.get("report") or _latest_report()

if not report:
    st.info("Run a scan to list findings. Builtin SAST works without Semgrep or Groq.")
    st.stop()

findings = [Finding.from_dict(row) for row in report.get("findings", [])]
fp = sum(1 for f in findings if f.triage == "false_positive")
tp = sum(1 for f in findings if f.triage == "true_positive")
unrev = sum(1 for f in findings if f.triage == "unreviewed")

with st.container(horizontal=True):
    st.metric("After critic", report.get("findings_after_critic", len(findings)), border=True)
    st.metric("Dropped as noise", report.get("dropped_as_noise", 0), border=True)
    st.metric("True positive labels", tp, border=True)
    st.metric("False positive labels", fp, border=True)

st.subheader("Router plan")
st.write(", ".join(report.get("planned_agents", [])))
st.write(report.get("producer_counts", {}))

st.subheader("Findings")
if not findings:
    st.write("No findings kept.")
    st.stop()

table = pd.DataFrame(
    [
        {
            "file": f.file,
            "line": f.line,
            "cwe": f.cwe_id,
            "severity": f.severity,
            "source": f.source,
            "title": f.title,
            "triage": f.triage,
        }
        for f in findings
    ]
)
st.dataframe(table, width="stretch", hide_index=True)

selected = st.selectbox(
    "Open a finding",
    options=list(range(len(findings))),
    format_func=lambda i: f"{findings[i].cwe_id} · {findings[i].file}:{findings[i].line}",
)
finding = findings[selected]
with st.container(border=True):
    st.markdown(f"**{finding.title}**")
    st.write(f"{finding.file}:{finding.line} · {finding.source} · {finding.severity}")
    st.code(finding.evidence or "(no snippet)")
    st.write(finding.rag_citation)
    st.write(finding.iso21434_note)
    st.write("Suggested fix")
    st.write(finding.suggested_fix)
    st.caption(finding.critic_rationale)
    decision = st.segmented_control(
        "Triage label (closed-loop feedback)",
        options=["unreviewed", "true_positive", "false_positive"],
        default=finding.triage,
        key=f"triage-{finding.id}",
    )
    if st.button("Save label", icon=":material/save:"):
        record(finding, decision)
        finding.triage = decision  # type: ignore[assignment]
        st.success(f"Stored in {LABELS_PATH.name}. Next scan will use this for ranking.")

st.subheader("Security of AI — prompt injection")
demo = run_demo()
st.write(
    "A malicious `poison.md` is in the knowledge folder. "
    "Without the filter it is loaded; with the allow-list it is skipped."
)
st.json(demo)

labels = load_labels()
if labels:
    st.subheader("Stored labels")
    st.json(labels)

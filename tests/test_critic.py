from secagent.critic import review
from secagent.models import Finding
from secagent.rag import KnowledgeBase


def test_critic_maps_cwe_and_drops_noise():
    kb = KnowledgeBase()
    keep = Finding(
        id="1",
        source="builtin_sast",
        file="tp.c",
        line=23,
        cwe_id="CWE-787",
        title="OOB write",
        evidence="index = data[0] - 1",
    )
    noise = Finding(
        id="2",
        source="llm_review",
        file="x.c",
        line=1,
        cwe_id="CWE-20",
        title="TODO comment leftover",
        evidence="// TODO",
    )
    out = review([keep, noise], kb, {})
    assert len(out) == 1
    assert out[0].cwe_id == "CWE-787"
    assert "cwe.mitre.org" in out[0].rag_citation.lower()
    assert out[0].severity == "high"

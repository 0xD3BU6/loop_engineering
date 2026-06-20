from datetime import UTC, datetime
import json

from loop_engineering.ioc import ReportBundle


SAMPLES = [
    {
        "sha256_hash": "a" * 64,
        "sha1_hash": "b" * 40,
        "md5_hash": "c" * 32,
        "file_name": "invoice.exe",
        "file_type": "exe",
        "first_seen": "2026-06-20 00:01:02",
        "signature": "ExampleRAT",
        "tags": ["rat", "exe"],
    }
]


def test_report_bundle_extracts_hash_iocs():
    bundle = ReportBundle(
        generated_at=datetime(2026, 6, 20, tzinfo=UTC),
        selector="100",
        samples=SAMPLES,
    )

    iocs = bundle.iocs

    assert {ioc["type"] for ioc in iocs} == {"SHA-256", "SHA-1", "MD5"}
    assert all(ioc["source"] == "MalwareBazaar" for ioc in iocs)
    assert all(ioc["malware_family"] == "ExampleRAT" for ioc in iocs)


def test_stix_contains_file_hash_indicator():
    bundle = ReportBundle(
        generated_at=datetime(2026, 6, 20, tzinfo=UTC),
        selector="100",
        samples=SAMPLES,
    )

    stix = json.loads(bundle.to_stix_json())
    indicators = [item for item in stix["objects"] if item["type"] == "indicator"]

    assert len(indicators) == 1
    assert indicators[0]["pattern"] == "[file:hashes.'SHA-256' = '" + ("a" * 64) + "']"


def test_markdown_labels_proof_of_compromise_not_exploit_poc():
    bundle = ReportBundle(
        generated_at=datetime(2026, 6, 20, tzinfo=UTC),
        selector="100",
        samples=SAMPLES,
    )

    report = bundle.to_markdown()

    assert "Proof Of Compromise" in report
    assert "not exploit proof-of-concept code" in report


def test_metadata_report_generates_blog_and_yara():
    bundle = ReportBundle(
        generated_at=datetime(2026, 6, 20, tzinfo=UTC),
        selector="100",
        samples=SAMPLES,
    )

    blog = bundle.to_blog_markdown()
    yara = bundle.to_yara_rules()

    assert "What The Agent Did" in blog
    assert "IOC Summary" in blog
    assert "YARA Rules" in blog
    assert 'import "hash"' in yara
    assert "hash.sha256(0, filesize)" in yara
    assert "a" * 64 in yara

"""Filesystem output helpers for generated intelligence reports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from loop_engineering.ioc import ReportBundle


@dataclass(frozen=True)
class WrittenReports:
    report_dir: Path
    markdown: Path
    blog: Path
    ioc_json: Path
    ioc_csv: Path
    stix_json: Path
    yara: Path


def write_report_bundle(bundle: ReportBundle, reports_dir: Path) -> WrittenReports:
    day = bundle.generated_at.strftime("%Y-%m-%d")
    target_dir = reports_dir / day
    target_dir.mkdir(parents=True, exist_ok=True)

    markdown = target_dir / "malwarebazaar-report.md"
    blog = target_dir / "technical-analysis.md"
    ioc_json = target_dir / "iocs.json"
    ioc_csv = target_dir / "iocs.csv"
    stix_json = target_dir / "stix.json"
    yara = target_dir / "malwarebazaar-hash-iocs.yar"

    markdown.write_text(bundle.to_markdown(), encoding="utf-8")
    blog.write_text(bundle.to_blog_markdown(), encoding="utf-8")
    ioc_json.write_text(bundle.to_ioc_json(), encoding="utf-8")
    ioc_csv.write_text(bundle.to_ioc_csv(), encoding="utf-8")
    stix_json.write_text(bundle.to_stix_json(), encoding="utf-8")
    yara.write_text(bundle.to_yara_rules(), encoding="utf-8")

    return WrittenReports(
        report_dir=target_dir,
        markdown=markdown,
        blog=blog,
        ioc_json=ioc_json,
        ioc_csv=ioc_csv,
        stix_json=stix_json,
        yara=yara,
    )

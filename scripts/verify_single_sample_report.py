#!/usr/bin/env python3
"""Verify sanitized single-sample malware analysis outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REQUIRED_FILES = {
    "technical-analysis.md",
    "analysis.json",
    "iocs.json",
    "sample.yar",
    "reviewer-prompt.md",
}
FORBIDDEN_SUFFIXES = {
    ".bin",
    ".dll",
    ".elf",
    ".exe",
    ".js",
    ".ps1",
    ".py",
    ".sample",
    ".sh",
    ".vbs",
    ".zip",
}
REQUIRED_BLOG_SECTIONS = [
    "## What The Agent Did",
    "## Sample Identity",
    "## Static Triage",
    "## IOCs",
    "## Static Findings",
    "## YARA Rules",
    "## Analyst Assessment",
    "## Verification Notes",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify single-sample report output")
    parser.add_argument("report_dir", type=Path)
    args = parser.parse_args(argv)

    findings = verify_report_dir(args.report_dir)
    if findings:
        for finding in findings:
            print(f"error: {finding}", file=sys.stderr)
        return 1
    print(f"verified={args.report_dir}")
    return 0


def verify_report_dir(report_dir: Path) -> list[str]:
    findings: list[str] = []
    if not report_dir.exists():
        return [f"report directory does not exist: {report_dir}"]
    present = {path.name for path in report_dir.iterdir() if path.is_file()}
    missing = REQUIRED_FILES - present
    if missing:
        findings.append(f"missing required files: {', '.join(sorted(missing))}")

    forbidden = [
        path.name
        for path in report_dir.iterdir()
        if path.is_file() and path.suffix.lower() in FORBIDDEN_SUFFIXES
    ]
    if forbidden:
        findings.append(f"raw or executable-looking files present in report output: {', '.join(sorted(forbidden))}")

    blog_path = report_dir / "technical-analysis.md"
    analysis_path = report_dir / "analysis.json"
    yara_path = report_dir / "sample.yar"
    ioc_path = report_dir / "iocs.json"

    if blog_path.exists():
        blog = blog_path.read_text(encoding="utf-8")
        for section in REQUIRED_BLOG_SECTIONS:
            if section not in blog:
                findings.append(f"technical blog missing section: {section}")
        unsupported_phrases = [
            "dynamic analysis showed",
            "sandbox observed",
            "executed the sample",
            "runtime behavior confirmed",
        ]
        for phrase in unsupported_phrases:
            if phrase in blog.lower():
                findings.append(f"technical blog contains unsupported dynamic-analysis phrase: {phrase}")

    analysis = {}
    if analysis_path.exists():
        try:
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            findings.append(f"analysis.json is invalid JSON: {exc}")
        if isinstance(analysis, dict):
            for field in ["sha256", "md5", "sha1", "static_code", "selected_strings"]:
                if field not in analysis:
                    findings.append(f"analysis.json missing field: {field}")

    if ioc_path.exists():
        try:
            iocs = json.loads(ioc_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            findings.append(f"iocs.json is invalid JSON: {exc}")
        else:
            if not isinstance(iocs, dict) or not iocs.get("iocs"):
                findings.append("iocs.json has no IOC entries")

    if yara_path.exists():
        yara = yara_path.read_text(encoding="utf-8")
        if "condition:" not in yara:
            findings.append("sample.yar missing condition")
        if "sample not executed" not in yara:
            findings.append("sample.yar missing static-analysis safety metadata")
        sha256 = analysis.get("sha256") if isinstance(analysis, dict) else None
        if sha256 and sha256 not in yara:
            findings.append("sample.yar does not include analyzed SHA-256")

    return findings


if __name__ == "__main__":
    raise SystemExit(main())

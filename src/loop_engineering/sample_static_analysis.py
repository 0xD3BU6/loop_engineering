"""Single-sample static malware analysis.

This module analyzes one downloaded sample at a time from inert bytes. It does
not execute samples, import source, load binaries, or fetch discovered URLs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any

from loop_engineering.static_code_analysis import (
    StaticCodeReport,
    analyze_source_text,
    render_static_code_yara,
)


PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{5,}")
SOURCE_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".hta",
    ".js",
    ".jse",
    ".lua",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".sh",
    ".vba",
    ".vbe",
    ".vbs",
    ".wsf",
}
SOURCE_TYPES = {
    "bash",
    "batch",
    "javascript",
    "js",
    "php",
    "powershell",
    "python",
    "script",
    "shell",
    "text",
    "vba",
    "vbs",
}
SUSPICIOUS_STRING_MARKERS = [
    "cmd.exe",
    "powershell",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "frombase64string",
    "eval(",
    "exec(",
    "wscript",
    "cscript",
    "reg add",
    "schtasks",
    "crontab",
    "/bin/sh",
    "http://",
    "https://",
]


@dataclass(frozen=True)
class SingleSampleAnalysis:
    generated_at: datetime
    metadata: dict[str, Any]
    source_name: str
    byte_count: int
    md5: str
    sha1: str
    sha256: str
    entropy: float
    file_magic: str
    printable_string_count: int
    selected_strings: list[str]
    static_code: StaticCodeReport

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["generated_at"] = self.generated_at.isoformat()
        data["static_code"] = self.static_code.to_dict()
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    def to_ioc_json(self) -> str:
        iocs: list[dict[str, str]] = [
            {"type": "MD5", "value": self.md5, "source": "single-sample-static-analysis"},
            {"type": "SHA-1", "value": self.sha1, "source": "single-sample-static-analysis"},
            {"type": "SHA-256", "value": self.sha256, "source": "single-sample-static-analysis"},
        ]
        iocs.extend({"type": "URL", "value": value, "source": "single-sample-static-analysis"} for value in self.static_code.urls)
        iocs.extend({"type": "IP", "value": value, "source": "single-sample-static-analysis"} for value in self.static_code.ips)
        iocs.extend(
            {"type": "DOMAIN", "value": value, "source": "single-sample-static-analysis"}
            for value in self.static_code.domains
        )
        return json.dumps(
            {
                "generated_at": self.generated_at.isoformat(),
                "source": "single-sample-static-analysis",
                "sha256": self.sha256,
                "iocs": iocs,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"

    def to_yara(self) -> str:
        static_yara = render_static_code_yara(self.static_code)
        strings = unique_preserve_order(self.selected_strings)[:20]
        lines = [
            'import "hash"',
            "",
            f"rule Single_Sample_Static_{self.sha256[:16]}",
            "{",
            "  meta:",
            '    source = "loop-engineering single-sample static analysis"',
            '    analysis = "static only; sample not executed"',
            f'    sha256 = "{self.sha256}"',
            f'    md5 = "{self.md5}"',
            f'    sha1 = "{self.sha1}"',
            f'    file_magic = "{sanitize_yara_string(self.file_magic)}"',
            f'    malwarebazaar_family = "{sanitize_yara_string(str(self.metadata.get("signature") or "unknown"))}"',
            "  strings:",
        ]
        if strings:
            for index, value in enumerate(strings, start=1):
                lines.append(f'    $s{index:02d} = "{sanitize_yara_string(value)}" nocase')
            condition = f'hash.sha256(0, filesize) == "{self.sha256}" or 2 of ($s*)'
        else:
            lines.append('    $placeholder = "no_selected_static_strings"')
            condition = f'hash.sha256(0, filesize) == "{self.sha256}"'
        lines.extend(["  condition:", f"    {condition}", "}", "", static_yara.strip(), ""])
        return "\n".join(lines)

    def to_blog_markdown(self) -> str:
        family = self.metadata.get("signature") or "unknown"
        file_name = self.metadata.get("file_name") or self.source_name
        file_type = self.metadata.get("file_type") or "unknown"
        tags = self.metadata.get("tags") or []
        tag_text = ", ".join(str(tag) for tag in tags) if isinstance(tags, list) else str(tags)
        findings = self.static_code.findings
        lines = [
            f"# Single-Sample Static Malware Analysis - `{self.sha256[:16]}`",
            "",
            "## Executive Summary",
            "",
            (
                f"The agent selected one MalwareBazaar submission and performed static analysis on that "
                f"single artifact. The sample was not executed, loaded, imported, or dynamically tested. "
                f"Static evidence produced {3 + len(self.static_code.urls) + len(self.static_code.ips) + len(self.static_code.domains)} IOCs "
                f"and {len(findings)} code/string findings."
            ),
            "",
            "## What The Agent Did",
            "",
            "1. Pulled recent MalwareBazaar metadata.",
            "2. Selected one unprocessed or source-preferred candidate.",
            "3. Downloaded only that sample's password-protected ZIP into quarantine.",
            "4. Read one archived member into memory for static analysis.",
            "5. Calculated hashes, entropy, file magic, printable strings, IOCs, and suspicious code/string patterns.",
            "6. Generated this technical blog, structured JSON, IOC JSON, YARA, and a verifier prompt.",
            "",
            "## Sample Identity",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| MalwareBazaar SHA-256 | `{self.metadata.get('sha256_hash') or 'unknown'}` |",
            f"| Analyzed SHA-256 | `{self.sha256}` |",
            f"| Family label | `{family}` |",
            f"| File name | `{file_name}` |",
            f"| Archived member | `{self.source_name}` |",
            f"| File type | `{file_type}` |",
            f"| First seen | `{self.metadata.get('first_seen') or 'unknown'}` |",
            f"| Tags | `{tag_text or 'none'}` |",
            "",
            "## Static Triage",
            "",
            "| Property | Value |",
            "|---|---:|",
            f"| Bytes analyzed | {self.byte_count} |",
            f"| Entropy | {self.entropy} |",
            f"| Printable strings | {self.printable_string_count} |",
            f"| File magic | `{self.file_magic}` |",
            "",
            "## IOCs",
            "",
            "| Type | Value |",
            "|---|---|",
            f"| MD5 | `{self.md5}` |",
            f"| SHA-1 | `{self.sha1}` |",
            f"| SHA-256 | `{self.sha256}` |",
        ]
        lines.extend(f"| URL | `{value}` |" for value in self.static_code.urls)
        lines.extend(f"| IP | `{value}` |" for value in self.static_code.ips)
        lines.extend(f"| Domain | `{value}` |" for value in self.static_code.domains)
        lines.extend(
            [
                "",
                "## Static Findings",
                "",
                "| Severity | Category | Evidence | Detail |",
                "|---|---|---|---|",
            ]
        )
        if findings:
            lines.extend(
                f"| {finding.severity} | {finding.category} | `{finding.value}` | {finding.detail} |"
                for finding in findings
            )
        else:
            lines.append("| info | none |  | No suspicious source/string patterns were detected by the static rules. |")
        lines.extend(
            [
                "",
                "## Selected Strings",
                "",
                "These strings were selected because they contain network indicators or suspicious execution markers.",
                "",
                "| String |",
                "|---|",
            ]
        )
        if self.selected_strings:
            lines.extend(f"| `{truncate_markdown(value, 180)}` |" for value in self.selected_strings[:30])
        else:
            lines.append("| none |")
        lines.extend(
            [
                "",
                "## YARA Rules",
                "",
                "The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.",
                "",
                "```yara",
                self.to_yara().strip(),
                "```",
                "",
                "## Analyst Assessment",
                "",
                render_assessment(self),
                "",
                "## Verification Notes",
                "",
                "- A second agent should verify that the blog claims are supported by `analysis.json` and `sample.yar`.",
                "- No dynamic behavior should be asserted unless a future static source analysis produces supporting evidence.",
                "- The raw sample ZIP remains in `quarantine/` and must not be committed.",
            ]
        )
        return "\n".join(lines) + "\n"


def select_single_candidate(samples: list[dict[str, Any]], seen_hashes: set[str]) -> dict[str, Any]:
    unseen = [sample for sample in samples if str(sample.get("sha256_hash") or "").lower() not in seen_hashes]
    pool = unseen or samples
    if not pool:
        raise ValueError("No MalwareBazaar candidates available")
    return sorted(pool, key=candidate_score, reverse=True)[0]


def candidate_score(sample: dict[str, Any]) -> tuple[int, str]:
    file_name = str(sample.get("file_name") or "").lower()
    file_type = str(sample.get("file_type") or "").lower()
    tags = " ".join(str(tag).lower() for tag in (sample.get("tags") or []))
    extension = Path(file_name).suffix
    source_like = extension in SOURCE_EXTENSIONS or file_type in SOURCE_TYPES or any(kind in tags for kind in SOURCE_TYPES)
    tagged = bool(sample.get("tags"))
    known_family = bool(sample.get("signature"))
    return (int(source_like) * 100 + int(tagged) * 10 + int(known_family), str(sample.get("first_seen") or ""))


def analyze_sample_bytes(data: bytes, metadata: dict[str, Any], *, source_name: str) -> SingleSampleAnalysis:
    strings = extract_printable_strings(data)
    text = decode_text_for_analysis(data, strings)
    static_code = analyze_source_text(text, language_hint=infer_language(metadata, source_name))
    selected_strings = select_interesting_strings(strings, static_code)
    return SingleSampleAnalysis(
        generated_at=datetime.now(UTC),
        metadata=metadata,
        source_name=source_name,
        byte_count=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        entropy=round(byte_entropy(data), 3),
        file_magic=detect_file_magic(data),
        printable_string_count=len(strings),
        selected_strings=selected_strings,
        static_code=static_code,
    )


def extract_printable_strings(data: bytes, *, limit: int = 5000) -> list[str]:
    strings = []
    for match in PRINTABLE_RE.finditer(data):
        value = match.group(0).decode("utf-8", errors="ignore").strip()
        if value:
            strings.append(value)
        if len(strings) >= limit:
            break
    return strings


def decode_text_for_analysis(data: bytes, strings: list[str]) -> str:
    null_ratio = data.count(b"\x00") / max(len(data), 1)
    if null_ratio < 0.05:
        for encoding in ("utf-8", "utf-16le", "latin-1"):
            try:
                decoded = data.decode(encoding)
            except UnicodeDecodeError:
                continue
            if decoded.count("\ufffd") < 5:
                return decoded
    return "\n".join(strings[:5000])


def select_interesting_strings(strings: list[str], static_code: StaticCodeReport) -> list[str]:
    selected: list[str] = []
    indicators = set(static_code.urls + static_code.ips + static_code.domains)
    for value in strings:
        lower = value.lower()
        if any(indicator in value for indicator in indicators) or any(marker in lower for marker in SUSPICIOUS_STRING_MARKERS):
            selected.append(value)
    return unique_preserve_order(selected)[:50]


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def detect_file_magic(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE/MZ executable"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"#!/"):
        return "script with shebang"
    if data[:64].lstrip().startswith((b"<?php", b"<script", b"function", b"var ", b"import ", b"from ")):
        return "source-like text"
    return data[:8].hex(" ") or "empty"


def infer_language(metadata: dict[str, Any], source_name: str) -> str:
    extension = Path(source_name.lower()).suffix
    if extension in {".js", ".jse"}:
        return "javascript"
    if extension == ".ps1":
        return "powershell"
    if extension == ".py":
        return "python"
    if extension in {".sh", ".bash"}:
        return "shell"
    if extension in {".vbs", ".vbe", ".vba"}:
        return "vbscript"
    if extension == ".php":
        return "php"
    return str(metadata.get("file_type") or "unknown")


def write_single_sample_outputs(analysis: SingleSampleAnalysis, reports_dir: Path) -> Path:
    day = analysis.generated_at.strftime("%Y-%m-%d")
    target = reports_dir / day / "samples" / analysis.sha256
    target.mkdir(parents=True, exist_ok=True)
    (target / "technical-analysis.md").write_text(analysis.to_blog_markdown(), encoding="utf-8")
    (target / "analysis.json").write_text(analysis.to_json(), encoding="utf-8")
    (target / "iocs.json").write_text(analysis.to_ioc_json(), encoding="utf-8")
    (target / "sample.yar").write_text(analysis.to_yara(), encoding="utf-8")
    (target / "reviewer-prompt.md").write_text(render_reviewer_prompt(target), encoding="utf-8")
    return target


def render_reviewer_prompt(report_dir: Path) -> str:
    return f"""# Reviewer prompt

Review the single-sample malware analysis in `{report_dir}`.

Check:

1. `technical-analysis.md` claims are supported by `analysis.json`.
2. `sample.yar` uses static indicators only and does not contain exploit logic.
3. The report does not claim dynamic behavior that was not observed.
4. No raw malware bytes are present in the report directory.
5. The output is useful as a defensive technical blog.

Return findings first, then a short approval or requested changes.
"""


def render_assessment(analysis: SingleSampleAnalysis) -> str:
    parts = []
    family = analysis.metadata.get("signature") or "unknown"
    if family != "unknown":
        parts.append(f"MalwareBazaar labels this sample as `{family}`, so triage should start with that family context.")
    else:
        parts.append("MalwareBazaar did not provide a family label; treat this as an unknown sample until corroborated.")
    if analysis.static_code.urls or analysis.static_code.ips or analysis.static_code.domains:
        parts.append("Static strings expose network indicators that can support enrichment and hunting.")
    if any(finding.severity == "high" for finding in analysis.static_code.findings):
        parts.append("High-severity static patterns were found, especially execution or script-loading indicators.")
    if analysis.entropy >= 7:
        parts.append("High entropy suggests packing, encryption, compression, or dense binary content.")
    if not analysis.static_code.findings:
        parts.append("The static rule set did not find source-like behavior markers; further insight requires richer static features.")
    return " ".join(parts)


def unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def sanitize_yara_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")[:220]


def truncate_markdown(value: str, limit: int) -> str:
    value = value.replace("|", "\\|").replace("\n", " ")
    return value if len(value) <= limit else value[: limit - 3] + "..."

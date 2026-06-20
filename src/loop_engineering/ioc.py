"""IOC normalization and report rendering."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
import csv
import io
import json
from typing import Any
from uuid import uuid5, NAMESPACE_URL


HASH_FIELDS = {
    "md5_hash": "MD5",
    "sha1_hash": "SHA-1",
    "sha256_hash": "SHA-256",
    "sha3_384_hash": "SHA3-384",
    "imphash": "IMPHASH",
    "tlsh": "TLSH",
    "telfhash": "TELFHASH",
    "gimphash": "GIMPHASH",
    "ssdeep": "SSDEEP",
    "dhash_icon": "ICON-DHASH",
}


@dataclass(frozen=True)
class ReportBundle:
    generated_at: datetime
    selector: str
    samples: list[dict[str, Any]]

    @property
    def iocs(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for sample in self.samples:
            for field, kind in HASH_FIELDS.items():
                value = sample.get(field)
                if not value:
                    continue
                rows.append(
                    {
                        "type": kind,
                        "value": str(value),
                        "sha256": sample.get("sha256_hash", ""),
                        "malware_family": sample.get("signature") or "unknown",
                        "file_name": sample.get("file_name") or "",
                        "file_type": sample.get("file_type") or "",
                        "first_seen": sample.get("first_seen") or "",
                        "source": "MalwareBazaar",
                    }
                )
        return rows

    def to_markdown(self) -> str:
        family_counts = Counter((sample.get("signature") or "unknown") for sample in self.samples)
        file_type_counts = Counter((sample.get("file_type") or "unknown") for sample in self.samples)
        lines = [
            "# MalwareBazaar Intelligence Report",
            "",
            f"- Generated: {self.generated_at.isoformat()}",
            f"- Selector: `{self.selector}`",
            f"- Samples: {len(self.samples)}",
            f"- IOCs: {len(self.iocs)}",
            "- Handling: metadata-only report; raw malware is not included.",
            "",
            "## Top Families",
            "",
            "| Family | Samples |",
            "|---|---:|",
        ]
        lines.extend(f"| {family} | {count} |" for family, count in family_counts.most_common(10))
        lines.extend(
            [
                "",
                "## File Types",
                "",
                "| File type | Samples |",
                "|---|---:|",
            ]
        )
        lines.extend(f"| {file_type} | {count} |" for file_type, count in file_type_counts.most_common(10))
        lines.extend(
            [
                "",
                "## Samples",
                "",
                "| SHA256 | Family | Type | First seen | Tags |",
                "|---|---|---|---|---|",
            ]
        )
        for sample in self.samples:
            tags = sample.get("tags") or []
            tag_text = ", ".join(str(tag) for tag in tags) if isinstance(tags, list) else str(tags)
            lines.append(
                "| {sha256} | {family} | {file_type} | {first_seen} | {tags} |".format(
                    sha256=sample.get("sha256_hash", ""),
                    family=sample.get("signature") or "unknown",
                    file_type=sample.get("file_type") or "unknown",
                    first_seen=sample.get("first_seen") or "",
                    tags=tag_text,
                )
            )
        lines.extend(
            [
                "",
                "## Proof Of Compromise",
                "",
                "This section records defensive evidence, not exploit proof-of-concept code.",
                "Each listed SHA256 was reported by MalwareBazaar with first-seen metadata and associated hashes.",
            ]
        )
        return "\n".join(lines) + "\n"

    def to_ioc_json(self) -> str:
        return json.dumps(
            {
                "generated_at": self.generated_at.isoformat(),
                "source": "MalwareBazaar",
                "selector": self.selector,
                "iocs": self.iocs,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"

    def to_ioc_csv(self) -> str:
        output = io.StringIO()
        fieldnames = ["type", "value", "sha256", "malware_family", "file_name", "file_type", "first_seen", "source"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(self.iocs)
        return output.getvalue()

    def to_stix_json(self) -> str:
        now = self.generated_at.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        objects: list[dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--" + str(uuid5(NAMESPACE_URL, "loop-engineering")),
                "created": now,
                "modified": now,
                "name": "loop-engineering",
                "identity_class": "organization",
            }
        ]
        for sample in self.samples:
            sha256 = sample.get("sha256_hash")
            if not sha256:
                continue
            family = sample.get("signature") or "unknown"
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--" + str(uuid5(NAMESPACE_URL, f"malwarebazaar:{sha256}")),
                    "created": now,
                    "modified": now,
                    "name": f"MalwareBazaar sample {sha256}",
                    "description": f"Metadata-only file hash IOC. Reported family: {family}.",
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
                    "pattern_type": "stix",
                    "valid_from": now,
                    "labels": ["malwarebazaar", str(family).lower().replace(" ", "-")],
                }
            )
        return json.dumps(
            {
                "type": "bundle",
                "id": "bundle--" + str(uuid5(NAMESPACE_URL, f"loop-engineering:{now}:{self.selector}")),
                "objects": objects,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"

    def to_blog_markdown(self) -> str:
        family_counts = Counter((sample.get("signature") or "unknown") for sample in self.samples)
        file_type_counts = Counter((sample.get("file_type") or "unknown") for sample in self.samples)
        title_day = self.generated_at.strftime("%Y-%m-%d")
        sample_noun = "submission" if len(self.samples) == 1 else "submissions"
        lines = [
            f"# MalwareBazaar Sample-by-Sample Technical Analysis - {title_day}",
            "",
            "## Executive Summary",
            "",
            (
                f"The agent analyzed {len(self.samples)} recent MalwareBazaar {sample_noun} one by one "
                f"and extracted {len(self.iocs)} defensive IOCs. This is static metadata analysis: "
                "samples were not downloaded, unpacked, executed, or dynamically tested."
            ),
            "",
            "## What The Agent Did",
            "",
            "1. Queried the MalwareBazaar Community API for recent submissions.",
            "2. Walked every returned sample individually.",
            "3. Normalized per-sample hashes, family labels, file names, file types, tags, and timestamps.",
            "4. Produced per-sample IOC tables and exact SHA-256 YARA rules.",
            "5. Wrote this Markdown report for GitHub publication and defender review.",
            "",
            "## Run Outcome",
            "",
            "| Metric | Value |",
            "|---|---:|",
            f"| Samples analyzed | {len(self.samples)} |",
            f"| Total IOCs | {len(self.iocs)} |",
            f"| Unique family labels | {len(family_counts)} |",
            f"| Unique file types | {len(file_type_counts)} |",
            "",
            "## Dataset Overview",
            "",
            "### Top Families",
            "",
            "| Family | Samples |",
            "|---|---:|",
        ]
        lines.extend(f"| {family} | {count} |" for family, count in family_counts.most_common(10))
        lines.extend(
            [
                "",
                "### File Type Distribution",
                "",
                "| File type | Samples |",
                "|---|---:|",
            ]
        )
        lines.extend(f"| {file_type} | {count} |" for file_type, count in file_type_counts.most_common(10))
        lines.extend(["", "## Per-Sample Analysis", ""])
        for index, sample in enumerate(self.samples, start=1):
            lines.extend(self._render_sample_analysis(sample, index))
        lines.extend(
            [
                "",
                "## Combined YARA Rules",
                "",
                "These rules are exact SHA-256 sample indicators. They are useful for known-sample "
                "matching, not for detecting variants or inferring behavior. Broader YARA coverage "
                "requires static features from source code or file bytes.",
                "",
                "```yara",
                self.to_yara_rules().strip(),
                "```",
                "",
                "## Limitations",
                "",
                "- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.",
                "- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.",
                "- Hash YARA rules match only exact known samples.",
                "- Source-like samples should be analyzed with `analyze-source` for real static code findings.",
            ]
        )
        return "\n".join(lines) + "\n"

    def to_yara_rules(self, *, max_rules: int = 100) -> str:
        lines = [
            'import "hash"',
            "",
            "/*",
            " * MalwareBazaar exact-hash YARA indicators.",
            " * Generated from metadata only; samples were not executed.",
            f" * Selector: {self.selector}",
            f" * Generated: {self.generated_at.isoformat()}",
            " */",
            "",
        ]
        for index, sample in enumerate(self.samples[:max_rules], start=1):
            rule = self._sample_yara_rule(sample, index)
            if rule:
                lines.extend([rule, ""])
        return "\n".join(lines).rstrip() + "\n"

    def _render_sample_analysis(self, sample: dict[str, Any], index: int) -> list[str]:
        sha256 = str(sample.get("sha256_hash") or "")
        family = str(sample.get("signature") or "unknown")
        file_name = str(sample.get("file_name") or "unknown")
        file_type = str(sample.get("file_type") or "unknown")
        first_seen = str(sample.get("first_seen") or "unknown")
        reporter = str(sample.get("reporter") or "unknown")
        tags = sample.get("tags") or []
        tag_text = ", ".join(str(tag) for tag in tags) if isinstance(tags, list) else str(tags)
        tag_text = tag_text or "none"
        iocs = self._sample_iocs(sample)
        rule = self._sample_yara_rule(sample, index)

        lines = [
            f"### Sample {index}: `{sha256[:16] or 'no-sha256'}`",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| SHA-256 | `{sha256 or 'missing'}` |",
            f"| Family label | `{family}` |",
            f"| File name | `{file_name}` |",
            f"| File type | `{file_type}` |",
            f"| First seen | `{first_seen}` |",
            f"| Reporter | `{reporter}` |",
            f"| Tags | `{tag_text}` |",
            "",
            "#### Per-Sample IOC Table",
            "",
            "| Type | Value |",
            "|---|---|",
        ]
        lines.extend(f"| {kind} | `{value}` |" for kind, value in iocs)
        if not iocs:
            lines.append("| none |  |")

        lines.extend(
            [
                "",
                "#### Technical Assessment",
                "",
                f"- The sample is tracked as `{family}` by MalwareBazaar metadata.",
                f"- The observed artifact type is `{file_type}`; analysis here is limited to metadata and hash IOCs.",
                "- No behavior, capability, persistence, or C2 claims are made without static source/byte features.",
                "- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.",
                "",
                "#### Sample YARA Rule",
                "",
                "```yara",
                rule.strip() if rule else "/* no valid SHA-256 available for this sample */",
                "```",
                "",
            ]
        )
        return lines

    def _sample_iocs(self, sample: dict[str, Any]) -> list[tuple[str, str]]:
        iocs: list[tuple[str, str]] = []
        for field, kind in HASH_FIELDS.items():
            value = sample.get(field)
            if value:
                iocs.append((kind, str(value)))
        return iocs

    def _sample_yara_rule(self, sample: dict[str, Any], index: int) -> str:
        sha256 = str(sample.get("sha256_hash") or "").lower()
        if len(sha256) != 64:
            return ""
        family = sanitize_yara_identifier(str(sample.get("signature") or "unknown"))
        rule_name = f"MalwareBazaar_{family}_{index:03d}_{sha256[:8]}"
        file_type = sanitize_yara_string(str(sample.get("file_type") or "unknown"))
        file_name = sanitize_yara_string(str(sample.get("file_name") or "unknown"))
        first_seen = sanitize_yara_string(str(sample.get("first_seen") or "unknown"))
        family_label = sanitize_yara_string(str(sample.get("signature") or "unknown"))
        return "\n".join(
            [
                f"rule {rule_name}",
                "{",
                "  meta:",
                '    source = "MalwareBazaar"',
                '    analysis = "metadata-only exact hash IOC; sample not executed"',
                f'    sha256 = "{sha256}"',
                f'    family = "{family_label}"',
                f'    file_name = "{file_name}"',
                f'    file_type = "{file_type}"',
                f'    first_seen = "{first_seen}"',
                "  condition:",
                f'    hash.sha256(0, filesize) == "{sha256}"',
                "}",
            ]
        )


def build_report_bundle(samples: list[dict[str, Any]], selector: str) -> ReportBundle:
    return ReportBundle(generated_at=datetime.now(UTC), selector=selector, samples=samples)


def sanitize_yara_identifier(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char == "_" else "_" for char in value)
    cleaned = cleaned.strip("_") or "unknown"
    if cleaned[0].isdigit():
        cleaned = "family_" + cleaned
    return cleaned[:48]


def sanitize_yara_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')[:200]

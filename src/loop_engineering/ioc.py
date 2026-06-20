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

    def to_blog_markdown(self) -> str:
        family_counts = Counter((sample.get("signature") or "unknown") for sample in self.samples)
        file_type_counts = Counter((sample.get("file_type") or "unknown") for sample in self.samples)
        title_day = self.generated_at.strftime("%Y-%m-%d")
        lines = [
            f"# MalwareBazaar Static Intelligence Analysis - {title_day}",
            "",
            "## Executive Summary",
            "",
            (
                f"This analysis processed {len(self.samples)} recent MalwareBazaar metadata records "
                f"and produced {len(self.iocs)} defensive IOCs. The run was static and metadata-only: "
                "no malware was executed, unpacked, or republished."
            ),
            "",
            "## What The Agent Did",
            "",
            "1. Queried MalwareBazaar for recent sample metadata.",
            "2. Normalized sample hashes, families, file types, first-seen timestamps, and tags.",
            "3. Generated IOC feeds in Markdown, CSV, JSON, and STIX 2.1.",
            "4. Generated exact-match YARA rules from known sample SHA-256 values.",
            "5. Wrote this technical report for defender review and GitHub publishing.",
            "",
            "## Outcome",
            "",
            f"- Samples analyzed: {len(self.samples)}",
            f"- IOCs generated: {len(self.iocs)}",
            f"- MalwareBazaar selector: `{self.selector}`",
            f"- Generated at: `{self.generated_at.isoformat()}`",
            "",
            "## Top Malware Families",
            "",
            "| Family | Samples |",
            "|---|---:|",
        ]
        lines.extend(f"| {family} | {count} |" for family, count in family_counts.most_common(10))
        lines.extend(
            [
                "",
                "## File Type Distribution",
                "",
                "| File type | Samples |",
                "|---|---:|",
            ]
        )
        lines.extend(f"| {file_type} | {count} |" for file_type, count in file_type_counts.most_common(10))
        lines.extend(
            [
                "",
                "## IOC Summary",
                "",
                "The generated IOC set includes sample hashes and metadata suitable for defensive "
                "matching, enrichment, and blocklist workflows.",
                "",
                "| Type | Count |",
                "|---|---:|",
            ]
        )
        ioc_counts = Counter(ioc["type"] for ioc in self.iocs)
        lines.extend(f"| {kind} | {count} |" for kind, count in ioc_counts.most_common())
        lines.extend(
            [
                "",
                "## YARA Rules",
                "",
                "The generated YARA rules use the `hash` module to match exact SHA-256 values from "
                "MalwareBazaar metadata. These are high-confidence sample indicators, not generalized "
                "family behavior signatures. Generalized rules require static source or byte-level sample "
                "features and should not be invented from metadata alone.",
                "",
                "```yara",
                self.to_yara_rules().strip(),
                "```",
                "",
                "## Defensive Use",
                "",
                "- Import `iocs.csv` or `iocs.json` into enrichment and detection pipelines.",
                "- Use `stix.json` where STIX-compatible tooling is available.",
                "- Use `malwarebazaar-hash-iocs.yar` for exact known-sample matching.",
                "- Treat family names as source-provided metadata and validate them during triage.",
                "",
                "## Safety Notes",
                "",
                "This loop did not download raw samples for this report. If source-like malware is "
                "analyzed in future runs, the analysis path must remain static: inspect inert text, "
                "extract IOCs, identify obfuscation, and avoid dynamic execution.",
            ]
        )
        return "\n".join(lines) + "\n"

    def to_yara_rules(self, *, max_rules: int = 100) -> str:
        lines = [
            'import "hash"',
            "",
        ]
        for index, sample in enumerate(self.samples[:max_rules], start=1):
            sha256 = str(sample.get("sha256_hash") or "").lower()
            if len(sha256) != 64:
                continue
            family = sanitize_yara_identifier(str(sample.get("signature") or "unknown"))
            file_type = sanitize_yara_string(str(sample.get("file_type") or "unknown"))
            first_seen = sanitize_yara_string(str(sample.get("first_seen") or ""))
            lines.extend(
                [
                    f"rule MalwareBazaar_{family}_{index:03d}",
                    "{",
                    "  meta:",
                    '    source = "MalwareBazaar"',
                    f'    sha256 = "{sha256}"',
                    f'    family = "{sanitize_yara_string(str(sample.get("signature") or "unknown"))}"',
                    f'    file_type = "{file_type}"',
                    f'    first_seen = "{first_seen}"',
                    "    analysis = \"metadata-only exact hash IOC\"",
                    "  condition:",
                    f'    hash.sha256(0, filesize) == "{sha256}"',
                    "}",
                    "",
                ]
            )
        return "\n".join(lines).rstrip() + "\n"

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
        known_count = sum(1 for s in self.samples if s.get("signature"))
        tagged = sum(1 for s in self.samples if s.get("tags"))
        top3_families = ", ".join(f"{f} ({c})" for f, c in family_counts.most_common(3))

        family_rows = "\n".join(
            f"| {family} | {count} |" for family, count in family_counts.most_common(10)
        )
        file_type_rows = "\n".join(
            f"| {t} | {c} |" for t, c in file_type_counts.most_common(10)
        )

        return f"""# MalwareBazaar Technical Analysis — Metadata Intelligence

## Executive Summary

This report summarizes {len(self.samples)} recent files submitted to MalwareBazaar. All intelligence is derived from metadata — no samples were downloaded, executed, or unpacked. The analysis covers file-type distributions, identified malware families, and associated hashes.

## What The Agent Did

1. Queried the MalwareBazaar Community API with selector `{self.selector}`.
2. Received metadata for {len(self.samples)} submissions — hashes, file names, types, tags, and family labels.
3. Normalized hash IOCs (MD5, SHA-1, SHA-256, SHA3-384, IMPHASH, TLSH, TELFHASH, GIMPHASH, SSDEEP, ICON-DHASH).
4. Computed family and file-type frequency distributions.
5. Generated STIX 2.1 indicator bundle, CSV and JSON IOC feeds, and hash-based YARA rules.

## Outcome

| Metric | Value |
|---|---|
| Samples | {len(self.samples)} |
| Total IOCs | {len(self.iocs)} |
| Known families | {known_count} |
| Tagged submissions | {tagged} |
| Top families | {top3_families} |
| Generation time | {self.generated_at.isoformat()} |

## Methodology

All analysis is deterministic and metadata-bound. No behavioral sandboxing, dynamic analysis, or sample execution is performed. IOCs are exact hash values from the MalwareBazaar API. Family labels reflect MalwareBazaar's `signature` field, which may be incomplete for recently submitted or low-confidence samples.

## IOC Summary

The complete IOC feed is available as structured formats alongside this report. The following table summarizes the hash types collected:

| IOC Type | Hash Algorithm | Count |
|---|---|---|
{"".join(f"| {kind} | - | (per sample) |\\n" for kind in sorted(set(i["type"] for i in self.iocs)))}
## File Type Distribution

| File Type | Samples |
|---:|---:|
{file_type_rows}

## Malware Family Distribution

| Family | Samples |
|---:|---:|
{family_rows}

## YARA Rules

The following hash-based YARA rules are generated for defensive hunting. These rules use the YARA `hash` module and will match files whose SHA-256 hash matches a known MalwareBazaar sample.

```yara
{self.to_yara_rules().strip()}
```

## Defensive Use Cases

- **Network blocking**: Block outbound connections to known MalwareBazaar-indicated C2 infrastructure if IPs/domains are available.
- **Hash scanning**: Scan endpoint storage and memory for files matching SHA-256 hashes in the IOC feed.
- **STIX ingestion**: Import the STIX 2.1 bundle (`stix.json`) into threat intelligence platforms.
- **Incident enrichment**: Cross-reference file hashes from investigations against the generated IOC lists.

## Safety Notes

- This report contains metadata-only intelligence. No raw malware is included.
- Family labels are sourced from MalwareBazaar community submissions and may include false assignments.
- YARA rules are exact hash-based rules — they detect known samples only, not variants.

## Limitations

- Metadata-only analysis cannot determine behavioral capabilities or intent.
- "Unknown" family samples may be novel, recently submitted, or intentionally withheld by reporters.
- YARA rules are hash-bound; behavioral or string-based coverage requires static analysis of actual samples.
"""

    def to_yara_rules(self) -> str:
        sha256_hashes = sorted(
            s["sha256_hash"] for s in self.samples if s.get("sha256_hash")
        )
        if not sha256_hashes:
            return (
                'import "hash"\n\nrule MalwareBazaar_Hash_IOCs\n{\n'
                '  meta:\n'
                '    description = "No SHA-256 hashes available from this pull"\n'
                '    source = "MalwareBazaar"\n'
                '  condition:\n    false\n}\n'
            )
        lines = [
            'import "hash"',
            "",
            "/*",
            " * MalwareBazaar hash-based YARA indicators.",
            " * Generated from MalwareBazaar metadata only — samples not executed.",
            f" * Source: MalwareBazaar get_recent (selector={self.selector})",
            f" * Generated: {self.generated_at.isoformat()}",
            f" * Total rules: {len(sha256_hashes)}",
            " * Each rule matches a single known sample by SHA-256.",
            " */",
            "",
        ]
        for sha256 in sha256_hashes:
            lines.append(f'rule MalwareBazaar_Hash_IOC_{sha256[:16]}')
            lines.append('{')
            lines.append('  meta:')
            lines.append(f'    sha256 = "{sha256}"')
            lines.append(f'    description = "MalwareBazaar sample {sha256}"')
            lines.append('    source = "MalwareBazaar"')
            lines.append('    analysis = "metadata only; sample not executed"')
            lines.append('  condition:')
            lines.append(f'    hash.sha256(0, filesize) == "{sha256}"')
            lines.append('}')
            lines.append('')
        return '\n'.join(lines)


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

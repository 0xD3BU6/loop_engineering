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


def build_report_bundle(samples: list[dict[str, Any]], selector: str) -> ReportBundle:
    return ReportBundle(generated_at=datetime.now(UTC), selector=selector, samples=samples)

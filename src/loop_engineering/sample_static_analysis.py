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
    KNOWN_MULTICHAR_TLDS,
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


def network_iocs_from_metadata(metadata: dict[str, Any]) -> dict[str, list[str]]:
    """Recover network indicators that live only in MalwareBazaar metadata.

    MalwareBazaar encodes IOC tags with dashes instead of dots (e.g.
    ``46-183-223-7`` or ``kelvin654-duckdns-org``). These are analyst-supplied
    context, not bytes observed in the sample, so callers must label them as
    metadata-derived rather than statically observed. IPv4 reconstruction is
    exact; domain reconstruction is heuristic because an encoded dot is
    indistinguishable from a real hyphen, so the caller preserves the raw tag.
    """
    ips: list[str] = []
    domains: list[str] = []
    tags = metadata.get("tags") or []
    if not isinstance(tags, list):
        tags = [tags]
    for raw in tags:
        tag = str(raw).strip()
        if not tag:
            continue
        ip = _tag_to_ipv4(tag)
        if ip is not None:
            ips.append(ip)
            continue
        domain = _tag_to_domain(tag)
        if domain is not None:
            domains.append(domain)
    return {"ips": sorted(set(ips)), "domains": sorted(set(domains))}


def _tag_to_ipv4(tag: str) -> str | None:
    parts = tag.split("-")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return None
    if all(0 <= int(part) <= 255 for part in parts):
        return ".".join(parts)
    return None


def _tag_to_domain(tag: str) -> str | None:
    if "-" not in tag:
        return None
    candidate = tag.replace("-", ".")
    tld = candidate.rsplit(".", 1)[-1].lower()
    if len(tld) == 2 or tld in KNOWN_MULTICHAR_TLDS:
        return candidate
    return None


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
    source_excerpt: str = ""

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
        for layer in self.static_code.decoded_layers:
            iocs.extend({"type": "URL", "value": value, "source": "static-decoded-layer"} for value in layer.get("urls", []))
            iocs.extend({"type": "IP", "value": value, "source": "static-decoded-layer"} for value in layer.get("ips", []))
            iocs.extend({"type": "DOMAIN", "value": value, "source": "static-decoded-layer"} for value in layer.get("domains", []))
        metadata_iocs = network_iocs_from_metadata(self.metadata)
        iocs.extend(
            {"type": "IP", "value": value, "source": "malwarebazaar-metadata"}
            for value in metadata_iocs["ips"]
        )
        iocs.extend(
            {"type": "DOMAIN", "value": value, "source": "malwarebazaar-metadata"}
            for value in metadata_iocs["domains"]
        )
        # Deduplicate while preserving the first (most specific) source seen.
        seen: set[tuple[str, str]] = set()
        unique_iocs = []
        for ioc in iocs:
            key = (ioc["type"], ioc["value"])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        iocs = unique_iocs
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

        metadata_iocs = network_iocs_from_metadata(self.metadata)
        metadata_values = metadata_iocs["ips"] + metadata_iocs["domains"]
        if metadata_values:
            lines.extend(
                [
                    "",
                    f"rule Single_Sample_Metadata_Network_{self.sha256[:16]}",
                    "{",
                    "  meta:",
                    '    source = "loop-engineering single-sample analysis (MalwareBazaar metadata)"',
                    '    analysis = "network indicators from submission tags; not statically observed"',
                    f'    sha256 = "{self.sha256}"',
                    "  strings:",
                ]
            )
            for index, value in enumerate(metadata_values, start=1):
                lines.append(f'    $n{index:02d} = "{sanitize_yara_string(value)}" nocase')
            lines.extend(["  condition:", "    any of them", "}", ""])

        decoded_values: list[str] = []
        for layer in self.static_code.decoded_layers:
            decoded_values.extend(layer.get("urls", []) + layer.get("ips", []) + layer.get("domains", []))
        decoded_values = unique_preserve_order(decoded_values)
        if decoded_values:
            lines.extend(
                [
                    "",
                    f"rule Single_Sample_Decoded_Payload_{self.sha256[:16]}",
                    "{",
                    "  meta:",
                    '    source = "loop-engineering single-sample analysis (decoded payload layers)"',
                    '    analysis = "indicators recovered by statically decoding embedded base64; not executed"',
                    f'    sha256 = "{self.sha256}"',
                    "  strings:",
                ]
            )
            for index, value in enumerate(decoded_values, start=1):
                lines.append(f'    $d{index:02d} = "{sanitize_yara_string(value)}" nocase')
            lines.extend(["  condition:", "    any of them", "}", ""])
        return "\n".join(lines)

    def _render_code_dissection(self) -> list[str]:
        sc = self.static_code
        if not (sc.deobfuscated or sc.decoded_layers or sc.functions):
            return []
        lines = ["", "## Code Dissection", ""]

        if sc.deobfuscated:
            lines.extend(
                [
                    "### Deobfuscation",
                    "",
                    (
                        "The sample assembles a payload through string concatenation and then strips a "
                        "junk token to reveal it. Reconstructing that string statically (no execution) "
                        "recovers the launched command:"
                    ),
                    "",
                    "```text",
                    truncate_markdown(" ".join(sc.deobfuscated[0].split()), 600),
                    "```",
                    "",
                ]
            )

        if sc.decoded_layers:
            lines.extend(
                [
                    "### Decoded Payload Layers",
                    "",
                    "Each base64 layer was decoded as inert bytes (not executed). Network indicators "
                    "recovered here come from the sample's own code, not from MalwareBazaar metadata.",
                    "",
                    "| Layer | Encoding | Recovered indicators | Preview |",
                    "|---|---|---|---|",
                ]
            )
            for layer in sc.decoded_layers:
                indicators = ", ".join(defang(v) for v in (layer.get("urls", []) + layer.get("ips", []) + layer.get("domains", []))) or "—"
                preview = truncate_markdown(layer.get("preview", ""), 120)
                lines.append(f"| {layer.get('depth')} | {layer.get('encoding')} | {indicators} | `{preview}` |")
            lines.append("")

        if sc.functions:
            lines.extend(["### Functions", ""])
            for func in sc.functions:
                markers = ", ".join(func.get("behaviour_markers") or []) or "no flagged behaviour (likely decoy/helper)"
                calls = ", ".join(f"`{c}`" for c in func.get("calls") or []) or "—"
                lines.extend(
                    [
                        f"#### `{func.get('signature')}`",
                        "",
                        f"- Behaviour: {markers}",
                        f"- Calls: {calls}",
                        "",
                        "```javascript",
                        truncate_code(func.get("body_excerpt", ""), 600) + ("\n// ... truncated ..." if func.get("truncated") and len(func.get("body_excerpt", "")) <= 600 else ""),
                        "```",
                        "",
                    ]
                )

        # The top-level (non-function) execution is where the real behaviour lives.
        markers = sorted({finding.category for finding in sc.findings if finding.severity in {"high", "medium"}})
        if markers:
            lines.extend(
                [
                    "### Top-Level Execution Behaviour",
                    "",
                    "Behaviour detected across the sample (including recovered/deobfuscated code): "
                    + ", ".join(f"`{m}`" for m in markers)
                    + ".",
                    "",
                ]
            )
        return lines

    def _narrative_title(self, family: str, file_type: str) -> str:
        kind = "dropper" if any(f.category == "shell_dropper" for f in self.static_code.findings) else (
            "loader" if self.static_code.deobfuscated or self.static_code.decoded_layers else "sample"
        )
        label = family if family != "unknown" else "An unlabelled"
        return f"Storytime: Dissecting a {label} {file_type.upper()} {kind}"

    def _render_story(self, family: str, file_type: str, source_url: str, decoded_count: int) -> list[str]:
        sc = self.static_code
        lang = sc.language_hint if sc.language_hint != "unknown" else file_type
        high = sorted({f.category for f in sc.findings if f.severity == "high"})

        lines = [
            f"# {self._narrative_title(family, file_type)}",
            "",
            f"> **Source:** [MalwareBazaar]({source_url}) · **SHA-256** `{self.sha256}` · "
            f"**Family** `{family}` · **Static analysis only — the sample was never run.**",
            "",
            "## The Story",
            "",
        ]

        opener = (
            f"It showed up on MalwareBazaar as a {self.byte_count}-byte `{file_type}` file"
            + (f", tagged `{family}`" if family != "unknown" else ", with no family label")
            + ". We pulled exactly one copy into quarantine, cracked open the password-protected "
            "archive, and read the bytes as inert text. Nothing here was executed — every claim "
            "below comes from reading the code, not running it. Here is what it was hiding."
        )
        lines.append(opener)
        lines.append("")

        # First contact: the code as it arrived.
        lines.extend(
            [
                "## First Contact — The Code As It Arrived",
                "",
                "Straight out of the archive, a portion of the sample looks like this (defanged):",
                "",
                f"```{lang}",
                self.source_excerpt or "(no readable source excerpt)",
                "```",
                "",
            ]
        )

        # The reveal: deobfuscation.
        if sc.deobfuscated:
            recovered = " ".join(sc.deobfuscated[0].split())
            lines.extend(
                [
                    "## Peeling Back the Obfuscation",
                    "",
                    "That wall of noise is deliberate. The sample assembles its real payload one "
                    "fragment at a time and laces every fragment with a junk token, so a casual look "
                    "(or a naive string scan) sees gibberish. Undo that concatenation and strip the "
                    "junk token — purely as text, nothing runs — and the mask drops:",
                    "",
                    "```text",
                    truncate_code(defang_text(recovered), 700),
                    "```",
                    "",
                    "Now the intent is legible. It hands a command to the system instead of doing "
                    "the work in plain sight.",
                    "",
                ]
            )

        # Following the chain through decoded layers.
        chain_layers = [layer for layer in sc.decoded_layers if layer.get("urls") or layer.get("ips") or layer.get("domains") or layer.get("preview")]
        if chain_layers:
            lines.extend(["## Following the Chain", "", "Each wrapper peels back to another (decoded as bytes, never executed):", ""])
            for layer in chain_layers:
                indicators = layer.get("urls", []) + layer.get("ips", []) + layer.get("domains", [])
                hook = (
                    f"reaching out to {', '.join(defang(v) for v in indicators)}"
                    if indicators
                    else "carrying more stage logic"
                )
                lines.append(
                    f"- **Layer {layer.get('depth')}** ({layer.get('encoding')}) — {hook}. "
                    f"Preview: `{truncate_markdown(layer.get('preview', ''), 110)}`"
                )
            lines.append("")

        if high:
            lines.extend(
                [
                    "## What It Wants To Do",
                    "",
                    "The behaviour that matters, recovered from the (deobfuscated) code: "
                    + ", ".join(f"`{cat}`" for cat in high)
                    + ". "
                    + self._behaviour_prose(high),
                    "",
                ]
            )
        return lines

    def _behaviour_prose(self, categories: list[str]) -> str:
        notes = {
            "shell_dropper": "It pulls follow-on payloads down with a shell download tool, makes them executable, and launches them — a classic drop-and-run loader.",
            "powershell_cradle": "It leans on a PowerShell download/exec cradle to fetch and run its next stage in memory.",
            "shell_execution": "It shells out to the OS to run external commands.",
            "dynamic_execution": "It builds and evaluates code at runtime, a common way to hide the real logic until execution.",
        }
        return " ".join(notes[c] for c in categories if c in notes)

    def _render_knowledge_section(self, correlations: dict[str, Any] | None) -> list[str]:
        if not correlations:
            return []
        lines = ["", "## What We've Learned So Far", "", "How this sample sits against everything the loop has analyzed before:", ""]
        corpus = correlations.get("corpus_size_before", 0)
        lines.append(f"- Corpus before this sample: **{corpus}** prior sample(s).")
        if correlations.get("is_new_family"):
            lines.append(f"- First time the loop has seen the `{self.metadata.get('signature')}` family.")
        elif correlations.get("family_seen_before"):
            lines.append(f"- The `{self.metadata.get('signature')}` family has been seen **{correlations['family_seen_before']}** time(s) before.")
        for overlap in correlations.get("infra_overlap", []):
            others = ", ".join(f"`{sha[:12]}`" for sha in overlap["also_in"])
            lines.append(f"- **Infrastructure reuse:** {overlap['type']} `{overlap['indicator']}` also appeared in {others}.")
        recurring = correlations.get("recurring_techniques", {})
        if recurring:
            techniques = ", ".join(f"`{t}` (×{c})" for t, c in sorted(recurring.items(), key=lambda kv: -kv[1]))
            lines.append(f"- Recurring techniques across the corpus: {techniques}.")
        if not correlations.get("infra_overlap") and not recurring and not correlations.get("family_seen_before"):
            lines.append("- No overlap with earlier samples yet — this one expands the knowledge base.")
        lines.append("")
        return lines

    def to_blog_markdown(self, correlations: dict[str, Any] | None = None) -> str:
        family = self.metadata.get("signature") or "unknown"
        file_name = self.metadata.get("file_name") or self.source_name
        file_type = self.metadata.get("file_type") or "unknown"
        tags = self.metadata.get("tags") or []
        tag_text = ", ".join(str(tag) for tag in tags) if isinstance(tags, list) else str(tags)
        findings = self.static_code.findings
        decoded_count = sum(len(L.get("urls", [])) + len(L.get("ips", [])) + len(L.get("domains", [])) for L in self.static_code.decoded_layers)
        network_meta = network_iocs_from_metadata(self.metadata)
        source_url = f"https://bazaar.abuse.ch/sample/{self.sha256}/"

        lines = self._render_story(family, file_type, source_url, decoded_count)
        lines += [
            "## Executive Summary",
            "",
            (
                f"One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. "
                f"Static evidence produced {3 + len(self.static_code.urls) + len(self.static_code.ips) + len(self.static_code.domains)} IOCs "
                f"and {len(findings)} code/string findings"
                + (
                    f", recovered {decoded_count} network indicator(s) by decoding the sample's own obfuscated/base64 payload layers"
                    if decoded_count
                    else ""
                )
                + (
                    f", plus {len(network_meta['ips']) + len(network_meta['domains'])} metadata-derived network indicator(s) listed separately below."
                    if network_meta["ips"] or network_meta["domains"]
                    else "."
                )
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
        metadata_iocs = network_iocs_from_metadata(self.metadata)
        if metadata_iocs["ips"] or metadata_iocs["domains"]:
            lines.extend(
                [
                    "",
                    "## Metadata-Derived Network Indicators",
                    "",
                    (
                        "These indicators come from MalwareBazaar submission tags, not from bytes "
                        "observed in this sample. The payload is obfuscated, so its real C2 is not "
                        "visible to static text extraction. Domain values are reconstructed from "
                        "dash-encoded tags and should be verified before blocking."
                    ),
                    "",
                    "| Type | Value | Source tag |",
                    "|---|---|---|",
                ]
            )
            lines.extend(f"| IP | `{value}` | metadata |" for value in metadata_iocs["ips"])
            lines.extend(f"| Domain | `{value}` | metadata |" for value in metadata_iocs["domains"])

        lines.extend(self._render_code_dissection())

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

        lines.extend(self._render_knowledge_section(correlations))

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
    source_excerpt = build_source_excerpt(text)
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
        source_excerpt=source_excerpt,
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


def write_single_sample_outputs(
    analysis: SingleSampleAnalysis,
    reports_dir: Path,
    correlations: dict[str, Any] | None = None,
) -> Path:
    day = analysis.generated_at.strftime("%Y-%m-%d")
    target = reports_dir / day / "samples" / analysis.sha256
    target.mkdir(parents=True, exist_ok=True)
    (target / "technical-analysis.md").write_text(analysis.to_blog_markdown(correlations), encoding="utf-8")
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


def truncate_code(value: str, limit: int) -> str:
    """Truncate a code excerpt for a fenced block, preserving newlines."""
    value = value.replace("```", "``​`")
    return value if len(value) <= limit else value[:limit] + "\n// ... truncated ..."


def defang(value: str) -> str:
    """Render a network indicator non-clickable for safe publication."""
    return value.replace("http", "hxxp").replace(".", "[.]")


_URL_DEFANG_RE = re.compile(r"https?://", re.IGNORECASE)
_IP_DEFANG_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def defang_text(text: str) -> str:
    """Defang network indicators inside a code excerpt without mangling the code.

    Only URL schemes and bare IPv4 addresses are neutralised so the excerpt is
    safe to publish (non-clickable, non-resolvable) while the surrounding code
    stays readable.
    """
    text = _URL_DEFANG_RE.sub(lambda m: m.group(0).replace("http", "hxxp"), text)
    return _IP_DEFANG_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text)


def build_source_excerpt(text: str, *, max_lines: int = 22, max_chars: int = 1500) -> str:
    """A bounded, defanged slice of the sample for the writeup.

    Shows a representative *portion* of the code (not the whole file) so a reader
    can see the obfuscation first-hand. Network indicators are defanged.
    """
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    excerpt = "\n".join(lines[:max_lines])
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars] + "\n... (truncated)"
    elif len(lines) > max_lines:
        excerpt += "\n... (truncated)"
    return defang_text(excerpt)

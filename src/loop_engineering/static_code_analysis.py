"""Static analysis helpers for source-like malware samples.

These routines treat input as inert text. They do not execute, import, decode
into runnable artifacts, or fetch URLs discovered in the sample.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import base64
import math
import re
from typing import Any


URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.IGNORECASE)
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")
HEX_BLOB_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){16,}|(?:0x[0-9a-fA-F]{2}[,\s]*){16,}")

# Multi-character gTLDs / reserved TLDs we accept in addition to any two-letter
# ccTLD. Without this allowlist DOMAIN_RE matches source-code member access such
# as `obj.replace` or `ns.Dictionary` as if they were domains, flooding the IOC
# list with false positives. Two-letter TLDs (covering all ccTLDs) are accepted
# separately in _looks_like_real_domain.
KNOWN_MULTICHAR_TLDS = frozenset(
    {
        # reserved (RFC 2606 / 6761) — kept so docs/tests can use them safely
        "example", "test", "invalid", "localhost", "local",
        # classic gTLDs
        "com", "net", "org", "info", "biz", "name", "pro", "mobi", "aero",
        "asia", "cat", "coop", "int", "jobs", "museum", "tel", "travel", "edu",
        "gov", "mil", "arpa", "xxx",
        # new gTLDs commonly abused in malware C2 / phishing
        "top", "xyz", "online", "site", "club", "shop", "app", "dev", "page",
        "link", "live", "icu", "cyou", "monster", "work", "click", "vip",
        "buzz", "fun", "space", "website", "tech", "store", "cloud", "win",
        "bid", "stream", "download", "gdn", "racing", "loan", "men", "date",
        "party", "review", "trade", "accountant", "science", "faith", "cricket",
        "host", "press", "fund", "agency", "today", "world", "life", "email",
        "digital", "network", "systems", "services", "solutions", "support",
        "tk", "pw", "cc", "io", "co", "me", "tv", "ai",
    }
)


PATTERNS = {
    "dynamic_execution": [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"Function\s*\(",
        r"setTimeout\s*\(\s*['\"]",
        r"setInterval\s*\(\s*['\"]",
    ],
    "shell_execution": [
        r"subprocess\.",
        r"os\.system\s*\(",
        r"child_process",
        r"cmd\.exe",
        r"/bin/sh",
        r"powershell(?:\.exe)?",
    ],
    "powershell_cradle": [
        r"DownloadString",
        r"DownloadFile",
        r"Invoke-Expression|\bIEX\b",
        r"FromBase64String",
        r"-enc(?:odedcommand)?\b",
    ],
    "persistence": [
        r"Run\\",
        r"CurrentVersion\\Run",
        r"Startup",
        r"crontab",
        r"LaunchAgents",
        r"systemd",
    ],
    "anti_analysis": [
        r"VirtualBox|VMware|QEMU|Sandbox",
        r"IsDebuggerPresent",
        r"sleep\s*\(\s*[1-9]\d{2,}",
        r"GetTickCount",
    ],
    "networking": [
        r"socket\.",
        r"requests\.",
        r"urllib",
        r"XMLHttpRequest",
        r"fetch\s*\(",
        r"WinHttp",
    ],
}


@dataclass(frozen=True)
class StaticCodeFinding:
    category: str
    value: str
    severity: str
    detail: str


@dataclass(frozen=True)
class StaticCodeReport:
    language_hint: str
    line_count: int
    byte_count: int
    entropy: float
    urls: list[str]
    ips: list[str]
    domains: list[str]
    findings: list[StaticCodeFinding]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [asdict(finding) for finding in self.findings]
        return data


def _looks_like_real_domain(candidate: str) -> bool:
    """Filter DOMAIN_RE hits that are actually source-code member access.

    A candidate is kept only when its right-most label is a plausible TLD: a
    two-letter ccTLD or a known multi-character gTLD. This rejects tokens like
    ``obj.replace`` or ``ns.Dictionary`` while keeping ``kelvin654.duckdns.org``
    and reserved domains such as ``evil.example``. Pure-numeric matches (an IP
    captured by the domain regex) are also dropped.
    """
    if candidate.replace(".", "").isdigit():
        return False
    tld = candidate.rsplit(".", 1)[-1].lower()
    return len(tld) == 2 or tld in KNOWN_MULTICHAR_TLDS


def analyze_source_text(text: str, *, language_hint: str = "unknown") -> StaticCodeReport:
    findings: list[StaticCodeFinding] = []
    entropy = shannon_entropy(text)
    urls = sorted(set(URL_RE.findall(text)))
    ips = sorted(set(IP_RE.findall(text)))
    domains = sorted(domain for domain in set(DOMAIN_RE.findall(text)) if _looks_like_real_domain(domain))

    for category, patterns in PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, text, flags=re.IGNORECASE)
            if matches:
                findings.append(
                    StaticCodeFinding(
                        category=category,
                        value=pattern,
                        severity=severity_for_category(category),
                        detail=f"Matched {len(matches)} occurrence(s)",
                    )
                )

    base64_blobs = BASE64_RE.findall(text)
    if base64_blobs:
        findings.append(
            StaticCodeFinding(
                category="obfuscation",
                value="base64_blob",
                severity="medium",
                detail=f"Found {len(base64_blobs)} long base64-like blob(s)",
            )
        )
        for blob in base64_blobs[:3]:
            decoded_hint = safe_decode_hint(blob)
            if decoded_hint:
                findings.append(
                    StaticCodeFinding(
                        category="decoded_hint",
                        value=decoded_hint,
                        severity="info",
                        detail="Preview from base64-like blob; not executed",
                    )
                )

    hex_blobs = HEX_BLOB_RE.findall(text)
    if hex_blobs:
        findings.append(
            StaticCodeFinding(
                category="obfuscation",
                value="hex_blob",
                severity="medium",
                detail=f"Found {len(hex_blobs)} long hex-escaped blob(s)",
            )
        )

    if entropy >= 5.2 and len(text) > 300:
        findings.append(
            StaticCodeFinding(
                category="obfuscation",
                value="high_entropy",
                severity="medium",
                detail=f"Text entropy is {entropy:.2f}",
            )
        )

    return StaticCodeReport(
        language_hint=language_hint,
        line_count=text.count("\n") + 1 if text else 0,
        byte_count=len(text.encode("utf-8", errors="replace")),
        entropy=round(entropy, 3),
        urls=urls,
        ips=ips,
        domains=domains,
        findings=findings,
    )


def severity_for_category(category: str) -> str:
    if category in {"dynamic_execution", "shell_execution", "powershell_cradle"}:
        return "high"
    if category in {"persistence", "anti_analysis", "networking"}:
        return "medium"
    return "info"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {char: text.count(char) for char in set(text)}
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def safe_decode_hint(blob: str) -> str:
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return ""
    preview = decoded[:120].decode("utf-8", errors="ignore")
    preview = "".join(char if char.isprintable() else " " for char in preview)
    return " ".join(preview.split())[:120]


def render_static_code_markdown(report: StaticCodeReport) -> str:
    lines = [
        "# Static Source Malware Analysis",
        "",
        f"- Language hint: `{report.language_hint}`",
        f"- Lines: {report.line_count}",
        f"- Bytes: {report.byte_count}",
        f"- Entropy: {report.entropy}",
        "- Handling: static text analysis only; sample was not executed.",
        "",
        "## Extracted IOCs",
        "",
        "| Type | Value |",
        "|---|---|",
    ]
    for url in report.urls:
        lines.append(f"| URL | `{url}` |")
    for ip in report.ips:
        lines.append(f"| IP | `{ip}` |")
    for domain in report.domains:
        lines.append(f"| Domain | `{domain}` |")
    if not report.urls and not report.ips and not report.domains:
        lines.append("| none |  |")

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Severity | Category | Value | Detail |",
            "|---|---|---|---|",
        ]
    )
    for finding in report.findings:
        lines.append(f"| {finding.severity} | {finding.category} | `{finding.value}` | {finding.detail} |")
    if not report.findings:
        lines.append("| info | none |  | No suspicious static patterns found |")
    return "\n".join(lines) + "\n"


def render_static_code_blog_markdown(report: StaticCodeReport) -> str:
    lines = [
        "# Static Source Malware Technical Analysis",
        "",
        "## Executive Summary",
        "",
        (
            "The agent performed static-only analysis on a source-like malware artifact. "
            "The sample was treated as inert text: it was not executed, imported, unpacked, "
            "or allowed to contact any extracted network indicators."
        ),
        "",
        "## What The Agent Did",
        "",
        "1. Read the source-like sample as text.",
        "2. Extracted URLs, IP addresses, and domain-like indicators.",
        "3. Searched for obfuscation, dynamic execution, shell execution, persistence, networking, and anti-analysis patterns.",
        "4. Produced a Markdown technical analysis and JSON report.",
        "5. Generated YARA rules from static strings and IOCs found in the source text.",
        "",
        "## Outcome",
        "",
        f"- Language hint: `{report.language_hint}`",
        f"- Lines inspected: {report.line_count}",
        f"- Bytes inspected: {report.byte_count}",
        f"- Entropy: {report.entropy}",
        f"- URLs: {len(report.urls)}",
        f"- IPs: {len(report.ips)}",
        f"- Domains: {len(report.domains)}",
        f"- Findings: {len(report.findings)}",
        "",
        "## IOCs",
        "",
        "| Type | Value |",
        "|---|---|",
    ]
    for url in report.urls:
        lines.append(f"| URL | `{url}` |")
    for ip in report.ips:
        lines.append(f"| IP | `{ip}` |")
    for domain in report.domains:
        lines.append(f"| Domain | `{domain}` |")
    if not report.urls and not report.ips and not report.domains:
        lines.append("| none |  |")

    lines.extend(
        [
            "",
            "## Static Findings",
            "",
            "| Severity | Category | Detail |",
            "|---|---|---|",
        ]
    )
    for finding in report.findings:
        lines.append(f"| {finding.severity} | {finding.category} | {finding.detail} (`{finding.value}`) |")
    if not report.findings:
        lines.append("| info | none | No suspicious static patterns found |")

    lines.extend(
        [
            "",
            "## YARA Rules",
            "",
            "These rules are static string/IOC rules derived from the source text. They are intended "
            "for defensive hunting and triage, not as a claim of generalized malware-family coverage.",
            "",
            "```yara",
            render_static_code_yara(report).strip(),
            "```",
            "",
            "## Defensive Notes",
            "",
            "- Validate extracted network indicators before blocking production traffic.",
            "- Treat decoded hints as triage clues only; do not execute decoded content.",
            "- Prefer exact static rules for known artifacts and broader rules only after multiple related samples are compared.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_static_code_yara(report: StaticCodeReport) -> str:
    strings: list[tuple[str, str, str]] = []
    for value in report.urls[:20]:
        strings.append(("url", value, "literal"))
    for value in report.ips[:20]:
        strings.append(("ip", value, "literal"))
    for value in report.domains[:20]:
        strings.append(("domain", value, "literal"))
    for finding in report.findings[:20]:
        if finding.category in {"dynamic_execution", "shell_execution", "powershell_cradle", "persistence"}:
            strings.append((finding.category, finding.value, "regex"))

    lines = [
        "rule Static_Source_Malware_Indicators",
        "{",
        "  meta:",
        '    source = "loop-engineering static source analysis"',
        f'    language_hint = "{sanitize_yara_string(report.language_hint)}"',
        '    analysis = "static text only; sample not executed"',
        "  strings:",
    ]
    if strings:
        for index, (kind, value, mode) in enumerate(strings, start=1):
            identifier = sanitize_yara_identifier(kind)
            if mode == "regex":
                lines.append(f"    ${identifier}_{index:02d} = /{sanitize_yara_regex(value)}/ nocase")
            else:
                lines.append(f'    ${identifier}_{index:02d} = "{sanitize_yara_string(value)}" nocase')
        lines.extend(
            [
                "  condition:",
                "    any of them",
                "}",
            ]
        )
    else:
        lines.extend(
            [
                '    $static_placeholder = "no_static_iocs_found"',
                "  condition:",
                "    false",
                "}",
            ]
        )
    return "\n".join(lines) + "\n"


def sanitize_yara_identifier(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char == "_" else "_" for char in value)
    cleaned = cleaned.strip("_") or "value"
    if cleaned[0].isdigit():
        cleaned = "value_" + cleaned
    return cleaned[:40]


def sanitize_yara_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')[:200]


def sanitize_yara_regex(value: str) -> str:
    return value.replace("/", r"\/")[:200]

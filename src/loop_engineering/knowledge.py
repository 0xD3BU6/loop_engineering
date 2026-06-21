"""Self-improving malware-intel knowledge base.

Each analyzed sample contributes a small structured record to a persistent
corpus. Before a new sample is recorded, it is correlated against everything
seen so far, so reports get smarter over time: shared C2/staging infrastructure
is surfaced, recurring families are counted, and technique trends emerge across
the corpus. This is deterministic accumulation, not model self-modification -
the loop "learns" by remembering and cross-referencing its own evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any


def build_record(analysis: Any, *, report_dir: str | None = None) -> dict[str, Any]:
    """Distil one analysis into a durable knowledge record."""
    sc = analysis.static_code
    decoded_urls: list[str] = []
    decoded_ips: list[str] = []
    decoded_domains: list[str] = []
    for layer in getattr(sc, "decoded_layers", []) or []:
        decoded_urls.extend(layer.get("urls", []))
        decoded_ips.extend(layer.get("ips", []))
        decoded_domains.extend(layer.get("domains", []))

    techniques = sorted({finding.category for finding in sc.findings})
    return {
        "sha256": analysis.sha256,
        "family": str(analysis.metadata.get("signature") or "unknown"),
        "file_type": str(analysis.metadata.get("file_type") or "unknown"),
        "first_seen": str(analysis.metadata.get("first_seen") or "unknown"),
        "analyzed_at": analysis.generated_at.replace(microsecond=0).isoformat(),
        "techniques": techniques,
        "iocs": {
            "ips": sorted(set(sc.ips) | set(decoded_ips)),
            "domains": sorted(set(sc.domains) | set(decoded_domains)),
            "urls": sorted(set(sc.urls) | set(decoded_urls)),
        },
        "report_dir": report_dir,
    }


def load_knowledge(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"samples": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"samples": []}
    if not isinstance(data, dict) or not isinstance(data.get("samples"), list):
        return {"samples": []}
    return data


def correlate(knowledge: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """Correlate a new record against the existing corpus (excluding itself)."""
    prior = [s for s in knowledge.get("samples", []) if s.get("sha256") != record["sha256"]]

    overlaps: list[dict[str, Any]] = []
    for kind in ("ips", "domains"):
        for indicator in record["iocs"].get(kind, []):
            also_in = [s["sha256"] for s in prior if indicator in s.get("iocs", {}).get(kind, [])]
            if also_in:
                overlaps.append({"type": kind[:-1].upper(), "indicator": indicator, "also_in": also_in})

    family = record["family"]
    family_prior = sum(1 for s in prior if s.get("family") == family and family != "unknown")
    technique_counts = {
        technique: sum(1 for s in prior if technique in s.get("techniques", []))
        for technique in record["techniques"]
    }
    return {
        "corpus_size_before": len(prior),
        "infra_overlap": overlaps,
        "family_seen_before": family_prior,
        "is_new_family": family != "unknown" and family_prior == 0,
        "recurring_techniques": {t: c for t, c in technique_counts.items() if c > 0},
    }


def update_knowledge(knowledge: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    samples = [s for s in knowledge.get("samples", []) if s.get("sha256") != record["sha256"]]
    samples.append(record)
    samples.sort(key=lambda s: s.get("analyzed_at", ""))
    return {"samples": samples, "updated_at": datetime.now(UTC).replace(microsecond=0).isoformat()}


def _infra_clusters(samples: list[dict[str, Any]]) -> list[tuple[str, str, list[str]]]:
    clusters: list[tuple[str, str, list[str]]] = []
    for kind in ("ips", "domains"):
        index: dict[str, list[str]] = {}
        for sample in samples:
            for indicator in sample.get("iocs", {}).get(kind, []):
                index.setdefault(indicator, []).append(sample["sha256"])
        for indicator, shas in sorted(index.items()):
            if len(shas) > 1:
                clusters.append((kind[:-1].upper(), indicator, sorted(set(shas))))
    return clusters


def render_observations_markdown(knowledge: dict[str, Any]) -> str:
    samples = knowledge.get("samples", [])
    lines = [
        "# Malware-Intel Observations",
        "",
        "Running log of every sample the single-sample loop has statically analyzed. "
        "Generated and updated automatically; newest last.",
        "",
        f"- Samples analyzed: {len(samples)}",
        f"- Distinct families: {len({s.get('family') for s in samples if s.get('family') != 'unknown'})}",
        f"- Infrastructure indicators reused across samples: {len(_infra_clusters(samples))}",
        "",
        "| Analyzed | SHA-256 | Family | Type | Techniques | IOCs |",
        "|---|---|---|---|---|---|",
    ]
    for sample in samples:
        ioc_count = sum(len(v) for v in sample.get("iocs", {}).values())
        techniques = ", ".join(sample.get("techniques", [])) or "—"
        lines.append(
            f"| {sample.get('analyzed_at', '?')} | `{sample.get('sha256', '')[:16]}` | "
            f"`{sample.get('family')}` | {sample.get('file_type')} | {techniques} | {ioc_count} |"
        )
    return "\n".join(lines) + "\n"


def render_knowledge_doc(knowledge: dict[str, Any]) -> str:
    samples = knowledge.get("samples", [])
    families: dict[str, int] = {}
    techniques: dict[str, int] = {}
    for sample in samples:
        fam = sample.get("family", "unknown")
        families[fam] = families.get(fam, 0) + 1
        for technique in sample.get("techniques", []):
            techniques[technique] = techniques.get(technique, 0) + 1
    clusters = _infra_clusters(samples)

    lines = [
        "# Malware-Intel Learned Knowledge",
        "",
        "Durable knowledge distilled from the single-sample analysis loop. Updated after "
        "each run so later analyses can lean on earlier ones.",
        "",
        f"_Corpus: {len(samples)} sample(s)._",
        "",
        "## Families observed",
        "",
        "| Family | Count |",
        "|---|---:|",
    ]
    for family, count in sorted(families.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{family}` | {count} |")

    lines.extend(["", "## Techniques observed", "", "| Technique | Samples |", "|---|---:|"])
    for technique, count in sorted(techniques.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{technique}` | {count} |")

    lines.extend(["", "## Shared infrastructure (seen in more than one sample)", ""])
    if clusters:
        lines.extend(["| Type | Indicator | Samples |", "|---|---|---|"])
        for kind, indicator, shas in clusters:
            sample_list = ", ".join(f"`{sha[:12]}`" for sha in shas)
            lines.append(f"| {kind} | `{indicator}` | {sample_list} |")
    else:
        lines.append("_No infrastructure reuse observed across the corpus yet._")
    return "\n".join(lines) + "\n"

#!/usr/bin/env python3
"""Collect ONE MalwareBazaar source-like sample for AI static analysis.

This is the deterministic, mechanical front-half of the loop. It does NOT write
the technical blog. It selects one unseen, source-like candidate, downloads only
that password-protected ZIP into the gitignored quarantine, extracts one archived
member as inert text, computes mechanical evidence (hashes, entropy, magic,
strings, network IOCs), and writes a handoff file for the AI analyst to read.

The AI harness (Claude) then reads the handoff + inert source, performs the real
reasoned analysis, and writes the sanitized report bundle under reports/. The raw
source text never leaves quarantine/ and is never committed.

Safety: no execution, no source import, no URL fetching, single sample only.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from loop_engineering.config import ConfigError, Settings  # noqa: E402
from loop_engineering.malware_bazaar import MalwareBazaarClient, MalwareBazaarError  # noqa: E402
from loop_engineering.sample_static_analysis import (  # noqa: E402
    analyze_sample_bytes,
    decode_text_for_analysis,
    extract_printable_strings,
    select_single_candidate,
)


STATE_PATH = ROOT / "harness" / "generated" / "single-sample-state.json"
MAX_SAMPLE_BYTES = int(os.getenv("LOOP_MAX_SAMPLE_BYTES", str(8 * 1024 * 1024)))
ZIP_PASSWORD = b"infected"

SOURCE_EXT_PRIORITY = (
    ".ps1", ".js", ".jse", ".vbs", ".vbe", ".vba", ".py", ".sh", ".bash",
    ".php", ".bat", ".cmd", ".hta", ".wsf", ".pl", ".lua",
)


def main() -> int:
    selector = os.getenv("LOOP_MALWAREBAZAAR_SELECTOR", "100")
    if selector not in {"100", "time"}:
        print("error: LOOP_MALWAREBAZAAR_SELECTOR must be 100 or time", file=sys.stderr)
        return 2
    try:
        settings = Settings.from_env()
        settings.require_malwarebazaar_key()
        if not settings.allow_raw_download:
            raise ConfigError(
                "collection requires LOOP_ALLOW_MALWARE_DOWNLOAD=1 inside an isolated lab. "
                "Exactly one password-protected sample ZIP is downloaded into quarantine."
            )

        client = MalwareBazaarClient(
            auth_key=settings.malwarebazaar_auth_key,
            endpoint=settings.malwarebazaar_endpoint,
        )
        state = read_state()
        seen = set(state.get("analyzed_hashes", []))
        samples = client.get_recent(selector=selector)
        candidate = select_single_candidate(samples, seen)
        sha256 = str(candidate.get("sha256_hash") or "").lower()
        if not sha256:
            raise MalwareBazaarError("Selected candidate has no SHA-256 hash")

        sample_quarantine = settings.quarantine_dir / sha256
        zip_path = client.download_sample_zip(
            sha256, sample_quarantine, allow_raw_download=settings.allow_raw_download
        )
        source_name, sample_bytes = read_one_member_from_zip(zip_path)

        # Mechanical evidence only. The AI does the actual reasoning afterwards.
        analysis = analyze_sample_bytes(sample_bytes, candidate, source_name=source_name)
        strings = extract_printable_strings(sample_bytes)
        source_text = decode_text_for_analysis(sample_bytes, strings)

        # Raw inert source: quarantine ONLY (gitignored, never published).
        source_path = sample_quarantine / "source.txt"
        source_path.write_text(source_text, encoding="utf-8", errors="replace")

        evidence = {
            "schema": "loop-engineering/handoff/v1",
            "collected_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "malwarebazaar": {
                "sha256_hash": candidate.get("sha256_hash"),
                "file_name": candidate.get("file_name"),
                "file_type": candidate.get("file_type"),
                "signature": candidate.get("signature"),
                "tags": candidate.get("tags"),
                "first_seen": candidate.get("first_seen"),
                "reporter": candidate.get("reporter"),
                "delivery_method": candidate.get("delivery_method"),
            },
            "archive_member": source_name,
            "language_hint": infer_language_label(source_name, candidate),
            "mechanical": {
                "byte_count": analysis.byte_count,
                "md5": analysis.md5,
                "sha1": analysis.sha1,
                "sha256": analysis.sha256,
                "entropy": analysis.entropy,
                "file_magic": analysis.file_magic,
                "printable_string_count": analysis.printable_string_count,
                "urls": analysis.static_code.urls,
                "ips": analysis.static_code.ips,
                "domains": analysis.static_code.domains,
                "selected_strings": analysis.selected_strings[:50],
            },
            "source_path": str(source_path),
            "source_truncated": len(source_text) > 200_000,
        }
        handoff_path = sample_quarantine / "handoff.json"
        handoff_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

        # analysis.json (mechanical evidence) is publishable and the verifier's ground truth.
        report_dir = settings.reports_dir / analysis.generated_at.strftime("%Y-%m-%d") / "samples" / analysis.sha256
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "analysis.json").write_text(analysis.to_json(), encoding="utf-8")

        result = {
            "sha256": analysis.sha256,
            "malwarebazaar_sha256": sha256,
            "report_dir": str(report_dir.relative_to(ROOT) if report_dir.is_absolute() else report_dir),
            "handoff_path": str(handoff_path),
            "source_path": str(source_path),
            "member": source_name,
            "bytes": analysis.byte_count,
            "family": candidate.get("signature") or "unknown",
            "file_type": candidate.get("file_type") or "unknown",
            "language_hint": evidence["language_hint"],
            "url_count": len(analysis.static_code.urls),
            "ip_count": len(analysis.static_code.ips),
            "domain_count": len(analysis.static_code.domains),
        }
        print(json.dumps(result, indent=2))
        return 0
    except (ConfigError, MalwareBazaarError, zipfile.BadZipFile, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def read_one_member_from_zip(zip_path: Path) -> tuple[str, bytes]:
    """Pick and read one archived member.

    MalwareBazaar ZIPs are WinZip-AES encrypted (compress_type=99), which
    CPython's zipfile cannot decrypt, so extraction is delegated to 7z. The
    archive password is the public MalwareBazaar convention ("infected"). We
    never execute the member; we only read it as inert bytes.
    """
    names = list_zip_members(zip_path)
    if not names:
        raise ValueError("Downloaded archive contains no files")
    names.sort(key=source_member_score, reverse=True)
    member = names[0]

    extract_dir = zip_path.parent / "extracted"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    extract_member_with_7z(zip_path, member, extract_dir)
    extracted = extract_dir / member
    if not extracted.exists():
        # 7z may flatten paths; fall back to basename search.
        matches = [p for p in extract_dir.rglob("*") if p.is_file() and p.name == Path(member).name]
        if not matches:
            raise ValueError(f"7z did not produce expected member {member}")
        extracted = matches[0]
    size = extracted.stat().st_size
    if size > MAX_SAMPLE_BYTES:
        raise ValueError(
            f"Selected member is {size} bytes, above LOOP_MAX_SAMPLE_BYTES={MAX_SAMPLE_BYTES}"
        )
    return member, extracted.read_bytes()


def list_zip_members(zip_path: Path) -> list[str]:
    with zipfile.ZipFile(zip_path) as archive:
        return [info.filename for info in archive.infolist() if not info.is_dir()]


def extract_member_with_7z(zip_path: Path, member: str, out_dir: Path) -> None:
    if shutil.which("7z") is None:
        raise ValueError("7z is required to extract AES-encrypted MalwareBazaar archives but was not found")
    result = subprocess.run(
        ["7z", "x", f"-p{ZIP_PASSWORD.decode()}", f"-o{out_dir}", str(zip_path), member, "-y"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(f"7z extraction failed: {result.stderr.strip() or result.stdout.strip()}")


def source_member_score(name: str) -> tuple[int, str]:
    lower = name.lower()
    for rank, ext in enumerate(reversed(SOURCE_EXT_PRIORITY), start=1):
        if lower.endswith(ext):
            return (rank, name)
    return (0, name)


def infer_language_label(source_name: str, metadata: dict) -> str:
    lower = source_name.lower()
    mapping = {
        ".ps1": "powershell", ".js": "javascript", ".jse": "javascript",
        ".vbs": "vbscript", ".vbe": "vbscript", ".vba": "vba",
        ".py": "python", ".sh": "shell", ".bash": "shell",
        ".php": "php", ".bat": "batch", ".cmd": "batch", ".hta": "hta", ".wsf": "wsf",
    }
    for ext, lang in mapping.items():
        if lower.endswith(ext):
            return lang
    return str(metadata.get("file_type") or "unknown")


def read_state() -> dict:
    if not STATE_PATH.exists():
        return {"iteration": 0, "analyzed_hashes": []}
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"iteration": 0, "analyzed_hashes": []}
    return data if isinstance(data, dict) else {"iteration": 0, "analyzed_hashes": []}


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run one real single-sample static malware analysis iteration.

This loop intentionally does not produce a 100-sample batch blog. It selects one
MalwareBazaar candidate, downloads only that sample ZIP into quarantine when
explicitly allowed, statically analyzes one archived member in memory, writes a
technical blog/YARA/IOC bundle, and optionally publishes the sanitized outputs.
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
    select_single_candidate,
    write_single_sample_outputs,
)


STATE_PATH = ROOT / "harness" / "generated" / "single-sample-state.json"
MAX_SAMPLE_BYTES = int(os.getenv("LOOP_MAX_SAMPLE_BYTES", str(8 * 1024 * 1024)))
ZIP_PASSWORD = b"infected"


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
                "single-sample analysis requires LOOP_ALLOW_MALWARE_DOWNLOAD=1 inside an isolated lab. "
                "The loop downloads exactly one password-protected sample ZIP into quarantine."
            )

        client = MalwareBazaarClient(
            auth_key=settings.malwarebazaar_auth_key,
            endpoint=settings.malwarebazaar_endpoint,
        )
        state = read_state()
        samples = client.get_recent(selector=selector)
        candidate = select_single_candidate(samples, set(state.get("analyzed_hashes", [])))
        sha256 = str(candidate.get("sha256_hash") or "").lower()
        if not sha256:
            raise MalwareBazaarError("Selected candidate has no SHA-256 hash")

        sample_quarantine = settings.quarantine_dir / sha256
        zip_path = client.download_sample_zip(sha256, sample_quarantine, allow_raw_download=settings.allow_raw_download)
        source_name, sample_bytes = read_one_member_from_zip(zip_path)
        analysis = analyze_sample_bytes(sample_bytes, candidate, source_name=source_name)
        report_dir = write_single_sample_outputs(analysis, settings.reports_dir)
        verify_report_dir(report_dir)

        state = update_state(state, sha256, report_dir, analysis)
        write_state(state)
        append_log(report_dir, analysis.sha256, candidate)
        print(f"selected={sha256}")
        print(f"analyzed_sha256={analysis.sha256}")
        print(f"report_dir={report_dir}")
        print(f"member={source_name}")
        print(f"bytes={len(sample_bytes)}")

        if os.getenv("LOOP_GIT_PUBLISH") == "1":
            return publish_outputs(report_dir)
        return 0
    except (ConfigError, MalwareBazaarError, zipfile.BadZipFile, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def read_one_member_from_zip(zip_path: Path) -> tuple[str, bytes]:
    with zipfile.ZipFile(zip_path) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if not members:
            raise ValueError("Downloaded archive contains no files")
        members.sort(key=lambda info: source_member_score(info.filename), reverse=True)
        member = members[0]
        if member.file_size > MAX_SAMPLE_BYTES:
            raise ValueError(
                f"Selected member is {member.file_size} bytes, above LOOP_MAX_SAMPLE_BYTES={MAX_SAMPLE_BYTES}"
            )
        try:
            with archive.open(member, pwd=ZIP_PASSWORD) as handle:
                return member.filename, handle.read(MAX_SAMPLE_BYTES + 1)
        except NotImplementedError:
            # MalwareBazaar now ships AES-encrypted ZIPs, which the stdlib zipfile
            # cannot decrypt. Fall back to 7z for the decrypt step only; selection
            # above still uses the stdlib central directory.
            data = _extract_member_via_7z(zip_path, member.filename)
            return member.filename, data[: MAX_SAMPLE_BYTES + 1]


def _extract_member_via_7z(zip_path: Path, member_name: str) -> bytes:
    seven_zip = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
    if seven_zip is None:
        raise ValueError(
            "Archive uses AES encryption that the stdlib cannot decrypt and no 7z binary is available"
        )
    result = subprocess.run(
        [seven_zip, "e", "-so", "-p" + ZIP_PASSWORD.decode(), str(zip_path), member_name],
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip() or "unknown 7z error"
        raise ValueError(f"7z failed to extract {member_name}: {detail}")
    return result.stdout


def source_member_score(name: str) -> tuple[int, str]:
    lower = name.lower()
    source_extensions = (".js", ".jse", ".ps1", ".py", ".sh", ".vbs", ".vbe", ".vba", ".bat", ".cmd", ".php")
    return (100 if lower.endswith(source_extensions) else 0, name)


def read_state() -> dict[str, object]:
    if not STATE_PATH.exists():
        return {"iteration": 0, "analyzed_hashes": []}
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"iteration": 0, "analyzed_hashes": []}
    return data if isinstance(data, dict) else {"iteration": 0, "analyzed_hashes": []}


def update_state(state: dict[str, object], malwarebazaar_sha256: str, report_dir: Path, analysis: object) -> dict[str, object]:
    analyzed = [str(value) for value in state.get("analyzed_hashes", [])]
    if malwarebazaar_sha256 not in analyzed:
        analyzed.append(malwarebazaar_sha256)
    return {
        "iteration": int(state.get("iteration", 0)) + 1,
        "last_run_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "last_malwarebazaar_sha256": malwarebazaar_sha256,
        "last_analyzed_sha256": getattr(analysis, "sha256"),
        "last_report_dir": str(report_dir.relative_to(ROOT) if report_dir.is_absolute() else report_dir),
        "analyzed_hashes": analyzed[-500:],
        "next_prompt": "harness/generated/single-sample-next-prompt.md",
    }


def write_state(state: dict[str, object]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    prompt_path = ROOT / "harness" / "generated" / "single-sample-next-prompt.md"
    prompt_path.write_text(render_next_prompt(state), encoding="utf-8")


def render_next_prompt(state: dict[str, object]) -> str:
    return f"""# Next single-sample malware-intel prompt

Continue the real analysis loop. Do not produce a 100-sample batch report.

Read:

- `CLAUDE.md`
- `domains/malware-intel/README.md`
- `docs/malware-intel-architecture.md`
- `{state["last_report_dir"]}/technical-analysis.md`
- `{state["last_report_dir"]}/reviewer-prompt.md`

Tasks:

1. Review the previous single-sample report for unsupported claims.
2. Run `python -m pytest`.
3. Run one more single-sample iteration:

```bash
LOOP_ALLOW_MALWARE_DOWNLOAD=1 LOOP_AUTONOMOUS=1 python scripts/run_single_sample_loop.py
```

4. Verify the new report is one sample only and contains real static evidence.
5. Commit/push only sanitized outputs if publishing is enabled.
6. Continue from the newly generated prompt.
"""


def append_log(report_dir: Path, analyzed_sha256: str, metadata: dict[str, object]) -> None:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    rel_report_dir = report_dir.relative_to(ROOT) if report_dir.is_absolute() else report_dir
    family = metadata.get("signature") or "unknown"
    log_path = ROOT / "LOG.md"
    entry = (
        f"\n## {today} · Single-sample static malware analysis · #analysis #ops\n"
        f"What: Analyzed one MalwareBazaar sample statically ({analyzed_sha256[:16]}, family `{family}`) "
        "and generated blog, IOC JSON, YARA, and reviewer prompt.\n"
        f"Refs: [{rel_report_dir}]({rel_report_dir}) (generated)\n"
    )
    log_path.write_text(log_path.read_text(encoding="utf-8").rstrip() + entry, encoding="utf-8")


def publish_outputs(report_dir: Path) -> int:
    if not is_git_repo():
        print("publish=skipped reason=not-a-git-repository")
        return 0
    rel_report_dir = report_dir.relative_to(ROOT) if report_dir.is_absolute() else report_dir
    paths = ["LOG.md", str(rel_report_dir), "harness/generated/single-sample-state.json", "harness/generated/single-sample-next-prompt.md"]
    run(["git", "add", *paths])
    diff = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT)
    if diff.returncode == 0:
        print("publish=skipped reason=no-changes")
        return 0
    run(["git", "commit", "-m", "Add single-sample malware analysis report"])
    if os.getenv("LOOP_GIT_PUSH") == "1":
        run(["git", "push"])
        print("publish=pushed")
    else:
        print("publish=committed push=skipped")
    return 0


def verify_report_dir(report_dir: Path) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_single_sample_report.py", str(report_dir)],
        cwd=ROOT,
    )
    if result.returncode != 0:
        raise ValueError(f"single-sample report verification failed for {report_dir}")


def is_git_repo() -> bool:
    return subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    raise SystemExit(main())

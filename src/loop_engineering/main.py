"""Command-line entry points for the malware intelligence loop."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from loop_engineering.config import ConfigError, Settings
from loop_engineering.ioc import build_report_bundle
from loop_engineering.malware_bazaar import MalwareBazaarClient, MalwareBazaarError
from loop_engineering.storage import write_report_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive MalwareBazaar IOC reporting loop")
    subparsers = parser.add_subparsers(dest="command", required=True)

    recent = subparsers.add_parser("fetch-recent", help="Fetch recent MalwareBazaar metadata as JSON")
    recent.add_argument("--selector", default="100", choices=["100", "time"], help="Recent selector")
    recent.add_argument("--output", type=Path, help="Optional JSON output path")

    report = subparsers.add_parser("report", help="Fetch metadata and write IOC reports")
    report.add_argument("--selector", default="100", choices=["100", "time"], help="Recent selector")

    download = subparsers.add_parser("download-sample", help="Download a passworded sample ZIP to quarantine")
    download.add_argument("sha256_hash", help="Sample SHA256 hash")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings.from_env()

    try:
        settings.require_malwarebazaar_key()
        client = MalwareBazaarClient(
            auth_key=settings.malwarebazaar_auth_key,
            endpoint=settings.malwarebazaar_endpoint,
        )

        if args.command == "fetch-recent":
            samples = client.get_recent(selector=args.selector)
            payload = json.dumps({"selector": args.selector, "samples": samples}, indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(payload, encoding="utf-8")
            else:
                print(payload, end="")
            return 0

        if args.command == "report":
            samples = client.get_recent(selector=args.selector)
            bundle = build_report_bundle(samples, selector=args.selector)
            written = write_report_bundle(bundle, settings.reports_dir)
            print(f"Wrote report bundle to {written.report_dir}")
            return 0

        if args.command == "download-sample":
            path = client.download_sample_zip(
                args.sha256_hash,
                settings.quarantine_dir,
                allow_raw_download=settings.allow_raw_download,
            )
            print(f"Wrote password-protected sample ZIP to {path}")
            return 0

    except (ConfigError, MalwareBazaarError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error(f"Unhandled command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

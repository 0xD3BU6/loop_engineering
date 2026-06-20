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
from loop_engineering.static_code_analysis import (
    analyze_source_text,
    render_static_code_blog_markdown,
    render_static_code_markdown,
    render_static_code_yara,
)


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

    static_code = subparsers.add_parser("analyze-source", help="Statically analyze an inert source/code sample")
    static_code.add_argument("path", type=Path, help="Text/source sample path")
    static_code.add_argument("--language", default="unknown", help="Language hint for the report")
    static_code.add_argument("--json", type=Path, help="Optional JSON output path")
    static_code.add_argument("--markdown", type=Path, help="Optional Markdown output path")
    static_code.add_argument("--blog", type=Path, help="Optional technical blog Markdown output path")
    static_code.add_argument("--yara", type=Path, help="Optional YARA output path")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings.from_env()

    try:
        if args.command == "fetch-recent":
            settings.require_malwarebazaar_key()
            client = MalwareBazaarClient(
                auth_key=settings.malwarebazaar_auth_key,
                endpoint=settings.malwarebazaar_endpoint,
            )
            samples = client.get_recent(selector=args.selector)
            payload = json.dumps({"selector": args.selector, "samples": samples}, indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(payload, encoding="utf-8")
            else:
                print(payload, end="")
            return 0

        if args.command == "report":
            settings.require_malwarebazaar_key()
            client = MalwareBazaarClient(
                auth_key=settings.malwarebazaar_auth_key,
                endpoint=settings.malwarebazaar_endpoint,
            )
            samples = client.get_recent(selector=args.selector)
            bundle = build_report_bundle(samples, selector=args.selector)
            written = write_report_bundle(bundle, settings.reports_dir)
            print(f"Wrote report bundle to {written.report_dir}")
            return 0

        if args.command == "download-sample":
            settings.require_malwarebazaar_key()
            client = MalwareBazaarClient(
                auth_key=settings.malwarebazaar_auth_key,
                endpoint=settings.malwarebazaar_endpoint,
            )
            path = client.download_sample_zip(
                args.sha256_hash,
                settings.quarantine_dir,
                allow_raw_download=settings.allow_raw_download,
            )
            print(f"Wrote password-protected sample ZIP to {path}")
            return 0

        if args.command == "analyze-source":
            text = args.path.read_text(encoding="utf-8", errors="replace")
            report = analyze_source_text(text, language_hint=args.language)
            if args.json:
                args.json.parent.mkdir(parents=True, exist_ok=True)
                args.json.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if args.markdown:
                args.markdown.parent.mkdir(parents=True, exist_ok=True)
                args.markdown.write_text(render_static_code_markdown(report), encoding="utf-8")
            if args.blog:
                args.blog.parent.mkdir(parents=True, exist_ok=True)
                args.blog.write_text(render_static_code_blog_markdown(report), encoding="utf-8")
            if args.yara:
                args.yara.parent.mkdir(parents=True, exist_ok=True)
                args.yara.write_text(render_static_code_yara(report), encoding="utf-8")
            if not args.json and not args.markdown and not args.blog and not args.yara:
                print(render_static_code_markdown(report), end="")
            return 0

    except (ConfigError, MalwareBazaarError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error(f"Unhandled command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

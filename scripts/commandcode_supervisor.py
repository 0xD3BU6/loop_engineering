#!/usr/bin/env python3
"""Outer supervisor for autonomous CommandCode workers.

The malware-intel loop can generate its own next prompt, but CommandCode may
stop after one agent turn and wait for human input. This supervisor starts a
fresh worker for each iteration, points it at the latest generated prompt, pulls
after the worker exits, and continues until the configured budget is exhausted.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
SINGLE_SAMPLE_PROMPT = ROOT / "harness" / "generated" / "single-sample-next-prompt.md"
FEED_PROMPT = ROOT / "harness" / "generated" / "next-commandcode-prompt.md"
STATE_PATH = ROOT / "harness" / "generated" / "autonomous-state.json"
RUNS_DIR = ROOT / "harness" / "runs"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command_template = os.getenv("COMMANDCODE_CMD", "").strip()
    if not command_template:
        print("error: COMMANDCODE_CMD is required", file=sys.stderr)
        print("example: COMMANDCODE_CMD='commandcode --prompt-file {prompt}'", file=sys.stderr)
        return 2

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    write_supervisor_event("start", {"iterations": args.iterations, "agents": args.agents})

    for cycle in range(1, args.iterations + 1):
        pull_if_requested(args.pull)
        prompt = latest_prompt()
        if not prompt.exists():
            print(f"error: prompt not found: {prompt}", file=sys.stderr)
            return 2

        for agent_index in range(1, args.agents + 1):
            worker_name = f"cycle-{cycle:03d}-agent-{agent_index:02d}"
            print(f"supervisor=launch worker={worker_name} prompt={prompt.relative_to(ROOT)}")
            before = read_state_iteration()
            result = run_worker(command_template, prompt, worker_name, args.timeout_seconds)
            pull_if_requested(args.pull)
            after = read_state_iteration()
            write_supervisor_event(
                "worker",
                {
                    "worker": worker_name,
                    "returncode": result,
                    "iteration_before": before,
                    "iteration_after": after,
                },
            )

            if result != 0:
                print(f"worker={worker_name} status=failed returncode={result}", file=sys.stderr)
                if not args.continue_on_failure:
                    return result

            if after > before:
                print(f"worker={worker_name} status=advanced iteration={after}")
                break

            print(f"worker={worker_name} status=no-advance")
            if agent_index < args.agents:
                time.sleep(args.agent_delay_seconds)

        if args.cycle_delay_seconds:
            time.sleep(args.cycle_delay_seconds)

    write_supervisor_event("stop", {"reason": "iteration-budget-exhausted"})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch fresh CommandCode workers for the malware-intel loop")
    parser.add_argument(
        "--iterations",
        type=int,
        default=int(os.getenv("LOOP_SUPERVISOR_ITERATIONS", "12")),
        help="Maximum supervisor cycles",
    )
    parser.add_argument(
        "--agents",
        type=int,
        default=int(os.getenv("LOOP_SUPERVISOR_AGENTS", "3")),
        help="Fresh workers to try per cycle when one does not advance state",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=int(os.getenv("LOOP_SUPERVISOR_TIMEOUT_SECONDS", "1800")),
        help="Per-worker timeout",
    )
    parser.add_argument(
        "--agent-delay-seconds",
        type=int,
        default=int(os.getenv("LOOP_SUPERVISOR_AGENT_DELAY_SECONDS", "10")),
        help="Delay before trying the next fresh worker",
    )
    parser.add_argument(
        "--cycle-delay-seconds",
        type=int,
        default=int(os.getenv("LOOP_SUPERVISOR_CYCLE_DELAY_SECONDS", "0")),
        help="Delay between supervisor cycles",
    )
    parser.add_argument(
        "--no-pull",
        action="store_false",
        dest="pull",
        help="Do not run git pull --ff-only before/after workers",
    )
    parser.add_argument(
        "--continue-on-failure",
        action="store_true",
        help="Try the next worker even when a worker exits non-zero",
    )
    return parser


def latest_prompt() -> Path:
    override = os.getenv("LOOP_SUPERVISOR_PROMPT", "").strip()
    if override:
        return (ROOT / override).resolve()
    return SINGLE_SAMPLE_PROMPT if SINGLE_SAMPLE_PROMPT.exists() else FEED_PROMPT


def run_worker(command_template: str, prompt: Path, worker_name: str, timeout_seconds: int) -> int:
    command = render_command(command_template, prompt, worker_name)
    env = os.environ.copy()
    env.setdefault("LOOP_AUTONOMOUS", "1")
    env.setdefault("LOOP_GIT_PUBLISH", "1")
    env.setdefault("LOOP_GIT_PUSH", "1")
    env["LOOP_WORKER_NAME"] = worker_name

    log_path = RUNS_DIR / f"{worker_name}.log"
    uses_prompt_argument = "{prompt}" in command_template or "{prompt_rel}" in command_template
    with log_path.open("w", encoding="utf-8") as log:
        log.write(f"$ {' '.join(command)}\n\n")
        log.flush()
        try:
            prompt_input = None if uses_prompt_argument else prompt.open("r", encoding="utf-8")
            process = subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                stdin=prompt_input,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
            )
            if prompt_input:
                prompt_input.close()
        except subprocess.TimeoutExpired:
            log.write(f"\nworker timed out after {timeout_seconds} seconds\n")
            return 124
    return process.returncode


def render_command(command_template: str, prompt: Path, worker_name: str) -> list[str]:
    rendered = command_template.format(
        prompt=str(prompt),
        prompt_rel=str(prompt.relative_to(ROOT)),
        worker=worker_name,
    )
    return shlex.split(rendered)


def pull_if_requested(enabled: bool) -> None:
    if not enabled or not is_git_repo():
        return
    result = subprocess.run(["git", "pull", "--ff-only"], cwd=ROOT)
    if result.returncode != 0:
        print("warning: git pull --ff-only failed; continuing with local state", file=sys.stderr)


def read_state_iteration() -> int:
    if not STATE_PATH.exists():
        return 0
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return 0
    if not isinstance(data, dict):
        return 0
    try:
        return int(data.get("iteration", 0))
    except (TypeError, ValueError):
        return 0


def write_supervisor_event(event: str, payload: dict[str, object]) -> None:
    path = RUNS_DIR / "supervisor-events.jsonl"
    row = {
        "event": event,
        "at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        **payload,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def is_git_repo() -> bool:
    return subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


if __name__ == "__main__":
    raise SystemExit(main())

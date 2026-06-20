# AI harness contract

This repo is designed so CommandCode, Claude Code, Codex, or any other coding-agent harness can
run the loop without being trusted with malware bytes or pasted secrets.

## Agent role

You are the loop engineer for `malware-intel`. Your job is to run the deterministic collector,
inspect the generated reports, update knowledge artifacts when there is a real finding, and
publish sanitized IOC output to GitHub.

## Default analysis run

Use this for real loop engineering: one sample, static analysis, blog, YARA, verifier prompt, then
next iteration.

```bash
export MALWAREBAZAAR_AUTH_KEY=...
export LOOP_ALLOW_MALWARE_DOWNLOAD=1
LOOP_AUTONOMOUS=1 python scripts/run_single_sample_loop.py
```

The single-sample runner:

1. Fetches recent MalwareBazaar metadata.
2. Selects one unprocessed or source-preferred sample.
3. Downloads only that sample ZIP into gitignored `quarantine/`.
4. Reads one archived member in memory and does static analysis only.
5. Writes sanitized outputs under `reports/YYYY-MM-DD/samples/<sha256>/`.
6. Runs deterministic report verification before optional publishing.

## Feed summary run

```bash
export MALWAREBAZAAR_AUTH_KEY=...
LOOP_AUTONOMOUS=1 python scripts/run_malware_intel_loop.py
```

The feed runner:

1. Fetches MalwareBazaar metadata with `get_recent`.
2. Generates reports, a technical blog, IOC feeds, STIX, and YARA under `reports/YYYY-MM-DD/`.
3. Appends a short `LOG.md` entry.
4. Does not download, unpack, or execute malware.
5. Writes `harness/generated/autonomous-state.json` and
   `harness/generated/next-commandcode-prompt.md` when `LOOP_AUTONOMOUS=1`.

## Publishing

Use git publishing only when the workspace is a real git repository:

```bash
export MALWAREBAZAAR_AUTH_KEY=...
export LOOP_GIT_PUBLISH=1
export LOOP_GIT_PUSH=1
LOOP_ALLOW_MALWARE_DOWNLOAD=1 python scripts/run_single_sample_loop.py
```

`LOOP_GIT_PUBLISH=1` commits generated report files and `LOG.md`.
`LOOP_GIT_PUSH=1` pushes the commit. Leave it unset for a local commit-only review flow.

## GitHub trigger

`.github/workflows/malware-intel.yml` runs on:

- manual `workflow_dispatch`
- daily schedule
- pushes to `main`

The workflow ignores commits that only touch `reports/**`, `LOG.md`, or `harness/generated/**`,
and also skips push events created by `github-actions[bot]`. That lets a normal code push start
the loop without creating an infinite chain of report commits.

## Selector

```bash
export LOOP_MALWAREBAZAAR_SELECTOR=time
```

Use `time` for the last 60 minutes, or `100` for the latest 100 additions. The default is `100`.

## Secret handling

Never paste GitHub tokens or MalwareBazaar keys into prompts, markdown files, logs, or source
code. Put them in environment variables locally or repository secrets in GitHub Actions.

## Autonomous operation

Use `harness/autonomous-commandcode-prompt.md` as the root prompt when you want the harness to
continue without human intervention. The single-sample loop creates its own next prompt after each
successful run under `harness/generated/single-sample-next-prompt.md`.

The autonomous loop remains domain-scoped. It may update reports, malware-intel docs, tests, and
workflow files. It must not edit unrelated domains or remove safety boundaries.

## Multi-agent relay

If CommandCode stops after one turn and waits for another prompt, run the outer supervisor:

```bash
export COMMANDCODE_CMD='commandcode --prompt-file {prompt}'
python scripts/commandcode_supervisor.py --iterations 24 --agents 3
```

The supervisor launches fresh workers with the generated next prompt, pulls after each worker, and
continues when `harness/generated/autonomous-state.json` advances. See
`harness/multi-agent-supervisor.md`.

## Safety boundary

The harness may read and summarize generated reports. It must not generate exploit PoC code,
publish raw malware, execute samples, or remove the quarantine guard. Raw ZIP download is only for
isolated lab use with `LOOP_ALLOW_MALWARE_DOWNLOAD=1`; sanitized report outputs are the only files
that may be committed.

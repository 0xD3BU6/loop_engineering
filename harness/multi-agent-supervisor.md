# Multi-agent CommandCode supervisor

CommandCode can complete one autonomous turn and then return to the prompt box. That means the
malware-intel loop needs an outer supervisor that starts a fresh worker with the generated next
prompt after each completion.

Use:

```bash
export MALWAREBAZAAR_AUTH_KEY=...
export LOOP_AUTONOMOUS=1
export LOOP_GIT_PUBLISH=1
export LOOP_GIT_PUSH=1
export COMMANDCODE_CMD='commandcode --prompt-file {prompt}'
python scripts/commandcode_supervisor.py --iterations 24 --agents 3
```

`COMMANDCODE_CMD` is a template. Supported placeholders:

- `{prompt}` - absolute path to `harness/generated/next-commandcode-prompt.md`
- `{prompt_rel}` - repo-relative prompt path
- `{worker}` - generated worker name, such as `cycle-001-agent-01`

If your CommandCode CLI reads prompt text from standard input instead of a prompt-file argument,
use a command template without `{prompt}`:

```bash
export COMMANDCODE_CMD='commandcode'
python scripts/commandcode_supervisor.py
```

In that mode, the supervisor pipes the prompt file into the worker's stdin.

## What the supervisor does

1. Pulls `origin/main` with `git pull --ff-only`.
2. Starts a fresh CommandCode worker with the latest generated prompt.
3. Waits for the worker to finish or time out.
4. Pulls again so it sees commits pushed by the worker.
5. Checks `harness/generated/autonomous-state.json`.
6. If the iteration advanced, starts the next cycle.
7. If the iteration did not advance, tries another fresh worker up to `--agents`.

Logs are written to `harness/runs/`.

## Why this works

The inner loop produces the next prompt:

```text
harness/generated/next-commandcode-prompt.md
```

The supervisor is the outer loop. It does not analyze malware itself; it only keeps launching fresh
domain-scoped agents that read the generated prompt and continue the same malware-intel loop.

## Important

The supervisor can only automate CommandCode if your CommandCode install has a non-interactive CLI
or can read prompt text from stdin. If your version is GUI-only, use the same handoff model but run
multiple terminals manually, each starting from `harness/generated/next-commandcode-prompt.md`.

# CommandCode loop prompt

Read these files first:

- `CLAUDE.md`
- `domains/malware-intel/README.md`
- `docs/malware-intel-architecture.md`
- `harness/README.md`
- `harness/autonomous-commandcode-prompt.md`

Run:

```bash
LOOP_AUTONOMOUS=1 python scripts/run_malware_intel_loop.py
```

After the command finishes:

1. Inspect the generated `reports/YYYY-MM-DD/malwarebazaar-report.md`.
2. If there is a notable new family, file type, or pattern, add a concise `docs/` note or update
   the domain README backlog.
3. If working with source-like malware, use the static `analyze-source` CLI only. Do not execute,
   import, unpack, or dynamically test samples.
4. Do not alter or commit anything under `quarantine/`.
5. Run `python -m pytest`.
6. If publishing is enabled by environment variables, let the runner commit and push. Otherwise,
   summarize changed files for human review.
7. Continue from `harness/generated/next-commandcode-prompt.md` until the harness token/time
   budget ends, a command fails, or a safety rule blocks progress.

Do not ask the user for tokens in chat. Require `MALWAREBAZAAR_AUTH_KEY` and GitHub credentials
through the harness environment.

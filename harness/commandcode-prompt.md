# CommandCode loop prompt

Read these files first:

- `CLAUDE.md`
- `domains/malware-intel/README.md`
- `docs/malware-intel-architecture.md`
- `harness/README.md`
- `harness/autonomous-commandcode-prompt.md`

Run:

```bash
LOOP_ALLOW_MALWARE_DOWNLOAD=1 LOOP_AUTONOMOUS=1 python scripts/run_single_sample_loop.py
```

After the command finishes:

1. Inspect the generated `reports/YYYY-MM-DD/samples/<sha256>/technical-analysis.md`.
2. Run `python scripts/verify_single_sample_report.py <report-dir>`.
3. If there is a notable static finding, add a concise `docs/` note or update the domain README backlog.
4. Do not alter or commit anything under `quarantine/`.
5. Run `python -m pytest`.
6. If publishing is enabled by environment variables, let the runner commit and push. Otherwise,
   summarize changed files for human review.
7. Continue from `harness/generated/single-sample-next-prompt.md` until the harness token/time
   budget ends, a command fails, or a safety rule blocks progress.

Do not ask the user for tokens in chat. Require `MALWAREBAZAAR_AUTH_KEY` and GitHub credentials
through the harness environment.

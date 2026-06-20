# CommandCode loop prompt

Read these files first:

- `CLAUDE.md`
- `domains/malware-intel/README.md`
- `docs/malware-intel-architecture.md`
- `harness/README.md`

Run:

```bash
python scripts/run_malware_intel_loop.py
```

After the command finishes:

1. Inspect the generated `reports/YYYY-MM-DD/malwarebazaar-report.md`.
2. If there is a notable new family, file type, or pattern, add a concise `docs/` note or update
   the domain README backlog.
3. Do not alter or commit anything under `quarantine/`.
4. Run `python -m pytest`.
5. If publishing is enabled by environment variables, let the runner commit and push. Otherwise,
   summarize changed files for human review.

Do not ask the user for tokens in chat. Require `MALWAREBAZAAR_AUTH_KEY` and GitHub credentials
through the harness environment.

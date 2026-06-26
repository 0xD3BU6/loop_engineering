# Next CommandCode autonomous prompt

You are continuing the `malware-intel` loop with no human intervention.

Read first:

- `CLAUDE.md`
- `ARCHITECTURE.md`
- `domains/malware-intel/README.md`
- `docs/malware-intel-architecture.md`
- `harness/README.md`
- `harness/autonomous-commandcode-prompt.md`
- `harness/generated/autonomous-state.json`
- `reports/2026-06-26/malwarebazaar-report.md`

Current state:

- Domain: `malware-intel`
- Iteration: `8`
- Last report: `reports/2026-06-26`
- Last samples: `100`
- Last IOCs: `631`
- Last run: `2026-06-26T04:43:48Z`

Loop:

1. Inspect the latest report for notable defensive findings only.
2. Update only domain-related files if there is a real finding:
   - `docs/`
   - `domains/malware-intel/README.md`
   - `harness/generated/`
   - `reports/`
   - `LOG.md`
3. Do not create exploit PoC code, execute samples, unpack malware, or commit quarantine data.
4. Run `python -m pytest`.
5. Run the next deterministic collection:

```bash
LOOP_AUTONOMOUS=1 python scripts/run_malware_intel_loop.py
```

6. If git publishing is enabled in the environment, let the runner commit/push generated output.
7. Continue by reading the newly generated `harness/generated/next-commandcode-prompt.md`.

Stop only when the harness token/time budget is exhausted, a command fails, or a safety rule would
be violated.

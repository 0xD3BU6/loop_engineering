# Next single-sample malware-intel prompt

Continue the real analysis loop. Do not produce a 100-sample batch report.

Read:

- `CLAUDE.md`
- `domains/malware-intel/README.md`
- `docs/malware-intel-architecture.md`
- `reports/2026-06-21/samples/76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50/technical-analysis.md`
- `reports/2026-06-21/samples/76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50/reviewer-prompt.md`

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

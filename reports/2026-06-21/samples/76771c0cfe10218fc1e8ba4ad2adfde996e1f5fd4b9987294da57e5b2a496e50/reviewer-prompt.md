# Reviewer prompt

Review the single-sample malware analysis in `reports/2026-06-21/samples/76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50`.

Check:

1. `technical-analysis.md` claims are supported by `analysis.json`.
2. `sample.yar` uses static indicators only and does not contain exploit logic.
3. The report does not claim dynamic behavior that was not observed.
4. No raw malware bytes are present in the report directory.
5. The output is useful as a defensive technical blog.

Return findings first, then a short approval or requested changes.

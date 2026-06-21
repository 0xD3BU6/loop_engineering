# Reviewer prompt

Review the single-sample malware analysis in `reports/2026-06-21/samples/33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482`.

Check:

1. `technical-analysis.md` claims are supported by `analysis.json`.
2. `sample.yar` uses static indicators only and does not contain exploit logic.
3. The report does not claim dynamic behavior that was not observed.
4. No raw malware bytes are present in the report directory.
5. The output is useful as a defensive technical blog.

Return findings first, then a short approval or requested changes.

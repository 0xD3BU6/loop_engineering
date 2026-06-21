# Reviewer prompt

Review the single-sample malware analysis in `reports/2026-06-21/samples/409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc`.

Check:

1. `technical-analysis.md` claims are supported by `analysis.json`.
2. `sample.yar` uses static indicators only and does not contain exploit logic.
3. The report does not claim dynamic behavior that was not observed.
4. No raw malware bytes are present in the report directory.
5. The output is useful as a defensive technical blog.

Return findings first, then a short approval or requested changes.

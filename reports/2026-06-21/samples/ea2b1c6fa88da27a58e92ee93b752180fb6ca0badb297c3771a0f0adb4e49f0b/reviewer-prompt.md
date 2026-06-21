# Reviewer prompt

Review the single-sample malware analysis in `reports/2026-06-21/samples/ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b`.

Check:

1. `technical-analysis.md` claims are supported by `analysis.json`.
2. `sample.yar` uses static indicators only and does not contain exploit logic.
3. The report does not claim dynamic behavior that was not observed.
4. No raw malware bytes are present in the report directory.
5. The output is useful as a defensive technical blog.

Return findings first, then a short approval or requested changes.

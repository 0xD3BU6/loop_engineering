# Reviewer prompt

Review the single-sample malware analysis in `reports/2026-06-21/samples/2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d`.

Check:

1. `technical-analysis.md` claims are supported by `analysis.json`.
2. `sample.yar` uses static indicators only and does not contain exploit logic.
3. The report does not claim dynamic behavior that was not observed.
4. No raw malware bytes are present in the report directory.
5. The output is useful as a defensive technical blog.

Return findings first, then a short approval or requested changes.

# Reviewer prompt

Review the single-sample malware analysis in `reports/2026-06-21/samples/2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af`.

Check:

1. `technical-analysis.md` claims are supported by `analysis.json`.
2. `sample.yar` uses static indicators only and does not contain exploit logic.
3. The report does not claim dynamic behavior that was not observed.
4. No raw malware bytes are present in the report directory.
5. The output is useful as a defensive technical blog.

Return findings first, then a short approval or requested changes.

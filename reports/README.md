# reports/ - generated defensive intelligence

Generated report bundles are written under `reports/YYYY-MM-DD/`:

- `malwarebazaar-report.md` - human-readable summary.
- `technical-analysis.md` - sample-by-sample technical blog/writeup covering actions, outcome, per-sample IOCs, and YARA.
- `iocs.csv` - flat IOC feed.
- `iocs.json` - structured IOC feed.
- `stix.json` - STIX 2.1 indicator bundle.
- `malwarebazaar-hash-iocs.yar` - exact SHA-256 YARA indicators using the `hash` module.

Raw malware samples are never stored here. Quarantine downloads, if explicitly enabled in an
isolated lab, are written to `quarantine/` and ignored by git.

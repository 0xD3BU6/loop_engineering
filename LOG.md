# Work log

Append-only journal of finished work bulks, so anyone (human or agent) can catch up fast.
Newest at the BOTTOM. Append an entry whenever a bulk of work wraps (ideally right before
the commit that ships it). Keep entries SHORT: header line + What + Refs, nothing else.

**Entry grammar** (strict, one header line per entry):
```
## YYYY-MM-DD · Short title · #tag1 #tag2
What: 1-2 lines, outcome first.
Refs: [doc](path) (new|updated), repo PR/commit links.
```

**Tags** (reuse before inventing): add your own as loops emerge, e.g.
#analysis #product #content #infra #skill #research #ops #revenue #growth

**Retrieval recipes** (macOS; entry headers always start `## 20`):
```bash
# index of all entries (one line each)
grep '^## 20' LOG.md
# last 5 entries, full
tail -r LOG.md | awk '{print} /^## 20/{c++; if(c==5) exit}' | tail -r
# all entries about a topic
awk '/^## 20/{p=/#product/} p' LOG.md
# entries from a month
awk '/^## 20/{p=/^## 2026-06/} p' LOG.md
```

---

## 2026-06-21 · Malware intel loop architecture · #infra #analysis
What: Added a metadata-only MalwareBazaar IOC reporting loop, GitHub Actions publishing workflow, and defensive safety boundary for raw sample handling.
Refs: [domain](domains/malware-intel/README.md) (new), [architecture](docs/malware-intel-architecture.md) (new), [reports](reports/README.md) (new)

## 2026-06-21 · AI harness runner · #infra #ops
What: Added a one-command harness runner and CommandCode prompt contract for autonomous metadata-only report generation and optional git publishing.
Refs: [harness](harness/README.md) (new), [runner](scripts/run_malware_intel_loop.py) (new)
## 2026-06-20 · MalwareBazaar IOC report · #analysis #ops
What: Generated metadata-only MalwareBazaar report with 100 samples and 625 IOCs.
Refs: [reports/2026-06-20](reports/2026-06-20) (generated)

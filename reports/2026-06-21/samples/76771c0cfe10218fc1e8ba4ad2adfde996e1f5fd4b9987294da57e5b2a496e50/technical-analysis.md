# Storytime: Dissecting a An unlabelled JS sample

> **Source:** [MalwareBazaar](https://bazaar.abuse.ch/sample/76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50/) · **SHA-256** `76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50` · **Family** `unknown` · **Static analysis only — the sample was never run.**

## The Story

It showed up on MalwareBazaar as a 8122362-byte `js` file, with no family label. We pulled exactly one copy into quarantine, cracked open the password-protected archive, and read the bytes as inert text. Nothing here was executed — every claim below comes from reading the code, not running it. Here is what it was hiding.

## First Contact — The Code As It Arrived

Straight out of the archive, a portion of the sample looks like this (defanged):

```javascript
(no readable source excerpt)
```

## Executive Summary

One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. Static evidence produced 3 IOCs and 0 code/string findings.

## What The Agent Did

1. Pulled recent MalwareBazaar metadata.
2. Selected one unprocessed or source-preferred candidate.
3. Downloaded only that sample's password-protected ZIP into quarantine.
4. Read one archived member into memory for static analysis.
5. Calculated hashes, entropy, file magic, printable strings, IOCs, and suspicious code/string patterns.
6. Generated this technical blog, structured JSON, IOC JSON, YARA, and a verifier prompt.

## Sample Identity

| Field | Value |
|---|---|
| MalwareBazaar SHA-256 | `76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50` |
| Analyzed SHA-256 | `76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50` |
| Family label | `unknown` |
| File name | `RFQ-MRF-889-MHS-TLQ-520 # 2600260001.js` |
| Archived member | `76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50.js` |
| File type | `js` |
| First seen | `2026-06-21 14:12:30` |
| Tags | `js` |

## Static Triage

| Property | Value |
|---|---:|
| Bytes analyzed | 8122362 |
| Entropy | 2.169 |
| Printable strings | 0 |
| File magic | `ff fe 2f 00 2f 00 20 00` |

## IOCs

| Type | Value |
|---|---|
| MD5 | `0fde1288ef288731aef0855b08be049a` |
| SHA-1 | `827749fd69bc733ab31a00d2376f5fcdcf58968d` |
| SHA-256 | `76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50` |

## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| info | none |  | No suspicious source/string patterns were detected by the static rules. |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| none |

## What We've Learned So Far

How this sample sits against everything the loop has analyzed before:

- Corpus before this sample: **4** prior sample(s).
- No overlap with earlier samples yet — this one expands the knowledge base.


## YARA Rules

The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.

```yara
import "hash"

rule Single_Sample_Static_76771c0cfe10218f
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50"
    md5 = "0fde1288ef288731aef0855b08be049a"
    sha1 = "827749fd69bc733ab31a00d2376f5fcdcf58968d"
    file_magic = "ff fe 2f 00 2f 00 20 00"
    malwarebazaar_family = "unknown"
  strings:
    $placeholder = "no_selected_static_strings"
  condition:
    hash.sha256(0, filesize) == "76771c0cfe10218fc1e8ba4ad2adfde996e1f5fd4b9987294da57e5b2a496e50"
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "javascript"
    analysis = "static text only; sample not executed"
  strings:
    $static_placeholder = "no_static_iocs_found"
  condition:
    false
}
```

## Analyst Assessment

MalwareBazaar did not provide a family label; treat this as an unknown sample until corroborated. The static rule set did not find source-like behavior markers; further insight requires richer static features.

## Verification Notes

- A second agent should verify that the blog claims are supported by `analysis.json` and `sample.yar`.
- No dynamic behavior should be asserted unless a future static source analysis produces supporting evidence.
- The raw sample ZIP remains in `quarantine/` and must not be committed.

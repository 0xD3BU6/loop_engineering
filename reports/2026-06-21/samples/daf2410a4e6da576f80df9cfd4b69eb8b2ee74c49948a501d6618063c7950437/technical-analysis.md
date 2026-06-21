# Single-Sample Static Malware Analysis - `daf2410a4e6da576`

## Executive Summary

The agent selected one MalwareBazaar submission and performed static analysis on that single artifact. The sample was not executed, loaded, imported, or dynamically tested. Static evidence produced 3 IOCs and 1 code/string findings, plus 2 metadata-derived network indicator(s) listed separately below.

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
| MalwareBazaar SHA-256 | `daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437` |
| Analyzed SHA-256 | `daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437` |
| Family label | `RemcosRAT` |
| File name | `givewegivingbestsolutionsforbetterplaces.js` |
| Archived member | `daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437.js` |
| File type | `js` |
| First seen | `2026-06-21 09:42:19` |
| Tags | `46-183-223-7, js, kelvin654-duckdns-org, RemcosRAT, spam-ita` |

## Static Triage

| Property | Value |
|---|---:|
| Bytes analyzed | 40906 |
| Entropy | 4.503 |
| Printable strings | 1023 |
| File magic | `source-like text` |

## IOCs

| Type | Value |
|---|---|
| MD5 | `f749306e539eab248f698468a5ffc7f0` |
| SHA-1 | `d7bbb24c3a449bbdf9031fb92753b2d96a68a587` |
| SHA-256 | `daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437` |

## Metadata-Derived Network Indicators

These indicators come from MalwareBazaar submission tags, not from bytes observed in this sample. The payload is obfuscated, so its real C2 is not visible to static text extraction. Domain values are reconstructed from dash-encoded tags and should be verified before blocking.

| Type | Value | Source tag |
|---|---|---|
| IP | `46.183.223.7` | metadata |
| Domain | `kelvin654.duckdns.org` | metadata |

## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| medium | persistence | `Startup` | Matched 1 occurrence(s) |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| none |

## YARA Rules

The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.

```yara
import "hash"

rule Single_Sample_Static_daf2410a4e6da576
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
    md5 = "f749306e539eab248f698468a5ffc7f0"
    sha1 = "d7bbb24c3a449bbdf9031fb92753b2d96a68a587"
    file_magic = "source-like text"
    malwarebazaar_family = "RemcosRAT"
  strings:
    $placeholder = "no_selected_static_strings"
  condition:
    hash.sha256(0, filesize) == "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "javascript"
    analysis = "static text only; sample not executed"
  strings:
    $persistence_01 = /Startup/ nocase
  condition:
    any of them
}


rule Single_Sample_Metadata_Network_daf2410a4e6da576
{
  meta:
    source = "loop-engineering single-sample analysis (MalwareBazaar metadata)"
    analysis = "network indicators from submission tags; not statically observed"
    sha256 = "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
  strings:
    $n01 = "46.183.223.7" nocase
    $n02 = "kelvin654.duckdns.org" nocase
  condition:
    any of them
}
```

## Analyst Assessment

MalwareBazaar labels this sample as `RemcosRAT`, so triage should start with that family context.

## Verification Notes

- A second agent should verify that the blog claims are supported by `analysis.json` and `sample.yar`.
- No dynamic behavior should be asserted unless a future static source analysis produces supporting evidence.
- The raw sample ZIP remains in `quarantine/` and must not be committed.

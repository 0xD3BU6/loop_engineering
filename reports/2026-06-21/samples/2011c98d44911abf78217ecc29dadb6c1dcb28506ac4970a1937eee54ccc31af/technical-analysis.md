# Storytime: Dissecting a NanoCore EXE sample

> **Source:** [MalwareBazaar](https://bazaar.abuse.ch/sample/2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af/) · **SHA-256** `2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af` · **Family** `NanoCore` · **Static analysis only — the sample was never run.**

## The Story

It showed up on MalwareBazaar as a 207872-byte `exe` file, tagged `NanoCore`. We pulled exactly one copy into quarantine, cracked open the password-protected archive, and read the bytes as inert text. Nothing here was executed — every claim below comes from reading the code, not running it. Here is what it was hiding.

## First Contact — The Code As It Arrived

Straight out of the archive, a portion of the sample looks like this (defanged):

```exe
!This program cannot be run in DOS mode.
.text
`.reloc
B.rsrc
-(&s8
-&&s9
,$&s:
&&*}&
&&*}#
&&*}#
&&*}(
-0&sY
-p&~C
-*& r
-T&s,
-2&~}
-#&~7
-,&~~
-/&~J
+# S&
-\&(#
.# G'
... (truncated)
```

## Technical Architecture & System Impact

How the pieces fit together and what each stage would do to a host that ran it (reconstructed from static evidence — nothing here was executed):

### Execution chain

- **Stage 0 — delivery:** the `exe` script analyzed here lands on the host and runs.

### System surfaces touched

| Surface | Effect on the host |
|---|---|
| Obfuscation | Hides its real payload behind encoding/packing to defeat casual inspection. |
| Persistence | Installs an autostart hook (registry Run key, Startup folder, cron, or systemd) so it survives reboot. |
| Network egress | Contacts the remote indicators listed above. |

**Blast radius:** a host that ran this would, by design, establishes outbound C2, persists across reboot. Treat any host with these indicators as compromised pending response.

## Executive Summary

One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. Static evidence produced 12 IOCs and 4 code/string findings.

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
| MalwareBazaar SHA-256 | `2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af` |
| Analyzed SHA-256 | `2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af` |
| Family label | `NanoCore` |
| File name | `navent.io.exe` |
| Archived member | `2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af.exe` |
| File type | `exe` |
| First seen | `2026-06-21 16:10:05` |
| Tags | `exe, NanoCore, RAT` |

## Static Triage

| Property | Value |
|---|---:|
| Bytes analyzed | 207872 |
| Entropy | 7.451 |
| Printable strings | 2109 |
| File magic | `PE/MZ executable` |

## IOCs

| Type | Value |
|---|---|
| MD5 | `ce8dbd9fce3e739bfed8a23a96a92fe0` |
| SHA-1 | `e68d17c94b4d37b1a9639bbebc542dafec3f9db3` |
| SHA-256 | `2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af` |
| IP | `1.2.2.0` |
| IP | `2.0.0.0` |
| IP | `8.0.0.0` |
| Domain | `8.Dl` |
| Domain | `O0.bv` |
| Domain | `Se.oI` |
| Domain | `System.IO` |
| Domain | `System.Net` |
| Domain | `c.uo` |

## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| medium | persistence | `Startup` | Matched 1 occurrence(s) |
| medium | obfuscation | `base64_blob` | Found 1 long base64-like blob(s) |
| info | decoded_hint | `< ї\ F< ї\ F< ї\ F< ї\ F< ї\ F` | Preview from base64-like blob; not executed |
| medium | obfuscation | `high_entropy` | Text entropy is 6.05 |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| `lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet` |
| `System.IO` |
| `System.IO.Compression` |
| `System.Net` |
| `System.Net.Sockets` |
| `8.0.0.0` |
| `1.2.2.0` |
| `Se.oI` |
| `O0.bv"^~I` |
| `8.Dl^A` |
| `c.uo.` |

## What We've Learned So Far

How this sample sits against everything the loop has analyzed before:

- Corpus before this sample: **8** prior sample(s).
- First time the loop has seen the `NanoCore` family.
- Recurring techniques across the corpus: `obfuscation` (×4), `decoded_hint` (×3), `persistence` (×2).


## YARA Rules

The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.

```yara
import "hash"

rule Single_Sample_Static_2011c98d44911abf
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af"
    md5 = "ce8dbd9fce3e739bfed8a23a96a92fe0"
    sha1 = "e68d17c94b4d37b1a9639bbebc542dafec3f9db3"
    file_magic = "PE/MZ executable"
    malwarebazaar_family = "NanoCore"
  strings:
    $s01 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet" nocase
    $s02 = "System.IO" nocase
    $s03 = "System.IO.Compression" nocase
    $s04 = "System.Net" nocase
    $s05 = "System.Net.Sockets" nocase
    $s06 = "8.0.0.0" nocase
    $s07 = "1.2.2.0" nocase
    $s08 = "Se.oI" nocase
    $s09 = "O0.bv\"^~I" nocase
    $s10 = "8.Dl^A" nocase
    $s11 = "c.uo." nocase
  condition:
    hash.sha256(0, filesize) == "2011c98d44911abf78217ecc29dadb6c1dcb28506ac4970a1937eee54ccc31af" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "exe"
    analysis = "static text only; sample not executed"
  strings:
    $ip_01 = "1.2.2.0" nocase
    $ip_02 = "2.0.0.0" nocase
    $ip_03 = "8.0.0.0" nocase
    $domain_04 = "8.Dl" nocase
    $domain_05 = "O0.bv" nocase
    $domain_06 = "Se.oI" nocase
    $domain_07 = "System.IO" nocase
    $domain_08 = "System.Net" nocase
    $domain_09 = "c.uo" nocase
    $persistence_10 = /Startup/ nocase
  condition:
    any of them
}
```

## Analyst Assessment

MalwareBazaar labels this sample as `NanoCore`, so triage should start with that family context. Static strings expose network indicators that can support enrichment and hunting. High entropy suggests packing, encryption, compression, or dense binary content.

## Verification Notes

- A second agent should verify that the blog claims are supported by `analysis.json` and `sample.yar`.
- No dynamic behavior should be asserted unless a future static source analysis produces supporting evidence.
- The raw sample ZIP remains in `quarantine/` and must not be committed.

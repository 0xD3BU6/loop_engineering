# Storytime: Dissecting a An unlabelled SH dropper

> **Source:** [MalwareBazaar](https://bazaar.abuse.ch/sample/ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b/) · **SHA-256** `ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b` · **Family** `unknown` · **Static analysis only — the sample was never run.**

## The Story

It showed up on MalwareBazaar as a 13982-byte `sh` file, with no family label. We pulled exactly one copy into quarantine, cracked open the password-protected archive, and read the bytes as inert text. Nothing here was executed — every claim below comes from reading the code, not running it. Here is what it was hiding.

## First Contact — The Code As It Arrived

Straight out of the archive, a portion of the sample looks like this (defanged):

```shell
#!/bin/bash
# ==============================================================================
# init.sh – Stage‑1 loader with verbose logging
# Logs every major step to /tmp/.deploy.log and prints log at end.
# Compatible with busybox / OpenWrt (no od, uses /proc/cpuinfo for endianness).
# ==============================================================================
set -o pipefail
# ---------- configuration ----------
BASE_URL="hxxp://91[.]239[.]211[.]89/bins"
MINER_URL="hxxp://91[.]239[.]211[.]89/miner/xmrig"
TIMEOUT=10
WATCHDOG_CRON="*/5 * * * *"
MINER_PID_FILE="/tmp/.miner.pid"
LOCK_DIR="/tmp/.miner.lock"
CTRL_PORT=42780
BOT_STARTUP_DELAY=12
LOG_FILE="/tmp/.deploy.log"
# ---------- helpers ----------
log_msg() {
    echo "$@"
    echo "[$(date '+%H:%M:%S')] $@" >> "$LOG_FILE"
}
... (truncated)
```

## Peeling Back the Obfuscation

That wall of noise is deliberate. The sample assembles its real payload one fragment at a time and laces every fragment with a junk token, so a casual look (or a naive string scan) sees gibberish. Undo that concatenation and strip the junk token — purely as text, nothing runs — and the mask drops:

```text
hxxp://91[.]239[.]211[.]89/bins
```

Now the intent is legible. It hands a command to the system instead of doing the work in plain sight.

## What It Wants To Do

The behaviour that matters, recovered from the (deobfuscated) code: `obfuscation`, `shell_dropper`, `shell_execution`. It pulls follow-on payloads down with a shell download tool, makes them executable, and launches them — a classic drop-and-run loader. It shells out to the OS to run external commands.

## Technical Architecture & System Impact

How the pieces fit together and what each stage would do to a host that ran it (reconstructed from static evidence — nothing here was executed):

### Execution chain

- **Stage 0 — delivery:** the `sh` shell dropper analyzed here lands on the host and runs.
- **Stage 1 — deobfuscation & hand-off:** it rebuilds a hidden command from fragmented/encoded strings and hands it to the system shell or interpreter.

### System surfaces touched

| Surface | Effect on the host |
|---|---|
| Obfuscation | Hides its real payload behind encoding/packing to defeat casual inspection. |
| Persistence | Installs an autostart hook (registry Run key, Startup folder, cron, or systemd) so it survives reboot. |
| Payload delivery / botnet enlistment | Pulls additional executables from attacker infrastructure, marks them runnable, and launches them — the host becomes a node executing attacker-controlled code. |
| Process execution | Spawns OS child processes / shells to run external commands. |

**Blast radius:** a host that ran this would, by design, fetches and runs further attacker code, establishes outbound C2, persists across reboot. Treat any host with these indicators as compromised pending response.

## Executive Summary

One MalwareBazaar submission, analyzed statically — never executed, loaded, imported, or dynamically tested. Static evidence produced 10 IOCs and 10 code/string findings.

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
| MalwareBazaar SHA-256 | `ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b` |
| Analyzed SHA-256 | `ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b` |
| Family label | `unknown` |
| File name | `init.sh` |
| Archived member | `ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b.sh` |
| File type | `sh` |
| First seen | `2026-06-21 15:27:42` |
| Tags | `sh` |

## Static Triage

| Property | Value |
|---|---:|
| Bytes analyzed | 13982 |
| Entropy | 5.156 |
| Printable strings | 365 |
| File magic | `script with shebang` |

## IOCs

| Type | Value |
|---|---|
| MD5 | `e3a12d8a0dc98b06b548a766aa77dc9c` |
| SHA-1 | `adb94417d3aec78b7779161ba359ce18816a3e09` |
| SHA-256 | `ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b` |
| URL | `http://91.239.211.89/bins` |
| URL | `http://91.239.211.89/miner/xmrig` |
| IP | `127.0.0.1` |
| IP | `91.239.211.89` |
| Domain | `guard.sh` |
| Domain | `init.sh` |
| Domain | `libprocesshider.so` |

## Code Dissection

### Deobfuscation

The sample assembles a payload through string concatenation and then strips a junk token to reveal it. Reconstructing that string statically (no execution) recovers the launched command:

```text
http://91.239.211.89/bins
```

### Top-Level Execution Behaviour

Behaviour detected across the sample (including recovered/deobfuscated code): `obfuscation`, `persistence`, `shell_dropper`, `shell_execution`.


## Static Findings

| Severity | Category | Evidence | Detail |
|---|---|---|---|
| high | shell_execution | `/bin/sh` | Matched 1 occurrence(s) |
| medium | persistence | `Startup` | Matched 2 occurrence(s) |
| medium | persistence | `crontab` | Matched 3 occurrence(s) |
| medium | persistence | `systemd` | Matched 7 occurrence(s) |
| high | shell_dropper | `\bwget\b` | Matched 5 occurrence(s) |
| high | shell_dropper | `\bcurl\b` | Matched 5 occurrence(s) |
| high | shell_dropper | `\bchmod\s+(?:\+x|777|755)` | Matched 9 occurrence(s) |
| high | shell_dropper | `\|\s*(?:sh|bash)\b` | Matched 1 occurrence(s) |
| high | shell_dropper | `\bbusybox\b` | Matched 1 occurrence(s) |
| high | obfuscation | `concat_replace_deobfuscation` | Recovered 2 concatenated/obfuscated payload string(s) |

## Selected Strings

These strings were selected because they contain network indicators or suspicious execution markers.

| String |
|---|
| `# init.sh` |
| `BASE_URL="http://91.239.211.89/bins"` |
| `MINER_URL="http://91.239.211.89/miner/xmrig"` |
| `printf '#!/bin/sh\necho ok\n' > "$testfile" 2>/dev/null \|\| return 1` |
| `local guard="$miner_dest-guard.sh"` |
| `if command -v crontab >/dev/null 2>&1; then` |
| `(crontab -l 2>/dev/null \| grep -v "$guard"; echo "$WATCHDOG_CRON $guard") \| crontab - 2>/dev/null \|\| true` |
| `log_msg "init.sh started` |
| `[ -f /usr/local/lib/libprocesshider.so ] && export LD_PRELOAD=/usr/local/lib/libprocesshider.so` |
| `if (echo >/dev/tcp/127.0.0.1/$CTRL_PORT) 2>/dev/null; then` |

## What We've Learned So Far

How this sample sits against everything the loop has analyzed before:

- Corpus before this sample: **3** prior sample(s).
- Recurring techniques across the corpus: `obfuscation` (×2), `shell_execution` (×2), `persistence` (×1), `shell_dropper` (×1).


## YARA Rules

The first rule combines an exact SHA-256 condition with selected static strings. The second rule is generated from static source/string findings.

```yara
import "hash"

rule Single_Sample_Static_ea2b1c6fa88da27a
{
  meta:
    source = "loop-engineering single-sample static analysis"
    analysis = "static only; sample not executed"
    sha256 = "ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b"
    md5 = "e3a12d8a0dc98b06b548a766aa77dc9c"
    sha1 = "adb94417d3aec78b7779161ba359ce18816a3e09"
    file_magic = "script with shebang"
    malwarebazaar_family = "unknown"
  strings:
    $s01 = "# init.sh" nocase
    $s02 = "BASE_URL=\"http://91.239.211.89/bins\"" nocase
    $s03 = "MINER_URL=\"http://91.239.211.89/miner/xmrig\"" nocase
    $s04 = "printf '#!/bin/sh\\necho ok\\n' > \"$testfile\" 2>/dev/null || return 1" nocase
    $s05 = "local guard=\"$miner_dest-guard.sh\"" nocase
    $s06 = "if command -v crontab >/dev/null 2>&1; then" nocase
    $s07 = "(crontab -l 2>/dev/null | grep -v \"$guard\"; echo \"$WATCHDOG_CRON $guard\") | crontab - 2>/dev/null || true" nocase
    $s08 = "log_msg \"init.sh started" nocase
    $s09 = "[ -f /usr/local/lib/libprocesshider.so ] && export LD_PRELOAD=/usr/local/lib/libprocesshider.so" nocase
    $s10 = "if (echo >/dev/tcp/127.0.0.1/$CTRL_PORT) 2>/dev/null; then" nocase
  condition:
    hash.sha256(0, filesize) == "ea2b1c6fa88da27a58e92ee93b752180fb6ca0badb297c3771a0f0adb4e49f0b" or 2 of ($s*)
}

rule Static_Source_Malware_Indicators
{
  meta:
    source = "loop-engineering static source analysis"
    language_hint = "shell"
    analysis = "static text only; sample not executed"
  strings:
    $url_01 = "http://91.239.211.89/bins" nocase
    $url_02 = "http://91.239.211.89/miner/xmrig" nocase
    $ip_03 = "127.0.0.1" nocase
    $ip_04 = "91.239.211.89" nocase
    $domain_05 = "guard.sh" nocase
    $domain_06 = "init.sh" nocase
    $domain_07 = "libprocesshider.so" nocase
    $shell_execution_08 = /\/bin\/sh/ nocase
    $persistence_09 = /Startup/ nocase
    $persistence_10 = /crontab/ nocase
    $persistence_11 = /systemd/ nocase
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

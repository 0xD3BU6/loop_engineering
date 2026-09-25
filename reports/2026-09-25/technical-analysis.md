# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-25

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 649 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

## What The Agent Did

1. Queried the MalwareBazaar Community API for recent submissions.
2. Walked every returned sample individually.
3. Normalized per-sample hashes, family labels, file names, file types, tags, and timestamps.
4. Produced per-sample IOC tables and exact SHA-256 YARA rules.
5. Wrote this Markdown report for GitHub publication and defender review.

## Run Outcome

| Metric | Value |
|---|---:|
| Samples analyzed | 100 |
| Total IOCs | 649 |
| Unique family labels | 12 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 52 |
| unknown | 33 |
| VShell | 4 |
| ValleyRAT | 2 |
| AsyncRAT | 2 |
| RustyStealer | 1 |
| CobaltStrike | 1 |
| ColibriLoader | 1 |
| RedLineStealer | 1 |
| NanoCore | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 57 |
| exe | 23 |
| php | 10 |
| sh | 2 |
| zip | 2 |
| unknown | 2 |
| dll | 2 |
| js | 2 |

## Per-Sample Analysis

### Sample 1: `b51bfb4f6afbf2bb`

| Field | Value |
|---|---|
| SHA-256 | `b51bfb4f6afbf2bb8f7f10a25cd40456b63866a92f0b745b2e2d245e6834e4a3` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-25 05:00:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d965982af5ffd0ce3039190a5461b80` |
| SHA-1 | `77d870db7fefe2e7462a02beb67913fe9b25a6a5` |
| SHA-256 | `b51bfb4f6afbf2bb8f7f10a25cd40456b63866a92f0b745b2e2d245e6834e4a3` |
| SHA3-384 | `b170ca80e095ff498a867dc2ef115e209c839e3c75de1be503b8c307503ba8261b6c911e0bda92730d5997cb11d2eced` |
| TLSH | `T16F432B8EB9E2993FC5D493BAFB5E121D3315B3D8C1CA3717CD098B64278650E8D2B681` |
| TELFHASH | `t1a0e06101fd65da1999cb9a74ee9d03a59900231761174b21cf50d7e4c83f054f709eda` |
| SSDEEP | `1536:aYCT5jd+9WlvDh4Ishav8NEXpig+mh9Vv:arT5xfkph+8NE5D+m3d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_b51bfb4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b51bfb4f6afbf2bb8f7f10a25cd40456b63866a92f0b745b2e2d245e6834e4a3"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:38"
  condition:
    hash.sha256(0, filesize) == "b51bfb4f6afbf2bb8f7f10a25cd40456b63866a92f0b745b2e2d245e6834e4a3"
}
```

### Sample 2: `f3c90a768b74b19f`

| Field | Value |
|---|---|
| SHA-256 | `f3c90a768b74b19fe48f8f26449e605137d22739d151d15ecbe4c5e399a70aea` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-25 05:00:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5a9210bf530bd9826398153e895702e` |
| SHA-1 | `2ce839d572794e6fbbb51f38ce4da4168fc0f66e` |
| SHA-256 | `f3c90a768b74b19fe48f8f26449e605137d22739d151d15ecbe4c5e399a70aea` |
| SHA3-384 | `45bcbc327a00c40fe5ad9a777a434b053c37f30432b877d13afc0cd57c2a8042493b2017c751969c211e796df4a0687c` |
| TLSH | `T104F31946F9819B12D5C112BAFE1E124E33231B78E2DE72039E146F257B8A97F0E7B415` |
| TELFHASH | `t102213072df404caca7d5845dc15bb0289aec38f92b033442ce2d6f8d89a3880b928037` |
| SSDEEP | `3072:B8rxODOMPQxcwVX0IcX7UWrRdNhyCzOa4MypDus:BqMPQ3VX8U0thyCzOanWus` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_f3c90a76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3c90a768b74b19fe48f8f26449e605137d22739d151d15ecbe4c5e399a70aea"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:36"
  condition:
    hash.sha256(0, filesize) == "f3c90a768b74b19fe48f8f26449e605137d22739d151d15ecbe4c5e399a70aea"
}
```

### Sample 3: `d18b4c9e0fe9fe36`

| Field | Value |
|---|---|
| SHA-256 | `d18b4c9e0fe9fe36a84bc787cc1b7a378fe4aab8aa4a71e370f35f515b6d4ec8` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-25 05:00:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64f964073ebccbecc32a81d0aec2ef67` |
| SHA-1 | `11af08a5bfc0cbf8eb5fcc2e7b954aaf197f563a` |
| SHA-256 | `d18b4c9e0fe9fe36a84bc787cc1b7a378fe4aab8aa4a71e370f35f515b6d4ec8` |
| SHA3-384 | `5329185c3bea254062726f8002c7d9c03c27f2e0821019f31515ee1cdeba27c8d86c9d8e96b17ef2effb22c5eac0e940` |
| TLSH | `T1A1D37BA2C86A6FA8C264D674B4748F781B93D51190875FFE52BBC3B58047D8CF9093B8` |
| SSDEEP | `1536:F3agWIs24aO2G1Vw0k1nHhGkhC5K7/WDoifXWdkUWkiXK/QOolQkU59:F3IE622Vwb1nBG4WK6DoYXWVia/kU59` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_d18b4c9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d18b4c9e0fe9fe36a84bc787cc1b7a378fe4aab8aa4a71e370f35f515b6d4ec8"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:12"
  condition:
    hash.sha256(0, filesize) == "d18b4c9e0fe9fe36a84bc787cc1b7a378fe4aab8aa4a71e370f35f515b6d4ec8"
}
```

### Sample 4: `968d6684b22dd9b4`

| Field | Value |
|---|---|
| SHA-256 | `968d6684b22dd9b4b39f9e4e376c194c6f95a318850cd703300acdcefd96596e` |
| Family label | `unknown` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-25 05:00:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `092e2507c784b83359724e061f2fce3a` |
| SHA-1 | `dd1483557e4882caa7a5bc2eb78d10c11fb6ff7e` |
| SHA-256 | `968d6684b22dd9b4b39f9e4e376c194c6f95a318850cd703300acdcefd96596e` |
| SHA3-384 | `8ae1acabda0785f17176cb5299c9df1eb36ebec05e7cbd47534d09409fdb24dc0105a55e11a095040335741e86184e66` |
| TLSH | `T178B2E1F0E98CA624C9B1DA75F829C7874F144F70A3E0F1533324431AA6A5962B1ADDA9` |
| SSDEEP | `768:j7V9P20hS4FKe1THl4VXHhI54Dw7Is3UozyL:jJQ3uHl4VXA4DW9zG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_968d6684
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "968d6684b22dd9b4b39f9e4e376c194c6f95a318850cd703300acdcefd96596e"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:11"
  condition:
    hash.sha256(0, filesize) == "968d6684b22dd9b4b39f9e4e376c194c6f95a318850cd703300acdcefd96596e"
}
```

### Sample 5: `f10c00d90bdc9326`

| Field | Value |
|---|---|
| SHA-256 | `f10c00d90bdc9326b6f7f2adec8821e94df9888fe3c8d493881bd17ae90455f4` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-25 05:00:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81e2786b2fe1cc3b3e19ec33604b22a6` |
| SHA-1 | `35f3115b97a474d7d9d01a33d1ce5e4a64fbd5da` |
| SHA-256 | `f10c00d90bdc9326b6f7f2adec8821e94df9888fe3c8d493881bd17ae90455f4` |
| SHA3-384 | `7e3372c20f297fa31a7db0c9194c07749d4aa115199a8f3afec50ae3ffeeeee7839d3911c0ccb4a5771bc7f55c9c5660` |
| TLSH | `T1005302A113A8BDF44E10243789DAA4956A74466481BF3863057D2B7CFFE3ADDD21CF82` |
| SSDEEP | `1536:429eu6GC1QuDo5qe/X9rfQilQ4LAQ4SX+f5Rr6BLnx:42Eu1GowqXJDZ4Suf5gLnx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_f10c00d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f10c00d90bdc9326b6f7f2adec8821e94df9888fe3c8d493881bd17ae90455f4"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:09"
  condition:
    hash.sha256(0, filesize) == "f10c00d90bdc9326b6f7f2adec8821e94df9888fe3c8d493881bd17ae90455f4"
}
```

### Sample 6: `6dd0443fc8902fcd`

| Field | Value |
|---|---|
| SHA-256 | `6dd0443fc8902fcd9daa12d3de222a4c8d2976e1bf44f1d6608c956af810740f` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-09-25 05:00:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43a1e1b38dc91955a00c87fb2673987f` |
| SHA-1 | `ed54ccd72fa395ea5aea36ddf0eda7a674181f8c` |
| SHA-256 | `6dd0443fc8902fcd9daa12d3de222a4c8d2976e1bf44f1d6608c956af810740f` |
| SHA3-384 | `2f7e8416643eb7f323283ed04d02d580ebafa2c89b878092136899ad51b77fd8acdca625a68d7b08441b4e181320c96a` |
| TLSH | `T114C45D66BDA19BD0C5E149BEFBAE436872035BB9E2EFB106CA045F907BD54810F3E141` |
| SSDEEP | `6144:S7bC/NwUNW4MWeJ8/P1fzB+yGHuXI+RaIJUWYU8BPUa7/xva5G3X587jx+vr:P/eWdlAHuY+R5JUTU4Ua79uG3y7l+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_6dd0443f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dd0443fc8902fcd9daa12d3de222a4c8d2976e1bf44f1d6608c956af810740f"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:07"
  condition:
    hash.sha256(0, filesize) == "6dd0443fc8902fcd9daa12d3de222a4c8d2976e1bf44f1d6608c956af810740f"
}
```

### Sample 7: `3dbba0713091675b`

| Field | Value |
|---|---|
| SHA-256 | `3dbba0713091675bf142e8ff9ef92a5eee1732eae2af19ce65585b7616a670ac` |
| Family label | `Mirai` |
| File name | `bot.mips64` |
| File type | `elf` |
| First seen | `2026-09-25 05:00:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52639fe89a6ebcc9a5b1d9bf14ec21d1` |
| SHA-1 | `398dde9cc059716fce901b0bc13a3a81b6ed348b` |
| SHA-256 | `3dbba0713091675bf142e8ff9ef92a5eee1732eae2af19ce65585b7616a670ac` |
| SHA3-384 | `0b13c99ea2185bfec8e02a73a73d1f6b99d5c00b4390faffa3f5027b4bdba0ff765fdb7702a560c7f2bfde399d998dd0` |
| TLSH | `T1B3357C633F11CF69E314D67048F3C6527AD524A31AE24095B26CC3283A61B6E6D9FFE4` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:YesFxBjjCsbj4T+VrCMofsWit4spTJrQhKxTCnOKW8j:YesFxwY4T+VrCu4SrgKxTCnzj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_3dbba071
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dbba0713091675bf142e8ff9ef92a5eee1732eae2af19ce65585b7616a670ac"
    family = "Mirai"
    file_name = "bot.mips64"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:05"
  condition:
    hash.sha256(0, filesize) == "3dbba0713091675bf142e8ff9ef92a5eee1732eae2af19ce65585b7616a670ac"
}
```

### Sample 8: `1fef7558f389cb04`

| Field | Value |
|---|---|
| SHA-256 | `1fef7558f389cb04087b9804dc9e47a338bda903ca546e7d7680cbfa2d5e8251` |
| Family label | `Mirai` |
| File name | `stub.aarch64` |
| File type | `elf` |
| First seen | `2026-09-25 05:00:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f0d8044ba47e86730377a8ce736bfc5` |
| SHA-1 | `6de460f172d1096c44107549a9555c3b81550606` |
| SHA-256 | `1fef7558f389cb04087b9804dc9e47a338bda903ca546e7d7680cbfa2d5e8251` |
| SHA3-384 | `95a972b2a344266093bf01a6ef9f1782fd28810a8187c611ed65bcde6da8c088ca10b7bdfe8fd52c297ff44d6b6c6fa4` |
| TLSH | `T15AF46C5DFD5F3D43C2C6E23ADB8AC3957227B0D8D61311A321C1021DE6CADAD8B5299E` |
| SSDEEP | `12288:qaOMNE5N3B76xF+y0ZdNd7JOSwa5YAmdlStnWtVfkHzF:qaReBKRU9r1aOnQfkHp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_1fef7558
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fef7558f389cb04087b9804dc9e47a338bda903ca546e7d7680cbfa2d5e8251"
    family = "Mirai"
    file_name = "stub.aarch64"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:02"
  condition:
    hash.sha256(0, filesize) == "1fef7558f389cb04087b9804dc9e47a338bda903ca546e7d7680cbfa2d5e8251"
}
```

### Sample 9: `66da8ab5528e3461`

| Field | Value |
|---|---|
| SHA-256 | `66da8ab5528e3461a0c44c8925c33c0b1f56eb153b645d78964f8dec8b520242` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-25 04:52:01` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1941ccdd96bb2320f557150c43719ee` |
| SHA-1 | `b9cdf395b38b44fe709f2f7a38c07cac580d8fcd` |
| SHA-256 | `66da8ab5528e3461a0c44c8925c33c0b1f56eb153b645d78964f8dec8b520242` |
| SHA3-384 | `d62d82acd3583da09a570a35c33c189b2d2e66b87d7f21778a80087797282350a41fe1c9001483ed287458df0f402587` |
| IMPHASH | `0d3bfa54e5f35077d6279067f73285ef` |
| TLSH | `T1BEE4F1BDB8E324F6FE25553BCD1547D2C2A2F095A3205BEBE178447A7C82BC84D64B12` |
| SSDEEP | `12288:aWGV6dbY77JQHJGB8QYNIplMiYtz5kztYTjH5UYJh:ajB6HJGCQUQlBzgZU0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_66da8ab5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66da8ab5528e3461a0c44c8925c33c0b1f56eb153b645d78964f8dec8b520242"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 04:52:01"
  condition:
    hash.sha256(0, filesize) == "66da8ab5528e3461a0c44c8925c33c0b1f56eb153b645d78964f8dec8b520242"
}
```

### Sample 10: `94bc2ca34571d711`

| Field | Value |
|---|---|
| SHA-256 | `94bc2ca34571d711e5ae1ae30b07a59207d653e16e89abf6558c60d6e43453d8` |
| Family label | `Mirai` |
| File name | `stub.mips64` |
| File type | `elf` |
| First seen | `2026-09-25 04:51:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7fd44b9881977742bf96ae57308f9dd` |
| SHA-1 | `1e805a60bb8269cbd54b4fd6386d77906de0c0dc` |
| SHA-256 | `94bc2ca34571d711e5ae1ae30b07a59207d653e16e89abf6558c60d6e43453d8` |
| SHA3-384 | `640b2492ffe80567dcadddf1c39de636157534b71609bd4ec27f7e002aa41afd5a78e46fc61b5039b8b352ab4cf9a98a` |
| TLSH | `T102F48D273B21DF65D355D67049F3C7914AE920A20AE340D6B2A8C3287E6172D2D9FFE4` |
| SSDEEP | `12288:4EO7hT7XQRW4tWl9B11U+bs/w7iGtgpiGGhQi3BF1PNMBHUJTxVO:o7Vh4t+9B1do/w7iG+SQiZa0JTxM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_94bc2ca3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94bc2ca34571d711e5ae1ae30b07a59207d653e16e89abf6558c60d6e43453d8"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:23"
  condition:
    hash.sha256(0, filesize) == "94bc2ca34571d711e5ae1ae30b07a59207d653e16e89abf6558c60d6e43453d8"
}
```

### Sample 11: `da4cf25c21b3ae8b`

| Field | Value |
|---|---|
| SHA-256 | `da4cf25c21b3ae8bdce987e0ac09451bd5e9c93bd3c11801a1f4d888f699898c` |
| Family label | `Mirai` |
| File name | `stub.i386` |
| File type | `elf` |
| First seen | `2026-09-25 04:51:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49d29262da021af196e51e597c3234e9` |
| SHA-1 | `c03b265e5703e2b5bf3f440e2b6b8af456e38835` |
| SHA-256 | `da4cf25c21b3ae8bdce987e0ac09451bd5e9c93bd3c11801a1f4d888f699898c` |
| SHA3-384 | `00eb8f7a3444057c4dfb73225be52a8fcda12fcad1db5bcdc22202cb17857966141660f0292f2a78d3ac48c53b3884c9` |
| TLSH | `T177157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/1:7NP46S4QVs7l6A5Zji59k0jZz06FYRsa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_da4cf25c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da4cf25c21b3ae8bdce987e0ac09451bd5e9c93bd3c11801a1f4d888f699898c"
    family = "Mirai"
    file_name = "stub.i386"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:21"
  condition:
    hash.sha256(0, filesize) == "da4cf25c21b3ae8bdce987e0ac09451bd5e9c93bd3c11801a1f4d888f699898c"
}
```

### Sample 12: `f6052038a49e3f6a`

| Field | Value |
|---|---|
| SHA-256 | `f6052038a49e3f6a34c5008d83d7863c6080dc26ab8a9a2f6ccf569df6a008fc` |
| Family label | `Mirai` |
| File name | `bot.armv5tel` |
| File type | `elf` |
| First seen | `2026-09-25 04:51:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfff159df168dd2c07db34146a3c4dfc` |
| SHA-1 | `585317c481cb14334b7dbc5727347be0912e7aa4` |
| SHA-256 | `f6052038a49e3f6a34c5008d83d7863c6080dc26ab8a9a2f6ccf569df6a008fc` |
| SHA3-384 | `e0d727325f851cc4761968e444c902156d3ddeacb62e69307b35e99469e436f370426185b974307a8dedb346b9359ab8` |
| TLSH | `T1C1254B54F890DF63C5D46B7AF65E82A833234778C3E7720699148B383B97A5F0B3A641` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:zkgJ32jpc+SrNUCSfc+Fp4Wop9657yD/hGnmCf:r4f1L89657yDAmCf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_f6052038
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6052038a49e3f6a34c5008d83d7863c6080dc26ab8a9a2f6ccf569df6a008fc"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:19"
  condition:
    hash.sha256(0, filesize) == "f6052038a49e3f6a34c5008d83d7863c6080dc26ab8a9a2f6ccf569df6a008fc"
}
```

### Sample 13: `e2b9601d09ff795c`

| Field | Value |
|---|---|
| SHA-256 | `e2b9601d09ff795cf4d070cd3f308ddbe03a28330cf40559abe4faae28948b95` |
| Family label | `Mirai` |
| File name | `bot.mips64el` |
| File type | `elf` |
| First seen | `2026-09-25 04:51:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b0eaed2ecc4d4c4800d8f453829db11` |
| SHA-1 | `82442d58f860d0f81f26c96367ec0222a0ecd7a6` |
| SHA-256 | `e2b9601d09ff795cf4d070cd3f308ddbe03a28330cf40559abe4faae28948b95` |
| SHA3-384 | `ebc57387bb515449b1bac6b3feb50747881beb098596089bd361b478d2582bfefe485acadc6ca24a4e832937803b750f` |
| TLSH | `T199356C46EF406FEBC09FCD30492EC35721EDE8CA42C5A62971FC4A8C7A5D3594AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:7BVL2UCtekP9MiCWKu/LoZespTm4C+xTCnOKW80:qUCBVUnusklMxTCnz0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_e2b9601d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2b9601d09ff795cf4d070cd3f308ddbe03a28330cf40559abe4faae28948b95"
    family = "Mirai"
    file_name = "bot.mips64el"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:18"
  condition:
    hash.sha256(0, filesize) == "e2b9601d09ff795cf4d070cd3f308ddbe03a28330cf40559abe4faae28948b95"
}
```

### Sample 14: `f042aa22cee4379d`

| Field | Value |
|---|---|
| SHA-256 | `f042aa22cee4379db0bc57e190f3384e0fe95d5ec15406ada2ea39f0b2e53244` |
| Family label | `Mirai` |
| File name | `stub.mipsel` |
| File type | `elf` |
| First seen | `2026-09-25 04:51:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1941b895b7019a1acc6bb4a4ce512cf2` |
| SHA-1 | `67ebc5209c3779463be904d567bd6f2c9349a5b5` |
| SHA-256 | `f042aa22cee4379db0bc57e190f3384e0fe95d5ec15406ada2ea39f0b2e53244` |
| SHA3-384 | `aee55c602b0e00f0cb235aa45fdb0d8f03fc6eec30e3b365018254152c26dc617b37fce66ddd4f01e7c82dbc3dc7a520` |
| TLSH | `T144F45B07FF815FEBC09FCD30852EC31721E9D48656C1A62A72FC4A8CBA5D6694BE3494` |
| SSDEEP | `12288:cAsRZePvWEwcj1b4D7QAEjYHZ6fxd8mg2cSAH07FFMk/mKsuSxzOTl1aplHPPhGb:GZwv1jJ4/9UZnQ28N+0JTxq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_f042aa22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f042aa22cee4379db0bc57e190f3384e0fe95d5ec15406ada2ea39f0b2e53244"
    family = "Mirai"
    file_name = "stub.mipsel"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:16"
  condition:
    hash.sha256(0, filesize) == "f042aa22cee4379db0bc57e190f3384e0fe95d5ec15406ada2ea39f0b2e53244"
}
```

### Sample 15: `1a2d9550172a6c94`

| Field | Value |
|---|---|
| SHA-256 | `1a2d9550172a6c94e7296a27e1faa3e884a3dc4881207e66864e21fd85f51aa3` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-09-25 04:51:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffdbf69de76da82f9ba41463c4eceba2` |
| SHA-1 | `398f36cfc350d9cfcf36cf509417ff95a74be243` |
| SHA-256 | `1a2d9550172a6c94e7296a27e1faa3e884a3dc4881207e66864e21fd85f51aa3` |
| SHA3-384 | `12eb8a5ce003442b9daa1482d42c8a73d6e721c6ede291327f25b785b2db19214976ac41ea051cd6e1ab3772c00c9208` |
| TLSH | `T1C5D43A03272D0B83D7A35CF0777717F487DA988621F5F588EA0B69C69271970628E5CE` |
| SSDEEP | `6144:tTYmx6gCPf3CSlHx16zY1GBhSIlo//8aIneTHyw5OJk3HeWDOURSYsR4bGQmsXUp:tT5x6ghSJe/FICaOAvg4bXtuvN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_1a2d9550
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a2d9550172a6c94e7296a27e1faa3e884a3dc4881207e66864e21fd85f51aa3"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:14"
  condition:
    hash.sha256(0, filesize) == "1a2d9550172a6c94e7296a27e1faa3e884a3dc4881207e66864e21fd85f51aa3"
}
```

### Sample 16: `7ca90a1040b5ce49`

| Field | Value |
|---|---|
| SHA-256 | `7ca90a1040b5ce49ff84075f63196acd92e6ce1929921c482d30e4385d89a602` |
| Family label | `Mirai` |
| File name | `stub.i486` |
| File type | `elf` |
| First seen | `2026-09-25 04:51:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ada508e52c0eb332ae120d89bdc8f152` |
| SHA-1 | `5c0ca5b941d988a543a9bb4bb2df08fddb8459d3` |
| SHA-256 | `7ca90a1040b5ce49ff84075f63196acd92e6ce1929921c482d30e4385d89a602` |
| SHA3-384 | `2aea24858f3171aab742a96be48de62ce1ba88d3278f6b3550178281f187079eed2be222ebd83b7adcd7f5c39173c4be` |
| TLSH | `T15D157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/k:7NP46S4QVs7l6A5Zji59k0jZz06FYRsD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_7ca90a10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ca90a1040b5ce49ff84075f63196acd92e6ce1929921c482d30e4385d89a602"
    family = "Mirai"
    file_name = "stub.i486"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:13"
  condition:
    hash.sha256(0, filesize) == "7ca90a1040b5ce49ff84075f63196acd92e6ce1929921c482d30e4385d89a602"
}
```

### Sample 17: `b43c73b5fa1fa005`

| Field | Value |
|---|---|
| SHA-256 | `b43c73b5fa1fa005798316d25fa6adfc532d8a1c2e4b307ef9a8032003c5de6c` |
| Family label | `Mirai` |
| File name | `bot.i386` |
| File type | `elf` |
| First seen | `2026-09-25 04:42:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34d1ed59901fecfaca20e80d712aaf18` |
| SHA-1 | `5743580151467867a98c538be76f655e0b110495` |
| SHA-256 | `b43c73b5fa1fa005798316d25fa6adfc532d8a1c2e4b307ef9a8032003c5de6c` |
| SHA3-384 | `c8fff3c326b6b522e205d3bbb3fb29036dc4474af00d74cfc8ee70a201b1ae689fad8e000123bc86a67e9d720c4f3c4e` |
| TLSH | `T121355C5BB2A374BCC157C830879BDA62BD35B46502226E7BB5C4DB302E26D702719F72` |
| TELFHASH | `t149e157754af934b4a6e6da14b352f0729b721427b7fd39f526226d84ef40fc04c6282b` |
| SSDEEP | `24576:t8cWtZteM46ToG9hse3v0AF+V8ceeURWjZR8EMNNs/9Lje:GjB46Tz3vn+EeoWjZrAN49a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_b43c73b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b43c73b5fa1fa005798316d25fa6adfc532d8a1c2e4b307ef9a8032003c5de6c"
    family = "Mirai"
    file_name = "bot.i386"
    file_type = "elf"
    first_seen = "2026-09-25 04:42:18"
  condition:
    hash.sha256(0, filesize) == "b43c73b5fa1fa005798316d25fa6adfc532d8a1c2e4b307ef9a8032003c5de6c"
}
```

### Sample 18: `ddb73c805e2f9655`

| Field | Value |
|---|---|
| SHA-256 | `ddb73c805e2f965512affd129db044f127f90d3b164e14b6e68332a28ca10c5d` |
| Family label | `Mirai` |
| File name | `stub.armv7l` |
| File type | `elf` |
| First seen | `2026-09-25 04:42:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d331f0da486dfdbbdafc6658a64b3a10` |
| SHA-1 | `f2ebc8c03cb403ccbb2f703f971b5ef67657c333` |
| SHA-256 | `ddb73c805e2f965512affd129db044f127f90d3b164e14b6e68332a28ca10c5d` |
| SHA3-384 | `4164fc0ba7c24450005bcc40b7f7bccc245e06da0db74197acf17f280c864e8aaf8d4b67605d91bf0d781d0eaae4873d` |
| TLSH | `T1AED44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKih:YCp7mXtni6aBh321eSiVWKw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_ddb73c80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddb73c805e2f965512affd129db044f127f90d3b164e14b6e68332a28ca10c5d"
    family = "Mirai"
    file_name = "stub.armv7l"
    file_type = "elf"
    first_seen = "2026-09-25 04:42:16"
  condition:
    hash.sha256(0, filesize) == "ddb73c805e2f965512affd129db044f127f90d3b164e14b6e68332a28ca10c5d"
}
```

### Sample 19: `88367ddc6e0629c0`

| Field | Value |
|---|---|
| SHA-256 | `88367ddc6e0629c037643b2bd6002345ea95cd763072ebc308d21bf8de7eab7e` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-09-25 04:42:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2cd2e15f9c3392b4c24994c6d25e5f57` |
| SHA-1 | `a04d4b9b02c7916bce64d789abbfc81be4861164` |
| SHA-256 | `88367ddc6e0629c037643b2bd6002345ea95cd763072ebc308d21bf8de7eab7e` |
| SHA3-384 | `0dc751b7f3da515ed8c88954b52bd9d7e71d66edb1246542d1041a661d0d3e4aeed89a234bb574729a8974e4c014a7ae` |
| TLSH | `T1D9052B076F505DF7C87BCD3705B5CB2624CDB88332E53B2A7678DA48BD1960746A38A8` |
| SSDEEP | `6144:HMiSZF2chMRF0yoSLsFpGJ2ccR/8BmSXB2LNWATbEzKaXEsy07bz/qYsf3hEJ4hH:EwR6yoSIKXB2LNWbz7Uochff7qx/x7y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_88367ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88367ddc6e0629c037643b2bd6002345ea95cd763072ebc308d21bf8de7eab7e"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-25 04:42:14"
  condition:
    hash.sha256(0, filesize) == "88367ddc6e0629c037643b2bd6002345ea95cd763072ebc308d21bf8de7eab7e"
}
```

### Sample 20: `3a7bf6f11d972b03`

| Field | Value |
|---|---|
| SHA-256 | `3a7bf6f11d972b034f44222b21fad10de8ac30d197ee406f027e4fe38951f245` |
| Family label | `Mirai` |
| File name | `bot.mpsl` |
| File type | `elf` |
| First seen | `2026-09-25 04:42:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8d09d62b7de582b86b6a671a7a7d3d8` |
| SHA-1 | `75790370d4b000f840ff90c0ee85dcd9698d9d6f` |
| SHA-256 | `3a7bf6f11d972b034f44222b21fad10de8ac30d197ee406f027e4fe38951f245` |
| SHA3-384 | `76ccb975a3d28ec1137bc29974ca664368ade5f2bd537368d8cd8870026ed6fb015ad5474a96726571be4a3089104b4a` |
| TLSH | `T1F1356C46EF406FEBC09FCD30492EC35721EDE8CA42C5A62971FC4A8C7A5D3594AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:7BVL2UCtekP9MiCWKu/LoZespTm4C+xTCnOKW8e9:qUCBVUnusklMxTCnze9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_3a7bf6f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a7bf6f11d972b034f44222b21fad10de8ac30d197ee406f027e4fe38951f245"
    family = "Mirai"
    file_name = "bot.mpsl"
    file_type = "elf"
    first_seen = "2026-09-25 04:42:12"
  condition:
    hash.sha256(0, filesize) == "3a7bf6f11d972b034f44222b21fad10de8ac30d197ee406f027e4fe38951f245"
}
```

### Sample 21: `e0799c11ec678995`

| Field | Value |
|---|---|
| SHA-256 | `e0799c11ec678995785494127ed3aedfd5624bc202600a0897d740f368356e50` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Heur.29680.227` |
| File type | `elf` |
| First seen | `2026-09-25 04:36:26` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97ac03035f980d550f46cbacbcdf8885` |
| SHA-1 | `ccced406697a8609f322457e6659e6fca6e8cb1e` |
| SHA-256 | `e0799c11ec678995785494127ed3aedfd5624bc202600a0897d740f368356e50` |
| SHA3-384 | `3ed0e3919a18a54cf58e593bb3ff81bd1bc7dce7f4fb7957d415ebc570861426fa9d52f3ec436f9af788a811f37fd3b9` |
| TLSH | `T1EBD44A03272D0B83E7A34CF0777707F4839A985621F9F589EA0AADC69771870625E5CE` |
| SSDEEP | `6144:CYnrGkjFL4zlSZ/LotI5Wwlo/guWmKa5R1o8M/tTXGU5OHV0wki8vRaMWQ1Lifa:JnrB4zsTmpE8+E+i8vRaZQ1ufa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_e0799c11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0799c11ec678995785494127ed3aedfd5624bc202600a0897d740f368356e50"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.29680.227"
    file_type = "elf"
    first_seen = "2026-09-25 04:36:26"
  condition:
    hash.sha256(0, filesize) == "e0799c11ec678995785494127ed3aedfd5624bc202600a0897d740f368356e50"
}
```

### Sample 22: `245376523422a056`

| Field | Value |
|---|---|
| SHA-256 | `245376523422a056afd0b406024a91e1f56bf74e99286db383715cb692201cac` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Heur.15762.20913` |
| File type | `elf` |
| First seen | `2026-09-25 04:36:23` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66bc605132ddaa51187c5ea1c34a4762` |
| SHA-1 | `a7e3276dc92bc9d8e0f63a512d607008bbd8a6af` |
| SHA-256 | `245376523422a056afd0b406024a91e1f56bf74e99286db383715cb692201cac` |
| SHA3-384 | `42b699da551632d06c35b2f3a9640d06afbc6fb45241901f576e1280c565a573d62ada5b1e41e85b60a2094164b7fc37` |
| TLSH | `T157B48F03A7F7E4B1D49142B1215567B94572C9B215BBD98FEFE52C84DE602C0E32C3AB` |
| TELFHASH | `t1cfe169b33abe0ded77d0a541d34f6b12ee1a92b319d431b609f3215832b2b825e71875` |
| SSDEEP | `12288:Gx13oK6k/6nj6G98H86LUi29T8c8uwYx4:Gj6k/6nj6Gyc6e9Ytuw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_24537652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "245376523422a056afd0b406024a91e1f56bf74e99286db383715cb692201cac"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.15762.20913"
    file_type = "elf"
    first_seen = "2026-09-25 04:36:23"
  condition:
    hash.sha256(0, filesize) == "245376523422a056afd0b406024a91e1f56bf74e99286db383715cb692201cac"
}
```

### Sample 23: `7372dcdb3ca9623b`

| Field | Value |
|---|---|
| SHA-256 | `7372dcdb3ca9623b3d77d5ee8bbab01a3406dca9beaab76e8166dc17e57ac8f6` |
| Family label | `Mirai` |
| File name | `dbg` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fddb4388cb9407108e2d120aabf4fa72` |
| SHA-1 | `2ff7a1f3e34ca7f15ee261e8e3e8d383011e60d9` |
| SHA-256 | `7372dcdb3ca9623b3d77d5ee8bbab01a3406dca9beaab76e8166dc17e57ac8f6` |
| SHA3-384 | `d0bd8260e396c740e2054a5442ebcdcb669bbde43867bd1ba45cbb523172ec85f91b9084514ea5c96d425ba4f8164aaa` |
| TLSH | `T18E357C5AF2F374FCC067C030439BDB62A835F47911226E7B25C4DA352D66EA01B29F66` |
| TELFHASH | `t1ffb1acb05efa70f0a2dbcd117322f0b95d72186666e936b11b23ad85ef40f800d66c1b` |
| SSDEEP | `12288:oueq0Xc87u5Q+YgDINWo7jt32Z7jjMNKzHa6F1myAdtu6SUVu97w5k:oueq0XcOu5Qqno7jt32XjVHPsq6SP7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_7372dcdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7372dcdb3ca9623b3d77d5ee8bbab01a3406dca9beaab76e8166dc17e57ac8f6"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:18"
  condition:
    hash.sha256(0, filesize) == "7372dcdb3ca9623b3d77d5ee8bbab01a3406dca9beaab76e8166dc17e57ac8f6"
}
```

### Sample 24: `5ea82ca14a7caef3`

| Field | Value |
|---|---|
| SHA-256 | `5ea82ca14a7caef36f86b34c28b856d5b19312b2b5a0983c653babecfbfcb98c` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfea8e82fce16fe90c911856833cee92` |
| SHA-1 | `567a26c04d94e64aca3423b645d4c1eea1eb512e` |
| SHA-256 | `5ea82ca14a7caef36f86b34c28b856d5b19312b2b5a0983c653babecfbfcb98c` |
| SHA3-384 | `b689e9908d7f781de9c879ed4d87d32160accdae0a7e9a6a76e42886f9b93ccc68a9e028978d2c3e1680dc5cb9589ef5` |
| TLSH | `T17D355C5BB2A374BCC157C830879BDA62BD35B46502226E7BB5C4DB302E26D702719F72` |
| TELFHASH | `t149e157754af934b4a6e6da14b352f0729b721427b7fd39f526226d84ef40fc04c6282b` |
| SSDEEP | `24576:t8cWtZteM46ToG9hse3v0AF+V8ceeURWjZR8EMNNs/9Lj8:GjB46Tz3vn+EeoWjZrAN49Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_5ea82ca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ea82ca14a7caef36f86b34c28b856d5b19312b2b5a0983c653babecfbfcb98c"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:16"
  condition:
    hash.sha256(0, filesize) == "5ea82ca14a7caef36f86b34c28b856d5b19312b2b5a0983c653babecfbfcb98c"
}
```

### Sample 25: `1399adc6c631adca`

| Field | Value |
|---|---|
| SHA-256 | `1399adc6c631adcafd569914690f9a0b3b19c67c8134f0ece43527e6feb3daa0` |
| Family label | `Mirai` |
| File name | `bot.i486` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `433a6b7745c96756649c74c60b5dc31e` |
| SHA-1 | `fc420d367fc51bfd4111a0b668eab84070a7e3ec` |
| SHA-256 | `1399adc6c631adcafd569914690f9a0b3b19c67c8134f0ece43527e6feb3daa0` |
| SHA3-384 | `f26c56b4609c5aa8dbf747e654cc52014e1eda3ca5fbb3c40cbf4dde052bbed5350bfef6323ce153274b6cef790e300b` |
| TLSH | `T1A2355C5BB2A374BCC157C830879BDA62BD35B46502226E7BB5C4DB302E26D702719F72` |
| TELFHASH | `t149e157754af934b4a6e6da14b352f0729b721427b7fd39f526226d84ef40fc04c6282b` |
| SSDEEP | `24576:t8cWtZteM46ToG9hse3v0AF+V8ceeURWjZR8EMNNs/9LjP:GjB46Tz3vn+EeoWjZrAN49z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_1399adc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1399adc6c631adcafd569914690f9a0b3b19c67c8134f0ece43527e6feb3daa0"
    family = "Mirai"
    file_name = "bot.i486"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:15"
  condition:
    hash.sha256(0, filesize) == "1399adc6c631adcafd569914690f9a0b3b19c67c8134f0ece43527e6feb3daa0"
}
```

### Sample 26: `3e326c40e2eb5f43`

| Field | Value |
|---|---|
| SHA-256 | `3e326c40e2eb5f43e9d369afc9d486ae1038a909e56b9cd0cf7d13a811894803` |
| Family label | `Mirai` |
| File name | `stub.x86_64` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c64862c6219202a347eb7354a206fbeb` |
| SHA-1 | `73b0696db1b27067d909680ad2027d55d5c31ae8` |
| SHA-256 | `3e326c40e2eb5f43e9d369afc9d486ae1038a909e56b9cd0cf7d13a811894803` |
| SHA3-384 | `4e4ce46e9e749449a438f794efb93f6ea4055eb0fa2af9444426b8118f1859493ef01737324c9b23f41d43a6ca04fad1` |
| TLSH | `T1AD157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/X:7NP46S4QVs7l6A5Zji59k0jZz06FYRsm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_3e326c40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e326c40e2eb5f43e9d369afc9d486ae1038a909e56b9cd0cf7d13a811894803"
    family = "Mirai"
    file_name = "stub.x86_64"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:13"
  condition:
    hash.sha256(0, filesize) == "3e326c40e2eb5f43e9d369afc9d486ae1038a909e56b9cd0cf7d13a811894803"
}
```

### Sample 27: `11abfeb045732990`

| Field | Value |
|---|---|
| SHA-256 | `11abfeb045732990eba6c2c164943f6874095278369e4fb7dec82f44dc3c8f77` |
| Family label | `Mirai` |
| File name | `stub.armv5tel` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f77125e10a9b59fe88a9776c0e6dae1` |
| SHA-1 | `cea8cfb0ac66c5bf64fe58a25ee80ee8ed4bc001` |
| SHA-256 | `11abfeb045732990eba6c2c164943f6874095278369e4fb7dec82f44dc3c8f77` |
| SHA3-384 | `b9ffdcdcb1d7603df1f5e6303e7b4934035329e2976e52b9cc667a1077cd763207387bb49256854ee91a6140c5a88c59` |
| TLSH | `T19FD44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKit:YCp7mXtni6aBh321eSiVWK2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_11abfeb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11abfeb045732990eba6c2c164943f6874095278369e4fb7dec82f44dc3c8f77"
    family = "Mirai"
    file_name = "stub.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:11"
  condition:
    hash.sha256(0, filesize) == "11abfeb045732990eba6c2c164943f6874095278369e4fb7dec82f44dc3c8f77"
}
```

### Sample 28: `47d0b1785f854dd4`

| Field | Value |
|---|---|
| SHA-256 | `47d0b1785f854dd45302fd203bbafb5c7a98892a906078fe0c2d944177eec4e6` |
| Family label | `unknown` |
| File name | `rev.sh` |
| File type | `sh` |
| First seen | `2026-09-25 04:33:09` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b3440ed5f3c7bf7fa4c037cec7a7938` |
| SHA-1 | `e97df414546c3cacfdd9424ba869db3e0fee1d82` |
| SHA-256 | `47d0b1785f854dd45302fd203bbafb5c7a98892a906078fe0c2d944177eec4e6` |
| SHA3-384 | `ba95813abdfc119d43d9471452806b51c9244e5a56d1c9d9c18fb383add89e4b2cb084ed9ab8a8acd89d78c90f1c1809` |
| TLSH | `T12321DCB1E2F1AD753F7480682206E23036DA3B579F8E8CE28C7D5AB23613954F094F21` |
| SSDEEP | `24:w1NLle/2gu4r+SrNvNSL5lOK70TGz5lOK70TGP:wThe6SuOK70TGGK70TGP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_47d0b178
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47d0b1785f854dd45302fd203bbafb5c7a98892a906078fe0c2d944177eec4e6"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-09-25 04:33:09"
  condition:
    hash.sha256(0, filesize) == "47d0b1785f854dd45302fd203bbafb5c7a98892a906078fe0c2d944177eec4e6"
}
```

### Sample 29: `6e0ff2e91da2d190`

| Field | Value |
|---|---|
| SHA-256 | `6e0ff2e91da2d190f0126a1da03a4a165e4641cdff432c2cdcf18382a2fee153` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57f1e8314564795c232a4854e54c4ca2` |
| SHA-1 | `3ee1f05ace4e7bc6af6f1029a784e525b40c5cce` |
| SHA-256 | `6e0ff2e91da2d190f0126a1da03a4a165e4641cdff432c2cdcf18382a2fee153` |
| SHA3-384 | `0587ba0f2ad2f24659d8d83e60167901ab24279aaa5f1eb88c7d765e42ef38077513261269e2b98c8cbf54503698e9bf` |
| TLSH | `T1AED46D07ADE484BDC8D6C0744FDBC33A9962F08A2239B64FBBC6AE817E15E50671C751` |
| TELFHASH | `t1a4e12f300cb6782572e395217343c2adad731c1597e931ea3a53a4fdeeee6c14c76862` |
| SSDEEP | `6144:KfftEEmvRkHvANkvGX+k7gL/6DODS9hIkT8uT+LOZ1q2bHj5AqBnVphh/PRsiJbv:K8viNcgluv1qQj5t9PRdbm4n/Ok` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_6e0ff2e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e0ff2e91da2d190f0126a1da03a4a165e4641cdff432c2cdcf18382a2fee153"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:08"
  condition:
    hash.sha256(0, filesize) == "6e0ff2e91da2d190f0126a1da03a4a165e4641cdff432c2cdcf18382a2fee153"
}
```

### Sample 30: `64e6b0c589b58649`

| Field | Value |
|---|---|
| SHA-256 | `64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001` |
| Family label | `unknown` |
| File name | `64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001.elf` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:07` |
| Reporter | `boredchilada2` |
| Tags | `boatnet, docker, elf, etherhiding, mirai, upx, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9040ff2bf68657d0932bc1e4c72ab987` |
| SHA-1 | `6de646d7fddebc9793e25c0cc35b275b8f98ade3` |
| SHA-256 | `64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001` |
| SHA3-384 | `dde189cfaefd96ad7f3f287d7ccea1905f318cca4eeb8576d0a7ba60293406743673f063524acc8ae68c8cbb8c5dbc68` |
| TLSH | `T1346423CB87F577B4D4382E7A69C2D796DD1A85D421F80977BEC8E1BC30C0A452E853A1` |
| SSDEEP | `6144:XK4a6gVMohfsFtAe0NP6nIajZOQUa1neS1C:GWxAe0dWlZKa1DC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_64e6b0c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001"
    family = "unknown"
    file_name = "64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001.elf"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:07"
  condition:
    hash.sha256(0, filesize) == "64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001"
}
```

### Sample 31: `049d378589c22ac3`

| Field | Value |
|---|---|
| SHA-256 | `049d378589c22ac33d5c62f3d74d6294e972db699a7eb0581857fe9c099f1b64` |
| Family label | `Mirai` |
| File name | `stub.x64` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24371a7240b37d274655b309b0ab4bc5` |
| SHA-1 | `87ef363960ccc1edb68ccb21183ade7b31fc20d7` |
| SHA-256 | `049d378589c22ac33d5c62f3d74d6294e972db699a7eb0581857fe9c099f1b64` |
| SHA3-384 | `ff97080f814c2469b78aa953b8bb900eb319abe75fd4726d8eabf75e0ffa123f9454f2152bdc1572b6c1dadfd95ad206` |
| TLSH | `T1A4157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/t:7NP46S4QVs7l6A5Zji59k0jZz06FYRsi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_049d3785
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049d378589c22ac33d5c62f3d74d6294e972db699a7eb0581857fe9c099f1b64"
    family = "Mirai"
    file_name = "stub.x64"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:06"
  condition:
    hash.sha256(0, filesize) == "049d378589c22ac33d5c62f3d74d6294e972db699a7eb0581857fe9c099f1b64"
}
```

### Sample 32: `f383a4b24a8af5f3`

| Field | Value |
|---|---|
| SHA-256 | `f383a4b24a8af5f3611abe94ffb9091812f8f82faf90d5b3829eba31d0e295c4` |
| Family label | `Mirai` |
| File name | `stub.armv6l` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8800d081d10363bdb49aa740028c86c2` |
| SHA-1 | `98a95e3dc1a043f989c4332d8c5c3e31f9c76511` |
| SHA-256 | `f383a4b24a8af5f3611abe94ffb9091812f8f82faf90d5b3829eba31d0e295c4` |
| SHA3-384 | `392bd6dc2cce7a05f39220240885d2a0e2b11fbf0361ffcbb10a7bdb6b868c823654e38ebe9167c22194bcd1ee84456b` |
| TLSH | `T190D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKia:YCp7mXtni6aBh321eSiVWKF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_f383a4b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f383a4b24a8af5f3611abe94ffb9091812f8f82faf90d5b3829eba31d0e295c4"
    family = "Mirai"
    file_name = "stub.armv6l"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:04"
  condition:
    hash.sha256(0, filesize) == "f383a4b24a8af5f3611abe94ffb9091812f8f82faf90d5b3829eba31d0e295c4"
}
```

### Sample 33: `5d5b1e26d0914ed0`

| Field | Value |
|---|---|
| SHA-256 | `5d5b1e26d0914ed0e176bcbe86ba2851c237b70fcb9e14463208aa3c8a5a9725` |
| Family label | `Mirai` |
| File name | `bot.armv7l` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d9aa214afcd7c0f1c8e3cb07660395b` |
| SHA-1 | `f442108e8a905b7580c81ef9594e05c3c85d32c7` |
| SHA-256 | `5d5b1e26d0914ed0e176bcbe86ba2851c237b70fcb9e14463208aa3c8a5a9725` |
| SHA3-384 | `00ee595e626cdaec2ab26f6f62980b4e28f3bd8ed5f34bd4092b1f65094b8f286c8264858626c3ca89ca477b1715a9a0` |
| TLSH | `T1CF254B54F890DF63C5D46B7AF65E82A833234778C3E7720699148B383B97A5F0B3A641` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:zkgJ32jpc+SrNUCSfc+Fp4Wop9657yD/hGnm0:r4f1L89657yDAm0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_5d5b1e26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d5b1e26d0914ed0e176bcbe86ba2851c237b70fcb9e14463208aa3c8a5a9725"
    family = "Mirai"
    file_name = "bot.armv7l"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:02"
  condition:
    hash.sha256(0, filesize) == "5d5b1e26d0914ed0e176bcbe86ba2851c237b70fcb9e14463208aa3c8a5a9725"
}
```

### Sample 34: `869833e828f25079`

| Field | Value |
|---|---|
| SHA-256 | `869833e828f250799f7e78f210242f2a240f2aaf4648f61911c7c6dd738f3378` |
| Family label | `Mirai` |
| File name | `bot.arm7n` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94593abdfb57a193d96afd5170ebf7e0` |
| SHA-1 | `bd8629b70c45f3c2db3c8d571b85d3200594e994` |
| SHA-256 | `869833e828f250799f7e78f210242f2a240f2aaf4648f61911c7c6dd738f3378` |
| SHA3-384 | `446727fd8c062e82c7cde107ef898f4a4b1bea50ba990b4daafe379c64e6c6021b219aa71751d0ff19f8fd73716c9960` |
| TLSH | `T152254B54F890DF63C5D46B7AF65E82A833234778C3E7720699148B383B97A5F0B3A641` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:zkgJ32jpc+SrNUCSfc+Fp4Wop9657yD/hGnmh:r4f1L89657yDAmh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_869833e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "869833e828f250799f7e78f210242f2a240f2aaf4648f61911c7c6dd738f3378"
    family = "Mirai"
    file_name = "bot.arm7n"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:00"
  condition:
    hash.sha256(0, filesize) == "869833e828f250799f7e78f210242f2a240f2aaf4648f61911c7c6dd738f3378"
}
```

### Sample 35: `2a3b30f3e5a7a8d8`

| Field | Value |
|---|---|
| SHA-256 | `2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b` |
| Family label | `unknown` |
| File name | `2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b.elf` |
| File type | `elf` |
| First seen | `2026-09-25 04:33:00` |
| Reporter | `boredchilada2` |
| Tags | `boatnet, docker, elf, etherhiding, mirai, upx, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18e555ed99350883992bc17af6f8f327` |
| SHA-1 | `5d16740a21ccdf6ed318e2896b9e7ebea7352a49` |
| SHA-256 | `2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b` |
| SHA3-384 | `e1f89c190c439c60a26bef5d8694948bfcc0898fca26bf200c1dc0d45b7e56462c68ada7cdf7f175361287da4dc72b60` |
| TLSH | `T11264235014E3B985CDA4DA1F5A764A8A9406EC87F3A31D1F3BC476BFBF223891403B91` |
| SSDEEP | `6144:b1JhdpiNMAH39ey9ywL9x2zcyuiDCnJVK7t/vh7EavG754nr8BbwV8ULRw:+jX9eyrHMcyuiDgJVK7tFESY54nwMw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_2a3b30f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b"
    family = "unknown"
    file_name = "2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b.elf"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:00"
  condition:
    hash.sha256(0, filesize) == "2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b"
}
```

### Sample 36: `3dd9ac7194cfdd43`

| Field | Value |
|---|---|
| SHA-256 | `3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8` |
| Family label | `unknown` |
| File name | `3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8.elf` |
| File type | `elf` |
| First seen | `2026-09-25 04:32:53` |
| Reporter | `boredchilada2` |
| Tags | `boatnet, docker, elf, etherhiding, mirai, upx, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37b914e89928e1265454b391f13267aa` |
| SHA-1 | `fdc59dc78b2e08af0038acce13d7c43e80c6149d` |
| SHA-256 | `3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8` |
| SHA3-384 | `918b469a6e11612e2b63b289355e19e62a7ca11f0534aebf17237f58c0df3640b1803b5ecdb8e7b12942c7f2a844ba23` |
| TLSH | `T14F6422902CF399A7EC7978F9111443C47B66B88547079AD76009B9B0C6FDB93B205ECE` |
| SSDEEP | `6144:JdOkxsYCdFWNaNwGgdg/7zA9pjXSwkptY1bNGcz2toQc8pZ:qkxsYC3/aGf7c/u1CbkXOSpZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_3dd9ac71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8"
    family = "unknown"
    file_name = "3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8.elf"
    file_type = "elf"
    first_seen = "2026-09-25 04:32:53"
  condition:
    hash.sha256(0, filesize) == "3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8"
}
```

### Sample 37: `032cf5ab06d8bf4b`

| Field | Value |
|---|---|
| SHA-256 | `032cf5ab06d8bf4bd324765b3179c4ab28eea7c8c949e8cf60044937d3e1cc7f` |
| Family label | `Mirai` |
| File name | `stub.armv7` |
| File type | `elf` |
| First seen | `2026-09-25 04:23:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `435225cc18ba76e80ba7ab9f3d33ef55` |
| SHA-1 | `2d34ed31b6891dc4c08b95179edb8938858ce9d0` |
| SHA-256 | `032cf5ab06d8bf4bd324765b3179c4ab28eea7c8c949e8cf60044937d3e1cc7f` |
| SHA3-384 | `3267b9bc62eea2969958f6363899c358dfc5a9e2af00da093710f41af86ae2a9ae9e7cd905c5b38d24d2ce3528c49e7e` |
| TLSH | `T1B4D44A55F8809F63C9C52A36F64E866833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiY:YCp7mXtni6aBh321eSiVWKP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_032cf5ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "032cf5ab06d8bf4bd324765b3179c4ab28eea7c8c949e8cf60044937d3e1cc7f"
    family = "Mirai"
    file_name = "stub.armv7"
    file_type = "elf"
    first_seen = "2026-09-25 04:23:56"
  condition:
    hash.sha256(0, filesize) == "032cf5ab06d8bf4bd324765b3179c4ab28eea7c8c949e8cf60044937d3e1cc7f"
}
```

### Sample 38: `5521e5e983dab5cd`

| Field | Value |
|---|---|
| SHA-256 | `5521e5e983dab5cd88bade12170967f0b85ea80829eeeed02cd84f9db979ddb4` |
| Family label | `unknown` |
| File name | `payload.bin.malware` |
| File type | `exe` |
| First seen | `2026-09-25 04:21:33` |
| Reporter | `ghozt` |
| Tags | `exe, MaaS, RAT, TELEPUZ` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5037c3f4e0689de7577383d2ee80d0ab` |
| SHA-1 | `df2522ab1acd2a173aa72ac5940571fef21641cb` |
| SHA-256 | `5521e5e983dab5cd88bade12170967f0b85ea80829eeeed02cd84f9db979ddb4` |
| SHA3-384 | `13a1049c102ca8ad546de3a72bee9327f0fb93f418b42e14b903cca303df68a0fe4b8f19f11f279806bbb27eed9a3352` |
| IMPHASH | `4192b5b49f2dea640789dde909ef651b` |
| TLSH | `T1EC741902F7D96DE0CCAFC33A96572223E17C790487719BBA4FD459632A51620A63D3EC` |
| SSDEEP | `6144:DA60ahgTxJC4rwm4emTOnud2+aB4kXT06Tlsb6EVxEXT:DcaY09sud2+aQ6TKbB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_5521e5e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5521e5e983dab5cd88bade12170967f0b85ea80829eeeed02cd84f9db979ddb4"
    family = "unknown"
    file_name = "payload.bin.malware"
    file_type = "exe"
    first_seen = "2026-09-25 04:21:33"
  condition:
    hash.sha256(0, filesize) == "5521e5e983dab5cd88bade12170967f0b85ea80829eeeed02cd84f9db979ddb4"
}
```

### Sample 39: `6d597ae1b707b6d0`

| Field | Value |
|---|---|
| SHA-256 | `6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507` |
| Family label | `Mirai` |
| File name | `6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507` |
| File type | `elf` |
| First seen | `2026-09-25 04:18:50` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8325d6770dbb76b9f8743b9484a47a3b` |
| SHA-1 | `d7d67d4133871419b79802f26bcf0d2ee720bf07` |
| SHA-256 | `6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507` |
| SHA3-384 | `cc3233c56b0de70a16c786fbf32a906ef120934a3303c98e574851372d07452fbc3b64af1ca4170d0a066ea0b72a1c89` |
| TLSH | `T1F344398AFD81AF25D5C5227BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_6d597ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507"
    family = "Mirai"
    file_name = "6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507"
    file_type = "elf"
    first_seen = "2026-09-25 04:18:50"
  condition:
    hash.sha256(0, filesize) == "6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507"
}
```

### Sample 40: `2d2fdfc7b1dd18df`

| Field | Value |
|---|---|
| SHA-256 | `2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21` |
| Family label | `unknown` |
| File name | `2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21.bin` |
| File type | `zip` |
| First seen | `2026-09-25 04:15:02` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85e951b2a1083c09cbfccba502475b5e` |
| SHA-1 | `c6618e97d0abffafdb7b25016c7a606ce98803de` |
| SHA-256 | `2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21` |
| SHA3-384 | `6b54d8c0aec5f4a3f853799ba320cfbf34f6277ac1992a44def64f6b60525e912163881325f1073e1f310cc33cdaa38a` |
| TLSH | `T102273355CC0574CB875B14FF4767622A4A683CB0A10BB852C2BE4D2727AB7BBE1B714C` |
| SSDEEP | `393216:DMJcekzNN0E5zv9lJEzqptKaozPo8Qo/Eal25mjNVPcvO1bG6lPqa+nANkLq:DMWp7hgeMaozPo5mEal2Y0v+6eF+K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_2d2fdfc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21"
    family = "unknown"
    file_name = "2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21.bin"
    file_type = "zip"
    first_seen = "2026-09-25 04:15:02"
  condition:
    hash.sha256(0, filesize) == "2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21"
}
```

### Sample 41: `b6307cb3e0da1b53`

| Field | Value |
|---|---|
| SHA-256 | `b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8` |
| Family label | `VShell` |
| File name | `b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8.exe` |
| File type | `exe` |
| First seen | `2026-09-25 04:09:51` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fd95cbbe8d961f26e89e870986f16ef` |
| SHA-1 | `549f20805c66c717cc497fcf8c34a4c6a202a893` |
| SHA-256 | `b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8` |
| SHA3-384 | `0909989e223246ec60c4c9edc5fdced1830472711bff54bea8cb8119a980900ff402ed520d1e8dc529468b20a14a5262` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T12571B541A0541AF2D94CE37F8487B895FD4FB248A2C80B0B0398981A2F7607BB4D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DS8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DSG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_041_b6307cb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8"
    family = "VShell"
    file_name = "b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8.exe"
    file_type = "exe"
    first_seen = "2026-09-25 04:09:51"
  condition:
    hash.sha256(0, filesize) == "b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8"
}
```

### Sample 42: `4131c88b0dea6ba4`

| Field | Value |
|---|---|
| SHA-256 | `4131c88b0dea6ba45cd633eed383240d41620e4467afa4e956d6c2dfafd58c1c` |
| Family label | `unknown` |
| File name | `WindowsCodecs.dll` |
| File type | `exe` |
| First seen | `2026-09-25 04:06:37` |
| Reporter | `ghozt` |
| Tags | `dll-sideloading, exe, loader, TELEPUZ, WindowsCodecs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4376f6e050ebd456f6640dc0ea408add` |
| SHA-1 | `b9b0970281db5f279ad59b2ee7e379312ceec64e` |
| SHA-256 | `4131c88b0dea6ba45cd633eed383240d41620e4467afa4e956d6c2dfafd58c1c` |
| SHA3-384 | `1a2583cf87511b19020580cb360c53d479adb3048b88ef5b5a6727c7e682d372b30849128826b0079d1fc74e881d5e61` |
| IMPHASH | `3da1e1538edcd467227c7f51667e1b54` |
| TLSH | `T184D21A6AFF0A8495C42DE23DD179DBD2F7B830E09331EE6D3741A8185E12643A617A2D` |
| SSDEEP | `384:SxpgmFsfZI1nDJXd3zgnvxmU5XX0Fy8CGDxAVwuUZLUU6fnwPQcgBfiDIuOxv0:SxpgmyZIDNdjgkUuPCGi23js9x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_4131c88b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4131c88b0dea6ba45cd633eed383240d41620e4467afa4e956d6c2dfafd58c1c"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-09-25 04:06:37"
  condition:
    hash.sha256(0, filesize) == "4131c88b0dea6ba45cd633eed383240d41620e4467afa4e956d6c2dfafd58c1c"
}
```

### Sample 43: `6cf2e852833668a2`

| Field | Value |
|---|---|
| SHA-256 | `6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a` |
| Family label | `VShell` |
| File name | `6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a.exe` |
| File type | `exe` |
| First seen | `2026-09-25 04:04:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9050d796586627030f8471b1400e6bd6` |
| SHA-1 | `49f303a741a1caeeee04b0fed794039a0f55e072` |
| SHA-256 | `6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a` |
| SHA3-384 | `a83ecea9ae7917ec381a685787e35852bbbf8e9eaf1cf9e74a1cc3e2656aa8efb05e4ac47a1ea6d0bd3ea7430c3fb27e` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1DA91C64170B999E7E85D85BB4C0FB8A0B919740A41C483A64378A5953E3967BF4BCB0E` |
| SSDEEP | `48:6IIF9BlQaexTRgZv7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMT000cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_043_6cf2e852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a"
    family = "VShell"
    file_name = "6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a.exe"
    file_type = "exe"
    first_seen = "2026-09-25 04:04:45"
  condition:
    hash.sha256(0, filesize) == "6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a"
}
```

### Sample 44: `16db4b5aefca60a0`

| Field | Value |
|---|---|
| SHA-256 | `16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698` |
| Family label | `VShell` |
| File name | `16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698.exe` |
| File type | `exe` |
| First seen | `2026-09-25 03:59:30` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12cf734117f67fcf1e0a852b84047cfd` |
| SHA-1 | `a22c7ec9d8cbd7ee4edffd58c5bf69abe8afd020` |
| SHA-256 | `16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698` |
| SHA3-384 | `2e8f7bad31e0fe49f2c9491db9a2ecc46f440f84b0fe69cb4b46fc0cedff1bc2d17d126ec32417a8f6fa12ca7ad780ae` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1FB715E88F3275AF1E43C47F80093A624D059ABB8C250AE8D5E60281D3C620BA255AF97` |
| SSDEEP | `48:6Icwm0hWt2WWJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jQWtUSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_044_16db4b5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698"
    family = "VShell"
    file_name = "16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:59:30"
  condition:
    hash.sha256(0, filesize) == "16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698"
}
```

### Sample 45: `b78a29eab41dc72b`

| Field | Value |
|---|---|
| SHA-256 | `b78a29eab41dc72b66375a7d9a8fad8d5942bfe3be9bed26a8bc9a0287c446e0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-25 03:59:19` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `012d9d5771dd02c4b81ff4d904e42483` |
| SHA-1 | `2019934322a24c9aab8b30d0b630049985e4dfa1` |
| SHA-256 | `b78a29eab41dc72b66375a7d9a8fad8d5942bfe3be9bed26a8bc9a0287c446e0` |
| SHA3-384 | `395d8707dc5a6a91e3fccc24585c920163ffa9e808c181f242a76f1d344df86942a1c51049769f2985b92b07a0e51c73` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T192564A07FD6A14E9C0AED53589729552BB617C891B3123D32B90F2387F76BD4ADBA300` |
| SSDEEP | `49152:t947P9fE8ODfHbrDpRumDHLofOIv3i3NNaKo51ZgswRN/+KGjMKQK1K6trckvK5o:t9A1MsSmp1xVtUEB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_b78a29ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b78a29eab41dc72b66375a7d9a8fad8d5942bfe3be9bed26a8bc9a0287c446e0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 03:59:19"
  condition:
    hash.sha256(0, filesize) == "b78a29eab41dc72b66375a7d9a8fad8d5942bfe3be9bed26a8bc9a0287c446e0"
}
```

### Sample 46: `32aaa1d07dc07217`

| Field | Value |
|---|---|
| SHA-256 | `32aaa1d07dc07217223009ad404925c5b518907e3b6c8aad1c2250e9f9dc54aa` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-25 03:58:42` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, upx, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fed8e2acb3f9a1876f11f759f155a200` |
| SHA-1 | `344d41f14532c587ccffc1cdcb8b938bac76c5fc` |
| SHA-256 | `32aaa1d07dc07217223009ad404925c5b518907e3b6c8aad1c2250e9f9dc54aa` |
| SHA3-384 | `2b3b0cb95466fafbaef0f5c1de24ccb184d2e1ed4a4d5d7881e9605b47a38b708b414043c644e79440231321aae9cc21` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T184C512598821F086C5B1092BB848AD20C382D6B96105BF34514B57F63FFD7EA6FF960E` |
| SSDEEP | `49152:iFKLYpbbBlirCXbRbtSfcGrVa56ozfKft9gCkd9zUCnlrQxatah4mqu:6KLKmObdgfckVa56oLKfkzUgzaim3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_32aaa1d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32aaa1d07dc07217223009ad404925c5b518907e3b6c8aad1c2250e9f9dc54aa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 03:58:42"
  condition:
    hash.sha256(0, filesize) == "32aaa1d07dc07217223009ad404925c5b518907e3b6c8aad1c2250e9f9dc54aa"
}
```

### Sample 47: `d3e5d5e5289c2e39`

| Field | Value |
|---|---|
| SHA-256 | `d3e5d5e5289c2e39e12dc91a4e286faf64812bf68c83c1f37e88b2fac79d105c` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-25 03:48:07` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad677925d4ffdde33c4392cc76c615ba` |
| SHA-1 | `a5d5deeba33eadfb479ea60995cf2336048b31c1` |
| SHA-256 | `d3e5d5e5289c2e39e12dc91a4e286faf64812bf68c83c1f37e88b2fac79d105c` |
| SHA3-384 | `be8e28fd88682d744df3e98d7835eff5b3c8991e8e4d8c30f7900033ea39dba5498754873bea3d755f69fced0f4d38f0` |
| IMPHASH | `0cd488c64d7af8ac72e356aaa23af145` |
| TLSH | `T1A7546D12F25110F9EC6BC17C82555526F532B8890B31EAFF17A442363E67AE1AF3DB14` |
| SSDEEP | `6144:XnjLHcGMY5vpnSLo38eldMRgYrFyksrLChTT0jVsCjU:zPMi9MPyksrLnTjU` |
| ICON-DHASH | `be7bdcd8d4d47bbe` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_047_d3e5d5e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3e5d5e5289c2e39e12dc91a4e286faf64812bf68c83c1f37e88b2fac79d105c"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 03:48:07"
  condition:
    hash.sha256(0, filesize) == "d3e5d5e5289c2e39e12dc91a4e286faf64812bf68c83c1f37e88b2fac79d105c"
}
```

### Sample 48: `db74e8707f2dd7fe`

| Field | Value |
|---|---|
| SHA-256 | `db74e8707f2dd7fe3819ce7ac210299191f7936dde7ae59a647dfdb9c8e44ea3` |
| Family label | `Mirai` |
| File name | `cwlfkwnt.arm` |
| File type | `elf` |
| First seen | `2026-09-25 03:47:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22adf6b0c44266dec7d54c5017e8034f` |
| SHA-1 | `2c04ee15522ab2cc4caa48094985d3c31b6019f4` |
| SHA-256 | `db74e8707f2dd7fe3819ce7ac210299191f7936dde7ae59a647dfdb9c8e44ea3` |
| SHA3-384 | `069fdac745c5e3691497454136e421c70bc728065a9d9b257ed0d4af8dbdc0bf6e36462c227280d20cafe1446bd32884` |
| TLSH | `T191254B54F890DF63C5D46B7AF65E82A833234778C3E7720699148B383B97A5F0B3A641` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:vXqMFZkx5n3PGDyF52oWJE09657Vx/hGnm7:X6U3G09657VxAm7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_db74e870
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db74e8707f2dd7fe3819ce7ac210299191f7936dde7ae59a647dfdb9c8e44ea3"
    family = "Mirai"
    file_name = "cwlfkwnt.arm"
    file_type = "elf"
    first_seen = "2026-09-25 03:47:19"
  condition:
    hash.sha256(0, filesize) == "db74e8707f2dd7fe3819ce7ac210299191f7936dde7ae59a647dfdb9c8e44ea3"
}
```

### Sample 49: `5103d28c77c07c46`

| Field | Value |
|---|---|
| SHA-256 | `5103d28c77c07c46450180d80c78de6346c580ea63f2dde2cdb9163ec53495d3` |
| Family label | `Mirai` |
| File name | `bot.i686` |
| File type | `elf` |
| First seen | `2026-09-25 03:47:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c6f722c4311956d03c1001bb1618511` |
| SHA-1 | `bdefd406872165837e7dc196b390f5e333c4d961` |
| SHA-256 | `5103d28c77c07c46450180d80c78de6346c580ea63f2dde2cdb9163ec53495d3` |
| SHA3-384 | `f0daf674a84dd15cb03599a6e352f911d6ef31386d80ed6a70feb81bb87984fa8f8f91caee085bf08d1c2e19935ea330` |
| TLSH | `T19E355B5BB2A374BCC157C830879BDA62BD35B46502226E7BB5C4DB302E26D702719F72` |
| TELFHASH | `t157e18a740ef974b5a6e2de60f322f0765a32142676fc39f516266e44ef40fc04c6686b` |
| SSDEEP | `24576:BiG46eqX46t1YRgBV+XdIAKHYoDqSRqZcEtCn5:E+X46tR+NIIoDpRqZhtS5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_5103d28c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5103d28c77c07c46450180d80c78de6346c580ea63f2dde2cdb9163ec53495d3"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-09-25 03:47:18"
  condition:
    hash.sha256(0, filesize) == "5103d28c77c07c46450180d80c78de6346c580ea63f2dde2cdb9163ec53495d3"
}
```

### Sample 50: `2b6c2e6c2ef7396f`

| Field | Value |
|---|---|
| SHA-256 | `2b6c2e6c2ef7396f6dca3183fb894ff41b3180bac8d9746c124de7b4ef3575a0` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.ELF.Mirai-COW.41418858` |
| File type | `elf` |
| First seen | `2026-09-25 03:44:13` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b9f98ea6e444a5ba8a98a234e44fd03` |
| SHA-1 | `866f4ef65b25ea699cd2e18b05d4245045b3b91b` |
| SHA-256 | `2b6c2e6c2ef7396f6dca3183fb894ff41b3180bac8d9746c124de7b4ef3575a0` |
| SHA3-384 | `04dfb5c9abd518e91b764b3fccc50331e278b6b46a37acd3d622d7cff71d9186903db708ba61c38082dc0acae9998b7c` |
| TLSH | `T1FEC46D56BD919B91C6E24ABAFBAD4368721753BDD2FF7007CA009FA077DA4810B3D241` |
| TELFHASH | `t177e0c0700ba84d97a2d24b2fd1cd334315606c3ac6805410588c5d4f44d2cdb789b931` |
| SSDEEP | `12288:V2+un3LvFWDUd0slwUaiJLvzd1mXPJ1JATjDX3NWPn:kfn7QC0slwUaiJLvD2aHRW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_2b6c2e6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b6c2e6c2ef7396f6dca3183fb894ff41b3180bac8d9746c124de7b4ef3575a0"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-COW.41418858"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:13"
  condition:
    hash.sha256(0, filesize) == "2b6c2e6c2ef7396f6dca3183fb894ff41b3180bac8d9746c124de7b4ef3575a0"
}
```

### Sample 51: `5b7e6286c02ededd`

| Field | Value |
|---|---|
| SHA-256 | `5b7e6286c02ededd19289332860e76ed053797d7f31d4be7806a2ac6f3e58694` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Heur.21131.6862` |
| File type | `elf` |
| First seen | `2026-09-25 03:44:12` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3431e26c4e170239d2343a0f0ece11c5` |
| SHA-1 | `4b3ad11c3bd01f14ae598a8c6a6fba9ea7dde6b6` |
| SHA-256 | `5b7e6286c02ededd19289332860e76ed053797d7f31d4be7806a2ac6f3e58694` |
| SHA3-384 | `184786e6586b6e761b7e2b1bce511ff57c14b866eff1f5f1e5a40479d376d03062122ae15600a4d414ae98867cf5e93b` |
| TLSH | `T17AB48D03EAB7E8B0D4A242B1215557B95572C5B315B7D88FEFE52C84DE60284F32C3AB` |
| TELFHASH | `t159e148b32afe1ded77e0a941c30b6712ed06d6b714d835b245f3209932b6a829f71835` |
| SSDEEP | `6144:c1c955yQ+IO5GysTXUV23Hi6rj/IiEUEaJsYo60mPA0isNDQK9i4oECjpf:c1c95+QdO23IQY70isNDQK9/VC9f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_5b7e6286
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b7e6286c02ededd19289332860e76ed053797d7f31d4be7806a2ac6f3e58694"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.21131.6862"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:12"
  condition:
    hash.sha256(0, filesize) == "5b7e6286c02ededd19289332860e76ed053797d7f31d4be7806a2ac6f3e58694"
}
```

### Sample 52: `27c593a40a437810`

| Field | Value |
|---|---|
| SHA-256 | `27c593a40a437810124f2f43a9d67365f1b91a3f52ab64e44d0f5b120ca78136` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.ELF.Mirai-COW.97552716` |
| File type | `elf` |
| First seen | `2026-09-25 03:44:09` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fce665ffd54fe009fce8626468fd2e38` |
| SHA-1 | `55bf21cc08ca4a06c8672f1143d3ada84a0cbe33` |
| SHA-256 | `27c593a40a437810124f2f43a9d67365f1b91a3f52ab64e44d0f5b120ca78136` |
| SHA3-384 | `6f826d14c2c69fc31a33ae5bed3b14d560ecd12feccb1426188c8f537aa6eb6a49c524df045422c3bbbbeec3e56550ef` |
| TLSH | `T1B0C46D66BD919B91C6E24ABAFBAE4368720753B9D2FF7007CA045F6077DA4810F3D241` |
| TELFHASH | `t13ae06f208ead00af82d047ebe29a325e09e1fc355ea1307809402f9e09a2887e24b152` |
| SSDEEP | `12288:pBTQS6h3W/qCYlDhUAJQvtW10X99/DfH3Ybn:bTQpOqCYlDhUAJQvCoTY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_27c593a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27c593a40a437810124f2f43a9d67365f1b91a3f52ab64e44d0f5b120ca78136"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-COW.97552716"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:09"
  condition:
    hash.sha256(0, filesize) == "27c593a40a437810124f2f43a9d67365f1b91a3f52ab64e44d0f5b120ca78136"
}
```

### Sample 53: `1d55613d5c924ace`

| Field | Value |
|---|---|
| SHA-256 | `1d55613d5c924ace53b733096a9ffe3c22c3f703f8abc4b18e55e1f75dd9f3d5` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Heur.8161.10136` |
| File type | `elf` |
| First seen | `2026-09-25 03:44:07` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f951e5ccf7cc7540cf88ca92fcb7236d` |
| SHA-1 | `ab6a068ac1ea9d403543d25db2d72f93124e9aa2` |
| SHA-256 | `1d55613d5c924ace53b733096a9ffe3c22c3f703f8abc4b18e55e1f75dd9f3d5` |
| SHA3-384 | `72d7cfe618f21c393655ad345056bd5a6d356318c2717d4a09d88ff58ae8767d1657c0ecd21f39df651aadb9d758625f` |
| TLSH | `T142C44A132A764B56C8D4C07931F30339E5B9968A21FCE51AEF915ECD7F38180367A3A9` |
| SSDEEP | `6144:9m2UlgOT8pwMkqep7rKad3A8OTatqUo0IgyIubZhmOWPGgVHLSbA:9m2UlSy3DOi3IgZez8PtHebA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_1d55613d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d55613d5c924ace53b733096a9ffe3c22c3f703f8abc4b18e55e1f75dd9f3d5"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.8161.10136"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:07"
  condition:
    hash.sha256(0, filesize) == "1d55613d5c924ace53b733096a9ffe3c22c3f703f8abc4b18e55e1f75dd9f3d5"
}
```

### Sample 54: `a965431e4a881f48`

| Field | Value |
|---|---|
| SHA-256 | `a965431e4a881f482e7e71d6f6e52c5c7ab05ce75e656869558c194d167bb5bf` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Heur.23741.18903` |
| File type | `elf` |
| First seen | `2026-09-25 03:44:05` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7075231163c232e021d470b5cfa61339` |
| SHA-1 | `321b211d901790c55288c4463d8dd47b65da6edd` |
| SHA-256 | `a965431e4a881f482e7e71d6f6e52c5c7ab05ce75e656869558c194d167bb5bf` |
| SHA3-384 | `9ca1472b1c8194ff130ead963d367c963a7743d44d216931f3e87490d0ca34cb4c6872476c73478533209f5e4914b58e` |
| TLSH | `T147C46D67BD919BC0C5E149BEFBAE436872035BB9E2EFB106CA045F917BC58850B3E141` |
| SSDEEP | `12288:8iZkjvsNPu47SEemhLuX3aWaXtPlUNawhN8djBhdX:aQ7SWgnb4jBh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_a965431e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a965431e4a881f482e7e71d6f6e52c5c7ab05ce75e656869558c194d167bb5bf"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.23741.18903"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:05"
  condition:
    hash.sha256(0, filesize) == "a965431e4a881f482e7e71d6f6e52c5c7ab05ce75e656869558c194d167bb5bf"
}
```

### Sample 55: `3ef8580795f9e384`

| Field | Value |
|---|---|
| SHA-256 | `3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3` |
| Family label | `Mirai` |
| File name | `3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3` |
| File type | `elf` |
| First seen | `2026-09-25 03:17:28` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11c0cbff17b428cd1b6cdb5d81d3d16a` |
| SHA-1 | `fe685a8e418551e8428283c645629d6f5dd6090f` |
| SHA-256 | `3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3` |
| SHA3-384 | `8f6167fcfa6106e09f5c59732bdda86fc34e478ae20a1fd219b90b86792347001c04e7eb2c3790d9f09316dcccbc63f7` |
| TLSH | `T1C2C3088BBC81DE6946C0277BFA2E418E330327B4D1DF71539D141F68B68A94F0E6A652` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJo:T2s/gAWuboqsJ9xcJxspJBqQgTuaJo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_3ef85807
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3"
    family = "Mirai"
    file_name = "3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3"
    file_type = "elf"
    first_seen = "2026-09-25 03:17:28"
  condition:
    hash.sha256(0, filesize) == "3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3"
}
```

### Sample 56: `bd01d8dfcb86adba`

| Field | Value |
|---|---|
| SHA-256 | `bd01d8dfcb86adbaaecf212506e71d5207715f3e92316cda3f7ac41910022217` |
| Family label | `unknown` |
| File name | `created-wp.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:58` |
| Reporter | `boredchilada2` |
| Tags | `account-injection, cpanel, kamp4ng, php, wordpress` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90fc465085d2558cda77a87d8b810143` |
| SHA-1 | `0408a5e816bb3d0849ca2f20b8993f05a7c66591` |
| SHA-256 | `bd01d8dfcb86adbaaecf212506e71d5207715f3e92316cda3f7ac41910022217` |
| SHA3-384 | `fc7efac02942dba5b4c9b7e8b0de0dca1f8ece09f47d322c03d08988db6ce31877e118b664f5fbe600a6ddc1c8ea48ee` |
| TLSH | `T14051F27420E65E4A2163E4943E4539053CC1C213A5196652B8FC37F9EF9DE57CCB336A` |
| SSDEEP | `48:AV9B3M+Vi7EL7Zi6AlRAihZ6QBrXghZqAxvhZx0cvrnOB6TGEvyv0Aef:AVFVAEUnAiT6GrQTqWvTx0cznOB66ibf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_bd01d8df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd01d8dfcb86adbaaecf212506e71d5207715f3e92316cda3f7ac41910022217"
    family = "unknown"
    file_name = "created-wp.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:58"
  condition:
    hash.sha256(0, filesize) == "bd01d8dfcb86adbaaecf212506e71d5207715f3e92316cda3f7ac41910022217"
}
```

### Sample 57: `12942bba4b7c24f3`

| Field | Value |
|---|---|
| SHA-256 | `12942bba4b7c24f3c9b37d972caea2d769c1882375faf5dc4b265a5dacdd63b3` |
| Family label | `unknown` |
| File name | `belom-ready.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:52` |
| Reporter | `boredchilada2` |
| Tags | `cpanel, kamp4ng, php, php-loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f8605229517688c51f13b950a07b5a7` |
| SHA-1 | `850bcbc2fe6d1bdda2bdbf3385e339836fd23122` |
| SHA-256 | `12942bba4b7c24f3c9b37d972caea2d769c1882375faf5dc4b265a5dacdd63b3` |
| SHA3-384 | `75388c243d01682db685cc7f4bce4b497cb3568f4c447bd85cc126d02a8cd2048b274fd1108baf842632cd7c9c80f11b` |
| TLSH | `T1D732939AA493090DF02390502BE7A70D32B4D507E903ED18BBEE21D5DF695DDEAFA350` |
| SSDEEP | `192:RV1/CmrVBl0XJitQw57BZRwk+Zwl+ZR4Kwl+ZR5vtNvtPMCndEeOSJV0Sp9L0F2o:RV1/jrVf6SURqFTKzskNyPWyxN/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_12942bba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12942bba4b7c24f3c9b37d972caea2d769c1882375faf5dc4b265a5dacdd63b3"
    family = "unknown"
    file_name = "belom-ready.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:52"
  condition:
    hash.sha256(0, filesize) == "12942bba4b7c24f3c9b37d972caea2d769c1882375faf5dc4b265a5dacdd63b3"
}
```

### Sample 58: `9b74712f8e5a46e0`

| Field | Value |
|---|---|
| SHA-256 | `9b74712f8e5a46e0f9718bf6da01590a033d95da66c6f6a7b3d34fd8a3a385b9` |
| Family label | `unknown` |
| File name | `anore-r2-stage2.php` |
| File type | `php` |
| First seen | `2026-09-25 03:14:48` |
| Reporter | `boredchilada2` |
| Tags | `anonsec, cloudflare-r2, kamp4ng, lpe, php, php-webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b84c7b0d3f4482cdf7aad726292544c` |
| SHA-1 | `1a72f146879b9960d1df79e5bc3dac13b269a22a` |
| SHA-256 | `9b74712f8e5a46e0f9718bf6da01590a033d95da66c6f6a7b3d34fd8a3a385b9` |
| SHA3-384 | `ae1d12cc5e88dd12cb0534ce47c2e320132f6425499b8f32412f38b7e0f96de0c8c3a62ce86c4dfde1e789d442bb769c` |
| TLSH | `T1BB7397E0B506C8E222DF0FB57FB22C5B6898C1F64145A9CA3EC8757933D892141E9FD6` |
| SSDEEP | `1536:RtYjc2gHwqtsLUh6IRmfASUuxLdqf0Xu0BlzOKjqaq+3RUI05C5CZQbZ5eG3:RtWcqqtsJ3KMv3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_9b74712f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b74712f8e5a46e0f9718bf6da01590a033d95da66c6f6a7b3d34fd8a3a385b9"
    family = "unknown"
    file_name = "anore-r2-stage2.php"
    file_type = "php"
    first_seen = "2026-09-25 03:14:48"
  condition:
    hash.sha256(0, filesize) == "9b74712f8e5a46e0f9718bf6da01590a033d95da66c6f6a7b3d34fd8a3a385b9"
}
```

### Sample 59: `d521dc2da106ed44`

| Field | Value |
|---|---|
| SHA-256 | `d521dc2da106ed44368a65f51095782f9d8e595305e773572a36d4e0b8bf6b46` |
| Family label | `unknown` |
| File name | `anore.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:42` |
| Reporter | `boredchilada2` |
| Tags | `cloudflare-r2, cpanel, kamp4ng, php, php-loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddd5bb0e30007bf7e4166b9eee0a4edc` |
| SHA-1 | `d4a9c6a16432073c6b34a9261ed85635d56dbb8a` |
| SHA-256 | `d521dc2da106ed44368a65f51095782f9d8e595305e773572a36d4e0b8bf6b46` |
| SHA3-384 | `41193f41fc9b86fba5239d0e5f6ba2203c7f29af30a3dea59908a6bba61c0b8e702b322d44504e69c0f3bdbcc726ac37` |
| TLSH | `T1F921414D2422C377448106E53797A2CFF217539B31E894E4B55ED7FA4E0AAA512E1CB8` |
| SSDEEP | `24:HhPEON7Jk7iOSXyXOkHm2TbVPxQRobsGFiDvcpeOKt7Kto2K5Vu:f2oyxHwQsGecppsuS0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_d521dc2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d521dc2da106ed44368a65f51095782f9d8e595305e773572a36d4e0b8bf6b46"
    family = "unknown"
    file_name = "anore.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:42"
  condition:
    hash.sha256(0, filesize) == "d521dc2da106ed44368a65f51095782f9d8e595305e773572a36d4e0b8bf6b46"
}
```

### Sample 60: `f45333b26481e36b`

| Field | Value |
|---|---|
| SHA-256 | `f45333b26481e36be1dc306f8630b6126c42e4a1cbbe024e2b286a580952f9b1` |
| Family label | `unknown` |
| File name | `a.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:37` |
| Reporter | `boredchilada2` |
| Tags | `cpanel, kamp4ng, php, php-loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `768aa37f499605a9ad96c70fb8031b79` |
| SHA-1 | `585eaef302a1da17998c8f1a75f5478c4faa36a2` |
| SHA-256 | `f45333b26481e36be1dc306f8630b6126c42e4a1cbbe024e2b286a580952f9b1` |
| SHA3-384 | `c2c926c74b27f943a8b2345e9f7f62225acb6d2975fb8d1b425a0f215315b3ae5abbe9fc7d91482d667317e73f7075dc` |
| TLSH | `T12E8263AB9AA314156513D0B86FAB53093275C103824ECD2C7FAD6288DFC57DDCDA2BD8` |
| SSDEEP | `192:Fs4pQBWoanbin8yBZ2/yN+k68VBCypyWyBLAcRsvrQQpcVtyA2yB0ys8/Hk4ZHSS:Fs4M6nWaygBAc+5IX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_f45333b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f45333b26481e36be1dc306f8630b6126c42e4a1cbbe024e2b286a580952f9b1"
    family = "unknown"
    file_name = "a.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:37"
  condition:
    hash.sha256(0, filesize) == "f45333b26481e36be1dc306f8630b6126c42e4a1cbbe024e2b286a580952f9b1"
}
```

### Sample 61: `b7f0d6a31daac70c`

| Field | Value |
|---|---|
| SHA-256 | `b7f0d6a31daac70c443ecdce04417b32002bcb7537ffc5f22f641dcea581c2b3` |
| Family label | `unknown` |
| File name | `sora.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:32` |
| Reporter | `boredchilada2` |
| Tags | `cpanel, kamp4ng, php, php-loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2309a28a1f4b276b38576a9e9e4b9026` |
| SHA-1 | `c66a1ad434ba665ca31703cf7418587d9107a13a` |
| SHA-256 | `b7f0d6a31daac70c443ecdce04417b32002bcb7537ffc5f22f641dcea581c2b3` |
| SHA3-384 | `6ef87e65da0b9e687352603316b6503660dadac9fbfcbd44d9518deee59090d52c5b7852348ebfd06d691e566d8d6ba6` |
| TLSH | `T14981A55218E318016217C0B8677786097668C25B6249CE187D9E63AC9FCEB4F81F72EF` |
| SSDEEP | `96:FZv6GAufpQBWkZpVY/jnbiWNgf0U9KuGrlDylJuvE:FsKpQBWo8nbiWNgsU4uGrlDylJR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_b7f0d6a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f0d6a31daac70c443ecdce04417b32002bcb7537ffc5f22f641dcea581c2b3"
    family = "unknown"
    file_name = "sora.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:32"
  condition:
    hash.sha256(0, filesize) == "b7f0d6a31daac70c443ecdce04417b32002bcb7537ffc5f22f641dcea581c2b3"
}
```

### Sample 62: `7f800bdb0cbc945b`

| Field | Value |
|---|---|
| SHA-256 | `7f800bdb0cbc945b8f59789e7276852f7ab4822f87b185b45c9a81ee7f84acde` |
| Family label | `unknown` |
| File name | `litespeed.txt` |
| File type | `unknown` |
| First seen | `2026-09-25 03:14:27` |
| Reporter | `boredchilada2` |
| Tags | `cpanel, file-manager, kamp4ng, php-webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dcfc2e70b9130bd26e01e010cb79c03` |
| SHA-256 | `7f800bdb0cbc945b8f59789e7276852f7ab4822f87b185b45c9a81ee7f84acde` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_7f800bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f800bdb0cbc945b8f59789e7276852f7ab4822f87b185b45c9a81ee7f84acde"
    family = "unknown"
    file_name = "litespeed.txt"
    file_type = "unknown"
    first_seen = "2026-09-25 03:14:27"
  condition:
    hash.sha256(0, filesize) == "7f800bdb0cbc945b8f59789e7276852f7ab4822f87b185b45c9a81ee7f84acde"
}
```

### Sample 63: `35697a14b56ddf66`

| Field | Value |
|---|---|
| SHA-256 | `35697a14b56ddf664d987433a87a105a3f2e9912b3edcde17f536a5dd490cbd2` |
| Family label | `unknown` |
| File name | `acc.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:22` |
| Reporter | `boredchilada2` |
| Tags | `cpanel, kamp4ng, php, php-webshell, team-kj` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fedc7263b557af7065d1a8a4d8587216` |
| SHA-1 | `5ce8da17d84365c6143cb329d1fafe60c79a592d` |
| SHA-256 | `35697a14b56ddf664d987433a87a105a3f2e9912b3edcde17f536a5dd490cbd2` |
| SHA3-384 | `dfb34f9db2942ee5d5fab8c7c500bf4c321729c4d70922231d05f42c4b2d8794d88db396dddc0c2f09b1a2e6638c7549` |
| TLSH | `T12D934D22B1C168376013DAA977C7A60D7659435B83024E44BCED1AE0DFC89F486BEFE5` |
| SSDEEP | `1536:HOylgBeji1lzl1yE29ypkj+ylTgKooAikp3gOaMjkRFt+0mOHZjd3:uyluPyj9yp++ylBun3g8GZl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_35697a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35697a14b56ddf664d987433a87a105a3f2e9912b3edcde17f536a5dd490cbd2"
    family = "unknown"
    file_name = "acc.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:22"
  condition:
    hash.sha256(0, filesize) == "35697a14b56ddf664d987433a87a105a3f2e9912b3edcde17f536a5dd490cbd2"
}
```

### Sample 64: `ce01dac06be173dd`

| Field | Value |
|---|---|
| SHA-256 | `ce01dac06be173ddfe6f1e1d65088a112272a2d158b7da505fc23f014e7ca63a` |
| Family label | `unknown` |
| File name | `kj.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:17` |
| Reporter | `boredchilada2` |
| Tags | `cpanel, kamp4ng, php, php-webshell, team-kj` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `406e903f12cb490431db07ec65e153ac` |
| SHA-1 | `db13f506c06863b77ddcf7198f0fa07c71ab166e` |
| SHA-256 | `ce01dac06be173ddfe6f1e1d65088a112272a2d158b7da505fc23f014e7ca63a` |
| SHA3-384 | `4d9bf4625711a58c4a3e206dd2e58f469e0c44322e1b3fbaed97008bc9166fad9cf127f81cad81c782842f5731a24d86` |
| TLSH | `T1CE132B21B1829C126107CABA77C3650D3669436F83024E88FD9D5AF5EFC45F4867AEE8` |
| SSDEEP | `768:AaytylUsoBwrTwJ98ji1l6UlE4zpJovYhCWVR44tQx9aTp/:3OylgBeji1lzl1yE29yp/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_ce01dac0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce01dac06be173ddfe6f1e1d65088a112272a2d158b7da505fc23f014e7ca63a"
    family = "unknown"
    file_name = "kj.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:17"
  condition:
    hash.sha256(0, filesize) == "ce01dac06be173ddfe6f1e1d65088a112272a2d158b7da505fc23f014e7ca63a"
}
```

### Sample 65: `6f94b2f7d0a57f39`

| Field | Value |
|---|---|
| SHA-256 | `6f94b2f7d0a57f39e500a08a24cf90177acd3c2cce1fdbdb586170d2a7d42cbe` |
| Family label | `unknown` |
| File name | `nexus.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:12` |
| Reporter | `boredchilada2` |
| Tags | `cpanel, kamp4ng, nexus, php, php-webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6371ceda495b1549070482217540c4e` |
| SHA-1 | `86f61a6de45dee6f1b93382463ff06fe666d8585` |
| SHA-256 | `6f94b2f7d0a57f39e500a08a24cf90177acd3c2cce1fdbdb586170d2a7d42cbe` |
| SHA3-384 | `badaef9ba6677c7f495525396400537877720d46276f0ceb96cb0de9d79f6af5bb63b760c1c99b7ed009d86338c483ab` |
| TLSH | `T19F63D76638EF24635217B8B8275B9B0F3255810BD009CD043EEC23D89FC5F99D9EA799` |
| SSDEEP | `768:FT94VpizpbtL4T1bNfqYINY79WKJ5zMLUsTeD9vM3bpHXXSl0RG+m2:FialWT1bNfqYwYcgvixq0xV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_6f94b2f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f94b2f7d0a57f39e500a08a24cf90177acd3c2cce1fdbdb586170d2a7d42cbe"
    family = "unknown"
    file_name = "nexus.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:12"
  condition:
    hash.sha256(0, filesize) == "6f94b2f7d0a57f39e500a08a24cf90177acd3c2cce1fdbdb586170d2a7d42cbe"
}
```

### Sample 66: `2f1f63b7d2fe56fd`

| Field | Value |
|---|---|
| SHA-256 | `2f1f63b7d2fe56fdad569712ecb92e4ffd6099f2f2a6cf7fbdbe76349490a45f` |
| Family label | `unknown` |
| File name | `alfa-putih.txt` |
| File type | `php` |
| First seen | `2026-09-25 03:14:06` |
| Reporter | `boredchilada2` |
| Tags | `alfa-team, cpanel, kamp4ng, php, php-webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9907fa36ecc59ba6619d33bc6b197ef` |
| SHA-1 | `88fe417e67b89f0e6bee32f4bc040708b3d4ec23` |
| SHA-256 | `2f1f63b7d2fe56fdad569712ecb92e4ffd6099f2f2a6cf7fbdbe76349490a45f` |
| SHA3-384 | `99790bb0984aaaf8bc69d35be49cb3af0933ec1cc6ace17b69cbf64c22657651603371fe54f76d34b1ea5369c2feeef1` |
| TLSH | `T1415521AB6D8F63369FD7E5A2C7D6E2405A70E8D7640B09C3B8807BC9CD7DC104A9D921` |
| SSDEEP | `24576:doFuJOgYr+hJIqai62VOTj+tagAqsjxj5t3+Wmx5VHjagrpdS+FE3lupxy:doFuJOgYr+hJIqai62VYj+tagnmxj5tr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_2f1f63b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f1f63b7d2fe56fdad569712ecb92e4ffd6099f2f2a6cf7fbdbe76349490a45f"
    family = "unknown"
    file_name = "alfa-putih.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:06"
  condition:
    hash.sha256(0, filesize) == "2f1f63b7d2fe56fdad569712ecb92e4ffd6099f2f2a6cf7fbdbe76349490a45f"
}
```

### Sample 67: `597e1f47936b2dc9`

| Field | Value |
|---|---|
| SHA-256 | `597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009` |
| Family label | `VShell` |
| File name | `597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009.exe` |
| File type | `exe` |
| First seen | `2026-09-25 03:10:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd59471e857f69a7bca85a93cbd1d0fe` |
| SHA-1 | `e17f6201bbd2a53557140c8b6fe83e83a6bc4a0a` |
| SHA-256 | `597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009` |
| SHA3-384 | `1442e0ff26667df44e715325134f57aa685b3892c1d723675dca365485d67cf86035425fd4c94cb681fb7aec3aae3765` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1E891C64170B989E7E85C45BF4C0FB8A4B91D740A41C483A60378A5993E3A57BF5BCB0E` |
| SSDEEP | `48:6IIF9BlQaexlgZS7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMw70cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_067_597e1f47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009"
    family = "VShell"
    file_name = "597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:10:13"
  condition:
    hash.sha256(0, filesize) == "597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009"
}
```

### Sample 68: `1ef89f262d5b25d2`

| Field | Value |
|---|---|
| SHA-256 | `1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22` |
| Family label | `unknown` |
| File name | `1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22.bin` |
| File type | `zip` |
| First seen | `2026-09-25 03:09:29` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d13701d99e8dc2a2d9e8b1f68297227e` |
| SHA-1 | `554f2f6ee30c35ef1b42fa68a6961506bc0e15fe` |
| SHA-256 | `1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22` |
| SHA3-384 | `9d6f107a4ad4fbefd5b13b686670f28c38aee836d515dbaadd8df0affe7fed666702d945b643b53f30f5eb410383ec42` |
| TLSH | `T1498423348BCA877C3BBAB93CC79C1CF3A465BF556A17CE056D31A03AA535B59481C213` |
| SSDEEP | `6144:tn1vWMtXQjknCyZhe6LTlvlH1ig3/pEl7HQSRyFWhY34pmancrg0ypXMeU9Aou:1xXtiz23fpigvpExwr6YIpxfyx21` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_1ef89f26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22"
    family = "unknown"
    file_name = "1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22.bin"
    file_type = "zip"
    first_seen = "2026-09-25 03:09:29"
  condition:
    hash.sha256(0, filesize) == "1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22"
}
```

### Sample 69: `b15f0c3550a40034`

| Field | Value |
|---|---|
| SHA-256 | `b15f0c3550a40034e11547bedd66d220d75ee73a99194e5285046b4e3cc031aa` |
| Family label | `ValleyRAT` |
| File name | `B137780B84CB1E07D3BE853460B28C3E.dll` |
| File type | `dll` |
| First seen | `2026-09-25 03:00:32` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b137780b84cb1e07d3be853460b28c3e` |
| SHA-1 | `54ce51830add45602d35779573f40d72e1e7cb65` |
| SHA-256 | `b15f0c3550a40034e11547bedd66d220d75ee73a99194e5285046b4e3cc031aa` |
| SHA3-384 | `a3ca9a7c55c2807b85edf2212a4dd09eee692224817c4699ed7c2c5b9c5c4ce1fc8271c9f7ba68159f9ee57e4cb56ea0` |
| IMPHASH | `ed719d06b435e943e2137e8d090ae910` |
| TLSH | `T1BD847E01B5818131E9AE0934B835DBA75A7DB8714BE0D4DFA3C44DAE9E207D1EB3871B` |
| SSDEEP | `6144:2cZZ+x7m+cWCDq7ZNIFTRhUE1Tk6++a3/z3mDAa/SnkuVNWEAYEQHTpo:vQc8nIFTRp1TkhhGWVY0+` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_069_b15f0c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b15f0c3550a40034e11547bedd66d220d75ee73a99194e5285046b4e3cc031aa"
    family = "ValleyRAT"
    file_name = "B137780B84CB1E07D3BE853460B28C3E.dll"
    file_type = "dll"
    first_seen = "2026-09-25 03:00:32"
  condition:
    hash.sha256(0, filesize) == "b15f0c3550a40034e11547bedd66d220d75ee73a99194e5285046b4e3cc031aa"
}
```

### Sample 70: `0b5ce68beab1bef3`

| Field | Value |
|---|---|
| SHA-256 | `0b5ce68beab1bef3e214c00995c5590825bb096cd2cc2a07af1dad9c4c8579b2` |
| Family label | `ValleyRAT` |
| File name | `D9102A1929D66B6A5CC6B1CEE95F3E8C.dll` |
| File type | `dll` |
| First seen | `2026-09-25 03:00:29` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9102a1929d66b6a5cc6b1cee95f3e8c` |
| SHA-1 | `191c852ec68d789f574dfcd533ea4b249c110ad7` |
| SHA-256 | `0b5ce68beab1bef3e214c00995c5590825bb096cd2cc2a07af1dad9c4c8579b2` |
| SHA3-384 | `40e9c6633bcf86bc807dd2f10b61dadc3cdc42e77e1645bf0179a4c68f491cf452fec265736a47b20c035868b1bb4927` |
| IMPHASH | `ed719d06b435e943e2137e8d090ae910` |
| TLSH | `T101847D01B5818131E9AE0934B835DBA75A7DB8710BE4D4DFA3C44DAE9E207D1EB3871B` |
| SSDEEP | `6144:AcZZ+x7m+cWCDq7ZNIFTRhUE1Tk6++a3/z3mDAa/SnkuVNzEAYEQHTpo:JQc8nIFTRp1TkhhGWVt0+` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_070_0b5ce68b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b5ce68beab1bef3e214c00995c5590825bb096cd2cc2a07af1dad9c4c8579b2"
    family = "ValleyRAT"
    file_name = "D9102A1929D66B6A5CC6B1CEE95F3E8C.dll"
    file_type = "dll"
    first_seen = "2026-09-25 03:00:29"
  condition:
    hash.sha256(0, filesize) == "0b5ce68beab1bef3e214c00995c5590825bb096cd2cc2a07af1dad9c4c8579b2"
}
```

### Sample 71: `2db23dbabf20814d`

| Field | Value |
|---|---|
| SHA-256 | `2db23dbabf20814d496c61778c178ecf7a0da76f199f5476f45b4bbd650a4dd4` |
| Family label | `CobaltStrike` |
| File name | `0b9bde384dac136914f21b8e5483c409.exe` |
| File type | `exe` |
| First seen | `2026-09-25 03:00:26` |
| Reporter | `abuse_ch` |
| Tags | `CobaltStrike, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b9bde384dac136914f21b8e5483c409` |
| SHA-1 | `25e750a10bc1d263e969d962f567fc55fbceff44` |
| SHA-256 | `2db23dbabf20814d496c61778c178ecf7a0da76f199f5476f45b4bbd650a4dd4` |
| SHA3-384 | `24af2165ee202185124895e611c19fc701a3864754a30e279dc756d043cc3a24e6fc88904372de24197389e73b06164a` |
| IMPHASH | `147442e63270e287ed57d33257638324` |
| TLSH | `T19292D83FE31358E9C506D5B845FF3733DCB139B385A6A32E2724D2B42E106A46E6E610` |
| SSDEEP | `192:/V7qaCF6Op1t2dobVXujRDcBaXWQjwOT/2dn9HysLn3WF8qa1Dojjgi:5qaCF31cix+Dc4zjInJ7LGFF46gi` |

#### Technical Assessment

- The sample is tracked as `CobaltStrike` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CobaltStrike_071_2db23dba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2db23dbabf20814d496c61778c178ecf7a0da76f199f5476f45b4bbd650a4dd4"
    family = "CobaltStrike"
    file_name = "0b9bde384dac136914f21b8e5483c409.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:00:26"
  condition:
    hash.sha256(0, filesize) == "2db23dbabf20814d496c61778c178ecf7a0da76f199f5476f45b4bbd650a4dd4"
}
```

### Sample 72: `6f0fd39f4698b31d`

| Field | Value |
|---|---|
| SHA-256 | `6f0fd39f4698b31d53bddccd15b0627683f09a5f43f90f56e557eb24c95d2c3f` |
| Family label | `ColibriLoader` |
| File name | `B63D2C05DC5F1683B99E2A4B4F9D3C24.exe` |
| File type | `exe` |
| First seen | `2026-09-25 03:00:23` |
| Reporter | `abuse_ch` |
| Tags | `ColibriLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b63d2c05dc5f1683b99e2a4b4f9d3c24` |
| SHA-1 | `d917a7d87d893882416261b2533b265052c3ec19` |
| SHA-256 | `6f0fd39f4698b31d53bddccd15b0627683f09a5f43f90f56e557eb24c95d2c3f` |
| SHA3-384 | `56c4d46024f1468a3123a44a1a6527ba8dac5b7b535417bcbe80cf6530b95bd9504e101591bd248fe1c802b67cac2706` |
| TLSH | `T151A21913BAC5527AE16102395F9B9F66703BAB2303776C95E3C367530813A867E3B48D` |
| SSDEEP | `384:9WyhWvbxf4vyEwGYo23mQXJ6nf6mfCQa9P9Ga/sfp7XRY:ouahno22lnjfkFb/s` |

#### Technical Assessment

- The sample is tracked as `ColibriLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ColibriLoader_072_6f0fd39f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f0fd39f4698b31d53bddccd15b0627683f09a5f43f90f56e557eb24c95d2c3f"
    family = "ColibriLoader"
    file_name = "B63D2C05DC5F1683B99E2A4B4F9D3C24.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:00:23"
  condition:
    hash.sha256(0, filesize) == "6f0fd39f4698b31d53bddccd15b0627683f09a5f43f90f56e557eb24c95d2c3f"
}
```

### Sample 73: `9b2a3b0dd168473c`

| Field | Value |
|---|---|
| SHA-256 | `9b2a3b0dd168473cd7cac5f37246b640e1df6a44647f1214e36b434826b63e5c` |
| Family label | `RedLineStealer` |
| File name | `1C06BE88EB3ADB8C17511F6FE4F8E631.exe` |
| File type | `exe` |
| First seen | `2026-09-25 03:00:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, RedLineStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c06be88eb3adb8c17511f6fe4f8e631` |
| SHA-1 | `8b304ba4bb4501094961c26af28d4f9b33a9df09` |
| SHA-256 | `9b2a3b0dd168473cd7cac5f37246b640e1df6a44647f1214e36b434826b63e5c` |
| SHA3-384 | `26c2881faa3ea66feee027d4be026727469ec4caa8986c6b3b3dd4c27e56eecac01ef2091cb75cf83097534d783f18bb` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B5A35D3067AC9F19EAFD1B74B4B2012043F0E48A9091FB4B4DC154E61FA7B865957EF2` |
| SSDEEP | `1536:9qs+XqrzWBlbG6jejoigI343Ywzi0Zb78ivombfexv0ujXyyed2f3tmulgS6pY:r0gzWHY3+zi0ZbYe1g0ujyzdXY` |

#### Technical Assessment

- The sample is tracked as `RedLineStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RedLineStealer_073_9b2a3b0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b2a3b0dd168473cd7cac5f37246b640e1df6a44647f1214e36b434826b63e5c"
    family = "RedLineStealer"
    file_name = "1C06BE88EB3ADB8C17511F6FE4F8E631.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:00:18"
  condition:
    hash.sha256(0, filesize) == "9b2a3b0dd168473cd7cac5f37246b640e1df6a44647f1214e36b434826b63e5c"
}
```

### Sample 74: `eab6449614bea514`

| Field | Value |
|---|---|
| SHA-256 | `eab6449614bea5149944852161e721dbeac40df491136e40c1edd31908521974` |
| Family label | `AsyncRAT` |
| File name | `PO2606-00023.js` |
| File type | `js` |
| First seen | `2026-09-25 03:00:15` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, js, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7fb3716e0aa3efe68d5d59b2a9e42e8` |
| SHA-1 | `6e3ea918b4f84a080af84144a839ea7e2fb2c55d` |
| SHA-256 | `eab6449614bea5149944852161e721dbeac40df491136e40c1edd31908521974` |
| SHA3-384 | `652766127390bb6e2f3e90a8fa948fbf4c160124f01b1052343b8b9c265cd5e49998a83d3e3e3b9465d82ca547cc10e9` |
| TLSH | `T16A75882B276C6C5BD815C1568E913EF6CA3B9117E2C0FE69AAE5833627EF57003C7241` |
| SSDEEP | `12288:64pp2Gq7ATDlDl1WgAuDRxqr4p1orEh4y9di1ON/tq2y0q2cvJIfCPvmP8c6mX0e:yEZlZXn9s1f0aVWNm59i` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_074_eab64496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eab6449614bea5149944852161e721dbeac40df491136e40c1edd31908521974"
    family = "AsyncRAT"
    file_name = "PO2606-00023.js"
    file_type = "js"
    first_seen = "2026-09-25 03:00:15"
  condition:
    hash.sha256(0, filesize) == "eab6449614bea5149944852161e721dbeac40df491136e40c1edd31908521974"
}
```

### Sample 75: `0f2211459a6fd395`

| Field | Value |
|---|---|
| SHA-256 | `0f2211459a6fd39506460bb309d30f673b27c7ab72fc9e41ea3c27e360f8e65f` |
| Family label | `AsyncRAT` |
| File name | `TEKLAS Purchase Order 24-09-2026.js` |
| File type | `js` |
| First seen | `2026-09-25 03:00:11` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, js, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b9c054bfce81fa1d530776142942246` |
| SHA-1 | `e37b5cfabf92bef203528b205fd279f8b6b0c68f` |
| SHA-256 | `0f2211459a6fd39506460bb309d30f673b27c7ab72fc9e41ea3c27e360f8e65f` |
| SHA3-384 | `1fc2125c74b7a547f4c915e40d812b403af54e214b84ffea05381ed2198b0b670dc591c0dbb1530239133af6b604b4c9` |
| TLSH | `T107754F2318D54992AA5BA2F7241B1E9FE33BA199A3C2FD11EFDBB0091F7D5D3094E041` |
| SSDEEP | `12288:64ppSSN8jPvZ1ELTYISB9O5Q+zDUU4n92JfCx6RCfZCVOQac98Bp5CQWjHuSUf5i:nQINXq6Ifo90G1k51lk` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_075_0f221145
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f2211459a6fd39506460bb309d30f673b27c7ab72fc9e41ea3c27e360f8e65f"
    family = "AsyncRAT"
    file_name = "TEKLAS Purchase Order 24-09-2026.js"
    file_type = "js"
    first_seen = "2026-09-25 03:00:11"
  condition:
    hash.sha256(0, filesize) == "0f2211459a6fd39506460bb309d30f673b27c7ab72fc9e41ea3c27e360f8e65f"
}
```

### Sample 76: `d165b25b803cbf5f`

| Field | Value |
|---|---|
| SHA-256 | `d165b25b803cbf5f2f2d3723cf1c778028832bbf26bf91a895f449439a1abbc9` |
| Family label | `NanoCore` |
| File name | `0ebea18d678fe2aabf937cc67d5c208d.exe` |
| File type | `exe` |
| First seen | `2026-09-25 03:00:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ebea18d678fe2aabf937cc67d5c208d` |
| SHA-1 | `8eed60eb37444cee59852002267b4fcc5b59fecc` |
| SHA-256 | `d165b25b803cbf5f2f2d3723cf1c778028832bbf26bf91a895f449439a1abbc9` |
| SHA3-384 | `78177dd78c02ff40d1e518e92cb244812c1f4659249839110f3affadb379b9270be9036c3166ca5c559e1a0cc630f974` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1DC14CF5677A84A2FE2DE867D611212169379C2E39CC3F3EE28D455B78F267E00A071D3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5/6V2qhLyNPYTbEj+:MLV6BtpmkIM2uL4YTv` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_076_d165b25b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d165b25b803cbf5f2f2d3723cf1c778028832bbf26bf91a895f449439a1abbc9"
    family = "NanoCore"
    file_name = "0ebea18d678fe2aabf937cc67d5c208d.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:00:07"
  condition:
    hash.sha256(0, filesize) == "d165b25b803cbf5f2f2d3723cf1c778028832bbf26bf91a895f449439a1abbc9"
}
```

### Sample 77: `70b6b983b1d9e902`

| Field | Value |
|---|---|
| SHA-256 | `70b6b983b1d9e90206328dbdea8f044682e1be807ec6e9c71dcd0cd76f3dbe9c` |
| Family label | `unknown` |
| File name | `kbvsxhrs.exe` |
| File type | `exe` |
| First seen | `2026-09-25 02:49:42` |
| Reporter | `KnownSpotter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `162c454c5a8ec5d998119b606d234000` |
| SHA-1 | `4f396620696537410eaf6e9438c3b07ab0099d37` |
| SHA-256 | `70b6b983b1d9e90206328dbdea8f044682e1be807ec6e9c71dcd0cd76f3dbe9c` |
| SHA3-384 | `a550439ab613408f76f7290a413fd201d5698cb4cfe3d721c5564eb800119ab1583fd38c190feb6813fe50e07a763591` |
| IMPHASH | `e49e29ce20d84592766af35ef8dc02a8` |
| TLSH | `T159F42342D913D722E08FB17EC60E2F646D339C8DDC5994E605E6E6F9807B7D02D28A4B` |
| SSDEEP | `12288:GsRUMGBcCI9zmSUpz9j6sUPDM6XGlnUCprR9ZzxcS3Mnwr6YaGdMT:GRTI9zm/Z9e7DMR9YyjdM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_70b6b983
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70b6b983b1d9e90206328dbdea8f044682e1be807ec6e9c71dcd0cd76f3dbe9c"
    family = "unknown"
    file_name = "kbvsxhrs.exe"
    file_type = "exe"
    first_seen = "2026-09-25 02:49:42"
  condition:
    hash.sha256(0, filesize) == "70b6b983b1d9e90206328dbdea8f044682e1be807ec6e9c71dcd0cd76f3dbe9c"
}
```

### Sample 78: `46874f0a718001b2`

| Field | Value |
|---|---|
| SHA-256 | `46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf` |
| Family label | `unknown` |
| File name | `46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf.exe` |
| File type | `exe` |
| First seen | `2026-09-25 02:49:40` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d360a9cee93f689afb0f0a0729632d1` |
| SHA-1 | `a1ce91933eb1ee0fd057f98cb81fc6b069e2cc72` |
| SHA-256 | `46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf` |
| SHA3-384 | `77da0fca69a8c3b9dc3838b5617108285d32ff267778b363ef1b9d825447bf244108b5f48d90394660dd498deae23166` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1EEE3129037C8C62AD66ECB3D25B04941B2B6E01E07A2FDAA55E2E01E7CD071BD5507FB` |
| SSDEEP | `3072:mayAGxQO10A2bYfMSCFOR2sR+mxXQlYfSLoKkAvaLX:uvgAuoMSCFORtoRafSLoboaLX` |
| ICON-DHASH | `6944d4cccd3996ea` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_46874f0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf"
    family = "unknown"
    file_name = "46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf.exe"
    file_type = "exe"
    first_seen = "2026-09-25 02:49:40"
  condition:
    hash.sha256(0, filesize) == "46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf"
}
```

### Sample 79: `f3ab3b97e0e4d642`

| Field | Value |
|---|---|
| SHA-256 | `f3ab3b97e0e4d6429f5eba95710c398ef65fd935b619056004c2e13a84dc6a7b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-25 02:47:16` |
| Reporter | `Bitsight` |
| Tags | `1TEST.file, B, dropped-by-GCleaner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7702e5ca4bae9b15c36d087de898a870` |
| SHA-1 | `e6228a98347f713e16dcdaedb7542f410566059b` |
| SHA-256 | `f3ab3b97e0e4d6429f5eba95710c398ef65fd935b619056004c2e13a84dc6a7b` |
| SHA3-384 | `3bb13f7c9c75049d75df5542a85b00695d8f70c1062da630125c8b2b32b2fa04d0815740f26ee6c23b2bdd922ecfbf30` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1C246F918FFCF95E4C9070E3520AFB21FD6345509D239FAAAEF942E71E5A3621492760C` |
| SSDEEP | `98304:v9e7FcQP45ESKC+WbtToK3t9DC+48ogBi:mCQgexC+ytTD9oR8M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_f3ab3b97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3ab3b97e0e4d6429f5eba95710c398ef65fd935b619056004c2e13a84dc6a7b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 02:47:16"
  condition:
    hash.sha256(0, filesize) == "f3ab3b97e0e4d6429f5eba95710c398ef65fd935b619056004c2e13a84dc6a7b"
}
```

### Sample 80: `18712e078a6f5419`

| Field | Value |
|---|---|
| SHA-256 | `18712e078a6f5419ee21ddee6803395a98824021401781b51f1d08c6e1454536` |
| Family label | `Mirai` |
| File name | `stub.i386` |
| File type | `elf` |
| First seen | `2026-09-25 02:34:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01d5294dfa87690e3431dca86ec1d674` |
| SHA-1 | `56d70988e72ccd2560e277308bb3d5a4dc4df6e9` |
| SHA-256 | `18712e078a6f5419ee21ddee6803395a98824021401781b51f1d08c6e1454536` |
| SHA3-384 | `a107dfcf06dd0738ed5fc7231bd8caf862372522e8e6a2d67446386531c7a5db54f26682392b955a2368e088652cdc13` |
| TLSH | `T10F157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/m:7NP46S4QVs7l6A5Zji59k0jZz06FYRsJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_18712e07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18712e078a6f5419ee21ddee6803395a98824021401781b51f1d08c6e1454536"
    family = "Mirai"
    file_name = "stub.i386"
    file_type = "elf"
    first_seen = "2026-09-25 02:34:17"
  condition:
    hash.sha256(0, filesize) == "18712e078a6f5419ee21ddee6803395a98824021401781b51f1d08c6e1454536"
}
```

### Sample 81: `6c09b421ab2cd705`

| Field | Value |
|---|---|
| SHA-256 | `6c09b421ab2cd70554f48581c5244045d34287ca589053b353420e42981d41b2` |
| Family label | `unknown` |
| File name | `Chara.exe` |
| File type | `exe` |
| First seen | `2026-09-25 02:30:47` |
| Reporter | `KnownSpotter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee1ec487fa25c6b0440093609913e358` |
| SHA-1 | `b1484a3c42239f7ed3ecec5ab324c140df1dff71` |
| SHA-256 | `6c09b421ab2cd70554f48581c5244045d34287ca589053b353420e42981d41b2` |
| SHA3-384 | `d7e784c223928eb28462cfeed3c99709ea481b7d596484f46881f5b362b00bc992df4fa1595bc283ee2752dba3794dbf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T135247274E32A81E9F139587B5191E813BED159239CF38AD039C962B9CF6322079C1FD6` |
| SSDEEP | `1536:K0lY8QLpCjeUMvgbMJqepD2CtluqlhT7zHI5nKpa:K0lY8QVK/iggJHxXlo` |
| ICON-DHASH | `8b6cd4e0b1e8b206` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_6c09b421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c09b421ab2cd70554f48581c5244045d34287ca589053b353420e42981d41b2"
    family = "unknown"
    file_name = "Chara.exe"
    file_type = "exe"
    first_seen = "2026-09-25 02:30:47"
  condition:
    hash.sha256(0, filesize) == "6c09b421ab2cd70554f48581c5244045d34287ca589053b353420e42981d41b2"
}
```

### Sample 82: `847818db1ce56d21`

| Field | Value |
|---|---|
| SHA-256 | `847818db1ce56d2193d3a658104d396b24271eb0b96fcf398f256f2dc4e9665d` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Heur.16503.24137` |
| File type | `elf` |
| First seen | `2026-09-25 02:25:32` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `025c720515b8846ddc8f6aec3b024dae` |
| SHA-1 | `99614de67acbc05388682a1b4d6a91792be220c8` |
| SHA-256 | `847818db1ce56d2193d3a658104d396b24271eb0b96fcf398f256f2dc4e9665d` |
| SHA3-384 | `5e89967bc7a855de8c613a65961566c95949f241bcd15a0b7b539d026c5acc98dcb436373e98453f3c0c9f38998a0eae` |
| TLSH | `T190B44B66FC819B81D5D11AFEFF6E924872132B78E2EF71139914AB3427D68D60E7E100` |
| SSDEEP | `12288:YGYjUeqU5gNu7Ua/E2fkIUalapdgt1IfVp1dPLYXG:4bRUas//gaL3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_847818db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847818db1ce56d2193d3a658104d396b24271eb0b96fcf398f256f2dc4e9665d"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.16503.24137"
    file_type = "elf"
    first_seen = "2026-09-25 02:25:32"
  condition:
    hash.sha256(0, filesize) == "847818db1ce56d2193d3a658104d396b24271eb0b96fcf398f256f2dc4e9665d"
}
```

### Sample 83: `ac68824501724706`

| Field | Value |
|---|---|
| SHA-256 | `ac6882450172470660c0e0bf49258034df16e3ea4319d0e06db3845524abfb5e` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.ELF.Mirai-COW.68995338` |
| File type | `elf` |
| First seen | `2026-09-25 02:25:30` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24f131e5499bd53f96b1e1b99b7a2b2d` |
| SHA-1 | `f625d3fa376d37f1c62cb896d91276020bd1b783` |
| SHA-256 | `ac6882450172470660c0e0bf49258034df16e3ea4319d0e06db3845524abfb5e` |
| SHA3-384 | `30bb5be941ff6fc147bee35417cb26263c76413d0d837c33b27bc177ef54bc60c9c6ffee4e6e459772fa937651dc7b37` |
| TLSH | `T1CFB45A66FC409B92C2D15AFBFF9E824873172779D2EF71039A04AB3427D68D60E3A541` |
| TELFHASH | `t1dae07d220d7c078820030926d3577504b720fd76ef04b4a65e49fdfb09b18947023415` |
| SSDEEP | `12288:zUXHsEIWWhW5YlDhUAJzvSWtlaZqHzk+giGn:gXHIJW5YlDhUAJzvx3Si` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_ac688245
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac6882450172470660c0e0bf49258034df16e3ea4319d0e06db3845524abfb5e"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-COW.68995338"
    file_type = "elf"
    first_seen = "2026-09-25 02:25:30"
  condition:
    hash.sha256(0, filesize) == "ac6882450172470660c0e0bf49258034df16e3ea4319d0e06db3845524abfb5e"
}
```

### Sample 84: `7412e1b0a97ec676`

| Field | Value |
|---|---|
| SHA-256 | `7412e1b0a97ec676f20c33056b7d2b7c1566b048a2389fdeab296928fb603924` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Heur.16843.186` |
| File type | `elf` |
| First seen | `2026-09-25 02:25:29` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec27c274caccf2bf0529ea5f24ecfa0f` |
| SHA-1 | `f93c4788c1d11c8f847134d01eb7ba6cc57babee` |
| SHA-256 | `7412e1b0a97ec676f20c33056b7d2b7c1566b048a2389fdeab296928fb603924` |
| SHA3-384 | `3f34b1b2a668edc50e750e0059d0487f5e0016d74fb73404c42d0aa9f46e54f305ba0acf2defc7b8ccb60cfd16524026` |
| TLSH | `T1E8B45C2269710F17C8C490B932F34735F5BA5B8A21A886273F915E8C7F35690367A7F8` |
| SSDEEP | `6144:76vUNfEW0+VSZRARUiqtIaovJo1hcgIubjh6+ePCVLCLSb3:76vUeuVXU7tG0hcDe14P6Ceb3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_7412e1b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7412e1b0a97ec676f20c33056b7d2b7c1566b048a2389fdeab296928fb603924"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.16843.186"
    file_type = "elf"
    first_seen = "2026-09-25 02:25:29"
  condition:
    hash.sha256(0, filesize) == "7412e1b0a97ec676f20c33056b7d2b7c1566b048a2389fdeab296928fb603924"
}
```

### Sample 85: `2c5d12b34cbd21cd`

| Field | Value |
|---|---|
| SHA-256 | `2c5d12b34cbd21cd5b4f62c3e85874a8d525c9f07c5bbed5761fac20a73ea0fb` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.ELF.Mirai-COW.29885185` |
| File type | `elf` |
| First seen | `2026-09-25 02:25:27` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbf13f3e9613baa5d2e6c143763ec75c` |
| SHA-1 | `165d0ad5588a5a975c29beb77a231488dce50c8f` |
| SHA-256 | `2c5d12b34cbd21cd5b4f62c3e85874a8d525c9f07c5bbed5761fac20a73ea0fb` |
| SHA3-384 | `7fa8113406022832033f28309933cd9b824ab673eb0f8acaed19c00da8cf9da9f881b8d22594d465f29e0f08c2797789` |
| TLSH | `T1A3B44A66FC419B92C2D15AFBFF9E82487317277DD2EF71039A04AB2427D68D20E3A541` |
| TELFHASH | `t143e026714d2c468b16834aeae5af37066b38b636eac4783520492e619a534d1b1a1810` |
| SSDEEP | `12288:xs9yg76pWdgCclZ/Q0Jfv8u155BQ3bT4ZLcsKn:O9yNCgCclZ/Q0JfvL6Ps` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_2c5d12b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c5d12b34cbd21cd5b4f62c3e85874a8d525c9f07c5bbed5761fac20a73ea0fb"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-COW.29885185"
    file_type = "elf"
    first_seen = "2026-09-25 02:25:27"
  condition:
    hash.sha256(0, filesize) == "2c5d12b34cbd21cd5b4f62c3e85874a8d525c9f07c5bbed5761fac20a73ea0fb"
}
```

### Sample 86: `46a9f920cb9049c9`

| Field | Value |
|---|---|
| SHA-256 | `46a9f920cb9049c9be7bf3afba7ec13b0d0d170029363a115f429996822d4871` |
| Family label | `BlackMatter` |
| File name | `ryfiairtp.exe` |
| File type | `exe` |
| First seen | `2026-09-25 02:23:18` |
| Reporter | `KnownSpotter` |
| Tags | `BlackMatter, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99484a1e0cbad4c346d74ce218929734` |
| SHA-1 | `b6960959b5cf40cfbfa9d975477c9c2d9cc1490a` |
| SHA-256 | `46a9f920cb9049c9be7bf3afba7ec13b0d0d170029363a115f429996822d4871` |
| SHA3-384 | `66518b7974fe3a102526d22863034c1d8ca8c2a5e7fa409bc6e13c4ba725b1cc0ebe66f1a471ed51544b1be9e87517db` |
| IMPHASH | `3bc510de773c954bd69d33670cb624d6` |
| TLSH | `T1A3F37E31B112D037CA6638F1A729B3B0738A9E2C16A9A457FAD4CF4B35738236F15947` |
| SSDEEP | `3072:3DDDDDDDDDDDDDDDDDDDE45d/t6sVkgZqltP3368m3ZFd47YzMJSW:p5d/zugZqll363ZFdgYzi` |

#### Technical Assessment

- The sample is tracked as `BlackMatter` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlackMatter_086_46a9f920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46a9f920cb9049c9be7bf3afba7ec13b0d0d170029363a115f429996822d4871"
    family = "BlackMatter"
    file_name = "ryfiairtp.exe"
    file_type = "exe"
    first_seen = "2026-09-25 02:23:18"
  condition:
    hash.sha256(0, filesize) == "46a9f920cb9049c9be7bf3afba7ec13b0d0d170029363a115f429996822d4871"
}
```

### Sample 87: `33d3afddaa5710cd`

| Field | Value |
|---|---|
| SHA-256 | `33d3afddaa5710cdcc4e93a7bae8be010c19747fb53d85fcd54ef32056a1eb0b` |
| Family label | `unknown` |
| File name | `enc-linux.bak` |
| File type | `elf` |
| First seen | `2026-09-25 02:18:18` |
| Reporter | `KnownSpotter` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8957e860cb421e9c06e0fd05010cd4b` |
| SHA-1 | `9d371d77700dca0950249b8e8a1da128dbbdc719` |
| SHA-256 | `33d3afddaa5710cdcc4e93a7bae8be010c19747fb53d85fcd54ef32056a1eb0b` |
| SHA3-384 | `c2cc3e4fe4af655ac93d9ddd7274971687b17974590b2fdf48ec4dfa2d47490296900aaba0e5907731ce2b88d48fc62f` |
| TLSH | `T1A3A42B06FF9258BDC4A5C470466B9BB3A652B8D811117A3B3368FB703E3AE205F1DB51` |
| SSDEEP | `6144:+Vs3H9hrWhwSKrVf4jmR2oh7Tx0GfbvUybRvrPQ9nRZj4soyA+dp/8gf8t42mq+B:T3dRWPWEGBbtbN7oj4st04sW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_33d3afdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33d3afddaa5710cdcc4e93a7bae8be010c19747fb53d85fcd54ef32056a1eb0b"
    family = "unknown"
    file_name = "enc-linux.bak"
    file_type = "elf"
    first_seen = "2026-09-25 02:18:18"
  condition:
    hash.sha256(0, filesize) == "33d3afddaa5710cdcc4e93a7bae8be010c19747fb53d85fcd54ef32056a1eb0b"
}
```

### Sample 88: `28ea992652c200b8`

| Field | Value |
|---|---|
| SHA-256 | `28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586` |
| Family label | `Mirai` |
| File name | `28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586` |
| File type | `elf` |
| First seen | `2026-09-25 02:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76959f941f9ecedccfa3a6fd6b0b1fa3` |
| SHA-1 | `26a8a16ba0afbe847dc05fa42339c9dbcb60e163` |
| SHA-256 | `28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586` |
| SHA3-384 | `2d86927d364298c126313068790f184be6cbe9ec58b537a956585b71dcf78b2b1997e569d0e850546adac9f4b19459e7` |
| TLSH | `T1C614098AFD81AF1585C527BBFE2E418A331317B8D2EE71129D145F2877CA94F0E3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNd:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_28ea9926
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586"
    family = "Mirai"
    file_name = "28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586"
    file_type = "elf"
    first_seen = "2026-09-25 02:17:14"
  condition:
    hash.sha256(0, filesize) == "28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586"
}
```

### Sample 89: `73d519c4ccb9d3c8`

| Field | Value |
|---|---|
| SHA-256 | `73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a` |
| Family label | `unknown` |
| File name | `73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a` |
| File type | `unknown` |
| First seen | `2026-09-25 01:53:07` |
| Reporter | `theodore_brucker` |
| Tags | `cowrie, honeypot, ssh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13da53e8666f03c7201a67bd1db4f4f2` |
| SHA-256 | `73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_73d519c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a"
    family = "unknown"
    file_name = "73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a"
    file_type = "unknown"
    first_seen = "2026-09-25 01:53:07"
  condition:
    hash.sha256(0, filesize) == "73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a"
}
```

### Sample 90: `d80b949b4c3d67a3`

| Field | Value |
|---|---|
| SHA-256 | `d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35` |
| Family label | `unknown` |
| File name | `d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35` |
| File type | `sh` |
| First seen | `2026-09-25 01:53:01` |
| Reporter | `theodore_brucker` |
| Tags | `cowrie, honeypot, sh, ssh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7501dafc7ddd1767dfed9470ae4a8a34` |
| SHA-1 | `6451418dfc1b74fcd7c68987d58bc1d137ae2f40` |
| SHA-256 | `d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35` |
| SHA3-384 | `924e0978105b11ea5082991261e2ffbd6a87fb59b8ae32c04fa87687688df80843ae19b647308ddbeee4e4a33b92b3d1` |
| TLSH | `T11022A5B1BA4233F1613C40B079DA5144B39C255F27A93DB9F0AAB5B4312C3C95DFE16A` |
| SSDEEP | `192:GdF41PIJSGExDxbQBTOu0DW+JLexPldpLrfl0bAmugc8xfvCNMOjlDU1v2RiNcKH:GdWFeabqTOu0mdxeAiKlDU1uRiGf/TSN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_d80b949b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35"
    family = "unknown"
    file_name = "d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35"
    file_type = "sh"
    first_seen = "2026-09-25 01:53:01"
  condition:
    hash.sha256(0, filesize) == "d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35"
}
```

### Sample 91: `055caa239318b8cd`

| Field | Value |
|---|---|
| SHA-256 | `055caa239318b8cd8497b8631dd1b1bef1e8ba5912791c48a2a3081a8d685b1b` |
| Family label | `GCleaner` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-09-25 01:52:06` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6dc66880d7c1b2014999764b0d309d68` |
| SHA-1 | `83667598ab701a6e0902b2ac20a97083221bc264` |
| SHA-256 | `055caa239318b8cd8497b8631dd1b1bef1e8ba5912791c48a2a3081a8d685b1b` |
| SHA3-384 | `9aa094a107f367abbf07b203249b62aee2c03b5b8b30b17c9522fae7a9549748b1a7289465a2420fdfdc84256e0ee272` |
| IMPHASH | `cbfcec59e4a5b111f28e442b8b24e1eb` |
| TLSH | `T1FCE4AF62A2A0C437D16337FB8D5B92B898F6FD103D2958892EE45D4C1F3B3817966393` |
| SSDEEP | `12288:mjZZtKGfanz1BulNam0SSiR1hsCTTHaAX2hol3n7PRGvqEY:85R0PuHhzaCXHaAX1lLPEqX` |
| ICON-DHASH | `399998ecd4d46c0e` |

#### Technical Assessment

- The sample is tracked as `GCleaner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GCleaner_091_055caa23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "055caa239318b8cd8497b8631dd1b1bef1e8ba5912791c48a2a3081a8d685b1b"
    family = "GCleaner"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-09-25 01:52:06"
  condition:
    hash.sha256(0, filesize) == "055caa239318b8cd8497b8631dd1b1bef1e8ba5912791c48a2a3081a8d685b1b"
}
```

### Sample 92: `23b2d67b756bfaae`

| Field | Value |
|---|---|
| SHA-256 | `23b2d67b756bfaae680f07784ba229676a1e054da6fbb39053443a4485aeb76b` |
| Family label | `Mirai` |
| File name | `tpijtvcr.aarch64` |
| File type | `elf` |
| First seen | `2026-09-25 01:29:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `009efb29760f595074928603ef390398` |
| SHA-1 | `f056d481b9841102439d26f1e9240071a9cde6c7` |
| SHA-256 | `23b2d67b756bfaae680f07784ba229676a1e054da6fbb39053443a4485aeb76b` |
| SHA3-384 | `966010285b5781f6b387454a7eefe052bfa6c3864bf47ed83467f3d27eae4982c0a10881ae5e748e6cb8206514fd25f4` |
| TLSH | `T149456C5DFD0F3D43C2CAE23DDB8A83E47127B098D62311A335C2035DE689D9D8B9695A` |
| TELFHASH | `t149a012020880810c0177ab114c95034910414833e81a3d551e0cda400410008034886a` |
| SSDEEP | `24576:PJd+qmvKQJwA6sT4VPEIYPXumdLrAGDF6ShnN2g/Hq1:BjmtwHuBvhl6ShnNzq1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_23b2d67b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23b2d67b756bfaae680f07784ba229676a1e054da6fbb39053443a4485aeb76b"
    family = "Mirai"
    file_name = "tpijtvcr.aarch64"
    file_type = "elf"
    first_seen = "2026-09-25 01:29:25"
  condition:
    hash.sha256(0, filesize) == "23b2d67b756bfaae680f07784ba229676a1e054da6fbb39053443a4485aeb76b"
}
```

### Sample 93: `cb6fdabd9a3c19f8`

| Field | Value |
|---|---|
| SHA-256 | `cb6fdabd9a3c19f8004d18fb0259ac89a01ce6e0b5cb4b6b8d8179bb6c3f81ea` |
| Family label | `Mirai` |
| File name | `ooikocqj.armv7` |
| File type | `elf` |
| First seen | `2026-09-25 01:20:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e22db8abb7bf1e518b2ba6cb0e8b0dc` |
| SHA-1 | `e5c1e26b8fce7e3494c220727b0c615ba988cf6d` |
| SHA-256 | `cb6fdabd9a3c19f8004d18fb0259ac89a01ce6e0b5cb4b6b8d8179bb6c3f81ea` |
| SHA3-384 | `f27b18cadea7ea8790416a6c79f6e4e2fda19bb1a9827e4a57de8db113b2e8facbc5fa85260c56653180342110e7dd81` |
| TLSH | `T19B254B54F890DF63C5D46B7AF65E82A833234778C3E7720699148B383B97A1F0B3A645` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:z0gA64PSUSH5h6omxnWPG7657hx/hGnJe:KccWu7657hxAJe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_cb6fdabd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb6fdabd9a3c19f8004d18fb0259ac89a01ce6e0b5cb4b6b8d8179bb6c3f81ea"
    family = "Mirai"
    file_name = "ooikocqj.armv7"
    file_type = "elf"
    first_seen = "2026-09-25 01:20:15"
  condition:
    hash.sha256(0, filesize) == "cb6fdabd9a3c19f8004d18fb0259ac89a01ce6e0b5cb4b6b8d8179bb6c3f81ea"
}
```

### Sample 94: `45ec4b84069887b7`

| Field | Value |
|---|---|
| SHA-256 | `45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40` |
| Family label | `Mirai` |
| File name | `45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40` |
| File type | `elf` |
| First seen | `2026-09-25 01:17:15` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78ad2772a41eac39a300aaca4045fa31` |
| SHA-1 | `0b54ff2bd984df3112b5c0133c1f23cfb531f64a` |
| SHA-256 | `45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40` |
| SHA3-384 | `e29a4ffa05116347dd84f9634f3c0d607e2b7149feb7ae08c465f9d202c7fa8994b12b7b37042952aa48909c4575350b` |
| TLSH | `T1E044398AFD80AF25D5C5267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ4:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_45ec4b84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40"
    family = "Mirai"
    file_name = "45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40"
    file_type = "elf"
    first_seen = "2026-09-25 01:17:15"
  condition:
    hash.sha256(0, filesize) == "45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40"
}
```

### Sample 95: `9ede0ecea5cbb266`

| Field | Value |
|---|---|
| SHA-256 | `9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578` |
| Family label | `unknown` |
| File name | `9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578.exe` |
| File type | `exe` |
| First seen | `2026-09-25 01:10:37` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `485353634eb0c2fb25b5c2c2e2689ad9` |
| SHA-1 | `6e2876f470ceef46b4e40bbe1165debf3dde9dd3` |
| SHA-256 | `9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578` |
| SHA3-384 | `1915caf2fdf5bc7b1231780045b87ac506bc4d9e30666e2537499c35b430e45fc75dab3e7aeff782b2a424a891179237` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T11F5533606352EC7BF19714369EB60BB55EFAB5F806D4A30303326C2D9C67620B4DE2B5` |
| SSDEEP | `24576:A4hadK+pK+eMu2FJ0TLQWoFy5yqT+wAwqKOztKNOmiB28twY/bYNki9pnaB:t08M1FJ0W4AptbDB28twibYNki9paB` |
| ICON-DHASH | `c4dadadad2f492c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_9ede0ece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578"
    family = "unknown"
    file_name = "9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578.exe"
    file_type = "exe"
    first_seen = "2026-09-25 01:10:37"
  condition:
    hash.sha256(0, filesize) == "9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578"
}
```

### Sample 96: `53bd728fc37bb1ad`

| Field | Value |
|---|---|
| SHA-256 | `53bd728fc37bb1adeaf907f8cf683e08d37304af2eb62626613f93dfc9b256ea` |
| Family label | `Mirai` |
| File name | `cwlfkwnt.mips` |
| File type | `elf` |
| First seen | `2026-09-25 01:10:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8fe38b2d4809774eee93fe94488d941` |
| SHA-1 | `be64ed45a69960c4b9a1d1367ed3f7400d7f4d82` |
| SHA-256 | `53bd728fc37bb1adeaf907f8cf683e08d37304af2eb62626613f93dfc9b256ea` |
| SHA3-384 | `a8d0fbad4e20ef7787f98e6223e2a54cb79975fbf0571357a857d96be24b5b7c5998dfed69be22a7fccfba83bf6a4f44` |
| TLSH | `T1FD356C633F11CF65E354D67048F3CA517A9920A31AF24095B26CC3283E61B6E6D9FEE4` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:PlFEDSkNOw3a41QCCmOdmmcpiMKYJNp7xTWnOKW8w:PlFEzE41QZmOUKsNJxTWnzw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_53bd728f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53bd728fc37bb1adeaf907f8cf683e08d37304af2eb62626613f93dfc9b256ea"
    family = "Mirai"
    file_name = "cwlfkwnt.mips"
    file_type = "elf"
    first_seen = "2026-09-25 01:10:34"
  condition:
    hash.sha256(0, filesize) == "53bd728fc37bb1adeaf907f8cf683e08d37304af2eb62626613f93dfc9b256ea"
}
```

### Sample 97: `4b72c66c002d60b9`

| Field | Value |
|---|---|
| SHA-256 | `4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919` |
| Family label | `unknown` |
| File name | `4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919.exe` |
| File type | `exe` |
| First seen | `2026-09-25 01:10:33` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c8ef3853cf34c4df175824870035c93` |
| SHA-1 | `4522f923277b1390e89ad5e5d564b2e8a188d477` |
| SHA-256 | `4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919` |
| SHA3-384 | `7a6f0da6ea9452ee41df12ab1ff71c1f55966f2924364d2bae7af35f16f79f12e2eafa6f8e79d7f0289460b414d0f875` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T177C5E13BB28B653EE06E5A357A72E220553B7B6169128C0796F4C84CDF361701E3F687` |
| SSDEEP | `49152:noLEI3TT+7cPHARppa7A+nqDrOp512ycM1MYnrZiBO6sz:oLE0Tww4pKFnqDrk12mTnrZiBOZ` |
| ICON-DHASH | `f0aa3bb2a2d469b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_4b72c66c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919"
    family = "unknown"
    file_name = "4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919.exe"
    file_type = "exe"
    first_seen = "2026-09-25 01:10:33"
  condition:
    hash.sha256(0, filesize) == "4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919"
}
```

### Sample 98: `2a7dc1fefb391e33`

| Field | Value |
|---|---|
| SHA-256 | `2a7dc1fefb391e333a9aef1690a66d7106046f2377fb4e81fbf2548539e9fe3e` |
| Family label | `Mirai` |
| File name | `cwlfkwnt.armv8` |
| File type | `elf` |
| First seen | `2026-09-25 01:10:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7592bbf758b05cef1134edbc1bd29f6a` |
| SHA-1 | `20d1c15a4b2fa732fb879936da1ac855f63f386e` |
| SHA-256 | `2a7dc1fefb391e333a9aef1690a66d7106046f2377fb4e81fbf2548539e9fe3e` |
| SHA3-384 | `067ab8ffb56f5b5a97588aad7e6bd7cc66a970270a0c4192f5ddb10443eb339eab010accc26aa4f83468467424b29bbb` |
| TLSH | `T1E8456C5DFD0F3D43C2CAE23DDB8A83E47127B098D62311A335C2035DE689D9D8B9695A` |
| TELFHASH | `t149a012020880810c0177ab114c95034910414833e81a3d551e0cda400410008034886a` |
| SSDEEP | `24576:PJd+qmvKQJwA6sT4VPEdYPXumdLrAGDF6ShnN2g/HqM:BjmtwHuqvhl6ShnNzqM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_2a7dc1fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a7dc1fefb391e333a9aef1690a66d7106046f2377fb4e81fbf2548539e9fe3e"
    family = "Mirai"
    file_name = "cwlfkwnt.armv8"
    file_type = "elf"
    first_seen = "2026-09-25 01:10:32"
  condition:
    hash.sha256(0, filesize) == "2a7dc1fefb391e333a9aef1690a66d7106046f2377fb4e81fbf2548539e9fe3e"
}
```

### Sample 99: `5fe8e459e8cd447c`

| Field | Value |
|---|---|
| SHA-256 | `5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3` |
| Family label | `unknown` |
| File name | `5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3.exe` |
| File type | `exe` |
| First seen | `2026-09-25 01:10:28` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ed3e856b36863e1557090f09dc7317f` |
| SHA-1 | `6c473056de8b13360299f489b332e9bd70fb9c36` |
| SHA-256 | `5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3` |
| SHA3-384 | `16c84d536c4b0dcf2edfaaccaa7b3d6efa35a5ff8e7fcdbcf7de8748c45c711e2218d63b13c709ce7274e1ca1535bb1a` |
| IMPHASH | `d5b1104f7bf955d6b89a47291d5b603b` |
| TLSH | `T17307339877854DA4F8FB423CA5C48E22A2B1B5242BA5D7BF0BF10D121D672D4DF387A1` |
| SSDEEP | `393216:J0L1F2pBgIfUKOc0XEAphVtnIwQSg+nFoIykzx8xvZ7X2r:CpspB58KP0RphDBo+FoIygx+vZ7` |
| ICON-DHASH | `aebc385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_5fe8e459
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3"
    family = "unknown"
    file_name = "5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3.exe"
    file_type = "exe"
    first_seen = "2026-09-25 01:10:28"
  condition:
    hash.sha256(0, filesize) == "5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3"
}
```

### Sample 100: `42e644a584b9a912`

| Field | Value |
|---|---|
| SHA-256 | `42e644a584b9a91261f406f15c63ae45288eea0557667897ae517bd4e9e37ff4` |
| Family label | `Mirai` |
| File name | `qzxuuppn.i486` |
| File type | `elf` |
| First seen | `2026-09-25 00:51:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f0bab4fd855837100ed989361d57d21` |
| SHA-1 | `2f4a3f2d15cad0f77aa361043b75f684bf0f1507` |
| SHA-256 | `42e644a584b9a91261f406f15c63ae45288eea0557667897ae517bd4e9e37ff4` |
| SHA3-384 | `25bc38770797cd6d463460610e6e6cd0c1b732a3f711378f8286d908c2fb75e5f7374f28a3e84cea896f7c117705a901` |
| TLSH | `T13B355C5BB2A374BCC157C830879BDA72AD35B46502227E7BB5C4DA302E26E701719F72` |
| TELFHASH | `t12be1a0714ef974b4e6e2d910f362f0b5a973192276fd36e41622ad44ef44f804ca386b` |
| SSDEEP | `24576:PCwAF37u146rWkLzeFe8vpXGTmhnscsn1y+vEIWF0:O5Q46rieMGpcm1y+8I80` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_42e644a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42e644a584b9a91261f406f15c63ae45288eea0557667897ae517bd4e9e37ff4"
    family = "Mirai"
    file_name = "qzxuuppn.i486"
    file_type = "elf"
    first_seen = "2026-09-25 00:51:36"
  condition:
    hash.sha256(0, filesize) == "42e644a584b9a91261f406f15c63ae45288eea0557667897ae517bd4e9e37ff4"
}
```


## Combined YARA Rules

These rules are exact SHA-256 sample indicators. They are useful for known-sample matching, not for detecting variants or inferring behavior. Broader YARA coverage requires static features from source code or file bytes.

```yara
import "hash"

/*
 * MalwareBazaar exact-hash YARA indicators.
 * Generated from metadata only; samples were not executed.
 * Selector: 100
 * Generated: 2026-09-25T05:05:01.795127+00:00
 */

rule MalwareBazaar_Mirai_001_b51bfb4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b51bfb4f6afbf2bb8f7f10a25cd40456b63866a92f0b745b2e2d245e6834e4a3"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:38"
  condition:
    hash.sha256(0, filesize) == "b51bfb4f6afbf2bb8f7f10a25cd40456b63866a92f0b745b2e2d245e6834e4a3"
}

rule MalwareBazaar_Mirai_002_f3c90a76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3c90a768b74b19fe48f8f26449e605137d22739d151d15ecbe4c5e399a70aea"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:36"
  condition:
    hash.sha256(0, filesize) == "f3c90a768b74b19fe48f8f26449e605137d22739d151d15ecbe4c5e399a70aea"
}

rule MalwareBazaar_Mirai_003_d18b4c9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d18b4c9e0fe9fe36a84bc787cc1b7a378fe4aab8aa4a71e370f35f515b6d4ec8"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:12"
  condition:
    hash.sha256(0, filesize) == "d18b4c9e0fe9fe36a84bc787cc1b7a378fe4aab8aa4a71e370f35f515b6d4ec8"
}

rule MalwareBazaar_unknown_004_968d6684
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "968d6684b22dd9b4b39f9e4e376c194c6f95a318850cd703300acdcefd96596e"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:11"
  condition:
    hash.sha256(0, filesize) == "968d6684b22dd9b4b39f9e4e376c194c6f95a318850cd703300acdcefd96596e"
}

rule MalwareBazaar_Mirai_005_f10c00d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f10c00d90bdc9326b6f7f2adec8821e94df9888fe3c8d493881bd17ae90455f4"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:09"
  condition:
    hash.sha256(0, filesize) == "f10c00d90bdc9326b6f7f2adec8821e94df9888fe3c8d493881bd17ae90455f4"
}

rule MalwareBazaar_Mirai_006_6dd0443f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dd0443fc8902fcd9daa12d3de222a4c8d2976e1bf44f1d6608c956af810740f"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:07"
  condition:
    hash.sha256(0, filesize) == "6dd0443fc8902fcd9daa12d3de222a4c8d2976e1bf44f1d6608c956af810740f"
}

rule MalwareBazaar_Mirai_007_3dbba071
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dbba0713091675bf142e8ff9ef92a5eee1732eae2af19ce65585b7616a670ac"
    family = "Mirai"
    file_name = "bot.mips64"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:05"
  condition:
    hash.sha256(0, filesize) == "3dbba0713091675bf142e8ff9ef92a5eee1732eae2af19ce65585b7616a670ac"
}

rule MalwareBazaar_Mirai_008_1fef7558
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fef7558f389cb04087b9804dc9e47a338bda903ca546e7d7680cbfa2d5e8251"
    family = "Mirai"
    file_name = "stub.aarch64"
    file_type = "elf"
    first_seen = "2026-09-25 05:00:02"
  condition:
    hash.sha256(0, filesize) == "1fef7558f389cb04087b9804dc9e47a338bda903ca546e7d7680cbfa2d5e8251"
}

rule MalwareBazaar_unknown_009_66da8ab5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66da8ab5528e3461a0c44c8925c33c0b1f56eb153b645d78964f8dec8b520242"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 04:52:01"
  condition:
    hash.sha256(0, filesize) == "66da8ab5528e3461a0c44c8925c33c0b1f56eb153b645d78964f8dec8b520242"
}

rule MalwareBazaar_Mirai_010_94bc2ca3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94bc2ca34571d711e5ae1ae30b07a59207d653e16e89abf6558c60d6e43453d8"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:23"
  condition:
    hash.sha256(0, filesize) == "94bc2ca34571d711e5ae1ae30b07a59207d653e16e89abf6558c60d6e43453d8"
}

rule MalwareBazaar_Mirai_011_da4cf25c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da4cf25c21b3ae8bdce987e0ac09451bd5e9c93bd3c11801a1f4d888f699898c"
    family = "Mirai"
    file_name = "stub.i386"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:21"
  condition:
    hash.sha256(0, filesize) == "da4cf25c21b3ae8bdce987e0ac09451bd5e9c93bd3c11801a1f4d888f699898c"
}

rule MalwareBazaar_Mirai_012_f6052038
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6052038a49e3f6a34c5008d83d7863c6080dc26ab8a9a2f6ccf569df6a008fc"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:19"
  condition:
    hash.sha256(0, filesize) == "f6052038a49e3f6a34c5008d83d7863c6080dc26ab8a9a2f6ccf569df6a008fc"
}

rule MalwareBazaar_Mirai_013_e2b9601d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2b9601d09ff795cf4d070cd3f308ddbe03a28330cf40559abe4faae28948b95"
    family = "Mirai"
    file_name = "bot.mips64el"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:18"
  condition:
    hash.sha256(0, filesize) == "e2b9601d09ff795cf4d070cd3f308ddbe03a28330cf40559abe4faae28948b95"
}

rule MalwareBazaar_Mirai_014_f042aa22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f042aa22cee4379db0bc57e190f3384e0fe95d5ec15406ada2ea39f0b2e53244"
    family = "Mirai"
    file_name = "stub.mipsel"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:16"
  condition:
    hash.sha256(0, filesize) == "f042aa22cee4379db0bc57e190f3384e0fe95d5ec15406ada2ea39f0b2e53244"
}

rule MalwareBazaar_Mirai_015_1a2d9550
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a2d9550172a6c94e7296a27e1faa3e884a3dc4881207e66864e21fd85f51aa3"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:14"
  condition:
    hash.sha256(0, filesize) == "1a2d9550172a6c94e7296a27e1faa3e884a3dc4881207e66864e21fd85f51aa3"
}

rule MalwareBazaar_Mirai_016_7ca90a10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ca90a1040b5ce49ff84075f63196acd92e6ce1929921c482d30e4385d89a602"
    family = "Mirai"
    file_name = "stub.i486"
    file_type = "elf"
    first_seen = "2026-09-25 04:51:13"
  condition:
    hash.sha256(0, filesize) == "7ca90a1040b5ce49ff84075f63196acd92e6ce1929921c482d30e4385d89a602"
}

rule MalwareBazaar_Mirai_017_b43c73b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b43c73b5fa1fa005798316d25fa6adfc532d8a1c2e4b307ef9a8032003c5de6c"
    family = "Mirai"
    file_name = "bot.i386"
    file_type = "elf"
    first_seen = "2026-09-25 04:42:18"
  condition:
    hash.sha256(0, filesize) == "b43c73b5fa1fa005798316d25fa6adfc532d8a1c2e4b307ef9a8032003c5de6c"
}

rule MalwareBazaar_Mirai_018_ddb73c80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddb73c805e2f965512affd129db044f127f90d3b164e14b6e68332a28ca10c5d"
    family = "Mirai"
    file_name = "stub.armv7l"
    file_type = "elf"
    first_seen = "2026-09-25 04:42:16"
  condition:
    hash.sha256(0, filesize) == "ddb73c805e2f965512affd129db044f127f90d3b164e14b6e68332a28ca10c5d"
}

rule MalwareBazaar_Mirai_019_88367ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88367ddc6e0629c037643b2bd6002345ea95cd763072ebc308d21bf8de7eab7e"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-25 04:42:14"
  condition:
    hash.sha256(0, filesize) == "88367ddc6e0629c037643b2bd6002345ea95cd763072ebc308d21bf8de7eab7e"
}

rule MalwareBazaar_Mirai_020_3a7bf6f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a7bf6f11d972b034f44222b21fad10de8ac30d197ee406f027e4fe38951f245"
    family = "Mirai"
    file_name = "bot.mpsl"
    file_type = "elf"
    first_seen = "2026-09-25 04:42:12"
  condition:
    hash.sha256(0, filesize) == "3a7bf6f11d972b034f44222b21fad10de8ac30d197ee406f027e4fe38951f245"
}

rule MalwareBazaar_Mirai_021_e0799c11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0799c11ec678995785494127ed3aedfd5624bc202600a0897d740f368356e50"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.29680.227"
    file_type = "elf"
    first_seen = "2026-09-25 04:36:26"
  condition:
    hash.sha256(0, filesize) == "e0799c11ec678995785494127ed3aedfd5624bc202600a0897d740f368356e50"
}

rule MalwareBazaar_Mirai_022_24537652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "245376523422a056afd0b406024a91e1f56bf74e99286db383715cb692201cac"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.15762.20913"
    file_type = "elf"
    first_seen = "2026-09-25 04:36:23"
  condition:
    hash.sha256(0, filesize) == "245376523422a056afd0b406024a91e1f56bf74e99286db383715cb692201cac"
}

rule MalwareBazaar_Mirai_023_7372dcdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7372dcdb3ca9623b3d77d5ee8bbab01a3406dca9beaab76e8166dc17e57ac8f6"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:18"
  condition:
    hash.sha256(0, filesize) == "7372dcdb3ca9623b3d77d5ee8bbab01a3406dca9beaab76e8166dc17e57ac8f6"
}

rule MalwareBazaar_Mirai_024_5ea82ca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ea82ca14a7caef36f86b34c28b856d5b19312b2b5a0983c653babecfbfcb98c"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:16"
  condition:
    hash.sha256(0, filesize) == "5ea82ca14a7caef36f86b34c28b856d5b19312b2b5a0983c653babecfbfcb98c"
}

rule MalwareBazaar_Mirai_025_1399adc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1399adc6c631adcafd569914690f9a0b3b19c67c8134f0ece43527e6feb3daa0"
    family = "Mirai"
    file_name = "bot.i486"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:15"
  condition:
    hash.sha256(0, filesize) == "1399adc6c631adcafd569914690f9a0b3b19c67c8134f0ece43527e6feb3daa0"
}

rule MalwareBazaar_Mirai_026_3e326c40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e326c40e2eb5f43e9d369afc9d486ae1038a909e56b9cd0cf7d13a811894803"
    family = "Mirai"
    file_name = "stub.x86_64"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:13"
  condition:
    hash.sha256(0, filesize) == "3e326c40e2eb5f43e9d369afc9d486ae1038a909e56b9cd0cf7d13a811894803"
}

rule MalwareBazaar_Mirai_027_11abfeb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11abfeb045732990eba6c2c164943f6874095278369e4fb7dec82f44dc3c8f77"
    family = "Mirai"
    file_name = "stub.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:11"
  condition:
    hash.sha256(0, filesize) == "11abfeb045732990eba6c2c164943f6874095278369e4fb7dec82f44dc3c8f77"
}

rule MalwareBazaar_unknown_028_47d0b178
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47d0b1785f854dd45302fd203bbafb5c7a98892a906078fe0c2d944177eec4e6"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-09-25 04:33:09"
  condition:
    hash.sha256(0, filesize) == "47d0b1785f854dd45302fd203bbafb5c7a98892a906078fe0c2d944177eec4e6"
}

rule MalwareBazaar_Mirai_029_6e0ff2e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e0ff2e91da2d190f0126a1da03a4a165e4641cdff432c2cdcf18382a2fee153"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:08"
  condition:
    hash.sha256(0, filesize) == "6e0ff2e91da2d190f0126a1da03a4a165e4641cdff432c2cdcf18382a2fee153"
}

rule MalwareBazaar_unknown_030_64e6b0c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001"
    family = "unknown"
    file_name = "64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001.elf"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:07"
  condition:
    hash.sha256(0, filesize) == "64e6b0c589b5864967dfbe79eca6c4d984961f36bc70f7a9e14955ed24f6d001"
}

rule MalwareBazaar_Mirai_031_049d3785
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049d378589c22ac33d5c62f3d74d6294e972db699a7eb0581857fe9c099f1b64"
    family = "Mirai"
    file_name = "stub.x64"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:06"
  condition:
    hash.sha256(0, filesize) == "049d378589c22ac33d5c62f3d74d6294e972db699a7eb0581857fe9c099f1b64"
}

rule MalwareBazaar_Mirai_032_f383a4b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f383a4b24a8af5f3611abe94ffb9091812f8f82faf90d5b3829eba31d0e295c4"
    family = "Mirai"
    file_name = "stub.armv6l"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:04"
  condition:
    hash.sha256(0, filesize) == "f383a4b24a8af5f3611abe94ffb9091812f8f82faf90d5b3829eba31d0e295c4"
}

rule MalwareBazaar_Mirai_033_5d5b1e26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d5b1e26d0914ed0e176bcbe86ba2851c237b70fcb9e14463208aa3c8a5a9725"
    family = "Mirai"
    file_name = "bot.armv7l"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:02"
  condition:
    hash.sha256(0, filesize) == "5d5b1e26d0914ed0e176bcbe86ba2851c237b70fcb9e14463208aa3c8a5a9725"
}

rule MalwareBazaar_Mirai_034_869833e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "869833e828f250799f7e78f210242f2a240f2aaf4648f61911c7c6dd738f3378"
    family = "Mirai"
    file_name = "bot.arm7n"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:00"
  condition:
    hash.sha256(0, filesize) == "869833e828f250799f7e78f210242f2a240f2aaf4648f61911c7c6dd738f3378"
}

rule MalwareBazaar_unknown_035_2a3b30f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b"
    family = "unknown"
    file_name = "2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b.elf"
    file_type = "elf"
    first_seen = "2026-09-25 04:33:00"
  condition:
    hash.sha256(0, filesize) == "2a3b30f3e5a7a8d8c001fa2cfa451154a2a98110c6006a8d09178167f2ab138b"
}

rule MalwareBazaar_unknown_036_3dd9ac71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8"
    family = "unknown"
    file_name = "3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8.elf"
    file_type = "elf"
    first_seen = "2026-09-25 04:32:53"
  condition:
    hash.sha256(0, filesize) == "3dd9ac7194cfdd4376196ffbb7b2c608ea11fc80ba1672dda6529109ecdf55e8"
}

rule MalwareBazaar_Mirai_037_032cf5ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "032cf5ab06d8bf4bd324765b3179c4ab28eea7c8c949e8cf60044937d3e1cc7f"
    family = "Mirai"
    file_name = "stub.armv7"
    file_type = "elf"
    first_seen = "2026-09-25 04:23:56"
  condition:
    hash.sha256(0, filesize) == "032cf5ab06d8bf4bd324765b3179c4ab28eea7c8c949e8cf60044937d3e1cc7f"
}

rule MalwareBazaar_unknown_038_5521e5e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5521e5e983dab5cd88bade12170967f0b85ea80829eeeed02cd84f9db979ddb4"
    family = "unknown"
    file_name = "payload.bin.malware"
    file_type = "exe"
    first_seen = "2026-09-25 04:21:33"
  condition:
    hash.sha256(0, filesize) == "5521e5e983dab5cd88bade12170967f0b85ea80829eeeed02cd84f9db979ddb4"
}

rule MalwareBazaar_Mirai_039_6d597ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507"
    family = "Mirai"
    file_name = "6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507"
    file_type = "elf"
    first_seen = "2026-09-25 04:18:50"
  condition:
    hash.sha256(0, filesize) == "6d597ae1b707b6d0b1afda261f4bb99502940d70168d614d6af82ec088628507"
}

rule MalwareBazaar_unknown_040_2d2fdfc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21"
    family = "unknown"
    file_name = "2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21.bin"
    file_type = "zip"
    first_seen = "2026-09-25 04:15:02"
  condition:
    hash.sha256(0, filesize) == "2d2fdfc7b1dd18dfa690ca08b5e738ed3760866d5be2109915c4445502eedd21"
}

rule MalwareBazaar_VShell_041_b6307cb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8"
    family = "VShell"
    file_name = "b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8.exe"
    file_type = "exe"
    first_seen = "2026-09-25 04:09:51"
  condition:
    hash.sha256(0, filesize) == "b6307cb3e0da1b5393cc002bdc02458d2a2604be5f12d184965f807e0d4415a8"
}

rule MalwareBazaar_unknown_042_4131c88b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4131c88b0dea6ba45cd633eed383240d41620e4467afa4e956d6c2dfafd58c1c"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-09-25 04:06:37"
  condition:
    hash.sha256(0, filesize) == "4131c88b0dea6ba45cd633eed383240d41620e4467afa4e956d6c2dfafd58c1c"
}

rule MalwareBazaar_VShell_043_6cf2e852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a"
    family = "VShell"
    file_name = "6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a.exe"
    file_type = "exe"
    first_seen = "2026-09-25 04:04:45"
  condition:
    hash.sha256(0, filesize) == "6cf2e852833668a207b89b003ebbb7ccddef6d1d892fb2f592e0b03154fae39a"
}

rule MalwareBazaar_VShell_044_16db4b5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698"
    family = "VShell"
    file_name = "16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:59:30"
  condition:
    hash.sha256(0, filesize) == "16db4b5aefca60a0f98d0aae888bdafd813a8a5f37fd2264b1667ec4f11b0698"
}

rule MalwareBazaar_unknown_045_b78a29ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b78a29eab41dc72b66375a7d9a8fad8d5942bfe3be9bed26a8bc9a0287c446e0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 03:59:19"
  condition:
    hash.sha256(0, filesize) == "b78a29eab41dc72b66375a7d9a8fad8d5942bfe3be9bed26a8bc9a0287c446e0"
}

rule MalwareBazaar_unknown_046_32aaa1d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32aaa1d07dc07217223009ad404925c5b518907e3b6c8aad1c2250e9f9dc54aa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 03:58:42"
  condition:
    hash.sha256(0, filesize) == "32aaa1d07dc07217223009ad404925c5b518907e3b6c8aad1c2250e9f9dc54aa"
}

rule MalwareBazaar_RustyStealer_047_d3e5d5e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3e5d5e5289c2e39e12dc91a4e286faf64812bf68c83c1f37e88b2fac79d105c"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 03:48:07"
  condition:
    hash.sha256(0, filesize) == "d3e5d5e5289c2e39e12dc91a4e286faf64812bf68c83c1f37e88b2fac79d105c"
}

rule MalwareBazaar_Mirai_048_db74e870
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db74e8707f2dd7fe3819ce7ac210299191f7936dde7ae59a647dfdb9c8e44ea3"
    family = "Mirai"
    file_name = "cwlfkwnt.arm"
    file_type = "elf"
    first_seen = "2026-09-25 03:47:19"
  condition:
    hash.sha256(0, filesize) == "db74e8707f2dd7fe3819ce7ac210299191f7936dde7ae59a647dfdb9c8e44ea3"
}

rule MalwareBazaar_Mirai_049_5103d28c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5103d28c77c07c46450180d80c78de6346c580ea63f2dde2cdb9163ec53495d3"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-09-25 03:47:18"
  condition:
    hash.sha256(0, filesize) == "5103d28c77c07c46450180d80c78de6346c580ea63f2dde2cdb9163ec53495d3"
}

rule MalwareBazaar_Mirai_050_2b6c2e6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b6c2e6c2ef7396f6dca3183fb894ff41b3180bac8d9746c124de7b4ef3575a0"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-COW.41418858"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:13"
  condition:
    hash.sha256(0, filesize) == "2b6c2e6c2ef7396f6dca3183fb894ff41b3180bac8d9746c124de7b4ef3575a0"
}

rule MalwareBazaar_Mirai_051_5b7e6286
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b7e6286c02ededd19289332860e76ed053797d7f31d4be7806a2ac6f3e58694"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.21131.6862"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:12"
  condition:
    hash.sha256(0, filesize) == "5b7e6286c02ededd19289332860e76ed053797d7f31d4be7806a2ac6f3e58694"
}

rule MalwareBazaar_Mirai_052_27c593a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27c593a40a437810124f2f43a9d67365f1b91a3f52ab64e44d0f5b120ca78136"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-COW.97552716"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:09"
  condition:
    hash.sha256(0, filesize) == "27c593a40a437810124f2f43a9d67365f1b91a3f52ab64e44d0f5b120ca78136"
}

rule MalwareBazaar_Mirai_053_1d55613d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d55613d5c924ace53b733096a9ffe3c22c3f703f8abc4b18e55e1f75dd9f3d5"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.8161.10136"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:07"
  condition:
    hash.sha256(0, filesize) == "1d55613d5c924ace53b733096a9ffe3c22c3f703f8abc4b18e55e1f75dd9f3d5"
}

rule MalwareBazaar_Mirai_054_a965431e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a965431e4a881f482e7e71d6f6e52c5c7ab05ce75e656869558c194d167bb5bf"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.23741.18903"
    file_type = "elf"
    first_seen = "2026-09-25 03:44:05"
  condition:
    hash.sha256(0, filesize) == "a965431e4a881f482e7e71d6f6e52c5c7ab05ce75e656869558c194d167bb5bf"
}

rule MalwareBazaar_Mirai_055_3ef85807
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3"
    family = "Mirai"
    file_name = "3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3"
    file_type = "elf"
    first_seen = "2026-09-25 03:17:28"
  condition:
    hash.sha256(0, filesize) == "3ef8580795f9e384a5c457cdd136c7b163fd03ce37f0e7d2961e1065aec52ed3"
}

rule MalwareBazaar_unknown_056_bd01d8df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd01d8dfcb86adbaaecf212506e71d5207715f3e92316cda3f7ac41910022217"
    family = "unknown"
    file_name = "created-wp.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:58"
  condition:
    hash.sha256(0, filesize) == "bd01d8dfcb86adbaaecf212506e71d5207715f3e92316cda3f7ac41910022217"
}

rule MalwareBazaar_unknown_057_12942bba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12942bba4b7c24f3c9b37d972caea2d769c1882375faf5dc4b265a5dacdd63b3"
    family = "unknown"
    file_name = "belom-ready.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:52"
  condition:
    hash.sha256(0, filesize) == "12942bba4b7c24f3c9b37d972caea2d769c1882375faf5dc4b265a5dacdd63b3"
}

rule MalwareBazaar_unknown_058_9b74712f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b74712f8e5a46e0f9718bf6da01590a033d95da66c6f6a7b3d34fd8a3a385b9"
    family = "unknown"
    file_name = "anore-r2-stage2.php"
    file_type = "php"
    first_seen = "2026-09-25 03:14:48"
  condition:
    hash.sha256(0, filesize) == "9b74712f8e5a46e0f9718bf6da01590a033d95da66c6f6a7b3d34fd8a3a385b9"
}

rule MalwareBazaar_unknown_059_d521dc2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d521dc2da106ed44368a65f51095782f9d8e595305e773572a36d4e0b8bf6b46"
    family = "unknown"
    file_name = "anore.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:42"
  condition:
    hash.sha256(0, filesize) == "d521dc2da106ed44368a65f51095782f9d8e595305e773572a36d4e0b8bf6b46"
}

rule MalwareBazaar_unknown_060_f45333b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f45333b26481e36be1dc306f8630b6126c42e4a1cbbe024e2b286a580952f9b1"
    family = "unknown"
    file_name = "a.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:37"
  condition:
    hash.sha256(0, filesize) == "f45333b26481e36be1dc306f8630b6126c42e4a1cbbe024e2b286a580952f9b1"
}

rule MalwareBazaar_unknown_061_b7f0d6a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f0d6a31daac70c443ecdce04417b32002bcb7537ffc5f22f641dcea581c2b3"
    family = "unknown"
    file_name = "sora.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:32"
  condition:
    hash.sha256(0, filesize) == "b7f0d6a31daac70c443ecdce04417b32002bcb7537ffc5f22f641dcea581c2b3"
}

rule MalwareBazaar_unknown_062_7f800bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f800bdb0cbc945b8f59789e7276852f7ab4822f87b185b45c9a81ee7f84acde"
    family = "unknown"
    file_name = "litespeed.txt"
    file_type = "unknown"
    first_seen = "2026-09-25 03:14:27"
  condition:
    hash.sha256(0, filesize) == "7f800bdb0cbc945b8f59789e7276852f7ab4822f87b185b45c9a81ee7f84acde"
}

rule MalwareBazaar_unknown_063_35697a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35697a14b56ddf664d987433a87a105a3f2e9912b3edcde17f536a5dd490cbd2"
    family = "unknown"
    file_name = "acc.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:22"
  condition:
    hash.sha256(0, filesize) == "35697a14b56ddf664d987433a87a105a3f2e9912b3edcde17f536a5dd490cbd2"
}

rule MalwareBazaar_unknown_064_ce01dac0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce01dac06be173ddfe6f1e1d65088a112272a2d158b7da505fc23f014e7ca63a"
    family = "unknown"
    file_name = "kj.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:17"
  condition:
    hash.sha256(0, filesize) == "ce01dac06be173ddfe6f1e1d65088a112272a2d158b7da505fc23f014e7ca63a"
}

rule MalwareBazaar_unknown_065_6f94b2f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f94b2f7d0a57f39e500a08a24cf90177acd3c2cce1fdbdb586170d2a7d42cbe"
    family = "unknown"
    file_name = "nexus.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:12"
  condition:
    hash.sha256(0, filesize) == "6f94b2f7d0a57f39e500a08a24cf90177acd3c2cce1fdbdb586170d2a7d42cbe"
}

rule MalwareBazaar_unknown_066_2f1f63b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f1f63b7d2fe56fdad569712ecb92e4ffd6099f2f2a6cf7fbdbe76349490a45f"
    family = "unknown"
    file_name = "alfa-putih.txt"
    file_type = "php"
    first_seen = "2026-09-25 03:14:06"
  condition:
    hash.sha256(0, filesize) == "2f1f63b7d2fe56fdad569712ecb92e4ffd6099f2f2a6cf7fbdbe76349490a45f"
}

rule MalwareBazaar_VShell_067_597e1f47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009"
    family = "VShell"
    file_name = "597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:10:13"
  condition:
    hash.sha256(0, filesize) == "597e1f47936b2dc91df74e9769273a62730043b835e260c77950672db2c5b009"
}

rule MalwareBazaar_unknown_068_1ef89f26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22"
    family = "unknown"
    file_name = "1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22.bin"
    file_type = "zip"
    first_seen = "2026-09-25 03:09:29"
  condition:
    hash.sha256(0, filesize) == "1ef89f262d5b25d2279aee12c81e1767e6e58c367ac13756d391f2cb56022b22"
}

rule MalwareBazaar_ValleyRAT_069_b15f0c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b15f0c3550a40034e11547bedd66d220d75ee73a99194e5285046b4e3cc031aa"
    family = "ValleyRAT"
    file_name = "B137780B84CB1E07D3BE853460B28C3E.dll"
    file_type = "dll"
    first_seen = "2026-09-25 03:00:32"
  condition:
    hash.sha256(0, filesize) == "b15f0c3550a40034e11547bedd66d220d75ee73a99194e5285046b4e3cc031aa"
}

rule MalwareBazaar_ValleyRAT_070_0b5ce68b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b5ce68beab1bef3e214c00995c5590825bb096cd2cc2a07af1dad9c4c8579b2"
    family = "ValleyRAT"
    file_name = "D9102A1929D66B6A5CC6B1CEE95F3E8C.dll"
    file_type = "dll"
    first_seen = "2026-09-25 03:00:29"
  condition:
    hash.sha256(0, filesize) == "0b5ce68beab1bef3e214c00995c5590825bb096cd2cc2a07af1dad9c4c8579b2"
}

rule MalwareBazaar_CobaltStrike_071_2db23dba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2db23dbabf20814d496c61778c178ecf7a0da76f199f5476f45b4bbd650a4dd4"
    family = "CobaltStrike"
    file_name = "0b9bde384dac136914f21b8e5483c409.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:00:26"
  condition:
    hash.sha256(0, filesize) == "2db23dbabf20814d496c61778c178ecf7a0da76f199f5476f45b4bbd650a4dd4"
}

rule MalwareBazaar_ColibriLoader_072_6f0fd39f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f0fd39f4698b31d53bddccd15b0627683f09a5f43f90f56e557eb24c95d2c3f"
    family = "ColibriLoader"
    file_name = "B63D2C05DC5F1683B99E2A4B4F9D3C24.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:00:23"
  condition:
    hash.sha256(0, filesize) == "6f0fd39f4698b31d53bddccd15b0627683f09a5f43f90f56e557eb24c95d2c3f"
}

rule MalwareBazaar_RedLineStealer_073_9b2a3b0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b2a3b0dd168473cd7cac5f37246b640e1df6a44647f1214e36b434826b63e5c"
    family = "RedLineStealer"
    file_name = "1C06BE88EB3ADB8C17511F6FE4F8E631.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:00:18"
  condition:
    hash.sha256(0, filesize) == "9b2a3b0dd168473cd7cac5f37246b640e1df6a44647f1214e36b434826b63e5c"
}

rule MalwareBazaar_AsyncRAT_074_eab64496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eab6449614bea5149944852161e721dbeac40df491136e40c1edd31908521974"
    family = "AsyncRAT"
    file_name = "PO2606-00023.js"
    file_type = "js"
    first_seen = "2026-09-25 03:00:15"
  condition:
    hash.sha256(0, filesize) == "eab6449614bea5149944852161e721dbeac40df491136e40c1edd31908521974"
}

rule MalwareBazaar_AsyncRAT_075_0f221145
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f2211459a6fd39506460bb309d30f673b27c7ab72fc9e41ea3c27e360f8e65f"
    family = "AsyncRAT"
    file_name = "TEKLAS Purchase Order 24-09-2026.js"
    file_type = "js"
    first_seen = "2026-09-25 03:00:11"
  condition:
    hash.sha256(0, filesize) == "0f2211459a6fd39506460bb309d30f673b27c7ab72fc9e41ea3c27e360f8e65f"
}

rule MalwareBazaar_NanoCore_076_d165b25b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d165b25b803cbf5f2f2d3723cf1c778028832bbf26bf91a895f449439a1abbc9"
    family = "NanoCore"
    file_name = "0ebea18d678fe2aabf937cc67d5c208d.exe"
    file_type = "exe"
    first_seen = "2026-09-25 03:00:07"
  condition:
    hash.sha256(0, filesize) == "d165b25b803cbf5f2f2d3723cf1c778028832bbf26bf91a895f449439a1abbc9"
}

rule MalwareBazaar_unknown_077_70b6b983
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70b6b983b1d9e90206328dbdea8f044682e1be807ec6e9c71dcd0cd76f3dbe9c"
    family = "unknown"
    file_name = "kbvsxhrs.exe"
    file_type = "exe"
    first_seen = "2026-09-25 02:49:42"
  condition:
    hash.sha256(0, filesize) == "70b6b983b1d9e90206328dbdea8f044682e1be807ec6e9c71dcd0cd76f3dbe9c"
}

rule MalwareBazaar_unknown_078_46874f0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf"
    family = "unknown"
    file_name = "46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf.exe"
    file_type = "exe"
    first_seen = "2026-09-25 02:49:40"
  condition:
    hash.sha256(0, filesize) == "46874f0a718001b23b1e9fdf1cb607e1ca7840e5a7bddc696f75f88a75f17caf"
}

rule MalwareBazaar_unknown_079_f3ab3b97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3ab3b97e0e4d6429f5eba95710c398ef65fd935b619056004c2e13a84dc6a7b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-25 02:47:16"
  condition:
    hash.sha256(0, filesize) == "f3ab3b97e0e4d6429f5eba95710c398ef65fd935b619056004c2e13a84dc6a7b"
}

rule MalwareBazaar_Mirai_080_18712e07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18712e078a6f5419ee21ddee6803395a98824021401781b51f1d08c6e1454536"
    family = "Mirai"
    file_name = "stub.i386"
    file_type = "elf"
    first_seen = "2026-09-25 02:34:17"
  condition:
    hash.sha256(0, filesize) == "18712e078a6f5419ee21ddee6803395a98824021401781b51f1d08c6e1454536"
}

rule MalwareBazaar_unknown_081_6c09b421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c09b421ab2cd70554f48581c5244045d34287ca589053b353420e42981d41b2"
    family = "unknown"
    file_name = "Chara.exe"
    file_type = "exe"
    first_seen = "2026-09-25 02:30:47"
  condition:
    hash.sha256(0, filesize) == "6c09b421ab2cd70554f48581c5244045d34287ca589053b353420e42981d41b2"
}

rule MalwareBazaar_Mirai_082_847818db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847818db1ce56d2193d3a658104d396b24271eb0b96fcf398f256f2dc4e9665d"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.16503.24137"
    file_type = "elf"
    first_seen = "2026-09-25 02:25:32"
  condition:
    hash.sha256(0, filesize) == "847818db1ce56d2193d3a658104d396b24271eb0b96fcf398f256f2dc4e9665d"
}

rule MalwareBazaar_Mirai_083_ac688245
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac6882450172470660c0e0bf49258034df16e3ea4319d0e06db3845524abfb5e"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-COW.68995338"
    file_type = "elf"
    first_seen = "2026-09-25 02:25:30"
  condition:
    hash.sha256(0, filesize) == "ac6882450172470660c0e0bf49258034df16e3ea4319d0e06db3845524abfb5e"
}

rule MalwareBazaar_Mirai_084_7412e1b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7412e1b0a97ec676f20c33056b7d2b7c1566b048a2389fdeab296928fb603924"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Heur.16843.186"
    file_type = "elf"
    first_seen = "2026-09-25 02:25:29"
  condition:
    hash.sha256(0, filesize) == "7412e1b0a97ec676f20c33056b7d2b7c1566b048a2389fdeab296928fb603924"
}

rule MalwareBazaar_Mirai_085_2c5d12b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c5d12b34cbd21cd5b4f62c3e85874a8d525c9f07c5bbed5761fac20a73ea0fb"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai-COW.29885185"
    file_type = "elf"
    first_seen = "2026-09-25 02:25:27"
  condition:
    hash.sha256(0, filesize) == "2c5d12b34cbd21cd5b4f62c3e85874a8d525c9f07c5bbed5761fac20a73ea0fb"
}

rule MalwareBazaar_BlackMatter_086_46a9f920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46a9f920cb9049c9be7bf3afba7ec13b0d0d170029363a115f429996822d4871"
    family = "BlackMatter"
    file_name = "ryfiairtp.exe"
    file_type = "exe"
    first_seen = "2026-09-25 02:23:18"
  condition:
    hash.sha256(0, filesize) == "46a9f920cb9049c9be7bf3afba7ec13b0d0d170029363a115f429996822d4871"
}

rule MalwareBazaar_unknown_087_33d3afdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33d3afddaa5710cdcc4e93a7bae8be010c19747fb53d85fcd54ef32056a1eb0b"
    family = "unknown"
    file_name = "enc-linux.bak"
    file_type = "elf"
    first_seen = "2026-09-25 02:18:18"
  condition:
    hash.sha256(0, filesize) == "33d3afddaa5710cdcc4e93a7bae8be010c19747fb53d85fcd54ef32056a1eb0b"
}

rule MalwareBazaar_Mirai_088_28ea9926
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586"
    family = "Mirai"
    file_name = "28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586"
    file_type = "elf"
    first_seen = "2026-09-25 02:17:14"
  condition:
    hash.sha256(0, filesize) == "28ea992652c200b8aa08b1f53ea623c013924aaea7f10f840db83a221ceb8586"
}

rule MalwareBazaar_unknown_089_73d519c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a"
    family = "unknown"
    file_name = "73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a"
    file_type = "unknown"
    first_seen = "2026-09-25 01:53:07"
  condition:
    hash.sha256(0, filesize) == "73d519c4ccb9d3c8c5a296ae4f5a6f4dfd24ccd51befce154601c6dd60713a7a"
}

rule MalwareBazaar_unknown_090_d80b949b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35"
    family = "unknown"
    file_name = "d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35"
    file_type = "sh"
    first_seen = "2026-09-25 01:53:01"
  condition:
    hash.sha256(0, filesize) == "d80b949b4c3d67a31503c8f9ebceaae6d00c5b3a73c3a248c29db6cc43d91a35"
}

rule MalwareBazaar_GCleaner_091_055caa23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "055caa239318b8cd8497b8631dd1b1bef1e8ba5912791c48a2a3081a8d685b1b"
    family = "GCleaner"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-09-25 01:52:06"
  condition:
    hash.sha256(0, filesize) == "055caa239318b8cd8497b8631dd1b1bef1e8ba5912791c48a2a3081a8d685b1b"
}

rule MalwareBazaar_Mirai_092_23b2d67b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23b2d67b756bfaae680f07784ba229676a1e054da6fbb39053443a4485aeb76b"
    family = "Mirai"
    file_name = "tpijtvcr.aarch64"
    file_type = "elf"
    first_seen = "2026-09-25 01:29:25"
  condition:
    hash.sha256(0, filesize) == "23b2d67b756bfaae680f07784ba229676a1e054da6fbb39053443a4485aeb76b"
}

rule MalwareBazaar_Mirai_093_cb6fdabd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb6fdabd9a3c19f8004d18fb0259ac89a01ce6e0b5cb4b6b8d8179bb6c3f81ea"
    family = "Mirai"
    file_name = "ooikocqj.armv7"
    file_type = "elf"
    first_seen = "2026-09-25 01:20:15"
  condition:
    hash.sha256(0, filesize) == "cb6fdabd9a3c19f8004d18fb0259ac89a01ce6e0b5cb4b6b8d8179bb6c3f81ea"
}

rule MalwareBazaar_Mirai_094_45ec4b84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40"
    family = "Mirai"
    file_name = "45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40"
    file_type = "elf"
    first_seen = "2026-09-25 01:17:15"
  condition:
    hash.sha256(0, filesize) == "45ec4b84069887b7c4970bec65a795cb665988000a48d3b2268905f87ab45d40"
}

rule MalwareBazaar_unknown_095_9ede0ece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578"
    family = "unknown"
    file_name = "9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578.exe"
    file_type = "exe"
    first_seen = "2026-09-25 01:10:37"
  condition:
    hash.sha256(0, filesize) == "9ede0ecea5cbb266b7ed3fa0088ba8f71f7c532c6cdf32ecfb7429013d141578"
}

rule MalwareBazaar_Mirai_096_53bd728f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53bd728fc37bb1adeaf907f8cf683e08d37304af2eb62626613f93dfc9b256ea"
    family = "Mirai"
    file_name = "cwlfkwnt.mips"
    file_type = "elf"
    first_seen = "2026-09-25 01:10:34"
  condition:
    hash.sha256(0, filesize) == "53bd728fc37bb1adeaf907f8cf683e08d37304af2eb62626613f93dfc9b256ea"
}

rule MalwareBazaar_unknown_097_4b72c66c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919"
    family = "unknown"
    file_name = "4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919.exe"
    file_type = "exe"
    first_seen = "2026-09-25 01:10:33"
  condition:
    hash.sha256(0, filesize) == "4b72c66c002d60b9c5d213bd09a7e12c79c3e593ce0fa3efe7301f49f7050919"
}

rule MalwareBazaar_Mirai_098_2a7dc1fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a7dc1fefb391e333a9aef1690a66d7106046f2377fb4e81fbf2548539e9fe3e"
    family = "Mirai"
    file_name = "cwlfkwnt.armv8"
    file_type = "elf"
    first_seen = "2026-09-25 01:10:32"
  condition:
    hash.sha256(0, filesize) == "2a7dc1fefb391e333a9aef1690a66d7106046f2377fb4e81fbf2548539e9fe3e"
}

rule MalwareBazaar_unknown_099_5fe8e459
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3"
    family = "unknown"
    file_name = "5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3.exe"
    file_type = "exe"
    first_seen = "2026-09-25 01:10:28"
  condition:
    hash.sha256(0, filesize) == "5fe8e459e8cd447c472c9244bb8f092c5e3465ef072ca0bd50350c581fb267e3"
}

rule MalwareBazaar_Mirai_100_42e644a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42e644a584b9a91261f406f15c63ae45288eea0557667897ae517bd4e9e37ff4"
    family = "Mirai"
    file_name = "qzxuuppn.i486"
    file_type = "elf"
    first_seen = "2026-09-25 00:51:36"
  condition:
    hash.sha256(0, filesize) == "42e644a584b9a91261f406f15c63ae45288eea0557667897ae517bd4e9e37ff4"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

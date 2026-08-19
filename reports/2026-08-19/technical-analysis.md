# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-19

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 588 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 588 |
| Unique family labels | 9 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 49 |
| Mirai | 44 |
| RemcosRAT | 1 |
| OverlordRAT | 1 |
| SnappyClient | 1 |
| RemusStealer | 1 |
| ValleyRAT | 1 |
| Vidar | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 62 |
| exe | 25 |
| unknown | 9 |
| sh | 2 |
| js | 1 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `e0b92c6a29b0f98e`

| Field | Value |
|---|---|
| SHA-256 | `e0b92c6a29b0f98e0bd3b348e4722b9e95eb66c3ca949207ebbca7ac889eb987` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-19 01:55:07` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86b372464122ae0d5222b6ce5022696d` |
| SHA-256 | `e0b92c6a29b0f98e0bd3b348e4722b9e95eb66c3ca949207ebbca7ac889eb987` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_e0b92c6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0b92c6a29b0f98e0bd3b348e4722b9e95eb66c3ca949207ebbca7ac889eb987"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 01:55:07"
  condition:
    hash.sha256(0, filesize) == "e0b92c6a29b0f98e0bd3b348e4722b9e95eb66c3ca949207ebbca7ac889eb987"
}
```

### Sample 2: `c3cc65ebb8dee634`

| Field | Value |
|---|---|
| SHA-256 | `c3cc65ebb8dee634758de9d96056b6c3246f95af67610ac79dae9d31b5789cab` |
| Family label | `unknown` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-19 01:54:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62c46156ff7c017e2c236c40f959ff04` |
| SHA-256 | `c3cc65ebb8dee634758de9d96056b6c3246f95af67610ac79dae9d31b5789cab` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_c3cc65eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3cc65ebb8dee634758de9d96056b6c3246f95af67610ac79dae9d31b5789cab"
    family = "unknown"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:34"
  condition:
    hash.sha256(0, filesize) == "c3cc65ebb8dee634758de9d96056b6c3246f95af67610ac79dae9d31b5789cab"
}
```

### Sample 3: `aa4272539b9b6376`

| Field | Value |
|---|---|
| SHA-256 | `aa4272539b9b637651ea999c3ea77c1ed7727d73e79876144849e71caadd3ecb` |
| Family label | `unknown` |
| File name | `bot.arc` |
| File type | `elf` |
| First seen | `2026-08-19 01:54:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1e15242ebfd722a1ce1a3ccbd256819` |
| SHA-256 | `aa4272539b9b637651ea999c3ea77c1ed7727d73e79876144849e71caadd3ecb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_aa427253
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa4272539b9b637651ea999c3ea77c1ed7727d73e79876144849e71caadd3ecb"
    family = "unknown"
    file_name = "bot.arc"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:32"
  condition:
    hash.sha256(0, filesize) == "aa4272539b9b637651ea999c3ea77c1ed7727d73e79876144849e71caadd3ecb"
}
```

### Sample 4: `806385c4d1ce5fb6`

| Field | Value |
|---|---|
| SHA-256 | `806385c4d1ce5fb675357095cb07a81e0a0aebe4962b66e5422e0000945c149d` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-19 01:54:31` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18c6be9c842ad5eea014af6dde935693` |
| SHA-256 | `806385c4d1ce5fb675357095cb07a81e0a0aebe4962b66e5422e0000945c149d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_806385c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "806385c4d1ce5fb675357095cb07a81e0a0aebe4962b66e5422e0000945c149d"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:31"
  condition:
    hash.sha256(0, filesize) == "806385c4d1ce5fb675357095cb07a81e0a0aebe4962b66e5422e0000945c149d"
}
```

### Sample 5: `715778aef73034eb`

| Field | Value |
|---|---|
| SHA-256 | `715778aef73034eb2e87607d5c3c43b57993a9bb99296041191b8f2801943a3f` |
| Family label | `unknown` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-08-19 01:54:30` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d136618de22d7c0d4fde88997cc336bd` |
| SHA-256 | `715778aef73034eb2e87607d5c3c43b57993a9bb99296041191b8f2801943a3f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_715778ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "715778aef73034eb2e87607d5c3c43b57993a9bb99296041191b8f2801943a3f"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:30"
  condition:
    hash.sha256(0, filesize) == "715778aef73034eb2e87607d5c3c43b57993a9bb99296041191b8f2801943a3f"
}
```

### Sample 6: `3f14d76a13d76477`

| Field | Value |
|---|---|
| SHA-256 | `3f14d76a13d76477bc2822af9d8bd6a6ccfc50fc1e40686414e00d5a600a3c38` |
| Family label | `unknown` |
| File name | `flutter.arm` |
| File type | `elf` |
| First seen | `2026-08-19 01:54:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74be22f9182b2a56fe4c9cdd2c4d950a` |
| SHA-256 | `3f14d76a13d76477bc2822af9d8bd6a6ccfc50fc1e40686414e00d5a600a3c38` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_3f14d76a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f14d76a13d76477bc2822af9d8bd6a6ccfc50fc1e40686414e00d5a600a3c38"
    family = "unknown"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:28"
  condition:
    hash.sha256(0, filesize) == "3f14d76a13d76477bc2822af9d8bd6a6ccfc50fc1e40686414e00d5a600a3c38"
}
```

### Sample 7: `e52cca6f483ac515`

| Field | Value |
|---|---|
| SHA-256 | `e52cca6f483ac515b68bccb39fb3103fe6f1162616965d0a0dc3dd0b985488e0` |
| Family label | `unknown` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-08-19 01:54:27` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb1c9f47c31989514b8aadac982181b9` |
| SHA-256 | `e52cca6f483ac515b68bccb39fb3103fe6f1162616965d0a0dc3dd0b985488e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_e52cca6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e52cca6f483ac515b68bccb39fb3103fe6f1162616965d0a0dc3dd0b985488e0"
    family = "unknown"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:27"
  condition:
    hash.sha256(0, filesize) == "e52cca6f483ac515b68bccb39fb3103fe6f1162616965d0a0dc3dd0b985488e0"
}
```

### Sample 8: `b78985f078be3124`

| Field | Value |
|---|---|
| SHA-256 | `b78985f078be3124e50fa43e8cce7067692d26a63120b3e3f5f5954d69064b77` |
| Family label | `unknown` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-19 01:52:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4771d0d628f3c35215c4475039137bfc` |
| SHA-1 | `50640850359fbba9a9ec7e6502131419c32374f2` |
| SHA-256 | `b78985f078be3124e50fa43e8cce7067692d26a63120b3e3f5f5954d69064b77` |
| SHA3-384 | `eac13c8320d14911ca28d79cc0f0bbd9c748aee10339266bd094426be019c2bbd4f9d1fa467a306f842238876f0449d4` |
| TLSH | `T1E3448D01FB180A23C1D31EB80E7B07A7D369898318F9F11E690E7F564731A7A96877D9` |
| SSDEEP | `6144:WtInXQiUwkWO5A90ufNY022eAgnsv7Ag1g2hYSnQLMOvv:WmXzUwkv5wi2eAgSxEv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_b78985f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b78985f078be3124e50fa43e8cce7067692d26a63120b3e3f5f5954d69064b77"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-19 01:52:53"
  condition:
    hash.sha256(0, filesize) == "b78985f078be3124e50fa43e8cce7067692d26a63120b3e3f5f5954d69064b77"
}
```

### Sample 9: `3dfcf989589e4f2e`

| Field | Value |
|---|---|
| SHA-256 | `3dfcf989589e4f2e46cad337be31ababc650446bf85afb935b57d7f04e416b11` |
| Family label | `unknown` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-19 01:52:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f757bf4b9f6d7189548271fd20495d2` |
| SHA-1 | `ad832aea256e5b679a65668d9080778ac43dbde5` |
| SHA-256 | `3dfcf989589e4f2e46cad337be31ababc650446bf85afb935b57d7f04e416b11` |
| SHA3-384 | `8453b4b9f103b8f707403efdfd75ea89dd40aee65cb954ee1546a1289022abc369a0a0ea2e070d9d858a87b66c5582bc` |
| TLSH | `T18B043A95F890DE52C6D0267AFA3D518C331317B8D3DAB106CE149E35E7EB85A0E3E942` |
| SSDEEP | `3072:KzftARJG9YyFiMWghSV3B/g/pn0j9DXBJcYEEURRrDti5jOsCMGZreAfcIAqT5GP:Kz1KgThSVRoqpDxJcYEEURRrDtEISAfW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_3dfcf989
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dfcf989589e4f2e46cad337be31ababc650446bf85afb935b57d7f04e416b11"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-19 01:52:49"
  condition:
    hash.sha256(0, filesize) == "3dfcf989589e4f2e46cad337be31ababc650446bf85afb935b57d7f04e416b11"
}
```

### Sample 10: `e20fdbe034b94a7e`

| Field | Value |
|---|---|
| SHA-256 | `e20fdbe034b94a7eb72d7b5fa32bed5e7851503c97da05a6303ae6a744e05569` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-19 01:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5dcb431883acb380c9119309fc02fa0` |
| SHA-256 | `e20fdbe034b94a7eb72d7b5fa32bed5e7851503c97da05a6303ae6a744e05569` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_e20fdbe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e20fdbe034b94a7eb72d7b5fa32bed5e7851503c97da05a6303ae6a744e05569"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-19 01:52:11"
  condition:
    hash.sha256(0, filesize) == "e20fdbe034b94a7eb72d7b5fa32bed5e7851503c97da05a6303ae6a744e05569"
}
```

### Sample 11: `cb4efe99fbc11bef`

| Field | Value |
|---|---|
| SHA-256 | `cb4efe99fbc11befd19e6eb33c1c29b00301429ddfb6864a10130dc7ac3eb5e0` |
| Family label | `unknown` |
| File name | `flutter.mipsel` |
| File type | `elf` |
| First seen | `2026-08-19 01:51:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8770c0083d72b222a0fc4503dddd339b` |
| SHA-1 | `94868c9ea3a3bf92a9ffa5fb3cd879bac60c140e` |
| SHA-256 | `cb4efe99fbc11befd19e6eb33c1c29b00301429ddfb6864a10130dc7ac3eb5e0` |
| SHA3-384 | `f0cbd01b9fef0022e65011825eb8842095275c0ae1618cce31c2e126798a3ae215b9c67218f31cf6d9a2b2f576be5a58` |
| TLSH | `T17E445C8A9E601FEBC46FCD30063E871719ED999BA2F16736C67CDC48358E24946E385C` |
| TELFHASH | `t1fa4123355f7995229ed2c4509cee9322a51ed1190755ee27df24854c102e09ff21be8f` |
| SSDEEP | `6144:zTTzGgib+PZBB7ipRkADLpR84CTL3geUHvRYLKV4:XTz2b+PZnip+mU4CTSCLKu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_cb4efe99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb4efe99fbc11befd19e6eb33c1c29b00301429ddfb6864a10130dc7ac3eb5e0"
    family = "unknown"
    file_name = "flutter.mipsel"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:46"
  condition:
    hash.sha256(0, filesize) == "cb4efe99fbc11befd19e6eb33c1c29b00301429ddfb6864a10130dc7ac3eb5e0"
}
```

### Sample 12: `9fb7b893aed67b41`

| Field | Value |
|---|---|
| SHA-256 | `9fb7b893aed67b419b904cf220720ca1a6ccd6e5d788ec027d806825d71220a6` |
| Family label | `unknown` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-19 01:51:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5b641afdf44b330ae5c4624d0560306` |
| SHA-1 | `0c280a1f0a9c3bc9e896ab5c116fbd59d319437c` |
| SHA-256 | `9fb7b893aed67b419b904cf220720ca1a6ccd6e5d788ec027d806825d71220a6` |
| SHA3-384 | `44cecd72f00008fd5b29cdfe251f9ae0e612e2cfec26c1394c5a18a3e4427ae674c1fa051e51e21fec366f900489b512` |
| TLSH | `T189A302DAD4C45D6A6A179808AE5AA4E0B74CF2CB2235DDA1B1C3CED64F81323D7053E7` |
| SSDEEP | `3072:O5p+oOo5oodH0Ncr8w9ILbrE0KYMHC3MR1y4u+qgww:kplDdHow9cE3C3MR1V` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_9fb7b893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb7b893aed67b419b904cf220720ca1a6ccd6e5d788ec027d806825d71220a6"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:34"
  condition:
    hash.sha256(0, filesize) == "9fb7b893aed67b419b904cf220720ca1a6ccd6e5d788ec027d806825d71220a6"
}
```

### Sample 13: `f75b53a2ca114382`

| Field | Value |
|---|---|
| SHA-256 | `f75b53a2ca1143821a72f92e033b95540ddf68de1bb37bc7f942976833ea99cc` |
| Family label | `unknown` |
| File name | `bot.x86` |
| File type | `elf` |
| First seen | `2026-08-19 01:51:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11754552fe376f699a83a65fdc798114` |
| SHA-1 | `dc21b85f3940997359ba78e5e39a2357029a63b6` |
| SHA-256 | `f75b53a2ca1143821a72f92e033b95540ddf68de1bb37bc7f942976833ea99cc` |
| SHA3-384 | `71b65b1536b8a76460e7fa88cdcf956b18a86c66bc281cec362a4c799cf41b4ef04a95862df587252c0ae94f87483378` |
| TLSH | `T10A530946AE47DE73D40324F106F39B615A31F83B5837998AE331BEF1DA226C1A21536D` |
| TELFHASH | `t1754146f66e6e0cecb350ac45cb0b6fd32d4ad1b70a9172f900630a5532f3e94c564835` |
| SSDEEP | `1536:Umc5EATP/BzLf8WdSFReQN3735jheIN8Nsi:45hzDUFIw37Jjs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_f75b53a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f75b53a2ca1143821a72f92e033b95540ddf68de1bb37bc7f942976833ea99cc"
    family = "unknown"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:33"
  condition:
    hash.sha256(0, filesize) == "f75b53a2ca1143821a72f92e033b95540ddf68de1bb37bc7f942976833ea99cc"
}
```

### Sample 14: `cd007446796b9319`

| Field | Value |
|---|---|
| SHA-256 | `cd007446796b931958b47b01258dc375654fc5ac44e09baaf82532237ca12bea` |
| Family label | `unknown` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-19 01:51:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6db617cbf08f470462c9ac41c2b5f7ee` |
| SHA-1 | `35213b766f03edbb9ef405d77e5da36dd0dccf31` |
| SHA-256 | `cd007446796b931958b47b01258dc375654fc5ac44e09baaf82532237ca12bea` |
| SHA3-384 | `f2de9a55bf1427a299fc065154b3a1b1af1e217de2d0a6934181f0f4c74f6e77f287609a39dbd48ded14076018843457` |
| TLSH | `T13F83124156FF88FBE230A375C65BDD346703CF7CEA1E26D099919AA070816727D70A93` |
| SSDEEP | `1536:Bcia+KEyPe+g4r2F5fKvqzGeGocS8C/E+ieN2poc2KWtDF9XZiP+a8OrrVBJ/f5:iilPyPerfeqUDS8npxyc2hXZixvzdR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_cd007446
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd007446796b931958b47b01258dc375654fc5ac44e09baaf82532237ca12bea"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:31"
  condition:
    hash.sha256(0, filesize) == "cd007446796b931958b47b01258dc375654fc5ac44e09baaf82532237ca12bea"
}
```

### Sample 15: `03a83f75a6b3a58b`

| Field | Value |
|---|---|
| SHA-256 | `03a83f75a6b3a58bf840d41a61f82808036dee034d1682fd028ace7e6007bca8` |
| Family label | `unknown` |
| File name | `bot.arm6` |
| File type | `elf` |
| First seen | `2026-08-19 01:51:30` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `973514ebff826a06d92b9bf4a0e987de` |
| SHA-1 | `50576ab4972f49eec4d8e3347a49d6b559e9b327` |
| SHA-256 | `03a83f75a6b3a58bf840d41a61f82808036dee034d1682fd028ace7e6007bca8` |
| SHA3-384 | `40b93f9e96edcefea85b3bea2091104bc2e7ca63b2c7620feeae8f8e8f4866318d253c33f19a36c0a970af2bd39733f2` |
| TLSH | `T19B832B17FA52CF12C5C311BAFA9E524933136FB8E3DE7212C920AF6067865DB0A76512` |
| TELFHASH | `t159d09771de4605c0779c860d92ca123abca9723567423298e78eae0d04932f0810a002` |
| SSDEEP | `1536:WbnOrpzrpsOQfkIFr1zxZo4F4U+E72dlx/amsFO/MhiHfwrwzS7yw5NY8hzJbG:3rNr3mkizxZxF7+Eelx/am1fwrwzS+wg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_03a83f75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03a83f75a6b3a58bf840d41a61f82808036dee034d1682fd028ace7e6007bca8"
    family = "unknown"
    file_name = "bot.arm6"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:30"
  condition:
    hash.sha256(0, filesize) == "03a83f75a6b3a58bf840d41a61f82808036dee034d1682fd028ace7e6007bca8"
}
```

### Sample 16: `f429a85a4a26dd50`

| Field | Value |
|---|---|
| SHA-256 | `f429a85a4a26dd508cac9d5270b8c3bd10075cae927d4e65d3811a885e4d7959` |
| Family label | `unknown` |
| File name | `dvr.sh` |
| File type | `sh` |
| First seen | `2026-08-19 01:51:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5164664fb8a01ea0ebfb279939a5589` |
| SHA-1 | `ce99bbc233a675c04758b142f983571eee0804d3` |
| SHA-256 | `f429a85a4a26dd508cac9d5270b8c3bd10075cae927d4e65d3811a885e4d7959` |
| SHA3-384 | `8cc0df2b94450fd03e1a1fd58623e011aee285b7d92b9354737d551fea19c98f0ce147f4169e34d893af383c3bb2cb7b` |
| TLSH | `T11BA1D38AA170D33DA46FDDBCBAE70A40588945E231B13F395EB008937C89970B349F5E` |
| SSDEEP | `96:il383vTiXLxd62AV35olPgj7yW6dn546Q3d1STBWLYTg/3iVXjIFFT4FTxaflcJb:il383vTiXLxd62AV35olPgj7yW6dn54a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_f429a85a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f429a85a4a26dd508cac9d5270b8c3bd10075cae927d4e65d3811a885e4d7959"
    family = "unknown"
    file_name = "dvr.sh"
    file_type = "sh"
    first_seen = "2026-08-19 01:51:29"
  condition:
    hash.sha256(0, filesize) == "f429a85a4a26dd508cac9d5270b8c3bd10075cae927d4e65d3811a885e4d7959"
}
```

### Sample 17: `b2207baadf7b5d29`

| Field | Value |
|---|---|
| SHA-256 | `b2207baadf7b5d299682820fbbe011b785f463cf34a5d9e6a9888cc808ad412e` |
| Family label | `unknown` |
| File name | `main.x86-core2` |
| File type | `elf` |
| First seen | `2026-08-19 01:51:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b06b5ba2e8878c7b731e1fb5ce5756a` |
| SHA-1 | `c51fb9de0926434cce67a7a9fec38345c1effcd8` |
| SHA-256 | `b2207baadf7b5d299682820fbbe011b785f463cf34a5d9e6a9888cc808ad412e` |
| SHA3-384 | `05531919ed4cd1ad505756d2a4e6505894e7dcbcb1aedaec776abdbb163ce4e14f6c501643ecde398c5f9155866545cb` |
| TLSH | `T10E635C81EA63C1B1E19341F00997F7E64535DB32504BEAEAFB9C7D21BC30B824D9662D` |
| TELFHASH | `t1613104fb1e601cfcf6e09841c75f52e3cf36d8176a20297a40b1699037f8c626066d35` |
| SSDEEP | `1536:9vEFrwvGZyvyMjQKKngNvo18PUVIZf2yCmUr:9vrfvyMP48caeyI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_b2207baa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2207baadf7b5d299682820fbbe011b785f463cf34a5d9e6a9888cc808ad412e"
    family = "unknown"
    file_name = "main.x86-core2"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:28"
  condition:
    hash.sha256(0, filesize) == "b2207baadf7b5d299682820fbbe011b785f463cf34a5d9e6a9888cc808ad412e"
}
```

### Sample 18: `b1f240b7153d4f3e`

| Field | Value |
|---|---|
| SHA-256 | `b1f240b7153d4f3e5c6239c00ea341f46e00df99b4e3751d85b341f4a8106b91` |
| Family label | `unknown` |
| File name | `flutter.mipsel` |
| File type | `elf` |
| First seen | `2026-08-19 01:51:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8426846a294ed3641438f8db5e37abe5` |
| SHA-1 | `14a979a00b4fe1ca99979755e21b999d8455ca1e` |
| SHA-256 | `b1f240b7153d4f3e5c6239c00ea341f46e00df99b4e3751d85b341f4a8106b91` |
| SHA3-384 | `fa05384b68c3a524402c2f5f5ea05aa70205f09458b81a6ada9b87bc708605650b314ea7a4853a0f4511d5b44188bdce` |
| TLSH | `T169D312561F401F68E8177C34ABD34A376E7A2A0BEE438C1395B9F5B264E250CD9C897C` |
| SSDEEP | `3072:+Z5zLDRCZMNMuM247hHglFj/vu0IIPXno/o0wjjLPwl6pao/A+9:+ZdlzKuU7QFj/m076YXTwkI4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_b1f240b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1f240b7153d4f3e5c6239c00ea341f46e00df99b4e3751d85b341f4a8106b91"
    family = "unknown"
    file_name = "flutter.mipsel"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:26"
  condition:
    hash.sha256(0, filesize) == "b1f240b7153d4f3e5c6239c00ea341f46e00df99b4e3751d85b341f4a8106b91"
}
```

### Sample 19: `6e642927debe1863`

| Field | Value |
|---|---|
| SHA-256 | `6e642927debe1863e1821a1cd1f69646fad9ab981c798817bc72f3025bd72a82` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-19 01:50:58` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8aaf63499dee285125da1de5bea8797d` |
| SHA-1 | `5432d698c7b87c67fa9159b409160d66ba25331d` |
| SHA-256 | `6e642927debe1863e1821a1cd1f69646fad9ab981c798817bc72f3025bd72a82` |
| SHA3-384 | `cc453969f5ec59e359d54c2c91c2eccdaaae445d994777c48a2290e557e05399092b472093ea3ecd960b676b77dbac6a` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T16B26230AA7A430F8F062D974CA46D711E7713C859BB099AB2788FE5B3F63190D92D335` |
| SSDEEP | `98304:rKAFjPjGUy+gkqyQLd/2uR7cH/0i9zva5P:rZCUy/kqyO/2uRoMus` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_6e642927
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e642927debe1863e1821a1cd1f69646fad9ab981c798817bc72f3025bd72a82"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 01:50:58"
  condition:
    hash.sha256(0, filesize) == "6e642927debe1863e1821a1cd1f69646fad9ab981c798817bc72f3025bd72a82"
}
```

### Sample 20: `3306801dde6110cb`

| Field | Value |
|---|---|
| SHA-256 | `3306801dde6110cb3020687b58d1fe78722d7fdc55e46423452d32d1163d9c5b` |
| Family label | `unknown` |
| File name | `main.x86-64-v2` |
| File type | `elf` |
| First seen | `2026-08-19 01:48:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8fb43c09d4c7ac3dad66e4c37851639` |
| SHA-1 | `07f02c6d4dea3238ac2217cb41d6130ba659a817` |
| SHA-256 | `3306801dde6110cb3020687b58d1fe78722d7fdc55e46423452d32d1163d9c5b` |
| SHA3-384 | `832c85b56c87f623afab6eca7b2d09d7121bc56312d1ccc90de587d6526c7bc4be8d0172f67a61ed1e99b94d8e493461` |
| TLSH | `T10653D75BB6E3B07CC287C0745A5AD9B1B931B8B002213D7FB7C8FA312935D512659F62` |
| TELFHASH | `t10e21af701e4e3960b1e3f5223359e57188722c5661e032f196b6b8f6cf50f831ab6833` |
| SSDEEP | `1536:seo0AkXgA3XLJ7ubKcUXuviCMzaRDQW2AUr:cnkXgArJ7uNqn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_3306801d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3306801dde6110cb3020687b58d1fe78722d7fdc55e46423452d32d1163d9c5b"
    family = "unknown"
    file_name = "main.x86-64-v2"
    file_type = "elf"
    first_seen = "2026-08-19 01:48:36"
  condition:
    hash.sha256(0, filesize) == "3306801dde6110cb3020687b58d1fe78722d7fdc55e46423452d32d1163d9c5b"
}
```

### Sample 21: `675c6dbee16d7b27`

| Field | Value |
|---|---|
| SHA-256 | `675c6dbee16d7b2786717eebd00016fd10caa96d09460539fc3c95e29de89099` |
| Family label | `unknown` |
| File name | `main.mips64el-n32` |
| File type | `elf` |
| First seen | `2026-08-19 01:48:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddc5fe6f0500884214626d7efbb2530f` |
| SHA-1 | `c8fe1ec34113d5ab016a281941c8a09c4fc8de95` |
| SHA-256 | `675c6dbee16d7b2786717eebd00016fd10caa96d09460539fc3c95e29de89099` |
| SHA3-384 | `9131365f657b3e8f3437e674423df53cd06733118a81d90f24ae6449666bbdebc6e0ba82fca3a8839d16ed040530f788` |
| TLSH | `T11DD32C45EF417FBBC05ECE34856E805B04942DF552E8422E72ECE9CC7B6D26C4BD2984` |
| SSDEEP | `1536:wnpcWpSv3kr69oi41yAlGJhpvoS0u/oUGI+kIXrwZFtpjfsErf:QKiyAgPJJ0fUljjfjdf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_675c6dbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "675c6dbee16d7b2786717eebd00016fd10caa96d09460539fc3c95e29de89099"
    family = "unknown"
    file_name = "main.mips64el-n32"
    file_type = "elf"
    first_seen = "2026-08-19 01:48:34"
  condition:
    hash.sha256(0, filesize) == "675c6dbee16d7b2786717eebd00016fd10caa96d09460539fc3c95e29de89099"
}
```

### Sample 22: `fd8f4bc36fbbf440`

| Field | Value |
|---|---|
| SHA-256 | `fd8f4bc36fbbf440347b7e8c6cf62fa93b6e762565e83035e4b15c0629bb1929` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-08-19 01:25:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c9e56639165ec07c7564659678097f2` |
| SHA-1 | `7e72e2daa48e737fa6fa992cac7dbb33a2fa4908` |
| SHA-256 | `fd8f4bc36fbbf440347b7e8c6cf62fa93b6e762565e83035e4b15c0629bb1929` |
| SHA3-384 | `0ac87cd11633caa28d458f3df771c707a001c6143e5d937bd7a1507081caa7f0ebb17a53ef04a6775213fe98594e274d` |
| TLSH | `T14BF30755FC458B16CAD316BBFF4E428C772607A8D3EE710399296F70379A86A0E3B141` |
| TELFHASH | `t17f21d075fb981dbcf3d0402882deb21a93dd70fe2e2d3420596e9b5f45325c87429855` |
| SSDEEP | `3072:AS0yuIC1HLL+yPd9XNE02qo+5qWC9eM9twzWiYA71vRpDS2QoHB:AS0yuIC1HLiyPdR29ELmeM9twCiYo1Jr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_fd8f4bc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd8f4bc36fbbf440347b7e8c6cf62fa93b6e762565e83035e4b15c0629bb1929"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-19 01:25:51"
  condition:
    hash.sha256(0, filesize) == "fd8f4bc36fbbf440347b7e8c6cf62fa93b6e762565e83035e4b15c0629bb1929"
}
```

### Sample 23: `91f51fa395793823`

| Field | Value |
|---|---|
| SHA-256 | `91f51fa39579382361b5d4faa0b2da6cb5288f4f33afba2ef85c482a5aad2226` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-08-19 01:25:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3c422fd5c986b366109a36990265f61` |
| SHA-1 | `edf9959d0a7cfea15dcfba8a30a5b96c318e9726` |
| SHA-256 | `91f51fa39579382361b5d4faa0b2da6cb5288f4f33afba2ef85c482a5aad2226` |
| SHA3-384 | `db61cf5b07db5ea521011fbb0f5539ece9381f20950f36e4ad87b32028e7869c451de5a780696a2392750fb39b970f8f` |
| TLSH | `T12D5301183AB1B723DA709DBBEE5240AB0AB3F6642487F330772658D477C815F60E16C5` |
| SSDEEP | `1536:6d5HSP0GPSMeWfZKkI7Mf5ZnbBRUAqX8iaPBZULHjZ9zl:6jSPfP4WfZKl0bBHOaPQHjZ9B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_91f51fa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91f51fa39579382361b5d4faa0b2da6cb5288f4f33afba2ef85c482a5aad2226"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-19 01:25:30"
  condition:
    hash.sha256(0, filesize) == "91f51fa39579382361b5d4faa0b2da6cb5288f4f33afba2ef85c482a5aad2226"
}
```

### Sample 24: `28cab475f6c372dd`

| Field | Value |
|---|---|
| SHA-256 | `28cab475f6c372dda827cfea42d1f99718526e1a3797aa2924c34cfa37c95137` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-19 01:19:17` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0745e2d7bf58aa83ad784e1c77980c5` |
| SHA-256 | `28cab475f6c372dda827cfea42d1f99718526e1a3797aa2924c34cfa37c95137` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_28cab475
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28cab475f6c372dda827cfea42d1f99718526e1a3797aa2924c34cfa37c95137"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-19 01:19:17"
  condition:
    hash.sha256(0, filesize) == "28cab475f6c372dda827cfea42d1f99718526e1a3797aa2924c34cfa37c95137"
}
```

### Sample 25: `4b56b9f267d6dec2`

| Field | Value |
|---|---|
| SHA-256 | `4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e` |
| Family label | `Mirai` |
| File name | `4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e.elf` |
| File type | `elf` |
| First seen | `2026-08-19 01:15:43` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d548884ee4e323efcd58a1d0f8ae163` |
| SHA-1 | `dbc133e5111d73028bfeac9c6082318e59b5506c` |
| SHA-256 | `4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e` |
| SHA3-384 | `d396f2d68be54442a942d24508d4a24a83ca3c26cfdd85ff0eb6c4179ba316f1f11cd9e9a8f4d95f9664edc17357a1b0` |
| TLSH | `T130635B01775D4B07E59A5EB0243F1BF1C7BFEE8229E0F2896A0EAB454170E73450AED9` |
| SSDEEP | `1536:EIgrQXVQJ1iu40TcOJe0hnf0g5h6qVZrHRIPTN:EInMBxcObf5VR+R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_4b56b9f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e"
    family = "Mirai"
    file_name = "4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:15:43"
  condition:
    hash.sha256(0, filesize) == "4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e"
}
```

### Sample 26: `bfad1f24080adc25`

| Field | Value |
|---|---|
| SHA-256 | `bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f` |
| Family label | `Mirai` |
| File name | `bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f.elf` |
| File type | `elf` |
| First seen | `2026-08-19 01:05:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb6a04567728be10d1f6044e81fe7fdd` |
| SHA-1 | `da995d07997635070ec5b3c8f29128b8e23e5693` |
| SHA-256 | `bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f` |
| SHA3-384 | `d37aa6aa94e71b06387440d98c436d24730bff23a4c493c696be4f56146fd289ea1576d08b73614c1087c66e524ce816` |
| TLSH | `T17CE33A46FB418A17C4D527B7FA9F414933229B6493EB33068D285FB43F86A6E0D63706` |
| TELFHASH | `t11a212171472592256a65de9888ed73b2022c8316638aef33df31c0dc64090ded636c4f` |
| SSDEEP | `3072:XPftxmxoqN7v/V9QYGAyKUir2MPrMSY1WYGzNvCM/9QVko:XXYLIYGAyBir2MPr/Y5GzNKM/9Uko` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_bfad1f24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f"
    family = "Mirai"
    file_name = "bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:05:42"
  condition:
    hash.sha256(0, filesize) == "bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f"
}
```

### Sample 27: `f9081df1dbc2fcf7`

| Field | Value |
|---|---|
| SHA-256 | `f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1` |
| Family label | `Mirai` |
| File name | `f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1.elf` |
| File type | `elf` |
| First seen | `2026-08-19 01:05:38` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6898735d6df1e2c5bfe58ad22e48460` |
| SHA-1 | `c9c9f6380090856aee9be9e6414fe856e673b54f` |
| SHA-256 | `f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1` |
| SHA3-384 | `d54db619ea0a73ee8a6e6be9b04e3e9c1d8409124d1020f2f78c76ff537492800a52d86d49d39e9d51ca982d7c1ad918` |
| TLSH | `T1E973D680FACB02F1C4074C34A1AAB67FDB32D5668031A66DFF959B72DB77641622324D` |
| TELFHASH | `t17511e37d2bb60ce0abd09812f20d63709e18e73b101076a71ab32869566a9d157bfd3c` |
| SSDEEP | `1536:Dps17tOQMQQEE2qZtUyinq2aoh17gWfCwGYWH59RQmgibH:Ns17sQzQEE2qZtUyinfaovg1wNu9RQmV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_f9081df1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1"
    family = "Mirai"
    file_name = "f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:05:38"
  condition:
    hash.sha256(0, filesize) == "f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1"
}
```

### Sample 28: `4c48a4770c8e84a0`

| Field | Value |
|---|---|
| SHA-256 | `4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc` |
| Family label | `Mirai` |
| File name | `4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc.elf` |
| File type | `elf` |
| First seen | `2026-08-19 01:05:35` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa793a033e7d3ec4462bd4d3fd98b2f8` |
| SHA-1 | `878940132c645f1de905ab1394f7dad482c92da2` |
| SHA-256 | `4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc` |
| SHA3-384 | `0b2905a6072a33bb86ef2d96704b2f1e7aef54dd009c5831689551ceba6261379da25b7cf8b857129fcbaaa2c9d9f648` |
| TLSH | `T12793951D3E219F7EFBAD823887BB8B219304279626E1D584D19CED011F7034E745BB9A` |
| TELFHASH | `t173016928543813f1d3805ddd7becef31e59080df59276e378e10e99a9b216828e01c2c` |
| SSDEEP | `1536:QSlZvgP49GjbpMD9NiANv0heWmi/f9CnOVU93TcXBrea3O1WlRe4:FlZvZGjlyiANv0heWm8f9w+yTcXBreaF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_4c48a477
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc"
    family = "Mirai"
    file_name = "4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:05:35"
  condition:
    hash.sha256(0, filesize) == "4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc"
}
```

### Sample 29: `1c6beaf26337c4fd`

| Field | Value |
|---|---|
| SHA-256 | `1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db` |
| Family label | `Mirai` |
| File name | `1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db.elf` |
| File type | `elf` |
| First seen | `2026-08-19 01:00:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24f8491450a0419deb5a4b9091a0566a` |
| SHA-1 | `5e1cd0d8b674091bb13d832c1ac890599c85ccf3` |
| SHA-256 | `1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db` |
| SHA3-384 | `8a5d97640c78c6104923d09412763618aef374d45245417b6867b7780ee9f35b94628bf607b31497107d5916159ff799` |
| TLSH | `T1F7733B4ADA87F8F1D9820578115FFB36D536F8326120EFF7D7D4FA67A861602A40621C` |
| TELFHASH | `t1fe21dbba1ff518d86bd04411b16a63706d5da73f19403a5313f15428276fe4252abe3e` |
| SSDEEP | `1536:PSzWT0UIl+fQKfEmR+93iwFTBx5HzAcPcyPE7edxlWm9JoP/:PSl09tRrwF75OP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_1c6beaf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db"
    family = "Mirai"
    file_name = "1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:00:33"
  condition:
    hash.sha256(0, filesize) == "1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db"
}
```

### Sample 30: `316b3856741a29f2`

| Field | Value |
|---|---|
| SHA-256 | `316b3856741a29f234c4b0309997a5d457b42d6f4eabbf25e620dfab7440a338` |
| Family label | `unknown` |
| File name | `MV_OEL_SURYA_PO6004226017_SR60042-0115.js` |
| File type | `js` |
| First seen | `2026-08-19 00:55:44` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54af2a1bb043bb6079b67548613697f4` |
| SHA-1 | `4ffbce4288b9d8e6b9d5b6fc1ca80ae38ec4af79` |
| SHA-256 | `316b3856741a29f234c4b0309997a5d457b42d6f4eabbf25e620dfab7440a338` |
| SHA3-384 | `2e82db444d6cc80d499c0a0ff3f3876179cc48fc6cf3ee2091a2e457edbaddc1556ad8184f839fdb508485a7a40da122` |
| TLSH | `T19DE517F636EE7B0F9901725D820D66294A1E9D110D43F3D8E8EF9AD8050F91B33E19AD` |
| SSDEEP | `49152:lnU0GL9FDaIkKgUGCpw5bOyPCuH1vOg+hCFBzuWPHHd5mwGhHJC088G:B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_316b3856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "316b3856741a29f234c4b0309997a5d457b42d6f4eabbf25e620dfab7440a338"
    family = "unknown"
    file_name = "MV_OEL_SURYA_PO6004226017_SR60042-0115.js"
    file_type = "js"
    first_seen = "2026-08-19 00:55:44"
  condition:
    hash.sha256(0, filesize) == "316b3856741a29f234c4b0309997a5d457b42d6f4eabbf25e620dfab7440a338"
}
```

### Sample 31: `1330b1af07f3575a`

| Field | Value |
|---|---|
| SHA-256 | `1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64` |
| Family label | `Mirai` |
| File name | `1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:55:37` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3572fb9a3068afdc37b181dd5468da55` |
| SHA-1 | `c52dbc3cf55acf77d10257d769365b06727a4bc4` |
| SHA-256 | `1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64` |
| SHA3-384 | `e08f90e94f8676af97bbca797a339839b840505e50318d36719e4c0b708501e25308cd958ab3983b0275af7c01838257` |
| TLSH | `T187630A96BC41A629C2C057BBEA6F119E3361A7DCC1DE3317CC245B647BCA81F1E22B45` |
| TELFHASH | `t1cee07200fc36cb6818dbab38ad8e07b88a02921351664b00cf50caf49c3f458e30ca4e` |
| SSDEEP | `1536:+Fxrwcj2DuQFTub5zKKRolv8t46tq0lAq:kxrXiDOtoJ84uqH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_1330b1af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64"
    family = "Mirai"
    file_name = "1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:55:37"
  condition:
    hash.sha256(0, filesize) == "1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64"
}
```

### Sample 32: `5fdd2d6b48143b20`

| Field | Value |
|---|---|
| SHA-256 | `5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d` |
| Family label | `Mirai` |
| File name | `5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:55:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fed8230e9894c802ab01b036c5e6b1e` |
| SHA-1 | `2efaaa336e38a4e93ac4c57ba009b9a96007f912` |
| SHA-256 | `5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d` |
| SHA3-384 | `84ce704ac0c8799dc3c72bcf799e6438c39c756882f74a0bf399a034900005521cbf2af5710a175563f8e49b40dd1957` |
| TLSH | `T1E27317396A06F62CD5E55078F4132AD229520A18BFDCD2E36C93103BFF74388756ED6A` |
| TELFHASH | `t18de02604ec368b6818dbaa34ad8d07bcd5019213556687109e50c6e49c3e464a32db4f` |
| SSDEEP | `1536:FXR7lTBSt/SSbhjKP4esTvq4wkpecl2kVBIVCCfy0K9q3RS:Q/SS5FeAvBEcl1uJ3R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_5fdd2d6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d"
    family = "Mirai"
    file_name = "5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:55:33"
  condition:
    hash.sha256(0, filesize) == "5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d"
}
```

### Sample 33: `9e000b451c872404`

| Field | Value |
|---|---|
| SHA-256 | `9e000b451c872404804000e33ca7ca8ad3b5f345f876a0500646c67a98453954` |
| Family label | `RemcosRAT` |
| File name | `6EF10B9988BD4AD12F1576F78CE852C5.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:55:08` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ef10b9988bd4ad12f1576f78ce852c5` |
| SHA-1 | `8c472e8959f21688390bc4466e5361d18c868293` |
| SHA-256 | `9e000b451c872404804000e33ca7ca8ad3b5f345f876a0500646c67a98453954` |
| SHA3-384 | `f00ba5df576f4562cc9474ce516ed00cbcc79725ed15899c0a6aaafe4430261e055182ba80945b56537084d76d90d5cb` |
| IMPHASH | `cd443d07fb22cc071cc33eee6cd16e2e` |
| TLSH | `T167B4BF01B6F2C1B2DA7654300936E735CEBC7C21183699AB63D61D5BBD30191DB3ABB2` |
| SSDEEP | `12288:w97mmDmUefn1CvVkeClYRLwvcHk2c+IsPZOrMs:wlxDmRnkvVkhYHk2c+DZe` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_033_9e000b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e000b451c872404804000e33ca7ca8ad3b5f345f876a0500646c67a98453954"
    family = "RemcosRAT"
    file_name = "6EF10B9988BD4AD12F1576F78CE852C5.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:55:08"
  condition:
    hash.sha256(0, filesize) == "9e000b451c872404804000e33ca7ca8ad3b5f345f876a0500646c67a98453954"
}
```

### Sample 34: `c2c6af0ad42ba497`

| Field | Value |
|---|---|
| SHA-256 | `c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26` |
| Family label | `Mirai` |
| File name | `c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:45:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be2e3ed1dbe95885f4c5e232a4124eca` |
| SHA-1 | `6679318eedaa5da1beb94469bc0f1ac6f478e727` |
| SHA-256 | `c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26` |
| SHA3-384 | `fab9c9a2207f932395ec783b2971607c757ebba05f24db98d343a1ebcbe059b49ab362ffb5ac93848276510cfea310d1` |
| TLSH | `T1CA634CDAE983F8F6FC110574201BAFB16E73F53B6139EED7DB9996729802642D10224C` |
| TELFHASH | `t16a11e2f50e7e18e8bbd15801800e1b526e6ce7372624357305335524339ee5650b7d39` |
| SSDEEP | `1536:D5UWnXx/EGRo/eoiD5L6INQ1Vraf4eb18Hm/W/WLUVUS7wTNUsdV:D5UWnXxxo/LiD5mIuaTCHm/4VL7uSO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_c2c6af0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26"
    family = "Mirai"
    file_name = "c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:45:33"
  condition:
    hash.sha256(0, filesize) == "c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26"
}
```

### Sample 35: `213c343ab852a0b1`

| Field | Value |
|---|---|
| SHA-256 | `213c343ab852a0b185a2198677bf48ac0e7372467cce84d813fe8c5ddc7464b7` |
| Family label | `OverlordRAT` |
| File name | `Updater.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:44:36` |
| Reporter | `iamaachum` |
| Tags | `download-windows-update-live, dropped-by-Stealc, exe, OverlordRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9636241120eb6b38a28e010dc70fa01` |
| SHA-1 | `f609394cb065f651b68b29352f1538a4ce19627c` |
| SHA-256 | `213c343ab852a0b185a2198677bf48ac0e7372467cce84d813fe8c5ddc7464b7` |
| SHA3-384 | `a304315180f64b49037458d41bdfdbe832a39eabeaf79bfe8117eb7db09954a544e9c37e6912d5b2be663c4fd9ccb0f9` |
| TLSH | `T116C6332835D5DC46DCA12B3485B5E7B047B41D8EA920EF0AAFD0BD9B3D36B7E8904127` |
| SSDEEP | `196608:dlzJA5mK4mplH9ugx1lNIdrwkTY3AiK1EIUmh/LRFXddJWiSDxcKdO:dlM4ax1bcJTqK1+6ltWfc` |

#### Technical Assessment

- The sample is tracked as `OverlordRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_OverlordRAT_035_213c343a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "213c343ab852a0b185a2198677bf48ac0e7372467cce84d813fe8c5ddc7464b7"
    family = "OverlordRAT"
    file_name = "Updater.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:44:36"
  condition:
    hash.sha256(0, filesize) == "213c343ab852a0b185a2198677bf48ac0e7372467cce84d813fe8c5ddc7464b7"
}
```

### Sample 36: `b9f4425ad3f99e54`

| Field | Value |
|---|---|
| SHA-256 | `b9f4425ad3f99e548342f9e281b1736776d9cd8d32728e2d6ee5e9caccda6acb` |
| Family label | `Mirai` |
| File name | `fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:43:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd7166b3cb1ffd8806f691d0d07a4d58` |
| SHA-1 | `6604a49f1b9b215e40c215310c19f3106325b01b` |
| SHA-256 | `b9f4425ad3f99e548342f9e281b1736776d9cd8d32728e2d6ee5e9caccda6acb` |
| SHA3-384 | `9bd60985b98a281b80dfaec22ef4b7e19470b57bcfe1d9c9c0db345480129eb6d0881a6e75ca19904d2225c756500c85` |
| TLSH | `T1CEC32C99FC90CE52C6D52675FA5E428C33231778D3DA7206CE109E34F7E796A0E3A942` |
| SSDEEP | `3072:Eyxziq8scoBFoUiDsBcYUQ4g8OZC5ghtr5IOInY93o+Hf1Dr:EQ9MohcYUQ4g8Ok5ghBInY95H9n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_b9f4425a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9f4425ad3f99e548342f9e281b1736776d9cd8d32728e2d6ee5e9caccda6acb"
    family = "Mirai"
    file_name = "fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:43:01"
  condition:
    hash.sha256(0, filesize) == "b9f4425ad3f99e548342f9e281b1736776d9cd8d32728e2d6ee5e9caccda6acb"
}
```

### Sample 37: `717ef4a13841aa27`

| Field | Value |
|---|---|
| SHA-256 | `717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961` |
| Family label | `unknown` |
| File name | `717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961.bin` |
| File type | `exe` |
| First seen | `2026-08-19 00:42:43` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11f472e21a050d7c1e95bb99c395727e` |
| SHA-1 | `82f8e25a1887573edb5a833d8248b323337a12f8` |
| SHA-256 | `717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961` |
| SHA3-384 | `9b7d826854cdc37e2d1017d0100b7231c9b21cfd176571db32f4efab0b0ebb5ccc2e6ee31d5c6a79782b1aa872943ef0` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T128569C5B7CD445EAD06A533289B761927BB1BC090FB623D72E90B3782FB66D48C79700` |
| SSDEEP | `49152:nmgMvWP8/8HMHLb1E//7cJ6rEZM2ft5mJT:nzL7vH7cJ6rEmuS1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_717ef4a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961"
    family = "unknown"
    file_name = "717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961.bin"
    file_type = "exe"
    first_seen = "2026-08-19 00:42:43"
  condition:
    hash.sha256(0, filesize) == "717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961"
}
```

### Sample 38: `fe8633eacbc02ea8`

| Field | Value |
|---|---|
| SHA-256 | `fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7` |
| Family label | `Mirai` |
| File name | `fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:40:32` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45beac48e010baed4b298d0a3f778880` |
| SHA-1 | `bc603ce8485324376897ea4bb9bc92a782e75db3` |
| SHA-256 | `fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7` |
| SHA3-384 | `7d295614b1d5d31f9c7236b62f45127cebe7008d93bfd048b598a8f814659cc55366a08d1016350e8a6de9819e47fa7e` |
| TLSH | `T1FF43F17692EEDA08D4E10D72EA3B4341FF932AB4E4E7112E97502335FBD509426E2653` |
| SSDEEP | `1536:Lsl+iUwf1ga0UruroLTRSAGcI5cwHkyNfW:LslIQg8KryJGciNN+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_fe8633ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7"
    family = "Mirai"
    file_name = "fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:40:32"
  condition:
    hash.sha256(0, filesize) == "fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7"
}
```

### Sample 39: `8e4c5d232d6a1d98`

| Field | Value |
|---|---|
| SHA-256 | `8e4c5d232d6a1d98d88a52565379f1c8e85fe297910fc4d4f526a0f0375932a5` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:40:18` |
| Reporter | `iamaachum` |
| Tags | `downtown886-com, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8f68066b2e990d00aafc93f7b5f6156` |
| SHA-1 | `fe9a45c7562567ba191ff6c79a375c7ee8af3a65` |
| SHA-256 | `8e4c5d232d6a1d98d88a52565379f1c8e85fe297910fc4d4f526a0f0375932a5` |
| SHA3-384 | `df43d828354f814e338989d9cd4f863e34f579d4b858868b8b1679a462049cfd05665291251773d6add2f001f757c0e5` |
| IMPHASH | `5fdc5e227e7d3c8edf3426ebcd607dda` |
| TLSH | `T15CC4F106F75904E9D029C1B9959A1666B7F37C019B20A5EF03A4864B2F27BC46F3EF24` |
| SSDEEP | `12288:6b971VO6Ym9FT0CrZXt9HmlZs/ekTODtA:y77ZZ9TXmie5A` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_8e4c5d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e4c5d232d6a1d98d88a52565379f1c8e85fe297910fc4d4f526a0f0375932a5"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:40:18"
  condition:
    hash.sha256(0, filesize) == "8e4c5d232d6a1d98d88a52565379f1c8e85fe297910fc4d4f526a0f0375932a5"
}
```

### Sample 40: `bbad922cd7ad33f2`

| Field | Value |
|---|---|
| SHA-256 | `bbad922cd7ad33f2592c001d0956491d873ed2270766e0f0f81c8adc076c8307` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:39:24` |
| Reporter | `iamaachum` |
| Tags | `45-115-27-4, AsgardProtector, exe, SunWukong, VorishkaStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c24fe5ae59d1369775d162697d52e370` |
| SHA-1 | `dd2387171456dcf0a516d546b9afcddead39868b` |
| SHA-256 | `bbad922cd7ad33f2592c001d0956491d873ed2270766e0f0f81c8adc076c8307` |
| SHA3-384 | `e6d99159d3b2e5e0eccde85ea72ce3dc322687cb524a80a6be95746d7555280b3f12a19b328287a4828d530d28ffd66b` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T142B5234342D8A028E1766736CDB2608712707D9B6BB8A5CF3B94BA0A3E73DD1D539707` |
| SSDEEP | `49152:bUHBjeYsjkZ6oOW/iXDML3GjoO/Qfidly7ZcK8I:bGByxW/iXIOQfiuZcK` |
| ICON-DHASH | `90b0f061b2b27171` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_bbad922c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbad922cd7ad33f2592c001d0956491d873ed2270766e0f0f81c8adc076c8307"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:39:24"
  condition:
    hash.sha256(0, filesize) == "bbad922cd7ad33f2592c001d0956491d873ed2270766e0f0f81c8adc076c8307"
}
```

### Sample 41: `9f4e92d43db6f77f`

| Field | Value |
|---|---|
| SHA-256 | `9f4e92d43db6f77fc3b5e7a764afb703ed327e595ff693bde6e03d7eb0e1cf19` |
| Family label | `SnappyClient` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:38:14` |
| Reporter | `iamaachum` |
| Tags | `exe, HijackLoader, SnappyClient, Vidar, YodaTeam` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `677d3e43a0ee2b00841b8e6eacb4f2b3` |
| SHA-1 | `14881a228c7220a44369127c85f64071627b5f22` |
| SHA-256 | `9f4e92d43db6f77fc3b5e7a764afb703ed327e595ff693bde6e03d7eb0e1cf19` |
| SHA3-384 | `b80280bed361a4693d44abfa22e98652a516acb180ae1ac06c8deac11bee046e3260985b7421ef5e407b20d191d6db82` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T1B0863341738862FFC1B1EC329F06EB825176D7EA1120AF474A992D181ED33BA77435DA` |
| SSDEEP | `196608:+pxrLLQ8TE+rOVhRj15/GgLkJSnm8UAdmap3x8wrdBUx:+pxM8DOHRjPGg/UAdRZx8wrdOx` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_041_9f4e92d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f4e92d43db6f77fc3b5e7a764afb703ed327e595ff693bde6e03d7eb0e1cf19"
    family = "SnappyClient"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:38:14"
  condition:
    hash.sha256(0, filesize) == "9f4e92d43db6f77fc3b5e7a764afb703ed327e595ff693bde6e03d7eb0e1cf19"
}
```

### Sample 42: `f79604e3722ffb8f`

| Field | Value |
|---|---|
| SHA-256 | `f79604e3722ffb8ffceed3bfe383a159ea9471475e4809b10071dcc7a9e28443` |
| Family label | `Mirai` |
| File name | `b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:37:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2ab24f6fbda8152459a1a1393cb6846` |
| SHA-1 | `d59366e4ce7d21408ff955520896f5f88a17ce53` |
| SHA-256 | `f79604e3722ffb8ffceed3bfe383a159ea9471475e4809b10071dcc7a9e28443` |
| SHA3-384 | `f6bc2a00791dd5f38c05ff4ee779b4863ed97364b87a3e556e2c7bd3a8e2081b88ab85e4cca161f07c2d902a87f109f5` |
| TLSH | `T132045C49BE746AFBC06FCE30052E830722DD945FA2F577796678CD4CB9AA20819F3854` |
| TELFHASH | `t12631c0f04b7b55125ac5c7ec84ec775a591e8515470adf33fd2180bc50260ade22ad4f` |
| SSDEEP | `3072:64j2vPDBbR5gF//FkPXTQkHSGCBrdGwOw9gzWmX7TyElW8Y5C1DM:lsLBbR5gt/FkPXkkHSGordGwOw9gztT8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_f79604e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f79604e3722ffb8ffceed3bfe383a159ea9471475e4809b10071dcc7a9e28443"
    family = "Mirai"
    file_name = "b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:37:03"
  condition:
    hash.sha256(0, filesize) == "f79604e3722ffb8ffceed3bfe383a159ea9471475e4809b10071dcc7a9e28443"
}
```

### Sample 43: `484d5188d6b19207`

| Field | Value |
|---|---|
| SHA-256 | `484d5188d6b19207e282fde9669f21985121631be18709a44ff6ae591da8c667` |
| Family label | `Mirai` |
| File name | `d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:37:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36cd2218121644f3057c26eebf229a54` |
| SHA-1 | `679b61d239fbe9b9aa5e8e10f16fc251349440b0` |
| SHA-256 | `484d5188d6b19207e282fde9669f21985121631be18709a44ff6ae591da8c667` |
| SHA3-384 | `91d843a8f355822742ad27b908ee4dc008293f101d8cec1888fa8db5cdef8d34a0aad4543cdc6ff4e84fbdd729de5a0d` |
| TLSH | `T1D004184F7710DF61C36CCA3009B38B4666E526522AE1C889F21CDE08BE6534DB96FED5` |
| TELFHASH | `t12631c0f04b7b55125ac5c7ec84ec775a591e8515470adf33fd2180bc50260ade22ad4f` |
| SSDEEP | `3072:yxvalRsKZ8bfpFJeTTN1i9JGCxLh94s23LQa028BAfRW1x1yoLIo1DEjP:aEi9Jlxt94sOXVEvE8IeOP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_484d5188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "484d5188d6b19207e282fde9669f21985121631be18709a44ff6ae591da8c667"
    family = "Mirai"
    file_name = "d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:37:00"
  condition:
    hash.sha256(0, filesize) == "484d5188d6b19207e282fde9669f21985121631be18709a44ff6ae591da8c667"
}
```

### Sample 44: `11f2e69de5bdeb0e`

| Field | Value |
|---|---|
| SHA-256 | `11f2e69de5bdeb0e8f71ad3964477297734f98e6cd477ee989f6697a734a0353` |
| Family label | `Mirai` |
| File name | `c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:36:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `116e62e05cdfa0c15d30c994b5ef8b70` |
| SHA-1 | `35eb8a7b4327b3e62f1a834d9e27d08d47322cd4` |
| SHA-256 | `11f2e69de5bdeb0e8f71ad3964477297734f98e6cd477ee989f6697a734a0353` |
| SHA3-384 | `34a16e14dca152e1d5b36e7bb731041d7626340504a6cdc24f1edd6c8d749ca0aba89ad420a8ee2fb348581b87f5642f` |
| TLSH | `T1AEC32AA9F880DE52C6C52676FB5E418C33231778D3DA7105CE109E35F7EB96A0E3A942` |
| SSDEEP | `3072:qRWr6nfMaK4UEo1EcYEEURVAKWpiOTvLIV0e1sEEWFOl2haf1Dr:qoAfb0EcYEEURVAphjLKB1sIK+a9n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_11f2e69d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f2e69de5bdeb0e8f71ad3964477297734f98e6cd477ee989f6697a734a0353"
    family = "Mirai"
    file_name = "c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:36:56"
  condition:
    hash.sha256(0, filesize) == "11f2e69de5bdeb0e8f71ad3964477297734f98e6cd477ee989f6697a734a0353"
}
```

### Sample 45: `306d872116c5e56b`

| Field | Value |
|---|---|
| SHA-256 | `306d872116c5e56b79bc547a55a8eaec496eee7e9229a17f864d7f068d6be2fc` |
| Family label | `Mirai` |
| File name | `0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:36:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b832166c6c90e33200e7c06c5257aace` |
| SHA-1 | `c53038b06035651ebae8443ce3e505c88e73635c` |
| SHA-256 | `306d872116c5e56b79bc547a55a8eaec496eee7e9229a17f864d7f068d6be2fc` |
| SHA3-384 | `ecee311ea1175e21518087b8fc680707f7c49ff6b008ee65e345978d416e825ef32c04db9dc3099ab8713afcad549548` |
| TLSH | `T1CAC34B06769144FCC16AC074C77FA937EA31785D13343ABE6784BB31AE22E761B0AB51` |
| SSDEEP | `3072:eT3WE/FtGArAzADd8aAk+4JevxdI6G4SXk:eTvtGcd8ax+4JCI6kU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_306d8721
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "306d872116c5e56b79bc547a55a8eaec496eee7e9229a17f864d7f068d6be2fc"
    family = "Mirai"
    file_name = "0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:36:52"
  condition:
    hash.sha256(0, filesize) == "306d872116c5e56b79bc547a55a8eaec496eee7e9229a17f864d7f068d6be2fc"
}
```

### Sample 46: `82b1a5ffdf569695`

| Field | Value |
|---|---|
| SHA-256 | `82b1a5ffdf569695f522537b98a78aa0dc655b7700efdbe80e1e664891cf709c` |
| Family label | `unknown` |
| File name | `FLTLIB.DLL` |
| File type | `exe` |
| First seen | `2026-08-19 00:36:19` |
| Reporter | `iamaachum` |
| Tags | `dll, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `987ea6e787945b049b32c1bdb31b54aa` |
| SHA-1 | `da97a8cfeeecbc1af4d034bb877f9558840a4fe3` |
| SHA-256 | `82b1a5ffdf569695f522537b98a78aa0dc655b7700efdbe80e1e664891cf709c` |
| SHA3-384 | `ba210664b7fb28333840a795dd114ab2a6a95835f793d4cdb3e12c32913be9ccbbd62dc10627cdae158ce9d7322d8385` |
| IMPHASH | `2d4dda0786e1ceafdd51569972dea026` |
| TLSH | `T1D5778C05A39705ABD436DAF8CA3492F2F2B37D524636814B0959F63F1F73A504B3BA21` |
| SSDEEP | `196608:gBw90Fzm+TtnKz7Puu0cRzOeYT9UMeN/I5usq:gBw90FvTiT0S6eYTOMepxl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_82b1a5ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82b1a5ffdf569695f522537b98a78aa0dc655b7700efdbe80e1e664891cf709c"
    family = "unknown"
    file_name = "FLTLIB.DLL"
    file_type = "exe"
    first_seen = "2026-08-19 00:36:19"
  condition:
    hash.sha256(0, filesize) == "82b1a5ffdf569695f522537b98a78aa0dc655b7700efdbe80e1e664891cf709c"
}
```

### Sample 47: `b05f75e7fad53ada`

| Field | Value |
|---|---|
| SHA-256 | `b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50` |
| Family label | `Mirai` |
| File name | `b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:35:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ae5c75d86c951fb6440c170d607b090` |
| SHA-1 | `197e7c028d66e1b9f008ffa61616b7f30676395f` |
| SHA-256 | `b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50` |
| SHA3-384 | `3ebe18e3e45b843b876bc9f178f97cdcd70109627955652878533223afb26d2de03ab64002eb3ea3973a630786ad55ab` |
| TLSH | `T1CA8302058B1C93CFF721A6B07573C06869B19B0DEFE565127EF96B802F054BFD14A4A2` |
| SSDEEP | `1536:CCdpMFjT7JrO/RUhg5JonsdlK4in0XVQJxpg7xTVFjKZn7bfLbEh09:5Lg0vEns/K4+0XaJxpgdJdG7rLwh09` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_b05f75e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50"
    family = "Mirai"
    file_name = "b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:35:42"
  condition:
    hash.sha256(0, filesize) == "b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50"
}
```

### Sample 48: `d2e3ab888135b450`

| Field | Value |
|---|---|
| SHA-256 | `d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8` |
| Family label | `Mirai` |
| File name | `d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:35:38` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1790552c750a9b0eead1f632c0f25e75` |
| SHA-1 | `5af93022b684f726026e7675e02ee20c623fd334` |
| SHA-256 | `d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8` |
| SHA3-384 | `f7c67d7b9e20cbde7b594d7fc46f7c268dffbca8407e5e43af924b1afb1798f9060080d97c2497d27e140631931983e5` |
| TLSH | `T1BA830249D6364FA1ECD712B0065D1C647B5393963C2FD25F0BD8C0A732AB4B8AAAE701` |
| SSDEEP | `1536:6qz9E2XrGxVyFfxUaOvU+ltQKssKc4Mr4zMwKp5j4UTq3uuBY0krOeQWqX:6YbrWVMS5tEv4wKPZn0krvy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_d2e3ab88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8"
    family = "Mirai"
    file_name = "d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:35:38"
  condition:
    hash.sha256(0, filesize) == "d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8"
}
```

### Sample 49: `c244f5419125b94d`

| Field | Value |
|---|---|
| SHA-256 | `c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808` |
| Family label | `Mirai` |
| File name | `c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:35:34` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8f9e2dfb21ed146ae9b7d9f77b72c42` |
| SHA-1 | `1560b63282dda0ec3a89b1b6c44a6d6481a23140` |
| SHA-256 | `c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808` |
| SHA3-384 | `f472f156958e07dfe3de71232837d1ab953d695cb44c6f4d0567cac13e925276bb532654069e9ea31462cedcd60148ae` |
| TLSH | `T11B43F1C299117B81C5B0AC7CFC27D506AAC395BE632F308573027E79B281E197776972` |
| SSDEEP | `1536:KlY4zgLOy5k2R6xgYhP2mnCvc9wmZ4gAYeiH6fQ:KlYOyk2RLCPnCvc9XZS4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_c244f541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808"
    family = "Mirai"
    file_name = "c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:35:34"
  condition:
    hash.sha256(0, filesize) == "c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808"
}
```

### Sample 50: `41aa2a9f47277b32`

| Field | Value |
|---|---|
| SHA-256 | `41aa2a9f47277b32efbb369b5b92c79d444d3c524cd55142d9e85603ddea3478` |
| Family label | `unknown` |
| File name | `FLStudio2025_v248_Win.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:35:32` |
| Reporter | `iamaachum` |
| Tags | `exe, Stealc, svhost-update-service-casa` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdf69e3345e9e518a03633c28358268b` |
| SHA-1 | `687ce6f9816eb8ad80f532ba2c832cf5476bdca0` |
| SHA-256 | `41aa2a9f47277b32efbb369b5b92c79d444d3c524cd55142d9e85603ddea3478` |
| SHA3-384 | `ddfd782f92432bb2466800bba244324904d77c849ad90c8e30c6cd3c1b7bfe98f1ebe66b09bc82e457aabaa047b2551e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T174651258336BDC06C5295F741C31E3F81FB85D98A561E2039EEABFEBB935A0068152C7` |
| SSDEEP | `24576:h4d+K3jGBJ8sRJWmMFbXZUUlwvuQOKs/NvRDmZ6fcmAOEiDwrggF8bwQR+io:h4d+6jG8sRJWNZTlFx/9RDOmjcMuQRa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_41aa2a9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41aa2a9f47277b32efbb369b5b92c79d444d3c524cd55142d9e85603ddea3478"
    family = "unknown"
    file_name = "FLStudio2025_v248_Win.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:35:32"
  condition:
    hash.sha256(0, filesize) == "41aa2a9f47277b32efbb369b5b92c79d444d3c524cd55142d9e85603ddea3478"
}
```

### Sample 51: `0482f7f1e2ebca3b`

| Field | Value |
|---|---|
| SHA-256 | `0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6` |
| Family label | `Mirai` |
| File name | `0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:35:31` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0fc30870f1efa8feb54efb4af2a23e30` |
| SHA-1 | `647bfc12449078d7331fb132b2dac3023ed3d905` |
| SHA-256 | `0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6` |
| SHA3-384 | `fc040abc3e75e28b07a1dfefe2d761109cb6544161bdea1cb10b28adcfa0013c79018c9031e0ac7cf83a0e671f6de871` |
| TLSH | `T1935302D4F377A9BCC62AA0315BA9E1C0DEC63C5DDA518E271035237F4D62C0A7394B66` |
| SSDEEP | `1536:Etg8iC2jvaTIM+fpxFW48OGuyBft9QBnfpJewMuiU4872gsGJ0:Em8iTLakHjW48UUV4fepuiU41Jv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_0482f7f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6"
    family = "Mirai"
    file_name = "0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:35:31"
  condition:
    hash.sha256(0, filesize) == "0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6"
}
```

### Sample 52: `be21ec6879ddc945`

| Field | Value |
|---|---|
| SHA-256 | `be21ec6879ddc9457fb48e2da6fe49a4208ded546205b3a161c358dcb016e38f` |
| Family label | `unknown` |
| File name | `vsdbg.dll` |
| File type | `exe` |
| First seen | `2026-08-19 00:33:08` |
| Reporter | `iamaachum` |
| Tags | `2-26-126-50, BlakcSeeStealer, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `036259e69237fb1d81f8f741a720db99` |
| SHA-1 | `4db30b3e8128d8262c7d9401d53b46f9e39e849d` |
| SHA-256 | `be21ec6879ddc9457fb48e2da6fe49a4208ded546205b3a161c358dcb016e38f` |
| SHA3-384 | `4e0d79f96053fdb3d9a2b6028af5001435fdbdc9b6648eb34b3fa1a15ea4e839d4f54614e470982dcc5216815949adc6` |
| IMPHASH | `94b3832211c2f09ccf19c03c6134422f` |
| TLSH | `T18957BF18A3E40465E86BEB38C661D733DAB1BC665636C20F0969F6460F73E508F6F721` |
| SSDEEP | `393216:AydtckjjXfD1ae7UIHQ0pt9Ni9qI19kxIGElTvOZHfostIk14kVkeG2vxZETfK8:pHQuhWt18IGOaZ/os+kVFG+sC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_be21ec68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be21ec6879ddc9457fb48e2da6fe49a4208ded546205b3a161c358dcb016e38f"
    family = "unknown"
    file_name = "vsdbg.dll"
    file_type = "exe"
    first_seen = "2026-08-19 00:33:08"
  condition:
    hash.sha256(0, filesize) == "be21ec6879ddc9457fb48e2da6fe49a4208ded546205b3a161c358dcb016e38f"
}
```

### Sample 53: `04c037e735415a02`

| Field | Value |
|---|---|
| SHA-256 | `04c037e735415a021da6cd41990f090cc7691b089680c18057e707c9b1fd5efa` |
| Family label | `Mirai` |
| File name | `5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:31:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdab19ddb03edf6f9aae9f90be2b33b2` |
| SHA-1 | `44b29ba87bb43b2cf419e9763006a9260e703556` |
| SHA-256 | `04c037e735415a021da6cd41990f090cc7691b089680c18057e707c9b1fd5efa` |
| SHA3-384 | `5df7992852927f25481056fd6847bd463a1ef7191dd8fc3e774db01f526398ef3063060aee6c33e5978ddc57bbf88b5e` |
| TLSH | `T10EC32AA9F880DE52C6C52676FB5E418C33231778D3DA7105CE109E35F7EB96A0E3A942` |
| SSDEEP | `3072:qRWr6nfMaK4UEo1EcYEEURVAKWpiOTvLIV0e1sEEWFOl2htf1Dr:qoAfb0EcYEEURVAphjLKB1sIK+t9n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_04c037e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04c037e735415a021da6cd41990f090cc7691b089680c18057e707c9b1fd5efa"
    family = "Mirai"
    file_name = "5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:31:53"
  condition:
    hash.sha256(0, filesize) == "04c037e735415a021da6cd41990f090cc7691b089680c18057e707c9b1fd5efa"
}
```

### Sample 54: `2e21eb201f4735ef`

| Field | Value |
|---|---|
| SHA-256 | `2e21eb201f4735eff29e9018b1b6918a384d6fe9189e9d477e5d1625dfbfa45b` |
| Family label | `Mirai` |
| File name | `46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:31:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `085bae89ed60f3a0932971c5c72f99f5` |
| SHA-1 | `2f79ae6d2fc3194de8390921a93a27a1a0018655` |
| SHA-256 | `2e21eb201f4735eff29e9018b1b6918a384d6fe9189e9d477e5d1625dfbfa45b` |
| SHA3-384 | `b7c6100449864406f217273e1a89e357391d2c9479216f7dac6a067c1188aadc40e01e2d18b3e55e1db4634464b0021e` |
| TLSH | `T159C32AA9F880DE52C6C52676FB5E418C33231778D3DA7105CE109E35F7EB96A0E3A942` |
| SSDEEP | `3072:qRWr6nfMaK4UEo1EcYEEURVAKWpiOTvLIV0e1sEEWFOl2hUf1Dr:qoAfb0EcYEEURVAphjLKB1sIK+U9n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_2e21eb20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e21eb201f4735eff29e9018b1b6918a384d6fe9189e9d477e5d1625dfbfa45b"
    family = "Mirai"
    file_name = "46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:31:50"
  condition:
    hash.sha256(0, filesize) == "2e21eb201f4735eff29e9018b1b6918a384d6fe9189e9d477e5d1625dfbfa45b"
}
```

### Sample 55: `0ecbba5d1aa1cfb3`

| Field | Value |
|---|---|
| SHA-256 | `0ecbba5d1aa1cfb32e96df6d6d7854929353733668ad1134256ec0451dc1a1da` |
| Family label | `unknown` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:31:45` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, windowsof-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6dfc4bbd11e3ca3f9e4e25876fe6b932` |
| SHA-1 | `90a7c111e85d486d07ef1035ae25a2bf92693100` |
| SHA-256 | `0ecbba5d1aa1cfb32e96df6d6d7854929353733668ad1134256ec0451dc1a1da` |
| SHA3-384 | `6b0b912a0e630d6a0c13e8e4f95d07071b8ff8afd3736c651a865e5856a1fbfe85facddb1f3475d2c507980f81cfc61f` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1F5564917BC5500A5C5EAD630C9764252BA30BC894B3433E72F62BAB82F777D46EB9740` |
| SSDEEP | `49152:sC9Ep/JeFSUPtrb/TyvO90d7HjmAFd4A64nsfJan3fmYZMQfbB3C5bgxsEj64LZL:2JeFSmatFkgxl2Wv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_0ecbba5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ecbba5d1aa1cfb32e96df6d6d7854929353733668ad1134256ec0451dc1a1da"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:31:45"
  condition:
    hash.sha256(0, filesize) == "0ecbba5d1aa1cfb32e96df6d6d7854929353733668ad1134256ec0451dc1a1da"
}
```

### Sample 56: `5d50a9324e9651f8`

| Field | Value |
|---|---|
| SHA-256 | `5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895` |
| Family label | `Mirai` |
| File name | `5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:30:37` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e3bc0f01cb6e77f79da56bd8c871d25` |
| SHA-1 | `1a1e5f7838f5eb692a9297b8f45bef1586943449` |
| SHA-256 | `5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895` |
| SHA3-384 | `de4cba56298a09c65d03c885fd08e2ceedcfabef1d127cf64bc93846ac44e4a5877b42227bb9dc1bc20728842807bc5f` |
| TLSH | `T1FA4302C2A6417A42C1E07C79FC27D905A9C794AD632F34457312AEBDF2C190673766B2` |
| SSDEEP | `1536:KlY4zgLOy5k2R6xgYhP2mnCvc9wmZ4g9p6dYfi:KlYOyk2RLCPnCvc9XZPp6dYq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_5d50a932
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895"
    family = "Mirai"
    file_name = "5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:30:37"
  condition:
    hash.sha256(0, filesize) == "5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895"
}
```

### Sample 57: `46726bc3c76a5727`

| Field | Value |
|---|---|
| SHA-256 | `46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf` |
| Family label | `Mirai` |
| File name | `46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:30:32` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f6a5e40d15db55b14400ede3298dd29` |
| SHA-1 | `887c7a9587d0d114e9d9ac41455e96c65d85acb7` |
| SHA-256 | `46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf` |
| SHA3-384 | `d8276a350297fcfd2dc1a7e940796bbd34886eded7adfea596a842757c6e08c73b74297d90e21c0271f3018f781a7ee8` |
| TLSH | `T1814301C296567A42C1A07C7CFC17D9067AC684AD631F3446B312BE7EB2C1E1932778B2` |
| SSDEEP | `1536:KlY4zgLOy5k2R6xgYhP2mnCvc9wmZ4gMPXfR:KlYOyk2RLCPnCvc9XZuPX5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_46726bc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf"
    family = "Mirai"
    file_name = "46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:30:32"
  condition:
    hash.sha256(0, filesize) == "46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf"
}
```

### Sample 58: `2ecf04b3f0010391`

| Field | Value |
|---|---|
| SHA-256 | `2ecf04b3f001039184d841dd067d6e47bf192047ffe6b92c72a9d57bda6c6afe` |
| Family label | `unknown` |
| File name | `?????.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:28:14` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ffeee5993c69e77a2553981ee2f9ea0` |
| SHA-1 | `b149646eae65f70490466a0b196f659a192f8e8b` |
| SHA-256 | `2ecf04b3f001039184d841dd067d6e47bf192047ffe6b92c72a9d57bda6c6afe` |
| SHA3-384 | `c2c5e17f22085c3be0bf99ff11350c02e6a1da0d7d08ed216c167d6dbc1c08d2eb615f01d084b77f6111ee8514af26f3` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1BC564A17FD6510A5C5EAD630C5764212BA30BC894B3433E32FA2BAB82F767D05EB9744` |
| SSDEEP | `49152:2uOVA6kgGE2C8rb/TTvO90d7HjmAFd4A64nsfJPsuLplRcJ0HjEUbP0geMtD3q3c:XgGEhUS3q3DvY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_2ecf04b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ecf04b3f001039184d841dd067d6e47bf192047ffe6b92c72a9d57bda6c6afe"
    family = "unknown"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:28:14"
  condition:
    hash.sha256(0, filesize) == "2ecf04b3f001039184d841dd067d6e47bf192047ffe6b92c72a9d57bda6c6afe"
}
```

### Sample 59: `64494586d79711a0`

| Field | Value |
|---|---|
| SHA-256 | `64494586d79711a0c12ad714f5f895a5d14200247cc02f0434f2bcd8b3b8002f` |
| Family label | `unknown` |
| File name | `ws-Setup-Complete.exe` |
| File type | `exe` |
| First seen | `2026-08-19 00:27:23` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, cdn-falconworks-cc, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5bd609ef62c5df53951f7c703f3bc42` |
| SHA-1 | `14b278902d4bd280d6cc89225437aff7984edbf6` |
| SHA-256 | `64494586d79711a0c12ad714f5f895a5d14200247cc02f0434f2bcd8b3b8002f` |
| SHA3-384 | `ff5e1efc65bb1822580d31fc6ab481092dafaa4e8b5aead81dbf203fc239ae3f246a7f799eb71f386d033c62a4d70d52` |
| IMPHASH | `682698ea78be8d2edcfadd8b96c3e30b` |
| TLSH | `T125B51245F7C282F2DD43993235AFF32F1B225E068D31C7DAE7E94D5A68A3780165B182` |
| SSDEEP | `49152:hgT7q72H/ahzCiw1jjht3C01X1N/A5Wj7TT5tSNH3VBGP4Y+Hd/t/:yTeCHi1I3zl1//5gNXVBGyd/t/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_64494586
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64494586d79711a0c12ad714f5f895a5d14200247cc02f0434f2bcd8b3b8002f"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:27:23"
  condition:
    hash.sha256(0, filesize) == "64494586d79711a0c12ad714f5f895a5d14200247cc02f0434f2bcd8b3b8002f"
}
```

### Sample 60: `172a1ed27fd5acad`

| Field | Value |
|---|---|
| SHA-256 | `172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273` |
| Family label | `Mirai` |
| File name | `172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:25:29` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c59f33b66c8041176ef32e6d755f8c2` |
| SHA-1 | `c4ef72dba201c8b02e9790ef588546fff0924969` |
| SHA-256 | `172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273` |
| SHA3-384 | `0d682745bb930706b3370aec6d3927fa7e8f607ab2e513a8995762a126961c4477436671737d2f1a4695911c409d78bb` |
| TLSH | `T1E4C36CC5B20C7E9EE5836E3CC20653176E0CAE40DC53950150B9FA53DAB76E72E26AC7` |
| TELFHASH | `t1d8e061f1978fa282028ccbcd83c9339c0a0cd001004bef03fd22443c80a081cb85988f` |
| SSDEEP | `3072:SGghiUk8Psr6RlmwIchMomQcHtpv2HXyzQLLjYov:SGlGsmWwIIMomZjv2HCzQXxv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_172a1ed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273"
    family = "Mirai"
    file_name = "172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:25:29"
  condition:
    hash.sha256(0, filesize) == "172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273"
}
```

### Sample 61: `1d65b76219f184a4`

| Field | Value |
|---|---|
| SHA-256 | `1d65b76219f184a4fc87d597b0ae50e2ef6f98a79558448b0f0868f761c5479f` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-19 00:22:20` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX3.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20b825c30a115515fc513b78f686a646` |
| SHA-1 | `56aaabe7c67573359adb2b73befb59503376e839` |
| SHA-256 | `1d65b76219f184a4fc87d597b0ae50e2ef6f98a79558448b0f0868f761c5479f` |
| SHA3-384 | `70b3a3738b063fa3c131e4d74998f9f029150c36384b1f2a3ce515c5b5c2048fde1e8c89fa7f3b1c843a266f67cf54a2` |
| IMPHASH | `1a093efe6f9d6f1f8c4a69f5bba32ce1` |
| TLSH | `T1E1547D29B76514FADE67853CC8424505EA72BC164BA0EBCF03E04A972F277D09E3E751` |
| SSDEEP | `6144:ntbKS7Wqb64y5iB2iRy+JveKdi2HIikE:tbKqnbHys2iBvFiu` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_061_1d65b762
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d65b76219f184a4fc87d597b0ae50e2ef6f98a79558448b0f0868f761c5479f"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-19 00:22:20"
  condition:
    hash.sha256(0, filesize) == "1d65b76219f184a4fc87d597b0ae50e2ef6f98a79558448b0f0868f761c5479f"
}
```

### Sample 62: `8e4de934b467663b`

| Field | Value |
|---|---|
| SHA-256 | `8e4de934b467663ba2d56bb8de0f643afc38d51e7ec2396abfcebc48d66a2909` |
| Family label | `Mirai` |
| File name | `4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:21:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03de5bd6ea5c4e69899bcfa605dff2f7` |
| SHA-1 | `b88fafb175a0d2ed1b899513daeeb9e52c587578` |
| SHA-256 | `8e4de934b467663ba2d56bb8de0f643afc38d51e7ec2396abfcebc48d66a2909` |
| SHA3-384 | `92f3a78506ade6b914bbe7bb87edfcbc9a771d7d9f2c0299ba633647d2522381111928ea27c163c31520f978fc806741` |
| TLSH | `T13C04294F7710DF61D369C93009B3CB9656E926622AE28449F31CDE08BE6434DA82FFD5` |
| TELFHASH | `t1ff31e0f09b3b65019b89c7ec85ecb74a591e85020706df33fe3180bc80260ade229d4f` |
| SSDEEP | `3072:kx1njY8VJOYpMMiqa6w74hrUBaR1sND3GR1DijI:MXVJLpMMiqJwUGgXozGnEI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_8e4de934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e4de934b467663ba2d56bb8de0f643afc38d51e7ec2396abfcebc48d66a2909"
    family = "Mirai"
    file_name = "4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:21:10"
  condition:
    hash.sha256(0, filesize) == "8e4de934b467663ba2d56bb8de0f643afc38d51e7ec2396abfcebc48d66a2909"
}
```

### Sample 63: `4cc97ea7fddc5faf`

| Field | Value |
|---|---|
| SHA-256 | `4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f` |
| Family label | `Mirai` |
| File name | `4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:20:31` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fd67d099b738aedae852ab04887ec5b` |
| SHA-1 | `4aa7f166c08589f64e2b3083e1c15f6f5d06449c` |
| SHA-256 | `4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f` |
| SHA3-384 | `b5332293e6a513c2e808663724479b31c565f3de334bb8fe7b95a079e9737defe61b84a9748b21b1316fb638951aebdd` |
| TLSH | `T179730180694298FED864B0F9BA6783B1FE226F40C141DC564593ADC2DF11A5A327FDD2` |
| SSDEEP | `1536:4YyUZQgXGJPeONAXl97OxbU2jz/ejpwDTJh2gbcV1cbKsBOI:4GZTWJPI197OOSz/ejGDTJh2CcV1cKPI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_4cc97ea7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f"
    family = "Mirai"
    file_name = "4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:20:31"
  condition:
    hash.sha256(0, filesize) == "4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f"
}
```

### Sample 64: `937904cca4fd1a67`

| Field | Value |
|---|---|
| SHA-256 | `937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88` |
| Family label | `unknown` |
| File name | `937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88.bin` |
| File type | `exe` |
| First seen | `2026-08-19 00:19:51` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9aebfd3ecb2d662dccc70919f1f66205` |
| SHA-1 | `3a3cdce168ec5930d1df827adf86680df78cc7bf` |
| SHA-256 | `937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88` |
| SHA3-384 | `f561c3b21eaae41a2ee30af3c1ad72bab505d5436b5ff15fe4312e3d9ea447868bc7d5fbf5f801bf6972a8a4d5145709` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T174366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaa9:uc3XND1aJrCOk9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_937904cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88"
    family = "unknown"
    file_name = "937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88.bin"
    file_type = "exe"
    first_seen = "2026-08-19 00:19:51"
  condition:
    hash.sha256(0, filesize) == "937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88"
}
```

### Sample 65: `50422a847e0c1c2c`

| Field | Value |
|---|---|
| SHA-256 | `50422a847e0c1c2c7e47336bbf9aab79285ba549dffe279dc4697e707c05f464` |
| Family label | `Mirai` |
| File name | `0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:16:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d8bb30591e6f60d94d5a31f935db29c` |
| SHA-1 | `2c3cc0a647fe8fab444a1c7437fe72a9cae6972f` |
| SHA-256 | `50422a847e0c1c2c7e47336bbf9aab79285ba549dffe279dc4697e707c05f464` |
| SHA3-384 | `3fedbe727af3951cc380567f1ba53560d8f69121e73cad60dea64941447fc4844c5ac028b4f6fc3ffa85fc225f6c3eb9` |
| TLSH | `T1EEE35B59FA5BC0F0D6D340F5062BEBAA963799212132F5B1FF563BB1F8B1301698522C` |
| SSDEEP | `3072:4bc3rQsk1lHEs1c1Eo455aCMylWIW/Hh/:4bc3rQPDHVfocB3l0P` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_50422a84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50422a847e0c1c2c7e47336bbf9aab79285ba549dffe279dc4697e707c05f464"
    family = "Mirai"
    file_name = "0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:16:50"
  condition:
    hash.sha256(0, filesize) == "50422a847e0c1c2c7e47336bbf9aab79285ba549dffe279dc4697e707c05f464"
}
```

### Sample 66: `0dd5d379001fe6a6`

| Field | Value |
|---|---|
| SHA-256 | `0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2` |
| Family label | `Mirai` |
| File name | `0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:16:19` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `133f07b704b05cf4adf0fb49d0ed978a` |
| SHA-1 | `0001dbd841e88e4656043a7c0208effeb41227c9` |
| SHA-256 | `0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2` |
| SHA3-384 | `cc9ce4bb69838f9c264077cd7f4588f8d067ad28c66d4cfc7356f5cdd43756d3b107bb13048ed3e9faf4587eab406706` |
| TLSH | `T15A53F256AE666EACE09C5C733CE93C57605CEF05E4414BDB6548A437A836E78CA483C3` |
| SSDEEP | `1536:actRMl+XD7oWkKLVZlmF8nUyw+CYhx2YTx03xnouy8DMd:FYl+z7oWkAvlmF4wRYhx2cKxoutDMd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_0dd5d379
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2"
    family = "Mirai"
    file_name = "0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:16:19"
  condition:
    hash.sha256(0, filesize) == "0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2"
}
```

### Sample 67: `86a894fe150c8f70`

| Field | Value |
|---|---|
| SHA-256 | `86a894fe150c8f706c6bd428e391c98259bc1153d99920d5cc0b84b8db688b0a` |
| Family label | `ValleyRAT` |
| File name | `3F54292A6F4F5B36BB0549C20992E880.dll` |
| File type | `dll` |
| First seen | `2026-08-19 00:15:14` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f54292a6f4f5b36bb0549c20992e880` |
| SHA-1 | `dcef980be7a248549cf431f224de54811c188183` |
| SHA-256 | `86a894fe150c8f706c6bd428e391c98259bc1153d99920d5cc0b84b8db688b0a` |
| SHA3-384 | `06d8781231118c14ef7c697f35261a803d77af849944d7087c6c06c0474fe85be8f48d6660ee70e9dbde14ef8123da3d` |
| IMPHASH | `015ade0acc2769b31f99b52582ac5d1a` |
| TLSH | `T13546CF173E5C00A6E05A1133CEA9B6E8F1AEBDF83B76019715A0BB1DFD32741CA1456B` |
| SSDEEP | `98304:HZ450y5i1sSv66fjpSBRzPTq0ULToBoa+A7Z4OiZrq1DfPHNADtV6v+zM+rwroDH:HaT8iRzPTq0UQBFt7Z4O7NADtV6v+zZE` |
| ICON-DHASH | `798e960f3396cc71` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_067_86a894fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86a894fe150c8f706c6bd428e391c98259bc1153d99920d5cc0b84b8db688b0a"
    family = "ValleyRAT"
    file_name = "3F54292A6F4F5B36BB0549C20992E880.dll"
    file_type = "dll"
    first_seen = "2026-08-19 00:15:14"
  condition:
    hash.sha256(0, filesize) == "86a894fe150c8f706c6bd428e391c98259bc1153d99920d5cc0b84b8db688b0a"
}
```

### Sample 68: `3980f39b92f36760`

| Field | Value |
|---|---|
| SHA-256 | `3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84` |
| Family label | `Mirai` |
| File name | `3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84.elf` |
| File type | `elf` |
| First seen | `2026-08-19 00:05:58` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37457ac8428b6430915d55f7c3e54c2e` |
| SHA-1 | `eac2bd886706d0a181d330c12191a41b25122a0d` |
| SHA-256 | `3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84` |
| SHA3-384 | `c81a9a7f43cb3082c73fe2623784d789ecdd56e045fb67f951965a2dbd217133fce922304b642deb75b6cdc9e0f5831b` |
| TLSH | `T19473198AB842A625C6C557B7FA1F018D331567D8D1DE33078D252F607BCA82F0E67B49` |
| TELFHASH | `t14c41bb6b9f750b9e4be4844481cee42a6bee308a1e5a2c42c91c730fc943343b42d92b` |
| SSDEEP | `1536:hSOoQfpVYFnod5iSuWfObiOVuO5cZv8t46AxZWlsF6LD:MOoQfpVYFaGXfy984Xxesa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_3980f39b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84"
    family = "Mirai"
    file_name = "3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:05:58"
  condition:
    hash.sha256(0, filesize) == "3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84"
}
```

### Sample 69: `64cda56c20ff6fce`

| Field | Value |
|---|---|
| SHA-256 | `64cda56c20ff6fce786658487df0881fabaa99776d5fc90836fcfaffbf1a24cf` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-19 00:03:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87904f7edcd21ca34fb8aba7e4b738d8` |
| SHA-1 | `71be6e8e9cbafeb546dc161cfa1f3cedc6e7fde2` |
| SHA-256 | `64cda56c20ff6fce786658487df0881fabaa99776d5fc90836fcfaffbf1a24cf` |
| SHA3-384 | `48c8f1cd69b6ff089648f5b881696b88e7636ef621ebf73978c4860b5b570c532c95b7038767568caf95d1a021291788` |
| TLSH | `T1A0147E00FB181913C5935DB41B7B0776E3798D4318B9F019290E7B568B33AFB9A87B86` |
| SSDEEP | `6144:ctXioCbGtY049YcyRF/yAoOyH56rY6kOby:q9Cb39YBp9O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_64cda56c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64cda56c20ff6fce786658487df0881fabaa99776d5fc90836fcfaffbf1a24cf"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-19 00:03:36"
  condition:
    hash.sha256(0, filesize) == "64cda56c20ff6fce786658487df0881fabaa99776d5fc90836fcfaffbf1a24cf"
}
```

### Sample 70: `37b38b9303be79f3`

| Field | Value |
|---|---|
| SHA-256 | `37b38b9303be79f30f74f7c0247ab5c6850c5ce16c4740e6b8273d6cfd926200` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-19 00:03:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d8c58fe0d6cb0bf2eeaa9ad0adbd160` |
| SHA-1 | `1ea0f833304323a8c40fd6ab62ee26132fcad99a` |
| SHA-256 | `37b38b9303be79f30f74f7c0247ab5c6850c5ce16c4740e6b8273d6cfd926200` |
| SHA3-384 | `760aa7cb581dc498c2685c742c6668888dd16306de9bad79df3a941b53dbaf9b306f552f3d9c55b29da78b5a6b86492f` |
| TLSH | `T15A5302E2D1DC5D21EC9EA0FA284CE38967D097AF3615C9A31F90AF550C57C3A39D0AA0` |
| SSDEEP | `1536:JyFV0mrwBcMPFZGUs6cy4nJ3I1w4PgjWuyH5no/aReIC4u+qgw0rL:ggmrmcMNZriTnJR4PKyH5nEa8IC4u+qY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_37b38b93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37b38b9303be79f30f74f7c0247ab5c6850c5ce16c4740e6b8273d6cfd926200"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-19 00:03:02"
  condition:
    hash.sha256(0, filesize) == "37b38b9303be79f30f74f7c0247ab5c6850c5ce16c4740e6b8273d6cfd926200"
}
```

### Sample 71: `951b00329104e147`

| Field | Value |
|---|---|
| SHA-256 | `951b00329104e1478887898169e968de2c1ccd0a6dce0cf54abc0c4c9d8934a4` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-18 23:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56e8f08e636abf907dc9629cf9d2a4ab` |
| SHA-256 | `951b00329104e1478887898169e968de2c1ccd0a6dce0cf54abc0c4c9d8934a4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_951b0032
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "951b00329104e1478887898169e968de2c1ccd0a6dce0cf54abc0c4c9d8934a4"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-18 23:52:09"
  condition:
    hash.sha256(0, filesize) == "951b00329104e1478887898169e968de2c1ccd0a6dce0cf54abc0c4c9d8934a4"
}
```

### Sample 72: `4f1512771f67829f`

| Field | Value |
|---|---|
| SHA-256 | `4f1512771f67829fa9f8ec1e0478f8bdfdb618ba9e84e92f2e987b2c6937532e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-18 23:42:52` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `990467946afd093549bdcf627c095342` |
| SHA-256 | `4f1512771f67829fa9f8ec1e0478f8bdfdb618ba9e84e92f2e987b2c6937532e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_4f151277
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f1512771f67829fa9f8ec1e0478f8bdfdb618ba9e84e92f2e987b2c6937532e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-18 23:42:52"
  condition:
    hash.sha256(0, filesize) == "4f1512771f67829fa9f8ec1e0478f8bdfdb618ba9e84e92f2e987b2c6937532e"
}
```

### Sample 73: `5ec6e9a22b3537e0`

| Field | Value |
|---|---|
| SHA-256 | `5ec6e9a22b3537e04d7d45b7ceecb9b715a3657aa537e1e3758e9cf13e1d5161` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-18 23:42:44` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9e58170d63e502eb360646b667e17e6` |
| SHA-256 | `5ec6e9a22b3537e04d7d45b7ceecb9b715a3657aa537e1e3758e9cf13e1d5161` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_5ec6e9a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ec6e9a22b3537e04d7d45b7ceecb9b715a3657aa537e1e3758e9cf13e1d5161"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-18 23:42:44"
  condition:
    hash.sha256(0, filesize) == "5ec6e9a22b3537e04d7d45b7ceecb9b715a3657aa537e1e3758e9cf13e1d5161"
}
```

### Sample 74: `565c7e58d69911df`

| Field | Value |
|---|---|
| SHA-256 | `565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f` |
| Family label | `unknown` |
| File name | `565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f.bin` |
| File type | `exe` |
| First seen | `2026-08-18 23:31:12` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4292346b14958dd443108324bd284d6f` |
| SHA-1 | `20f05a0d0a4c0c193c0facac5ea937e422260f56` |
| SHA-256 | `565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f` |
| SHA3-384 | `a1fffa806635b44e4d9462c6f3178ae18164634f1c53bf7626c4dbdc4807363acb3aba168a1eb3d52fdb7556e87ace44` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T11F268B13BD4510B4C19AD638C53B6363B624BC894B3477D31F51AAB42FB2BC4AEB9B44` |
| SSDEEP | `98304:AXlSVac9axfHtvnju09vKTqfM3liFVXT6:EoJaxfHtvna09vKTqfM3lb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_565c7e58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f"
    family = "unknown"
    file_name = "565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f.bin"
    file_type = "exe"
    first_seen = "2026-08-18 23:31:12"
  condition:
    hash.sha256(0, filesize) == "565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f"
}
```

### Sample 75: `dfa0e88fa2c28581`

| Field | Value |
|---|---|
| SHA-256 | `dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a` |
| Family label | `unknown` |
| File name | `dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a.bin` |
| File type | `exe` |
| First seen | `2026-08-18 23:31:10` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f885c439c08d1e6ae554339d0f1bc3b` |
| SHA-1 | `f97a4e0c8f38544f38140ea05c87356e57f619ee` |
| SHA-256 | `dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a` |
| SHA3-384 | `fd10df325e2a5b207a62c3af31df3fe19498a8c61dd665e6df9cec1bea42017b871a98e572570d164bf200285d2d33a5` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1A1369C43BD95A0A4C4EED63485725251B730B8894B3033E72E52FBB92E337C45EB9B94` |
| SSDEEP | `49152:oKWw3S279zxZKgrb/TNvO90d7HjmAFd4A64nsfJFoBn/sB6NpokBZKpl9TOkAbOp:r79z/zMA6tjYN8W6CasRZi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_dfa0e88f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a"
    family = "unknown"
    file_name = "dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a.bin"
    file_type = "exe"
    first_seen = "2026-08-18 23:31:10"
  condition:
    hash.sha256(0, filesize) == "dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a"
}
```

### Sample 76: `1c129e9920c0d948`

| Field | Value |
|---|---|
| SHA-256 | `1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251` |
| Family label | `unknown` |
| File name | `1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251.bin` |
| File type | `exe` |
| First seen | `2026-08-18 23:31:07` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52bdbdd795fe564af2f8f235e2d6153f` |
| SHA-1 | `0ae02d81e043c5c878f743b75c17c17f65ed6d3f` |
| SHA-256 | `1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251` |
| SHA3-384 | `a9300ebef8cae81c07fc7b9039f42f5b59da9ef3ac614555109f7b1a1e2ed7a3c18dd6d1d45b7cdf63b0b9884b49539b` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T14B668C17FD5510A5C6EAE734C5728222B630B8894B3477E32FA1BAB82F767C45E78740` |
| SSDEEP | `49152:Iph1ZbR4xtUrb/TjvO90d7HjmAFd4A64nsfJEwh6rdicQl1bjQLuQU7a5FOsip9X:wR4xtZimatKS5Gmyv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_1c129e99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251"
    family = "unknown"
    file_name = "1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251.bin"
    file_type = "exe"
    first_seen = "2026-08-18 23:31:07"
  condition:
    hash.sha256(0, filesize) == "1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251"
}
```

### Sample 77: `68fb701f506aa2e5`

| Field | Value |
|---|---|
| SHA-256 | `68fb701f506aa2e51ebe43730167ea0d34a48539aaf0ed62c4de118dd9c2d53f` |
| Family label | `unknown` |
| File name | `main.x86-64-v4` |
| File type | `elf` |
| First seen | `2026-08-18 23:18:21` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f16cce520a49f74bf63ed26fe1970f3a` |
| SHA-1 | `d398dfcdf96143969254d9266134990e08f47d4e` |
| SHA-256 | `68fb701f506aa2e51ebe43730167ea0d34a48539aaf0ed62c4de118dd9c2d53f` |
| SHA3-384 | `83fe8bb241994983505921a30ad158499a3b7a5f150519226b9dcb55ca21c0393261468bfc91229765fba84719071ba2` |
| TLSH | `T11D530916B6E3B0BCD297C0745A5AD9F2BA317CA402213E7F97C8FA312D35D006B59E61` |
| TELFHASH | `t196218071095d38e1b1a7e6167355e1718c35191622e032f2c67ab9facf62f421bb1c33` |
| SSDEEP | `1536:PJ1QWo6gVfWJji6FkO4IT+NOQEqHf+h3z6JhzFUr:xzGQJji6aO4iq2Sc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_68fb701f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68fb701f506aa2e51ebe43730167ea0d34a48539aaf0ed62c4de118dd9c2d53f"
    family = "unknown"
    file_name = "main.x86-64-v4"
    file_type = "elf"
    first_seen = "2026-08-18 23:18:21"
  condition:
    hash.sha256(0, filesize) == "68fb701f506aa2e51ebe43730167ea0d34a48539aaf0ed62c4de118dd9c2d53f"
}
```

### Sample 78: `100e0977f68d28b7`

| Field | Value |
|---|---|
| SHA-256 | `100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5` |
| Family label | `unknown` |
| File name | `100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5` |
| File type | `sh` |
| First seen | `2026-08-18 23:00:10` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd261f26a2ea571e0232728b220692be` |
| SHA-1 | `8381ef55e7cdaf2134c4ad3ee4106139279391c4` |
| SHA-256 | `100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5` |
| SHA3-384 | `aeec00386a91d42066ac74ad35159e08a9fa5d2924cfa7da712f461db35a4d5c70527c6f02c1ec5fa5f4d3532934914d` |
| TLSH | `T1FE11718F25700AB303A9C49876D71800E83340AF6646C714EE56CEDE79111A0B9FCF6E` |
| SSDEEP | `24:Q4RxG7Z+7V4j4XlUw7qHOdSIOJBXxZg3SIQkRmWLY:qC1qH8SIEBxyi9kRmWc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_100e0977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5"
    family = "unknown"
    file_name = "100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5"
    file_type = "sh"
    first_seen = "2026-08-18 23:00:10"
  condition:
    hash.sha256(0, filesize) == "100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5"
}
```

### Sample 79: `8910f0cb2eb97c3b`

| Field | Value |
|---|---|
| SHA-256 | `8910f0cb2eb97c3b1ced8b512bb34884a958ba7d81829841b2e60eb487157662` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-08-18 22:52:18` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, app-api-embervault-cc, AsgardProtector, dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55ecbb206e755651ddc70297948d8753` |
| SHA-1 | `6539df0786d917bd699e0b197a1b6f90bfc592dd` |
| SHA-256 | `8910f0cb2eb97c3b1ced8b512bb34884a958ba7d81829841b2e60eb487157662` |
| SHA3-384 | `dd7e18d7f5ccd0ed408c59fd5ba93a8480b7c144d379796c1c706e6f5edbe457a401fde3255d6768b39fc0288e60034c` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T12395236013F4C4A5ECB657B598F74E63967078025A3EA7CF35E69D4A2F272C4893130E` |
| SSDEEP | `49152:og5kN/EgqxZczQWaHD5IpLvjj+Zsln3jjNqm3:owoEzIpSal3jxqi` |
| ICON-DHASH | `03e08e2727c3c64a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_8910f0cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8910f0cb2eb97c3b1ced8b512bb34884a958ba7d81829841b2e60eb487157662"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-18 22:52:18"
  condition:
    hash.sha256(0, filesize) == "8910f0cb2eb97c3b1ced8b512bb34884a958ba7d81829841b2e60eb487157662"
}
```

### Sample 80: `c5cf2b566923f4b6`

| Field | Value |
|---|---|
| SHA-256 | `c5cf2b566923f4b635dc09f80d3bd20e8b61a517967e38553fb179e594e931ce` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-18 22:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `750b4ec044f78af684385f2d4656e511` |
| SHA-256 | `c5cf2b566923f4b635dc09f80d3bd20e8b61a517967e38553fb179e594e931ce` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_c5cf2b56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5cf2b566923f4b635dc09f80d3bd20e8b61a517967e38553fb179e594e931ce"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-18 22:52:13"
  condition:
    hash.sha256(0, filesize) == "c5cf2b566923f4b635dc09f80d3bd20e8b61a517967e38553fb179e594e931ce"
}
```

### Sample 81: `870101471c67e4a0`

| Field | Value |
|---|---|
| SHA-256 | `870101471c67e4a08b5172e0cc700933f44645bcd097801516c1df02a69d5da7` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-08-18 22:50:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4629b4646ec203282e7dbc4e3cc5c8d7` |
| SHA-1 | `2d165be9ad05cc0b5d1311e0c2cefd8b99ede05b` |
| SHA-256 | `870101471c67e4a08b5172e0cc700933f44645bcd097801516c1df02a69d5da7` |
| SHA3-384 | `0d2352e6e3ced8b5205b8ddbb7982d55908b7e4e4932b60e7ac21852411770cd03a9f5882cd36208f75ccfb446a414fa` |
| TLSH | `T11C832B816A46CEB7D8831BB502F397360531F83A0F2EDE86E72DFCB56A425C87516358` |
| TELFHASH | `t12031ec36977102166a51cc24dcee57f1252d86272748ee73ef36c5cc641a09ae227c4f` |
| SSDEEP | `1536:ShZerRy3lVDKvfb9IZG4R9bdx6eQaP++CMq32UFSTGhk15uJnaroXfIFTcuwM9:Shqo3lVDKbd4brP+zf2UMT2M5OIdHwM9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_87010147
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870101471c67e4a08b5172e0cc700933f44645bcd097801516c1df02a69d5da7"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-18 22:50:41"
  condition:
    hash.sha256(0, filesize) == "870101471c67e4a08b5172e0cc700933f44645bcd097801516c1df02a69d5da7"
}
```

### Sample 82: `1ae15ba98f8c31b8`

| Field | Value |
|---|---|
| SHA-256 | `1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3` |
| Family label | `unknown` |
| File name | `1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3.exe` |
| File type | `exe` |
| First seen | `2026-08-18 22:45:50` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8cb2299faae4544ddb2082db2b491ae7` |
| SHA-1 | `bcb5a18c7e334dd56cf7c0f77d1c82da02d1de2e` |
| SHA-256 | `1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3` |
| SHA3-384 | `7047b900c84a2a997529e7cae8a0ba2f57f82f8f7689db39f2e8d45ba35dc9a53e9d265d0a6a6f5cff3a4aef3fa85ecd` |
| IMPHASH | `b8048b8957358587b4fda264349e8f60` |
| TLSH | `T1E3D5226A38F22A70D47AC3728F43E07E717E3B918A668D5777D839005E02698AC77375` |
| SSDEEP | `49152:CguA2SZfAc07lbP46s6kVKVHB8sxJNSd+C5LWuDxKt/LI+7oziS8QvAkiVj2mV8t:Cg92l71P4ckVK9B8s80CdbDuv7o9XriC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_1ae15ba9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3"
    family = "unknown"
    file_name = "1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3.exe"
    file_type = "exe"
    first_seen = "2026-08-18 22:45:50"
  condition:
    hash.sha256(0, filesize) == "1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3"
}
```

### Sample 83: `8034c27ec7cff773`

| Field | Value |
|---|---|
| SHA-256 | `8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1` |
| Family label | `unknown` |
| File name | `8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1.exe` |
| File type | `exe` |
| First seen | `2026-08-18 22:45:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f639cf42cd1dca4841a17cd4bbf774d` |
| SHA-1 | `724dc8fd55a0e7875198f470eaac6833e07f2518` |
| SHA-256 | `8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1` |
| SHA3-384 | `3d573c2ef08ce7775564233b29cfb72452fe4704b3f53fbacff980ef82727771b43e1b88384fd8af2e75de13c9ae1f78` |
| IMPHASH | `24e8765fd838d429e6f908cdeb96c2d6` |
| TLSH | `T1DBD5238AFDF219B1E47BC7BA95C3706EB129BB4047244C577A8CEB006E524983D76339` |
| SSDEEP | `49152:PCNgXbtDkeIo5MaColDlLTJEF+B51Wn/r0J4fsAPdydhPJdx2aVkQe5:7hDZ0FaDlLTVB5a/rNFWhrx2uc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_8034c27e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1"
    family = "unknown"
    file_name = "8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1.exe"
    file_type = "exe"
    first_seen = "2026-08-18 22:45:45"
  condition:
    hash.sha256(0, filesize) == "8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1"
}
```

### Sample 84: `787f169a719e78bc`

| Field | Value |
|---|---|
| SHA-256 | `787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197` |
| Family label | `Vidar` |
| File name | `787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197.bin` |
| File type | `exe` |
| First seen | `2026-08-18 22:43:15` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68edc179300bbd24798773b1362111a3` |
| SHA-1 | `245d18548672cd138776b165d57dc59c94fc8e6b` |
| SHA-256 | `787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197` |
| SHA3-384 | `7c3aee8f89165f727f67c6c9e068ce09730f3db507e0296ea5db1a1632bb494280a102777a5b2eb0b567e6554e0355fc` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1FF166B07AE9148F5C4AAE735C8B79256B734B8484B3533D72E60AEB82F713C15E39B44` |
| SSDEEP | `49152:iP15i2WrRclY+b68X9GUNq0RXCqKt64NR5sVElzIxo5wn9:iDgS68NlNHC56c5KE+N` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_084_787f169a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197"
    family = "Vidar"
    file_name = "787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197.bin"
    file_type = "exe"
    first_seen = "2026-08-18 22:43:15"
  condition:
    hash.sha256(0, filesize) == "787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197"
}
```

### Sample 85: `6aba832d095cf909`

| Field | Value |
|---|---|
| SHA-256 | `6aba832d095cf90906b34335f698bee1debe024ce3422375ee9394aea94dc934` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-18 22:34:44` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6699cdad824d4e21964db174cb9622d2` |
| SHA-1 | `6d8bf8874c0ac7dddc63370689cab279f92c9d3e` |
| SHA-256 | `6aba832d095cf90906b34335f698bee1debe024ce3422375ee9394aea94dc934` |
| SHA3-384 | `d698c10e2f66b5860a9ad3a3b4526920bb68572eae7a7cab168ad8e77798c38a78cc55cd57562019c036db0789d54e3d` |
| IMPHASH | `8308f72a4cb5fd67d7f3ce32fdc32584` |
| TLSH | `T182464C05BA6B94ACD15BC47483068A639E2170DF1B36BAFF018486783F6ABF15B3D714` |
| SSDEEP | `98304:NjbltFqoOFYQlOdda0WH8JvwvRhCYAvX:3dG/` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_085_6aba832d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aba832d095cf90906b34335f698bee1debe024ce3422375ee9394aea94dc934"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 22:34:44"
  condition:
    hash.sha256(0, filesize) == "6aba832d095cf90906b34335f698bee1debe024ce3422375ee9394aea94dc934"
}
```

### Sample 86: `58373b38eeae8828`

| Field | Value |
|---|---|
| SHA-256 | `58373b38eeae8828e8b9b660942c74e6b1ab0fc62799d1e7e228670f7838be95` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-18 22:26:31` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX1.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61c8d09c13a669f8bf9b7bed9c957d65` |
| SHA-1 | `c435c1f68a84d5933ec60ae02188c0e4fb404da1` |
| SHA-256 | `58373b38eeae8828e8b9b660942c74e6b1ab0fc62799d1e7e228670f7838be95` |
| SHA3-384 | `d58ae75a3f6a62552942ee70296f90d5da9e4284e692667d614cb71b044a7909adf8e59b02334896dae2f11a69b50c56` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T14826C44F28557054E49A8E35A0760271B764FC78C73C23EF2E9CE6B41E262C35A67F92` |
| SSDEEP | `49152:Lyx5leVprhFYfSx6Blc5u3YoYFMfRvCJblTwFvFja:yOjUz5RvCJblMC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_58373b38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58373b38eeae8828e8b9b660942c74e6b1ab0fc62799d1e7e228670f7838be95"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 22:26:31"
  condition:
    hash.sha256(0, filesize) == "58373b38eeae8828e8b9b660942c74e6b1ab0fc62799d1e7e228670f7838be95"
}
```

### Sample 87: `38aba4040537b204`

| Field | Value |
|---|---|
| SHA-256 | `38aba4040537b20450e78092d79b4a9bd92eab8814842d6ecd1cad93e8f6a6ab` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-18 21:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05907edac4616717ee10ec7aea10b92d` |
| SHA-256 | `38aba4040537b20450e78092d79b4a9bd92eab8814842d6ecd1cad93e8f6a6ab` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_38aba404
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38aba4040537b20450e78092d79b4a9bd92eab8814842d6ecd1cad93e8f6a6ab"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-18 21:52:11"
  condition:
    hash.sha256(0, filesize) == "38aba4040537b20450e78092d79b4a9bd92eab8814842d6ecd1cad93e8f6a6ab"
}
```

### Sample 88: `7e0be7ce68bfeaeb`

| Field | Value |
|---|---|
| SHA-256 | `7e0be7ce68bfeaeb2e461f6aa1b15163f68fb928b82f9c811bc3047caabb694b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-18 21:42:25` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7a1eb0cbaf9f03ac781c84404055723` |
| SHA-256 | `7e0be7ce68bfeaeb2e461f6aa1b15163f68fb928b82f9c811bc3047caabb694b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_7e0be7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e0be7ce68bfeaeb2e461f6aa1b15163f68fb928b82f9c811bc3047caabb694b"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-18 21:42:25"
  condition:
    hash.sha256(0, filesize) == "7e0be7ce68bfeaeb2e461f6aa1b15163f68fb928b82f9c811bc3047caabb694b"
}
```

### Sample 89: `e1c28de1482b14ac`

| Field | Value |
|---|---|
| SHA-256 | `e1c28de1482b14ac76cb710339a1bebd76243bc78fcee1ef02194b5bc11194a6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-18 21:42:17` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `670b8088fb655eeb9578874bbe953ed4` |
| SHA-256 | `e1c28de1482b14ac76cb710339a1bebd76243bc78fcee1ef02194b5bc11194a6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_e1c28de1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1c28de1482b14ac76cb710339a1bebd76243bc78fcee1ef02194b5bc11194a6"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-18 21:42:17"
  condition:
    hash.sha256(0, filesize) == "e1c28de1482b14ac76cb710339a1bebd76243bc78fcee1ef02194b5bc11194a6"
}
```

### Sample 90: `8f33056539a54c26`

| Field | Value |
|---|---|
| SHA-256 | `8f33056539a54c26e62296cd29b267659a4c250fe8dbec61575863daac044b1e` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-18 21:32:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d719a048062e50a0d1e70152021bf874` |
| SHA-1 | `63142120f16a950cc1d010133b1c4688635a9f6d` |
| SHA-256 | `8f33056539a54c26e62296cd29b267659a4c250fe8dbec61575863daac044b1e` |
| SHA3-384 | `406439bf8a88d03e1357d36c10ed8a86ed4980bab470dde3eede46a0637d8c673155d47c25f62de4353443d8bd8aecf8` |
| TLSH | `T1EA04194E3710CF61C76DC93009B3CB4666F526512AE28849F36CDE08AE6534DB96FED8` |
| TELFHASH | `t102319db08b7b65115ac5c7ec88ec775a591a8515470adf33fd2180bc50260ade22ad4f` |
| SSDEEP | `3072:15dzatGNtrQQ8Pcglx1dXXGObhCpXRTI5amHk2lD5NBM6pAy1DajA:wHXWObspBI4h6DvWUAoEA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_8f330565
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f33056539a54c26e62296cd29b267659a4c250fe8dbec61575863daac044b1e"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-18 21:32:43"
  condition:
    hash.sha256(0, filesize) == "8f33056539a54c26e62296cd29b267659a4c250fe8dbec61575863daac044b1e"
}
```

### Sample 91: `f13850c06490d3b5`

| Field | Value |
|---|---|
| SHA-256 | `f13850c06490d3b58ab165277428eb03da1ef715d125bb32c9150802d895fae3` |
| Family label | `Mirai` |
| File name | `726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909.elf` |
| File type | `elf` |
| First seen | `2026-08-18 21:32:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da5f49b789a0f0367d32d9559f37f97b` |
| SHA-1 | `c0020255d014c41f5eb0de8780b25845e8474750` |
| SHA-256 | `f13850c06490d3b58ab165277428eb03da1ef715d125bb32c9150802d895fae3` |
| SHA3-384 | `b8f08050e5045798735d171e9c387cbf1b95531c5f64f1992b7720706c7c76c50e33e99c6cf50107e4c40a2f104eaaf8` |
| TLSH | `T1B9C33A06769144FCC166C074877F9937EA31785D13343ABF6B84BA31AE22E365F0AB52` |
| SSDEEP | `3072:z8TnKcynnGAHAQAcmeEDEpmGw4FBrtG4VMMJ:z8T0nG4meAGlrtr3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_f13850c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f13850c06490d3b58ab165277428eb03da1ef715d125bb32c9150802d895fae3"
    family = "Mirai"
    file_name = "726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909.elf"
    file_type = "elf"
    first_seen = "2026-08-18 21:32:41"
  condition:
    hash.sha256(0, filesize) == "f13850c06490d3b58ab165277428eb03da1ef715d125bb32c9150802d895fae3"
}
```

### Sample 92: `66445c49af8308ae`

| Field | Value |
|---|---|
| SHA-256 | `66445c49af8308aecd8f34f6b758daeb53c15964115b0fc2bdcc1fff285ff45f` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-18 21:31:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0ec343a05868a9ba7a61e2857c68d38` |
| SHA-1 | `42dc6f410df64768eeccc19bf91e6025434f7dc7` |
| SHA-256 | `66445c49af8308aecd8f34f6b758daeb53c15964115b0fc2bdcc1fff285ff45f` |
| SHA3-384 | `aacdbbc5899c1b00f5b4a60356527b6f385ef60725d5aa1ba1fec5a3a9ab631c7591bfe62653f5a09b462270b635199c` |
| TLSH | `T1FB8302B1DE324276FE35A0F91634DE5579942A023F1CD71C5AB676B8288333D84AAF60` |
| SSDEEP | `1536:jKNXmLq7ENT08M12RLxgKCDq6l0d4RgZoFmiaj4JzeR3ZbOAwiM5/USCvDeeQdB:jK9+q7I/jRLE/l0d4yZhttR3JOAwDUVK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_66445c49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66445c49af8308aecd8f34f6b758daeb53c15964115b0fc2bdcc1fff285ff45f"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-18 21:31:48"
  condition:
    hash.sha256(0, filesize) == "66445c49af8308aecd8f34f6b758daeb53c15964115b0fc2bdcc1fff285ff45f"
}
```

### Sample 93: `726cea848f900ffe`

| Field | Value |
|---|---|
| SHA-256 | `726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909` |
| Family label | `Mirai` |
| File name | `726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909.elf` |
| File type | `elf` |
| First seen | `2026-08-18 21:31:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c6714a0bee18ba1bad2f2f492a9da18` |
| SHA-1 | `c9b4708efbb635e71e1fa726bff0aadf8273afed` |
| SHA-256 | `726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909` |
| SHA3-384 | `64205ae623ba55ae3a505ec4aa64f084a84042f61c4eb816f1f266ba8d2f7b471c619076be642cb9ebbc458bb32cadb1` |
| TLSH | `T10E53F1F233257FF8CC461A39C6370184E23AFC6ABA54879B19E2937AD5B8705B160B50` |
| SSDEEP | `1536:H1iyGfYN+pylhWawj6lsliDd1S7345v1O7PISsIOK:VbJNThWa460AI73QvmPIgOK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_726cea84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909"
    family = "Mirai"
    file_name = "726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909.elf"
    file_type = "elf"
    first_seen = "2026-08-18 21:31:16"
  condition:
    hash.sha256(0, filesize) == "726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909"
}
```

### Sample 94: `83fee7d8d646273f`

| Field | Value |
|---|---|
| SHA-256 | `83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689` |
| Family label | `Mirai` |
| File name | `83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689.elf` |
| File type | `elf` |
| First seen | `2026-08-18 21:31:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b296b81c7738107158ce9d2d39414de` |
| SHA-1 | `153f70b82a8cb366bc37c758107a836b89095b2f` |
| SHA-256 | `83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689` |
| SHA3-384 | `64626e7beff63366ac2d96664c856a2cf5ebe4924dabefd1f2a9cf62db271a705e5191214a72c31d0746d23ef84c9188` |
| TLSH | `T1B0C36BC5B20D3E9EE4832E7CC20657135E1C9E509C83450190B9FA57DAB76E72E36ACB` |
| TELFHASH | `t1c5e0b1f1878fa205458dcbcd83c9779c1a0dd145004bef13fd62553c816091cb95998f` |
| SSDEEP | `3072:TD8QEsxYJHSDjPHbXemqykacP467qSveL338QLLjyonkMd:TD8Q4SDbHbGPacPjhveLn8QXvnkm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_83fee7d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689"
    family = "Mirai"
    file_name = "83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689.elf"
    file_type = "elf"
    first_seen = "2026-08-18 21:31:11"
  condition:
    hash.sha256(0, filesize) == "83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689"
}
```

### Sample 95: `067a0c37ea6a7b25`

| Field | Value |
|---|---|
| SHA-256 | `067a0c37ea6a7b2553f7d136582f06aea334b55490c87d4fbfbec835d95242e8` |
| Family label | `Mirai` |
| File name | `flutter.x86` |
| File type | `elf` |
| First seen | `2026-08-18 21:29:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `467425a9275792fac07d2a64f13cfc98` |
| SHA-1 | `7def408e18bffc83cf84683ea82c7389fc844bdd` |
| SHA-256 | `067a0c37ea6a7b2553f7d136582f06aea334b55490c87d4fbfbec835d95242e8` |
| SHA3-384 | `a2125f656767aeacddf1d4f193f9f3cd6b0a9cbc25181cb6d44a9ea6f713f24873cb1a0dd663e1ca3d164ae2d2f3dd0b` |
| TLSH | `T100046C1BEA42F170E4738071515ADBB39A35A9344302C407FBA63F34EDB46C5E689B2E` |
| SSDEEP | `3072:HzQXystVg3Cr++VtOn2DrlQxAJFpIugpqtMXkBlOUWxlXGhaiGTXYlYavvBw:HzQXy3Cx+2DrWxuFpIugIlQW5CYQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_067a0c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "067a0c37ea6a7b2553f7d136582f06aea334b55490c87d4fbfbec835d95242e8"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-08-18 21:29:45"
  condition:
    hash.sha256(0, filesize) == "067a0c37ea6a7b2553f7d136582f06aea334b55490c87d4fbfbec835d95242e8"
}
```

### Sample 96: `ec810c58f343b42f`

| Field | Value |
|---|---|
| SHA-256 | `ec810c58f343b42f75cc2e6a24ce244702c2f6ded7ce7acf19eb02c02cdee5f9` |
| Family label | `Mirai` |
| File name | `flutter.x86` |
| File type | `elf` |
| First seen | `2026-08-18 21:29:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f64dac9f2b67b1356612fd9aae52405` |
| SHA-1 | `79fa94cc3d672d7615d607365f966fbbf9c049d3` |
| SHA-256 | `ec810c58f343b42f75cc2e6a24ce244702c2f6ded7ce7acf19eb02c02cdee5f9` |
| SHA3-384 | `53fc98b77c75e38348ca26223859805c77b8dabae6a944d8363a4f6bd21c4334ff3e1976238817656bf86a4ceba44739` |
| TLSH | `T19993120C9C5B8B1CE5A68A792ED570C72D6619B4C6A8017ABD310D4CF3B6640A33B7CF` |
| SSDEEP | `1536:bkpAzlsU4u1lVg0PBfMR58ylESrp8nFd06smrXlYUJJVF2yr/qtcUO4taAzM:bM4sU4u1lu0PBEH8y+0WFfTltVoKCqj7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_ec810c58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec810c58f343b42f75cc2e6a24ce244702c2f6ded7ce7acf19eb02c02cdee5f9"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-08-18 21:29:19"
  condition:
    hash.sha256(0, filesize) == "ec810c58f343b42f75cc2e6a24ce244702c2f6ded7ce7acf19eb02c02cdee5f9"
}
```

### Sample 97: `6764b21b8804275d`

| Field | Value |
|---|---|
| SHA-256 | `6764b21b8804275d8969b71eea7b5b3be3d4a6cc5878a05d251a3d7de77f9935` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-08-18 21:27:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73e803837eb17b480c83b9a4fd700273` |
| SHA-1 | `d310789259a83be7b565d9a7bbf2dd07e6edfc2a` |
| SHA-256 | `6764b21b8804275d8969b71eea7b5b3be3d4a6cc5878a05d251a3d7de77f9935` |
| SHA3-384 | `8c07e918566daecf5a403c8196c7a5610f0fa9b3f2c42c91bfe5de328cffcc3db0cb5caa570131325330822f4a88afb1` |
| TLSH | `T1D4C32AA9F890DE52C6C52676FB5E418C33231778D3DA7105CE109E34F7EB96A0E3A942` |
| SSDEEP | `3072:mJP2VStktVeEUiFiW/cYEEUZKdXHOjvLpf2Mj4eiCl0xTbCf1Dl:mMgOt5N/cYEEUZKdXuTLhBj4cUnC95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_6764b21b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6764b21b8804275d8969b71eea7b5b3be3d4a6cc5878a05d251a3d7de77f9935"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-18 21:27:53"
  condition:
    hash.sha256(0, filesize) == "6764b21b8804275d8969b71eea7b5b3be3d4a6cc5878a05d251a3d7de77f9935"
}
```

### Sample 98: `8a59d346ea1b71f3`

| Field | Value |
|---|---|
| SHA-256 | `8a59d346ea1b71f3d86c0b0335e6a2924de89bb5bdd38a0f25eb90c37a85ad1a` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-08-18 21:26:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb46ac270ff01eca50d098bbc07e1f03` |
| SHA-1 | `8832c2895b7320313f3a436490ec94fc85d7abe7` |
| SHA-256 | `8a59d346ea1b71f3d86c0b0335e6a2924de89bb5bdd38a0f25eb90c37a85ad1a` |
| SHA3-384 | `8c18493049c14dac6e3a9c5b2145aaef9e59c4d58cada598df8dedb978e1947b3b87ed361e3019ef16bc2b8dfde5ed2f` |
| TLSH | `T1CE430234841DACF2C589003FFEA5824A9E4146B8E82774349DED7B5735D69823F3BA87` |
| SSDEEP | `1536:5oLfG5KiejmQcOGEsyfWP4xp1YtawyUDfz:CLuwjGObfc4v1QyYL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_8a59d346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a59d346ea1b71f3d86c0b0335e6a2924de89bb5bdd38a0f25eb90c37a85ad1a"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-18 21:26:34"
  condition:
    hash.sha256(0, filesize) == "8a59d346ea1b71f3d86c0b0335e6a2924de89bb5bdd38a0f25eb90c37a85ad1a"
}
```

### Sample 99: `d4260a0d332b4d74`

| Field | Value |
|---|---|
| SHA-256 | `d4260a0d332b4d7442cb571fa036c82746fb123450ddac11257d328eae4c34a3` |
| Family label | `Mirai` |
| File name | `bot.spc` |
| File type | `elf` |
| First seen | `2026-08-18 21:26:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c9accb84a7b8e0a01ff4b4e6ede3f06` |
| SHA-1 | `f4fdb3a01066227764fc90d6873dfc9384215197` |
| SHA-256 | `d4260a0d332b4d7442cb571fa036c82746fb123450ddac11257d328eae4c34a3` |
| SHA3-384 | `9cbb45e863d3ed70b8a30c7c7ec419cfaf7fe2244bb5452bdbb7bf5769e959c9025362d4e5e1982cde4def1e7420b932` |
| TLSH | `T1F8832911A93A2A17C0E4957711F78325F2E2630E25B4CA3D7DB20F8FFF10B54695A6B2` |
| SSDEEP | `1536:u3GUP4HESWoKsJl7rzdbsEpqxnVIQZvaeAlTO:eGcsJl7rxsKWnVIQZXOK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_d4260a0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4260a0d332b4d7442cb571fa036c82746fb123450ddac11257d328eae4c34a3"
    family = "Mirai"
    file_name = "bot.spc"
    file_type = "elf"
    first_seen = "2026-08-18 21:26:33"
  condition:
    hash.sha256(0, filesize) == "d4260a0d332b4d7442cb571fa036c82746fb123450ddac11257d328eae4c34a3"
}
```

### Sample 100: `3069d54ae404f4b3`

| Field | Value |
|---|---|
| SHA-256 | `3069d54ae404f4b3c3465bd91e112bc622ef793f413eef812dd4c348438b9974` |
| Family label | `Mirai` |
| File name | `64fce8e35348bad4a580d70a12f4052bbf7a63d1e400ca6f964f7f630080534a.elf` |
| File type | `elf` |
| First seen | `2026-08-18 21:26:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0413fd20ea83610d684def75622fc96f` |
| SHA-1 | `afce5d4bac713e1d1baa8c4891ec2a935cfde632` |
| SHA-256 | `3069d54ae404f4b3c3465bd91e112bc622ef793f413eef812dd4c348438b9974` |
| SHA3-384 | `55174fef1bdcf68c9c6d64ef632260c6267b52990fc9e15b8512292c2f956a29ce1fb500a0cef18862109011460caa58` |
| TLSH | `T19EC32B99FC90DE12C6D52675F95E428D332317B8C3DA7106CE109F34B7E796A0E3A942` |
| SSDEEP | `3072:MPMelnNkCeAGoMiXPuWUQ4g8OKCjkjjNeNDRenS0Xg1Qf1DlP:MESeA3uWUQ4g8O3jkjGen5eQ95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_3069d54a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3069d54ae404f4b3c3465bd91e112bc622ef793f413eef812dd4c348438b9974"
    family = "Mirai"
    file_name = "64fce8e35348bad4a580d70a12f4052bbf7a63d1e400ca6f964f7f630080534a.elf"
    file_type = "elf"
    first_seen = "2026-08-18 21:26:31"
  condition:
    hash.sha256(0, filesize) == "3069d54ae404f4b3c3465bd91e112bc622ef793f413eef812dd4c348438b9974"
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
 * Generated: 2026-08-19T01:55:40.201058+00:00
 */

rule MalwareBazaar_unknown_001_e0b92c6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0b92c6a29b0f98e0bd3b348e4722b9e95eb66c3ca949207ebbca7ac889eb987"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 01:55:07"
  condition:
    hash.sha256(0, filesize) == "e0b92c6a29b0f98e0bd3b348e4722b9e95eb66c3ca949207ebbca7ac889eb987"
}

rule MalwareBazaar_unknown_002_c3cc65eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3cc65ebb8dee634758de9d96056b6c3246f95af67610ac79dae9d31b5789cab"
    family = "unknown"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:34"
  condition:
    hash.sha256(0, filesize) == "c3cc65ebb8dee634758de9d96056b6c3246f95af67610ac79dae9d31b5789cab"
}

rule MalwareBazaar_unknown_003_aa427253
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa4272539b9b637651ea999c3ea77c1ed7727d73e79876144849e71caadd3ecb"
    family = "unknown"
    file_name = "bot.arc"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:32"
  condition:
    hash.sha256(0, filesize) == "aa4272539b9b637651ea999c3ea77c1ed7727d73e79876144849e71caadd3ecb"
}

rule MalwareBazaar_unknown_004_806385c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "806385c4d1ce5fb675357095cb07a81e0a0aebe4962b66e5422e0000945c149d"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:31"
  condition:
    hash.sha256(0, filesize) == "806385c4d1ce5fb675357095cb07a81e0a0aebe4962b66e5422e0000945c149d"
}

rule MalwareBazaar_unknown_005_715778ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "715778aef73034eb2e87607d5c3c43b57993a9bb99296041191b8f2801943a3f"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:30"
  condition:
    hash.sha256(0, filesize) == "715778aef73034eb2e87607d5c3c43b57993a9bb99296041191b8f2801943a3f"
}

rule MalwareBazaar_unknown_006_3f14d76a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f14d76a13d76477bc2822af9d8bd6a6ccfc50fc1e40686414e00d5a600a3c38"
    family = "unknown"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:28"
  condition:
    hash.sha256(0, filesize) == "3f14d76a13d76477bc2822af9d8bd6a6ccfc50fc1e40686414e00d5a600a3c38"
}

rule MalwareBazaar_unknown_007_e52cca6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e52cca6f483ac515b68bccb39fb3103fe6f1162616965d0a0dc3dd0b985488e0"
    family = "unknown"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-19 01:54:27"
  condition:
    hash.sha256(0, filesize) == "e52cca6f483ac515b68bccb39fb3103fe6f1162616965d0a0dc3dd0b985488e0"
}

rule MalwareBazaar_unknown_008_b78985f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b78985f078be3124e50fa43e8cce7067692d26a63120b3e3f5f5954d69064b77"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-19 01:52:53"
  condition:
    hash.sha256(0, filesize) == "b78985f078be3124e50fa43e8cce7067692d26a63120b3e3f5f5954d69064b77"
}

rule MalwareBazaar_unknown_009_3dfcf989
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dfcf989589e4f2e46cad337be31ababc650446bf85afb935b57d7f04e416b11"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-19 01:52:49"
  condition:
    hash.sha256(0, filesize) == "3dfcf989589e4f2e46cad337be31ababc650446bf85afb935b57d7f04e416b11"
}

rule MalwareBazaar_unknown_010_e20fdbe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e20fdbe034b94a7eb72d7b5fa32bed5e7851503c97da05a6303ae6a744e05569"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-19 01:52:11"
  condition:
    hash.sha256(0, filesize) == "e20fdbe034b94a7eb72d7b5fa32bed5e7851503c97da05a6303ae6a744e05569"
}

rule MalwareBazaar_unknown_011_cb4efe99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb4efe99fbc11befd19e6eb33c1c29b00301429ddfb6864a10130dc7ac3eb5e0"
    family = "unknown"
    file_name = "flutter.mipsel"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:46"
  condition:
    hash.sha256(0, filesize) == "cb4efe99fbc11befd19e6eb33c1c29b00301429ddfb6864a10130dc7ac3eb5e0"
}

rule MalwareBazaar_unknown_012_9fb7b893
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb7b893aed67b419b904cf220720ca1a6ccd6e5d788ec027d806825d71220a6"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:34"
  condition:
    hash.sha256(0, filesize) == "9fb7b893aed67b419b904cf220720ca1a6ccd6e5d788ec027d806825d71220a6"
}

rule MalwareBazaar_unknown_013_f75b53a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f75b53a2ca1143821a72f92e033b95540ddf68de1bb37bc7f942976833ea99cc"
    family = "unknown"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:33"
  condition:
    hash.sha256(0, filesize) == "f75b53a2ca1143821a72f92e033b95540ddf68de1bb37bc7f942976833ea99cc"
}

rule MalwareBazaar_unknown_014_cd007446
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd007446796b931958b47b01258dc375654fc5ac44e09baaf82532237ca12bea"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:31"
  condition:
    hash.sha256(0, filesize) == "cd007446796b931958b47b01258dc375654fc5ac44e09baaf82532237ca12bea"
}

rule MalwareBazaar_unknown_015_03a83f75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03a83f75a6b3a58bf840d41a61f82808036dee034d1682fd028ace7e6007bca8"
    family = "unknown"
    file_name = "bot.arm6"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:30"
  condition:
    hash.sha256(0, filesize) == "03a83f75a6b3a58bf840d41a61f82808036dee034d1682fd028ace7e6007bca8"
}

rule MalwareBazaar_unknown_016_f429a85a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f429a85a4a26dd508cac9d5270b8c3bd10075cae927d4e65d3811a885e4d7959"
    family = "unknown"
    file_name = "dvr.sh"
    file_type = "sh"
    first_seen = "2026-08-19 01:51:29"
  condition:
    hash.sha256(0, filesize) == "f429a85a4a26dd508cac9d5270b8c3bd10075cae927d4e65d3811a885e4d7959"
}

rule MalwareBazaar_unknown_017_b2207baa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2207baadf7b5d299682820fbbe011b785f463cf34a5d9e6a9888cc808ad412e"
    family = "unknown"
    file_name = "main.x86-core2"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:28"
  condition:
    hash.sha256(0, filesize) == "b2207baadf7b5d299682820fbbe011b785f463cf34a5d9e6a9888cc808ad412e"
}

rule MalwareBazaar_unknown_018_b1f240b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1f240b7153d4f3e5c6239c00ea341f46e00df99b4e3751d85b341f4a8106b91"
    family = "unknown"
    file_name = "flutter.mipsel"
    file_type = "elf"
    first_seen = "2026-08-19 01:51:26"
  condition:
    hash.sha256(0, filesize) == "b1f240b7153d4f3e5c6239c00ea341f46e00df99b4e3751d85b341f4a8106b91"
}

rule MalwareBazaar_unknown_019_6e642927
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e642927debe1863e1821a1cd1f69646fad9ab981c798817bc72f3025bd72a82"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 01:50:58"
  condition:
    hash.sha256(0, filesize) == "6e642927debe1863e1821a1cd1f69646fad9ab981c798817bc72f3025bd72a82"
}

rule MalwareBazaar_unknown_020_3306801d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3306801dde6110cb3020687b58d1fe78722d7fdc55e46423452d32d1163d9c5b"
    family = "unknown"
    file_name = "main.x86-64-v2"
    file_type = "elf"
    first_seen = "2026-08-19 01:48:36"
  condition:
    hash.sha256(0, filesize) == "3306801dde6110cb3020687b58d1fe78722d7fdc55e46423452d32d1163d9c5b"
}

rule MalwareBazaar_unknown_021_675c6dbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "675c6dbee16d7b2786717eebd00016fd10caa96d09460539fc3c95e29de89099"
    family = "unknown"
    file_name = "main.mips64el-n32"
    file_type = "elf"
    first_seen = "2026-08-19 01:48:34"
  condition:
    hash.sha256(0, filesize) == "675c6dbee16d7b2786717eebd00016fd10caa96d09460539fc3c95e29de89099"
}

rule MalwareBazaar_Mirai_022_fd8f4bc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd8f4bc36fbbf440347b7e8c6cf62fa93b6e762565e83035e4b15c0629bb1929"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-19 01:25:51"
  condition:
    hash.sha256(0, filesize) == "fd8f4bc36fbbf440347b7e8c6cf62fa93b6e762565e83035e4b15c0629bb1929"
}

rule MalwareBazaar_Mirai_023_91f51fa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91f51fa39579382361b5d4faa0b2da6cb5288f4f33afba2ef85c482a5aad2226"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-19 01:25:30"
  condition:
    hash.sha256(0, filesize) == "91f51fa39579382361b5d4faa0b2da6cb5288f4f33afba2ef85c482a5aad2226"
}

rule MalwareBazaar_unknown_024_28cab475
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28cab475f6c372dda827cfea42d1f99718526e1a3797aa2924c34cfa37c95137"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-19 01:19:17"
  condition:
    hash.sha256(0, filesize) == "28cab475f6c372dda827cfea42d1f99718526e1a3797aa2924c34cfa37c95137"
}

rule MalwareBazaar_Mirai_025_4b56b9f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e"
    family = "Mirai"
    file_name = "4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:15:43"
  condition:
    hash.sha256(0, filesize) == "4b56b9f267d6dec2aeeb1b93af1acad6332e2fe3a484965bffce5b1fdc8b208e"
}

rule MalwareBazaar_Mirai_026_bfad1f24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f"
    family = "Mirai"
    file_name = "bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:05:42"
  condition:
    hash.sha256(0, filesize) == "bfad1f24080adc25cec34fabbee2b5cb467f38610c95355f2d397ebd04f6d76f"
}

rule MalwareBazaar_Mirai_027_f9081df1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1"
    family = "Mirai"
    file_name = "f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:05:38"
  condition:
    hash.sha256(0, filesize) == "f9081df1dbc2fcf77f6daad99d3f19e0ede5e2053defdffa7f9fa97014e0dca1"
}

rule MalwareBazaar_Mirai_028_4c48a477
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc"
    family = "Mirai"
    file_name = "4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:05:35"
  condition:
    hash.sha256(0, filesize) == "4c48a4770c8e84a0e9dfd67687dc094e0b2f10130493701e57a05bcb15bc79cc"
}

rule MalwareBazaar_Mirai_029_1c6beaf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db"
    family = "Mirai"
    file_name = "1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db.elf"
    file_type = "elf"
    first_seen = "2026-08-19 01:00:33"
  condition:
    hash.sha256(0, filesize) == "1c6beaf26337c4fd9df5f2c2ea37cb777d0f01d5eac6fb8691875d53ff1ec7db"
}

rule MalwareBazaar_unknown_030_316b3856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "316b3856741a29f234c4b0309997a5d457b42d6f4eabbf25e620dfab7440a338"
    family = "unknown"
    file_name = "MV_OEL_SURYA_PO6004226017_SR60042-0115.js"
    file_type = "js"
    first_seen = "2026-08-19 00:55:44"
  condition:
    hash.sha256(0, filesize) == "316b3856741a29f234c4b0309997a5d457b42d6f4eabbf25e620dfab7440a338"
}

rule MalwareBazaar_Mirai_031_1330b1af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64"
    family = "Mirai"
    file_name = "1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:55:37"
  condition:
    hash.sha256(0, filesize) == "1330b1af07f3575a5b1d986342682e893180a2d5f3b45da4c1e573c950f11f64"
}

rule MalwareBazaar_Mirai_032_5fdd2d6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d"
    family = "Mirai"
    file_name = "5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:55:33"
  condition:
    hash.sha256(0, filesize) == "5fdd2d6b48143b20dd583efed99cefdafa928b7d31dfb20f7e113b6bb64d887d"
}

rule MalwareBazaar_RemcosRAT_033_9e000b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e000b451c872404804000e33ca7ca8ad3b5f345f876a0500646c67a98453954"
    family = "RemcosRAT"
    file_name = "6EF10B9988BD4AD12F1576F78CE852C5.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:55:08"
  condition:
    hash.sha256(0, filesize) == "9e000b451c872404804000e33ca7ca8ad3b5f345f876a0500646c67a98453954"
}

rule MalwareBazaar_Mirai_034_c2c6af0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26"
    family = "Mirai"
    file_name = "c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:45:33"
  condition:
    hash.sha256(0, filesize) == "c2c6af0ad42ba49749146c98fbecaae17d26329d91d1cdfcfaa8ee4890377f26"
}

rule MalwareBazaar_OverlordRAT_035_213c343a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "213c343ab852a0b185a2198677bf48ac0e7372467cce84d813fe8c5ddc7464b7"
    family = "OverlordRAT"
    file_name = "Updater.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:44:36"
  condition:
    hash.sha256(0, filesize) == "213c343ab852a0b185a2198677bf48ac0e7372467cce84d813fe8c5ddc7464b7"
}

rule MalwareBazaar_Mirai_036_b9f4425a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9f4425ad3f99e548342f9e281b1736776d9cd8d32728e2d6ee5e9caccda6acb"
    family = "Mirai"
    file_name = "fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:43:01"
  condition:
    hash.sha256(0, filesize) == "b9f4425ad3f99e548342f9e281b1736776d9cd8d32728e2d6ee5e9caccda6acb"
}

rule MalwareBazaar_unknown_037_717ef4a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961"
    family = "unknown"
    file_name = "717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961.bin"
    file_type = "exe"
    first_seen = "2026-08-19 00:42:43"
  condition:
    hash.sha256(0, filesize) == "717ef4a13841aa2766a3b38f615755d1e85228ac6ab6efa6ea662db7eca62961"
}

rule MalwareBazaar_Mirai_038_fe8633ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7"
    family = "Mirai"
    file_name = "fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:40:32"
  condition:
    hash.sha256(0, filesize) == "fe8633eacbc02ea80bfafc2a5e7d38e97aaa5ba86a6fc9273fcc16fddfdbc6c7"
}

rule MalwareBazaar_unknown_039_8e4c5d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e4c5d232d6a1d98d88a52565379f1c8e85fe297910fc4d4f526a0f0375932a5"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:40:18"
  condition:
    hash.sha256(0, filesize) == "8e4c5d232d6a1d98d88a52565379f1c8e85fe297910fc4d4f526a0f0375932a5"
}

rule MalwareBazaar_unknown_040_bbad922c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbad922cd7ad33f2592c001d0956491d873ed2270766e0f0f81c8adc076c8307"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:39:24"
  condition:
    hash.sha256(0, filesize) == "bbad922cd7ad33f2592c001d0956491d873ed2270766e0f0f81c8adc076c8307"
}

rule MalwareBazaar_SnappyClient_041_9f4e92d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f4e92d43db6f77fc3b5e7a764afb703ed327e595ff693bde6e03d7eb0e1cf19"
    family = "SnappyClient"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:38:14"
  condition:
    hash.sha256(0, filesize) == "9f4e92d43db6f77fc3b5e7a764afb703ed327e595ff693bde6e03d7eb0e1cf19"
}

rule MalwareBazaar_Mirai_042_f79604e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f79604e3722ffb8ffceed3bfe383a159ea9471475e4809b10071dcc7a9e28443"
    family = "Mirai"
    file_name = "b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:37:03"
  condition:
    hash.sha256(0, filesize) == "f79604e3722ffb8ffceed3bfe383a159ea9471475e4809b10071dcc7a9e28443"
}

rule MalwareBazaar_Mirai_043_484d5188
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "484d5188d6b19207e282fde9669f21985121631be18709a44ff6ae591da8c667"
    family = "Mirai"
    file_name = "d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:37:00"
  condition:
    hash.sha256(0, filesize) == "484d5188d6b19207e282fde9669f21985121631be18709a44ff6ae591da8c667"
}

rule MalwareBazaar_Mirai_044_11f2e69d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f2e69de5bdeb0e8f71ad3964477297734f98e6cd477ee989f6697a734a0353"
    family = "Mirai"
    file_name = "c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:36:56"
  condition:
    hash.sha256(0, filesize) == "11f2e69de5bdeb0e8f71ad3964477297734f98e6cd477ee989f6697a734a0353"
}

rule MalwareBazaar_Mirai_045_306d8721
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "306d872116c5e56b79bc547a55a8eaec496eee7e9229a17f864d7f068d6be2fc"
    family = "Mirai"
    file_name = "0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:36:52"
  condition:
    hash.sha256(0, filesize) == "306d872116c5e56b79bc547a55a8eaec496eee7e9229a17f864d7f068d6be2fc"
}

rule MalwareBazaar_unknown_046_82b1a5ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82b1a5ffdf569695f522537b98a78aa0dc655b7700efdbe80e1e664891cf709c"
    family = "unknown"
    file_name = "FLTLIB.DLL"
    file_type = "exe"
    first_seen = "2026-08-19 00:36:19"
  condition:
    hash.sha256(0, filesize) == "82b1a5ffdf569695f522537b98a78aa0dc655b7700efdbe80e1e664891cf709c"
}

rule MalwareBazaar_Mirai_047_b05f75e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50"
    family = "Mirai"
    file_name = "b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:35:42"
  condition:
    hash.sha256(0, filesize) == "b05f75e7fad53ada4a99d4ee157560fde73cc245ede5a4a329b2b5c11c44dc50"
}

rule MalwareBazaar_Mirai_048_d2e3ab88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8"
    family = "Mirai"
    file_name = "d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:35:38"
  condition:
    hash.sha256(0, filesize) == "d2e3ab888135b45013cf049ce0497b834b44aeb88704cfb1f7c4abec4b03c1e8"
}

rule MalwareBazaar_Mirai_049_c244f541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808"
    family = "Mirai"
    file_name = "c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:35:34"
  condition:
    hash.sha256(0, filesize) == "c244f5419125b94d127c65c9e6b69a0d5c94873a95fe3fc6d418305ac14e1808"
}

rule MalwareBazaar_unknown_050_41aa2a9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41aa2a9f47277b32efbb369b5b92c79d444d3c524cd55142d9e85603ddea3478"
    family = "unknown"
    file_name = "FLStudio2025_v248_Win.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:35:32"
  condition:
    hash.sha256(0, filesize) == "41aa2a9f47277b32efbb369b5b92c79d444d3c524cd55142d9e85603ddea3478"
}

rule MalwareBazaar_Mirai_051_0482f7f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6"
    family = "Mirai"
    file_name = "0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:35:31"
  condition:
    hash.sha256(0, filesize) == "0482f7f1e2ebca3bcb7e8fca855d1ea82e613291c70f6f4557107cf7823192c6"
}

rule MalwareBazaar_unknown_052_be21ec68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be21ec6879ddc9457fb48e2da6fe49a4208ded546205b3a161c358dcb016e38f"
    family = "unknown"
    file_name = "vsdbg.dll"
    file_type = "exe"
    first_seen = "2026-08-19 00:33:08"
  condition:
    hash.sha256(0, filesize) == "be21ec6879ddc9457fb48e2da6fe49a4208ded546205b3a161c358dcb016e38f"
}

rule MalwareBazaar_Mirai_053_04c037e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04c037e735415a021da6cd41990f090cc7691b089680c18057e707c9b1fd5efa"
    family = "Mirai"
    file_name = "5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:31:53"
  condition:
    hash.sha256(0, filesize) == "04c037e735415a021da6cd41990f090cc7691b089680c18057e707c9b1fd5efa"
}

rule MalwareBazaar_Mirai_054_2e21eb20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e21eb201f4735eff29e9018b1b6918a384d6fe9189e9d477e5d1625dfbfa45b"
    family = "Mirai"
    file_name = "46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:31:50"
  condition:
    hash.sha256(0, filesize) == "2e21eb201f4735eff29e9018b1b6918a384d6fe9189e9d477e5d1625dfbfa45b"
}

rule MalwareBazaar_unknown_055_0ecbba5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ecbba5d1aa1cfb32e96df6d6d7854929353733668ad1134256ec0451dc1a1da"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:31:45"
  condition:
    hash.sha256(0, filesize) == "0ecbba5d1aa1cfb32e96df6d6d7854929353733668ad1134256ec0451dc1a1da"
}

rule MalwareBazaar_Mirai_056_5d50a932
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895"
    family = "Mirai"
    file_name = "5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:30:37"
  condition:
    hash.sha256(0, filesize) == "5d50a9324e9651f8fc808a2bf966e3c9b30b8d05b0019670f1f095af0ff73895"
}

rule MalwareBazaar_Mirai_057_46726bc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf"
    family = "Mirai"
    file_name = "46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:30:32"
  condition:
    hash.sha256(0, filesize) == "46726bc3c76a572749eb883a736e6ba796df0b8a22bab3e27abc8f3f5dd42cbf"
}

rule MalwareBazaar_unknown_058_2ecf04b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ecf04b3f001039184d841dd067d6e47bf192047ffe6b92c72a9d57bda6c6afe"
    family = "unknown"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:28:14"
  condition:
    hash.sha256(0, filesize) == "2ecf04b3f001039184d841dd067d6e47bf192047ffe6b92c72a9d57bda6c6afe"
}

rule MalwareBazaar_unknown_059_64494586
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64494586d79711a0c12ad714f5f895a5d14200247cc02f0434f2bcd8b3b8002f"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-19 00:27:23"
  condition:
    hash.sha256(0, filesize) == "64494586d79711a0c12ad714f5f895a5d14200247cc02f0434f2bcd8b3b8002f"
}

rule MalwareBazaar_Mirai_060_172a1ed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273"
    family = "Mirai"
    file_name = "172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:25:29"
  condition:
    hash.sha256(0, filesize) == "172a1ed27fd5acad8699a05faecd862b10b01997eeae5fde960a6019d3145273"
}

rule MalwareBazaar_RemusStealer_061_1d65b762
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d65b76219f184a4fc87d597b0ae50e2ef6f98a79558448b0f0868f761c5479f"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-19 00:22:20"
  condition:
    hash.sha256(0, filesize) == "1d65b76219f184a4fc87d597b0ae50e2ef6f98a79558448b0f0868f761c5479f"
}

rule MalwareBazaar_Mirai_062_8e4de934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e4de934b467663ba2d56bb8de0f643afc38d51e7ec2396abfcebc48d66a2909"
    family = "Mirai"
    file_name = "4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:21:10"
  condition:
    hash.sha256(0, filesize) == "8e4de934b467663ba2d56bb8de0f643afc38d51e7ec2396abfcebc48d66a2909"
}

rule MalwareBazaar_Mirai_063_4cc97ea7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f"
    family = "Mirai"
    file_name = "4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:20:31"
  condition:
    hash.sha256(0, filesize) == "4cc97ea7fddc5faf98f2d71888b1f990dcf44c4d082622b7e4e8c20359653a5f"
}

rule MalwareBazaar_unknown_064_937904cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88"
    family = "unknown"
    file_name = "937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88.bin"
    file_type = "exe"
    first_seen = "2026-08-19 00:19:51"
  condition:
    hash.sha256(0, filesize) == "937904cca4fd1a67c8ca473e7894a84ee8db3fe48d015441fe876dd6b5113c88"
}

rule MalwareBazaar_Mirai_065_50422a84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50422a847e0c1c2c7e47336bbf9aab79285ba549dffe279dc4697e707c05f464"
    family = "Mirai"
    file_name = "0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:16:50"
  condition:
    hash.sha256(0, filesize) == "50422a847e0c1c2c7e47336bbf9aab79285ba549dffe279dc4697e707c05f464"
}

rule MalwareBazaar_Mirai_066_0dd5d379
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2"
    family = "Mirai"
    file_name = "0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:16:19"
  condition:
    hash.sha256(0, filesize) == "0dd5d379001fe6a689e401523a63a82f1548136d674a1fe2f18eec128cd552a2"
}

rule MalwareBazaar_ValleyRAT_067_86a894fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86a894fe150c8f706c6bd428e391c98259bc1153d99920d5cc0b84b8db688b0a"
    family = "ValleyRAT"
    file_name = "3F54292A6F4F5B36BB0549C20992E880.dll"
    file_type = "dll"
    first_seen = "2026-08-19 00:15:14"
  condition:
    hash.sha256(0, filesize) == "86a894fe150c8f706c6bd428e391c98259bc1153d99920d5cc0b84b8db688b0a"
}

rule MalwareBazaar_Mirai_068_3980f39b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84"
    family = "Mirai"
    file_name = "3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84.elf"
    file_type = "elf"
    first_seen = "2026-08-19 00:05:58"
  condition:
    hash.sha256(0, filesize) == "3980f39b92f36760b7e4758d0c4261245d2572985942c97e22f3094493f5df84"
}

rule MalwareBazaar_Mirai_069_64cda56c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64cda56c20ff6fce786658487df0881fabaa99776d5fc90836fcfaffbf1a24cf"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-19 00:03:36"
  condition:
    hash.sha256(0, filesize) == "64cda56c20ff6fce786658487df0881fabaa99776d5fc90836fcfaffbf1a24cf"
}

rule MalwareBazaar_Mirai_070_37b38b93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37b38b9303be79f30f74f7c0247ab5c6850c5ce16c4740e6b8273d6cfd926200"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-19 00:03:02"
  condition:
    hash.sha256(0, filesize) == "37b38b9303be79f30f74f7c0247ab5c6850c5ce16c4740e6b8273d6cfd926200"
}

rule MalwareBazaar_unknown_071_951b0032
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "951b00329104e1478887898169e968de2c1ccd0a6dce0cf54abc0c4c9d8934a4"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-18 23:52:09"
  condition:
    hash.sha256(0, filesize) == "951b00329104e1478887898169e968de2c1ccd0a6dce0cf54abc0c4c9d8934a4"
}

rule MalwareBazaar_unknown_072_4f151277
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f1512771f67829fa9f8ec1e0478f8bdfdb618ba9e84e92f2e987b2c6937532e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-18 23:42:52"
  condition:
    hash.sha256(0, filesize) == "4f1512771f67829fa9f8ec1e0478f8bdfdb618ba9e84e92f2e987b2c6937532e"
}

rule MalwareBazaar_unknown_073_5ec6e9a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ec6e9a22b3537e04d7d45b7ceecb9b715a3657aa537e1e3758e9cf13e1d5161"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-18 23:42:44"
  condition:
    hash.sha256(0, filesize) == "5ec6e9a22b3537e04d7d45b7ceecb9b715a3657aa537e1e3758e9cf13e1d5161"
}

rule MalwareBazaar_unknown_074_565c7e58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f"
    family = "unknown"
    file_name = "565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f.bin"
    file_type = "exe"
    first_seen = "2026-08-18 23:31:12"
  condition:
    hash.sha256(0, filesize) == "565c7e58d69911df063704f17049462faa012852053f034b6aacf6651515304f"
}

rule MalwareBazaar_unknown_075_dfa0e88f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a"
    family = "unknown"
    file_name = "dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a.bin"
    file_type = "exe"
    first_seen = "2026-08-18 23:31:10"
  condition:
    hash.sha256(0, filesize) == "dfa0e88fa2c28581d8c12b04d4f3e2518c578c62edc249dda867dbc7c0715d7a"
}

rule MalwareBazaar_unknown_076_1c129e99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251"
    family = "unknown"
    file_name = "1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251.bin"
    file_type = "exe"
    first_seen = "2026-08-18 23:31:07"
  condition:
    hash.sha256(0, filesize) == "1c129e9920c0d9488cff21e6562ff95bc3b329e23c93d92c3799ab4a42f75251"
}

rule MalwareBazaar_unknown_077_68fb701f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68fb701f506aa2e51ebe43730167ea0d34a48539aaf0ed62c4de118dd9c2d53f"
    family = "unknown"
    file_name = "main.x86-64-v4"
    file_type = "elf"
    first_seen = "2026-08-18 23:18:21"
  condition:
    hash.sha256(0, filesize) == "68fb701f506aa2e51ebe43730167ea0d34a48539aaf0ed62c4de118dd9c2d53f"
}

rule MalwareBazaar_unknown_078_100e0977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5"
    family = "unknown"
    file_name = "100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5"
    file_type = "sh"
    first_seen = "2026-08-18 23:00:10"
  condition:
    hash.sha256(0, filesize) == "100e0977f68d28b7b8dcf48a7eb8a7783bbc9c6922eeb92656f610c306f0d0c5"
}

rule MalwareBazaar_unknown_079_8910f0cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8910f0cb2eb97c3b1ced8b512bb34884a958ba7d81829841b2e60eb487157662"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-18 22:52:18"
  condition:
    hash.sha256(0, filesize) == "8910f0cb2eb97c3b1ced8b512bb34884a958ba7d81829841b2e60eb487157662"
}

rule MalwareBazaar_unknown_080_c5cf2b56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5cf2b566923f4b635dc09f80d3bd20e8b61a517967e38553fb179e594e931ce"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-18 22:52:13"
  condition:
    hash.sha256(0, filesize) == "c5cf2b566923f4b635dc09f80d3bd20e8b61a517967e38553fb179e594e931ce"
}

rule MalwareBazaar_Mirai_081_87010147
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870101471c67e4a08b5172e0cc700933f44645bcd097801516c1df02a69d5da7"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-18 22:50:41"
  condition:
    hash.sha256(0, filesize) == "870101471c67e4a08b5172e0cc700933f44645bcd097801516c1df02a69d5da7"
}

rule MalwareBazaar_unknown_082_1ae15ba9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3"
    family = "unknown"
    file_name = "1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3.exe"
    file_type = "exe"
    first_seen = "2026-08-18 22:45:50"
  condition:
    hash.sha256(0, filesize) == "1ae15ba98f8c31b82415710967ecd9d0a6397ba299f9ee2848f209c98f08f1b3"
}

rule MalwareBazaar_unknown_083_8034c27e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1"
    family = "unknown"
    file_name = "8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1.exe"
    file_type = "exe"
    first_seen = "2026-08-18 22:45:45"
  condition:
    hash.sha256(0, filesize) == "8034c27ec7cff773651896227ca69f13b3788f0706cf95851f16b1f5be91b5e1"
}

rule MalwareBazaar_Vidar_084_787f169a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197"
    family = "Vidar"
    file_name = "787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197.bin"
    file_type = "exe"
    first_seen = "2026-08-18 22:43:15"
  condition:
    hash.sha256(0, filesize) == "787f169a719e78bcc790ce8edb42e8f737b99d00892a1a158cf97f19d7df2197"
}

rule MalwareBazaar_RustyStealer_085_6aba832d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aba832d095cf90906b34335f698bee1debe024ce3422375ee9394aea94dc934"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 22:34:44"
  condition:
    hash.sha256(0, filesize) == "6aba832d095cf90906b34335f698bee1debe024ce3422375ee9394aea94dc934"
}

rule MalwareBazaar_unknown_086_58373b38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58373b38eeae8828e8b9b660942c74e6b1ab0fc62799d1e7e228670f7838be95"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 22:26:31"
  condition:
    hash.sha256(0, filesize) == "58373b38eeae8828e8b9b660942c74e6b1ab0fc62799d1e7e228670f7838be95"
}

rule MalwareBazaar_unknown_087_38aba404
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38aba4040537b20450e78092d79b4a9bd92eab8814842d6ecd1cad93e8f6a6ab"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-18 21:52:11"
  condition:
    hash.sha256(0, filesize) == "38aba4040537b20450e78092d79b4a9bd92eab8814842d6ecd1cad93e8f6a6ab"
}

rule MalwareBazaar_unknown_088_7e0be7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e0be7ce68bfeaeb2e461f6aa1b15163f68fb928b82f9c811bc3047caabb694b"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-18 21:42:25"
  condition:
    hash.sha256(0, filesize) == "7e0be7ce68bfeaeb2e461f6aa1b15163f68fb928b82f9c811bc3047caabb694b"
}

rule MalwareBazaar_unknown_089_e1c28de1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1c28de1482b14ac76cb710339a1bebd76243bc78fcee1ef02194b5bc11194a6"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-18 21:42:17"
  condition:
    hash.sha256(0, filesize) == "e1c28de1482b14ac76cb710339a1bebd76243bc78fcee1ef02194b5bc11194a6"
}

rule MalwareBazaar_Mirai_090_8f330565
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f33056539a54c26e62296cd29b267659a4c250fe8dbec61575863daac044b1e"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-18 21:32:43"
  condition:
    hash.sha256(0, filesize) == "8f33056539a54c26e62296cd29b267659a4c250fe8dbec61575863daac044b1e"
}

rule MalwareBazaar_Mirai_091_f13850c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f13850c06490d3b58ab165277428eb03da1ef715d125bb32c9150802d895fae3"
    family = "Mirai"
    file_name = "726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909.elf"
    file_type = "elf"
    first_seen = "2026-08-18 21:32:41"
  condition:
    hash.sha256(0, filesize) == "f13850c06490d3b58ab165277428eb03da1ef715d125bb32c9150802d895fae3"
}

rule MalwareBazaar_Mirai_092_66445c49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66445c49af8308aecd8f34f6b758daeb53c15964115b0fc2bdcc1fff285ff45f"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-18 21:31:48"
  condition:
    hash.sha256(0, filesize) == "66445c49af8308aecd8f34f6b758daeb53c15964115b0fc2bdcc1fff285ff45f"
}

rule MalwareBazaar_Mirai_093_726cea84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909"
    family = "Mirai"
    file_name = "726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909.elf"
    file_type = "elf"
    first_seen = "2026-08-18 21:31:16"
  condition:
    hash.sha256(0, filesize) == "726cea848f900ffe7f1a12534e15b0f6ef6703bb8f96a60c59b7a65720af6909"
}

rule MalwareBazaar_Mirai_094_83fee7d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689"
    family = "Mirai"
    file_name = "83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689.elf"
    file_type = "elf"
    first_seen = "2026-08-18 21:31:11"
  condition:
    hash.sha256(0, filesize) == "83fee7d8d646273f1ed9c7b34fef8d20cd9c0633180a6813eda7a2e9d2e77689"
}

rule MalwareBazaar_Mirai_095_067a0c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "067a0c37ea6a7b2553f7d136582f06aea334b55490c87d4fbfbec835d95242e8"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-08-18 21:29:45"
  condition:
    hash.sha256(0, filesize) == "067a0c37ea6a7b2553f7d136582f06aea334b55490c87d4fbfbec835d95242e8"
}

rule MalwareBazaar_Mirai_096_ec810c58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec810c58f343b42f75cc2e6a24ce244702c2f6ded7ce7acf19eb02c02cdee5f9"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-08-18 21:29:19"
  condition:
    hash.sha256(0, filesize) == "ec810c58f343b42f75cc2e6a24ce244702c2f6ded7ce7acf19eb02c02cdee5f9"
}

rule MalwareBazaar_Mirai_097_6764b21b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6764b21b8804275d8969b71eea7b5b3be3d4a6cc5878a05d251a3d7de77f9935"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-18 21:27:53"
  condition:
    hash.sha256(0, filesize) == "6764b21b8804275d8969b71eea7b5b3be3d4a6cc5878a05d251a3d7de77f9935"
}

rule MalwareBazaar_Mirai_098_8a59d346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a59d346ea1b71f3d86c0b0335e6a2924de89bb5bdd38a0f25eb90c37a85ad1a"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-18 21:26:34"
  condition:
    hash.sha256(0, filesize) == "8a59d346ea1b71f3d86c0b0335e6a2924de89bb5bdd38a0f25eb90c37a85ad1a"
}

rule MalwareBazaar_Mirai_099_d4260a0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4260a0d332b4d7442cb571fa036c82746fb123450ddac11257d328eae4c34a3"
    family = "Mirai"
    file_name = "bot.spc"
    file_type = "elf"
    first_seen = "2026-08-18 21:26:33"
  condition:
    hash.sha256(0, filesize) == "d4260a0d332b4d7442cb571fa036c82746fb123450ddac11257d328eae4c34a3"
}

rule MalwareBazaar_Mirai_100_3069d54a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3069d54ae404f4b3c3465bd91e112bc622ef793f413eef812dd4c348438b9974"
    family = "Mirai"
    file_name = "64fce8e35348bad4a580d70a12f4052bbf7a63d1e400ca6f964f7f630080534a.elf"
    file_type = "elf"
    first_seen = "2026-08-18 21:26:31"
  condition:
    hash.sha256(0, filesize) == "3069d54ae404f4b3c3465bd91e112bc622ef793f413eef812dd4c348438b9974"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

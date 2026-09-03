# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-03

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
| Unique family labels | 9 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 56 |
| Mirai | 18 |
| Vidar | 18 |
| CoinMiner | 2 |
| ConnectWise | 2 |
| Formbook | 1 |
| AgentTesla | 1 |
| NanoCore | 1 |
| Prometei | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 54 |
| elf | 26 |
| sh | 10 |
| unknown | 5 |
| js | 3 |
| jar | 1 |
| gz | 1 |

## Per-Sample Analysis

### Sample 1: `ef684ef8bf90c0d8`

| Field | Value |
|---|---|
| SHA-256 | `ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4` |
| Family label | `unknown` |
| File name | `ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4.bin` |
| File type | `exe` |
| First seen | `2026-09-03 04:34:35` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afee8b1b35405c2cbf5be6ea4d515561` |
| SHA-1 | `ad630836facc7b850ea1b91dfda96bf1cc2f3803` |
| SHA-256 | `ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4` |
| SHA3-384 | `07c23888840bc2770bedeec0fdaae9ae8b29309e64c4a1fed8a07c1dc229085de092c77d9bddf648c038370c19e22008` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T172867D47BA94A090C1E9D638C5B611217B64B8899B3433F33F91AAB12F333D56F79B50` |
| SSDEEP | `49152:49vA0+xoVDlPrb/TgvO90d7HjmAFd4A64nsfJO88LH5tZmVXKPtbyRK4Xv7U0eU5:nw5qZmVTRr7UfcotxHbLVWV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_ef684ef8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4"
    family = "unknown"
    file_name = "ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4.bin"
    file_type = "exe"
    first_seen = "2026-09-03 04:34:35"
  condition:
    hash.sha256(0, filesize) == "ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4"
}
```

### Sample 2: `a0a578706ff876c6`

| Field | Value |
|---|---|
| SHA-256 | `a0a578706ff876c631451765720f236434e703d453fbb897903635a1fed96ce8` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-03 04:01:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d9e580d918ba402960807d30a20334d` |
| SHA-1 | `a56cef1d3651ac16aee6fb0f790e6ffbf25a68ba` |
| SHA-256 | `a0a578706ff876c631451765720f236434e703d453fbb897903635a1fed96ce8` |
| SHA3-384 | `2303f3475148ba5bca28ecff109153585631b0f9c3b02680d643c94e1023d1085a1cdfaba25640760089e920172d95bd` |
| TLSH | `T16DC27D966A867C44BEC98A3E4CBD2B1D6DF5C3D1224942AC3D4B3C71DC11FACD618B1A` |
| SSDEEP | `768:j8vCB+25j6es8Rqb9FYpMSUpi+20qUpi+20YQX:j8l25Jid2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_a0a57870
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0a578706ff876c631451765720f236434e703d453fbb897903635a1fed96ce8"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 04:01:00"
  condition:
    hash.sha256(0, filesize) == "a0a578706ff876c631451765720f236434e703d453fbb897903635a1fed96ce8"
}
```

### Sample 3: `d8f869b3431dcbcb`

| Field | Value |
|---|---|
| SHA-256 | `d8f869b3431dcbcb0acda45675798b496b2ece53c064723828abae155537badf` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-03 03:55:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a66d49200e099d476db7a764ed5908c2` |
| SHA-1 | `abf28ef71cd1285069a41cc00c782a4dec90cf0c` |
| SHA-256 | `d8f869b3431dcbcb0acda45675798b496b2ece53c064723828abae155537badf` |
| SHA3-384 | `6fd27533aa95dcf15ec14921cba035db3365f40942b26498f60c1fae937185c8c61455a7aed441d278ce2552684daac6` |
| TLSH | `T128042B56E6818A17C4D2177AFADF52463333A764D3DB33069928AFB43F8679E0E23501` |
| TELFHASH | `t13531ef3117316511aeb1da589ce963b7252ec6266284ef73de25c4cc940a09bf637c4f` |
| SSDEEP | `3072:bzBxBWf8PSLjuzg+rWucVSnaTHQqanN7tR6b4stvmiE7CTeSGwaWM/9aWU:QfzLCzg+rWu8SaTwqanN7tRg4wmp7CTV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_d8f869b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8f869b3431dcbcb0acda45675798b496b2ece53c064723828abae155537badf"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-03 03:55:49"
  condition:
    hash.sha256(0, filesize) == "d8f869b3431dcbcb0acda45675798b496b2ece53c064723828abae155537badf"
}
```

### Sample 4: `cb56319e8492f141`

| Field | Value |
|---|---|
| SHA-256 | `cb56319e8492f14166c7d6928e5f2baf1e7f09320d27ffbc6cd894c5e0978c43` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-03 03:53:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c45e2b0cb45a750d3b5861ac977eee9` |
| SHA-1 | `c08c603e6aebb06a44765b9534c53d4ecb8f2ca9` |
| SHA-256 | `cb56319e8492f14166c7d6928e5f2baf1e7f09320d27ffbc6cd894c5e0978c43` |
| SHA3-384 | `bb42eb5cb3eea385a1549bce7464f99897144b5f22404c513d42bb2b3fef883432804bd8f76644866f29760259171d78` |
| TLSH | `T1C533192692B8161BD4C4A67E12EB57A5F1B62B4800D8D70F7C320D4FFE653606A3B2B4` |
| TELFHASH | `t186f09e45fd744b188de27674ac8c03a184134313612387248f98d9e0cc3e11ab74cd1d` |
| SSDEEP | `1536:cXgenSoNIHlMhfqS0ALkrqpVjrZxU4QCP2TL:c1NKMhfvLnl1PuL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_cb56319e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb56319e8492f14166c7d6928e5f2baf1e7f09320d27ffbc6cd894c5e0978c43"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-03 03:53:26"
  condition:
    hash.sha256(0, filesize) == "cb56319e8492f14166c7d6928e5f2baf1e7f09320d27ffbc6cd894c5e0978c43"
}
```

### Sample 5: `2f5db24de6751d83`

| Field | Value |
|---|---|
| SHA-256 | `2f5db24de6751d834bce8650d026d04529ac93782037a9262a4521dfca21e55f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-03 03:45:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55c3e22edf6fdcb19a50796625ddd764` |
| SHA-1 | `39cd84752f53a00512050eb9c7830b9f5fab17f5` |
| SHA-256 | `2f5db24de6751d834bce8650d026d04529ac93782037a9262a4521dfca21e55f` |
| SHA3-384 | `b985e656409479e84f5681753f6a963639a9be578326be74171a3030fa5dbaef45af51e38b0fae843cdbec9c048ec15f` |
| TLSH | `T165236C6516857C14AE99C4365C7F2F0CBDAD43E6314492EE7FCA3CF28C4A6ADA20871D` |
| SSDEEP | `768:Cr9NyXsZztCV9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:MHusZLcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_2f5db24d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f5db24de6751d834bce8650d026d04529ac93782037a9262a4521dfca21e55f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 03:45:42"
  condition:
    hash.sha256(0, filesize) == "2f5db24de6751d834bce8650d026d04529ac93782037a9262a4521dfca21e55f"
}
```

### Sample 6: `fc419a7b5035aba3`

| Field | Value |
|---|---|
| SHA-256 | `fc419a7b5035aba342a1031c68dd7879f5df3184291b440def4e78fc87bf70ca` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-03 03:37:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6da19f557aad3f1832cf2925f21630e` |
| SHA-1 | `f912d630c34dc5394be1b173f58c813e19b3a8b8` |
| SHA-256 | `fc419a7b5035aba342a1031c68dd7879f5df3184291b440def4e78fc87bf70ca` |
| SHA3-384 | `a9f511318135e32554cb70def83a3ae63ddc13b19146e0208f9267ea09149e63e0a1e0c5ea034c9eeb038f1bef3ea998` |
| TLSH | `T195F30956F8828B15D5C152BEFE0E528E33232B78D2DE72029D246F35778A87F0E3A515` |
| TELFHASH | `t1d8c08076c5854be8b1dd822082fe535436b5f0cf061404b31e483b9f45e5e32f711167` |
| SSDEEP | `3072:aeBbBf+P4+MtrjGDOWnBWUdoc8YdNX4JZmJSabocs0pwKEeaQkdDCef+:UP6tXGDOWnBWUoc8aXcmEac8pw0aQkdw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_fc419a7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc419a7b5035aba342a1031c68dd7879f5df3184291b440def4e78fc87bf70ca"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-03 03:37:40"
  condition:
    hash.sha256(0, filesize) == "fc419a7b5035aba342a1031c68dd7879f5df3184291b440def4e78fc87bf70ca"
}
```

### Sample 7: `17c6cd29b51c3462`

| Field | Value |
|---|---|
| SHA-256 | `17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1` |
| Family label | `Vidar` |
| File name | `17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1.bin` |
| File type | `exe` |
| First seen | `2026-09-03 03:36:53` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ccdc8b931c809bbeac91f5f6c682c71` |
| SHA-1 | `47d1583b884244b3f0134d7934d3a3a713001d6c` |
| SHA-256 | `17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1` |
| SHA3-384 | `9073ddbcb79c62207e66d5428980895e556473d2db3339eb2b62ab185171a385b356d15400c48a6796205022dcc90b81` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1F5283347BE58A090C1A9D638C5AA02217B657C89CB3133F32E51ABB62F373D15FB9750` |
| SSDEEP | `1572864:Qjrge/p1NvhYYU0UExzvNhT36sq3T+2Ajb/zbcSoFYecZTIt0Mp0x:Kh3GYU3sTTgKdH/nFuYrTI9pO` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_007_17c6cd29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1"
    family = "Vidar"
    file_name = "17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1.bin"
    file_type = "exe"
    first_seen = "2026-09-03 03:36:53"
  condition:
    hash.sha256(0, filesize) == "17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1"
}
```

### Sample 8: `c71e9e7d22935bfe`

| Field | Value |
|---|---|
| SHA-256 | `c71e9e7d22935bfe6e15f65ae2facc639fc35becb7efbb9c013f5e27c27a28a3` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-03 03:24:40` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fedbce38e929cabe0c23d7032e9520f` |
| SHA-256 | `c71e9e7d22935bfe6e15f65ae2facc639fc35becb7efbb9c013f5e27c27a28a3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_c71e9e7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c71e9e7d22935bfe6e15f65ae2facc639fc35becb7efbb9c013f5e27c27a28a3"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 03:24:40"
  condition:
    hash.sha256(0, filesize) == "c71e9e7d22935bfe6e15f65ae2facc639fc35becb7efbb9c013f5e27c27a28a3"
}
```

### Sample 9: `6e284e5a451cedcb`

| Field | Value |
|---|---|
| SHA-256 | `6e284e5a451cedcb0c4098cc52898e41cbc7fdd6b3398003d87aabb4199ef8e3` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-03 03:18:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df0541db1edfe859b215f706ff2d7f54` |
| SHA-1 | `ab1e7cb15e352138e4449a567663066731589605` |
| SHA-256 | `6e284e5a451cedcb0c4098cc52898e41cbc7fdd6b3398003d87aabb4199ef8e3` |
| SHA3-384 | `a6fe56f5af7f311a74860574228ba44325bdcf14b44ad3988f31ca3aa3dfcf87f06e35743e84a492a20c01fa99129184` |
| TLSH | `T1E2F32902B31C0943D2632EF43A3B27E193DFE69125B4F644391FAB8991B1D325686DDE` |
| SSDEEP | `1536:cpDGF+SzjozxpaA1y5xONW1i6Qv3NqzhS2gXC3vFwbv2fvAgVDd15R3qrDrK0UGn:cU/mpauax5QIgX2vFfgg3GcxI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_6e284e5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e284e5a451cedcb0c4098cc52898e41cbc7fdd6b3398003d87aabb4199ef8e3"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-03 03:18:39"
  condition:
    hash.sha256(0, filesize) == "6e284e5a451cedcb0c4098cc52898e41cbc7fdd6b3398003d87aabb4199ef8e3"
}
```

### Sample 10: `85814a9cb07115a9`

| Field | Value |
|---|---|
| SHA-256 | `85814a9cb07115a91cedfd92d09430ececaed70ba63f1ff89d2a39284345311c` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-03 03:06:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fb520df62dd284d6d478e1b75f102fc` |
| SHA-1 | `5daa86dccc9ac3cd9620699e21e9da644ed54776` |
| SHA-256 | `85814a9cb07115a91cedfd92d09430ececaed70ba63f1ff89d2a39284345311c` |
| SHA3-384 | `682bf06de8a5c1c0886abf1261e0dd396a045a6c87283dbe1b95f9bae6d89dc8f1b7813cdee89af9f0705b3d131563f1` |
| TLSH | `T125B37DC5B743D4F1F86A4AF4107B97269B32D435112AEB42D37A293AEC67610DB1B32C` |
| TELFHASH | `t1ff515bfb2d7f0ce8a741a901d30e6f52694eeb3b256037a2456388393297dc145bac3d` |
| SSDEEP | `3072:8B1Mzp6wUQE5Ts4m4bE5TeWBsCR0WwzjZ7:nppUQITsasRVEjZ7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_85814a9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85814a9cb07115a91cedfd92d09430ececaed70ba63f1ff89d2a39284345311c"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-03 03:06:48"
  condition:
    hash.sha256(0, filesize) == "85814a9cb07115a91cedfd92d09430ececaed70ba63f1ff89d2a39284345311c"
}
```

### Sample 11: `b33780a313eea2c5`

| Field | Value |
|---|---|
| SHA-256 | `b33780a313eea2c5357072b2cf80dbb6ee260d4a9edb6dd15c5281f8bfebbb0d` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-03 03:03:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6dddee1c5fa1631c301656803142289b` |
| SHA-1 | `a70d95f79e14145acc7cb7cdeeedf1b78f983c32` |
| SHA-256 | `b33780a313eea2c5357072b2cf80dbb6ee260d4a9edb6dd15c5281f8bfebbb0d` |
| SHA3-384 | `224e441e8a9f56a227d7a222570d4cfc86fee1102540f7a2d7f51d4f675543e0a39cf17005e49c4ba9c6f503379e8076` |
| TLSH | `T1B5F35A17B4C084FEC8D5C1788FAFA22AD972F4595135B25F2784BE272E5EE305B6E210` |
| TELFHASH | `t12261dcb13d9a789861e3e336b30bda6ffc32091114e5b4a4ee6759e4de127c80db2431` |
| SSDEEP | `3072:Z75SJHiXewBWwe/or4TegpS66IggnI1sQun2X6VALmA3sRsDUQ:Z7eiXi7i8JaunMMRsDUQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_b33780a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b33780a313eea2c5357072b2cf80dbb6ee260d4a9edb6dd15c5281f8bfebbb0d"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-03 03:03:56"
  condition:
    hash.sha256(0, filesize) == "b33780a313eea2c5357072b2cf80dbb6ee260d4a9edb6dd15c5281f8bfebbb0d"
}
```

### Sample 12: `3977a21a9d3c71e9`

| Field | Value |
|---|---|
| SHA-256 | `3977a21a9d3c71e92bbad445b22dc6e68040655b471c43a4049a907b43c7eda7` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-03 03:03:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8453a696ca795ff37a4fa2d2b33d30ff` |
| SHA-1 | `68656aed5bbb983a73993adc7b14cf76e78ec932` |
| SHA-256 | `3977a21a9d3c71e92bbad445b22dc6e68040655b471c43a4049a907b43c7eda7` |
| SHA3-384 | `4df96538a6e581e6ff61fb2982524eb2e0dbd83c6465020c91c7f5531b42c0faf573b6ed07a16cb43b873341db9a51d8` |
| TLSH | `T1E7C27D956A867C44BEC94A3E4CBE2B1D6DF5C3D1224D42AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:/c8vCB+25j6es8R1t9FYpMSUpi+20qUpi+20YQX:E8l25JNd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_3977a21a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3977a21a9d3c71e92bbad445b22dc6e68040655b471c43a4049a907b43c7eda7"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 03:03:54"
  condition:
    hash.sha256(0, filesize) == "3977a21a9d3c71e92bbad445b22dc6e68040655b471c43a4049a907b43c7eda7"
}
```

### Sample 13: `6b72d0a9ad928800`

| Field | Value |
|---|---|
| SHA-256 | `6b72d0a9ad92880093950575d538c51689070f7e6513dae7c682f35ee51eb7e8` |
| Family label | `unknown` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-03 02:57:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `806db13d435c656de9ecb66e23430734` |
| SHA-1 | `7c969e7fc2a686557690c8a6e6763446de2ac972` |
| SHA-256 | `6b72d0a9ad92880093950575d538c51689070f7e6513dae7c682f35ee51eb7e8` |
| SHA3-384 | `bd066801b9840223ed497b083b67be27102d2ebe7f1b9e02ed563bb65a4fc4a962a10e2e7f2d43a22159cf9b4895f7b3` |
| TLSH | `T1F943C896B8D39A6AD2C1533AFB4FD78A33A277D8C2DE3703C9150A2177CA54F4D22950` |
| TELFHASH | `t186f09e45fd744b188de27674ac8c03a184134313612387248f98d9e0cc3e11ab74cd1d` |
| SSDEEP | `1536:YG9ypqZR3uPwpwXR2VBH4r7FBVeaKYsFtP3YYhmxGXwt:YGykLR/H4HFBoUs/P3rmxa2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_6b72d0a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b72d0a9ad92880093950575d538c51689070f7e6513dae7c682f35ee51eb7e8"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-03 02:57:37"
  condition:
    hash.sha256(0, filesize) == "6b72d0a9ad92880093950575d538c51689070f7e6513dae7c682f35ee51eb7e8"
}
```

### Sample 14: `0e65ee89ff5fc6b6`

| Field | Value |
|---|---|
| SHA-256 | `0e65ee89ff5fc6b61425c9e1419b3c528d1ab8ddfda5943916815c7708d1a800` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-03 02:57:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6d6539f76d0234c41cb1e13c6b35c18` |
| SHA-1 | `89306ab34756172a5fbb92edca363584bf012704` |
| SHA-256 | `0e65ee89ff5fc6b61425c9e1419b3c528d1ab8ddfda5943916815c7708d1a800` |
| SHA3-384 | `6dbb18c22f71f114af1bf22aeb87188a61f9529647b58841118221419dbe05cb36ae32cbea71d6501562422a6e025b67` |
| TLSH | `T158D35BB3C8352F68E6689474B0309F7C1F63A52581CB1FA996B7C2758087E9DF5093B8` |
| SSDEEP | `1536:Tu6qQ9suwLYCBanAumfhhxo/CxKRn/t7DIoU2H0pTW8zcs36/jW/qRpk:TlqQiAnmfDxixRlxUwITWUcsK6/Apk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_0e65ee89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e65ee89ff5fc6b61425c9e1419b3c528d1ab8ddfda5943916815c7708d1a800"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-03 02:57:36"
  condition:
    hash.sha256(0, filesize) == "0e65ee89ff5fc6b61425c9e1419b3c528d1ab8ddfda5943916815c7708d1a800"
}
```

### Sample 15: `c6b26808450ef52a`

| Field | Value |
|---|---|
| SHA-256 | `c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc` |
| Family label | `unknown` |
| File name | `c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc.exe` |
| File type | `exe` |
| First seen | `2026-09-03 02:57:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffa5232a97b3d07ef9df8af4426f0a9a` |
| SHA-1 | `aa5417f848dda405586134445095ec74b38ae3e2` |
| SHA-256 | `c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc` |
| SHA3-384 | `656895b58979dbe1afcdf106c8ae374d5d67f51b898fec769f76d3364d2053dd765447385f20ab33d565be8e32bb5d37` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T1E8D52399F9F20974C472C3B78F82F06DB019BB920B715DA77ADC6A008D67A946C36374` |
| SSDEEP | `49152:9QdyrsiiL3kzks1jl6ZaV0sl9PrfLefDMpA7J97KGjYWfYcI6xFuPEv:98f/Uzks1AZaH9PrsgypFM3AOc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_c6b26808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc"
    family = "unknown"
    file_name = "c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc.exe"
    file_type = "exe"
    first_seen = "2026-09-03 02:57:36"
  condition:
    hash.sha256(0, filesize) == "c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc"
}
```

### Sample 16: `1081a33b778532e6`

| Field | Value |
|---|---|
| SHA-256 | `1081a33b778532e62bbd9c7a820c1cb3e7aaa7f8eb530f051bfdfff1df4c26ee` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-03 02:54:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ded58c0dd600085b8ffc4f1d86923667` |
| SHA-1 | `bcf70a9e0921b109b8a30452528b20c16747366f` |
| SHA-256 | `1081a33b778532e62bbd9c7a820c1cb3e7aaa7f8eb530f051bfdfff1df4c26ee` |
| SHA3-384 | `dd504b25f52282d3cf5a3e9cbc8b759fd07e83dc8c90c254f119ce7d45b118e9717bf7d1edb94bc4b80fca6078b8aeed` |
| TLSH | `T19E0449C7F900DEBEF80AE33748534919B130BBA214925A336257357BED3A1990577F8A` |
| SSDEEP | `3072:f+R/QBbHTaBClaVzDZUZ1km3/JAgx960ujVrjbiYLjZXdycd0EfS:fG/sUtUZGmmgL60udLjLyc+EfS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_1081a33b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1081a33b778532e62bbd9c7a820c1cb3e7aaa7f8eb530f051bfdfff1df4c26ee"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-03 02:54:34"
  condition:
    hash.sha256(0, filesize) == "1081a33b778532e62bbd9c7a820c1cb3e7aaa7f8eb530f051bfdfff1df4c26ee"
}
```

### Sample 17: `9023ab82373fb0f7`

| Field | Value |
|---|---|
| SHA-256 | `9023ab82373fb0f73383ef04391da19e6920a757f841c42c447a5d23a0caeb9e` |
| Family label | `unknown` |
| File name | `Day01-001.png` |
| File type | `unknown` |
| First seen | `2026-09-03 02:54:34` |
| Reporter | `anonymous` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff0720cc9ffe4b701d5a55b8578f6dc3` |
| SHA-256 | `9023ab82373fb0f73383ef04391da19e6920a757f841c42c447a5d23a0caeb9e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_9023ab82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9023ab82373fb0f73383ef04391da19e6920a757f841c42c447a5d23a0caeb9e"
    family = "unknown"
    file_name = "Day01-001.png"
    file_type = "unknown"
    first_seen = "2026-09-03 02:54:34"
  condition:
    hash.sha256(0, filesize) == "9023ab82373fb0f73383ef04391da19e6920a757f841c42c447a5d23a0caeb9e"
}
```

### Sample 18: `505f5cb7c7f77e79`

| Field | Value |
|---|---|
| SHA-256 | `505f5cb7c7f77e79627c8c5131bb3907a58924fae413a0166412598a2bda4491` |
| Family label | `unknown` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-09-03 02:54:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83c1b99bcfe966d6478d11b6c02e8936` |
| SHA-1 | `162fc120a4c2f2d29103afe85c82597eec1391da` |
| SHA-256 | `505f5cb7c7f77e79627c8c5131bb3907a58924fae413a0166412598a2bda4491` |
| SHA3-384 | `3ae70292bb9dba4392dbf3590702125b3fbffa0c6a4aab9f7f68282d1d6b80a8d9f44aaa1cf66c558b83193763d1f6d3` |
| TLSH | `T15AF3F745FC919F26C6C256BBFB4E828D372617A8D3EE320399255F21378B95B0E37142` |
| TELFHASH | `t132d0123bb51e97fc22c816d1156d63005b28f4851b15205705dd0e9fa156433b21b325` |
| SSDEEP | `3072:yvErTxgqZb6Wir4UM3b/C04ukyjuJvYV3liU+0v:ysrTxfZb6Wir4d604uPju2V3liU+0v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_505f5cb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "505f5cb7c7f77e79627c8c5131bb3907a58924fae413a0166412598a2bda4491"
    family = "unknown"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-03 02:54:33"
  condition:
    hash.sha256(0, filesize) == "505f5cb7c7f77e79627c8c5131bb3907a58924fae413a0166412598a2bda4491"
}
```

### Sample 19: `c156082ea56c54a8`

| Field | Value |
|---|---|
| SHA-256 | `c156082ea56c54a81382e990581ef7c9f6415f29bddde455c2241b245dd4633f` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-03 02:51:34` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2bb38e8d014053ec8916a7b5375b0a1` |
| SHA-256 | `c156082ea56c54a81382e990581ef7c9f6415f29bddde455c2241b245dd4633f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_c156082e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c156082ea56c54a81382e990581ef7c9f6415f29bddde455c2241b245dd4633f"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 02:51:34"
  condition:
    hash.sha256(0, filesize) == "c156082ea56c54a81382e990581ef7c9f6415f29bddde455c2241b245dd4633f"
}
```

### Sample 20: `ce99a1520f381fba`

| Field | Value |
|---|---|
| SHA-256 | `ce99a1520f381fba7ca927bc9e214b6e34bebd54548c1c22543bc5b39660510d` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-03 02:51:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5521a82046a18f865069931496072edf` |
| SHA-1 | `c6161eb7d2b69508a0bb871f13e8bd78a5e9c609` |
| SHA-256 | `ce99a1520f381fba7ca927bc9e214b6e34bebd54548c1c22543bc5b39660510d` |
| SHA3-384 | `538303de56509997823868caead8baa555924557f1a5039ebc8fb1b60841e498e8132480b53265b7dbf89c80966454dd` |
| TLSH | `T1993112DE01245E710142DA8F72B73188B59DA5FB2C8FE3E888091EAD568C7CCF661B49` |
| SSDEEP | `24:b/JMClKoTpupm1nzeDmvpc6Bc61Ey8gWVn:9pKEBymc6Bc6T5WVn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_ce99a152
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce99a1520f381fba7ca927bc9e214b6e34bebd54548c1c22543bc5b39660510d"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-03 02:51:33"
  condition:
    hash.sha256(0, filesize) == "ce99a1520f381fba7ca927bc9e214b6e34bebd54548c1c22543bc5b39660510d"
}
```

### Sample 21: `29797d9cd6453d3c`

| Field | Value |
|---|---|
| SHA-256 | `29797d9cd6453d3c7e6da7322e296434a7fe7bbb844a682065c334f6031c667f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-03 02:48:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `feb98963a3c8c9546df22ae6d3da284a` |
| SHA-1 | `ab0b4a6d69a66ccf83c70a928eee9f2788006abe` |
| SHA-256 | `29797d9cd6453d3c7e6da7322e296434a7fe7bbb844a682065c334f6031c667f` |
| SHA3-384 | `7fcc1e0b3c1c0cf994a976fc86091c5d001cef55e6637adedbe0d5aba1980b2b2c8eb4bfc05165213167a7b3bef16581` |
| TLSH | `T188236C6526857C15AA99C4361C7E2F0CBDAD43E6320452DE7FCE3CF28C4AA9DA20971D` |
| SSDEEP | `768:scsr0a1ldG9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Chjcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_29797d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29797d9cd6453d3c7e6da7322e296434a7fe7bbb844a682065c334f6031c667f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 02:48:38"
  condition:
    hash.sha256(0, filesize) == "29797d9cd6453d3c7e6da7322e296434a7fe7bbb844a682065c334f6031c667f"
}
```

### Sample 22: `e63465a408f71076`

| Field | Value |
|---|---|
| SHA-256 | `e63465a408f710767942b9e7dd7a81c6aa28832f528f47ee4963f8f2b6468f46` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-03 02:39:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6b9fa3e865ef526bf10c8303c472196` |
| SHA-1 | `727821066b755fd487e928399091f6dca4ca15d4` |
| SHA-256 | `e63465a408f710767942b9e7dd7a81c6aa28832f528f47ee4963f8f2b6468f46` |
| SHA3-384 | `80b6d888fb4ddb0ef75b787d7fa9d32fe60f7ad469e88ab2ff97ca3ab1b9388429b3521b69393ae1289fbc7773347941` |
| TLSH | `T14A24961E6E228F7DF279873487F78A35D75923D622E1D640E1ACD1111E2039EA41FBAC` |
| TELFHASH | `t117418218097817e0a3295d9d459dff37d6a331df7e166c378e11e86aab69a434e10c0c` |
| SSDEEP | `3072:puvywIzosGY559rIng+RnwwnV7jKaLuMcC7DKIE1kNcB3BcMl:puvywIzJGwnrI3R+muMT7GIqkNE3BcA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_e63465a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e63465a408f710767942b9e7dd7a81c6aa28832f528f47ee4963f8f2b6468f46"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-03 02:39:33"
  condition:
    hash.sha256(0, filesize) == "e63465a408f710767942b9e7dd7a81c6aa28832f528f47ee4963f8f2b6468f46"
}
```

### Sample 23: `f8e48c91780b5caf`

| Field | Value |
|---|---|
| SHA-256 | `f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b` |
| Family label | `unknown` |
| File name | `f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b.exe` |
| File type | `exe` |
| First seen | `2026-09-03 02:27:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da4b6a146401e4fee3845e37d578b7f9` |
| SHA-1 | `b8ff7cf32ed4da0850346b7284ebcddb511774a0` |
| SHA-256 | `f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b` |
| SHA3-384 | `6b3132c5621a8a5bf6371cf9eb04045a0440cd88d4a93e2e3647bcaa0d2b1fa94d526f2754ada4262653e56074289185` |
| IMPHASH | `009a6997980020a892fd5267e2082fa5` |
| TLSH | `T103A45C40B2B95165CAB19D7D8A72929A98F0FB0CC41D4653BBEAB4E23FBC750C490C5B` |
| SSDEEP | `6144:UFdaFon66fPiE+o7xEKKjecXW5ZmBGpeCzZuT7kqofNfKrWBMCsnBEgokIvgtPss:GdF/fa6/TvAh1LwHx3/HaX8SGY/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_f8e48c91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b"
    family = "unknown"
    file_name = "f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b.exe"
    file_type = "exe"
    first_seen = "2026-09-03 02:27:18"
  condition:
    hash.sha256(0, filesize) == "f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b"
}
```

### Sample 24: `e9aafe8252705c37`

| Field | Value |
|---|---|
| SHA-256 | `e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f` |
| Family label | `unknown` |
| File name | `e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f.exe` |
| File type | `exe` |
| First seen | `2026-09-03 02:12:21` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ff8a5302dedbb910d1b9a28bc5cb16d` |
| SHA-1 | `3f7ec7c64287bf2e4daca3de48fec42a18501a14` |
| SHA-256 | `e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f` |
| SHA3-384 | `05f1caca928b9bded04520ff11b38147e2af4f866797e2e5b8691f0b009d65b0953359b8e1b11d2989fd39dfe19a8640` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T1EFD5239435F759B5CC37C7B29F57E0AEB23A37A08A608E17FA8D29048E835905837375` |
| SSDEEP | `49152:mQeUbywJEXvLZ1uixrnPsdAU50tLPIIrwcZZ+/xkhKESZfaEAgBm:LekovzzxrnPnU4LA2VZZ1JF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_e9aafe82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f"
    family = "unknown"
    file_name = "e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f.exe"
    file_type = "exe"
    first_seen = "2026-09-03 02:12:21"
  condition:
    hash.sha256(0, filesize) == "e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f"
}
```

### Sample 25: `b7de6647c4ef8606`

| Field | Value |
|---|---|
| SHA-256 | `b7de6647c4ef8606dbbdf967b66c4367d326e096f09bb2f6aea97b3bc9f1560f` |
| Family label | `unknown` |
| File name | `Agency_Appointment_MT_Griya_Bugis_Letter.js` |
| File type | `js` |
| First seen | `2026-09-03 02:12:12` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf64fc7ca2bb4f032351afba246b31b5` |
| SHA-1 | `87ce8172e166ec9a2df3fddab20b453dc7f89739` |
| SHA-256 | `b7de6647c4ef8606dbbdf967b66c4367d326e096f09bb2f6aea97b3bc9f1560f` |
| SHA3-384 | `4a60a7ae6aea43c9e90f2813a680ba0eea783d3b59561d98b8ce0b9d133ee6c21a91aa3696cb660693be7d5155c5a0ca` |
| TLSH | `T133E5E7D237DEA746841A776AA00DAD2C4B5A41311FC339D16BDF0AB8870F1825AD4FDE` |
| SSDEEP | `12288:DsRQcMIQeYskc/oR94hxYswvXqlIXVRc7OYjjgvpjDaIvHD6fVpFwEpqMLURjQTD:D+TMIPh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_b7de6647
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7de6647c4ef8606dbbdf967b66c4367d326e096f09bb2f6aea97b3bc9f1560f"
    family = "unknown"
    file_name = "Agency_Appointment_MT_Griya_Bugis_Letter.js"
    file_type = "js"
    first_seen = "2026-09-03 02:12:12"
  condition:
    hash.sha256(0, filesize) == "b7de6647c4ef8606dbbdf967b66c4367d326e096f09bb2f6aea97b3bc9f1560f"
}
```

### Sample 26: `faddaa67db9ba811`

| Field | Value |
|---|---|
| SHA-256 | `faddaa67db9ba8110597b04ffecba8e37c8a54c1b257d98701e0a85035224c08` |
| Family label | `unknown` |
| File name | `RFQ_LINKER MARINE SERVICE RefN0_LMS_03.09.2026.js` |
| File type | `js` |
| First seen | `2026-09-03 02:01:40` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c836906903a47995fe5fb2b225ec49e7` |
| SHA-1 | `5aa5a272b03a74faa0afc67b5c1378c574bec33a` |
| SHA-256 | `faddaa67db9ba8110597b04ffecba8e37c8a54c1b257d98701e0a85035224c08` |
| SHA3-384 | `49e4f686d4bf40aa557082c41bbd107dcab42526a959bc7ab545c101ee14e5245b9e54b9a1f751e03233c762815498ed` |
| TLSH | `T1DB675B4F46BDB952F5C32DD3F99A04CA9746B9E073706B1C0B058018BB8989B73E3D5A` |
| SSDEEP | `3072:gnarWdXVWhRsFoR1rYKd5c9htUujbwEKVoebC8uwEIcDvFInEOYmvmCpLNkE1H0f:W` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_faddaa67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faddaa67db9ba8110597b04ffecba8e37c8a54c1b257d98701e0a85035224c08"
    family = "unknown"
    file_name = "RFQ_LINKER MARINE SERVICE RefN0_LMS_03.09.2026.js"
    file_type = "js"
    first_seen = "2026-09-03 02:01:40"
  condition:
    hash.sha256(0, filesize) == "faddaa67db9ba8110597b04ffecba8e37c8a54c1b257d98701e0a85035224c08"
}
```

### Sample 27: `b9608f3bdd4fb928`

| Field | Value |
|---|---|
| SHA-256 | `b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98` |
| Family label | `CoinMiner` |
| File name | `b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98.exe` |
| File type | `exe` |
| First seen | `2026-09-03 01:52:27` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6abba47ce5b7f42bcf077a3d61448272` |
| SHA-1 | `8187b9b52435f92f4d07d278aed01d4dcab48a8f` |
| SHA-256 | `b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98` |
| SHA3-384 | `05aa9a3fceb116ae0e611621cfc9e07fdb9327d65fac0c8af12c496b048176c41e4a4666ef2f131634ed9fbf1ace17c3` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T14236338A2CC285B5D85BC7786A2270AD737FB3A04860BE5F37CE6E044E56E09547B3C5` |
| SSDEEP | `98304:Ms6IS6vPluvdFnec5YzKfSYkvCnD9RghPyiHDufkaAE9pVB:MHcvUecqeQv8Mhai69B` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_027_b9608f3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98"
    family = "CoinMiner"
    file_name = "b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98.exe"
    file_type = "exe"
    first_seen = "2026-09-03 01:52:27"
  condition:
    hash.sha256(0, filesize) == "b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98"
}
```

### Sample 28: `ebcd6dd0aeeb568b`

| Field | Value |
|---|---|
| SHA-256 | `ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717` |
| Family label | `unknown` |
| File name | `ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:37:31` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03750f57fb8e7aba283b78631467b91c` |
| SHA-1 | `e5cf90e809b6a0a85c286f2aa1f770415d46f61f` |
| SHA-256 | `ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717` |
| SHA3-384 | `1ee3c8691ca33316f9bb88ae64da5f64bf8a76f3bef332efb2cdda50a6d94a81eb34f117b13edeac5918cc9b47fbec5d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1732833477D9164A8D9569B38E57B42217EA0BCCCC73277A72D50B2302F247C0AEFAB45` |
| SSDEEP | `1572864:yQhgMhChcXS4NEoXjwCK35zZeYOFdQc6Nl0ZVqqmrqacpwL9eyFwsZVqJMR:rhFU+X/NEoc/EdQcBVlm2Rp8EcZuJMR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_ebcd6dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717"
    family = "unknown"
    file_name = "ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:37:31"
  condition:
    hash.sha256(0, filesize) == "ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717"
}
```

### Sample 29: `a105ff3e50426f85`

| Field | Value |
|---|---|
| SHA-256 | `a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd` |
| Family label | `Vidar` |
| File name | `a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:37:20` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6850ffabce6a5e021e9e228ca760e4a` |
| SHA-1 | `515f8c4b36ed45212094bd801cffffb1257e7b14` |
| SHA-256 | `a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd` |
| SHA3-384 | `be6177b8bc18406d9bf801796985c2cce21ea84829578732eb3c2e1fe14c13de88206ebc4c00d0bcd7e66c9741dc6d97` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16B2833477D9165A9D8129B38E03B42617EA47CCCC73577E72DA0A2302F287C16EFAB45` |
| SSDEEP | `1572864:yrcRac4l6nNiyyY2FzxgYlR6zu/WOfo5aqrHED4XKuuNhahlZluXiymv:9i4NdyrFxVR6MR1qrHQsKjNhahzMU` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_029_a105ff3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd"
    family = "Vidar"
    file_name = "a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:37:20"
  condition:
    hash.sha256(0, filesize) == "a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd"
}
```

### Sample 30: `866b1b1fa53cc679`

| Field | Value |
|---|---|
| SHA-256 | `866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e` |
| Family label | `Vidar` |
| File name | `866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:37:11` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `196700536a19e531171e1f5dfb571773` |
| SHA-1 | `fc4ac53f8549f1870766ee69bc8b6d6a3a9e6311` |
| SHA-256 | `866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e` |
| SHA3-384 | `8ebcce614b8cecaae13da896ea5a9d979149da8178d9476d015d2da44a5e33b539375ddd43d229d8622213b877c69211` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1602833473D916569C9229B38E47B02617BA47CCCC736B7E32E90A2702F257C05EFAB45` |
| SSDEEP | `1572864:yn0qbtW8Bcje2FxLwvgTYtN/EmWANp+Ji6+euWA0XDRQdy9mlT:TqESZv1pLzbbS12yS` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_030_866b1b1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e"
    family = "Vidar"
    file_name = "866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:37:11"
  condition:
    hash.sha256(0, filesize) == "866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e"
}
```

### Sample 31: `d21d068229f42021`

| Field | Value |
|---|---|
| SHA-256 | `d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0` |
| Family label | `Vidar` |
| File name | `d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:37:03` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccc9720656e0bed9652e15a67019c1db` |
| SHA-1 | `5fd17d3f281ce81e2e754c5dbcadf034d71e1a67` |
| SHA-256 | `d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0` |
| SHA3-384 | `64125b0b184f30a5bf2f4589c1ec740dc3e3ce7059413042ab9ffe28331a69de85cecf75ba9e22f4e5a952dace137781` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B52833473D956569C9129738E47B42217BA4BCCCC73677E32E90A2302F24BC06EFAB55` |
| SSDEEP | `1572864:y72GkzzCu0gJ4NqNZNCVQ5jRgNZrODo1hnr0SMDMk4B4RWenRMVK1y:mPkL0+x7NCVQ5j+NQo1NPMpRW0RYWy` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_031_d21d0682
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0"
    family = "Vidar"
    file_name = "d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:37:03"
  condition:
    hash.sha256(0, filesize) == "d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0"
}
```

### Sample 32: `065f8b64455be57d`

| Field | Value |
|---|---|
| SHA-256 | `065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660` |
| Family label | `unknown` |
| File name | `065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:56` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1073fe13d4ee2ace9bb5856e18185a93` |
| SHA-1 | `0879bf67e8fdb2ebcde1862cf1a4d6fb99b28b64` |
| SHA-256 | `065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660` |
| SHA3-384 | `8866dce3c53142f9e60e6222989e7cd6486f117d6f21bd6e8c901b687b4b94916f48caa6a4e1b355900915afd012b8cc` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B92833477D956569C9129B38E57B0261BA64BCCCC73277E32E50B2302F24BC06EFAB45` |
| SSDEEP | `1572864:yzsW3+SiTnvnrUC/03/WYySlYt5g8XRrFZZRKrPvit3v61qf2hhOwK6x97/:uknvnrUCmySlQR/ZsPvs3v6y273K6j` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_065f8b64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660"
    family = "unknown"
    file_name = "065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:56"
  condition:
    hash.sha256(0, filesize) == "065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660"
}
```

### Sample 33: `affbb003f93d939e`

| Field | Value |
|---|---|
| SHA-256 | `affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5` |
| Family label | `unknown` |
| File name | `affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:49` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47e30dc6fc9a22c718a748e686341e0d` |
| SHA-1 | `f19e3b7c60b73261dbe2a99b78c53b15cc26e0c2` |
| SHA-256 | `affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5` |
| SHA3-384 | `f2e9ba87bd3f8d5ba9bd33efb4189d72f1f8a419528e66dbc545fdda73ec8e275dcc873532dace006cb704a855d9d3c6` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1BA2833476C916469D9229B38E47B4261BF647CCCCB3673A32D50B2302F247C1AEFAB55` |
| SSDEEP | `1572864:ygcl8g5ab6KuYbMHnWAz3hZWiJUSuYRVBhrcq6RTJq5AgkYYmnrNe366n3nwbRv9:cBu6SoHWAxEiJ9R9t6RlhgBJg366n3nU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_affbb003
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5"
    family = "unknown"
    file_name = "affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:49"
  condition:
    hash.sha256(0, filesize) == "affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5"
}
```

### Sample 34: `bb6afa93514e7527`

| Field | Value |
|---|---|
| SHA-256 | `bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4` |
| Family label | `Vidar` |
| File name | `bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:43` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab1801280f0266457be50d78ac198581` |
| SHA-1 | `c9a2b5bb3d4207a283568eaced5616aa90317930` |
| SHA-256 | `bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4` |
| SHA3-384 | `69826e8523da163cf6b36de8ea0418fda20d46f6bbc7bec31bb2cc68e7cea65026902e22a63fc93e0421a90a3d59f943` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15C766C0BBF9541A8C01AEA35C5A79212FA717C8CCB3473EB5E9061342E367D26DB5F24` |
| SSDEEP | `98304:8zYVHM+bb+qdF8pklF5NUzCt2kslgyGIVsCCCHYeAA2dAZlMwJU:8sHM+bb+qdF8pkP5NUW2kslbGI4Q2WrU` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_034_bb6afa93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4"
    family = "Vidar"
    file_name = "bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:43"
  condition:
    hash.sha256(0, filesize) == "bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4"
}
```

### Sample 35: `7fdd4c3e1a3f88b7`

| Field | Value |
|---|---|
| SHA-256 | `7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc` |
| Family label | `unknown` |
| File name | `7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:40` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bbe2a6af1ed4e1538b2a5420614606d` |
| SHA-1 | `bff36409b6b65d7358cc3aa5da99cfa03e66b109` |
| SHA-256 | `7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc` |
| SHA3-384 | `5888426ad7159caf242eb588b170f7ed2e4fd2204c303251c7fd191364545a4e6d1772dd3f2d793c8c3467cca0f1b56c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E6467C476D912569D86AD738E47B4361BAB4BC8CC73673A32D50B6302F207C0AEF6B15` |
| SSDEEP | `49152:L++VY7QzJNBQ2kzfxy0Nmydb0HLg6KfYhWYUMYubyEBfebYNmtbKbokyedXAPm7w:LbN45HVQs6pWYUAGpEldhYjT73jr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_7fdd4c3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc"
    family = "unknown"
    file_name = "7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:40"
  condition:
    hash.sha256(0, filesize) == "7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc"
}
```

### Sample 36: `b968e449be596e2d`

| Field | Value |
|---|---|
| SHA-256 | `b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012` |
| Family label | `Vidar` |
| File name | `b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:38` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fd91d2349af5d785eb014d7d2fd6741` |
| SHA-1 | `877ec4960e71700865583d5d325baafe61d1f456` |
| SHA-256 | `b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012` |
| SHA3-384 | `67588789ae47ef32f1b25160485b546e0519951b9da92968a6bbc48c788cd9b075c7c1773f8bd5bc3b374ad1629e9f30` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B71833477C9165A9C8269738E47B42617B64BCCCC732B7E32D50A6302F247C0AEFAB55` |
| SSDEEP | `1572864:yug7NfFn5zQwJJjpsdFVDCOBFYveAgL/8N4PNJVUTaK0/ertFUnbhbwW10q9WlP2:WR5JsTV1fYeAgL/8qJyaP/eZFUnbpwW1` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_036_b968e449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012"
    family = "Vidar"
    file_name = "b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:38"
  condition:
    hash.sha256(0, filesize) == "b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012"
}
```

### Sample 37: `586a770f60fb43e9`

| Field | Value |
|---|---|
| SHA-256 | `586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99` |
| Family label | `Vidar` |
| File name | `586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:32` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f04c922c46325270221f9b6fef2cd6c` |
| SHA-1 | `179701a6daa16546342e195b2bfd91ae533f4596` |
| SHA-256 | `586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99` |
| SHA3-384 | `f09607b717fdab6d61eb92eb3090004c8c63a58a36cd6bd84dd1127a86f9407a23adb52ab182aecc2c4692a78f64db32` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1432833477D916469C9169739E47B43216BA0BCCCC73277E32E90A6302F24BC06EFAB55` |
| SSDEEP | `1572864:y86jEv/I3NNU/HPLrcIUBJ8YG6ESn0ZxYJBeE0KQfZXBIgEvU3KdV41S8cj:AQ3I3/svLrTUg5RQuejh0df5BI1bn4Oj` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_037_586a770f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99"
    family = "Vidar"
    file_name = "586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:32"
  condition:
    hash.sha256(0, filesize) == "586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99"
}
```

### Sample 38: `8761ae715595e4cc`

| Field | Value |
|---|---|
| SHA-256 | `8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42` |
| Family label | `unknown` |
| File name | `8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:25` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06ec5ba3022d81bb55d7fbf1a8add2cb` |
| SHA-1 | `d563a056a9e0c9609b26559bf0398cf8b95829ca` |
| SHA-256 | `8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42` |
| SHA3-384 | `40b777f6858f329991dda90b8ea9a8f990a508c7c36010a87da01adf6cdf89925b92fc343dffc7c68f76b6866a842893` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17D2833473D8565A8C9529738E57B4231BEA47C8CC73277A32DA0B6302F24BC05EFAB55` |
| SSDEEP | `3145728:hSL3c7V4W9FQW7/fnth6xo+IZW4XEjsMTe/:hR4Wku/ftYZUW4X83e/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_8761ae71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42"
    family = "unknown"
    file_name = "8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:25"
  condition:
    hash.sha256(0, filesize) == "8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42"
}
```

### Sample 39: `2679d8e62411ea12`

| Field | Value |
|---|---|
| SHA-256 | `2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37` |
| Family label | `Vidar` |
| File name | `2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:19` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b75a68bc47a204cc9443a9a00155f978` |
| SHA-1 | `e6f3ce4b9a5a51cab5b5039159f8cf73b240d26f` |
| SHA-256 | `2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37` |
| SHA3-384 | `2fac0b869dde05baee9e2b022d9a49ed42398a76d90dc4c53ac23dfd1cd75cfcac282f02ae2f400fbe37f85c01e90157` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17D1833477DA165A9D9629738E53B42617FA4BC8CCB3277E32D9061302F247C09EFAB44` |
| SSDEEP | `1572864:yvd/WoOONJapx1PNGjqBN6jR0Sj6c4FlSRWCkvsWJhtJcVE2AT2UF:yd/lOEJapNb410Sj54eRWlhKE2AT2k` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_039_2679d8e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37"
    family = "Vidar"
    file_name = "2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:19"
  condition:
    hash.sha256(0, filesize) == "2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37"
}
```

### Sample 40: `8ec9b81c2be13a2a`

| Field | Value |
|---|---|
| SHA-256 | `8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b` |
| Family label | `unknown` |
| File name | `8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:12` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35ec690a3ffff6dc3fd104e644bb2c13` |
| SHA-1 | `1af0aa4a6a979b6f8216964db4c19269dcdc6135` |
| SHA-256 | `8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b` |
| SHA3-384 | `d7d93207f95abef9cc3fd3152ad39eb6b177464a0366ebb6df49bb9af2aa54e49ffedb3d3110abc473a4f020b0431624` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T157467C4B7D916569C9669B38E43B43617B60BCCCC73177A32E90A6702F207C06EFAB15` |
| SSDEEP | `49152:vWPOZeN5DfoR4ZBY9WwPUX3CkiJC0zYRThVHQEOCSxaZTZpvALZIqzXTw5xa1jKi:vbXGvY/W32IHICo9hzc72j9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_8ec9b81c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b"
    family = "unknown"
    file_name = "8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:12"
  condition:
    hash.sha256(0, filesize) == "8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b"
}
```

### Sample 41: `2af024203c58f63a`

| Field | Value |
|---|---|
| SHA-256 | `2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26` |
| Family label | `Vidar` |
| File name | `2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:11` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a161422c933602162575732787e6a1e` |
| SHA-1 | `7b35170205aad6938b1caf4d1aeba4376de308aa` |
| SHA-256 | `2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26` |
| SHA3-384 | `070eb92be99147236c4b1a6f39016c578ca6011f46bcd4b0acd481afabd677fcb72b4c37091925e091b205f5b38c7182` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1CD467C477E9169A9D8269738E17B03617BA0BC8CCB3173A32D50B2702F257C16EF6B15` |
| SSDEEP | `49152:jmHtGEkVbSdTnU6ztuUu8XIxR+q4FbheS4Evf71Uytb45s0Tme4iBKw5xqDnap:j89nUYLiMhLf71U8cs0q47qD6` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_041_2af02420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26"
    family = "Vidar"
    file_name = "2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:11"
  condition:
    hash.sha256(0, filesize) == "2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26"
}
```

### Sample 42: `31dca2b9c929b787`

| Field | Value |
|---|---|
| SHA-256 | `31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92` |
| Family label | `Vidar` |
| File name | `31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:09` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `468167385643a7de9dea36fef7eea279` |
| SHA-1 | `7e2f6d05198c20e42f124bb794bbeacee5929930` |
| SHA-256 | `31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92` |
| SHA3-384 | `9b0c2596b87c39d10622af9efbce4f6013e2ad15d9cadf453bf42514eff3d1b0cb78fb0bc17349de7f8bf8f8885db105` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1091833472C916468D9529738E47B43617FA4BC8CCB3277A32E90A2702F357C06EFAB55` |
| SSDEEP | `1572864:yzPtYLkUhKnQjAAAivX/WtRgtcxaHwxo3DAjWyaGqLFuXDvp3Ptzn9Fk:oPtPnQjAjeX/WjgCoToWyaGUFuLJPtDU` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_042_31dca2b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92"
    family = "Vidar"
    file_name = "31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:09"
  condition:
    hash.sha256(0, filesize) == "31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92"
}
```

### Sample 43: `50b80355b83bce83`

| Field | Value |
|---|---|
| SHA-256 | `50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30` |
| Family label | `Vidar` |
| File name | `50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:36:01` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `543ad84c8fdc0b8dfc2e41eb7022e92a` |
| SHA-1 | `8af82eeefe210eefbbe0d7e666c4132c919ee5e5` |
| SHA-256 | `50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30` |
| SHA3-384 | `424d4caad562fc44441747de4d14e391780bcc52f0e0619520c9e2f5236fb8d53d9d63176ea1aaa95f5d617697a7bea5` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1771833472D9161ADD9129B38E47B42217B64BCCCC732B7E72D50A2702F247C0AEFAB55` |
| SSDEEP | `1572864:ysoqeBXAvqFy8SCgicpRa1hOG3s9SA8UtubpcqemH2BF8BQ381EX8xmZv7q0GvGi:BeN7Fy/CcRa1hOGJA8fbpcqemW3aQG3H` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_043_50b80355
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30"
    family = "Vidar"
    file_name = "50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:01"
  condition:
    hash.sha256(0, filesize) == "50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30"
}
```

### Sample 44: `173aa53eac2c81dd`

| Field | Value |
|---|---|
| SHA-256 | `173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d` |
| Family label | `unknown` |
| File name | `173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:35:51` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d94bc0da402548920fc5fd0bd2655b62` |
| SHA-1 | `6125457d249ccf9ed16e06bcac8e8b99b10f5110` |
| SHA-256 | `173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d` |
| SHA3-384 | `0c9e33a299d663ba725677d7e7f3422006c3952a05060086a9339b8daf9b9591b5ee4d8d04abe7bdcd373f2e92c449c9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1DC2833473C9164A9D8169B39E57B0261BE64BC8CC77277A32E50B2702F347C09EFAB54` |
| SSDEEP | `1572864:ys8f+iO/dzKT6lLOqZthW0jJBHrvsKskTIAxAOiiiAa5w60iepgjx1j:k+iWdGT6vthW0dBLvsKskTIAxAOg5w6T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_173aa53e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d"
    family = "unknown"
    file_name = "173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:35:51"
  condition:
    hash.sha256(0, filesize) == "173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d"
}
```

### Sample 45: `be5a7f27fdbe89bd`

| Field | Value |
|---|---|
| SHA-256 | `be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532` |
| Family label | `Vidar` |
| File name | `be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:35:42` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `596147c8d4539199b28e8decd708ef8e` |
| SHA-1 | `d8686bdced1f6881df4c5a1452af5b911a8dc682` |
| SHA-256 | `be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532` |
| SHA3-384 | `f5f186691e03935a3ee0610e8ccf317fb0e27cd96de62f90c72ec83bedbf51e283f700d51f08c1ba9624f4030f9bbb04` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B51833477D916469D9269B38E47B03217EA4BCCCC73277A32DA0A2702F647C05EFAB45` |
| SSDEEP | `1572864:ykmlbuH/KGfqByNNj7CL9ImfrC6uCw+gtTTtKOMMd5L/n2E5WGYBUP:pfrfUykImWndTt/Fn2xQ` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_045_be5a7f27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532"
    family = "Vidar"
    file_name = "be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:35:42"
  condition:
    hash.sha256(0, filesize) == "be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532"
}
```

### Sample 46: `d4429b3ea619c4c4`

| Field | Value |
|---|---|
| SHA-256 | `d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350` |
| Family label | `unknown` |
| File name | `d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:35:35` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d86ecf77f049e187b59a297919c4d1a` |
| SHA-1 | `1064d650df0b6c9a739b3183c63d8d584c5c7794` |
| SHA-256 | `d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350` |
| SHA3-384 | `b7066f23300b7f2d06165e288af3d994ae21b31571cf6d4cb4ed1a37768664554aafb3a255004b1b9855b07cc6425639` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1BC283347BE58A090C5A9D635C9B712217B297888CB3133F32E51AAB12F373D15F7A760` |
| SSDEEP | `1572864:QjrjlW8Ip1MEuAeNPUjNUg/bU/3igXKEyih+2GGA3lMb3qiSxlTyaqnGT4X:KI8UmcU/7yc9SlU3qhTy3m4X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_d4429b3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350"
    family = "unknown"
    file_name = "d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:35:35"
  condition:
    hash.sha256(0, filesize) == "d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350"
}
```

### Sample 47: `a5a7c21a04c0a654`

| Field | Value |
|---|---|
| SHA-256 | `a5a7c21a04c0a654173999496842d1e65ad8831faf5f591f5317deb1d800ccf8` |
| Family label | `unknown` |
| File name | `poop` |
| File type | `elf` |
| First seen | `2026-09-03 01:34:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20ae3417929f72b7b2ae8c135d92b894` |
| SHA-1 | `6edcb65bfeea01ea2841fff9b62a6fbfbf82dc16` |
| SHA-256 | `a5a7c21a04c0a654173999496842d1e65ad8831faf5f591f5317deb1d800ccf8` |
| SHA3-384 | `49d55909c95d9ecd394af0bd7e5f45de42e8887b24aae4ebeebdff5d39eeca39999d52e7dcda178425eef72dfaa25449` |
| TLSH | `T1A5353364DBB4E104FA6A7D7D0CB45C345D2D7C8936FBDF61C4B0E9042AAAD0B878A91C` |
| SSDEEP | `24576:8xjYKXhddU2aABFkxaU1D6tFrGQhl4PRecoNy53r8Nioi5+AWk6dlehn6:8+KxdmybkoU1DgFlNcCyNf0eg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_a5a7c21a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5a7c21a04c0a654173999496842d1e65ad8831faf5f591f5317deb1d800ccf8"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-09-03 01:34:35"
  condition:
    hash.sha256(0, filesize) == "a5a7c21a04c0a654173999496842d1e65ad8831faf5f591f5317deb1d800ccf8"
}
```

### Sample 48: `ff1aeefd1b5b454c`

| Field | Value |
|---|---|
| SHA-256 | `ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af` |
| Family label | `unknown` |
| File name | `ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af.bin` |
| File type | `exe` |
| First seen | `2026-09-03 01:34:20` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0c6e886d1bf83f15687a7f70770d0bb` |
| SHA-1 | `e98921a397b20677c93cfecfa5f8ef173f5fca3c` |
| SHA-256 | `ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af` |
| SHA3-384 | `0b0f5950d7f6c0612ad316bc4d5517a3a6ac6769226a95a9b4369b7c0ad405349421b95dc85022cf3be6a98924075ec9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T185366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaq:uc3XND1aJrCOkq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_ff1aeefd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af"
    family = "unknown"
    file_name = "ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:34:20"
  condition:
    hash.sha256(0, filesize) == "ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af"
}
```

### Sample 49: `d5fa2e2050df64c2`

| Field | Value |
|---|---|
| SHA-256 | `d5fa2e2050df64c22d199fbc883cea114253d778765a41503ce26eab1397c3bb` |
| Family label | `unknown` |
| File name | `meteorclient.live__meteor-client-1.21.11-86c1d3.jar` |
| File type | `jar` |
| First seen | `2026-09-03 01:22:23` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, fake-meteor-site, jar, MeteorClient, meteorclient.live, Minecraft, Polygon, session-stealer, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4f9bb7beb8ddb7d521863216187fb89` |
| SHA-256 | `d5fa2e2050df64c22d199fbc883cea114253d778765a41503ce26eab1397c3bb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_d5fa2e20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5fa2e2050df64c22d199fbc883cea114253d778765a41503ce26eab1397c3bb"
    family = "unknown"
    file_name = "meteorclient.live__meteor-client-1.21.11-86c1d3.jar"
    file_type = "jar"
    first_seen = "2026-09-03 01:22:23"
  condition:
    hash.sha256(0, filesize) == "d5fa2e2050df64c22d199fbc883cea114253d778765a41503ce26eab1397c3bb"
}
```

### Sample 50: `6dd9cbb836647f00`

| Field | Value |
|---|---|
| SHA-256 | `6dd9cbb836647f0028f8569c5c1aa9594501dec9922e1f20c4b3b7ab43f3014f` |
| Family label | `Formbook` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-03 00:52:09` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remcos, exe, Formbook, RemoteHost` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30b261f62be614d8216924c5e255c7de` |
| SHA-1 | `c45ceaa933858e5a92ddac825054ae3c5e5ff0c2` |
| SHA-256 | `6dd9cbb836647f0028f8569c5c1aa9594501dec9922e1f20c4b3b7ab43f3014f` |
| SHA3-384 | `ee087033c91ee2167a71be418c4912236fd26d993e28b906f340716d0c1b11de1aff2c09e9c083a418439ccf7d20833d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CF35DF752218CA23D02E1AB0C95FD3F8DA675FA9D810EF07AEC5FEDBB471B444912602` |
| SSDEEP | `24576:OxWIfp0oELdQEI8KARw3xcWXBveacSXe6B6YMWI7BgsaB:JM0rxQEo5Hb9urlna` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_050_6dd9cbb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dd9cbb836647f0028f8569c5c1aa9594501dec9922e1f20c4b3b7ab43f3014f"
    family = "Formbook"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 00:52:09"
  condition:
    hash.sha256(0, filesize) == "6dd9cbb836647f0028f8569c5c1aa9594501dec9922e1f20c4b3b7ab43f3014f"
}
```

### Sample 51: `67af64ccdb246c4b`

| Field | Value |
|---|---|
| SHA-256 | `67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67` |
| Family label | `Mirai` |
| File name | `67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67.elf` |
| File type | `elf` |
| First seen | `2026-09-02 23:32:20` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab53b158d8b9b062ede6399ae0d83f0e` |
| SHA-1 | `7ccbcdf69bc64f31bf70a99a77aae3d05ac913cc` |
| SHA-256 | `67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67` |
| SHA3-384 | `eb76147c7d7051cf7c816ac9ece2c71d1792803c14b186458496e744c2b5318d37c846f02f1161a9bf31ecf6f994ce11` |
| TLSH | `T15DB36CC9F683D0F2F8660AB5403BA7669B32D535022AEA42D77A1C35FC63550DB1B36C` |
| TELFHASH | `t10c51d5fa697e0ce4f764a845d30d2f217a0ed67b156133b505f3953532a7e8180bac39` |
| SSDEEP | `3072:ZtP8kw55QkyLOUzIvomSfkj7qbEspNdP346g:/8kw3QkpOywbEK7PI6g` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_67af64cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67"
    family = "Mirai"
    file_name = "67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67.elf"
    file_type = "elf"
    first_seen = "2026-09-02 23:32:20"
  condition:
    hash.sha256(0, filesize) == "67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67"
}
```

### Sample 52: `bb15153a05516064`

| Field | Value |
|---|---|
| SHA-256 | `bb15153a05516064114ea1d783dd58c8284e901c8db0647b48e7ff3ff5e22040` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-02 23:29:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7d54e7cd2535e3a827fbba80253c487` |
| SHA-1 | `12533e40d0002ddcf8f10caed14526789af4bd0a` |
| SHA-256 | `bb15153a05516064114ea1d783dd58c8284e901c8db0647b48e7ff3ff5e22040` |
| SHA3-384 | `d19234fbf919d72c45cc624ed133e00fa26a8b37f9ab6fb7a1b0a5ad27bcc14e32e81553fd9975900731d7a7ebb696fb` |
| TLSH | `T1D524B709AF610EFBD86FDD3706E90B4625CC641722A93B353578D928F50AA4F4AE3C74` |
| SSDEEP | `3072:n+IH3HXkhxyRrzPPEwSdFNDmO/TFmpBrBNku+OBgl:zrzPK3r/gpBr8SBg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_bb15153a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb15153a05516064114ea1d783dd58c8284e901c8db0647b48e7ff3ff5e22040"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-02 23:29:38"
  condition:
    hash.sha256(0, filesize) == "bb15153a05516064114ea1d783dd58c8284e901c8db0647b48e7ff3ff5e22040"
}
```

### Sample 53: `5e4aa2174e706863`

| Field | Value |
|---|---|
| SHA-256 | `5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7` |
| Family label | `unknown` |
| File name | `5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7.exe` |
| File type | `exe` |
| First seen | `2026-09-02 23:27:20` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c67d438cadd5a4361382daa6ef51ac57` |
| SHA-1 | `90cd4c1532960a0c593914f3546af251bce5b2d8` |
| SHA-256 | `5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7` |
| SHA3-384 | `30eff58f62ebb2a9187fc6f1746e17e547617e02d0148ceac6770e695b1385b49af79620fd5ea9e4851b831a7700581b` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T172D523AAFD0619B2E836C37B8783A07DB16D37894764CC5F75CC5B40AD929242C3727A` |
| SSDEEP | `49152:wtvxUGj/TH5QskqQVm3hi8eHkV+nDI997WcSpUKQPhWXHHvucqAfek:aTD57DBRDeHkViDIXRSsJWXHP/H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_5e4aa217
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7"
    family = "unknown"
    file_name = "5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7.exe"
    file_type = "exe"
    first_seen = "2026-09-02 23:27:20"
  condition:
    hash.sha256(0, filesize) == "5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7"
}
```

### Sample 54: `c58e18034de47fa1`

| Field | Value |
|---|---|
| SHA-256 | `c58e18034de47fa16597b11ae1c058ee866a8f6d0d8cf4682d0215af07a9ae24` |
| Family label | `ConnectWise` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 23:22:03` |
| Reporter | `Bitsight` |
| Tags | `ConnectWise, dropped-by-GCleaner, E, exe, signed, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b6a3bf347df55db3e9b69eb1e2ab580` |
| SHA-1 | `aa01f11251117f7868f4622a77e777fc12918308` |
| SHA-256 | `c58e18034de47fa16597b11ae1c058ee866a8f6d0d8cf4682d0215af07a9ae24` |
| SHA3-384 | `9df6c95708fb62fcbc985aa30794b166eea75983482884173a6a4887636abd28d0adb9c8e1cf0a6a73fe5a01654213d1` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T13956F141B3D695B5C0BF0638D87A42A65634BC148712CBFF57E4BD296D32BC08E7236A` |
| SSDEEP | `49152:0fRBDtJkGYYpT0+TFiH7efP3nrGLq7FVsLBe+1GVxrKlsuwGenGwfZVkVjOi8if0:Yqs6efP3rn/TYGVxz3GBwRVkGuyXOM` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_054_c58e1803
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c58e18034de47fa16597b11ae1c058ee866a8f6d0d8cf4682d0215af07a9ae24"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 23:22:03"
  condition:
    hash.sha256(0, filesize) == "c58e18034de47fa16597b11ae1c058ee866a8f6d0d8cf4682d0215af07a9ae24"
}
```

### Sample 55: `0b8a6ea5423f6ce1`

| Field | Value |
|---|---|
| SHA-256 | `0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9` |
| Family label | `unknown` |
| File name | `0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9.bin` |
| File type | `exe` |
| First seen | `2026-09-02 23:04:31` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d037a0a99c4c68b4c68e55cf0aed83b` |
| SHA-1 | `6d25e54f12ec5a6b7f0687320c6c1d0cd25a9d62` |
| SHA-256 | `0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9` |
| SHA3-384 | `b90814a0d3a4c70f0b4c79572d46d50250592fe8f7a88fac918ab19c9f1ca902a2148c2bf11aeca0a59df2bf2c2868c1` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1192833473D9164A9D9569B38E47B4361BAA07CCCCB3277A32D90B2302F247C05EFAB55` |
| SSDEEP | `1572864:ywjT1jheJO0P3TTnKBlYr5PtYMhf7JySSGsjI3otLHXN0Hb4y5rTsdEiceLlS:fTHeJO8TDKUdPnf/S/jew3mb4y53sKRr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_0b8a6ea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9"
    family = "unknown"
    file_name = "0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:31"
  condition:
    hash.sha256(0, filesize) == "0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9"
}
```

### Sample 56: `daf4250ed250279b`

| Field | Value |
|---|---|
| SHA-256 | `daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046` |
| Family label | `unknown` |
| File name | `daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046.bin` |
| File type | `exe` |
| First seen | `2026-09-02 23:04:23` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4012f783161a937640f49db7e4e46c2d` |
| SHA-1 | `ee7e5828e0889cbc551f114f4864f6a9005061ed` |
| SHA-256 | `daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046` |
| SHA3-384 | `65ab1c8805a29a6ce390a3d72a6d5bbb36f5464b52f7b2a7a4fddeca1f145fc09194f7ab554a1d189c4f0d1112399818` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1EB2833477D906469D812DB38E47B4262BA74BCCCC73677A32E50A2702F297C05EFAB54` |
| SSDEEP | `1572864:yBLLKY1nJpBkTyfX/NZc7u/sLLzk0DeW7FhSEKWo4pM3hjgUwegBcXUPX:0p1nvxmBn5EJx4CFgBWUPX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_daf4250e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046"
    family = "unknown"
    file_name = "daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:23"
  condition:
    hash.sha256(0, filesize) == "daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046"
}
```

### Sample 57: `58aceed329e0410f`

| Field | Value |
|---|---|
| SHA-256 | `58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163` |
| Family label | `Vidar` |
| File name | `58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163.bin` |
| File type | `exe` |
| First seen | `2026-09-02 23:04:16` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b22f858cc20a727a2699b0f657317bf` |
| SHA-1 | `4072e9cae8d2bfcd913b11333652ddcafaca83d3` |
| SHA-256 | `58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163` |
| SHA3-384 | `7568ff182bdad6cfa10cfe8a455f62fd2a7c9c86a7195cca35041a88b916e4532a148554401c7a5641e8b2b0df9d1679` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1471833477C816568C916AB38E57B42617FA47CCCC73277A32D90A2702F25BC09EFAB45` |
| SSDEEP | `1572864:yV/9eu02YyAT7+vSJyBmKqoZewRfZU3lQUNVlPVmUBy4PYV+F29dVRuTp8mt2:EgNVnsEyBm3oEwRBoVlPknlVHuTprt2` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_057_58aceed3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163"
    family = "Vidar"
    file_name = "58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:16"
  condition:
    hash.sha256(0, filesize) == "58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163"
}
```

### Sample 58: `aba3cc5c9e97db4e`

| Field | Value |
|---|---|
| SHA-256 | `aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552` |
| Family label | `Vidar` |
| File name | `aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552.bin` |
| File type | `exe` |
| First seen | `2026-09-02 23:04:10` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bf34cdd5ded1a967fa2bf428071ea89` |
| SHA-1 | `ee6827bf4352771f5d9159df56b14115d738019c` |
| SHA-256 | `aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552` |
| SHA3-384 | `03ed70567ee6c504484cabec10cf776e2597d032eb22938cafc93fc10fbbef50bd4ffe2fb91423e4ec0e810771f36bd0` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A2466B433D916469C856E739E57B43227B60BC8CC73573A32E90A6702F257C0AEFAB45` |
| SSDEEP | `98304:SC09WQrNlpKhqlHJJM0BV3m7vt/YiWD027ZDo:S8QrR/aSRD00Do` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_058_aba3cc5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552"
    family = "Vidar"
    file_name = "aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:10"
  condition:
    hash.sha256(0, filesize) == "aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552"
}
```

### Sample 59: `07077ec5e760d738`

| Field | Value |
|---|---|
| SHA-256 | `07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca` |
| Family label | `unknown` |
| File name | `07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca.bin` |
| File type | `exe` |
| First seen | `2026-09-02 23:04:08` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `235d2757875f9398e28a19a45949308b` |
| SHA-1 | `561de7eb4b644d306ed385eba482352cc9e64439` |
| SHA-256 | `07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca` |
| SHA3-384 | `c9ae8555fff7878eb6769b2a39e0a0e52fe107751b67cc40679e5bddb10c72ed302b29c243807c52c799ddd81b375a20` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1052833477C8564ADC9169B38E17B0321BE64BC8CC73277A72D90A6302F257C06EFAB55` |
| SSDEEP | `1572864:ytD6uhaBof8ThCd7yPi1jccfhWu/YgTygV1DwPvst/vXaF5kLrSv3u9cF0lmzWbQ:M6uhaBoEThy7yq15W1gz1N3qFKrSv3uG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_07077ec5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca"
    family = "unknown"
    file_name = "07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:08"
  condition:
    hash.sha256(0, filesize) == "07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca"
}
```

### Sample 60: `d425d527f4bf5fa1`

| Field | Value |
|---|---|
| SHA-256 | `d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9` |
| Family label | `Vidar` |
| File name | `d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9.bin` |
| File type | `exe` |
| First seen | `2026-09-02 23:04:02` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee3f9514ff661eab45d5cbeeab12dbd4` |
| SHA-1 | `da0db099df42dd5aec15bfb31c69ba0f488d2f6e` |
| SHA-256 | `d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9` |
| SHA3-384 | `f6352320dc96f055d8221ebae68076c41ff38532b1c3dfd42fcea801faf08df8f0e9f1895520ed090e3913bb6cd27a91` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1592833476D916568D9269B38E43B4321BB64BC8CC73277E32D90B2702F247C06EFAB55` |
| SSDEEP | `1572864:yNQufhXClHPU7sd6XlBOUvSG9YeiQl8y4jjJmMXt6PuTdCDdx:Onfhlsd6PNYeZ49GuTdIx` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_060_d425d527
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9"
    family = "Vidar"
    file_name = "d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:02"
  condition:
    hash.sha256(0, filesize) == "d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9"
}
```

### Sample 61: `842ab7ab49181415`

| Field | Value |
|---|---|
| SHA-256 | `842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857` |
| Family label | `unknown` |
| File name | `842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857` |
| File type | `gz` |
| First seen | `2026-09-02 23:00:14` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec, gz` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1b50fab13b9f816c77b3f42a55b70e1` |
| SHA-1 | `cacf723c0cac0dd9d423c4e311a43d57e28d1adb` |
| SHA-256 | `842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857` |
| SHA3-384 | `3e74215d37b41531dd7d4a4616f02a5f3d482682614b8fbcfce8f61c32b5059549be4a1533c5b316dd0eef1e2982ed84` |
| TLSH | `T185D533739A77EF6249916161B81719D8E0E3F52111C339B64F408CBCE3E4A69E68F3E4` |
| SSDEEP | `49152:Up55rdin5e/zS6/5e8gOGFWHDxun7BTmeD7UnJdDFwWJ2OD7DbkjvIxn1/45:kB05iz7/DPGFWHFunZXonXDFBPjkMxa5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_842ab7ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857"
    family = "unknown"
    file_name = "842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857"
    file_type = "gz"
    first_seen = "2026-09-02 23:00:14"
  condition:
    hash.sha256(0, filesize) == "842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857"
}
```

### Sample 62: `5c80a2d4b00b367d`

| Field | Value |
|---|---|
| SHA-256 | `5c80a2d4b00b367d44f0bc3540f7ec0158e4b216495de17be1ee2dad7a6651b7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 22:52:38` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adc469c1abf14a831a1fa9e7bf894fa7` |
| SHA-1 | `e6a66767c5ffc4f2e569d305cd6aab23bc82d4f5` |
| SHA-256 | `5c80a2d4b00b367d44f0bc3540f7ec0158e4b216495de17be1ee2dad7a6651b7` |
| SHA3-384 | `466fc5b450235478c56f69700977588df349a2fdc5661ca1af7b369cf633f57283e1f79ae6f6fb3c855426cf08acb489` |
| IMPHASH | `5ff667cbb06c6b3aeaca43236983df11` |
| TLSH | `T1C5B4F156B78407F8D026F578D62A6951A2B278922B9275EF036012A71F73BC54F3FF20` |
| SSDEEP | `6144:8D6EpAn94msIgSronclGBHyVF4gFSrr8krN4YjfmE6a4p18/YU3tCssO7OAbrKan:8D6YA94vncoB2VkxNj0n18/9xbrK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_5c80a2d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c80a2d4b00b367d44f0bc3540f7ec0158e4b216495de17be1ee2dad7a6651b7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 22:52:38"
  condition:
    hash.sha256(0, filesize) == "5c80a2d4b00b367d44f0bc3540f7ec0158e4b216495de17be1ee2dad7a6651b7"
}
```

### Sample 63: `3932795771fe8fcb`

| Field | Value |
|---|---|
| SHA-256 | `3932795771fe8fcb4580771d9e478951af7cdc22870e8c723191a6dfe2de28ec` |
| Family label | `ConnectWise` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 22:47:40` |
| Reporter | `Bitsight` |
| Tags | `C, ConnectWise, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0278b284fc3934be70d7cf454c80e88` |
| SHA-1 | `696242f53e8338ac317d26b219d1484f40294931` |
| SHA-256 | `3932795771fe8fcb4580771d9e478951af7cdc22870e8c723191a6dfe2de28ec` |
| SHA3-384 | `dd824691955149499d982f1ba0f6cf76483ecad33b55054a385885977d657b75d15762568465cad3cd3eb540f5c11c46` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T155771256E2FD00E8D57AC0BCC6575517EBB2345917309BEB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:cuMLRvXoeOvHiwB3sv+h1hW25F+wX0ff6yajCs6+4S3NftX:c51oeeCwbrhWG+tf6fj4ulX` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_063_39327957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3932795771fe8fcb4580771d9e478951af7cdc22870e8c723191a6dfe2de28ec"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 22:47:40"
  condition:
    hash.sha256(0, filesize) == "3932795771fe8fcb4580771d9e478951af7cdc22870e8c723191a6dfe2de28ec"
}
```

### Sample 64: `0910fc3c5cb222b5`

| Field | Value |
|---|---|
| SHA-256 | `0910fc3c5cb222b5b43eef9b187784e36e484728acaa1198b41fb54707c3e167` |
| Family label | `AgentTesla` |
| File name | `orden de compra.exe` |
| File type | `exe` |
| First seen | `2026-09-02 22:32:49` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72cf16d053b1ebdd462c5e3124b064ba` |
| SHA-1 | `c1a7f3a586088fe377155ac211c9f9f348b4710d` |
| SHA-256 | `0910fc3c5cb222b5b43eef9b187784e36e484728acaa1198b41fb54707c3e167` |
| SHA3-384 | `cee3f5912c319bb60407b85081744af8804737cd76eb2782f5fd32058ce3657d8dbaf016f45d17aab6689df74abab926` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18545E04223E85A69F8BFAB7C5474052087F4FC56DA36D73E6E8940ED18B2B81C961733` |
| SSDEEP | `24576:/PL2MhgqlgQMFpl9xeA7spF0RoGHKGv1BY:/qMeqlg9Fpl93sQRvHKV` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_064_0910fc3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0910fc3c5cb222b5b43eef9b187784e36e484728acaa1198b41fb54707c3e167"
    family = "AgentTesla"
    file_name = "orden de compra.exe"
    file_type = "exe"
    first_seen = "2026-09-02 22:32:49"
  condition:
    hash.sha256(0, filesize) == "0910fc3c5cb222b5b43eef9b187784e36e484728acaa1198b41fb54707c3e167"
}
```

### Sample 65: `0026d4ecdb0b8eed`

| Field | Value |
|---|---|
| SHA-256 | `0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e` |
| Family label | `Mirai` |
| File name | `0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e.elf` |
| File type | `elf` |
| First seen | `2026-09-02 22:27:23` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a071624f939f766fc01321cd5423a38` |
| SHA-1 | `9e520452c07e20566df6b7f8f1fb82d97b3583ee` |
| SHA-256 | `0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e` |
| SHA3-384 | `f5bf6ba80ccc4c5453ea5f0481197c6df3db06eb4191271274c49cddd8a071728f82f9377300e3a3ea5fb8b9c787229f` |
| TLSH | `T17BF30745FC919E26C6C2167BFB4E828D372617A8D3EE32039D255F21378B95B0E3B152` |
| TELFHASH | `t16bd02217ba8daffc83c0028901ae12002f6cf2832740305a69e90f9f001203b322b030` |
| SSDEEP | `3072:pTZsc2gY+E2qvNSMd/5Y4AhywwzsY9IqnJSiq:pmc2gY+E2qvNlBY4AEww59IqnJSiq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_0026d4ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e"
    family = "Mirai"
    file_name = "0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e.elf"
    file_type = "elf"
    first_seen = "2026-09-02 22:27:23"
  condition:
    hash.sha256(0, filesize) == "0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e"
}
```

### Sample 66: `084a1a1431eca542`

| Field | Value |
|---|---|
| SHA-256 | `084a1a1431eca54254a61f6c5c330f08b68654fab510bbeb2c1cd72a97326d6b` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-02 22:23:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b83e04a9fdf288a62edeeae22331f73` |
| SHA-1 | `195031192b3a3626d03039aefcf0cf3d9f6f2bb7` |
| SHA-256 | `084a1a1431eca54254a61f6c5c330f08b68654fab510bbeb2c1cd72a97326d6b` |
| SHA3-384 | `109b815522b463382b76b70c91e608a7946b198db5a660ff3806258d6d670dc9f36f566e1fd090f6f17256d07b3d7c90` |
| TLSH | `T11943C696B8D3996AD2D1533AFB5F978A33A277D4C2DE3613C9190B2133CA14F8D23950` |
| TELFHASH | `t186f09e45fd744b188de27674ac8c03a184134313612387248f98d9e0cc3e11ab74cd1d` |
| SSDEEP | `1536:KPvm+193+DfuEg2z/ITq5h+y2sIBq9oxxL4+:K2wYXz/Yq5hvXIBsoxp9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_084a1a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "084a1a1431eca54254a61f6c5c330f08b68654fab510bbeb2c1cd72a97326d6b"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-02 22:23:37"
  condition:
    hash.sha256(0, filesize) == "084a1a1431eca54254a61f6c5c330f08b68654fab510bbeb2c1cd72a97326d6b"
}
```

### Sample 67: `9994f013616d3886`

| Field | Value |
|---|---|
| SHA-256 | `9994f013616d38865431d1df6b1c74d1c6cbd15c34da99dacab30e780e26c125` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-02 22:23:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4d613cb70f95bd18a702bcf4beae1db` |
| SHA-1 | `9b4df580d9750494422a22f87237d654bf7c8fdf` |
| SHA-256 | `9994f013616d38865431d1df6b1c74d1c6cbd15c34da99dacab30e780e26c125` |
| SHA3-384 | `e8f645a5f7c8b771a8c16ec66c407f607ab4ccd80dc5c8505f0278c54d479fc1941b6af653912d7182e7a1b3de7946ac` |
| TLSH | `T143235C6516857C24AE98C4361C7E2F0CB9AD83E6324452EE7FCB3CF68C4A6AD910971D` |
| SSDEEP | `768:4+J9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:4+Ccr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_9994f013
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9994f013616d38865431d1df6b1c74d1c6cbd15c34da99dacab30e780e26c125"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-02 22:23:35"
  condition:
    hash.sha256(0, filesize) == "9994f013616d38865431d1df6b1c74d1c6cbd15c34da99dacab30e780e26c125"
}
```

### Sample 68: `02f01bb20d47400a`

| Field | Value |
|---|---|
| SHA-256 | `02f01bb20d47400abd0b37895a0c8b0ad6d7785c326f0bda61c0cc8fd32284fa` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-02 22:20:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74b14caa2b402f3a6fcb5c1c882773cf` |
| SHA-1 | `83da56d59d21b6ec717a91a5a5872b66cb2faa93` |
| SHA-256 | `02f01bb20d47400abd0b37895a0c8b0ad6d7785c326f0bda61c0cc8fd32284fa` |
| SHA3-384 | `7c4d36604eae0c2167a02680c9b788ca019880f21c7c20f37497598b1037007a29e96d03a9e82e7bf64f6d8abad1a7dc` |
| TLSH | `T18CF33916B4C094FEC8E5C1788FAFE12AD972F4591234B21F2794BE272E5EE305B5E610` |
| TELFHASH | `t14d61fcb139663d9462f7e137738fd96be836092014e671e1ae7369e2ce223840d72436` |
| SSDEEP | `3072:aZ8Z8wFdJ2AlrTQ/DLumT6NaI1seGl6s/LVS0AY6gGuFpiX:aZ/ewNOHG4MHG8pi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_02f01bb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02f01bb20d47400abd0b37895a0c8b0ad6d7785c326f0bda61c0cc8fd32284fa"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-02 22:20:39"
  condition:
    hash.sha256(0, filesize) == "02f01bb20d47400abd0b37895a0c8b0ad6d7785c326f0bda61c0cc8fd32284fa"
}
```

### Sample 69: `6ece7c73a89d0aea`

| Field | Value |
|---|---|
| SHA-256 | `6ece7c73a89d0aea67a9f38a49b7589b54e7e07ff4dd6cf1c4b7ff0905d15880` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-02 22:02:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d27b6c9979cdc4b9c7d4230b0e5fe1f5` |
| SHA-1 | `e20713220f653cefb5b9cbe14ea1b0baa8ff3dc7` |
| SHA-256 | `6ece7c73a89d0aea67a9f38a49b7589b54e7e07ff4dd6cf1c4b7ff0905d15880` |
| SHA3-384 | `9d82e9cf9e74e35ebc2c9dcdb6d8efa09ec3bcf7b3d1d2aa2840e247f98394e35f4f9c6abc808819ef522b90300ea499` |
| TLSH | `T11744D61E2E728F3DF2A9873487B74A25D75862D723D1D640F16CD1102F2029EA46FFA8` |
| TELFHASH | `t1e641831c0e7413f0a2295d9d459dff3ad6a330eb7e166c378e11e86aa769a834d10c0c` |
| SSDEEP | `6144:8I7K3ivzGYHu2H++X+L8T2+JSro5O1EssMOjh5occ/:ju6uLyYEssMOjh5occ/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_6ece7c73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ece7c73a89d0aea67a9f38a49b7589b54e7e07ff4dd6cf1c4b7ff0905d15880"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-02 22:02:50"
  condition:
    hash.sha256(0, filesize) == "6ece7c73a89d0aea67a9f38a49b7589b54e7e07ff4dd6cf1c4b7ff0905d15880"
}
```

### Sample 70: `847ccdf192ec6c72`

| Field | Value |
|---|---|
| SHA-256 | `847ccdf192ec6c7278d8f235ae3c6f48f11ff941fc1c2807680e2fc5344b1065` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-02 21:44:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e962713ff0ada49f5835fc3e7f308fb` |
| SHA-1 | `2b12301ccbed49916947e204348396c1cc86b2e0` |
| SHA-256 | `847ccdf192ec6c7278d8f235ae3c6f48f11ff941fc1c2807680e2fc5344b1065` |
| SHA3-384 | `3f740adb6894cb752b6ec8863ebfdad5a78da637edb4e6a68155465460a7e90202bed811e7533a98fa84b81faeddc88a` |
| TLSH | `T13F235C552A857C14AA98C8371D7F2F0CB9A943E6320452DE7FCF3CF68C4AADD910962D` |
| SSDEEP | `768:bJFWzZx5q9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:dkzNcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_847ccdf1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847ccdf192ec6c7278d8f235ae3c6f48f11ff941fc1c2807680e2fc5344b1065"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-02 21:44:48"
  condition:
    hash.sha256(0, filesize) == "847ccdf192ec6c7278d8f235ae3c6f48f11ff941fc1c2807680e2fc5344b1065"
}
```

### Sample 71: `ad820b12eaf9a124`

| Field | Value |
|---|---|
| SHA-256 | `ad820b12eaf9a124fd15f846859b765441ff31d83613872f829691905245809f` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-02 21:38:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f4e79630665cc978936a83e25af9cb2` |
| SHA-1 | `66508bf4b8f5ee0c98396ef66facbc4ba4da9d9f` |
| SHA-256 | `ad820b12eaf9a124fd15f846859b765441ff31d83613872f829691905245809f` |
| SHA3-384 | `4a8c23bc458c0b5af5ceb96a81cefceaa083f40cd0f8cf74341a2caafc3de10927f5d4b719003293e68b9300429b572c` |
| TLSH | `T151313BEA14241A712102CA9D7363355AB29DA2FB2C5FC7D4D84D4DAA42887CCF2B1B8D` |
| SSDEEP | `24:TtZEFKlRW6TVc4vrxGj83ag5wI+tK2N5jkK:qKlLVc4d28Kg5QF54K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_ad820b12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad820b12eaf9a124fd15f846859b765441ff31d83613872f829691905245809f"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-02 21:38:40"
  condition:
    hash.sha256(0, filesize) == "ad820b12eaf9a124fd15f846859b765441ff31d83613872f829691905245809f"
}
```

### Sample 72: `2ae3c4bb100d33d7`

| Field | Value |
|---|---|
| SHA-256 | `2ae3c4bb100d33d7de57809caf7447d09e8afec83f28d246c3f9d772523f09d4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 21:37:46` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX1.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `381e4edd65484ba08d5dc656d027d4fa` |
| SHA-1 | `0823dccace0cf9d924a61a63f240a52b754e6306` |
| SHA-256 | `2ae3c4bb100d33d7de57809caf7447d09e8afec83f28d246c3f9d772523f09d4` |
| SHA3-384 | `d57201f8799bb0d478992b36b8db25992fdea043688f3ed0800f622288dc7a26d17fb41bc6cfa7378f57dc15b463ed09` |
| IMPHASH | `e59d00b0d90522ee1a983f13d4ff7e50` |
| TLSH | `T1940623117781D875E26314324E78F39896BEFA350E660F9F37850AAD9E707C2A731B06` |
| SSDEEP | `98304:vATvXJ8ItMCPacZFehQ4j7FaZ46jwQm/umDspCu:8/+bTFwberDspv` |
| ICON-DHASH | `c2a8b49a9ada9690` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_2ae3c4bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ae3c4bb100d33d7de57809caf7447d09e8afec83f28d246c3f9d772523f09d4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 21:37:46"
  condition:
    hash.sha256(0, filesize) == "2ae3c4bb100d33d7de57809caf7447d09e8afec83f28d246c3f9d772523f09d4"
}
```

### Sample 73: `f396236bb973e1d6`

| Field | Value |
|---|---|
| SHA-256 | `f396236bb973e1d6fe39ade485a594d680892d6772d579de9a71533fbd21804a` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-02 21:26:49` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac68cec60f2504893b49a4f633b7ecdb` |
| SHA-256 | `f396236bb973e1d6fe39ade485a594d680892d6772d579de9a71533fbd21804a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_f396236b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f396236bb973e1d6fe39ade485a594d680892d6772d579de9a71533fbd21804a"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-02 21:26:49"
  condition:
    hash.sha256(0, filesize) == "f396236bb973e1d6fe39ade485a594d680892d6772d579de9a71533fbd21804a"
}
```

### Sample 74: `cabddafb8e09e8d8`

| Field | Value |
|---|---|
| SHA-256 | `cabddafb8e09e8d852901885bead3dccd00805d41bd5bde3cd0e08ccc9a7ac34` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 21:03:10` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2514ed78e122dbe375b7de3e52dedf8` |
| SHA-1 | `090ece231af4149ad0323f6907852f3e7343a3a9` |
| SHA-256 | `cabddafb8e09e8d852901885bead3dccd00805d41bd5bde3cd0e08ccc9a7ac34` |
| SHA3-384 | `11cd81d52b78a5a09dd3024618dc7f6dd3bc4a9dc8e07a2c1a2e0e031b2102937fb000beaac73441da798e35de2a55c1` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T19BE60133A1ED25FBE0694B39197392154E377F3168138D1E96F438E8DB35F60292BA42` |
| SSDEEP | `98304:uAX7oWeJJv9WbY3gsanRwFIjtPTfJ0MLf77K4zn5SHMYmCQiFnVo/g3IH:doWeJNcbY3gsbIBPTfuu7Jn5ShFvIH` |
| ICON-DHASH | `6869696969696969` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_cabddafb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cabddafb8e09e8d852901885bead3dccd00805d41bd5bde3cd0e08ccc9a7ac34"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 21:03:10"
  condition:
    hash.sha256(0, filesize) == "cabddafb8e09e8d852901885bead3dccd00805d41bd5bde3cd0e08ccc9a7ac34"
}
```

### Sample 75: `25b17f1c0501789e`

| Field | Value |
|---|---|
| SHA-256 | `25b17f1c0501789e6cb492441d30ecff8c3d3920b6a94dfff20a0daa02229512` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-02 20:55:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00178417f170df95f2cad81f04501d15` |
| SHA-1 | `a410bdd932d3f2ee46656a0e96a9fc9f73bc1fc6` |
| SHA-256 | `25b17f1c0501789e6cb492441d30ecff8c3d3920b6a94dfff20a0daa02229512` |
| SHA3-384 | `dae14cac5571b0af7b99dcadc95b828a002f1c79639abe03c09cd2c638bffbdeb9b6c8d692598d2b136b5121df6f40cd` |
| TLSH | `T1ABC27D966A867C44BEC94A3E4CBE2B1D6DF5C3D1224942AC3D8B3C71DC11F9CD618B1A` |
| SSDEEP | `768:g8vCB+25j6es8Rk9FYpMSUpi+20qUpi+20YQX:g8l25JCd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_25b17f1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25b17f1c0501789e6cb492441d30ecff8c3d3920b6a94dfff20a0daa02229512"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-02 20:55:44"
  condition:
    hash.sha256(0, filesize) == "25b17f1c0501789e6cb492441d30ecff8c3d3920b6a94dfff20a0daa02229512"
}
```

### Sample 76: `b7bad05c7e44fd0d`

| Field | Value |
|---|---|
| SHA-256 | `b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2` |
| Family label | `unknown` |
| File name | `b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2.exe` |
| File type | `exe` |
| First seen | `2026-09-02 20:52:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ab5ccfab11d5bd4593acd0b19404378` |
| SHA-1 | `90fb2f2a8b786d9113181d3ef402f5ba32ccf4d5` |
| SHA-256 | `b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2` |
| SHA3-384 | `353f31aab9de13d92bfb276299f5d408f36fd60cfaacbae36d93d8b9a42b21262fff26409d8ab41f962e31654c71bc85` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T1E6D52394A9F61974C8B3C3B7CF82E16D715E33948AB14F97BACC59004E66A986C37370` |
| SSDEEP | `49152:sFvOUGSDIlRKAOvxWirPWgK7pLwT0j7WPPo6Ek1RtAVLI+zWUu:shHGScnDYWirPqpLwTto6Us+xu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_b7bad05c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2"
    family = "unknown"
    file_name = "b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2.exe"
    file_type = "exe"
    first_seen = "2026-09-02 20:52:36"
  condition:
    hash.sha256(0, filesize) == "b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2"
}
```

### Sample 77: `96fbc96352571c3a`

| Field | Value |
|---|---|
| SHA-256 | `96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c` |
| Family label | `unknown` |
| File name | `96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c.bin` |
| File type | `exe` |
| First seen | `2026-09-02 20:47:32` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f80e4f22f658b423b08200fa930aa13` |
| SHA-1 | `871bcf7a21df651636ea201472bce2d947cb4c26` |
| SHA-256 | `96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c` |
| SHA3-384 | `3104f8f05d2207d21355d957fadb8a49fcae91dea305c0526c3ac0d9e979857b628d574f92e2026c8b3b9006512b3210` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19F766C077A6506B8C0999734C97B42527B65BC8D8F3273E32E547A382F76BC0AD7A704` |
| SSDEEP | `49152:131LHA0Acih7lfEoUrCNlz9vfMzL+dzk9kNutu2yz/FJWUzTYtiM7Qp:1BC3Lgadzk9kNutu2etgW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_96fbc963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c"
    family = "unknown"
    file_name = "96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c.bin"
    file_type = "exe"
    first_seen = "2026-09-02 20:47:32"
  condition:
    hash.sha256(0, filesize) == "96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c"
}
```

### Sample 78: `4b62026ec5bff817`

| Field | Value |
|---|---|
| SHA-256 | `4b62026ec5bff8176775fe5b6dfff7e6481afa461da0567c41ac7bf1abe8b7d5` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-02 20:46:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e03a90cb21b76d9c0983576c5adeeca` |
| SHA-1 | `5ecf33f549f25e205f7e60907833ee22309256ea` |
| SHA-256 | `4b62026ec5bff8176775fe5b6dfff7e6481afa461da0567c41ac7bf1abe8b7d5` |
| SHA3-384 | `5163a52f8cf57a76e14fdaac0b8fb9947232a487d3275f7f420d8769d413822ede96dcb5a9a219f39cef191b9f7d0f26` |
| TLSH | `T1FAC27D966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:X8vCB+25j6es8RRA9FYpMSUpi+20qUpi+20YQX:X8l25JEd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_4b62026e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b62026ec5bff8176775fe5b6dfff7e6481afa461da0567c41ac7bf1abe8b7d5"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-02 20:46:56"
  condition:
    hash.sha256(0, filesize) == "4b62026ec5bff8176775fe5b6dfff7e6481afa461da0567c41ac7bf1abe8b7d5"
}
```

### Sample 79: `c12e819df8b2526a`

| Field | Value |
|---|---|
| SHA-256 | `c12e819df8b2526a35b97ff5437194b9518c9d4b8c301746f7c7d3e25aaf00da` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-02 20:46:54` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6248b5b5b0d6a2805e3eb2948bc0195c` |
| SHA-256 | `c12e819df8b2526a35b97ff5437194b9518c9d4b8c301746f7c7d3e25aaf00da` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_c12e819d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c12e819df8b2526a35b97ff5437194b9518c9d4b8c301746f7c7d3e25aaf00da"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-02 20:46:54"
  condition:
    hash.sha256(0, filesize) == "c12e819df8b2526a35b97ff5437194b9518c9d4b8c301746f7c7d3e25aaf00da"
}
```

### Sample 80: `5d5ca63931bc049b`

| Field | Value |
|---|---|
| SHA-256 | `5d5ca63931bc049be479599cfe5c96c2ed601658f4272bf015a5f24b93e2cb6d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 20:40:53` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75eed147046b92d1d1a98dc2423caa53` |
| SHA-1 | `304370c569fe4074e45aad87b5a4434f47455b90` |
| SHA-256 | `5d5ca63931bc049be479599cfe5c96c2ed601658f4272bf015a5f24b93e2cb6d` |
| SHA3-384 | `6de9af69903e5f8828cdc35028c6c8c0df36e88e239d6808510a313a42ea1093df147310550c70f6af518226c8b96988` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T10C771256E2FD00E8D5BAC0BCC6575517EBB23459173097EB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:WuMLmvXoeOvHiwB3sn+h1hW25F+wXCff6yajCs6+4S3Nftp:W5UoeeCwDrhWG+bf6fj4ulp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_5d5ca639
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d5ca63931bc049be479599cfe5c96c2ed601658f4272bf015a5f24b93e2cb6d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 20:40:53"
  condition:
    hash.sha256(0, filesize) == "5d5ca63931bc049be479599cfe5c96c2ed601658f4272bf015a5f24b93e2cb6d"
}
```

### Sample 81: `298fed4ed5f4f5c7`

| Field | Value |
|---|---|
| SHA-256 | `298fed4ed5f4f5c7a3a6722436be6172b1f4c81e1f274720f9b0b65d7f0b341a` |
| Family label | `unknown` |
| File name | `pago corporativo;FE94876;01;.js` |
| File type | `js` |
| First seen | `2026-09-02 20:39:17` |
| Reporter | `cypherpunk472` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4cd4533c20cf69901cf34a72ea7f032` |
| SHA-1 | `04ecee1265668b3a3283a7843f5958617c810c77` |
| SHA-256 | `298fed4ed5f4f5c7a3a6722436be6172b1f4c81e1f274720f9b0b65d7f0b341a` |
| SHA3-384 | `5af6bff8ea4663434e6b4d9bc2d4e4fd84fa89559829e6781ec1aa250f5d1744c404eba8d7c69d721ecad82358d25d40` |
| TLSH | `T1BAC7582FB0CD1A9B8AEFB7E545C1F4363821F2BBDDB2184CE054C6629511AEFD58610E` |
| SSDEEP | `3072:G3+vkvhv0wEckwYAaY29eReSey3nBsjOeFcXOX3HsWAabtU2I2e2N2Mi6LpKp3TY:v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_298fed4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "298fed4ed5f4f5c7a3a6722436be6172b1f4c81e1f274720f9b0b65d7f0b341a"
    family = "unknown"
    file_name = "pago corporativo;FE94876;01;.js"
    file_type = "js"
    first_seen = "2026-09-02 20:39:17"
  condition:
    hash.sha256(0, filesize) == "298fed4ed5f4f5c7a3a6722436be6172b1f4c81e1f274720f9b0b65d7f0b341a"
}
```

### Sample 82: `4801195bebee290e`

| Field | Value |
|---|---|
| SHA-256 | `4801195bebee290ed488e07e87a4ad96218febd18e595cdc024af65a0beb0c0f` |
| Family label | `unknown` |
| File name | `malware_sample_tmp_dot_c.bin` |
| File type | `elf` |
| First seen | `2026-09-02 20:24:27` |
| Reporter | `luxFoz` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3935c28077ead75c31aa04b79796a15` |
| SHA-1 | `1450e9f310930778d5688872bd518fc990435469` |
| SHA-256 | `4801195bebee290ed488e07e87a4ad96218febd18e595cdc024af65a0beb0c0f` |
| SHA3-384 | `ee5728f82e2f0f4cfa714a7d240bdf7f21be3f5c28a7b9be0aa1e15e41afdfcb6f9feec2cbf94757943121caeacb413a` |
| TLSH | `T152C53A07FCA044AAC0AE9231C9629162BB72BC495B3123D73F54B7782F72BD0AD79754` |
| TELFHASH | `t188524b744ebc34b5b66ada11f36275b4957718a522f438b15033bc85ffc0e842cea86b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:NYvvoYyN5dMLuxbbaMD7DtsgoBTI/OFwPzNa:3YyBH/njoRnSzNa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_4801195b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4801195bebee290ed488e07e87a4ad96218febd18e595cdc024af65a0beb0c0f"
    family = "unknown"
    file_name = "malware_sample_tmp_dot_c.bin"
    file_type = "elf"
    first_seen = "2026-09-02 20:24:27"
  condition:
    hash.sha256(0, filesize) == "4801195bebee290ed488e07e87a4ad96218febd18e595cdc024af65a0beb0c0f"
}
```

### Sample 83: `de48b45702c25d93`

| Field | Value |
|---|---|
| SHA-256 | `de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146` |
| Family label | `Mirai` |
| File name | `de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146.elf` |
| File type | `elf` |
| First seen | `2026-09-02 20:17:25` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02e71a64edb6b2e970371ac68fb5adb6` |
| SHA-1 | `d0d39977fb6743d477a0cecea82616cab288bad6` |
| SHA-256 | `de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146` |
| SHA3-384 | `49883bffb5ed99774bf51ae7b81cc49d4c81087fa77b54e7aa8ce472bb609e4233ce99ddd93c528229e8513f0c7a6364` |
| TLSH | `T18A941903EBDD2F9AE0A7CF354C361066445C1C2A7B96CD3AEFA82849760B7950F4658F` |
| SSDEEP | `6144:ZwoB5fn6KtpVxNSvwdp71/SVdEk4nOdWZRQOi9hrKZ6CfbCQR:yoB5yEpVxIvwvRSf4OdWwbhrKhfbT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_de48b457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146"
    family = "Mirai"
    file_name = "de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146.elf"
    file_type = "elf"
    first_seen = "2026-09-02 20:17:25"
  condition:
    hash.sha256(0, filesize) == "de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146"
}
```

### Sample 84: `632483ffc92cf6cf`

| Field | Value |
|---|---|
| SHA-256 | `632483ffc92cf6cf7aa1900f312ec8a89af06bc3ce8edab8147013cee68510dc` |
| Family label | `NanoCore` |
| File name | `14e53f177fc328f845b1847b5cab0703.exe` |
| File type | `exe` |
| First seen | `2026-09-02 20:15:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14e53f177fc328f845b1847b5cab0703` |
| SHA-1 | `ba14a6da5bf5b12145fd2c642d1e91140ee35228` |
| SHA-256 | `632483ffc92cf6cf7aa1900f312ec8a89af06bc3ce8edab8147013cee68510dc` |
| SHA3-384 | `09ab01cb598b011c56669f88c749514fd2fea2bcc48353cc76fc1479a162449968ca483d7307c1f4814f69beabe310c2` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15214C02A77A94A2FE2DE8679711252139378C2E39CD3F3EE18D415B68F667E406070D3` |
| SSDEEP | `3072:gzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HIQ/6d6+Il1c3rxbivlpfk:gLV6Bta6dtJmakIM5BXT6rxmA` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_084_632483ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "632483ffc92cf6cf7aa1900f312ec8a89af06bc3ce8edab8147013cee68510dc"
    family = "NanoCore"
    file_name = "14e53f177fc328f845b1847b5cab0703.exe"
    file_type = "exe"
    first_seen = "2026-09-02 20:15:06"
  condition:
    hash.sha256(0, filesize) == "632483ffc92cf6cf7aa1900f312ec8a89af06bc3ce8edab8147013cee68510dc"
}
```

### Sample 85: `47e6a0142c874d07`

| Field | Value |
|---|---|
| SHA-256 | `47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219` |
| Family label | `unknown` |
| File name | `47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219.exe` |
| File type | `exe` |
| First seen | `2026-09-02 20:07:42` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbb22293590f1f8267af96bf8899083b` |
| SHA-1 | `59442f0c3d050dae16a559d91a5b164dbc8e6842` |
| SHA-256 | `47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219` |
| SHA3-384 | `0170a56fabdee4307300cb15b203937547513155349946492ad7178e52e1ccd8063bec118bea90e400a892f709e4c639` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T14DD523D9AAF22A74C436C7B3DF82E4ADB12D37A14A614D973BCCAD108D131D49C766B0` |
| SSDEEP | `49152:aiPAZr69WxkZui2kz0be+DWgjVIOL7MPc5uPG/NEOhAoSeUlxAjqqF5ytlQL9bp6:fPAZe9Wx2X2PNCgjVBrmG/NzAorUlxqJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_47e6a014
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219"
    family = "unknown"
    file_name = "47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219.exe"
    file_type = "exe"
    first_seen = "2026-09-02 20:07:42"
  condition:
    hash.sha256(0, filesize) == "47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219"
}
```

### Sample 86: `3dc0efeaf17700be`

| Field | Value |
|---|---|
| SHA-256 | `3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea` |
| Family label | `Mirai` |
| File name | `3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea.elf` |
| File type | `elf` |
| First seen | `2026-09-02 20:07:22` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94dd65a28c8de4da2dd53314258625d4` |
| SHA-1 | `58c4dc45ecf95c02eab0e750214a8d3016bace96` |
| SHA-256 | `3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea` |
| SHA3-384 | `ae59b3448569186b78725d1332d4ace38fa364bff82eb5c22a139bd789d9c2e0d1889e416fa18da5ad3b9d753aee8a5e` |
| TLSH | `T1D094C391641145DBCE1088BA7B2C8F7463812CB1D36B1F7E1956891DA28F8CFF5CABE4` |
| SSDEEP | `6144:V4B1KilFcYWSpI/Te3Z/f9R1Q2xkf7vtBkogrK:V4BYilSYWqISR1JxkTvIogW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_3dc0efea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea"
    family = "Mirai"
    file_name = "3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea.elf"
    file_type = "elf"
    first_seen = "2026-09-02 20:07:22"
  condition:
    hash.sha256(0, filesize) == "3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea"
}
```

### Sample 87: `b98c9031c643b5c8`

| Field | Value |
|---|---|
| SHA-256 | `b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3` |
| Family label | `unknown` |
| File name | `b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3.elf` |
| File type | `elf` |
| First seen | `2026-09-02 20:02:21` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52f42c21ca48f02aaf462825d11ea335` |
| SHA-1 | `5d0c9fc89f5a0b2a59a3e67e184fa0baec75ba33` |
| SHA-256 | `b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3` |
| SHA3-384 | `49390603190b0f85c2776594f54bd7565c58a71a140ac349b836b34122638d066fa1c4df9c327070e9e45bffed991d40` |
| TLSH | `T1ECC3122436DA7496C03D9925F88215C43FFB727D60AFA61A66384B3F35DA88E13D4F81` |
| SSDEEP | `3072:y5RrO9GJdVz6NrCS/cPKHi0Z/6e4jitkFT1g4+JIcUGlSot:SmnNrV/cPKC0x4jitkpubskSot` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_b98c9031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3"
    family = "unknown"
    file_name = "b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3.elf"
    file_type = "elf"
    first_seen = "2026-09-02 20:02:21"
  condition:
    hash.sha256(0, filesize) == "b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3"
}
```

### Sample 88: `14b0fdba2beb047d`

| Field | Value |
|---|---|
| SHA-256 | `14b0fdba2beb047d7796352ce56ceabeebb1a70863f29f088a046ca05246196f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 19:55:46` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `106c6d0f6666522ab7e1ba0f545480e3` |
| SHA-1 | `8320c9d00dfbbe01c9fefbed5a9953830e25b6ec` |
| SHA-256 | `14b0fdba2beb047d7796352ce56ceabeebb1a70863f29f088a046ca05246196f` |
| SHA3-384 | `35094322de2645a0060fae27f35b0905c64a781bd6535a74ea66493bb785c65dae2deb501037c7cfa87dc76df1c9fcfe` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T120265A477DA12569D866D738E57B43227A60BD8CC73533E32D90A2702F247C1AEFAB05` |
| SSDEEP | `49152:XEfxT5gzDcw6/JhOI8NTP6+VFe4QFPA36YBs/O9hkVOq9H6w5xRjGaq:Xtct4PTy2hnBs/O9GVN57Rjq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_14b0fdba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14b0fdba2beb047d7796352ce56ceabeebb1a70863f29f088a046ca05246196f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 19:55:46"
  condition:
    hash.sha256(0, filesize) == "14b0fdba2beb047d7796352ce56ceabeebb1a70863f29f088a046ca05246196f"
}
```

### Sample 89: `c381052b7db304df`

| Field | Value |
|---|---|
| SHA-256 | `c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985` |
| Family label | `Vidar` |
| File name | `c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985.bin` |
| File type | `exe` |
| First seen | `2026-09-02 19:49:06` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e4cb2205425cb606a0bdc0a2ecc3abe` |
| SHA-1 | `07d90b08968bb60338d47d27e4b7bbb60e4b3137` |
| SHA-256 | `c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985` |
| SHA3-384 | `6c6e6978c2f83fb8d438db889b2f5c890bfc21c36a487ae00216fa429408383efe1e113e2171d18f87b3f66670cefc82` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T159E65B436A4244E4C9B1AF39C37752E1BA6CB88CC73137B72E64D6B42F223D1A979744` |
| SSDEEP | `393216:LP1g0wuvlwSICkasXw05GrBSy64lweu3X1E3QGZTkR8tUuTdPC8PRJjPbNkgAEm4:jXB` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_089_c381052b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985"
    family = "Vidar"
    file_name = "c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985.bin"
    file_type = "exe"
    first_seen = "2026-09-02 19:49:06"
  condition:
    hash.sha256(0, filesize) == "c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985"
}
```

### Sample 90: `54620981fdf60ef6`

| Field | Value |
|---|---|
| SHA-256 | `54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96` |
| Family label | `unknown` |
| File name | `54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96.bin` |
| File type | `exe` |
| First seen | `2026-09-02 19:49:02` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b48ab50ceaedaba80efd3cc165426b4b` |
| SHA-1 | `d17c4120291588085a2bca4a203f4dce3f95de62` |
| SHA-256 | `54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96` |
| SHA3-384 | `05d82752b009f83e2cb96053795089da50f09122bfeae6dcbc3ec4c11a2d38bcc529b4bace5db8faeaad6755f996a409` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T101366A03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaW:uc3XND1aJrCOkW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_54620981
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96"
    family = "unknown"
    file_name = "54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96.bin"
    file_type = "exe"
    first_seen = "2026-09-02 19:49:02"
  condition:
    hash.sha256(0, filesize) == "54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96"
}
```

### Sample 91: `6b290e28bce7de32`

| Field | Value |
|---|---|
| SHA-256 | `6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65` |
| Family label | `CoinMiner` |
| File name | `6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65.exe` |
| File type | `exe` |
| First seen | `2026-09-02 19:47:32` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2bc53c8a11743165d77d928643e74f3` |
| SHA-1 | `f8780e44098efeac1ce602c736093d1aa8b0a5cf` |
| SHA-256 | `6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65` |
| SHA3-384 | `3b447f6b36c02d56977835d560cb5c07eb5b884ced616881ac13c7dd105f53496aa4af3a192d3abe3c2f99822ec2bdd6` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T1A53633A81DC19AF8D09BC3B8494725AEB33E77928A61BC173BCC79500D87F08653A7C5` |
| SSDEEP | `98304:IAfBoW3ybWvCt/gL46preqAy1wF6+dZU+BryZm9DW2lAF:IQoW3ybz/b6xeqx1wF6OU+NvW2` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_091_6b290e28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65"
    family = "CoinMiner"
    file_name = "6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65.exe"
    file_type = "exe"
    first_seen = "2026-09-02 19:47:32"
  condition:
    hash.sha256(0, filesize) == "6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65"
}
```

### Sample 92: `8cc7987d58d80951`

| Field | Value |
|---|---|
| SHA-256 | `8cc7987d58d8095184529de67f18bd247a3cc7590fd1cf6078d590b5d78d480c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 19:20:26` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc9ec6ef5e997fa850e5807ab7f4da83` |
| SHA-1 | `ab97f8b9b2f493437601cee5cf390581b94b070b` |
| SHA-256 | `8cc7987d58d8095184529de67f18bd247a3cc7590fd1cf6078d590b5d78d480c` |
| SHA3-384 | `e978ffa1acbab1c8e9b6130ca33e958049bdab3f3e1fa11d95825f971b312763dcf66e9d737e49d732ee0189bccd77ee` |
| IMPHASH | `546132e32748c96a28e3e4416aaac265` |
| TLSH | `T166F5F082BB42D535D046AF71DA65D7FCB329FE18CA104B4736C62E0BBDE6AC64D252C0` |
| SSDEEP | `49152:ZskR5ShtG4HcmAB1LtCtktIYPr3CAOq1QJTYnP2ndkmyiX9XKfetk/dFQU1WlbWi:ZRkHbArtCtkt5DoyuUmdo5/dFBJc` |
| ICON-DHASH | `00c8c8f0f0fcfc00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_8cc7987d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cc7987d58d8095184529de67f18bd247a3cc7590fd1cf6078d590b5d78d480c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 19:20:26"
  condition:
    hash.sha256(0, filesize) == "8cc7987d58d8095184529de67f18bd247a3cc7590fd1cf6078d590b5d78d480c"
}
```

### Sample 93: `5b9a396000622460`

| Field | Value |
|---|---|
| SHA-256 | `5b9a396000622460864f616fe46f4232fae004838284a97c729f74c056f0a6c4` |
| Family label | `unknown` |
| File name | `Boostrapsrrer.exe` |
| File type | `exe` |
| First seen | `2026-09-02 19:10:14` |
| Reporter | `Alex_sev` |
| Tags | `exe, generic, killav, loader, stealer, Worgtop` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e531ed92c41db52616a6ac4a26d0dd6f` |
| SHA-1 | `f755cd38b7db43fe15d8decc8086cb1e7d2d5f13` |
| SHA-256 | `5b9a396000622460864f616fe46f4232fae004838284a97c729f74c056f0a6c4` |
| SHA3-384 | `13388fc2aa260c8b3b37d997f666abd3ecdaa2f565b14215297c85d75284420c3dd3d691736b3e8d00ddf2a6d4318cc3` |
| IMPHASH | `5192a4c65487ec8ce4c7e38ef81eb8b4` |
| TLSH | `T156167C65061FCD0FCA4158F4987A7A639325B4C92B2096E8FD04B4E6B3D7D3A17A03F6` |
| SSDEEP | `49152:WO5gK9bQ8+QYQvqkmCMcvtxTg9Xryq83wGUvFgF8S:LSwvqgMc/TgJryP3wnvsz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_5b9a3960
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b9a396000622460864f616fe46f4232fae004838284a97c729f74c056f0a6c4"
    family = "unknown"
    file_name = "Boostrapsrrer.exe"
    file_type = "exe"
    first_seen = "2026-09-02 19:10:14"
  condition:
    hash.sha256(0, filesize) == "5b9a396000622460864f616fe46f4232fae004838284a97c729f74c056f0a6c4"
}
```

### Sample 94: `bc94f10c4b7da185`

| Field | Value |
|---|---|
| SHA-256 | `bc94f10c4b7da185b319cf4b6195321d4d456ff877324d905867df810880c22c` |
| Family label | `Mirai` |
| File name | `mips64b` |
| File type | `elf` |
| First seen | `2026-09-02 19:07:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fca3678147dbd97edc703087173aa24` |
| SHA-1 | `c073e417dae239bd5d5e9fb07e29ff58f2b091ee` |
| SHA-256 | `bc94f10c4b7da185b319cf4b6195321d4d456ff877324d905867df810880c22c` |
| SHA3-384 | `23e0d1b81a1a7572ca3b961fb08773056c48f8084f584b68769e6b6b64ced8e63fa79b3e37e4af54c295ec64d71b2185` |
| TLSH | `T18E844C579F87CD6EF60687B88DE78BF4B1E561D72678C653C3AF79050A041C0482EACA` |
| SSDEEP | `6144:RBwR0kNRqAYwRuU4cC5o5ooM3XcxfGK+vECYfFH15VdqyHoRhLO:RqRTNRqAYwff5oL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_bc94f10c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc94f10c4b7da185b319cf4b6195321d4d456ff877324d905867df810880c22c"
    family = "Mirai"
    file_name = "mips64b"
    file_type = "elf"
    first_seen = "2026-09-02 19:07:47"
  condition:
    hash.sha256(0, filesize) == "bc94f10c4b7da185b319cf4b6195321d4d456ff877324d905867df810880c22c"
}
```

### Sample 95: `b90022410dcee12e`

| Field | Value |
|---|---|
| SHA-256 | `b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f` |
| Family label | `unknown` |
| File name | `b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f.bin` |
| File type | `exe` |
| First seen | `2026-09-02 18:52:30` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `caceea71d546b5324465c18a06b1be42` |
| SHA-1 | `390cbecde75dd6018c370db4031891d4a0ea322a` |
| SHA-256 | `b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f` |
| SHA3-384 | `1b7ef7f6c32cfee5d591912335c7434c3b66ee1bd077e00bfe4073e7d52a15b2f55fc17b31c0c1a7ee7f32e5ec35321d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B2668C036A4915E4D865DE30C27A57627A64FCCDC73633E32E81AB742F397D09ABA740` |
| SSDEEP | `49152:ESl2HcvbE1IV831k6U6IjNjLBuFJgdMMaDwPwMG0al+6zkArsDVMOMW8CNtufSP6:EjuELtqrunKaDn+S9sD20if8Cfew` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_b9002241
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f"
    family = "unknown"
    file_name = "b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f.bin"
    file_type = "exe"
    first_seen = "2026-09-02 18:52:30"
  condition:
    hash.sha256(0, filesize) == "b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f"
}
```

### Sample 96: `d4df270ea5a14671`

| Field | Value |
|---|---|
| SHA-256 | `d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272` |
| Family label | `Vidar` |
| File name | `d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272.bin` |
| File type | `exe` |
| First seen | `2026-09-02 18:52:28` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31f4986728b8c317d340f3d878a84f01` |
| SHA-1 | `aa8e1b114a17eb75221011ceae5c3293ba3dbcab` |
| SHA-256 | `d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272` |
| SHA3-384 | `6581800b93bd1d92aa2565b79ca57e2000643f9de4fe9decee8bec84595c404e3562cfb186579428c69e27e29d0a36e2` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C3667C07BD6105E4C4AA8638C87B9343B779B88D4B3277D32E50BA382F797C499B6714` |
| SSDEEP | `49152:rj4JCr/RdwI/b9VaNqc1aiHRYGXcQLEPXgXIwr8q+MmLrRpyOWmV+CWt:rbpiHRXsiEYXJiLrR4pc6` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_096_d4df270e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272"
    family = "Vidar"
    file_name = "d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272.bin"
    file_type = "exe"
    first_seen = "2026-09-02 18:52:28"
  condition:
    hash.sha256(0, filesize) == "d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272"
}
```

### Sample 97: `85a2a141e838b0ab`

| Field | Value |
|---|---|
| SHA-256 | `85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8` |
| Family label | `Vidar` |
| File name | `85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8.bin` |
| File type | `exe` |
| First seen | `2026-09-02 18:52:24` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9286bea7164a8eca03f572aa6e4be4ed` |
| SHA-1 | `a38eae7b861bd86f5a1c1616b1a1d5ef833c87ac` |
| SHA-256 | `85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8` |
| SHA3-384 | `6004790c51b44ed60f4b77ef42c3812b51c50167db205cb7bea6eb2ffb068be803c39092058510bac7a65126c4cffe02` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10CF57D43FCE208E9C469A3358AB68295BB347C081B3127D37EA0B7782F766D09D75785` |
| SSDEEP | `49152:Ff82qpwSHMdCLv/aJciockMLx+/tugGFVTycA43WHWkgHuV:Fj9d+/rBMLx+/tugGFVTycA43WHWL4` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_097_85a2a141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8"
    family = "Vidar"
    file_name = "85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8.bin"
    file_type = "exe"
    first_seen = "2026-09-02 18:52:24"
  condition:
    hash.sha256(0, filesize) == "85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8"
}
```

### Sample 98: `a8b95815956cae83`

| Field | Value |
|---|---|
| SHA-256 | `a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f` |
| Family label | `Prometei` |
| File name | `a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f` |
| File type | `elf` |
| First seen | `2026-09-02 18:50:25` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7c747394124153da45951175e53bf72` |
| SHA-1 | `695a674891b5b082376b7daa1e36cfae646564b1` |
| SHA-256 | `a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f` |
| SHA3-384 | `c68bd6b92e52bafe17b822b214e3fd82fcff7a298f9c07ae2dcbca0a000248487530d132e110c5c0adce83d5e638f624` |
| TLSH | `T171A423B4F9219E8F6DD769B91B24835DE182C172589D4C2313AE94E34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdo:Fs6pyCC/Ya2hpi6T6N4m` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_098_a8b95815
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f"
    family = "Prometei"
    file_name = "a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f"
    file_type = "elf"
    first_seen = "2026-09-02 18:50:25"
  condition:
    hash.sha256(0, filesize) == "a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f"
}
```

### Sample 99: `024a468c83ccd295`

| Field | Value |
|---|---|
| SHA-256 | `024a468c83ccd295d61855b84cb6ab026dd6674b1609161426bc9b04cbf0f35c` |
| Family label | `unknown` |
| File name | `netlogd_x86_64` |
| File type | `elf` |
| First seen | `2026-09-02 18:35:25` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c11d7377dc89384ea49ad1761530736f` |
| SHA-1 | `73b5b0705bb46ba558496a3fc581ab640e0e766f` |
| SHA-256 | `024a468c83ccd295d61855b84cb6ab026dd6674b1609161426bc9b04cbf0f35c` |
| SHA3-384 | `85b668d120f53698f4f61e2795605173387c5b32c57d4b1678c92d3aaf10a8339ef4ce695f92e4ebad27930c8fe5871c` |
| TLSH | `T19C158D47F5F248F9C8A9CC75C34FE033E619B88A9112752B3BD567416A3AF50AF09B12` |
| TELFHASH | `t193223f301d72796632d7d600b303eabdac725c1986e931f02d53a4d5eecf9c14daa8a3` |
| SSDEEP | `12288:ZApYbsK75weSDadW8x5mEI68QCNARjw6FMhS9IttY3reTjD06MlNyaYr/:ykvSW88xcwjw6FMcVIH06iya` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_024a468c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "024a468c83ccd295d61855b84cb6ab026dd6674b1609161426bc9b04cbf0f35c"
    family = "unknown"
    file_name = "netlogd_x86_64"
    file_type = "elf"
    first_seen = "2026-09-02 18:35:25"
  condition:
    hash.sha256(0, filesize) == "024a468c83ccd295d61855b84cb6ab026dd6674b1609161426bc9b04cbf0f35c"
}
```

### Sample 100: `4647cad54d9fe7fd`

| Field | Value |
|---|---|
| SHA-256 | `4647cad54d9fe7fdceac886773f33f796c75ed95bd532c3e25da49e8c584a053` |
| Family label | `unknown` |
| File name | `netlogd_mipsbe` |
| File type | `elf` |
| First seen | `2026-09-02 18:35:24` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be65d229d7a9133d49a5bef94c0fcc01` |
| SHA-1 | `b6653394f52de33acb5b387512320dd72d9699c6` |
| SHA-256 | `4647cad54d9fe7fdceac886773f33f796c75ed95bd532c3e25da49e8c584a053` |
| SHA3-384 | `76b754ec30a04588d0a48218ba9d9d5de7089a76d2203252dc38de8d0efddc34571959c0c39e329e57216badf29a9fff` |
| TLSH | `T1F0F45C077934CFACF564113465B749B263F216870BEB4247C368EE31BBA421D891FAE9` |
| SSDEEP | `12288:eM33Y2OwR2Bvfs/CbKXO5Y2rSlamdXI2Y0OeQTT:7nFOtp3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_4647cad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4647cad54d9fe7fdceac886773f33f796c75ed95bd532c3e25da49e8c584a053"
    family = "unknown"
    file_name = "netlogd_mipsbe"
    file_type = "elf"
    first_seen = "2026-09-02 18:35:24"
  condition:
    hash.sha256(0, filesize) == "4647cad54d9fe7fdceac886773f33f796c75ed95bd532c3e25da49e8c584a053"
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
 * Generated: 2026-09-03T04:40:00.866395+00:00
 */

rule MalwareBazaar_unknown_001_ef684ef8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4"
    family = "unknown"
    file_name = "ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4.bin"
    file_type = "exe"
    first_seen = "2026-09-03 04:34:35"
  condition:
    hash.sha256(0, filesize) == "ef684ef8bf90c0d89217b3373f64253dc8056dab0dd871555e5fcabe7671cbf4"
}

rule MalwareBazaar_unknown_002_a0a57870
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0a578706ff876c631451765720f236434e703d453fbb897903635a1fed96ce8"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 04:01:00"
  condition:
    hash.sha256(0, filesize) == "a0a578706ff876c631451765720f236434e703d453fbb897903635a1fed96ce8"
}

rule MalwareBazaar_Mirai_003_d8f869b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8f869b3431dcbcb0acda45675798b496b2ece53c064723828abae155537badf"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-03 03:55:49"
  condition:
    hash.sha256(0, filesize) == "d8f869b3431dcbcb0acda45675798b496b2ece53c064723828abae155537badf"
}

rule MalwareBazaar_Mirai_004_cb56319e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb56319e8492f14166c7d6928e5f2baf1e7f09320d27ffbc6cd894c5e0978c43"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-03 03:53:26"
  condition:
    hash.sha256(0, filesize) == "cb56319e8492f14166c7d6928e5f2baf1e7f09320d27ffbc6cd894c5e0978c43"
}

rule MalwareBazaar_unknown_005_2f5db24d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f5db24de6751d834bce8650d026d04529ac93782037a9262a4521dfca21e55f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 03:45:42"
  condition:
    hash.sha256(0, filesize) == "2f5db24de6751d834bce8650d026d04529ac93782037a9262a4521dfca21e55f"
}

rule MalwareBazaar_Mirai_006_fc419a7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc419a7b5035aba342a1031c68dd7879f5df3184291b440def4e78fc87bf70ca"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-03 03:37:40"
  condition:
    hash.sha256(0, filesize) == "fc419a7b5035aba342a1031c68dd7879f5df3184291b440def4e78fc87bf70ca"
}

rule MalwareBazaar_Vidar_007_17c6cd29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1"
    family = "Vidar"
    file_name = "17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1.bin"
    file_type = "exe"
    first_seen = "2026-09-03 03:36:53"
  condition:
    hash.sha256(0, filesize) == "17c6cd29b51c34627cbccb1add64fad17909d1f1e96ac374f4573281aa5dd9a1"
}

rule MalwareBazaar_unknown_008_c71e9e7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c71e9e7d22935bfe6e15f65ae2facc639fc35becb7efbb9c013f5e27c27a28a3"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 03:24:40"
  condition:
    hash.sha256(0, filesize) == "c71e9e7d22935bfe6e15f65ae2facc639fc35becb7efbb9c013f5e27c27a28a3"
}

rule MalwareBazaar_Mirai_009_6e284e5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e284e5a451cedcb0c4098cc52898e41cbc7fdd6b3398003d87aabb4199ef8e3"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-03 03:18:39"
  condition:
    hash.sha256(0, filesize) == "6e284e5a451cedcb0c4098cc52898e41cbc7fdd6b3398003d87aabb4199ef8e3"
}

rule MalwareBazaar_Mirai_010_85814a9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85814a9cb07115a91cedfd92d09430ececaed70ba63f1ff89d2a39284345311c"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-03 03:06:48"
  condition:
    hash.sha256(0, filesize) == "85814a9cb07115a91cedfd92d09430ececaed70ba63f1ff89d2a39284345311c"
}

rule MalwareBazaar_Mirai_011_b33780a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b33780a313eea2c5357072b2cf80dbb6ee260d4a9edb6dd15c5281f8bfebbb0d"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-03 03:03:56"
  condition:
    hash.sha256(0, filesize) == "b33780a313eea2c5357072b2cf80dbb6ee260d4a9edb6dd15c5281f8bfebbb0d"
}

rule MalwareBazaar_unknown_012_3977a21a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3977a21a9d3c71e92bbad445b22dc6e68040655b471c43a4049a907b43c7eda7"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-03 03:03:54"
  condition:
    hash.sha256(0, filesize) == "3977a21a9d3c71e92bbad445b22dc6e68040655b471c43a4049a907b43c7eda7"
}

rule MalwareBazaar_unknown_013_6b72d0a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b72d0a9ad92880093950575d538c51689070f7e6513dae7c682f35ee51eb7e8"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-03 02:57:37"
  condition:
    hash.sha256(0, filesize) == "6b72d0a9ad92880093950575d538c51689070f7e6513dae7c682f35ee51eb7e8"
}

rule MalwareBazaar_Mirai_014_0e65ee89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e65ee89ff5fc6b61425c9e1419b3c528d1ab8ddfda5943916815c7708d1a800"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-03 02:57:36"
  condition:
    hash.sha256(0, filesize) == "0e65ee89ff5fc6b61425c9e1419b3c528d1ab8ddfda5943916815c7708d1a800"
}

rule MalwareBazaar_unknown_015_c6b26808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc"
    family = "unknown"
    file_name = "c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc.exe"
    file_type = "exe"
    first_seen = "2026-09-03 02:57:36"
  condition:
    hash.sha256(0, filesize) == "c6b26808450ef52a5373d1d1ed214bc7b131e2ba5e81c97bac24d99fdc0ba4dc"
}

rule MalwareBazaar_Mirai_016_1081a33b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1081a33b778532e62bbd9c7a820c1cb3e7aaa7f8eb530f051bfdfff1df4c26ee"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-03 02:54:34"
  condition:
    hash.sha256(0, filesize) == "1081a33b778532e62bbd9c7a820c1cb3e7aaa7f8eb530f051bfdfff1df4c26ee"
}

rule MalwareBazaar_unknown_017_9023ab82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9023ab82373fb0f73383ef04391da19e6920a757f841c42c447a5d23a0caeb9e"
    family = "unknown"
    file_name = "Day01-001.png"
    file_type = "unknown"
    first_seen = "2026-09-03 02:54:34"
  condition:
    hash.sha256(0, filesize) == "9023ab82373fb0f73383ef04391da19e6920a757f841c42c447a5d23a0caeb9e"
}

rule MalwareBazaar_unknown_018_505f5cb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "505f5cb7c7f77e79627c8c5131bb3907a58924fae413a0166412598a2bda4491"
    family = "unknown"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-03 02:54:33"
  condition:
    hash.sha256(0, filesize) == "505f5cb7c7f77e79627c8c5131bb3907a58924fae413a0166412598a2bda4491"
}

rule MalwareBazaar_unknown_019_c156082e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c156082ea56c54a81382e990581ef7c9f6415f29bddde455c2241b245dd4633f"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-03 02:51:34"
  condition:
    hash.sha256(0, filesize) == "c156082ea56c54a81382e990581ef7c9f6415f29bddde455c2241b245dd4633f"
}

rule MalwareBazaar_unknown_020_ce99a152
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce99a1520f381fba7ca927bc9e214b6e34bebd54548c1c22543bc5b39660510d"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-03 02:51:33"
  condition:
    hash.sha256(0, filesize) == "ce99a1520f381fba7ca927bc9e214b6e34bebd54548c1c22543bc5b39660510d"
}

rule MalwareBazaar_unknown_021_29797d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29797d9cd6453d3c7e6da7322e296434a7fe7bbb844a682065c334f6031c667f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-03 02:48:38"
  condition:
    hash.sha256(0, filesize) == "29797d9cd6453d3c7e6da7322e296434a7fe7bbb844a682065c334f6031c667f"
}

rule MalwareBazaar_Mirai_022_e63465a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e63465a408f710767942b9e7dd7a81c6aa28832f528f47ee4963f8f2b6468f46"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-03 02:39:33"
  condition:
    hash.sha256(0, filesize) == "e63465a408f710767942b9e7dd7a81c6aa28832f528f47ee4963f8f2b6468f46"
}

rule MalwareBazaar_unknown_023_f8e48c91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b"
    family = "unknown"
    file_name = "f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b.exe"
    file_type = "exe"
    first_seen = "2026-09-03 02:27:18"
  condition:
    hash.sha256(0, filesize) == "f8e48c91780b5caf19ffea19636a5ee5976190571654666f55dbb1d10dba281b"
}

rule MalwareBazaar_unknown_024_e9aafe82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f"
    family = "unknown"
    file_name = "e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f.exe"
    file_type = "exe"
    first_seen = "2026-09-03 02:12:21"
  condition:
    hash.sha256(0, filesize) == "e9aafe8252705c375a794133af9fa17e34c93d52b4703ca36c39bf7a24b8ac1f"
}

rule MalwareBazaar_unknown_025_b7de6647
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7de6647c4ef8606dbbdf967b66c4367d326e096f09bb2f6aea97b3bc9f1560f"
    family = "unknown"
    file_name = "Agency_Appointment_MT_Griya_Bugis_Letter.js"
    file_type = "js"
    first_seen = "2026-09-03 02:12:12"
  condition:
    hash.sha256(0, filesize) == "b7de6647c4ef8606dbbdf967b66c4367d326e096f09bb2f6aea97b3bc9f1560f"
}

rule MalwareBazaar_unknown_026_faddaa67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faddaa67db9ba8110597b04ffecba8e37c8a54c1b257d98701e0a85035224c08"
    family = "unknown"
    file_name = "RFQ_LINKER MARINE SERVICE RefN0_LMS_03.09.2026.js"
    file_type = "js"
    first_seen = "2026-09-03 02:01:40"
  condition:
    hash.sha256(0, filesize) == "faddaa67db9ba8110597b04ffecba8e37c8a54c1b257d98701e0a85035224c08"
}

rule MalwareBazaar_CoinMiner_027_b9608f3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98"
    family = "CoinMiner"
    file_name = "b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98.exe"
    file_type = "exe"
    first_seen = "2026-09-03 01:52:27"
  condition:
    hash.sha256(0, filesize) == "b9608f3bdd4fb928a28027ae60f5a974d5eea6f0a3b6867e978884adf945ec98"
}

rule MalwareBazaar_unknown_028_ebcd6dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717"
    family = "unknown"
    file_name = "ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:37:31"
  condition:
    hash.sha256(0, filesize) == "ebcd6dd0aeeb568b1010b8c664c2c9590b973af8d7b919b182e7d990c9dcc717"
}

rule MalwareBazaar_Vidar_029_a105ff3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd"
    family = "Vidar"
    file_name = "a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:37:20"
  condition:
    hash.sha256(0, filesize) == "a105ff3e50426f85385f6ab0cecfc01aecdae51a8aabf4f787ab5bf6cd8506bd"
}

rule MalwareBazaar_Vidar_030_866b1b1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e"
    family = "Vidar"
    file_name = "866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:37:11"
  condition:
    hash.sha256(0, filesize) == "866b1b1fa53cc6798f43564f5c54826c3fa03731f1b1ca0ae323643ccd40a66e"
}

rule MalwareBazaar_Vidar_031_d21d0682
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0"
    family = "Vidar"
    file_name = "d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:37:03"
  condition:
    hash.sha256(0, filesize) == "d21d068229f4202115346c53e44c5128cbb5cabc708ea9485471e9067983b5f0"
}

rule MalwareBazaar_unknown_032_065f8b64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660"
    family = "unknown"
    file_name = "065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:56"
  condition:
    hash.sha256(0, filesize) == "065f8b64455be57d5997f5f4f0c21b181b417ac1d5f66043caa5ac19e24d6660"
}

rule MalwareBazaar_unknown_033_affbb003
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5"
    family = "unknown"
    file_name = "affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:49"
  condition:
    hash.sha256(0, filesize) == "affbb003f93d939eada88497d6bdd4e335fa32e5d8cfacb1486acbc2cce1b1c5"
}

rule MalwareBazaar_Vidar_034_bb6afa93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4"
    family = "Vidar"
    file_name = "bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:43"
  condition:
    hash.sha256(0, filesize) == "bb6afa93514e75276745b5ee7aaf8308d1dabe2ac40f1a1dbec76d0db48066a4"
}

rule MalwareBazaar_unknown_035_7fdd4c3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc"
    family = "unknown"
    file_name = "7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:40"
  condition:
    hash.sha256(0, filesize) == "7fdd4c3e1a3f88b723d381468107540349533d0665fbc569c6daa739a37c8efc"
}

rule MalwareBazaar_Vidar_036_b968e449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012"
    family = "Vidar"
    file_name = "b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:38"
  condition:
    hash.sha256(0, filesize) == "b968e449be596e2ddd2de3b3fba621b2d805a61831256202699f81cb3310c012"
}

rule MalwareBazaar_Vidar_037_586a770f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99"
    family = "Vidar"
    file_name = "586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:32"
  condition:
    hash.sha256(0, filesize) == "586a770f60fb43e916edd98ded65621c38aa6ba0a6488e445e5fab8258779a99"
}

rule MalwareBazaar_unknown_038_8761ae71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42"
    family = "unknown"
    file_name = "8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:25"
  condition:
    hash.sha256(0, filesize) == "8761ae715595e4ccc4b0de0413ab136120f5efe17fa386dec5e506f4b2433e42"
}

rule MalwareBazaar_Vidar_039_2679d8e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37"
    family = "Vidar"
    file_name = "2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:19"
  condition:
    hash.sha256(0, filesize) == "2679d8e62411ea12c57b0e12f9c5b49331c94d7748ccb9d2ab79df39b48e1c37"
}

rule MalwareBazaar_unknown_040_8ec9b81c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b"
    family = "unknown"
    file_name = "8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:12"
  condition:
    hash.sha256(0, filesize) == "8ec9b81c2be13a2a89158a3b7d11628543a939d68b59dcccd56c722a57a1647b"
}

rule MalwareBazaar_Vidar_041_2af02420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26"
    family = "Vidar"
    file_name = "2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:11"
  condition:
    hash.sha256(0, filesize) == "2af024203c58f63a805fecfd68e1d05cddde45e2de6f7ec94c45afca7af22d26"
}

rule MalwareBazaar_Vidar_042_31dca2b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92"
    family = "Vidar"
    file_name = "31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:09"
  condition:
    hash.sha256(0, filesize) == "31dca2b9c929b787e1cf3bddd2b396cd5c3ddf4031274c9ebcccfcf0e5015d92"
}

rule MalwareBazaar_Vidar_043_50b80355
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30"
    family = "Vidar"
    file_name = "50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:36:01"
  condition:
    hash.sha256(0, filesize) == "50b80355b83bce83fb36acf2cdc0cf03f341066dcbd6194c2d8681a207b24f30"
}

rule MalwareBazaar_unknown_044_173aa53e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d"
    family = "unknown"
    file_name = "173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:35:51"
  condition:
    hash.sha256(0, filesize) == "173aa53eac2c81dde77791ee6c13f2531d7f3d1ffb8105573a39fb1d4210c32d"
}

rule MalwareBazaar_Vidar_045_be5a7f27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532"
    family = "Vidar"
    file_name = "be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:35:42"
  condition:
    hash.sha256(0, filesize) == "be5a7f27fdbe89bdf760c46c460047362176dcdc350abedfd801c230bd7e3532"
}

rule MalwareBazaar_unknown_046_d4429b3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350"
    family = "unknown"
    file_name = "d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:35:35"
  condition:
    hash.sha256(0, filesize) == "d4429b3ea619c4c4c90bd5d82dcfc8b2c800d3975cfc9b529d49461c7001d350"
}

rule MalwareBazaar_unknown_047_a5a7c21a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5a7c21a04c0a654173999496842d1e65ad8831faf5f591f5317deb1d800ccf8"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-09-03 01:34:35"
  condition:
    hash.sha256(0, filesize) == "a5a7c21a04c0a654173999496842d1e65ad8831faf5f591f5317deb1d800ccf8"
}

rule MalwareBazaar_unknown_048_ff1aeefd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af"
    family = "unknown"
    file_name = "ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af.bin"
    file_type = "exe"
    first_seen = "2026-09-03 01:34:20"
  condition:
    hash.sha256(0, filesize) == "ff1aeefd1b5b454c353834f28c6e9f7bfab957a1c3a32e8e262f6d856dad40af"
}

rule MalwareBazaar_unknown_049_d5fa2e20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5fa2e2050df64c22d199fbc883cea114253d778765a41503ce26eab1397c3bb"
    family = "unknown"
    file_name = "meteorclient.live__meteor-client-1.21.11-86c1d3.jar"
    file_type = "jar"
    first_seen = "2026-09-03 01:22:23"
  condition:
    hash.sha256(0, filesize) == "d5fa2e2050df64c22d199fbc883cea114253d778765a41503ce26eab1397c3bb"
}

rule MalwareBazaar_Formbook_050_6dd9cbb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dd9cbb836647f0028f8569c5c1aa9594501dec9922e1f20c4b3b7ab43f3014f"
    family = "Formbook"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-03 00:52:09"
  condition:
    hash.sha256(0, filesize) == "6dd9cbb836647f0028f8569c5c1aa9594501dec9922e1f20c4b3b7ab43f3014f"
}

rule MalwareBazaar_Mirai_051_67af64cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67"
    family = "Mirai"
    file_name = "67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67.elf"
    file_type = "elf"
    first_seen = "2026-09-02 23:32:20"
  condition:
    hash.sha256(0, filesize) == "67af64ccdb246c4bf9a50d813d2ca01c6f7c3272c08a6abcdc12761dad2ffa67"
}

rule MalwareBazaar_Mirai_052_bb15153a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb15153a05516064114ea1d783dd58c8284e901c8db0647b48e7ff3ff5e22040"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-02 23:29:38"
  condition:
    hash.sha256(0, filesize) == "bb15153a05516064114ea1d783dd58c8284e901c8db0647b48e7ff3ff5e22040"
}

rule MalwareBazaar_unknown_053_5e4aa217
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7"
    family = "unknown"
    file_name = "5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7.exe"
    file_type = "exe"
    first_seen = "2026-09-02 23:27:20"
  condition:
    hash.sha256(0, filesize) == "5e4aa2174e706863bf2b3117c1333af714da7a754b5b6cd26447cea3417070b7"
}

rule MalwareBazaar_ConnectWise_054_c58e1803
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c58e18034de47fa16597b11ae1c058ee866a8f6d0d8cf4682d0215af07a9ae24"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 23:22:03"
  condition:
    hash.sha256(0, filesize) == "c58e18034de47fa16597b11ae1c058ee866a8f6d0d8cf4682d0215af07a9ae24"
}

rule MalwareBazaar_unknown_055_0b8a6ea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9"
    family = "unknown"
    file_name = "0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:31"
  condition:
    hash.sha256(0, filesize) == "0b8a6ea5423f6ce14b85258248e144f414c1fab2733aba3734af09eeabb9f4a9"
}

rule MalwareBazaar_unknown_056_daf4250e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046"
    family = "unknown"
    file_name = "daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:23"
  condition:
    hash.sha256(0, filesize) == "daf4250ed250279bfe11e81526759922f67ea98af275f92b718d47ff2640a046"
}

rule MalwareBazaar_Vidar_057_58aceed3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163"
    family = "Vidar"
    file_name = "58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:16"
  condition:
    hash.sha256(0, filesize) == "58aceed329e0410ffaadd64051e5646b76051d7fee7389a423b98fbf7acbe163"
}

rule MalwareBazaar_Vidar_058_aba3cc5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552"
    family = "Vidar"
    file_name = "aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:10"
  condition:
    hash.sha256(0, filesize) == "aba3cc5c9e97db4eb32c8ad07bf35a9d4f73906daa6a78cb3b5e6bdac3946552"
}

rule MalwareBazaar_unknown_059_07077ec5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca"
    family = "unknown"
    file_name = "07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:08"
  condition:
    hash.sha256(0, filesize) == "07077ec5e760d7387a43de0784b55b4529a8a2c1497d137ffc6a005c23cf10ca"
}

rule MalwareBazaar_Vidar_060_d425d527
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9"
    family = "Vidar"
    file_name = "d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9.bin"
    file_type = "exe"
    first_seen = "2026-09-02 23:04:02"
  condition:
    hash.sha256(0, filesize) == "d425d527f4bf5fa168c5672508b6c5dc358c58c7f865a43f8c77c692d784a2b9"
}

rule MalwareBazaar_unknown_061_842ab7ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857"
    family = "unknown"
    file_name = "842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857"
    file_type = "gz"
    first_seen = "2026-09-02 23:00:14"
  condition:
    hash.sha256(0, filesize) == "842ab7ab49181415c8beb089851cce560ae6162149eaa6622d46123e55e69857"
}

rule MalwareBazaar_unknown_062_5c80a2d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c80a2d4b00b367d44f0bc3540f7ec0158e4b216495de17be1ee2dad7a6651b7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 22:52:38"
  condition:
    hash.sha256(0, filesize) == "5c80a2d4b00b367d44f0bc3540f7ec0158e4b216495de17be1ee2dad7a6651b7"
}

rule MalwareBazaar_ConnectWise_063_39327957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3932795771fe8fcb4580771d9e478951af7cdc22870e8c723191a6dfe2de28ec"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 22:47:40"
  condition:
    hash.sha256(0, filesize) == "3932795771fe8fcb4580771d9e478951af7cdc22870e8c723191a6dfe2de28ec"
}

rule MalwareBazaar_AgentTesla_064_0910fc3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0910fc3c5cb222b5b43eef9b187784e36e484728acaa1198b41fb54707c3e167"
    family = "AgentTesla"
    file_name = "orden de compra.exe"
    file_type = "exe"
    first_seen = "2026-09-02 22:32:49"
  condition:
    hash.sha256(0, filesize) == "0910fc3c5cb222b5b43eef9b187784e36e484728acaa1198b41fb54707c3e167"
}

rule MalwareBazaar_Mirai_065_0026d4ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e"
    family = "Mirai"
    file_name = "0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e.elf"
    file_type = "elf"
    first_seen = "2026-09-02 22:27:23"
  condition:
    hash.sha256(0, filesize) == "0026d4ecdb0b8eeda2f86c5d8e4442abb5f6601a8976ae1621a44ecbdc202e4e"
}

rule MalwareBazaar_Mirai_066_084a1a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "084a1a1431eca54254a61f6c5c330f08b68654fab510bbeb2c1cd72a97326d6b"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-02 22:23:37"
  condition:
    hash.sha256(0, filesize) == "084a1a1431eca54254a61f6c5c330f08b68654fab510bbeb2c1cd72a97326d6b"
}

rule MalwareBazaar_unknown_067_9994f013
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9994f013616d38865431d1df6b1c74d1c6cbd15c34da99dacab30e780e26c125"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-02 22:23:35"
  condition:
    hash.sha256(0, filesize) == "9994f013616d38865431d1df6b1c74d1c6cbd15c34da99dacab30e780e26c125"
}

rule MalwareBazaar_Mirai_068_02f01bb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02f01bb20d47400abd0b37895a0c8b0ad6d7785c326f0bda61c0cc8fd32284fa"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-02 22:20:39"
  condition:
    hash.sha256(0, filesize) == "02f01bb20d47400abd0b37895a0c8b0ad6d7785c326f0bda61c0cc8fd32284fa"
}

rule MalwareBazaar_Mirai_069_6ece7c73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ece7c73a89d0aea67a9f38a49b7589b54e7e07ff4dd6cf1c4b7ff0905d15880"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-02 22:02:50"
  condition:
    hash.sha256(0, filesize) == "6ece7c73a89d0aea67a9f38a49b7589b54e7e07ff4dd6cf1c4b7ff0905d15880"
}

rule MalwareBazaar_unknown_070_847ccdf1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847ccdf192ec6c7278d8f235ae3c6f48f11ff941fc1c2807680e2fc5344b1065"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-02 21:44:48"
  condition:
    hash.sha256(0, filesize) == "847ccdf192ec6c7278d8f235ae3c6f48f11ff941fc1c2807680e2fc5344b1065"
}

rule MalwareBazaar_unknown_071_ad820b12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad820b12eaf9a124fd15f846859b765441ff31d83613872f829691905245809f"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-02 21:38:40"
  condition:
    hash.sha256(0, filesize) == "ad820b12eaf9a124fd15f846859b765441ff31d83613872f829691905245809f"
}

rule MalwareBazaar_unknown_072_2ae3c4bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ae3c4bb100d33d7de57809caf7447d09e8afec83f28d246c3f9d772523f09d4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 21:37:46"
  condition:
    hash.sha256(0, filesize) == "2ae3c4bb100d33d7de57809caf7447d09e8afec83f28d246c3f9d772523f09d4"
}

rule MalwareBazaar_unknown_073_f396236b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f396236bb973e1d6fe39ade485a594d680892d6772d579de9a71533fbd21804a"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-02 21:26:49"
  condition:
    hash.sha256(0, filesize) == "f396236bb973e1d6fe39ade485a594d680892d6772d579de9a71533fbd21804a"
}

rule MalwareBazaar_unknown_074_cabddafb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cabddafb8e09e8d852901885bead3dccd00805d41bd5bde3cd0e08ccc9a7ac34"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 21:03:10"
  condition:
    hash.sha256(0, filesize) == "cabddafb8e09e8d852901885bead3dccd00805d41bd5bde3cd0e08ccc9a7ac34"
}

rule MalwareBazaar_unknown_075_25b17f1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25b17f1c0501789e6cb492441d30ecff8c3d3920b6a94dfff20a0daa02229512"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-02 20:55:44"
  condition:
    hash.sha256(0, filesize) == "25b17f1c0501789e6cb492441d30ecff8c3d3920b6a94dfff20a0daa02229512"
}

rule MalwareBazaar_unknown_076_b7bad05c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2"
    family = "unknown"
    file_name = "b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2.exe"
    file_type = "exe"
    first_seen = "2026-09-02 20:52:36"
  condition:
    hash.sha256(0, filesize) == "b7bad05c7e44fd0d443f38d80bf9474eb0441ee8587bca745a7572ac28d942d2"
}

rule MalwareBazaar_unknown_077_96fbc963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c"
    family = "unknown"
    file_name = "96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c.bin"
    file_type = "exe"
    first_seen = "2026-09-02 20:47:32"
  condition:
    hash.sha256(0, filesize) == "96fbc96352571c3af1230bda2ab42b23aed9ed239232ae71db074a616e1d5a9c"
}

rule MalwareBazaar_unknown_078_4b62026e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b62026ec5bff8176775fe5b6dfff7e6481afa461da0567c41ac7bf1abe8b7d5"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-02 20:46:56"
  condition:
    hash.sha256(0, filesize) == "4b62026ec5bff8176775fe5b6dfff7e6481afa461da0567c41ac7bf1abe8b7d5"
}

rule MalwareBazaar_unknown_079_c12e819d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c12e819df8b2526a35b97ff5437194b9518c9d4b8c301746f7c7d3e25aaf00da"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-02 20:46:54"
  condition:
    hash.sha256(0, filesize) == "c12e819df8b2526a35b97ff5437194b9518c9d4b8c301746f7c7d3e25aaf00da"
}

rule MalwareBazaar_unknown_080_5d5ca639
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d5ca63931bc049be479599cfe5c96c2ed601658f4272bf015a5f24b93e2cb6d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 20:40:53"
  condition:
    hash.sha256(0, filesize) == "5d5ca63931bc049be479599cfe5c96c2ed601658f4272bf015a5f24b93e2cb6d"
}

rule MalwareBazaar_unknown_081_298fed4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "298fed4ed5f4f5c7a3a6722436be6172b1f4c81e1f274720f9b0b65d7f0b341a"
    family = "unknown"
    file_name = "pago corporativo;FE94876;01;.js"
    file_type = "js"
    first_seen = "2026-09-02 20:39:17"
  condition:
    hash.sha256(0, filesize) == "298fed4ed5f4f5c7a3a6722436be6172b1f4c81e1f274720f9b0b65d7f0b341a"
}

rule MalwareBazaar_unknown_082_4801195b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4801195bebee290ed488e07e87a4ad96218febd18e595cdc024af65a0beb0c0f"
    family = "unknown"
    file_name = "malware_sample_tmp_dot_c.bin"
    file_type = "elf"
    first_seen = "2026-09-02 20:24:27"
  condition:
    hash.sha256(0, filesize) == "4801195bebee290ed488e07e87a4ad96218febd18e595cdc024af65a0beb0c0f"
}

rule MalwareBazaar_Mirai_083_de48b457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146"
    family = "Mirai"
    file_name = "de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146.elf"
    file_type = "elf"
    first_seen = "2026-09-02 20:17:25"
  condition:
    hash.sha256(0, filesize) == "de48b45702c25d939ae1ecdd8ab9f5c79dfa530ee81a64bd7af564440ab46146"
}

rule MalwareBazaar_NanoCore_084_632483ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "632483ffc92cf6cf7aa1900f312ec8a89af06bc3ce8edab8147013cee68510dc"
    family = "NanoCore"
    file_name = "14e53f177fc328f845b1847b5cab0703.exe"
    file_type = "exe"
    first_seen = "2026-09-02 20:15:06"
  condition:
    hash.sha256(0, filesize) == "632483ffc92cf6cf7aa1900f312ec8a89af06bc3ce8edab8147013cee68510dc"
}

rule MalwareBazaar_unknown_085_47e6a014
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219"
    family = "unknown"
    file_name = "47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219.exe"
    file_type = "exe"
    first_seen = "2026-09-02 20:07:42"
  condition:
    hash.sha256(0, filesize) == "47e6a0142c874d0716d828d33bae74d29f9c24e13bf80e3f2e5734320028d219"
}

rule MalwareBazaar_Mirai_086_3dc0efea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea"
    family = "Mirai"
    file_name = "3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea.elf"
    file_type = "elf"
    first_seen = "2026-09-02 20:07:22"
  condition:
    hash.sha256(0, filesize) == "3dc0efeaf17700be3cc94b762d377b31e94744ce67cfd3fb8c9e58c03c093fea"
}

rule MalwareBazaar_unknown_087_b98c9031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3"
    family = "unknown"
    file_name = "b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3.elf"
    file_type = "elf"
    first_seen = "2026-09-02 20:02:21"
  condition:
    hash.sha256(0, filesize) == "b98c9031c643b5c8f432c41df3512f5862e5e7272a117066b478eb137ffaccc3"
}

rule MalwareBazaar_unknown_088_14b0fdba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14b0fdba2beb047d7796352ce56ceabeebb1a70863f29f088a046ca05246196f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 19:55:46"
  condition:
    hash.sha256(0, filesize) == "14b0fdba2beb047d7796352ce56ceabeebb1a70863f29f088a046ca05246196f"
}

rule MalwareBazaar_Vidar_089_c381052b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985"
    family = "Vidar"
    file_name = "c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985.bin"
    file_type = "exe"
    first_seen = "2026-09-02 19:49:06"
  condition:
    hash.sha256(0, filesize) == "c381052b7db304df78fe1964ddd318b1df808f89f81ea78bf63c8e4927356985"
}

rule MalwareBazaar_unknown_090_54620981
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96"
    family = "unknown"
    file_name = "54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96.bin"
    file_type = "exe"
    first_seen = "2026-09-02 19:49:02"
  condition:
    hash.sha256(0, filesize) == "54620981fdf60ef62541fc467aacf3acdcfbdc9df8de23e2dd0fbe33e3489c96"
}

rule MalwareBazaar_CoinMiner_091_6b290e28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65"
    family = "CoinMiner"
    file_name = "6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65.exe"
    file_type = "exe"
    first_seen = "2026-09-02 19:47:32"
  condition:
    hash.sha256(0, filesize) == "6b290e28bce7de325c98067c618e42432d43ec7708028cec3908982285c00f65"
}

rule MalwareBazaar_unknown_092_8cc7987d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cc7987d58d8095184529de67f18bd247a3cc7590fd1cf6078d590b5d78d480c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 19:20:26"
  condition:
    hash.sha256(0, filesize) == "8cc7987d58d8095184529de67f18bd247a3cc7590fd1cf6078d590b5d78d480c"
}

rule MalwareBazaar_unknown_093_5b9a3960
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b9a396000622460864f616fe46f4232fae004838284a97c729f74c056f0a6c4"
    family = "unknown"
    file_name = "Boostrapsrrer.exe"
    file_type = "exe"
    first_seen = "2026-09-02 19:10:14"
  condition:
    hash.sha256(0, filesize) == "5b9a396000622460864f616fe46f4232fae004838284a97c729f74c056f0a6c4"
}

rule MalwareBazaar_Mirai_094_bc94f10c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc94f10c4b7da185b319cf4b6195321d4d456ff877324d905867df810880c22c"
    family = "Mirai"
    file_name = "mips64b"
    file_type = "elf"
    first_seen = "2026-09-02 19:07:47"
  condition:
    hash.sha256(0, filesize) == "bc94f10c4b7da185b319cf4b6195321d4d456ff877324d905867df810880c22c"
}

rule MalwareBazaar_unknown_095_b9002241
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f"
    family = "unknown"
    file_name = "b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f.bin"
    file_type = "exe"
    first_seen = "2026-09-02 18:52:30"
  condition:
    hash.sha256(0, filesize) == "b90022410dcee12e45e73327a6e1d9288aeeb175db0895445453e14f146d0c0f"
}

rule MalwareBazaar_Vidar_096_d4df270e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272"
    family = "Vidar"
    file_name = "d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272.bin"
    file_type = "exe"
    first_seen = "2026-09-02 18:52:28"
  condition:
    hash.sha256(0, filesize) == "d4df270ea5a146713de213817b88ba95e575c2eea4c1e66f4c070cacc6ae1272"
}

rule MalwareBazaar_Vidar_097_85a2a141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8"
    family = "Vidar"
    file_name = "85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8.bin"
    file_type = "exe"
    first_seen = "2026-09-02 18:52:24"
  condition:
    hash.sha256(0, filesize) == "85a2a141e838b0ab2d506444430b75870919caec56768af7631d1c8f83dee2e8"
}

rule MalwareBazaar_Prometei_098_a8b95815
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f"
    family = "Prometei"
    file_name = "a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f"
    file_type = "elf"
    first_seen = "2026-09-02 18:50:25"
  condition:
    hash.sha256(0, filesize) == "a8b95815956cae833e1798b4f0f18f17c232c8f7e391bc577207dd6fd450211f"
}

rule MalwareBazaar_unknown_099_024a468c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "024a468c83ccd295d61855b84cb6ab026dd6674b1609161426bc9b04cbf0f35c"
    family = "unknown"
    file_name = "netlogd_x86_64"
    file_type = "elf"
    first_seen = "2026-09-02 18:35:25"
  condition:
    hash.sha256(0, filesize) == "024a468c83ccd295d61855b84cb6ab026dd6674b1609161426bc9b04cbf0f35c"
}

rule MalwareBazaar_unknown_100_4647cad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4647cad54d9fe7fdceac886773f33f796c75ed95bd532c3e25da49e8c584a053"
    family = "unknown"
    file_name = "netlogd_mipsbe"
    file_type = "elf"
    first_seen = "2026-09-02 18:35:24"
  condition:
    hash.sha256(0, filesize) == "4647cad54d9fe7fdceac886773f33f796c75ed95bd532c3e25da49e8c584a053"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

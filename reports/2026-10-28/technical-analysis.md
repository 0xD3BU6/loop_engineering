# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-28

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 677 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 677 |
| Unique family labels | 8 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| SalatStealer | 56 |
| unknown | 23 |
| Mirai | 16 |
| ConnectWise | 1 |
| QuasarRAT | 1 |
| AgentTesla | 1 |
| RemcosRAT | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 63 |
| elf | 29 |
| vbs | 4 |
| macho | 2 |
| msi | 1 |
| zsh | 1 |

## Per-Sample Analysis

### Sample 1: `ac548fda4f1cffc0`

| Field | Value |
|---|---|
| SHA-256 | `ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7` |
| Family label | `unknown` |
| File name | `ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7.elf` |
| File type | `elf` |
| First seen | `2026-10-28 05:53:15` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0ab8c67edb28dc7c284d26982c65a02` |
| SHA-1 | `6e2e57550ec61e5525a58ed08c9ac214b1412cce` |
| SHA-256 | `ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7` |
| SHA3-384 | `751a33de66da017986f0e5857c7eabcb72b24579767cbe411d880886b7ecd793b8b571d16677f1147084522cc3783c52` |
| TLSH | `T13AE35B06B4D1C8FEC89AC2745B9BF136DA71F4194238B16F27D8AB632F4EE205B5D610` |
| TELFHASH | `t15251dc342da23d9462e3e336b30be67de8720a2219e171e1ef736dd1ce167c40da2016` |
| SSDEEP | `3072:sgJNpOx/ocv6/Tm7Lt2louN6JSiBrXcUCrfEVHUK1W:bJWx6mvu8SLEVHU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_ac548fda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7"
    family = "unknown"
    file_name = "ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7.elf"
    file_type = "elf"
    first_seen = "2026-10-28 05:53:15"
  condition:
    hash.sha256(0, filesize) == "ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7"
}
```

### Sample 2: `7c5dcda6d5ed9aca`

| Field | Value |
|---|---|
| SHA-256 | `7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3` |
| Family label | `unknown` |
| File name | `7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:34:45` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1eae65f6164e14b76019a46eb5206ea` |
| SHA-1 | `6e21fd4148f1147541beafe9db9422f02bba1e84` |
| SHA-256 | `7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3` |
| SHA3-384 | `b0a1087bf0c42ff85dd3eb23b316c3c089ff07041cdf7d04731401c7c780eedcacf3f12f3c959c63569a847bc838f338` |
| TLSH | `T15C939E12E8649E9CF03F6C3520788ABA4323E1D4C9176DBB2856C2651147EA8F59FFF4` |
| SSDEEP | `1536:B3BhJIDzJnOW2SluAJSMxUBG0WZi5AKxdDew80Cpixx8sR+q:B3BhJIDzJOeluAJXUyMxV805xcq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_7c5dcda6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3"
    family = "unknown"
    file_name = "7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:45"
  condition:
    hash.sha256(0, filesize) == "7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3"
}
```

### Sample 3: `12fcb09c83e233ec`

| Field | Value |
|---|---|
| SHA-256 | `12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695` |
| Family label | `unknown` |
| File name | `12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:34:40` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73a8b89dd0a639d31629eb31ee76c320` |
| SHA-1 | `2393d15fc01e0c39146b5b3525bf545ef9716097` |
| SHA-256 | `12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695` |
| SHA3-384 | `b724098d9765c3f342c7bd52457af3e738ff03ad40f71038d4200ddbf034d9838224a14b657d031da3fb39695015f6dc` |
| TLSH | `T101939F52E8609D9CF03FAC3510789AB94723E0D488176FBB2856C2661247E98F59FFF4` |
| SSDEEP | `1536:B3BhJ8DzJnOW2SluAJSMxUBG0WZi5AKxdDeT80Cpixx8sR+:B3BhJ8DzJOeluAJXUyMx+805xc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_12fcb09c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695"
    family = "unknown"
    file_name = "12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:40"
  condition:
    hash.sha256(0, filesize) == "12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695"
}
```

### Sample 4: `78a70d90cdb6b37f`

| Field | Value |
|---|---|
| SHA-256 | `78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7` |
| Family label | `unknown` |
| File name | `78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:34:36` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc2824e29d82476d80eb6ca1cd8132b1` |
| SHA-1 | `407e0bc51eace518cc884627f3af2f2c1a163a1a` |
| SHA-256 | `78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7` |
| SHA3-384 | `625c8f98d123cf401ecac17a56e4a361d4a82f8275fad7a7d56ac6e02e4965c70b85cae5e0a72c4a1c1c32b409c7e499` |
| TLSH | `T19AC32BDABC409B51D6D525BAFE0D908D33634BFCE3F971029D199B2E178AC5B0E3A601` |
| SSDEEP | `3072:I7T81GB6OSa4+v33k+ZL/RjFbl5VEjRL8aAGKOTXNJD6z:99gk+ZL/vp5VEjRL8alKQ2z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_78a70d90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7"
    family = "unknown"
    file_name = "78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:36"
  condition:
    hash.sha256(0, filesize) == "78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7"
}
```

### Sample 5: `8c5afc29edbe22b4`

| Field | Value |
|---|---|
| SHA-256 | `8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7` |
| Family label | `unknown` |
| File name | `8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:34:32` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebcaa8e17e0f385eea0a48f51136b959` |
| SHA-1 | `cd1012e410ab5161c4b8d60a340e7a74851d6ea3` |
| SHA-256 | `8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7` |
| SHA3-384 | `f7949dd21b844e23d999accae7c16b70f8a4c8f0ccc9051866824be37d0e67ccc4788147bb91cb512e8024d71a745806` |
| TLSH | `T1A9A31BDAB8408B51D6D555BAFD1D90CD33230BFCE3ED71129D18AB2E174BC670A3A605` |
| SSDEEP | `3072:20cNJzJJfSb4bMCry6tSVeR6V0dDVy3van+EbQDa6:gcbAjVtSVeAV2Y3vJW6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_8c5afc29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7"
    family = "unknown"
    file_name = "8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:32"
  condition:
    hash.sha256(0, filesize) == "8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7"
}
```

### Sample 6: `61c16cac594f7827`

| Field | Value |
|---|---|
| SHA-256 | `61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db` |
| Family label | `Mirai` |
| File name | `61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:34:18` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, jkl, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16d9b3c54ceb1b009a44ad9f6e9485e4` |
| SHA-1 | `050dcdb43e5c1d9a0465794466e390dcbac7fd5f` |
| SHA-256 | `61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db` |
| SHA3-384 | `aecad276b368358e54f049f678f9f3a97e3afc03b811db368497799b3a0441db9cd96f20b5566e86e63a378e94772527` |
| TLSH | `T1EB834AC1D183D8F9FD19057924A7F337A232E9BC0128FEE3F75497B25425A94B04AA8D` |
| TELFHASH | `t1b551c1f9167a0d94a7d09c02f25e97603d4efbbb245076e3497368312216b8356bbc39` |
| SSDEEP | `1536:YuqW5Xch0VamHLy1FF+LP2ng1W00bZzpqo5OD8WYvSrwXQR6e1ffT:YbiJVaILy1POun90aRko5AZYwwhe1ffT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_61c16cac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db"
    family = "Mirai"
    file_name = "61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:18"
  condition:
    hash.sha256(0, filesize) == "61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db"
}
```

### Sample 7: `ca7929791d818cc4`

| Field | Value |
|---|---|
| SHA-256 | `ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b` |
| Family label | `Mirai` |
| File name | `ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:34:13` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, jkl, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba589e02d3c544d3e63a54b035ec53db` |
| SHA-1 | `97f4d8ea9bf62aa7253da76cd4febf3bcfd1312c` |
| SHA-256 | `ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b` |
| SHA3-384 | `6fb24ed52af34136d7991f3251923b15c3976ec056d75b05ace7a15bc3d90b165a43e1c0c5af460657681ae6ba39e8a4` |
| TLSH | `T19D939E128E645D9CF42E7D3120B58BBA8B13A184851B6DF73996C2665007DC8F1EFBF8` |
| SSDEEP | `1536:R6Z8E2hn++lWIntORpoqM9tkaGP89iOVti+X+hEKZa9WdVDCEj7LOwbsR/H:R6Z8Nhn+oTtOport+P4vtdOlZlVD3LOl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_ca792979
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b"
    family = "Mirai"
    file_name = "ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:13"
  condition:
    hash.sha256(0, filesize) == "ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b"
}
```

### Sample 8: `59fd01a3738cf09a`

| Field | Value |
|---|---|
| SHA-256 | `59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e` |
| Family label | `Mirai` |
| File name | `59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:34:08` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, jkl, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a68ab4195b68043e5b679dc29815392a` |
| SHA-1 | `c9241141686c6eb552da1f5d6e8bdccc30858492` |
| SHA-256 | `59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e` |
| SHA3-384 | `9d5d3262c53cdddd35cfcae4fe12bf737c5664b307761a5e8dbf4b75142a2e2eaf6bd2c6a9385477b4ae4be35150ff0c` |
| TLSH | `T16BC3080ABFB11EFBD4AFCD3345A98709389C564A21B43B766574D82CF65B14F06E38A0` |
| SSDEEP | `1536:k6sWkYsBFxAN9bQhG3tIgMp8gxY1QydojYdjb8nb45fMoO95atyhAex9/l1CHL8r:klTCtIgMp8RU9lAL8LEnWaoUUwSx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_59fd01a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e"
    family = "Mirai"
    file_name = "59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:08"
  condition:
    hash.sha256(0, filesize) == "59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e"
}
```

### Sample 9: `7e8758ebe49cdac4`

| Field | Value |
|---|---|
| SHA-256 | `7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da` |
| Family label | `Mirai` |
| File name | `7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:34:03` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, jkl, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2480cd04fda56ee100d9a1ce932eb72a` |
| SHA-1 | `8962e77f0072ad13b64956f59a66e6d703665ef5` |
| SHA-256 | `7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da` |
| SHA3-384 | `22288204896a96e7730d0d609500b87afecf60b09af86199775510a2f64c7606b6fa3603687a109fb715bf5aec96189f` |
| TLSH | `T18EC30A89BC808B11D5D625BAFE0F518D33134BB8E3FA7113CE145B2D678AC6B0A7B615` |
| SSDEEP | `3072:XCURAF6WApnfmVCENxjP5lBqjyMsALwaBOvcmvKAX4cWter5UIB:pQVvFPwjyMpwaBOvcmvvX1bB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_7e8758eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da"
    family = "Mirai"
    file_name = "7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:03"
  condition:
    hash.sha256(0, filesize) == "7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da"
}
```

### Sample 10: `a86b362e490613b3`

| Field | Value |
|---|---|
| SHA-256 | `a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b` |
| Family label | `Mirai` |
| File name | `a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:33:58` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, jkl, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab0edd534c2caf681041312e0e24f950` |
| SHA-1 | `6823e951348d9df1f3afcef9ef4fbe3b5e4c2414` |
| SHA-256 | `a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b` |
| SHA3-384 | `25a82ca2fc41d423f3688ed5b7bd981d54f8f947d2c7b4f4df8af4e577a0e0bc0ffcb5d7bbae1935b551cce4667f4ebc` |
| TLSH | `T151B31BCABC818B11C5C555BAFE1E618D33234BB8E3EE7213CE149B2D77868670A3B515` |
| SSDEEP | `3072:zQjRAZ4C9S9mn9E09Th/JZLn1UOsGaN2FePWr6cW54Uwou:ZXnHhhz1UOvaMePfhu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_a86b362e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b"
    family = "Mirai"
    file_name = "a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:33:58"
  condition:
    hash.sha256(0, filesize) == "a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b"
}
```

### Sample 11: `9f7050c6acb26c73`

| Field | Value |
|---|---|
| SHA-256 | `9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9` |
| Family label | `Mirai` |
| File name | `9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:33:54` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, jkl, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9b2dab88a20cfbe4a4370c03b300cb3` |
| SHA-1 | `9da06a00eff80a0a7b2c8cab1ebe645ad030538a` |
| SHA-256 | `9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9` |
| SHA3-384 | `414124cde3c4d5fcb7b7b6af6dec405d18d323ddc715e8f71b460749e4ee6a4439301b4e267dcf09ad9769586d1330c5` |
| TLSH | `T1C7A30A8ABCC1C612C5E4A0B6BB1F91DD376643B8D3E67207DD18AB19774B8670E3B241` |
| SSDEEP | `1536:R0TwcuYZcvyRyJ6Q/VnnsRnIglFPLshzGtaCrv5bHen9I3UwbsRLt:R0TBuCcaRDgnsRnIqhIzAaCrwnSUwIt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_9f7050c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9"
    family = "Mirai"
    file_name = "9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:33:54"
  condition:
    hash.sha256(0, filesize) == "9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9"
}
```

### Sample 12: `5418fcbc94234135`

| Field | Value |
|---|---|
| SHA-256 | `5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094` |
| Family label | `Mirai` |
| File name | `5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094.bin` |
| File type | `elf` |
| First seen | `2026-10-28 05:33:49` |
| Reporter | `tipo_deincognito` |
| Tags | `ddos, elf, jkl, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2965d2c58fa723adb442e36fee7b1ed1` |
| SHA-1 | `ff5d9836e9d811e5cf1622c762cd3db1845017ca` |
| SHA-256 | `5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094` |
| SHA3-384 | `7c09b7d8785f16c7500587bffeb8b689b73e48650fd2474840d4c0f6f1e43e400a36455db3e460a6ca79a9370bb29dbf` |
| TLSH | `T15DA3088ABCC5C612C5E0A0B6BB0F91DD372643B8D3E67207CD19AB19774B8670E3B251` |
| SSDEEP | `1536:x4N/6nq59XGTX+kV7BHbW9/zGold+ogFruRZgyvvUwbsRx8UMkv:uNyqDXyXLVHby/zGKd+ogkFvUwy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_5418fcbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094"
    family = "Mirai"
    file_name = "5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:33:49"
  condition:
    hash.sha256(0, filesize) == "5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094"
}
```

### Sample 13: `2c0167ce11b75014`

| Field | Value |
|---|---|
| SHA-256 | `2c0167ce11b750143df49f1c55dd24090c66003a267e1a5d915f1e7acaf8ddd9` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-28 05:13:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ffad6f4c631ffc59ddeea641bcd0fae` |
| SHA-1 | `49a6849cad11c487c9f486a20e5b224cfe07fe9c` |
| SHA-256 | `2c0167ce11b750143df49f1c55dd24090c66003a267e1a5d915f1e7acaf8ddd9` |
| SHA3-384 | `1b03a09a24251e29b1664724e24e64e9c8110f1eee46fa1991a2c1e17c32fdde0762f10c952a983fbe1ce3699b222f12` |
| TLSH | `T173740A88A1F1E7DED2D4EA75B31D780D3B230736B1D73146A51EAA3323EB1450AF9921` |
| TELFHASH | `t10df0c91000795acd47c784905b61d037422d3e243b9134e7c7a0b32e8d31a8234eaf77` |
| SSDEEP | `6144:JjwKSrlkaJoiI2L6uiQXFlnMeEiqbnLwRZPkthCWa9Ri45:zSRkaC1u98d3+POBa9Ri+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_2c0167ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c0167ce11b750143df49f1c55dd24090c66003a267e1a5d915f1e7acaf8ddd9"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-28 05:13:18"
  condition:
    hash.sha256(0, filesize) == "2c0167ce11b750143df49f1c55dd24090c66003a267e1a5d915f1e7acaf8ddd9"
}
```

### Sample 14: `b9a89b50f1d73a22`

| Field | Value |
|---|---|
| SHA-256 | `b9a89b50f1d73a22363c408643e9572c2b60b5d88220c72d10a2050866e9a0aa` |
| Family label | `unknown` |
| File name | `z17nfe_calcgraf_informatica_e_consultoria_ltda.vbs` |
| File type | `vbs` |
| First seen | `2026-10-28 05:01:18` |
| Reporter | `fabiodemartin` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d7f7a21b0dad29738279bf6cfa224e7` |
| SHA-1 | `7484224719e6ba99d289daf20d50bfadc3221060` |
| SHA-256 | `b9a89b50f1d73a22363c408643e9572c2b60b5d88220c72d10a2050866e9a0aa` |
| SHA3-384 | `4e5f5846257b8ab037983850e3649df7fb83d2d264b89f954881d840f0df1961d3738448a3c8201ba3375eb9a9bd1368` |
| TLSH | `T1AE23F93C9E18227FA7F8D614D6D6494FF081B573B6212ECAF0CB1348857756278CAA1E` |
| SSDEEP | `384:lJQuSD91WM5lNhyWdniEtQfRp5dhGUNwDTxBbdzkcRudnTOyvrMJvzcQgjWdmuEz:lJbqNh7HTcNLACslGecfS31HE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_b9a89b50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9a89b50f1d73a22363c408643e9572c2b60b5d88220c72d10a2050866e9a0aa"
    family = "unknown"
    file_name = "z17nfe_calcgraf_informatica_e_consultoria_ltda.vbs"
    file_type = "vbs"
    first_seen = "2026-10-28 05:01:18"
  condition:
    hash.sha256(0, filesize) == "b9a89b50f1d73a22363c408643e9572c2b60b5d88220c72d10a2050866e9a0aa"
}
```

### Sample 15: `3c4365a3691a6059`

| Field | Value |
|---|---|
| SHA-256 | `3c4365a3691a6059377ae369468b91364efd56fd829f6974406155e6a5000289` |
| Family label | `SalatStealer` |
| File name | `aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676.exe` |
| File type | `exe` |
| First seen | `2026-10-28 04:54:30` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17a457e35697cd7f6ac68bfbe465cddf` |
| SHA-1 | `d3a83e5f1c743c224870daedf75cdc4f7d1484bc` |
| SHA-256 | `3c4365a3691a6059377ae369468b91364efd56fd829f6974406155e6a5000289` |
| SHA3-384 | `18c6cc602e147e1a167eb163938dc6bc82a97eb4ea0cae5978e8a5381fe4ae6d952eb32952b4cbecc364456e798dbf47` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T17BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+f:yBkKr5rszpNDy+f` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_015_3c4365a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c4365a3691a6059377ae369468b91364efd56fd829f6974406155e6a5000289"
    family = "SalatStealer"
    file_name = "aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:54:30"
  condition:
    hash.sha256(0, filesize) == "3c4365a3691a6059377ae369468b91364efd56fd829f6974406155e6a5000289"
}
```

### Sample 16: `a9a4ff6d4f4a2687`

| Field | Value |
|---|---|
| SHA-256 | `a9a4ff6d4f4a268709fcdbf6f92812d2fe5bafb79091c2dd951ecd6ddda3353b` |
| Family label | `SalatStealer` |
| File name | `9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b.exe` |
| File type | `exe` |
| First seen | `2026-10-28 04:54:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fe56fa4294916b22c995d5ae4f1a1f9` |
| SHA-1 | `dc864b182216a7aefb920974a8429905433cac14` |
| SHA-256 | `a9a4ff6d4f4a268709fcdbf6f92812d2fe5bafb79091c2dd951ecd6ddda3353b` |
| SHA3-384 | `67a821c5bc86a9448f79d4b824f441205cd229a62271518f87013f460a9c7a510350b869a56dd40b635ad471c5d0098b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T14AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+l:yBkKr5rszpNDy+l` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_016_a9a4ff6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9a4ff6d4f4a268709fcdbf6f92812d2fe5bafb79091c2dd951ecd6ddda3353b"
    family = "SalatStealer"
    file_name = "9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:54:22"
  condition:
    hash.sha256(0, filesize) == "a9a4ff6d4f4a268709fcdbf6f92812d2fe5bafb79091c2dd951ecd6ddda3353b"
}
```

### Sample 17: `aa0b71e4b729b985`

| Field | Value |
|---|---|
| SHA-256 | `aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676` |
| Family label | `SalatStealer` |
| File name | `aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676.exe` |
| File type | `exe` |
| First seen | `2026-10-28 04:53:23` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acaac1f4b9dc99eb63c73550e8ab802e` |
| SHA-1 | `f2d4bfabe013bcf7ad775a17665a0e1671a79cc2` |
| SHA-256 | `aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676` |
| SHA3-384 | `42b9632617d234b7451d9e68f907d944dd9ce9bbca01bbff97f6e40e18402e7cd6ff99e4d4ffeed4350fa33754fabee1` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E0F5335BF1AF47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ob:iJiafuIO7rhWEES4c` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_017_aa0b71e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676"
    family = "SalatStealer"
    file_name = "aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:53:23"
  condition:
    hash.sha256(0, filesize) == "aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676"
}
```

### Sample 18: `9d9e8dd3f2722379`

| Field | Value |
|---|---|
| SHA-256 | `9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b` |
| Family label | `SalatStealer` |
| File name | `9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b.exe` |
| File type | `exe` |
| First seen | `2026-10-28 04:53:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5a0c6ecfd4863654081f9aa9ae268a1` |
| SHA-1 | `a9d97b80a636edf7134ae76cb502057b5341b66f` |
| SHA-256 | `9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b` |
| SHA3-384 | `f930e4f9058de44dadf14f761f57d5fe8dfc80a588f9232714e8925e42ea21257ac39efa1ac808db1fcf840231d535b2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T17EF5335BF1AB47B3F7D9A831561FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OB:iJiafuIO7rhWEES4w` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_018_9d9e8dd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b"
    family = "SalatStealer"
    file_name = "9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:53:15"
  condition:
    hash.sha256(0, filesize) == "9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b"
}
```

### Sample 19: `86a05d09d28118a7`

| Field | Value |
|---|---|
| SHA-256 | `86a05d09d28118a71bf3c7dbdf75b489c719196f533d9c9afa7a82ec7b94b6b6` |
| Family label | `unknown` |
| File name | `splsh4` |
| File type | `elf` |
| First seen | `2026-10-28 04:38:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `199e84f5de8c77e9ed8c786d0e8212f6` |
| SHA-1 | `a71b908bea273fb4fc3faf8ee413c2cd554a7bf6` |
| SHA-256 | `86a05d09d28118a71bf3c7dbdf75b489c719196f533d9c9afa7a82ec7b94b6b6` |
| SHA3-384 | `ce2289b7c508d93795fa459d052eb39fd1f224449ffb1104b506c74492ff2f65370f68ae2169a9b6b92635d5f496d51e` |
| TLSH | `T174838E12DD649D9CF05E6E3110B486FE4323A1C8941B6DBB3846C766014BE98F59FBF4` |
| SSDEEP | `1536:pBNnhwGgbJs8JpX8OSMgYqAwSEilUKpPw3HHkvC4xib8sRW:pBNnhwGg1bpX8OuYQQbpQHkv0bU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_86a05d09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86a05d09d28118a71bf3c7dbdf75b489c719196f533d9c9afa7a82ec7b94b6b6"
    family = "unknown"
    file_name = "splsh4"
    file_type = "elf"
    first_seen = "2026-10-28 04:38:22"
  condition:
    hash.sha256(0, filesize) == "86a05d09d28118a71bf3c7dbdf75b489c719196f533d9c9afa7a82ec7b94b6b6"
}
```

### Sample 20: `0841b4670b41bcbe`

| Field | Value |
|---|---|
| SHA-256 | `0841b4670b41bcbe18f8f9ddab82452e5d8b520a28450588188683c088f9dc84` |
| Family label | `SalatStealer` |
| File name | `236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80.exe` |
| File type | `exe` |
| First seen | `2026-10-28 04:34:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `671ca084d7da69bd253304ab829a9a01` |
| SHA-1 | `734fe5752586ba8a7995faacedee5a53e6fd3b37` |
| SHA-256 | `0841b4670b41bcbe18f8f9ddab82452e5d8b520a28450588188683c088f9dc84` |
| SHA3-384 | `badbb1c2c26d98d24ee07165dd6f13e6d58cd8f4a83a73557e6b7edc9e5e26ff26f960c2739fa93734d7e4bba323fd15` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C8C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+1:yBkKr5rszpNDy+1` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_020_0841b467
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0841b4670b41bcbe18f8f9ddab82452e5d8b520a28450588188683c088f9dc84"
    family = "SalatStealer"
    file_name = "236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:34:25"
  condition:
    hash.sha256(0, filesize) == "0841b4670b41bcbe18f8f9ddab82452e5d8b520a28450588188683c088f9dc84"
}
```

### Sample 21: `236531d8f7ef3ff8`

| Field | Value |
|---|---|
| SHA-256 | `236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80` |
| Family label | `SalatStealer` |
| File name | `236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80.exe` |
| File type | `exe` |
| First seen | `2026-10-28 04:33:27` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `300bb77330f0df3ab3fe986eadda30a5` |
| SHA-1 | `0fd6e599abf9b28b19189f79b67f9637981daa4a` |
| SHA-256 | `236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80` |
| SHA3-384 | `49abfb91902b95bfc29b584ee12a0d28eec23468b3046a1146ca0faf5d4c9229d76a6b9d8afcb979fc6bb5ebcc9bd758` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1FBF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Op:iJiafuIO7rhWEES4e` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_021_236531d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80"
    family = "SalatStealer"
    file_name = "236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:33:27"
  condition:
    hash.sha256(0, filesize) == "236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80"
}
```

### Sample 22: `827cc24586574e26`

| Field | Value |
|---|---|
| SHA-256 | `827cc24586574e26e93fcf02b31c1b510af2d00a1497d617206e208ef9019470` |
| Family label | `SalatStealer` |
| File name | `ad27629e028c8e53.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:27:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fadf64319a20ab55ac26cda068317ca` |
| SHA-1 | `209285adaef239cc8694049dd617f85c84c78b05` |
| SHA-256 | `827cc24586574e26e93fcf02b31c1b510af2d00a1497d617206e208ef9019470` |
| SHA3-384 | `1beee825afff954ec1a91fb0795106419b1dd05bee8dd19a4991737e7bf4fa5d0027026d335e55846086d4f99edb1b4d` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T10AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+i:yBkKr5rszpNDy+i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_022_827cc245
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "827cc24586574e26e93fcf02b31c1b510af2d00a1497d617206e208ef9019470"
    family = "SalatStealer"
    file_name = "ad27629e028c8e53.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:27:34"
  condition:
    hash.sha256(0, filesize) == "827cc24586574e26e93fcf02b31c1b510af2d00a1497d617206e208ef9019470"
}
```

### Sample 23: `17a29bd3e29162db`

| Field | Value |
|---|---|
| SHA-256 | `17a29bd3e29162db7116a19f8998f8da888849f8352a9d701bcb0b8d21f8f92a` |
| Family label | `SalatStealer` |
| File name | `facec362d36d153b.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:27:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15d0d9b880a44f0512ee7b4954ad8a10` |
| SHA-1 | `bfef9e44b1408592503180fa49a1b2811159a8e4` |
| SHA-256 | `17a29bd3e29162db7116a19f8998f8da888849f8352a9d701bcb0b8d21f8f92a` |
| SHA3-384 | `4b30900dff45c117c0fe3d90efca5d972c722f585e3d0b9697e628f756f87cbe65b3a1aa128985730528e017d2a55b27` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T115C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+T:yBkKr5rszpNDy+T` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_023_17a29bd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17a29bd3e29162db7116a19f8998f8da888849f8352a9d701bcb0b8d21f8f92a"
    family = "SalatStealer"
    file_name = "facec362d36d153b.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:27:27"
  condition:
    hash.sha256(0, filesize) == "17a29bd3e29162db7116a19f8998f8da888849f8352a9d701bcb0b8d21f8f92a"
}
```

### Sample 24: `620e76aba9c35b98`

| Field | Value |
|---|---|
| SHA-256 | `620e76aba9c35b980150339578bd7126b1044e76f7e4402097b8f1320507665a` |
| Family label | `SalatStealer` |
| File name | `99e0b6dea820607e.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:26:40` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73dd67895db58fd41b4dbd6af5206844` |
| SHA-1 | `6f997ceeca072645bc9e25c307a94ddd4afc5bb4` |
| SHA-256 | `620e76aba9c35b980150339578bd7126b1044e76f7e4402097b8f1320507665a` |
| SHA3-384 | `aab0c855b39f93c58484129712fb3459f7d9779ade701813c53856265d35823bc4455f337d243f3c7f5adaf324993be1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T164C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+k:yBkKr5rszpNDy+k` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_024_620e76ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "620e76aba9c35b980150339578bd7126b1044e76f7e4402097b8f1320507665a"
    family = "SalatStealer"
    file_name = "99e0b6dea820607e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:26:40"
  condition:
    hash.sha256(0, filesize) == "620e76aba9c35b980150339578bd7126b1044e76f7e4402097b8f1320507665a"
}
```

### Sample 25: `70a362e93f81af40`

| Field | Value |
|---|---|
| SHA-256 | `70a362e93f81af408809b14693f2cbf018e895902a5cfa92c59f79317de229f4` |
| Family label | `SalatStealer` |
| File name | `cc111f672b2fce00.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:26:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d64ddc26725e9e6a037218a2b08323e7` |
| SHA-1 | `e5f885cd59c327f4d2472306bff6b516c68af3ce` |
| SHA-256 | `70a362e93f81af408809b14693f2cbf018e895902a5cfa92c59f79317de229f4` |
| SHA3-384 | `54d966e7f75efe11d61ec2405d9ad83d3448ea26c111ad1c2278a639744096952d290524684fe51cc8885e9913cab1f7` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T137C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+c:yBkKr5rszpNDy+c` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_025_70a362e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70a362e93f81af408809b14693f2cbf018e895902a5cfa92c59f79317de229f4"
    family = "SalatStealer"
    file_name = "cc111f672b2fce00.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:26:27"
  condition:
    hash.sha256(0, filesize) == "70a362e93f81af408809b14693f2cbf018e895902a5cfa92c59f79317de229f4"
}
```

### Sample 26: `3f4b07ff57290ace`

| Field | Value |
|---|---|
| SHA-256 | `3f4b07ff57290ace38836d65cc29d373614ec928f7640cefa32e31d694b7c175` |
| Family label | `SalatStealer` |
| File name | `f9bc72da6f6d1ac8.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `402730f5468691e972fda58ce04309d0` |
| SHA-1 | `f352f573f2c65aaddf6d6853c47d3b9b5d07a819` |
| SHA-256 | `3f4b07ff57290ace38836d65cc29d373614ec928f7640cefa32e31d694b7c175` |
| SHA3-384 | `df232b8f5fe896dab8b04ef2f1b2ab2b6ae73cb1d72f43d8ce3ab580cb9a7662d0ed89337af779852175c5464cc072f2` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T16BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+v:yBkKr5rszpNDy+v` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_026_3f4b07ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f4b07ff57290ace38836d65cc29d373614ec928f7640cefa32e31d694b7c175"
    family = "SalatStealer"
    file_name = "f9bc72da6f6d1ac8.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:59"
  condition:
    hash.sha256(0, filesize) == "3f4b07ff57290ace38836d65cc29d373614ec928f7640cefa32e31d694b7c175"
}
```

### Sample 27: `863b07e707af0820`

| Field | Value |
|---|---|
| SHA-256 | `863b07e707af08201e4bf064eb3a6d2c8b180b6827b22364d35e8d487cc371a3` |
| Family label | `SalatStealer` |
| File name | `289624b2a0a08726.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:54` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddcb9e5c6b2ca7f053bcfb6d2a654e7b` |
| SHA-1 | `10d3fdc16e07368bfe26557b699efdaf398aff71` |
| SHA-256 | `863b07e707af08201e4bf064eb3a6d2c8b180b6827b22364d35e8d487cc371a3` |
| SHA3-384 | `be16ef6603aa923792ed2fd7b96306c55b8abb98b9e1a008d7f5d6dfc3c4d450b5fe7c56708b0fdf327d34c88af3f7e6` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T118C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+O:yBkKr5rszpNDy+O` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_027_863b07e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "863b07e707af08201e4bf064eb3a6d2c8b180b6827b22364d35e8d487cc371a3"
    family = "SalatStealer"
    file_name = "289624b2a0a08726.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:54"
  condition:
    hash.sha256(0, filesize) == "863b07e707af08201e4bf064eb3a6d2c8b180b6827b22364d35e8d487cc371a3"
}
```

### Sample 28: `12fc49e9953f19fe`

| Field | Value |
|---|---|
| SHA-256 | `12fc49e9953f19fe26d2931e26ef0ed8f526f656c05f3feadb7bec38883eed98` |
| Family label | `SalatStealer` |
| File name | `35e96ca150b108a1.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47362517d9730146dafa1699f746e88d` |
| SHA-1 | `c4e4783ca02df241dcf291354cd7ce3a3ece688a` |
| SHA-256 | `12fc49e9953f19fe26d2931e26ef0ed8f526f656c05f3feadb7bec38883eed98` |
| SHA3-384 | `0c0dade622ff03915a72cfcc83915726bf3272520c5b8e3d13ef98f53159739d21b1a2de568f007d79518fb0c28a1575` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D4C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+N:yBkKr5rszpNDy+N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_028_12fc49e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12fc49e9953f19fe26d2931e26ef0ed8f526f656c05f3feadb7bec38883eed98"
    family = "SalatStealer"
    file_name = "35e96ca150b108a1.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:46"
  condition:
    hash.sha256(0, filesize) == "12fc49e9953f19fe26d2931e26ef0ed8f526f656c05f3feadb7bec38883eed98"
}
```

### Sample 29: `ad27629e028c8e53`

| Field | Value |
|---|---|
| SHA-256 | `ad27629e028c8e531fd2fc9659ef67ba0b623518b2902aee544b46dee9f89134` |
| Family label | `SalatStealer` |
| File name | `ad27629e028c8e53.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbdc2756e3285e533a6e4f8e84fce3e1` |
| SHA-1 | `75c6127d3ec639d0bd53e1465867c77fcfcb72be` |
| SHA-256 | `ad27629e028c8e531fd2fc9659ef67ba0b623518b2902aee544b46dee9f89134` |
| SHA3-384 | `d2cd28b038b13a692e6d3529d3ef842947796d59f53b456b59cb40b12e24a180bf92e52c1ed99d734b85b33c557cd436` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T11AF5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ou:iJiafuIO7rhWEES4B` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_029_ad27629e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad27629e028c8e531fd2fc9659ef67ba0b623518b2902aee544b46dee9f89134"
    family = "SalatStealer"
    file_name = "ad27629e028c8e53.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:45"
  condition:
    hash.sha256(0, filesize) == "ad27629e028c8e531fd2fc9659ef67ba0b623518b2902aee544b46dee9f89134"
}
```

### Sample 30: `105cd340fb5e1612`

| Field | Value |
|---|---|
| SHA-256 | `105cd340fb5e161275dc21408d4bcfdb2106046819256f1df5a463471c793ba5` |
| Family label | `SalatStealer` |
| File name | `a3ed80d1b8c2846e.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:39` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87cea1eddba9ede478ef434a584b1a94` |
| SHA-1 | `f9f482cfd34c2cdc5afc08f6d4c8d94cb605ddfe` |
| SHA-256 | `105cd340fb5e161275dc21408d4bcfdb2106046819256f1df5a463471c793ba5` |
| SHA3-384 | `48e62947dc9adfb5f3a6f6398168126120ccbf449d5138bfbb8b4df6248e84aa3199bc52b93a9d2d4e0600a54f0b374b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C3C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+j:yBkKr5rszpNDy+j` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_030_105cd340
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "105cd340fb5e161275dc21408d4bcfdb2106046819256f1df5a463471c793ba5"
    family = "SalatStealer"
    file_name = "a3ed80d1b8c2846e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:39"
  condition:
    hash.sha256(0, filesize) == "105cd340fb5e161275dc21408d4bcfdb2106046819256f1df5a463471c793ba5"
}
```

### Sample 31: `facec362d36d153b`

| Field | Value |
|---|---|
| SHA-256 | `facec362d36d153beb30f98abdb1e90c0f8cc79f2ba6489c6a6529934b148487` |
| Family label | `SalatStealer` |
| File name | `facec362d36d153b.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a16e5d2d69d99a3841701e495b26842` |
| SHA-1 | `acab80df8846c9f6c5b65604fb7687d773a87dda` |
| SHA-256 | `facec362d36d153beb30f98abdb1e90c0f8cc79f2ba6489c6a6529934b148487` |
| SHA3-384 | `6635ab57ee49c78682933ea57ced25dacf895859e62e7eb0ce21254a707fd0267bf9b034d15027bdfb3c3d5e3d90a445` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T199F5335BF5AB47B3F7D9A831560FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O/:iJiafuIO7rhWEES4m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_031_facec362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "facec362d36d153beb30f98abdb1e90c0f8cc79f2ba6489c6a6529934b148487"
    family = "SalatStealer"
    file_name = "facec362d36d153b.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:35"
  condition:
    hash.sha256(0, filesize) == "facec362d36d153beb30f98abdb1e90c0f8cc79f2ba6489c6a6529934b148487"
}
```

### Sample 32: `99e0b6dea820607e`

| Field | Value |
|---|---|
| SHA-256 | `99e0b6dea820607e7d32569ac24fe594091f48aef8889c8078ced0a505ee45a8` |
| Family label | `SalatStealer` |
| File name | `99e0b6dea820607e.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e5779c91c38dbb85ccec3641a8d1f8b` |
| SHA-1 | `c774ac1535befa3f1c46cb7cbb97ea54368aa9f0` |
| SHA-256 | `99e0b6dea820607e7d32569ac24fe594091f48aef8889c8078ced0a505ee45a8` |
| SHA3-384 | `29b4bf5b6adccb06fb195a72b9bd9e1c979f2f71aec5d8fb24262c2ad8955986635159274307303ad1a08b3b4276a417` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T19EF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O4:iJiafuIO7rhWEES4V` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_032_99e0b6de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99e0b6dea820607e7d32569ac24fe594091f48aef8889c8078ced0a505ee45a8"
    family = "SalatStealer"
    file_name = "99e0b6dea820607e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:26"
  condition:
    hash.sha256(0, filesize) == "99e0b6dea820607e7d32569ac24fe594091f48aef8889c8078ced0a505ee45a8"
}
```

### Sample 33: `cc111f672b2fce00`

| Field | Value |
|---|---|
| SHA-256 | `cc111f672b2fce001a3974a4d7f0fe77274ae23604a1302fd335afe6457daf50` |
| Family label | `SalatStealer` |
| File name | `cc111f672b2fce00.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:16` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93dd2ba96caefee2f581bdbe603248cd` |
| SHA-1 | `567adfa8a5f4d02206127e2346ee5595e19c707b` |
| SHA-256 | `cc111f672b2fce001a3974a4d7f0fe77274ae23604a1302fd335afe6457daf50` |
| SHA3-384 | `b33e973e0549da7795ec4060976df870c451eaa2ed531daaf8768c036f26411a163d20ab96e8220ab4fe6d6e6c8f052a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14EF5335BF1AB47B3F7D9A931560FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OA:iJiafuIO7rhWEES4D` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_033_cc111f67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc111f672b2fce001a3974a4d7f0fe77274ae23604a1302fd335afe6457daf50"
    family = "SalatStealer"
    file_name = "cc111f672b2fce00.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:16"
  condition:
    hash.sha256(0, filesize) == "cc111f672b2fce001a3974a4d7f0fe77274ae23604a1302fd335afe6457daf50"
}
```

### Sample 34: `f9bc72da6f6d1ac8`

| Field | Value |
|---|---|
| SHA-256 | `f9bc72da6f6d1ac841895da772b2dda58ba2ade288382a89adea90f1cbc9b5be` |
| Family label | `SalatStealer` |
| File name | `f9bc72da6f6d1ac8.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:25:07` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c5ef6895fbf67f068db6451b71b8ee3` |
| SHA-1 | `34fc72e652c8b89f27449d9be13622b15fca94e6` |
| SHA-256 | `f9bc72da6f6d1ac841895da772b2dda58ba2ade288382a89adea90f1cbc9b5be` |
| SHA3-384 | `a165445fd472a86ac1a2d31fcee9c38cec4eea13394776b0f946ae6d5a728c49bb2403136491e4938d2997c2e2382130` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T136F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oj:iJiafuIO7rhWEES4Q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_034_f9bc72da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9bc72da6f6d1ac841895da772b2dda58ba2ade288382a89adea90f1cbc9b5be"
    family = "SalatStealer"
    file_name = "f9bc72da6f6d1ac8.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:07"
  condition:
    hash.sha256(0, filesize) == "f9bc72da6f6d1ac841895da772b2dda58ba2ade288382a89adea90f1cbc9b5be"
}
```

### Sample 35: `289624b2a0a08726`

| Field | Value |
|---|---|
| SHA-256 | `289624b2a0a0872632ee8e37ad2a05db6bf910f95c1e9b2cff193857538828d7` |
| Family label | `SalatStealer` |
| File name | `289624b2a0a08726.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:24:57` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `770101ee683dfa9aff9d1f29b37a243e` |
| SHA-1 | `e0c36d3825dd4af1ac84e11e601a882763bf2388` |
| SHA-256 | `289624b2a0a0872632ee8e37ad2a05db6bf910f95c1e9b2cff193857538828d7` |
| SHA3-384 | `42554759ae85dfc0dad6d2448d78df51e082bcc05e6b598ca144c5912bebba5d55541110b6c82bc86378401a55720411` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T123F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OS:iJiafuIO7rhWEES4x` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_035_289624b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "289624b2a0a0872632ee8e37ad2a05db6bf910f95c1e9b2cff193857538828d7"
    family = "SalatStealer"
    file_name = "289624b2a0a08726.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:24:57"
  condition:
    hash.sha256(0, filesize) == "289624b2a0a0872632ee8e37ad2a05db6bf910f95c1e9b2cff193857538828d7"
}
```

### Sample 36: `35e96ca150b108a1`

| Field | Value |
|---|---|
| SHA-256 | `35e96ca150b108a1976d181aaff6819edcc20b509cbe45940f175622a4937794` |
| Family label | `SalatStealer` |
| File name | `35e96ca150b108a1.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:24:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d9d74de805565237d72b3a19feb8a68` |
| SHA-1 | `aeeeea85a13777982827ebecce8894e6edbb2adc` |
| SHA-256 | `35e96ca150b108a1976d181aaff6819edcc20b509cbe45940f175622a4937794` |
| SHA3-384 | `e5006925531d222332f5dc588fa9ec6253b9c8868d31a15d78da66dbf85d4fc3d9949f453a6485920f6e3ecacf50416f` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T114F5335BF1AB47B3F7D9A831560FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oh:iJiafuIO7rhWEES4m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_036_35e96ca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e96ca150b108a1976d181aaff6819edcc20b509cbe45940f175622a4937794"
    family = "SalatStealer"
    file_name = "35e96ca150b108a1.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:24:48"
  condition:
    hash.sha256(0, filesize) == "35e96ca150b108a1976d181aaff6819edcc20b509cbe45940f175622a4937794"
}
```

### Sample 37: `a3ed80d1b8c2846e`

| Field | Value |
|---|---|
| SHA-256 | `a3ed80d1b8c2846ed66d1ea2937b30b403dd4331fe2b9f46517f48e675838f51` |
| Family label | `SalatStealer` |
| File name | `a3ed80d1b8c2846e.bin` |
| File type | `exe` |
| First seen | `2026-10-28 04:24:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34b23de7636bba38663119ce5ca91a03` |
| SHA-1 | `fb2b8fd0be94baa28c3acb0eae3b30e02d055d7c` |
| SHA-256 | `a3ed80d1b8c2846ed66d1ea2937b30b403dd4331fe2b9f46517f48e675838f51` |
| SHA3-384 | `ff35fc71f2369b65b05dd2cb491f186afe71e277f07d5a1790114f980d21830c64eeb54b73a928dcc7167e67d7019b1c` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T11CF5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4On:iJiafuIO7rhWEES4M` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_037_a3ed80d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3ed80d1b8c2846ed66d1ea2937b30b403dd4331fe2b9f46517f48e675838f51"
    family = "SalatStealer"
    file_name = "a3ed80d1b8c2846e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:24:39"
  condition:
    hash.sha256(0, filesize) == "a3ed80d1b8c2846ed66d1ea2937b30b403dd4331fe2b9f46517f48e675838f51"
}
```

### Sample 38: `acd2e7872edb9612`

| Field | Value |
|---|---|
| SHA-256 | `acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc` |
| Family label | `unknown` |
| File name | `macho_acd2e7872edb.bin` |
| File type | `macho` |
| First seen | `2026-10-28 04:24:29` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d84433937a8d84b60be672403c520136` |
| SHA-1 | `4b58dfb36af8d18609c36eb6ed402ef7a52c025c` |
| SHA-256 | `acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc` |
| SHA3-384 | `78648d7925f75420717fd7929382f7a2188863d0235a10fc01fc7f142659db63ec6badf269f353e68c8fa47a360e2218` |
| TLSH | `T1B685F2508A5F62AAD48F3833CC151F1955A856920A54AFFE7370CF76AD32643FA23372` |
| SSDEEP | `24576:a4eh2DonjPMecYqF+AUAIKCz2aHyjdsbiTqOYq0I9hg+F036gMysuB+Yzy/ByV:aY8jzcjnHNaS5TrYq0ihPF0qfDYGM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_acd2e787
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc"
    family = "unknown"
    file_name = "macho_acd2e7872edb.bin"
    file_type = "macho"
    first_seen = "2026-10-28 04:24:29"
  condition:
    hash.sha256(0, filesize) == "acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc"
}
```

### Sample 39: `46b5e5360b677c41`

| Field | Value |
|---|---|
| SHA-256 | `46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907` |
| Family label | `ConnectWise` |
| File name | `46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907.msi` |
| File type | `msi` |
| First seen | `2026-10-28 04:24:03` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdde68033423a9cff6470c1e3b1d6794` |
| SHA-1 | `0b74f08484ba8cba28aacdda2f88dd727ae9f6a2` |
| SHA-256 | `46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907` |
| SHA3-384 | `d281d0fd1da39aefbb8878367acd4cda042ca2cb6840a83e00352b2bf9f62ade2d6382d74a1302cc07f93c0d20548242` |
| TLSH | `T1EAD623116BF8D368E0B22AF5E8776C61A5377F115D22D12E2224791F2C71A8089E377F` |
| SSDEEP | `196608:MHxcp9ym3nltDUJVeHxcp9ym37Hxcp9ym3/Hxcp9ym3mHxcp9ym3uHxcp9ym38Hn:qGplp9GpFGpJGp0Gp8GpaGpA` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_039_46b5e536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907"
    family = "ConnectWise"
    file_name = "46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907.msi"
    file_type = "msi"
    first_seen = "2026-10-28 04:24:03"
  condition:
    hash.sha256(0, filesize) == "46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907"
}
```

### Sample 40: `67df067cd21dface`

| Field | Value |
|---|---|
| SHA-256 | `67df067cd21dface1cc93f53b7bb20e7efe5d4aed7fd33960ce105a6b3f448f5` |
| Family label | `unknown` |
| File name | `67df067cd21dface_decoded-stage.zsh` |
| File type | `zsh` |
| First seen | `2026-10-28 04:10:16` |
| Reporter | `Dense` |
| Tags | `zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `502fe8b129ec1c7a7288d664c91f49a2` |
| SHA-1 | `028bb4fa2c9e2b7a15ed16a960f9f5166d3ecb53` |
| SHA-256 | `67df067cd21dface1cc93f53b7bb20e7efe5d4aed7fd33960ce105a6b3f448f5` |
| SHA3-384 | `3d1b413d6dd3983cd4f301c6fe63c10bf232a5ce8e6d7733f479a05fe152d18a39d6944181f265b5887e8f7ee703a62c` |
| TLSH | `T1C931A7B04C1001B594DB1DC8EF2B84AAB1B524D99F8BE3DF0FB11AF8246E541C58F976` |
| SSDEEP | `48:QBv2V1K14p04e8IMrUVK14SdXCtcCQzouQf3GkAeI5P:QBv+1K14i4LrUVK14Sxcc1zou4GkiP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zsh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_67df067c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67df067cd21dface1cc93f53b7bb20e7efe5d4aed7fd33960ce105a6b3f448f5"
    family = "unknown"
    file_name = "67df067cd21dface_decoded-stage.zsh"
    file_type = "zsh"
    first_seen = "2026-10-28 04:10:16"
  condition:
    hash.sha256(0, filesize) == "67df067cd21dface1cc93f53b7bb20e7efe5d4aed7fd33960ce105a6b3f448f5"
}
```

### Sample 41: `a91f36a69921e514`

| Field | Value |
|---|---|
| SHA-256 | `a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453` |
| Family label | `unknown` |
| File name | `a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453` |
| File type | `elf` |
| First seen | `2026-10-28 04:00:18` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b311b9aec17c2a60059e7cba8866fd1` |
| SHA-1 | `8b1eaee4af6976a5aa90050de025150d77c9af46` |
| SHA-256 | `a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453` |
| SHA3-384 | `5b1823e450056b20a5504a601c2b396f63bf3e882ee398279fc7e3d46484c7ddd1d7bd322a8a504571d2d4e561bb3bdc` |
| TLSH | `T134653C07B6A744BEC0F5C430874BC5B3AD35B8546225397F3695AB202E77E204B6EFA1` |
| SSDEEP | `24576:1ro/0ANxszDzekOKYpPid8xv0o6BVglub1pzTW+uIX2jiR:1rs0iO7eS6Co6BGlEvp3R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_a91f36a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453"
    family = "unknown"
    file_name = "a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453"
    file_type = "elf"
    first_seen = "2026-10-28 04:00:18"
  condition:
    hash.sha256(0, filesize) == "a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453"
}
```

### Sample 42: `a4ab01b4d1fc8733`

| Field | Value |
|---|---|
| SHA-256 | `a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847` |
| Family label | `unknown` |
| File name | `a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847` |
| File type | `elf` |
| First seen | `2026-10-28 04:00:09` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3dd50a48d5374a751ff55fff58e70127` |
| SHA-1 | `dd7e72be2645dec97fdc4cd814dc1d846ca14194` |
| SHA-256 | `a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847` |
| SHA3-384 | `1302c5e777db19c59ceff603d1ac9d723c3243e348942a0fcb1d64e4bd2804cf6469b255c1607d689c9a9e88312c0e9d` |
| TLSH | `T1A122712BEA83C6A9C0C853F818C745B037B19490D731635B935DEC391D63B884B2EE9B` |
| TELFHASH | `t196b012c0df0f050412921c30dc5d8798a013450bf8b817001979cad1165470b070452c` |
| SSDEEP | `96:RD0BWBShzf7ce5wXS/i9/iaH/ba7OkSl3qwi8GHEZAqoiKTgQlmKuE3:RD08chzfHkS6Vs5rHEubiqg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_a4ab01b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847"
    family = "unknown"
    file_name = "a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847"
    file_type = "elf"
    first_seen = "2026-10-28 04:00:09"
  condition:
    hash.sha256(0, filesize) == "a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847"
}
```

### Sample 43: `b9801e021eb76af7`

| Field | Value |
|---|---|
| SHA-256 | `b9801e021eb76af73f22da5f78130998d08376a111dde32b4f121216efde255c` |
| Family label | `unknown` |
| File name | `z1nfe_fxo_servicos_de_informatica_ltda.vbs` |
| File type | `vbs` |
| First seen | `2026-10-28 04:00:06` |
| Reporter | `fabiodemartin` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97604cb874db26bd32351643c714c3de` |
| SHA-1 | `32f9e4d244290c8d52db3202a7bbadfeedb3291c` |
| SHA-256 | `b9801e021eb76af73f22da5f78130998d08376a111dde32b4f121216efde255c` |
| SHA3-384 | `da94c0e1637db3c58cf9fe505cc7274d451070242ec9bb1573cb5e93ddfb25ec13928521ffac7aba1d7534761d59020a` |
| TLSH | `T16823C43C0D1602FB46FED719E5DC1A0BFA61F857B5A9AD08D0C30786A29320BF5C966D` |
| SSDEEP | `768:n8QvwdeOLTiEersluoiw1+JIh4Dng9v/mfhkGVbemwZty+srkKhv1/ozY1:nCTgL9i6g9v/2CBmwWykvtozY1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_b9801e02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9801e021eb76af73f22da5f78130998d08376a111dde32b4f121216efde255c"
    family = "unknown"
    file_name = "z1nfe_fxo_servicos_de_informatica_ltda.vbs"
    file_type = "vbs"
    first_seen = "2026-10-28 04:00:06"
  condition:
    hash.sha256(0, filesize) == "b9801e021eb76af73f22da5f78130998d08376a111dde32b4f121216efde255c"
}
```

### Sample 44: `ff33bc871d0f05d3`

| Field | Value |
|---|---|
| SHA-256 | `ff33bc871d0f05d3049b84dee6edd44a9d761395a0617d09d6216adcb6b0bbc8` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-28 03:47:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d05db587b2c77c320a2fd0261a0590f` |
| SHA-1 | `ae848e121a31b3c571fdd8d05dfe8d5cb93b6cc2` |
| SHA-256 | `ff33bc871d0f05d3049b84dee6edd44a9d761395a0617d09d6216adcb6b0bbc8` |
| SHA3-384 | `a17e1ab1d783147be6f06cef6c2fc37ebc6954a7c15d5197676a0ba3aac6583ee5517c35346706a1af282a4fb312e549` |
| TLSH | `T1DF556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSV:SDjxB4m5n8XlaPWi+d+a4TjxQP4X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_ff33bc87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff33bc871d0f05d3049b84dee6edd44a9d761395a0617d09d6216adcb6b0bbc8"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-28 03:47:01"
  condition:
    hash.sha256(0, filesize) == "ff33bc871d0f05d3049b84dee6edd44a9d761395a0617d09d6216adcb6b0bbc8"
}
```

### Sample 45: `e98a383f2ac8c34b`

| Field | Value |
|---|---|
| SHA-256 | `e98a383f2ac8c34b44c2fdf33790b3fec6123320c5dd38004cd29ca657d8e4bd` |
| Family label | `SalatStealer` |
| File name | `2610a90206fc62d1.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:27:54` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6ef63dd0e6c18c8533649aefe84d999` |
| SHA-1 | `a71224508c275ed2cd04f921bcbe9ecb7b0f208a` |
| SHA-256 | `e98a383f2ac8c34b44c2fdf33790b3fec6123320c5dd38004cd29ca657d8e4bd` |
| SHA3-384 | `f1bddcffd6c5414d51da7f369efb40130fa31104a334f18023c975918d9f50e5e72e93c35183da011a74ce607836a1d6` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E2C65C11FACB54F6F9036831416BB37F23315D048B28DB9BEB583B6AF877691186A305` |
| SSDEEP | `49152:KpXZKft05HtyvruRo9JBDRHCTdU391KX1NbNV4L6d+NTPeGFPbQuhHEPCw8sWAyB:CZ0tkRorxxCO3ukFJFzAKoU4aeEl` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_045_e98a383f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e98a383f2ac8c34b44c2fdf33790b3fec6123320c5dd38004cd29ca657d8e4bd"
    family = "SalatStealer"
    file_name = "2610a90206fc62d1.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:27:54"
  condition:
    hash.sha256(0, filesize) == "e98a383f2ac8c34b44c2fdf33790b3fec6123320c5dd38004cd29ca657d8e4bd"
}
```

### Sample 46: `5102c6aea1d4f788`

| Field | Value |
|---|---|
| SHA-256 | `5102c6aea1d4f788bce14dd58632d813e5edb19dd06f627d52a8637e7209114e` |
| Family label | `SalatStealer` |
| File name | `acb38f8ad036f246.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:27:48` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58e058e5952cc7b1eef6ef15c6825394` |
| SHA-1 | `9375b41f73e95962d29ea308d500045e6c072e6b` |
| SHA-256 | `5102c6aea1d4f788bce14dd58632d813e5edb19dd06f627d52a8637e7209114e` |
| SHA3-384 | `57056b917a85742abdaa6613b378c840b22c16229fdc140397bf2bd151af200774669c8b0b733e57a348f15364879994` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T16CC65C11FACB54F6F9036831416BB37F23315D048B28DB9BEB583B6AF877691186A305` |
| SSDEEP | `49152:ipXZKft05HtyvruRo9JBDRHCTdU391KX1NbNV4L6d+NTPeGFPbQuhHEPAw8sWA7B:6Z0tkRorxxCO3ukFJFzAoxU4aeEl` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_046_5102c6ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5102c6aea1d4f788bce14dd58632d813e5edb19dd06f627d52a8637e7209114e"
    family = "SalatStealer"
    file_name = "acb38f8ad036f246.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:27:48"
  condition:
    hash.sha256(0, filesize) == "5102c6aea1d4f788bce14dd58632d813e5edb19dd06f627d52a8637e7209114e"
}
```

### Sample 47: `8211cd8cc3b4ec95`

| Field | Value |
|---|---|
| SHA-256 | `8211cd8cc3b4ec950d4b85330b0e3cbe9566c7098cf4a8e36faf127924720831` |
| Family label | `SalatStealer` |
| File name | `877aa9afadd04a38.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:27:26` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3368d3569adc2fad864d446ac51079d2` |
| SHA-1 | `d5082fd4f682310fa96bf9e19d803b12f36c37eb` |
| SHA-256 | `8211cd8cc3b4ec950d4b85330b0e3cbe9566c7098cf4a8e36faf127924720831` |
| SHA3-384 | `65282f8d4530dbc497df1d9adf83391e9542ec29353239cfc8f2394b7457eeb7e7acd099613a1cb4a735a19ad3964b24` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T10AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+5:yBkKr5rszpNDy+5` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_047_8211cd8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8211cd8cc3b4ec950d4b85330b0e3cbe9566c7098cf4a8e36faf127924720831"
    family = "SalatStealer"
    file_name = "877aa9afadd04a38.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:27:26"
  condition:
    hash.sha256(0, filesize) == "8211cd8cc3b4ec950d4b85330b0e3cbe9566c7098cf4a8e36faf127924720831"
}
```

### Sample 48: `0f8704e6b74bf56c`

| Field | Value |
|---|---|
| SHA-256 | `0f8704e6b74bf56c42f2a011f609d4ecb296869dff9da7eedaa0d3ef832989f7` |
| Family label | `SalatStealer` |
| File name | `4d875a161b1955be.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8bfe165db0c042fa516ee883928b98d` |
| SHA-1 | `92d37720a9e91b8fe5415506a710ba5fd462ce3d` |
| SHA-256 | `0f8704e6b74bf56c42f2a011f609d4ecb296869dff9da7eedaa0d3ef832989f7` |
| SHA3-384 | `2c2805d6097adf6b434d464cca73e6243ce39fc56dbcde699e33f6f948c79a23a86208dc71182cf4e6fe3e49d4293371` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C0C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+s:yBkKr5rszpNDy+s` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_048_0f8704e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f8704e6b74bf56c42f2a011f609d4ecb296869dff9da7eedaa0d3ef832989f7"
    family = "SalatStealer"
    file_name = "4d875a161b1955be.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:59"
  condition:
    hash.sha256(0, filesize) == "0f8704e6b74bf56c42f2a011f609d4ecb296869dff9da7eedaa0d3ef832989f7"
}
```

### Sample 49: `e92dbab84f249982`

| Field | Value |
|---|---|
| SHA-256 | `e92dbab84f2499820739a972236fc9fffccb9be6fb104baced5d44073e72fa80` |
| Family label | `SalatStealer` |
| File name | `14cf458f75226509.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:50` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `769c81851d102654e2cd0b0b601eb8d5` |
| SHA-1 | `03197e75e23f01e81c0aa09a4e5fdd5527ef84eb` |
| SHA-256 | `e92dbab84f2499820739a972236fc9fffccb9be6fb104baced5d44073e72fa80` |
| SHA3-384 | `453121f14fd65484c28fe6abfdb3b8231e895c6b4db50fd663580f3ea649a6f49916f3daae242036a07521e013cac4dd` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T145C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+P:yBkKr5rszpNDy+P` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_049_e92dbab8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e92dbab84f2499820739a972236fc9fffccb9be6fb104baced5d44073e72fa80"
    family = "SalatStealer"
    file_name = "14cf458f75226509.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:50"
  condition:
    hash.sha256(0, filesize) == "e92dbab84f2499820739a972236fc9fffccb9be6fb104baced5d44073e72fa80"
}
```

### Sample 50: `7194f0ca6291b432`

| Field | Value |
|---|---|
| SHA-256 | `7194f0ca6291b43289f9be23323efaf30ebf303d26f0d141c2fdc10b78e446d9` |
| Family label | `SalatStealer` |
| File name | `3c894e6611902696.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:44` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16a20e9aa30aaea16144550b871b5d20` |
| SHA-1 | `a4172256939b84959545ba6906a500eda0b7e57b` |
| SHA-256 | `7194f0ca6291b43289f9be23323efaf30ebf303d26f0d141c2fdc10b78e446d9` |
| SHA3-384 | `c69623366cbe46f9d7668fcc7e58f25b98ffc5d42b160c979236354a5c376e4aa9d19ab92cff36e79adb7b44594ad94c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T10BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+X:yBkKr5rszpNDy+X` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_050_7194f0ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7194f0ca6291b43289f9be23323efaf30ebf303d26f0d141c2fdc10b78e446d9"
    family = "SalatStealer"
    file_name = "3c894e6611902696.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:44"
  condition:
    hash.sha256(0, filesize) == "7194f0ca6291b43289f9be23323efaf30ebf303d26f0d141c2fdc10b78e446d9"
}
```

### Sample 51: `c4fc3e23a6bd979c`

| Field | Value |
|---|---|
| SHA-256 | `c4fc3e23a6bd979cbaa5e275e4af667b35b84c304bb0e89375b467959379f0c3` |
| Family label | `SalatStealer` |
| File name | `f22b60b7ca8a8f52.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f3e6cc4a01629304e091d31d07754f7` |
| SHA-1 | `a69951f1f7b83dfba562cf141ef8825028370777` |
| SHA-256 | `c4fc3e23a6bd979cbaa5e275e4af667b35b84c304bb0e89375b467959379f0c3` |
| SHA3-384 | `9199d4d4dcd8390bc514337bd5a173ef6e2b9f9f62175a88c81c657945d7e746384ad23a4a57ec48a5b3599304a84e26` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T170C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+2:yBkKr5rszpNDy+2` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_051_c4fc3e23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4fc3e23a6bd979cbaa5e275e4af667b35b84c304bb0e89375b467959379f0c3"
    family = "SalatStealer"
    file_name = "f22b60b7ca8a8f52.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:35"
  condition:
    hash.sha256(0, filesize) == "c4fc3e23a6bd979cbaa5e275e4af667b35b84c304bb0e89375b467959379f0c3"
}
```

### Sample 52: `2610a90206fc62d1`

| Field | Value |
|---|---|
| SHA-256 | `2610a90206fc62d150006f26f527b36e06b634805f33bd6b7e0dd4c0864c3c16` |
| Family label | `SalatStealer` |
| File name | `2610a90206fc62d1.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7730d5beb066ec059d8365a2810bdfac` |
| SHA-1 | `a04a4c32fa1656367719e1748c44a4bbe1dfd08c` |
| SHA-256 | `2610a90206fc62d150006f26f527b36e06b634805f33bd6b7e0dd4c0864c3c16` |
| SHA3-384 | `b4720b83ddb48684d79858823726441626d26e4dc77e70dfd26b5d7c438c5b283d5c0bb106ed92e6038b0c60b4bfd7a9` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C2F533C8E5992C73E6A9077DB060984E45A7D14E06FFA16D4FBE11830E88DD53E83C6B` |
| SSDEEP | `98304:VtfoFd2HhhpX4N6m7nMJAltp72SXtQHMuZydvWAj2S:Vdo2Hhhc6vAJ2mtQHMuodv/jZ` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_052_2610a902
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2610a90206fc62d150006f26f527b36e06b634805f33bd6b7e0dd4c0864c3c16"
    family = "SalatStealer"
    file_name = "2610a90206fc62d1.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:32"
  condition:
    hash.sha256(0, filesize) == "2610a90206fc62d150006f26f527b36e06b634805f33bd6b7e0dd4c0864c3c16"
}
```

### Sample 53: `c661bc6971ae777b`

| Field | Value |
|---|---|
| SHA-256 | `c661bc6971ae777bfcbdf418c9355bc9a823e1a79bcd58a11f014fd3da7993ec` |
| Family label | `SalatStealer` |
| File name | `2fe07b45c805f46f.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca743c3b827e61b0ca6b936732f77e11` |
| SHA-1 | `4704d40333be0f439eeb90efa5c7c85405dc44f2` |
| SHA-256 | `c661bc6971ae777bfcbdf418c9355bc9a823e1a79bcd58a11f014fd3da7993ec` |
| SHA3-384 | `11b6c128ec7ad672c64934790732e260196728bec1bf55aa39ae290cca65d421b207a93985e1a2ef16574c1d6ea36360` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T15EC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_053_c661bc69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c661bc6971ae777bfcbdf418c9355bc9a823e1a79bcd58a11f014fd3da7993ec"
    family = "SalatStealer"
    file_name = "2fe07b45c805f46f.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:29"
  condition:
    hash.sha256(0, filesize) == "c661bc6971ae777bfcbdf418c9355bc9a823e1a79bcd58a11f014fd3da7993ec"
}
```

### Sample 54: `acb38f8ad036f246`

| Field | Value |
|---|---|
| SHA-256 | `acb38f8ad036f246caa281820acc989728cdcf12a86598f3eb815fc188b50d3e` |
| Family label | `SalatStealer` |
| File name | `acb38f8ad036f246.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:23` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16b4a4dfff7d5aaa779a1974544f9c89` |
| SHA-1 | `e269d16b4c3e7bde597a6d47ba9904151db7e4da` |
| SHA-256 | `acb38f8ad036f246caa281820acc989728cdcf12a86598f3eb815fc188b50d3e` |
| SHA3-384 | `31e8bb417a3639f762d41db589009a0dc506e548a35db18d6a01638928239491ffa4b351ff891e462d9617f3a80089a1` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T115F53390E5723C37F150A475FCAA59B838CDE36DAF0BF1C46A061B38CA7EA6C94154B1` |
| SSDEEP | `98304:nyGV2gjps92zWoAtLpBxXJ+tdNKFNkvE:nyq2BJZpLoHNKFOvE` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_054_acb38f8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acb38f8ad036f246caa281820acc989728cdcf12a86598f3eb815fc188b50d3e"
    family = "SalatStealer"
    file_name = "acb38f8ad036f246.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:23"
  condition:
    hash.sha256(0, filesize) == "acb38f8ad036f246caa281820acc989728cdcf12a86598f3eb815fc188b50d3e"
}
```

### Sample 55: `877aa9afadd04a38`

| Field | Value |
|---|---|
| SHA-256 | `877aa9afadd04a380d2b00bdeb1c40d0163939f2648d6119eb02048a043dd7ed` |
| Family label | `SalatStealer` |
| File name | `877aa9afadd04a38.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba3dae490a913378e459b7f249074f9f` |
| SHA-1 | `aa9e0b1ed168bb9d9102e38cf1bc7f749e500179` |
| SHA-256 | `877aa9afadd04a380d2b00bdeb1c40d0163939f2648d6119eb02048a043dd7ed` |
| SHA3-384 | `af5f724293e0420fd57d9c06c9e0452b637813292fc5b46a041c04a4706744ec610e9093d084746bda89c9dfea65aa32` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T11AF5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Od:iJiafuIO7rhWEES4Y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_055_877aa9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "877aa9afadd04a380d2b00bdeb1c40d0163939f2648d6119eb02048a043dd7ed"
    family = "SalatStealer"
    file_name = "877aa9afadd04a38.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:13"
  condition:
    hash.sha256(0, filesize) == "877aa9afadd04a380d2b00bdeb1c40d0163939f2648d6119eb02048a043dd7ed"
}
```

### Sample 56: `4d875a161b1955be`

| Field | Value |
|---|---|
| SHA-256 | `4d875a161b1955be1c69eb28a440de92f30edd4f30fe0fc3dabf49d858279056` |
| Family label | `SalatStealer` |
| File name | `4d875a161b1955be.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:26:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `621a881b711163982e7deb4a2bb28737` |
| SHA-1 | `7878d4e2d19a37bdac39d622251263fc71eae6e2` |
| SHA-256 | `4d875a161b1955be1c69eb28a440de92f30edd4f30fe0fc3dabf49d858279056` |
| SHA3-384 | `35658a98ce6e3378dd837563c735c7704a244ea3135ff2d1861e4ce954944fba4ce413ac9133d20dc6b66abf87a26219` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12BF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O4:iJiafuIO7rhWEES4F` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_056_4d875a16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d875a161b1955be1c69eb28a440de92f30edd4f30fe0fc3dabf49d858279056"
    family = "SalatStealer"
    file_name = "4d875a161b1955be.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:04"
  condition:
    hash.sha256(0, filesize) == "4d875a161b1955be1c69eb28a440de92f30edd4f30fe0fc3dabf49d858279056"
}
```

### Sample 57: `14cf458f75226509`

| Field | Value |
|---|---|
| SHA-256 | `14cf458f7522650981b6d7e9d0c81a90ca776dd99e7b75da08ee869da646294b` |
| Family label | `SalatStealer` |
| File name | `14cf458f75226509.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:25:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a5682d5a7eb6c3f4583e57915bab4d3` |
| SHA-1 | `7d5954eb89ab26f7a74389f8967701c7c3f0ab3a` |
| SHA-256 | `14cf458f7522650981b6d7e9d0c81a90ca776dd99e7b75da08ee869da646294b` |
| SHA3-384 | `c835794602f80456b271eb35f6d238e57b1261e042efdd8cb8447d35ebb2c561cb8888dd26f96b6557a5bff62dba9bd1` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C1F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O7:iJiafuIO7rhWEES4Y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_057_14cf458f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14cf458f7522650981b6d7e9d0c81a90ca776dd99e7b75da08ee869da646294b"
    family = "SalatStealer"
    file_name = "14cf458f75226509.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:54"
  condition:
    hash.sha256(0, filesize) == "14cf458f7522650981b6d7e9d0c81a90ca776dd99e7b75da08ee869da646294b"
}
```

### Sample 58: `3c894e6611902696`

| Field | Value |
|---|---|
| SHA-256 | `3c894e661190269657300ba3fb0f736e0d81b8291fc5116a3f7aef561798fb00` |
| Family label | `SalatStealer` |
| File name | `3c894e6611902696.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:25:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ee63266be06a1d9f6bf5e18afcb43e9` |
| SHA-1 | `9303004593663c0e6ca1c9fdc9920c68a0bd4437` |
| SHA-256 | `3c894e661190269657300ba3fb0f736e0d81b8291fc5116a3f7aef561798fb00` |
| SHA3-384 | `600f05b7ffdb75caaac90426a3b7c9ec3eb5c00cd2f5c9b1e6300b0412c788a1daca2099ea3c3ab9f5a570c52d0352fd` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T16BF5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oj:iJiafuIO7rhWEES4y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_058_3c894e66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c894e661190269657300ba3fb0f736e0d81b8291fc5116a3f7aef561798fb00"
    family = "SalatStealer"
    file_name = "3c894e6611902696.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:45"
  condition:
    hash.sha256(0, filesize) == "3c894e661190269657300ba3fb0f736e0d81b8291fc5116a3f7aef561798fb00"
}
```

### Sample 59: `625eda1fbc4e313f`

| Field | Value |
|---|---|
| SHA-256 | `625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8` |
| Family label | `unknown` |
| File name | `625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8.exe` |
| File type | `exe` |
| First seen | `2026-10-28 03:25:38` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ee757569a09b756796897c50cada88f` |
| SHA-1 | `49f2cf5fec005fa948b415eae16c15f73ef2015f` |
| SHA-256 | `625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8` |
| SHA3-384 | `3db03ba4d7d494f05a1455f69a63469c61f06c9933cad1d13c82a90bde900ecd7e67ebc349c58f2e709d4ec327875818` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T163C46C1B37524E50C2851BB3C1AB940087A69687BAE7F30FB28513A71D073FEDD4A697` |
| SSDEEP | `6144:l48vd1mMCsMRo4eUUPgQ8Vu+vIDcRMZi9gmVjgJyXyQe9nPC6k1Kt7qg5WMha:1loNRo4lKsBMYGyXyD9nPC6ks` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_625eda1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8"
    family = "unknown"
    file_name = "625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8.exe"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:38"
  condition:
    hash.sha256(0, filesize) == "625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8"
}
```

### Sample 60: `f22b60b7ca8a8f52`

| Field | Value |
|---|---|
| SHA-256 | `f22b60b7ca8a8f5204630da7340ad6f1886479d759e116b0fada583e82fa9782` |
| Family label | `SalatStealer` |
| File name | `f22b60b7ca8a8f52.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:25:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b91e4f793fd6227fdffed97fc6b86cc` |
| SHA-1 | `5f977db7b486ebdc1e874b4c9ad05d920a7fee80` |
| SHA-256 | `f22b60b7ca8a8f5204630da7340ad6f1886479d759e116b0fada583e82fa9782` |
| SHA3-384 | `02e9a95974279b524c4a96cb50a4fcb48f7f27fc6f7954de5aa2c51824a193627149ee0d01d131715bc88e960e6ce337` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1FFF5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oy:iJiafuIO7rhWEES4J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_060_f22b60b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f22b60b7ca8a8f5204630da7340ad6f1886479d759e116b0fada583e82fa9782"
    family = "SalatStealer"
    file_name = "f22b60b7ca8a8f52.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:35"
  condition:
    hash.sha256(0, filesize) == "f22b60b7ca8a8f5204630da7340ad6f1886479d759e116b0fada583e82fa9782"
}
```

### Sample 61: `2fe07b45c805f46f`

| Field | Value |
|---|---|
| SHA-256 | `2fe07b45c805f46f45c6c5bcadb6812e6974968d9f8d3d5150c0bac7b34cc0c5` |
| Family label | `SalatStealer` |
| File name | `2fe07b45c805f46f.bin` |
| File type | `exe` |
| First seen | `2026-10-28 03:25:25` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dda4628003ce6fe17f1dbcd96eeb5bf1` |
| SHA-1 | `7fedaff874dbfe1cb05701dec80ec84363e13caa` |
| SHA-256 | `2fe07b45c805f46f45c6c5bcadb6812e6974968d9f8d3d5150c0bac7b34cc0c5` |
| SHA3-384 | `abbc5fb9bd669f19bfd67ecb59c2ce952d41352cc293dac9628c7f339310e06a1bd2b924eef6527e187e6f8a4ba5218b` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T162F5335BF1AB47B3F7D9A931560FC67458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Of:iJiafuIO7rhWEES4Y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_061_2fe07b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fe07b45c805f46f45c6c5bcadb6812e6974968d9f8d3d5150c0bac7b34cc0c5"
    family = "SalatStealer"
    file_name = "2fe07b45c805f46f.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:25"
  condition:
    hash.sha256(0, filesize) == "2fe07b45c805f46f45c6c5bcadb6812e6974968d9f8d3d5150c0bac7b34cc0c5"
}
```

### Sample 62: `529f2e3b53f4dce8`

| Field | Value |
|---|---|
| SHA-256 | `529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15` |
| Family label | `unknown` |
| File name | `529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15.elf` |
| File type | `elf` |
| First seen | `2026-10-28 03:18:17` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87c68f013478f9d80da14f6898930a4e` |
| SHA-1 | `2bef7b34f3d1b9e49f9a4f4be79e2b569fa55c47` |
| SHA-256 | `529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15` |
| SHA3-384 | `ab5a92c3019d3c7daeeefe320251455efef82ed68dd606a5055c18e9aea99d181c783e86a4379b14029c695bd9cc1c69` |
| TLSH | `T15914B70E6E228F7EF66CC77447B74E30976923D627E1D644E2ACC1145F2029E641FBA8` |
| TELFHASH | `t19d4186680d7813f4a2756c5d449dff66d6a331db7e162c238e10e85aab68f839d14c0c` |
| SSDEEP | `1536:F0MijSbBfKP1P6ub6u4tuuHpOl6j8tN1dvaUii38EUvNmJx4x9hOu9RWCAb+Jdcj:Fc+sldDh3cz9hhnWvKjqssieMXdImaa0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_529f2e3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15"
    family = "unknown"
    file_name = "529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15.elf"
    file_type = "elf"
    first_seen = "2026-10-28 03:18:17"
  condition:
    hash.sha256(0, filesize) == "529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15"
}
```

### Sample 63: `5eb8048165e5151b`

| Field | Value |
|---|---|
| SHA-256 | `5eb8048165e5151b53c770f0feb0a7a5b8c61b695f5ea0dad1f4a1dee7c43921` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-28 03:06:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c72926fa114faad769afdc5bcc6abebf` |
| SHA-1 | `13bec953b3576b61a9f51c47ae4625f9ef08e1ad` |
| SHA-256 | `5eb8048165e5151b53c770f0feb0a7a5b8c61b695f5ea0dad1f4a1dee7c43921` |
| SHA3-384 | `a69563ba7f110ff87e2206306d3054be5d915ffce07ab7aaef40f57bd4357123a3580177e8723ea85e7e1cbf4c386c7a` |
| TLSH | `T19A556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSH:SDjxB4m5n8XlaPWi+d+a4TjxQP4h` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_5eb80481
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5eb8048165e5151b53c770f0feb0a7a5b8c61b695f5ea0dad1f4a1dee7c43921"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-28 03:06:21"
  condition:
    hash.sha256(0, filesize) == "5eb8048165e5151b53c770f0feb0a7a5b8c61b695f5ea0dad1f4a1dee7c43921"
}
```

### Sample 64: `b6d267ca64c2c4db`

| Field | Value |
|---|---|
| SHA-256 | `b6d267ca64c2c4dbb53138794f7e0694a926a4a99e3ba38b71546a83adcfd9eb` |
| Family label | `unknown` |
| File name | `jklx86` |
| File type | `elf` |
| First seen | `2026-10-28 02:49:26` |
| Reporter | `YaRi78` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd33a765930fc35fc584d2cb96c57b22` |
| SHA-1 | `4a05a32c811e6ced27e49c6e5cd08e7796853c2e` |
| SHA-256 | `b6d267ca64c2c4dbb53138794f7e0694a926a4a99e3ba38b71546a83adcfd9eb` |
| SHA3-384 | `d5abfccc85ef73f74554c9fcf6b41b5fe1f43d91ea5b7b5cfd6ca7e948d13d5b09100c94a2b6081604a37b77ad5207ca` |
| TLSH | `T162836CC19283D4F9ED450239207AF337A771DEB90158FEF3F35496329826A62F14A64E` |
| TELFHASH | `t10231c3f612360cd8abc05911f21e2b717d4dab6b25203be204f31939261ee8352bbd7d` |
| SSDEEP | `1536:/5Sa8Bsmnkqz+jaHSrAFRrUveVSrE/4jN7gtRNdFwt3QRS:hzXmR+jsSrAFR8ri6NctXDwD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_b6d267ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6d267ca64c2c4dbb53138794f7e0694a926a4a99e3ba38b71546a83adcfd9eb"
    family = "unknown"
    file_name = "jklx86"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:26"
  condition:
    hash.sha256(0, filesize) == "b6d267ca64c2c4dbb53138794f7e0694a926a4a99e3ba38b71546a83adcfd9eb"
}
```

### Sample 65: `1b9b1623b3fb809a`

| Field | Value |
|---|---|
| SHA-256 | `1b9b1623b3fb809ad58da971475ddfb8c6421dfc6459450d313f5aa3aa5f47db` |
| Family label | `Mirai` |
| File name | `jklspc` |
| File type | `elf` |
| First seen | `2026-10-28 02:49:22` |
| Reporter | `YaRi78` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `345c77ae32a12258c877d3d726ab1e22` |
| SHA-1 | `ea4ff992d71c0bdf3be9cb8de0ad494edec2a6bb` |
| SHA-256 | `1b9b1623b3fb809ad58da971475ddfb8c6421dfc6459450d313f5aa3aa5f47db` |
| SHA3-384 | `37bbffa882c76ff8f4903db5dcadfb2e518cae7c4776839559e91074e3a58fa25ea66c060d9eda5b9fb972141f1f03e9` |
| TLSH | `T169A31A21FD35592BC9C0217B51E34530F5B643E91ABC8A5E3FA31D8DDF18660312FAAA` |
| SSDEEP | `1536:PvY8ZAFrPQzAh2OLj/WjN6Fu65/CR/9AWx4nhA58PYtzMLhOW:3YZbn2OGwFZoGnK8PWpW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_1b9b1623
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9b1623b3fb809ad58da971475ddfb8c6421dfc6459450d313f5aa3aa5f47db"
    family = "Mirai"
    file_name = "jklspc"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:22"
  condition:
    hash.sha256(0, filesize) == "1b9b1623b3fb809ad58da971475ddfb8c6421dfc6459450d313f5aa3aa5f47db"
}
```

### Sample 66: `478ef62c5a9c90b2`

| Field | Value |
|---|---|
| SHA-256 | `478ef62c5a9c90b25940d000215e3a61013d9aca52184dfdde067c5b1d0fd157` |
| Family label | `Mirai` |
| File name | `jklsh4` |
| File type | `elf` |
| First seen | `2026-10-28 02:49:21` |
| Reporter | `YaRi78` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f620960d07a44839bbe411b474f17bda` |
| SHA-1 | `3e89865d0e9adf760e4443f0db4ce5cc0f54fbbc` |
| SHA-256 | `478ef62c5a9c90b25940d000215e3a61013d9aca52184dfdde067c5b1d0fd157` |
| SHA3-384 | `4a6adcbf16ae27cd4a10a8a5019ad32ff9c3ac49e5bda261c01a9187f501201659f2ab88c917938defe1b049e389eb11` |
| TLSH | `T1B2939F12EC645E9CF02A6C3520B88ABA5313E1D8D9176DBB3846C2611147EACF59FFF4` |
| SSDEEP | `1536:BMfee1DzJt7yH8erA4XMCu+7ObWiezKxdF+eYnCpxcS8sRf:BMfee1DzJ93erA4BuY2xZYnNSR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_478ef62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "478ef62c5a9c90b25940d000215e3a61013d9aca52184dfdde067c5b1d0fd157"
    family = "Mirai"
    file_name = "jklsh4"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:21"
  condition:
    hash.sha256(0, filesize) == "478ef62c5a9c90b25940d000215e3a61013d9aca52184dfdde067c5b1d0fd157"
}
```

### Sample 67: `e852ad29f1c5caa1`

| Field | Value |
|---|---|
| SHA-256 | `e852ad29f1c5caa101a294ac4583c2b788cc282a662709253457b91b7b72269e` |
| Family label | `Mirai` |
| File name | `jklppc` |
| File type | `elf` |
| First seen | `2026-10-28 02:49:21` |
| Reporter | `YaRi78` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9a687319b754c91f5fa7d3cd023e7ef` |
| SHA-1 | `f4f347f5b231d0656837a565d4431a8cc5e687bf` |
| SHA-256 | `e852ad29f1c5caa101a294ac4583c2b788cc282a662709253457b91b7b72269e` |
| SHA3-384 | `c2a2f3b0da2b203ce5dac34cf9bc805ad0b7e70e9901991f811c349966943fc05f408ee9a900f64c6c1a7214b5f22b1e` |
| TLSH | `T1CF935A0173594447E3EB0EB11D3F6BE193DED6A132A0A2C6694EEB0F8175A325186FCD` |
| SSDEEP | `1536:y7iZtnM3LUEvFqo4TkrLYIHiv2sLdvz4upED3cljOdwgzmG5qqsNTdD/Q548sRmE:fZe3tvQPBkuobdwSmdbQqcE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_e852ad29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e852ad29f1c5caa101a294ac4583c2b788cc282a662709253457b91b7b72269e"
    family = "Mirai"
    file_name = "jklppc"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:21"
  condition:
    hash.sha256(0, filesize) == "e852ad29f1c5caa101a294ac4583c2b788cc282a662709253457b91b7b72269e"
}
```

### Sample 68: `74e8f45a91123693`

| Field | Value |
|---|---|
| SHA-256 | `74e8f45a9112369342084413575e7ffbb3ae1c864f5362e61ed36e2ba578ae4a` |
| Family label | `unknown` |
| File name | `jklmpsl` |
| File type | `elf` |
| First seen | `2026-10-28 02:49:21` |
| Reporter | `YaRi78` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `970c5c7e51d889a7b6ca15860fc16195` |
| SHA-1 | `c7f68f37956507cd680a3e19a961585b5d078e93` |
| SHA-256 | `74e8f45a9112369342084413575e7ffbb3ae1c864f5362e61ed36e2ba578ae4a` |
| SHA3-384 | `a17a761455fba0a143a624f6952afdd39f1638d11e4acb2bbc24d0a946ff015486fdaf0a8c1e879b4d8dc77279bb14ed` |
| TLSH | `T1AEC3090AFFA10EFBD8AFCD3345A9070A389C594621B42B3A6574D81CF65E18F1AE3C54` |
| SSDEEP | `1536:JBw6cY4B5xAV9bkNqRFWGUVxAxTJQORoLsd/b8jjz5fMoO95aqyhAexOJIWN86q/:JSTwFWGsxKMjHAoh24` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_74e8f45a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74e8f45a9112369342084413575e7ffbb3ae1c864f5362e61ed36e2ba578ae4a"
    family = "unknown"
    file_name = "jklmpsl"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:21"
  condition:
    hash.sha256(0, filesize) == "74e8f45a9112369342084413575e7ffbb3ae1c864f5362e61ed36e2ba578ae4a"
}
```

### Sample 69: `f6b082b40807012f`

| Field | Value |
|---|---|
| SHA-256 | `f6b082b40807012f5b9812e4952110f2c73b53eb97664aa3067e2f69a57848bf` |
| Family label | `unknown` |
| File name | `jklmips` |
| File type | `elf` |
| First seen | `2026-10-28 02:49:20` |
| Reporter | `YaRi78` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75152511111fced1a72ce5fca47e715d` |
| SHA-1 | `59986c126be2ce28dc738de1d520470d8e0f64c0` |
| SHA-256 | `f6b082b40807012f5b9812e4952110f2c73b53eb97664aa3067e2f69a57848bf` |
| SHA3-384 | `9c6a82a4efc1875429b1cf135ee549028138061fe9343f83f61eb85fd2474fa7f1ddfb59eb7e261fa86d6548364be07e` |
| TLSH | `T163B3E80B7E629F6DF36C82344FB78B35639923D533E08685D26CEA405E6034D586FBA4` |
| TELFHASH | `t1cf115118893813f097721cdd6becfe76e46170eb0a216d338d10f9589a2de069d00c2c` |
| SSDEEP | `1536:8MXrnmNagwyZUuKK6KK73KKSiHLzU10hK63XxGYzv3S3JKehF88sR5WV:9bmNdZUGirzU0KTYzv3Ob8bWV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_f6b082b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6b082b40807012f5b9812e4952110f2c73b53eb97664aa3067e2f69a57848bf"
    family = "unknown"
    file_name = "jklmips"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:20"
  condition:
    hash.sha256(0, filesize) == "f6b082b40807012f5b9812e4952110f2c73b53eb97664aa3067e2f69a57848bf"
}
```

### Sample 70: `049326ac87a62f1e`

| Field | Value |
|---|---|
| SHA-256 | `049326ac87a62f1ea6f88d0b766bd0855ce2f48d781aa04a6679d0f35bc387aa` |
| Family label | `unknown` |
| File name | `jklm68k` |
| File type | `elf` |
| First seen | `2026-10-28 02:49:20` |
| Reporter | `YaRi78` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14a7563e22ff89d7601d51ba9631385e` |
| SHA-1 | `c58d4d77aa073d490c8561e6feb9e59b1f33b81b` |
| SHA-256 | `049326ac87a62f1ea6f88d0b766bd0855ce2f48d781aa04a6679d0f35bc387aa` |
| SHA3-384 | `4ea21a2c5fbbaeb6c32c80ed42a1caf924445561176f89f6e1e6e55d6c2842add70363b0848656c6bfd68b6dc7eff324` |
| TLSH | `T121933DE2B410DC3EF45BE2B7C41F0606B125A3E44F922B277257F963DE6A1781826E47` |
| SSDEEP | `1536:srjGjXN0FqNn40Y2PMPCjpzSCTnc0m3303300nIjd8JOQ8FTVoXzZoGUgZ1R3ET5:sOjXN0Fw40rPMQhSCTc0m3303300nu8I` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_049326ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049326ac87a62f1ea6f88d0b766bd0855ce2f48d781aa04a6679d0f35bc387aa"
    family = "unknown"
    file_name = "jklm68k"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:20"
  condition:
    hash.sha256(0, filesize) == "049326ac87a62f1ea6f88d0b766bd0855ce2f48d781aa04a6679d0f35bc387aa"
}
```

### Sample 71: `eba53e0022821148`

| Field | Value |
|---|---|
| SHA-256 | `eba53e00228211485d5f29ec646f4e2a78b606b1a0516195a2e735649d419ede` |
| Family label | `QuasarRAT` |
| File name | `289fe7df4bde67c9086465ef1096ed4a.exe` |
| File type | `exe` |
| First seen | `2026-10-28 02:45:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `289fe7df4bde67c9086465ef1096ed4a` |
| SHA-1 | `abfc98609dce0d6b8ab6cfb0711ace993d3eb2ce` |
| SHA-256 | `eba53e00228211485d5f29ec646f4e2a78b606b1a0516195a2e735649d419ede` |
| SHA3-384 | `1bbccfcc76838263e72981f84509520ca0fd7729cc0be82b12d25c284ba12db6dce2fe21610af946ec0be9fe2296ef59` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T141E54A1437F81F37E1AEE277D6B1541667F0E82AB363970B6181667A2C83B508D017BB` |
| SSDEEP | `49152:ecMas0UF5eTTBNagCY61+UtsDtVqXKVFzBEEoG93uTHHB72eh2NT:ecMa8cTBNagCY6TtsDtVkKVh` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_071_eba53e00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eba53e00228211485d5f29ec646f4e2a78b606b1a0516195a2e735649d419ede"
    family = "QuasarRAT"
    file_name = "289fe7df4bde67c9086465ef1096ed4a.exe"
    file_type = "exe"
    first_seen = "2026-10-28 02:45:07"
  condition:
    hash.sha256(0, filesize) == "eba53e00228211485d5f29ec646f4e2a78b606b1a0516195a2e735649d419ede"
}
```

### Sample 72: `25d0dd9619dcf939`

| Field | Value |
|---|---|
| SHA-256 | `25d0dd9619dcf939045b31b78d4f3c4227176ed7144e53572dad436711d8c4f9` |
| Family label | `unknown` |
| File name | `Dinamode.vbs` |
| File type | `vbs` |
| First seen | `2026-10-28 02:45:03` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9e364c3bb9fa49b48ff36ed441e29d3` |
| SHA-1 | `501c4a7589d8cfb2f0e5120e4e196ef0adb17cee` |
| SHA-256 | `25d0dd9619dcf939045b31b78d4f3c4227176ed7144e53572dad436711d8c4f9` |
| SHA3-384 | `399790e999851d0fff97b29a4206552f6b531739769d4cd14b198cb913080bf4d70066557554bebf11aa3545e51b6a2c` |
| TLSH | `T11CC3C42BDDD6233DAAC2869DA904055584F88535433380FCB79A5E193BB25F897BE33C` |
| SSDEEP | `1536:fQsxwpBC0f32VGaqSvBOkUpLlVzFPmvCl9UugSLkXUK63/oNqc2ij7bazW0cDx:fQsxotm6SvMkU1/lngSYXUdvCqk7Wx2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_25d0dd96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25d0dd9619dcf939045b31b78d4f3c4227176ed7144e53572dad436711d8c4f9"
    family = "unknown"
    file_name = "Dinamode.vbs"
    file_type = "vbs"
    first_seen = "2026-10-28 02:45:03"
  condition:
    hash.sha256(0, filesize) == "25d0dd9619dcf939045b31b78d4f3c4227176ed7144e53572dad436711d8c4f9"
}
```

### Sample 73: `4775a4bc9b1569c4`

| Field | Value |
|---|---|
| SHA-256 | `4775a4bc9b1569c415b6fe972a8bd611aa67b0e726aa342d1d0b910ae1a56bc0` |
| Family label | `SalatStealer` |
| File name | `f96e1da6bcff41bf.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:27:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `880df18e0296450acf988c7a10fba5c8` |
| SHA-1 | `ecdded27adcb16d522b8ed9664a5c8a2cd9c5f88` |
| SHA-256 | `4775a4bc9b1569c415b6fe972a8bd611aa67b0e726aa342d1d0b910ae1a56bc0` |
| SHA3-384 | `ce701a2e6c5224c16af440c95854ceefc79f53035993a1b269f1d1b951d90a89c333b2aa3ba295f37f39204ea31260f6` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T128C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+a:yBkKr5rszpNDy+a` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_073_4775a4bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4775a4bc9b1569c415b6fe972a8bd611aa67b0e726aa342d1d0b910ae1a56bc0"
    family = "SalatStealer"
    file_name = "f96e1da6bcff41bf.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:27:38"
  condition:
    hash.sha256(0, filesize) == "4775a4bc9b1569c415b6fe972a8bd611aa67b0e726aa342d1d0b910ae1a56bc0"
}
```

### Sample 74: `bd2613d5ee4e574c`

| Field | Value |
|---|---|
| SHA-256 | `bd2613d5ee4e574ce3ab806b9173aaf8d19125a418380c095c8dd950585a38f2` |
| Family label | `SalatStealer` |
| File name | `72d644ac1629a373.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:27:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27b787edd054d5f8d2b434e3de3f70d2` |
| SHA-1 | `30da5d7a0388a3ec1e5bc123d1dae5a8397dc32a` |
| SHA-256 | `bd2613d5ee4e574ce3ab806b9173aaf8d19125a418380c095c8dd950585a38f2` |
| SHA3-384 | `06600233ccb2c1e37211f959a1f81e771b21e801d52d58c75fa6bc8522731fb015b42ed5f4843dc297c3e42f517f99cd` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T184C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Q:yBkKr5rszpNDy+Q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_074_bd2613d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd2613d5ee4e574ce3ab806b9173aaf8d19125a418380c095c8dd950585a38f2"
    family = "SalatStealer"
    file_name = "72d644ac1629a373.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:27:27"
  condition:
    hash.sha256(0, filesize) == "bd2613d5ee4e574ce3ab806b9173aaf8d19125a418380c095c8dd950585a38f2"
}
```

### Sample 75: `ad1dcfa9f23425b1`

| Field | Value |
|---|---|
| SHA-256 | `ad1dcfa9f23425b19046fe8fc6fa5f931d3c7b995eabda15a906d9805f73ac77` |
| Family label | `SalatStealer` |
| File name | `3d61e14f06d431d9.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:26:32` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f381cabfd49818b8f03689077504fcd2` |
| SHA-1 | `72cbc6cc0773f26e880d866d65d43dc2da3b3182` |
| SHA-256 | `ad1dcfa9f23425b19046fe8fc6fa5f931d3c7b995eabda15a906d9805f73ac77` |
| SHA3-384 | `90160975222f339d95b7cc0f32954b804ce98d7dfac8e7bdd41780f787ba9dbc866f44c26c34477748eff769a14765e4` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A8C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+0:yBkKr5rszpNDy+0` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_075_ad1dcfa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad1dcfa9f23425b19046fe8fc6fa5f931d3c7b995eabda15a906d9805f73ac77"
    family = "SalatStealer"
    file_name = "3d61e14f06d431d9.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:26:32"
  condition:
    hash.sha256(0, filesize) == "ad1dcfa9f23425b19046fe8fc6fa5f931d3c7b995eabda15a906d9805f73ac77"
}
```

### Sample 76: `56f5cea579c701d7`

| Field | Value |
|---|---|
| SHA-256 | `56f5cea579c701d705a6845e9da4cbc3c590d95ee613c0a57e8cc6c3285837fe` |
| Family label | `SalatStealer` |
| File name | `f03f2348f8a567fb.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:26:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cba0342ee042aee08a9a6029795ef803` |
| SHA-1 | `78943cce934b48472c51d58145fc232ed587d032` |
| SHA-256 | `56f5cea579c701d705a6845e9da4cbc3c590d95ee613c0a57e8cc6c3285837fe` |
| SHA3-384 | `71604d822cc408852b4b7305bba2f32b523b95d8d53d34d7d533a13f4651b4c417d217e66b4a550cf3038cfa074f82f5` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D1C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+n:yBkKr5rszpNDy+n` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_076_56f5cea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56f5cea579c701d705a6845e9da4cbc3c590d95ee613c0a57e8cc6c3285837fe"
    family = "SalatStealer"
    file_name = "f03f2348f8a567fb.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:26:09"
  condition:
    hash.sha256(0, filesize) == "56f5cea579c701d705a6845e9da4cbc3c590d95ee613c0a57e8cc6c3285837fe"
}
```

### Sample 77: `c02ad52f440b82a9`

| Field | Value |
|---|---|
| SHA-256 | `c02ad52f440b82a9d2e2abb27e5fc0bd1900b1f527b1478e350e65937b257c73` |
| Family label | `SalatStealer` |
| File name | `6f24c1175f940d89.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:25:58` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae617b84351ec6a39e241c321e782fe7` |
| SHA-1 | `5d6f24ed92a96df6a454a5f09e47404367f50405` |
| SHA-256 | `c02ad52f440b82a9d2e2abb27e5fc0bd1900b1f527b1478e350e65937b257c73` |
| SHA3-384 | `02513970eea653ba39d23a589267ba60bb7e7cdd6f22f5f17676e54a23ae3116c2eee881e287408603f5c394af0bbf7d` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F3C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+v:yBkKr5rszpNDy+v` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_077_c02ad52f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c02ad52f440b82a9d2e2abb27e5fc0bd1900b1f527b1478e350e65937b257c73"
    family = "SalatStealer"
    file_name = "6f24c1175f940d89.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:58"
  condition:
    hash.sha256(0, filesize) == "c02ad52f440b82a9d2e2abb27e5fc0bd1900b1f527b1478e350e65937b257c73"
}
```

### Sample 78: `eed2564c58124584`

| Field | Value |
|---|---|
| SHA-256 | `eed2564c5812458458350371b70b232a0da1b415127bc2146135f8421776faea` |
| Family label | `SalatStealer` |
| File name | `a04a8a3490737f32.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:25:51` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29ce1bddaf9dea2addcbf9f8fbf2a783` |
| SHA-1 | `27001346a324d94017e393e4743d77ad4f925b0e` |
| SHA-256 | `eed2564c5812458458350371b70b232a0da1b415127bc2146135f8421776faea` |
| SHA3-384 | `bbc7782135d2297859c1e9afdf5d8b8fa4f131e17b89e867f52d16af0422cab26b92e56414e5e4496540de63b904c76c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T176C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+8:yBkKr5rszpNDy+8` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_078_eed2564c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eed2564c5812458458350371b70b232a0da1b415127bc2146135f8421776faea"
    family = "SalatStealer"
    file_name = "a04a8a3490737f32.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:51"
  condition:
    hash.sha256(0, filesize) == "eed2564c5812458458350371b70b232a0da1b415127bc2146135f8421776faea"
}
```

### Sample 79: `79138e57f432ac8e`

| Field | Value |
|---|---|
| SHA-256 | `79138e57f432ac8e0a450066e9aa432fe41366ba5a5966512a9c07d56c7b1b4f` |
| Family label | `SalatStealer` |
| File name | `3237f0d9b05d332e.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:25:42` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecf39e1667dcce2ca7732f9c727d7854` |
| SHA-1 | `155ea7758fc25122590cf252fa57a104255db9da` |
| SHA-256 | `79138e57f432ac8e0a450066e9aa432fe41366ba5a5966512a9c07d56c7b1b4f` |
| SHA3-384 | `f7491cfd2608d6ea7f179228e1d17bc1bd55e12e4819b563e9507f0d94cdc5a603dcd815d6277497f7ee929f97de7aef` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T123C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Z:yBkKr5rszpNDy+Z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_079_79138e57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79138e57f432ac8e0a450066e9aa432fe41366ba5a5966512a9c07d56c7b1b4f"
    family = "SalatStealer"
    file_name = "3237f0d9b05d332e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:42"
  condition:
    hash.sha256(0, filesize) == "79138e57f432ac8e0a450066e9aa432fe41366ba5a5966512a9c07d56c7b1b4f"
}
```

### Sample 80: `f96e1da6bcff41bf`

| Field | Value |
|---|---|
| SHA-256 | `f96e1da6bcff41bfd857fc0ebed69239dbc5c7d28f546e5743c80e73646cb901` |
| Family label | `SalatStealer` |
| File name | `f96e1da6bcff41bf.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:25:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0829ad52bd7f8bad2ba733f7584f7da` |
| SHA-1 | `9a0b62fb1f86460bb0d8c2c3ec705f563c1a432c` |
| SHA-256 | `f96e1da6bcff41bfd857fc0ebed69239dbc5c7d28f546e5743c80e73646cb901` |
| SHA3-384 | `403ba6bf922645df5320378f654604927679cdc9093fce490cd60267be9b3e947c82f3654a0012608cfcef9d6dcc6b8f` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T18BF5335BF1AF47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oe:iJiafuIO7rhWEES4x` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_080_f96e1da6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f96e1da6bcff41bfd857fc0ebed69239dbc5c7d28f546e5743c80e73646cb901"
    family = "SalatStealer"
    file_name = "f96e1da6bcff41bf.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:36"
  condition:
    hash.sha256(0, filesize) == "f96e1da6bcff41bfd857fc0ebed69239dbc5c7d28f546e5743c80e73646cb901"
}
```

### Sample 81: `96ffebedca2b15a7`

| Field | Value |
|---|---|
| SHA-256 | `96ffebedca2b15a742a001d533fb9857d9339494ddcd5521510fa6024e0cb855` |
| Family label | `SalatStealer` |
| File name | `37a5b3cfde85c087.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:25:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e3db65ecb2be0a61a5029fb388c2cf8` |
| SHA-1 | `a56dea1722ee610f6ad1090a1a5bf8e77b75a0b6` |
| SHA-256 | `96ffebedca2b15a742a001d533fb9857d9339494ddcd5521510fa6024e0cb855` |
| SHA3-384 | `103f5c7b155e0ad5da96f07661b6faf6594fb28fe3e48d8e287049fcae06ba530116aa57c06a33fa113e4effc76b7064` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T109C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+A:yBkKr5rszpNDy+A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_081_96ffebed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96ffebedca2b15a742a001d533fb9857d9339494ddcd5521510fa6024e0cb855"
    family = "SalatStealer"
    file_name = "37a5b3cfde85c087.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:35"
  condition:
    hash.sha256(0, filesize) == "96ffebedca2b15a742a001d533fb9857d9339494ddcd5521510fa6024e0cb855"
}
```

### Sample 82: `72d644ac1629a373`

| Field | Value |
|---|---|
| SHA-256 | `72d644ac1629a37306a5591ee27eebcd68893180854c5650a0b9732b91724b60` |
| Family label | `SalatStealer` |
| File name | `72d644ac1629a373.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:25:27` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0ea80308687ca4fc4bee1fea1c144ce` |
| SHA-1 | `5004e385f39ced5f79de881441aca6e3461bbeb7` |
| SHA-256 | `72d644ac1629a37306a5591ee27eebcd68893180854c5650a0b9732b91724b60` |
| SHA3-384 | `ca1d5aa693d99466f52dec0460681a8484717d7520769ffaf4169552ce4f848cbc877aead986d49f93674898d6dbfc49` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1D1F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ok:iJiafuIO7rhWEES4n` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_082_72d644ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d644ac1629a37306a5591ee27eebcd68893180854c5650a0b9732b91724b60"
    family = "SalatStealer"
    file_name = "72d644ac1629a373.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:27"
  condition:
    hash.sha256(0, filesize) == "72d644ac1629a37306a5591ee27eebcd68893180854c5650a0b9732b91724b60"
}
```

### Sample 83: `3d61e14f06d431d9`

| Field | Value |
|---|---|
| SHA-256 | `3d61e14f06d431d9b0e409ce64c9be543ea9f7d0fb18d0d444037360c62309dd` |
| Family label | `SalatStealer` |
| File name | `3d61e14f06d431d9.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:25:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89170600deb5642b83bd60ee4334b08c` |
| SHA-1 | `c70f21b9c6f0a9de5424c96b52f448febba27d64` |
| SHA-256 | `3d61e14f06d431d9b0e409ce64c9be543ea9f7d0fb18d0d444037360c62309dd` |
| SHA3-384 | `c5116ad5b5126ddcbb432b72f3da35946088fa471f77afc73a5b078ae54b7771b6a4b6c94a4687127a905db5e8bb8e97` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T17DF5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O4:iJiafuIO7rhWEES4B` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_083_3d61e14f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d61e14f06d431d9b0e409ce64c9be543ea9f7d0fb18d0d444037360c62309dd"
    family = "SalatStealer"
    file_name = "3d61e14f06d431d9.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:17"
  condition:
    hash.sha256(0, filesize) == "3d61e14f06d431d9b0e409ce64c9be543ea9f7d0fb18d0d444037360c62309dd"
}
```

### Sample 84: `f03f2348f8a567fb`

| Field | Value |
|---|---|
| SHA-256 | `f03f2348f8a567fb3a8edef1ffc7b000416c04d4c3b2730ec66b0dd24f0ce355` |
| Family label | `SalatStealer` |
| File name | `f03f2348f8a567fb.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:25:07` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82b5a021a6feaf68a1b201b6cdb21662` |
| SHA-1 | `89a72fd561a40f5d82df528567e0650dc4c723a4` |
| SHA-256 | `f03f2348f8a567fb3a8edef1ffc7b000416c04d4c3b2730ec66b0dd24f0ce355` |
| SHA3-384 | `5c787808a947137d6ecff4c405a09d2bc5b27cfe03d320366656a8c80a2d13180e830cdb0e1830427504caf30a3670cf` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T131F5335BF1AB47B3F7D9A835560FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ob:iJiafuIO7rhWEES4+` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_084_f03f2348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f03f2348f8a567fb3a8edef1ffc7b000416c04d4c3b2730ec66b0dd24f0ce355"
    family = "SalatStealer"
    file_name = "f03f2348f8a567fb.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:07"
  condition:
    hash.sha256(0, filesize) == "f03f2348f8a567fb3a8edef1ffc7b000416c04d4c3b2730ec66b0dd24f0ce355"
}
```

### Sample 85: `6f24c1175f940d89`

| Field | Value |
|---|---|
| SHA-256 | `6f24c1175f940d89064bd78d860d7038236cf83001e22531bc1c2856abe43b6a` |
| Family label | `SalatStealer` |
| File name | `6f24c1175f940d89.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:24:57` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `807bc298098c931b198e021da30b13c7` |
| SHA-1 | `b3978bdfef58cf337e005647fba58b38f675e8db` |
| SHA-256 | `6f24c1175f940d89064bd78d860d7038236cf83001e22531bc1c2856abe43b6a` |
| SHA3-384 | `404333b8816b34859ae5adb1afa6a7de76770ef5214845ecfec929124d3ff049b1f6b51241b3efd2bc6b06684b2706ee` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T13FF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oj:iJiafuIO7rhWEES4w` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_085_6f24c117
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f24c1175f940d89064bd78d860d7038236cf83001e22531bc1c2856abe43b6a"
    family = "SalatStealer"
    file_name = "6f24c1175f940d89.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:57"
  condition:
    hash.sha256(0, filesize) == "6f24c1175f940d89064bd78d860d7038236cf83001e22531bc1c2856abe43b6a"
}
```

### Sample 86: `a04a8a3490737f32`

| Field | Value |
|---|---|
| SHA-256 | `a04a8a3490737f3259a856a19ec8b8f818c00608ee75d7a50e68c9a06adff9fb` |
| Family label | `SalatStealer` |
| File name | `a04a8a3490737f32.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:24:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04a98fdf01f1487fd562b8f4fa5a1c00` |
| SHA-1 | `91df523d0ee734975ec7b669a8c883dd771f94b8` |
| SHA-256 | `a04a8a3490737f3259a856a19ec8b8f818c00608ee75d7a50e68c9a06adff9fb` |
| SHA3-384 | `ae4eb4434fb60a51156fbef4b2cfa4e6674e572acc9bc912a18f16b8c756cdfcf3d3fc8b3cc477dfd81ed3ba8f286489` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C8F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O4:iJiafuIO7rhWEES4B` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_086_a04a8a34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a04a8a3490737f3259a856a19ec8b8f818c00608ee75d7a50e68c9a06adff9fb"
    family = "SalatStealer"
    file_name = "a04a8a3490737f32.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:47"
  condition:
    hash.sha256(0, filesize) == "a04a8a3490737f3259a856a19ec8b8f818c00608ee75d7a50e68c9a06adff9fb"
}
```

### Sample 87: `3237f0d9b05d332e`

| Field | Value |
|---|---|
| SHA-256 | `3237f0d9b05d332e99b52ff405efa59f429311ab12ac1a2f73fbf62794171364` |
| Family label | `SalatStealer` |
| File name | `3237f0d9b05d332e.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:24:37` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3b66f6444993f28e787190beb4dd65d` |
| SHA-1 | `99fa2945a43d29d2688b77be484c882dcbcc9bf6` |
| SHA-256 | `3237f0d9b05d332e99b52ff405efa59f429311ab12ac1a2f73fbf62794171364` |
| SHA3-384 | `be5a4387eeabe0be40b8ac58dbfd3408494ddf983531b8364155efc073a8ebd0bddd8853e83bd8b661f9357393b3fba2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10AF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ot:iJiafuIO7rhWEES4q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_087_3237f0d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3237f0d9b05d332e99b52ff405efa59f429311ab12ac1a2f73fbf62794171364"
    family = "SalatStealer"
    file_name = "3237f0d9b05d332e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:37"
  condition:
    hash.sha256(0, filesize) == "3237f0d9b05d332e99b52ff405efa59f429311ab12ac1a2f73fbf62794171364"
}
```

### Sample 88: `37a5b3cfde85c087`

| Field | Value |
|---|---|
| SHA-256 | `37a5b3cfde85c08764d469a15cc0db30468790fe1cd874ca352cef3118be18c7` |
| Family label | `SalatStealer` |
| File name | `37a5b3cfde85c087.bin` |
| File type | `exe` |
| First seen | `2026-10-28 02:24:28` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d484a90b3c0a6623dd384dd2781238f` |
| SHA-1 | `019a3b83bcab40a215dccee7f1113402f856ccf7` |
| SHA-256 | `37a5b3cfde85c08764d469a15cc0db30468790fe1cd874ca352cef3118be18c7` |
| SHA3-384 | `1a65860be3e2f64fabbd4b6365fed4fa64966a96776baa5ba67dde937e70918f3817e51144e03957fe324d59f402189d` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T150F5335BF1AF47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OE:iJiafuIO7rhWEES4z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_088_37a5b3cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37a5b3cfde85c08764d469a15cc0db30468790fe1cd874ca352cef3118be18c7"
    family = "SalatStealer"
    file_name = "37a5b3cfde85c087.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:28"
  condition:
    hash.sha256(0, filesize) == "37a5b3cfde85c08764d469a15cc0db30468790fe1cd874ca352cef3118be18c7"
}
```

### Sample 89: `1d86622d46ef87c4`

| Field | Value |
|---|---|
| SHA-256 | `1d86622d46ef87c4d2db72a031b7e927d31363e72e0fd4c95c69f23da5f3b9e1` |
| Family label | `AgentTesla` |
| File name | `ENQUIRY SASPRMAT26090237 (997-SP30).pif` |
| File type | `exe` |
| First seen | `2026-10-28 02:24:26` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `207c30488b1133f74bbcbbc6772b41b8` |
| SHA-1 | `1a0232b4f79f9211796eb440e719fcacbe03ded9` |
| SHA-256 | `1d86622d46ef87c4d2db72a031b7e927d31363e72e0fd4c95c69f23da5f3b9e1` |
| SHA3-384 | `b305689c14a1d17e7eb9a674be18af2eb353efe74da8b01b28598c37ca05efbe9371d1a942f8493592cf59cbdd3200c6` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B1E4F058123B8602E9B16FF05D71E0B85B7A6DAA6430E0285FC21CEBB5737507D8673B` |
| SSDEEP | `12288:ypAgiBSATM78ii58YFGZAZZ82BGOr0ySW787sLHk4FV7Lmu2mckKB:6AgiBSATM7PqioGCOQLHk4FV7LtvcT` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_089_1d86622d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d86622d46ef87c4d2db72a031b7e927d31363e72e0fd4c95c69f23da5f3b9e1"
    family = "AgentTesla"
    file_name = "ENQUIRY SASPRMAT26090237 (997-SP30).pif"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:26"
  condition:
    hash.sha256(0, filesize) == "1d86622d46ef87c4d2db72a031b7e927d31363e72e0fd4c95c69f23da5f3b9e1"
}
```

### Sample 90: `bcca48907156b96e`

| Field | Value |
|---|---|
| SHA-256 | `bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829` |
| Family label | `unknown` |
| File name | `bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829.exe` |
| File type | `exe` |
| First seen | `2026-10-28 02:23:19` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37e71ffa292235784707e7063bb0d561` |
| SHA-1 | `a03161698abaf26756f94e4a64d26b5ca944ade5` |
| SHA-256 | `bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829` |
| SHA3-384 | `6836d7a67216f097246befe46824c4f0ab08c4a472e68dc0bdec7f10cab264ff34c240acefb9c365466c0d329f45542f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T145C46C2636664E50C2994F77C18BA50083E2AAC2FEE7F70F718403662D473EED947697` |
| SSDEEP | `12288:KYb63sNiecXugrs+rj/5HbBg0zo0Ugmy9rybW:KYOsNcXu5+f/51g0E0UgVZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_bcca4890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829"
    family = "unknown"
    file_name = "bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829.exe"
    file_type = "exe"
    first_seen = "2026-10-28 02:23:19"
  condition:
    hash.sha256(0, filesize) == "bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829"
}
```

### Sample 91: `ed91a6cf7e6414f1`

| Field | Value |
|---|---|
| SHA-256 | `ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7` |
| Family label | `unknown` |
| File name | `ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7.exe` |
| File type | `exe` |
| First seen | `2026-10-28 02:23:13` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce1f985cc4f86d391498e25769f00c63` |
| SHA-1 | `f14b3aa4d23e157915ddc252cfe461af1b2d2713` |
| SHA-256 | `ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7` |
| SHA3-384 | `5bb446f476bc222b42c887f9caf18d2e3ef5dbeafce5d8bcc49aeb125c11de649939a51174fece25e867799a8dd80b60` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13BD3BE4C73E84551CCFF86B90E70523997B9E0330522E6455E952AE98FBBFE00D64B8B` |
| SSDEEP | `3072:l0toeIdvNJXK9Z57/zQM2LI/JjKWBvizPyeqEAql1kb2HyCCaY:tNw9zzzQUJjKSvSPl66SCfY` |
| ICON-DHASH | `4c88c8e88c9a9ac4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_ed91a6cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7"
    family = "unknown"
    file_name = "ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7.exe"
    file_type = "exe"
    first_seen = "2026-10-28 02:23:13"
  condition:
    hash.sha256(0, filesize) == "ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7"
}
```

### Sample 92: `1fbdd925143e28ea`

| Field | Value |
|---|---|
| SHA-256 | `1fbdd925143e28ea6542bcc3b15cd44de7c0b226082f6f99450f0e1822db2068` |
| Family label | `unknown` |
| File name | `macho_1fbdd925143e.bin` |
| File type | `macho` |
| First seen | `2026-10-28 02:15:36` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a133e6df01026fb3b8cad0b75a398bd5` |
| SHA-1 | `17c9938ef480a14ca79451aaeeb3dd1d5b83ad42` |
| SHA-256 | `1fbdd925143e28ea6542bcc3b15cd44de7c0b226082f6f99450f0e1822db2068` |
| SHA3-384 | `9da1da06963dd3b13b49888971623f5b6da91ba376ded37400d713ccd62525cb2b58ab1920fe7e4e2f29b1e60de3c639` |
| TLSH | `T1E395F1404FA66186D54E01739C8A8F1C84B470A1CF89DEEE6341B39A8E3A7D3B7571B7` |
| SSDEEP | `49152:XD+cMB9mlK1GfGZrcVCNBQjxKD6RyZY0MZMn9cu+X8BaaV9+gz5V1gldIM1KNFEu:GnxN0oDMn5G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_1fbdd925
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fbdd925143e28ea6542bcc3b15cd44de7c0b226082f6f99450f0e1822db2068"
    family = "unknown"
    file_name = "macho_1fbdd925143e.bin"
    file_type = "macho"
    first_seen = "2026-10-28 02:15:36"
  condition:
    hash.sha256(0, filesize) == "1fbdd925143e28ea6542bcc3b15cd44de7c0b226082f6f99450f0e1822db2068"
}
```

### Sample 93: `358521ef5d11b522`

| Field | Value |
|---|---|
| SHA-256 | `358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de` |
| Family label | `unknown` |
| File name | `358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de` |
| File type | `exe` |
| First seen | `2026-10-28 02:15:08` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43c74be428f22336bda91a85889dd06a` |
| SHA-1 | `2d71485f50f608abbeb5694ed7086575e2c04c32` |
| SHA-256 | `358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de` |
| SHA3-384 | `ee6ee404c6047ed9e24e481d858ba4bdad6a6c3625ab5a310f863ede90b9d56140f71ec68677ec7799d699c4eb67fea3` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1F836238A32AC80F8D0076678D4B74D15F3B37C9E22B9970F97908A661E13790BF34B56` |
| SSDEEP | `24576:jbLgBbLguriDQhfdmMSirYbcMNgef0QeQjGCX6SASk:jnsnuQqMSPbcBVQeje6SA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_358521ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de"
    family = "unknown"
    file_name = "358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de"
    file_type = "exe"
    first_seen = "2026-10-28 02:15:08"
  condition:
    hash.sha256(0, filesize) == "358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de"
}
```

### Sample 94: `a573d2eb7adc9558`

| Field | Value |
|---|---|
| SHA-256 | `a573d2eb7adc9558e63591fbf3e9d5db5afe5bb4f87e5ecd6baf91e8ebf38a70` |
| Family label | `Mirai` |
| File name | `splarm7` |
| File type | `elf` |
| First seen | `2026-10-28 01:58:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72f3c70cf3db51f427b23f405263ce21` |
| SHA-1 | `d7ab0e9e1d0d9909ec79abdbc6d5c2202755babe` |
| SHA-256 | `a573d2eb7adc9558e63591fbf3e9d5db5afe5bb4f87e5ecd6baf91e8ebf38a70` |
| SHA3-384 | `e987add92696efd132d43c6bfbb2c4c4d00ce7caf942f126dddaa9c114b539f010df337b5dae3a802b3dff095455534b` |
| TLSH | `T18CC31ACABC809B11D5D525BAFE0E118D33134BB8E3F971029E145B2E678AC6B0E7B611` |
| TELFHASH | `t14ff0dc34cc880ccceed1a84099dc93150d0e70873b3221452ebda7cd4a214d1392da22` |
| SSDEEP | `3072:bmTWRA1+rGETq8qEdoG9pjg8L/RHQfYDa3hZp/eZlTSfuFkWD:968n9Xg8L/aADa3hZp/e7TSk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_a573d2eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a573d2eb7adc9558e63591fbf3e9d5db5afe5bb4f87e5ecd6baf91e8ebf38a70"
    family = "Mirai"
    file_name = "splarm7"
    file_type = "elf"
    first_seen = "2026-10-28 01:58:15"
  condition:
    hash.sha256(0, filesize) == "a573d2eb7adc9558e63591fbf3e9d5db5afe5bb4f87e5ecd6baf91e8ebf38a70"
}
```

### Sample 95: `8e442d817d771957`

| Field | Value |
|---|---|
| SHA-256 | `8e442d817d771957101f4e6f08826e231a0273634dfccec774b5eb354c684e09` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-28 01:46:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e5c5e3a48496c2c21fd58835babc851` |
| SHA-1 | `dc7e8a99a2e900220ed25d3b1634f578608d3e13` |
| SHA-256 | `8e442d817d771957101f4e6f08826e231a0273634dfccec774b5eb354c684e09` |
| SHA3-384 | `d42c9a5a81d20bd1fe9b980e6c53ab764c8a8df197cb158d7d5f8dd43decd426b69b1f5597ebaf01367817c74211c7fe` |
| TLSH | `T1EE74F988E1F1E7DED2D4EA75B31D784D3A230736B1DB3146A11DAA3323EB1450ABD921` |
| TELFHASH | `t1dbf09e392f724bf852dbd618910bd46b0a783c115a0714c2ca942def4c5fd4118c9d31` |
| SSDEEP | `6144:gtW5aYwR2gMdyotExMn7Muhp4YAEGoXdwP/wutMQca9ij:GWYYMkdyZG7ddX2wsWa9ij` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_8e442d81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e442d817d771957101f4e6f08826e231a0273634dfccec774b5eb354c684e09"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-28 01:46:26"
  condition:
    hash.sha256(0, filesize) == "8e442d817d771957101f4e6f08826e231a0273634dfccec774b5eb354c684e09"
}
```

### Sample 96: `2021308de500344f`

| Field | Value |
|---|---|
| SHA-256 | `2021308de500344f418587206ad03cd3cc1d667a7a356df9c4f3af653765e05a` |
| Family label | `Mirai` |
| File name | `bot-linux-arm64` |
| File type | `elf` |
| First seen | `2026-10-28 01:40:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2904ce3836d30d6ea678c969782c88a8` |
| SHA-1 | `065ce61ff2409f658853c5d70f2cd1e8c840d5e8` |
| SHA-256 | `2021308de500344f418587206ad03cd3cc1d667a7a356df9c4f3af653765e05a` |
| SHA3-384 | `6849f4b2ee7e4d7399048560c378a560e2107889b36400a36379e62f7b7de413c6b5217e3f1695f1e2d607d4504a4d60` |
| TLSH | `T1DB566C4ABC1E6462D6CE79752F3652947339BC049F82D3136B14BB3CB9F27688B13261` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:zaepyOhXx060l14qM77Srsr+601Iu+IQhX4mWdsPktLHWMD5E/0:zaUyYXx2l14rSrsrR0XEascJE/0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_2021308d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2021308de500344f418587206ad03cd3cc1d667a7a356df9c4f3af653765e05a"
    family = "Mirai"
    file_name = "bot-linux-arm64"
    file_type = "elf"
    first_seen = "2026-10-28 01:40:05"
  condition:
    hash.sha256(0, filesize) == "2021308de500344f418587206ad03cd3cc1d667a7a356df9c4f3af653765e05a"
}
```

### Sample 97: `bea63659c3ff5771`

| Field | Value |
|---|---|
| SHA-256 | `bea63659c3ff5771c6360280c011c6adefe39b97bfb0671703d32d8c0a66acf8` |
| Family label | `RemcosRAT` |
| File name | `Kronragede.vbs` |
| File type | `vbs` |
| First seen | `2026-10-28 01:35:15` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `573080d807dcf7844e1a723b5916587e` |
| SHA-1 | `e44d27e3ffed1f71d9b358bf04fe0d6b6fc1332f` |
| SHA-256 | `bea63659c3ff5771c6360280c011c6adefe39b97bfb0671703d32d8c0a66acf8` |
| SHA3-384 | `a23dd53bca309f482cd8ff5246802200a660a972bbfe3b9717b4ed4d5459ac91524834ef828e0a78d602fa768102d854` |
| TLSH | `T100C3A2E8F9F436363DC3479BBA40077985B98DD5013AB2ECE5981639102295CDFBEA34` |
| SSDEEP | `1536:yJkBC8bMPhUt9aarOGQpSTMm6M7tipozcvefo5wpSJzX1pgzElxEBH29favsKnC3:yJkBd061Ov2MmcegypShX1yzS+BoOfm` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_097_bea63659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bea63659c3ff5771c6360280c011c6adefe39b97bfb0671703d32d8c0a66acf8"
    family = "RemcosRAT"
    file_name = "Kronragede.vbs"
    file_type = "vbs"
    first_seen = "2026-10-28 01:35:15"
  condition:
    hash.sha256(0, filesize) == "bea63659c3ff5771c6360280c011c6adefe39b97bfb0671703d32d8c0a66acf8"
}
```

### Sample 98: `287479610fa89ca0`

| Field | Value |
|---|---|
| SHA-256 | `287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0` |
| Family label | `CoinMiner` |
| File name | `287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0.exe` |
| File type | `exe` |
| First seen | `2026-10-28 01:28:15` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cb40a52dc8afde1c6e76c98902642d8` |
| SHA-1 | `8a8348d02e8be123936aae4429c570d741ee05c4` |
| SHA-256 | `287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0` |
| SHA3-384 | `a172b648944f50113520aaac0461833877caa6fedb096cf8f24c4d4e8b6a28dcd3b498138cca2fa43974a4a9afdc2717` |
| IMPHASH | `d9b55e0412bd077ed483747cc1f1aba0` |
| TLSH | `T13E57A051B30B05F6FF434C3645FAAB1F7B39EEDC8970C556E428342AB962C1B869C291` |
| SSDEEP | `393216:zA+0Wj8igSXaZTBrp9QpIDc17yvaYVnRVunLnm62u/VN3qbM:p8kX6DGpfyvaYVRqnm6J3d` |
| ICON-DHASH | `69f0b4d2eadae868` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_098_28747961
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0"
    family = "CoinMiner"
    file_name = "287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0.exe"
    file_type = "exe"
    first_seen = "2026-10-28 01:28:15"
  condition:
    hash.sha256(0, filesize) == "287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0"
}
```

### Sample 99: `945fb0492e3bd25e`

| Field | Value |
|---|---|
| SHA-256 | `945fb0492e3bd25e0fb1f709c97c6e76d123e1696ddee60b0ce9c6381086d36b` |
| Family label | `SalatStealer` |
| File name | `68d0fb10c960b98f.bin` |
| File type | `exe` |
| First seen | `2026-10-28 01:26:15` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c55362cb474173f7c505057cd69dcff` |
| SHA-1 | `045ebb14749dd5b5f9ca252fdae7367c3fbc3af9` |
| SHA-256 | `945fb0492e3bd25e0fb1f709c97c6e76d123e1696ddee60b0ce9c6381086d36b` |
| SHA3-384 | `d3c17a54ef90ff64f264ed679adf72ed8f8a40cb8f1da103ab73d0f66011788b5be804ed30fa187d96d9c77c2ff0383e` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A0C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_099_945fb049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "945fb0492e3bd25e0fb1f709c97c6e76d123e1696ddee60b0ce9c6381086d36b"
    family = "SalatStealer"
    file_name = "68d0fb10c960b98f.bin"
    file_type = "exe"
    first_seen = "2026-10-28 01:26:15"
  condition:
    hash.sha256(0, filesize) == "945fb0492e3bd25e0fb1f709c97c6e76d123e1696ddee60b0ce9c6381086d36b"
}
```

### Sample 100: `f0defb7afeac53d8`

| Field | Value |
|---|---|
| SHA-256 | `f0defb7afeac53d86f98f8fd1e740fce38f460d4ade8165fca65e0c79ed24363` |
| Family label | `SalatStealer` |
| File name | `f075a49217b38786.bin` |
| File type | `exe` |
| First seen | `2026-10-28 01:26:00` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afbce2857f57d6a7e15b5f99e6619a0c` |
| SHA-1 | `866755089f0b2926d8f0763ce93af3c06d00d489` |
| SHA-256 | `f0defb7afeac53d86f98f8fd1e740fce38f460d4ade8165fca65e0c79ed24363` |
| SHA3-384 | `22a5ddcacad7b4cd582e7b300ece8d9e6f5c1d2d68ddf36f40b06b99c599f89f707baa3f44fd8320b40da93372a0c3ea` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T103C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+G:yBkKr5rszpNDy+G` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_100_f0defb7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0defb7afeac53d86f98f8fd1e740fce38f460d4ade8165fca65e0c79ed24363"
    family = "SalatStealer"
    file_name = "f075a49217b38786.bin"
    file_type = "exe"
    first_seen = "2026-10-28 01:26:00"
  condition:
    hash.sha256(0, filesize) == "f0defb7afeac53d86f98f8fd1e740fce38f460d4ade8165fca65e0c79ed24363"
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
 * Generated: 2026-10-28T05:54:08.531720+00:00
 */

rule MalwareBazaar_unknown_001_ac548fda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7"
    family = "unknown"
    file_name = "ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7.elf"
    file_type = "elf"
    first_seen = "2026-10-28 05:53:15"
  condition:
    hash.sha256(0, filesize) == "ac548fda4f1cffc02123cc9bcdefed56fcd0e63090b957b38d81d2673a56f3f7"
}

rule MalwareBazaar_unknown_002_7c5dcda6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3"
    family = "unknown"
    file_name = "7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:45"
  condition:
    hash.sha256(0, filesize) == "7c5dcda6d5ed9aca6de35f365b1c592b08b8aa7897cd9c2c04d0537609d281f3"
}

rule MalwareBazaar_unknown_003_12fcb09c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695"
    family = "unknown"
    file_name = "12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:40"
  condition:
    hash.sha256(0, filesize) == "12fcb09c83e233ecdce291ee80daffb51d6d0c38fb508e5a949281a808e1e695"
}

rule MalwareBazaar_unknown_004_78a70d90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7"
    family = "unknown"
    file_name = "78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:36"
  condition:
    hash.sha256(0, filesize) == "78a70d90cdb6b37fd584e0e8cc60dfbe75b65a6bfad8f2a58416748e22b810d7"
}

rule MalwareBazaar_unknown_005_8c5afc29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7"
    family = "unknown"
    file_name = "8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:32"
  condition:
    hash.sha256(0, filesize) == "8c5afc29edbe22b4abd231af41276febfe04a38f39780bbd07477062f18ff7f7"
}

rule MalwareBazaar_Mirai_006_61c16cac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db"
    family = "Mirai"
    file_name = "61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:18"
  condition:
    hash.sha256(0, filesize) == "61c16cac594f7827510cf4c7c18e84ea42b69157e69d0397fb46886b838325db"
}

rule MalwareBazaar_Mirai_007_ca792979
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b"
    family = "Mirai"
    file_name = "ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:13"
  condition:
    hash.sha256(0, filesize) == "ca7929791d818cc4e20bdf4879a10a00af7e3aad1af858e74cfced026ac4ef8b"
}

rule MalwareBazaar_Mirai_008_59fd01a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e"
    family = "Mirai"
    file_name = "59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:08"
  condition:
    hash.sha256(0, filesize) == "59fd01a3738cf09afd03b7ff5323302532f2d141a90a582b940527f2f53dd04e"
}

rule MalwareBazaar_Mirai_009_7e8758eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da"
    family = "Mirai"
    file_name = "7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:34:03"
  condition:
    hash.sha256(0, filesize) == "7e8758ebe49cdac437c9acdf3e90b67c8ad4bbb0d453de3363d931b3eea2d1da"
}

rule MalwareBazaar_Mirai_010_a86b362e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b"
    family = "Mirai"
    file_name = "a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:33:58"
  condition:
    hash.sha256(0, filesize) == "a86b362e490613b3d0605fc4f10cc0c5522fb875450c45bf6c9574ae1ac7123b"
}

rule MalwareBazaar_Mirai_011_9f7050c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9"
    family = "Mirai"
    file_name = "9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:33:54"
  condition:
    hash.sha256(0, filesize) == "9f7050c6acb26c7307dbdff36a717baf8b075e0120a342356fe3b17a32c374a9"
}

rule MalwareBazaar_Mirai_012_5418fcbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094"
    family = "Mirai"
    file_name = "5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094.bin"
    file_type = "elf"
    first_seen = "2026-10-28 05:33:49"
  condition:
    hash.sha256(0, filesize) == "5418fcbc94234135b6558b24d8edb728623b6c019b801d6f9fd93a29c985d094"
}

rule MalwareBazaar_Mirai_013_2c0167ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c0167ce11b750143df49f1c55dd24090c66003a267e1a5d915f1e7acaf8ddd9"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-28 05:13:18"
  condition:
    hash.sha256(0, filesize) == "2c0167ce11b750143df49f1c55dd24090c66003a267e1a5d915f1e7acaf8ddd9"
}

rule MalwareBazaar_unknown_014_b9a89b50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9a89b50f1d73a22363c408643e9572c2b60b5d88220c72d10a2050866e9a0aa"
    family = "unknown"
    file_name = "z17nfe_calcgraf_informatica_e_consultoria_ltda.vbs"
    file_type = "vbs"
    first_seen = "2026-10-28 05:01:18"
  condition:
    hash.sha256(0, filesize) == "b9a89b50f1d73a22363c408643e9572c2b60b5d88220c72d10a2050866e9a0aa"
}

rule MalwareBazaar_SalatStealer_015_3c4365a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c4365a3691a6059377ae369468b91364efd56fd829f6974406155e6a5000289"
    family = "SalatStealer"
    file_name = "aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:54:30"
  condition:
    hash.sha256(0, filesize) == "3c4365a3691a6059377ae369468b91364efd56fd829f6974406155e6a5000289"
}

rule MalwareBazaar_SalatStealer_016_a9a4ff6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9a4ff6d4f4a268709fcdbf6f92812d2fe5bafb79091c2dd951ecd6ddda3353b"
    family = "SalatStealer"
    file_name = "9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:54:22"
  condition:
    hash.sha256(0, filesize) == "a9a4ff6d4f4a268709fcdbf6f92812d2fe5bafb79091c2dd951ecd6ddda3353b"
}

rule MalwareBazaar_SalatStealer_017_aa0b71e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676"
    family = "SalatStealer"
    file_name = "aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:53:23"
  condition:
    hash.sha256(0, filesize) == "aa0b71e4b729b985daa382f3ee2e28dd33b9556e2971554fc55a2ec047282676"
}

rule MalwareBazaar_SalatStealer_018_9d9e8dd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b"
    family = "SalatStealer"
    file_name = "9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:53:15"
  condition:
    hash.sha256(0, filesize) == "9d9e8dd3f2722379ef3774e6ca015cc7081e07b66384ac9a920746da203fe85b"
}

rule MalwareBazaar_unknown_019_86a05d09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86a05d09d28118a71bf3c7dbdf75b489c719196f533d9c9afa7a82ec7b94b6b6"
    family = "unknown"
    file_name = "splsh4"
    file_type = "elf"
    first_seen = "2026-10-28 04:38:22"
  condition:
    hash.sha256(0, filesize) == "86a05d09d28118a71bf3c7dbdf75b489c719196f533d9c9afa7a82ec7b94b6b6"
}

rule MalwareBazaar_SalatStealer_020_0841b467
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0841b4670b41bcbe18f8f9ddab82452e5d8b520a28450588188683c088f9dc84"
    family = "SalatStealer"
    file_name = "236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:34:25"
  condition:
    hash.sha256(0, filesize) == "0841b4670b41bcbe18f8f9ddab82452e5d8b520a28450588188683c088f9dc84"
}

rule MalwareBazaar_SalatStealer_021_236531d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80"
    family = "SalatStealer"
    file_name = "236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80.exe"
    file_type = "exe"
    first_seen = "2026-10-28 04:33:27"
  condition:
    hash.sha256(0, filesize) == "236531d8f7ef3ff832a84b8d8d14c705e170a928f7a674b8646022ccc6e6ec80"
}

rule MalwareBazaar_SalatStealer_022_827cc245
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "827cc24586574e26e93fcf02b31c1b510af2d00a1497d617206e208ef9019470"
    family = "SalatStealer"
    file_name = "ad27629e028c8e53.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:27:34"
  condition:
    hash.sha256(0, filesize) == "827cc24586574e26e93fcf02b31c1b510af2d00a1497d617206e208ef9019470"
}

rule MalwareBazaar_SalatStealer_023_17a29bd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17a29bd3e29162db7116a19f8998f8da888849f8352a9d701bcb0b8d21f8f92a"
    family = "SalatStealer"
    file_name = "facec362d36d153b.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:27:27"
  condition:
    hash.sha256(0, filesize) == "17a29bd3e29162db7116a19f8998f8da888849f8352a9d701bcb0b8d21f8f92a"
}

rule MalwareBazaar_SalatStealer_024_620e76ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "620e76aba9c35b980150339578bd7126b1044e76f7e4402097b8f1320507665a"
    family = "SalatStealer"
    file_name = "99e0b6dea820607e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:26:40"
  condition:
    hash.sha256(0, filesize) == "620e76aba9c35b980150339578bd7126b1044e76f7e4402097b8f1320507665a"
}

rule MalwareBazaar_SalatStealer_025_70a362e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70a362e93f81af408809b14693f2cbf018e895902a5cfa92c59f79317de229f4"
    family = "SalatStealer"
    file_name = "cc111f672b2fce00.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:26:27"
  condition:
    hash.sha256(0, filesize) == "70a362e93f81af408809b14693f2cbf018e895902a5cfa92c59f79317de229f4"
}

rule MalwareBazaar_SalatStealer_026_3f4b07ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f4b07ff57290ace38836d65cc29d373614ec928f7640cefa32e31d694b7c175"
    family = "SalatStealer"
    file_name = "f9bc72da6f6d1ac8.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:59"
  condition:
    hash.sha256(0, filesize) == "3f4b07ff57290ace38836d65cc29d373614ec928f7640cefa32e31d694b7c175"
}

rule MalwareBazaar_SalatStealer_027_863b07e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "863b07e707af08201e4bf064eb3a6d2c8b180b6827b22364d35e8d487cc371a3"
    family = "SalatStealer"
    file_name = "289624b2a0a08726.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:54"
  condition:
    hash.sha256(0, filesize) == "863b07e707af08201e4bf064eb3a6d2c8b180b6827b22364d35e8d487cc371a3"
}

rule MalwareBazaar_SalatStealer_028_12fc49e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12fc49e9953f19fe26d2931e26ef0ed8f526f656c05f3feadb7bec38883eed98"
    family = "SalatStealer"
    file_name = "35e96ca150b108a1.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:46"
  condition:
    hash.sha256(0, filesize) == "12fc49e9953f19fe26d2931e26ef0ed8f526f656c05f3feadb7bec38883eed98"
}

rule MalwareBazaar_SalatStealer_029_ad27629e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad27629e028c8e531fd2fc9659ef67ba0b623518b2902aee544b46dee9f89134"
    family = "SalatStealer"
    file_name = "ad27629e028c8e53.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:45"
  condition:
    hash.sha256(0, filesize) == "ad27629e028c8e531fd2fc9659ef67ba0b623518b2902aee544b46dee9f89134"
}

rule MalwareBazaar_SalatStealer_030_105cd340
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "105cd340fb5e161275dc21408d4bcfdb2106046819256f1df5a463471c793ba5"
    family = "SalatStealer"
    file_name = "a3ed80d1b8c2846e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:39"
  condition:
    hash.sha256(0, filesize) == "105cd340fb5e161275dc21408d4bcfdb2106046819256f1df5a463471c793ba5"
}

rule MalwareBazaar_SalatStealer_031_facec362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "facec362d36d153beb30f98abdb1e90c0f8cc79f2ba6489c6a6529934b148487"
    family = "SalatStealer"
    file_name = "facec362d36d153b.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:35"
  condition:
    hash.sha256(0, filesize) == "facec362d36d153beb30f98abdb1e90c0f8cc79f2ba6489c6a6529934b148487"
}

rule MalwareBazaar_SalatStealer_032_99e0b6de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99e0b6dea820607e7d32569ac24fe594091f48aef8889c8078ced0a505ee45a8"
    family = "SalatStealer"
    file_name = "99e0b6dea820607e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:26"
  condition:
    hash.sha256(0, filesize) == "99e0b6dea820607e7d32569ac24fe594091f48aef8889c8078ced0a505ee45a8"
}

rule MalwareBazaar_SalatStealer_033_cc111f67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc111f672b2fce001a3974a4d7f0fe77274ae23604a1302fd335afe6457daf50"
    family = "SalatStealer"
    file_name = "cc111f672b2fce00.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:16"
  condition:
    hash.sha256(0, filesize) == "cc111f672b2fce001a3974a4d7f0fe77274ae23604a1302fd335afe6457daf50"
}

rule MalwareBazaar_SalatStealer_034_f9bc72da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9bc72da6f6d1ac841895da772b2dda58ba2ade288382a89adea90f1cbc9b5be"
    family = "SalatStealer"
    file_name = "f9bc72da6f6d1ac8.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:25:07"
  condition:
    hash.sha256(0, filesize) == "f9bc72da6f6d1ac841895da772b2dda58ba2ade288382a89adea90f1cbc9b5be"
}

rule MalwareBazaar_SalatStealer_035_289624b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "289624b2a0a0872632ee8e37ad2a05db6bf910f95c1e9b2cff193857538828d7"
    family = "SalatStealer"
    file_name = "289624b2a0a08726.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:24:57"
  condition:
    hash.sha256(0, filesize) == "289624b2a0a0872632ee8e37ad2a05db6bf910f95c1e9b2cff193857538828d7"
}

rule MalwareBazaar_SalatStealer_036_35e96ca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e96ca150b108a1976d181aaff6819edcc20b509cbe45940f175622a4937794"
    family = "SalatStealer"
    file_name = "35e96ca150b108a1.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:24:48"
  condition:
    hash.sha256(0, filesize) == "35e96ca150b108a1976d181aaff6819edcc20b509cbe45940f175622a4937794"
}

rule MalwareBazaar_SalatStealer_037_a3ed80d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3ed80d1b8c2846ed66d1ea2937b30b403dd4331fe2b9f46517f48e675838f51"
    family = "SalatStealer"
    file_name = "a3ed80d1b8c2846e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 04:24:39"
  condition:
    hash.sha256(0, filesize) == "a3ed80d1b8c2846ed66d1ea2937b30b403dd4331fe2b9f46517f48e675838f51"
}

rule MalwareBazaar_unknown_038_acd2e787
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc"
    family = "unknown"
    file_name = "macho_acd2e7872edb.bin"
    file_type = "macho"
    first_seen = "2026-10-28 04:24:29"
  condition:
    hash.sha256(0, filesize) == "acd2e7872edb9612a92e835bd243a83d185407e1680dea2e70845620874ff1dc"
}

rule MalwareBazaar_ConnectWise_039_46b5e536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907"
    family = "ConnectWise"
    file_name = "46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907.msi"
    file_type = "msi"
    first_seen = "2026-10-28 04:24:03"
  condition:
    hash.sha256(0, filesize) == "46b5e5360b677c411999085a3efadc20637254ffcdb190477dce690116dee907"
}

rule MalwareBazaar_unknown_040_67df067c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67df067cd21dface1cc93f53b7bb20e7efe5d4aed7fd33960ce105a6b3f448f5"
    family = "unknown"
    file_name = "67df067cd21dface_decoded-stage.zsh"
    file_type = "zsh"
    first_seen = "2026-10-28 04:10:16"
  condition:
    hash.sha256(0, filesize) == "67df067cd21dface1cc93f53b7bb20e7efe5d4aed7fd33960ce105a6b3f448f5"
}

rule MalwareBazaar_unknown_041_a91f36a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453"
    family = "unknown"
    file_name = "a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453"
    file_type = "elf"
    first_seen = "2026-10-28 04:00:18"
  condition:
    hash.sha256(0, filesize) == "a91f36a69921e514fad597ae9aac0c04551594b2aabd500440b033dc56a22453"
}

rule MalwareBazaar_unknown_042_a4ab01b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847"
    family = "unknown"
    file_name = "a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847"
    file_type = "elf"
    first_seen = "2026-10-28 04:00:09"
  condition:
    hash.sha256(0, filesize) == "a4ab01b4d1fc873330ad1da14e628dfdc03d8e1b1903cf58c4860e6929dd5847"
}

rule MalwareBazaar_unknown_043_b9801e02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9801e021eb76af73f22da5f78130998d08376a111dde32b4f121216efde255c"
    family = "unknown"
    file_name = "z1nfe_fxo_servicos_de_informatica_ltda.vbs"
    file_type = "vbs"
    first_seen = "2026-10-28 04:00:06"
  condition:
    hash.sha256(0, filesize) == "b9801e021eb76af73f22da5f78130998d08376a111dde32b4f121216efde255c"
}

rule MalwareBazaar_Mirai_044_ff33bc87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff33bc871d0f05d3049b84dee6edd44a9d761395a0617d09d6216adcb6b0bbc8"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-28 03:47:01"
  condition:
    hash.sha256(0, filesize) == "ff33bc871d0f05d3049b84dee6edd44a9d761395a0617d09d6216adcb6b0bbc8"
}

rule MalwareBazaar_SalatStealer_045_e98a383f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e98a383f2ac8c34b44c2fdf33790b3fec6123320c5dd38004cd29ca657d8e4bd"
    family = "SalatStealer"
    file_name = "2610a90206fc62d1.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:27:54"
  condition:
    hash.sha256(0, filesize) == "e98a383f2ac8c34b44c2fdf33790b3fec6123320c5dd38004cd29ca657d8e4bd"
}

rule MalwareBazaar_SalatStealer_046_5102c6ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5102c6aea1d4f788bce14dd58632d813e5edb19dd06f627d52a8637e7209114e"
    family = "SalatStealer"
    file_name = "acb38f8ad036f246.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:27:48"
  condition:
    hash.sha256(0, filesize) == "5102c6aea1d4f788bce14dd58632d813e5edb19dd06f627d52a8637e7209114e"
}

rule MalwareBazaar_SalatStealer_047_8211cd8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8211cd8cc3b4ec950d4b85330b0e3cbe9566c7098cf4a8e36faf127924720831"
    family = "SalatStealer"
    file_name = "877aa9afadd04a38.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:27:26"
  condition:
    hash.sha256(0, filesize) == "8211cd8cc3b4ec950d4b85330b0e3cbe9566c7098cf4a8e36faf127924720831"
}

rule MalwareBazaar_SalatStealer_048_0f8704e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f8704e6b74bf56c42f2a011f609d4ecb296869dff9da7eedaa0d3ef832989f7"
    family = "SalatStealer"
    file_name = "4d875a161b1955be.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:59"
  condition:
    hash.sha256(0, filesize) == "0f8704e6b74bf56c42f2a011f609d4ecb296869dff9da7eedaa0d3ef832989f7"
}

rule MalwareBazaar_SalatStealer_049_e92dbab8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e92dbab84f2499820739a972236fc9fffccb9be6fb104baced5d44073e72fa80"
    family = "SalatStealer"
    file_name = "14cf458f75226509.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:50"
  condition:
    hash.sha256(0, filesize) == "e92dbab84f2499820739a972236fc9fffccb9be6fb104baced5d44073e72fa80"
}

rule MalwareBazaar_SalatStealer_050_7194f0ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7194f0ca6291b43289f9be23323efaf30ebf303d26f0d141c2fdc10b78e446d9"
    family = "SalatStealer"
    file_name = "3c894e6611902696.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:44"
  condition:
    hash.sha256(0, filesize) == "7194f0ca6291b43289f9be23323efaf30ebf303d26f0d141c2fdc10b78e446d9"
}

rule MalwareBazaar_SalatStealer_051_c4fc3e23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4fc3e23a6bd979cbaa5e275e4af667b35b84c304bb0e89375b467959379f0c3"
    family = "SalatStealer"
    file_name = "f22b60b7ca8a8f52.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:35"
  condition:
    hash.sha256(0, filesize) == "c4fc3e23a6bd979cbaa5e275e4af667b35b84c304bb0e89375b467959379f0c3"
}

rule MalwareBazaar_SalatStealer_052_2610a902
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2610a90206fc62d150006f26f527b36e06b634805f33bd6b7e0dd4c0864c3c16"
    family = "SalatStealer"
    file_name = "2610a90206fc62d1.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:32"
  condition:
    hash.sha256(0, filesize) == "2610a90206fc62d150006f26f527b36e06b634805f33bd6b7e0dd4c0864c3c16"
}

rule MalwareBazaar_SalatStealer_053_c661bc69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c661bc6971ae777bfcbdf418c9355bc9a823e1a79bcd58a11f014fd3da7993ec"
    family = "SalatStealer"
    file_name = "2fe07b45c805f46f.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:29"
  condition:
    hash.sha256(0, filesize) == "c661bc6971ae777bfcbdf418c9355bc9a823e1a79bcd58a11f014fd3da7993ec"
}

rule MalwareBazaar_SalatStealer_054_acb38f8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acb38f8ad036f246caa281820acc989728cdcf12a86598f3eb815fc188b50d3e"
    family = "SalatStealer"
    file_name = "acb38f8ad036f246.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:23"
  condition:
    hash.sha256(0, filesize) == "acb38f8ad036f246caa281820acc989728cdcf12a86598f3eb815fc188b50d3e"
}

rule MalwareBazaar_SalatStealer_055_877aa9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "877aa9afadd04a380d2b00bdeb1c40d0163939f2648d6119eb02048a043dd7ed"
    family = "SalatStealer"
    file_name = "877aa9afadd04a38.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:13"
  condition:
    hash.sha256(0, filesize) == "877aa9afadd04a380d2b00bdeb1c40d0163939f2648d6119eb02048a043dd7ed"
}

rule MalwareBazaar_SalatStealer_056_4d875a16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d875a161b1955be1c69eb28a440de92f30edd4f30fe0fc3dabf49d858279056"
    family = "SalatStealer"
    file_name = "4d875a161b1955be.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:26:04"
  condition:
    hash.sha256(0, filesize) == "4d875a161b1955be1c69eb28a440de92f30edd4f30fe0fc3dabf49d858279056"
}

rule MalwareBazaar_SalatStealer_057_14cf458f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14cf458f7522650981b6d7e9d0c81a90ca776dd99e7b75da08ee869da646294b"
    family = "SalatStealer"
    file_name = "14cf458f75226509.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:54"
  condition:
    hash.sha256(0, filesize) == "14cf458f7522650981b6d7e9d0c81a90ca776dd99e7b75da08ee869da646294b"
}

rule MalwareBazaar_SalatStealer_058_3c894e66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c894e661190269657300ba3fb0f736e0d81b8291fc5116a3f7aef561798fb00"
    family = "SalatStealer"
    file_name = "3c894e6611902696.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:45"
  condition:
    hash.sha256(0, filesize) == "3c894e661190269657300ba3fb0f736e0d81b8291fc5116a3f7aef561798fb00"
}

rule MalwareBazaar_unknown_059_625eda1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8"
    family = "unknown"
    file_name = "625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8.exe"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:38"
  condition:
    hash.sha256(0, filesize) == "625eda1fbc4e313f0d8e744b856968468d5315abf1315ef0e5cbe1516349b3f8"
}

rule MalwareBazaar_SalatStealer_060_f22b60b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f22b60b7ca8a8f5204630da7340ad6f1886479d759e116b0fada583e82fa9782"
    family = "SalatStealer"
    file_name = "f22b60b7ca8a8f52.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:35"
  condition:
    hash.sha256(0, filesize) == "f22b60b7ca8a8f5204630da7340ad6f1886479d759e116b0fada583e82fa9782"
}

rule MalwareBazaar_SalatStealer_061_2fe07b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fe07b45c805f46f45c6c5bcadb6812e6974968d9f8d3d5150c0bac7b34cc0c5"
    family = "SalatStealer"
    file_name = "2fe07b45c805f46f.bin"
    file_type = "exe"
    first_seen = "2026-10-28 03:25:25"
  condition:
    hash.sha256(0, filesize) == "2fe07b45c805f46f45c6c5bcadb6812e6974968d9f8d3d5150c0bac7b34cc0c5"
}

rule MalwareBazaar_unknown_062_529f2e3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15"
    family = "unknown"
    file_name = "529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15.elf"
    file_type = "elf"
    first_seen = "2026-10-28 03:18:17"
  condition:
    hash.sha256(0, filesize) == "529f2e3b53f4dce8282dd8d64811ad05b878b0e79cea352027153dd81f1d5b15"
}

rule MalwareBazaar_Mirai_063_5eb80481
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5eb8048165e5151b53c770f0feb0a7a5b8c61b695f5ea0dad1f4a1dee7c43921"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-28 03:06:21"
  condition:
    hash.sha256(0, filesize) == "5eb8048165e5151b53c770f0feb0a7a5b8c61b695f5ea0dad1f4a1dee7c43921"
}

rule MalwareBazaar_unknown_064_b6d267ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6d267ca64c2c4dbb53138794f7e0694a926a4a99e3ba38b71546a83adcfd9eb"
    family = "unknown"
    file_name = "jklx86"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:26"
  condition:
    hash.sha256(0, filesize) == "b6d267ca64c2c4dbb53138794f7e0694a926a4a99e3ba38b71546a83adcfd9eb"
}

rule MalwareBazaar_Mirai_065_1b9b1623
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9b1623b3fb809ad58da971475ddfb8c6421dfc6459450d313f5aa3aa5f47db"
    family = "Mirai"
    file_name = "jklspc"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:22"
  condition:
    hash.sha256(0, filesize) == "1b9b1623b3fb809ad58da971475ddfb8c6421dfc6459450d313f5aa3aa5f47db"
}

rule MalwareBazaar_Mirai_066_478ef62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "478ef62c5a9c90b25940d000215e3a61013d9aca52184dfdde067c5b1d0fd157"
    family = "Mirai"
    file_name = "jklsh4"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:21"
  condition:
    hash.sha256(0, filesize) == "478ef62c5a9c90b25940d000215e3a61013d9aca52184dfdde067c5b1d0fd157"
}

rule MalwareBazaar_Mirai_067_e852ad29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e852ad29f1c5caa101a294ac4583c2b788cc282a662709253457b91b7b72269e"
    family = "Mirai"
    file_name = "jklppc"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:21"
  condition:
    hash.sha256(0, filesize) == "e852ad29f1c5caa101a294ac4583c2b788cc282a662709253457b91b7b72269e"
}

rule MalwareBazaar_unknown_068_74e8f45a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74e8f45a9112369342084413575e7ffbb3ae1c864f5362e61ed36e2ba578ae4a"
    family = "unknown"
    file_name = "jklmpsl"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:21"
  condition:
    hash.sha256(0, filesize) == "74e8f45a9112369342084413575e7ffbb3ae1c864f5362e61ed36e2ba578ae4a"
}

rule MalwareBazaar_unknown_069_f6b082b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6b082b40807012f5b9812e4952110f2c73b53eb97664aa3067e2f69a57848bf"
    family = "unknown"
    file_name = "jklmips"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:20"
  condition:
    hash.sha256(0, filesize) == "f6b082b40807012f5b9812e4952110f2c73b53eb97664aa3067e2f69a57848bf"
}

rule MalwareBazaar_unknown_070_049326ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049326ac87a62f1ea6f88d0b766bd0855ce2f48d781aa04a6679d0f35bc387aa"
    family = "unknown"
    file_name = "jklm68k"
    file_type = "elf"
    first_seen = "2026-10-28 02:49:20"
  condition:
    hash.sha256(0, filesize) == "049326ac87a62f1ea6f88d0b766bd0855ce2f48d781aa04a6679d0f35bc387aa"
}

rule MalwareBazaar_QuasarRAT_071_eba53e00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eba53e00228211485d5f29ec646f4e2a78b606b1a0516195a2e735649d419ede"
    family = "QuasarRAT"
    file_name = "289fe7df4bde67c9086465ef1096ed4a.exe"
    file_type = "exe"
    first_seen = "2026-10-28 02:45:07"
  condition:
    hash.sha256(0, filesize) == "eba53e00228211485d5f29ec646f4e2a78b606b1a0516195a2e735649d419ede"
}

rule MalwareBazaar_unknown_072_25d0dd96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25d0dd9619dcf939045b31b78d4f3c4227176ed7144e53572dad436711d8c4f9"
    family = "unknown"
    file_name = "Dinamode.vbs"
    file_type = "vbs"
    first_seen = "2026-10-28 02:45:03"
  condition:
    hash.sha256(0, filesize) == "25d0dd9619dcf939045b31b78d4f3c4227176ed7144e53572dad436711d8c4f9"
}

rule MalwareBazaar_SalatStealer_073_4775a4bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4775a4bc9b1569c415b6fe972a8bd611aa67b0e726aa342d1d0b910ae1a56bc0"
    family = "SalatStealer"
    file_name = "f96e1da6bcff41bf.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:27:38"
  condition:
    hash.sha256(0, filesize) == "4775a4bc9b1569c415b6fe972a8bd611aa67b0e726aa342d1d0b910ae1a56bc0"
}

rule MalwareBazaar_SalatStealer_074_bd2613d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd2613d5ee4e574ce3ab806b9173aaf8d19125a418380c095c8dd950585a38f2"
    family = "SalatStealer"
    file_name = "72d644ac1629a373.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:27:27"
  condition:
    hash.sha256(0, filesize) == "bd2613d5ee4e574ce3ab806b9173aaf8d19125a418380c095c8dd950585a38f2"
}

rule MalwareBazaar_SalatStealer_075_ad1dcfa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad1dcfa9f23425b19046fe8fc6fa5f931d3c7b995eabda15a906d9805f73ac77"
    family = "SalatStealer"
    file_name = "3d61e14f06d431d9.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:26:32"
  condition:
    hash.sha256(0, filesize) == "ad1dcfa9f23425b19046fe8fc6fa5f931d3c7b995eabda15a906d9805f73ac77"
}

rule MalwareBazaar_SalatStealer_076_56f5cea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56f5cea579c701d705a6845e9da4cbc3c590d95ee613c0a57e8cc6c3285837fe"
    family = "SalatStealer"
    file_name = "f03f2348f8a567fb.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:26:09"
  condition:
    hash.sha256(0, filesize) == "56f5cea579c701d705a6845e9da4cbc3c590d95ee613c0a57e8cc6c3285837fe"
}

rule MalwareBazaar_SalatStealer_077_c02ad52f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c02ad52f440b82a9d2e2abb27e5fc0bd1900b1f527b1478e350e65937b257c73"
    family = "SalatStealer"
    file_name = "6f24c1175f940d89.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:58"
  condition:
    hash.sha256(0, filesize) == "c02ad52f440b82a9d2e2abb27e5fc0bd1900b1f527b1478e350e65937b257c73"
}

rule MalwareBazaar_SalatStealer_078_eed2564c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eed2564c5812458458350371b70b232a0da1b415127bc2146135f8421776faea"
    family = "SalatStealer"
    file_name = "a04a8a3490737f32.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:51"
  condition:
    hash.sha256(0, filesize) == "eed2564c5812458458350371b70b232a0da1b415127bc2146135f8421776faea"
}

rule MalwareBazaar_SalatStealer_079_79138e57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79138e57f432ac8e0a450066e9aa432fe41366ba5a5966512a9c07d56c7b1b4f"
    family = "SalatStealer"
    file_name = "3237f0d9b05d332e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:42"
  condition:
    hash.sha256(0, filesize) == "79138e57f432ac8e0a450066e9aa432fe41366ba5a5966512a9c07d56c7b1b4f"
}

rule MalwareBazaar_SalatStealer_080_f96e1da6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f96e1da6bcff41bfd857fc0ebed69239dbc5c7d28f546e5743c80e73646cb901"
    family = "SalatStealer"
    file_name = "f96e1da6bcff41bf.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:36"
  condition:
    hash.sha256(0, filesize) == "f96e1da6bcff41bfd857fc0ebed69239dbc5c7d28f546e5743c80e73646cb901"
}

rule MalwareBazaar_SalatStealer_081_96ffebed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96ffebedca2b15a742a001d533fb9857d9339494ddcd5521510fa6024e0cb855"
    family = "SalatStealer"
    file_name = "37a5b3cfde85c087.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:35"
  condition:
    hash.sha256(0, filesize) == "96ffebedca2b15a742a001d533fb9857d9339494ddcd5521510fa6024e0cb855"
}

rule MalwareBazaar_SalatStealer_082_72d644ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d644ac1629a37306a5591ee27eebcd68893180854c5650a0b9732b91724b60"
    family = "SalatStealer"
    file_name = "72d644ac1629a373.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:27"
  condition:
    hash.sha256(0, filesize) == "72d644ac1629a37306a5591ee27eebcd68893180854c5650a0b9732b91724b60"
}

rule MalwareBazaar_SalatStealer_083_3d61e14f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d61e14f06d431d9b0e409ce64c9be543ea9f7d0fb18d0d444037360c62309dd"
    family = "SalatStealer"
    file_name = "3d61e14f06d431d9.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:17"
  condition:
    hash.sha256(0, filesize) == "3d61e14f06d431d9b0e409ce64c9be543ea9f7d0fb18d0d444037360c62309dd"
}

rule MalwareBazaar_SalatStealer_084_f03f2348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f03f2348f8a567fb3a8edef1ffc7b000416c04d4c3b2730ec66b0dd24f0ce355"
    family = "SalatStealer"
    file_name = "f03f2348f8a567fb.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:25:07"
  condition:
    hash.sha256(0, filesize) == "f03f2348f8a567fb3a8edef1ffc7b000416c04d4c3b2730ec66b0dd24f0ce355"
}

rule MalwareBazaar_SalatStealer_085_6f24c117
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f24c1175f940d89064bd78d860d7038236cf83001e22531bc1c2856abe43b6a"
    family = "SalatStealer"
    file_name = "6f24c1175f940d89.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:57"
  condition:
    hash.sha256(0, filesize) == "6f24c1175f940d89064bd78d860d7038236cf83001e22531bc1c2856abe43b6a"
}

rule MalwareBazaar_SalatStealer_086_a04a8a34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a04a8a3490737f3259a856a19ec8b8f818c00608ee75d7a50e68c9a06adff9fb"
    family = "SalatStealer"
    file_name = "a04a8a3490737f32.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:47"
  condition:
    hash.sha256(0, filesize) == "a04a8a3490737f3259a856a19ec8b8f818c00608ee75d7a50e68c9a06adff9fb"
}

rule MalwareBazaar_SalatStealer_087_3237f0d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3237f0d9b05d332e99b52ff405efa59f429311ab12ac1a2f73fbf62794171364"
    family = "SalatStealer"
    file_name = "3237f0d9b05d332e.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:37"
  condition:
    hash.sha256(0, filesize) == "3237f0d9b05d332e99b52ff405efa59f429311ab12ac1a2f73fbf62794171364"
}

rule MalwareBazaar_SalatStealer_088_37a5b3cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37a5b3cfde85c08764d469a15cc0db30468790fe1cd874ca352cef3118be18c7"
    family = "SalatStealer"
    file_name = "37a5b3cfde85c087.bin"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:28"
  condition:
    hash.sha256(0, filesize) == "37a5b3cfde85c08764d469a15cc0db30468790fe1cd874ca352cef3118be18c7"
}

rule MalwareBazaar_AgentTesla_089_1d86622d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d86622d46ef87c4d2db72a031b7e927d31363e72e0fd4c95c69f23da5f3b9e1"
    family = "AgentTesla"
    file_name = "ENQUIRY SASPRMAT26090237 (997-SP30).pif"
    file_type = "exe"
    first_seen = "2026-10-28 02:24:26"
  condition:
    hash.sha256(0, filesize) == "1d86622d46ef87c4d2db72a031b7e927d31363e72e0fd4c95c69f23da5f3b9e1"
}

rule MalwareBazaar_unknown_090_bcca4890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829"
    family = "unknown"
    file_name = "bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829.exe"
    file_type = "exe"
    first_seen = "2026-10-28 02:23:19"
  condition:
    hash.sha256(0, filesize) == "bcca48907156b96e3baee96b2bbbeb196ca885ceb2c5e818cc0811e6c8c86829"
}

rule MalwareBazaar_unknown_091_ed91a6cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7"
    family = "unknown"
    file_name = "ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7.exe"
    file_type = "exe"
    first_seen = "2026-10-28 02:23:13"
  condition:
    hash.sha256(0, filesize) == "ed91a6cf7e6414f1e03a9d4b88b26f2f107d0613ba7d759c168618b681d89ab7"
}

rule MalwareBazaar_unknown_092_1fbdd925
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fbdd925143e28ea6542bcc3b15cd44de7c0b226082f6f99450f0e1822db2068"
    family = "unknown"
    file_name = "macho_1fbdd925143e.bin"
    file_type = "macho"
    first_seen = "2026-10-28 02:15:36"
  condition:
    hash.sha256(0, filesize) == "1fbdd925143e28ea6542bcc3b15cd44de7c0b226082f6f99450f0e1822db2068"
}

rule MalwareBazaar_unknown_093_358521ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de"
    family = "unknown"
    file_name = "358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de"
    file_type = "exe"
    first_seen = "2026-10-28 02:15:08"
  condition:
    hash.sha256(0, filesize) == "358521ef5d11b5220119212dbb2e166bf192c36657f147a4091eb4473a7b20de"
}

rule MalwareBazaar_Mirai_094_a573d2eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a573d2eb7adc9558e63591fbf3e9d5db5afe5bb4f87e5ecd6baf91e8ebf38a70"
    family = "Mirai"
    file_name = "splarm7"
    file_type = "elf"
    first_seen = "2026-10-28 01:58:15"
  condition:
    hash.sha256(0, filesize) == "a573d2eb7adc9558e63591fbf3e9d5db5afe5bb4f87e5ecd6baf91e8ebf38a70"
}

rule MalwareBazaar_Mirai_095_8e442d81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e442d817d771957101f4e6f08826e231a0273634dfccec774b5eb354c684e09"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-28 01:46:26"
  condition:
    hash.sha256(0, filesize) == "8e442d817d771957101f4e6f08826e231a0273634dfccec774b5eb354c684e09"
}

rule MalwareBazaar_Mirai_096_2021308d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2021308de500344f418587206ad03cd3cc1d667a7a356df9c4f3af653765e05a"
    family = "Mirai"
    file_name = "bot-linux-arm64"
    file_type = "elf"
    first_seen = "2026-10-28 01:40:05"
  condition:
    hash.sha256(0, filesize) == "2021308de500344f418587206ad03cd3cc1d667a7a356df9c4f3af653765e05a"
}

rule MalwareBazaar_RemcosRAT_097_bea63659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bea63659c3ff5771c6360280c011c6adefe39b97bfb0671703d32d8c0a66acf8"
    family = "RemcosRAT"
    file_name = "Kronragede.vbs"
    file_type = "vbs"
    first_seen = "2026-10-28 01:35:15"
  condition:
    hash.sha256(0, filesize) == "bea63659c3ff5771c6360280c011c6adefe39b97bfb0671703d32d8c0a66acf8"
}

rule MalwareBazaar_CoinMiner_098_28747961
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0"
    family = "CoinMiner"
    file_name = "287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0.exe"
    file_type = "exe"
    first_seen = "2026-10-28 01:28:15"
  condition:
    hash.sha256(0, filesize) == "287479610fa89ca0bec36a597881a71f5c893c1226422a75bd06105a681abee0"
}

rule MalwareBazaar_SalatStealer_099_945fb049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "945fb0492e3bd25e0fb1f709c97c6e76d123e1696ddee60b0ce9c6381086d36b"
    family = "SalatStealer"
    file_name = "68d0fb10c960b98f.bin"
    file_type = "exe"
    first_seen = "2026-10-28 01:26:15"
  condition:
    hash.sha256(0, filesize) == "945fb0492e3bd25e0fb1f709c97c6e76d123e1696ddee60b0ce9c6381086d36b"
}

rule MalwareBazaar_SalatStealer_100_f0defb7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0defb7afeac53d86f98f8fd1e740fce38f460d4ade8165fca65e0c79ed24363"
    family = "SalatStealer"
    file_name = "f075a49217b38786.bin"
    file_type = "exe"
    first_seen = "2026-10-28 01:26:00"
  condition:
    hash.sha256(0, filesize) == "f0defb7afeac53d86f98f8fd1e740fce38f460d4ade8165fca65e0c79ed24363"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

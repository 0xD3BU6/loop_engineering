# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-18

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 599 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 599 |
| Unique family labels | 5 |
| Unique file types | 4 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 52 |
| unknown | 44 |
| Prometei | 2 |
| AgentTesla | 1 |
| WannaCry | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 66 |
| unknown | 13 |
| sh | 11 |
| exe | 10 |

## Per-Sample Analysis

### Sample 1: `b1a20cacc85411c6`

| Field | Value |
|---|---|
| SHA-256 | `b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55` |
| Family label | `Prometei` |
| File name | `b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55` |
| File type | `elf` |
| First seen | `2026-07-18 03:08:45` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `489875327f1f5431f40ad26e8edfa439` |
| SHA-1 | `8e96fc85f4042753387e57d2c493228673c4e230` |
| SHA-256 | `b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55` |
| SHA3-384 | `41eb3fc20fbdf4279bfd7de3f424967082fec4aac24ffdc46d925f862519f7b82cb62ba6c10d7b8c8b3d11e3d08756b0` |
| TLSH | `T190A423B4F9229E8F6DD769B91B24C31DE181D172589D4C2313AE94A34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsd2:Fs6pyCC/Ya2hpi6T6N4g` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_001_b1a20cac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55"
    family = "Prometei"
    file_name = "b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55"
    file_type = "elf"
    first_seen = "2026-07-18 03:08:45"
  condition:
    hash.sha256(0, filesize) == "b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55"
}
```

### Sample 2: `3ef32ae4171c7a2d`

| Field | Value |
|---|---|
| SHA-256 | `3ef32ae4171c7a2da4aab0c7bdc9a31581e9e49365b96ea951f6c06625e0b7d7` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-18 02:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2fc6693306b7808fe77a22113cd238f` |
| SHA-1 | `6506f5da77f44587fc9a9779b7c9233194b15b14` |
| SHA-256 | `3ef32ae4171c7a2da4aab0c7bdc9a31581e9e49365b96ea951f6c06625e0b7d7` |
| SHA3-384 | `5096b028f65ccde51a05b4de23b0a245bba6fc130c513d9f67d82d52904fa22fb278a621145e630bc1adfe815ac5226d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1DEE6334C99F005EDEBB7903CEDE055A2D46874664B72C68F9BA483F02D271D04E3DE6A` |
| SSDEEP | `393216:csRlR402DOKDaCz+rB/KkSxY1XMCHWUjXXcuI3/PGTAI:csjqDcKkm6XMb8XsH/O7` |
| ICON-DHASH | `e86864e0d8e8ec48` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_3ef32ae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ef32ae4171c7a2da4aab0c7bdc9a31581e9e49365b96ea951f6c06625e0b7d7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 02:52:33"
  condition:
    hash.sha256(0, filesize) == "3ef32ae4171c7a2da4aab0c7bdc9a31581e9e49365b96ea951f6c06625e0b7d7"
}
```

### Sample 3: `701a6e782f4d2a96`

| Field | Value |
|---|---|
| SHA-256 | `701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5` |
| Family label | `Prometei` |
| File name | `701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5` |
| File type | `elf` |
| First seen | `2026-07-18 02:49:10` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e975794476871486889659871debff2f` |
| SHA-1 | `0be71e1c736e5f72b1161c68ceca127148fc5b94` |
| SHA-256 | `701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5` |
| SHA3-384 | `6f5658e069e1cfd92403fc56455da8a709a63b69402f8d82d5fb3d5e193bc287c5c81cf260024ae54da00bd367245e0a` |
| TLSH | `T128A423B4F9219E8F6DD769B91B24C31DE182C172589D4C2313AE94E34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdo:Fs6pyCC/Ya2hpi6T6N4G` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_003_701a6e78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5"
    family = "Prometei"
    file_name = "701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5"
    file_type = "elf"
    first_seen = "2026-07-18 02:49:10"
  condition:
    hash.sha256(0, filesize) == "701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5"
}
```

### Sample 4: `73deadaedd02f160`

| Field | Value |
|---|---|
| SHA-256 | `73deadaedd02f160279aca69237debc6a66a46a6401180a12b172be08b0877ee` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 02:45:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32182c7f79ef9e4235667ae68ef7f9b2` |
| SHA-1 | `88946166dffd50c6b15793aa795496e9518abfcd` |
| SHA-256 | `73deadaedd02f160279aca69237debc6a66a46a6401180a12b172be08b0877ee` |
| SHA3-384 | `1deb91eeff952da3e2a879b3ce05fa84c2c7b9f259415f80b5b06e0f9a9c6b534cd1156ea7ba8edbf361facc6d572583` |
| TLSH | `T1B8D312FEE286BD6EC95E4D7E72FBB2E16E96305F7424776B42359E04670888B7023050` |
| SSDEEP | `3072:OyrEp8NpstVuGi2ZBE4YPQ4ulm1VL3cJR0FVR5XHKP4pDFx+g:OwEp8rqVxE4EQ4ugs0FVRtH1pDn+g` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_73deadae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73deadaedd02f160279aca69237debc6a66a46a6401180a12b172be08b0877ee"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 02:45:46"
  condition:
    hash.sha256(0, filesize) == "73deadaedd02f160279aca69237debc6a66a46a6401180a12b172be08b0877ee"
}
```

### Sample 5: `877525407f4b6fea`

| Field | Value |
|---|---|
| SHA-256 | `877525407f4b6feafe8e16b736e9eaad24ef4df2ad142387cc005b3b0fba76f6` |
| Family label | `unknown` |
| File name | `d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65` |
| File type | `elf` |
| First seen | `2026-07-18 02:26:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92517887ba84517087365c3a968b4474` |
| SHA-1 | `acaf4e685fd695d48981bcdab5b331c6c70482d4` |
| SHA-256 | `877525407f4b6feafe8e16b736e9eaad24ef4df2ad142387cc005b3b0fba76f6` |
| SHA3-384 | `3e20148f190965251eac0ccfd237f14dcf83ec6ce5a5ad23753f9841f26a181b1f148a12c01e764f78afdf403492ecf0` |
| TLSH | `T1F5366D4BF1A360FCC1ABC434475B9963B931786901247DBB66D4EA302B33F605B69F62` |
| TELFHASH | `t1ab7286f466e430e0a596c969e7b6b4b0d6730cfa67e1b5b148373d62df94f080d2ac12` |
| SSDEEP | `98304:5vI4TQi3ZyDeOG7ys4nB4Jbg7uH+Kj5blEx6Bceka8TNqK7KSrsmhXHojZ+rgY:HJN4nojw8BCbRhCV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_87752540
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "877525407f4b6feafe8e16b736e9eaad24ef4df2ad142387cc005b3b0fba76f6"
    family = "unknown"
    file_name = "d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65"
    file_type = "elf"
    first_seen = "2026-07-18 02:26:57"
  condition:
    hash.sha256(0, filesize) == "877525407f4b6feafe8e16b736e9eaad24ef4df2ad142387cc005b3b0fba76f6"
}
```

### Sample 6: `1e83be9c9bcc879b`

| Field | Value |
|---|---|
| SHA-256 | `1e83be9c9bcc879bbf68332b8c5b5fb5ab2591ae6098a4ed4fe65aee0780cfac` |
| Family label | `unknown` |
| File name | `51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a` |
| File type | `elf` |
| First seen | `2026-07-18 02:26:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f2923d90252b80cc12adb63a61ee57c` |
| SHA-1 | `76a39f86cdce0bf9371e94c790bc0e557a4c49c1` |
| SHA-256 | `1e83be9c9bcc879bbf68332b8c5b5fb5ab2591ae6098a4ed4fe65aee0780cfac` |
| SHA3-384 | `6a0cdb5bf28ba6d76269321fda6d56ee01adfa5a54197d5d4e4bfb9f213faa1602b4a38eb2f3d451ab95892ffa226faf` |
| TLSH | `T136367D88E793E0F0E66308F0559BD7F761301A355053F6F6EB8A6B65B4323416F093AA` |
| TELFHASH | `t16482a0b3009ca4f9abe09807c36f7174cff6e0e7169069f165e5bcc156b2c936a26934` |
| SSDEEP | `98304:MMFny9W9ty/P8U0bbpjlSGHyW3Eaud/z5R6XOlvSOI5QHQbA:MMFnhjUWySuP8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_1e83be9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e83be9c9bcc879bbf68332b8c5b5fb5ab2591ae6098a4ed4fe65aee0780cfac"
    family = "unknown"
    file_name = "51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a"
    file_type = "elf"
    first_seen = "2026-07-18 02:26:44"
  condition:
    hash.sha256(0, filesize) == "1e83be9c9bcc879bbf68332b8c5b5fb5ab2591ae6098a4ed4fe65aee0780cfac"
}
```

### Sample 7: `7df3cebf5b779a0a`

| Field | Value |
|---|---|
| SHA-256 | `7df3cebf5b779a0a266ca4fdb979fab474223505bfc9a63d27a1ff985ef9fffc` |
| Family label | `unknown` |
| File name | `1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d` |
| File type | `elf` |
| First seen | `2026-07-18 02:26:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f30e4a13e462ab1f0348d5b8acf705f8` |
| SHA-1 | `efd6eb2a650dda0032b29865b591c9b9b638e140` |
| SHA-256 | `7df3cebf5b779a0a266ca4fdb979fab474223505bfc9a63d27a1ff985ef9fffc` |
| SHA3-384 | `96e954c680d471784589577f88ebdbd05d8ddc775e2617e1ea4f3964949f372c44dce700038e2e90922e4be8ad12c640` |
| TLSH | `T1F1167C94ED0F3912F3C7E23CCF4A97E1721B3694E32390B279D2524DD59E9E4C6A2A11` |
| SSDEEP | `98304:hJ6DjeU7AAWLEGnAoTPT9lqYM4Cj8ev+4FWK:hIDjeU7qDnnTKH3L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_7df3cebf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7df3cebf5b779a0a266ca4fdb979fab474223505bfc9a63d27a1ff985ef9fffc"
    family = "unknown"
    file_name = "1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d"
    file_type = "elf"
    first_seen = "2026-07-18 02:26:25"
  condition:
    hash.sha256(0, filesize) == "7df3cebf5b779a0a266ca4fdb979fab474223505bfc9a63d27a1ff985ef9fffc"
}
```

### Sample 8: `bed4780f7c726192`

| Field | Value |
|---|---|
| SHA-256 | `bed4780f7c726192443063214f085b9f93b89f736e25ab17e44c1aa77f667c2f` |
| Family label | `unknown` |
| File name | `049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b` |
| File type | `elf` |
| First seen | `2026-07-18 02:26:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6948f214e3e79d6e4ff27517baa8aa8` |
| SHA-1 | `fd859a43f66cfe5178235599739b6c280dc546e5` |
| SHA-256 | `bed4780f7c726192443063214f085b9f93b89f736e25ab17e44c1aa77f667c2f` |
| SHA3-384 | `db1ed1abb088cb6d97d64ff0cb620bc72945e5925ac190b98d0c4a0282d2f84284770349d233e9cff20ea21b2824e3bc` |
| TLSH | `T1C1065B81FC41CF52C9D02A7BF66E828833530779D2EA70069D255B7467DF99B0F3AA42` |
| TELFHASH | `t19121fe108de82999f3c1b2d950fbb1e9989c2dcec74129f64b16754f1e62ed22061e2f` |
| SSDEEP | `49152:CM+evMmZywCyGTQxjCRMfy5xjBgdxp0J2Apj:CM6mZynMxjC+qC3p0J3pj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_bed4780f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bed4780f7c726192443063214f085b9f93b89f736e25ab17e44c1aa77f667c2f"
    family = "unknown"
    file_name = "049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b"
    file_type = "elf"
    first_seen = "2026-07-18 02:26:03"
  condition:
    hash.sha256(0, filesize) == "bed4780f7c726192443063214f085b9f93b89f736e25ab17e44c1aa77f667c2f"
}
```

### Sample 9: `d45935ba4fc0213c`

| Field | Value |
|---|---|
| SHA-256 | `d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65` |
| Family label | `unknown` |
| File name | `d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65` |
| File type | `elf` |
| First seen | `2026-07-18 02:25:43` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ac48fc25ec684b2cede7adf242b1651` |
| SHA-1 | `0854f2ca4c2a54d4ec932fb64579f3f440e234fe` |
| SHA-256 | `d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65` |
| SHA3-384 | `c12db8a50b7c34899f11b2c71b63c1dd4aeab3bc8b05a79eedb902d29e15143126b001c6fa558b55e6324c743f196f93` |
| TLSH | `T18895332B6E83F089E6C77B8C51EDFB2B9F4B14115B4019AC346CE18D51430E36ED9E9A` |
| SSDEEP | `49152:8QJaWpfEMN5RQSfAkYp3mhb34VSyMUtYbVJrxFddOiugavGezs:fp8M5QmArp3m54kQcrxF7OiugavGezs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_d45935ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65"
    family = "unknown"
    file_name = "d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:43"
  condition:
    hash.sha256(0, filesize) == "d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65"
}
```

### Sample 10: `cd6dc7a2725ad855`

| Field | Value |
|---|---|
| SHA-256 | `cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f` |
| Family label | `unknown` |
| File name | `cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f` |
| File type | `elf` |
| First seen | `2026-07-18 02:25:42` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d6062a9d3e08ea7c9d7ee54139457d0` |
| SHA-1 | `b8828dbaac27f85e408b28af922ce03455ae52d7` |
| SHA-256 | `cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f` |
| SHA3-384 | `3a4507475309f9efa994ca99a7107b80229ccbd1c2a214b0d3a2153b54fb31cd4e7da3bb2bdb31e5379516566f8b3450` |
| TLSH | `T1C08533611A9B65DEEB6F83A533C7C344112718A03AA1995CF817E1B39CB7458B3C7A32` |
| SSDEEP | `24576:gDIQnDTsBV9JTZIkrlNK++DvjPO+tpNcS5SzRRk9fFVcqp7LMZnYuG78qLWYf1MX:qDTsdv2DvjW+tcxNm5J7AOMRU4pSI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_cd6dc7a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f"
    family = "unknown"
    file_name = "cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:42"
  condition:
    hash.sha256(0, filesize) == "cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f"
}
```

### Sample 11: `51228996cf0280ef`

| Field | Value |
|---|---|
| SHA-256 | `51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a` |
| Family label | `unknown` |
| File name | `51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a` |
| File type | `elf` |
| First seen | `2026-07-18 02:25:40` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c556ed940db446c46ac3e92271e10472` |
| SHA-1 | `a59ac1b178deef238cb08df040999786b65ea75b` |
| SHA-256 | `51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a` |
| SHA3-384 | `a2d0b5efc0aeed719cc596e4e1d9fb4740e2687ee842dcb33a24ce21664d0f3ba812b93b05b7b437aa52b8ca3374380d` |
| TLSH | `T1258533DAA21ED2EFF4C3BB37CD4B306917C451D3FA0C607411962A1A5E258DEA99F384` |
| TELFHASH | `t1b8b0024b4905555d51057436c44d254860ca117a3841d257955c4001336b175c36799f` |
| SSDEEP | `49152:g+I2qmR4qgzpORQwvOSfJIPO83/6q8kkUb2Ql:gdekQR1O6JIdP18kkUSG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_51228996
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a"
    family = "unknown"
    file_name = "51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:40"
  condition:
    hash.sha256(0, filesize) == "51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a"
}
```

### Sample 12: `1858c51b58e913ca`

| Field | Value |
|---|---|
| SHA-256 | `1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d` |
| Family label | `unknown` |
| File name | `1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d` |
| File type | `elf` |
| First seen | `2026-07-18 02:25:39` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `055a97568f56cd2a04b43cc3f6cc88c7` |
| SHA-1 | `c9b93c78e6d09da14d693dc7996420d47c0138ab` |
| SHA-256 | `1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d` |
| SHA3-384 | `01959b8cf0891cc94d8c1a47e8b81e96ae77190fedd09c61ab467a32d6363b18f6d19ea8a79cf83e3cc6754b7931bb20` |
| TLSH | `T1E27533FC6207B9B1C5716FA295DFB2194AA4499F3D09AC13E134764082FBB4FC3E6684` |
| SSDEEP | `49152:5HJ+qSGVEiP63/fGKzMMcYbAG2guOviOfvtqD:5cbJim/fGYMMcTGjuOqOntc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_1858c51b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d"
    family = "unknown"
    file_name = "1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:39"
  condition:
    hash.sha256(0, filesize) == "1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d"
}
```

### Sample 13: `049a2ed3406e7c70`

| Field | Value |
|---|---|
| SHA-256 | `049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b` |
| Family label | `unknown` |
| File name | `049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b` |
| File type | `elf` |
| First seen | `2026-07-18 02:25:37` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b66634a4b9445c23eb96c1fe52e72dd8` |
| SHA-1 | `82643cdd009c6074f4e0898fded08a2603a5765f` |
| SHA-256 | `049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b` |
| SHA3-384 | `51b20d051134c73422fe571db54674a94e807376023dd703f7936c1f28b3ea00553d906122f9c28093026656a7883d4f` |
| TLSH | `T1D46533B31FEFC353B5E9189E124D3419F01B5C6AE5DC635A102986362BF23C96726E43` |
| SSDEEP | `24576:PWSbE0vxM6IrReSkipH4idSUS7+XRD0cvDiHPHYq3dPCjg1c0aPqYXQMNkuk3Vgw:uIBxirLdG7+hRv0YyFYg1ctqQJAV5J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_049a2ed3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b"
    family = "unknown"
    file_name = "049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:37"
  condition:
    hash.sha256(0, filesize) == "049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b"
}
```

### Sample 14: `f84fab97acebb6a5`

| Field | Value |
|---|---|
| SHA-256 | `f84fab97acebb6a52e2e839403b8e3a7fe040dcc30e808b6198e02a3621015a8` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-18 02:17:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb8d2d42a44c9b3f8796ccd77ccf4842` |
| SHA-1 | `d2f0b43c27602c9a01682d9b1b8949aae454d956` |
| SHA-256 | `f84fab97acebb6a52e2e839403b8e3a7fe040dcc30e808b6198e02a3621015a8` |
| SHA3-384 | `6b09d139d904262e56c93fed5434c0225662e9f5286809da08f1a617b24e05a8dd9817b7b97d09f5ea1d03c391972d08` |
| TLSH | `T1F001ABCBD650AD00412EAA1EA2A71190B411C3CF164B0FB47F9C292EFF88804B026F98` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha8c1hwqm9jCyeEzGl7:e9Qp+Ms8c16qQjgEql7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_f84fab97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f84fab97acebb6a52e2e839403b8e3a7fe040dcc30e808b6198e02a3621015a8"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-18 02:17:53"
  condition:
    hash.sha256(0, filesize) == "f84fab97acebb6a52e2e839403b8e3a7fe040dcc30e808b6198e02a3621015a8"
}
```

### Sample 15: `ee28d48c9b22e4f0`

| Field | Value |
|---|---|
| SHA-256 | `ee28d48c9b22e4f02b8c61bc98af039df9cda6939b99fb71d9b0fd16e9fba14e` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-07-18 02:06:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e83c3615eac82b11b5e7e3ead73ca9f8` |
| SHA-1 | `b07f7797e0332e402bd747d1c1391c164bc35b2a` |
| SHA-256 | `ee28d48c9b22e4f02b8c61bc98af039df9cda6939b99fb71d9b0fd16e9fba14e` |
| SHA3-384 | `4d4429d1634223b57d68bbe4906f899fe212704a4ad4eceb418dfe69e8059655f5625620f3cd3dfd5bfcb7006b078abd` |
| TLSH | `T125B312B086254F31E120367BCCB8035AB165CFBCF17F3EE679452A75206690E8FC6698` |
| SSDEEP | `3072:0q7fc/RikR3vMA1vfEiYitDAXvmHpXOl20KvI:t4RFtvMivfEiYi4vGI2fvI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_ee28d48c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee28d48c9b22e4f02b8c61bc98af039df9cda6939b99fb71d9b0fd16e9fba14e"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-18 02:06:33"
  condition:
    hash.sha256(0, filesize) == "ee28d48c9b22e4f02b8c61bc98af039df9cda6939b99fb71d9b0fd16e9fba14e"
}
```

### Sample 16: `fe83fd60fa468232`

| Field | Value |
|---|---|
| SHA-256 | `fe83fd60fa4682327eb66a1991685d427054af49f0bf0956546d77acc1f1db6a` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-18 02:03:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b45eac742a1dcd6b9046cb1a7a75e429` |
| SHA-1 | `bcacd420f7a898ae6a2371e38d775e95e3860d78` |
| SHA-256 | `fe83fd60fa4682327eb66a1991685d427054af49f0bf0956546d77acc1f1db6a` |
| SHA3-384 | `0cbc13757dd1b83dbb5b5904a106b4df5fa709c778cd6e944917900e80251635e74bf4f380d348787357ab80f1512649` |
| TLSH | `T16DC313FE8F07221AEBB087B479041FD16B25596729D28889FCD4BC278D81CF17614BDA` |
| SSDEEP | `3072:RTazfnTXMJCm9V4l8BN3S117rMR/Pd3aRXXUaV0:9azfnT8Fkl8f3G3MluXXR0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_fe83fd60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe83fd60fa4682327eb66a1991685d427054af49f0bf0956546d77acc1f1db6a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-18 02:03:03"
  condition:
    hash.sha256(0, filesize) == "fe83fd60fa4682327eb66a1991685d427054af49f0bf0956546d77acc1f1db6a"
}
```

### Sample 17: `296a72481bfbddcf`

| Field | Value |
|---|---|
| SHA-256 | `296a72481bfbddcfc395c8e0ed3b6c3c0489530f8c20c90f60c519c4cb73e3df` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-18 02:03:02` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b0ca49256172bf132a0e168ee289ec9` |
| SHA-1 | `7a6bcb2a919d526c8b008400a3cb98ef790eb97f` |
| SHA-256 | `296a72481bfbddcfc395c8e0ed3b6c3c0489530f8c20c90f60c519c4cb73e3df` |
| SHA3-384 | `dea8bf238ec9e6e88fd760864e3bf81a18bafd863d67eb4e6a3f28f0b766c01d6787f513c36fe59af7af8c0012bd0910` |
| TLSH | `T1D5236C651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCB3CF28C5A69D910971D` |
| SSDEEP | `768:DXRWNGxV89GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:9lxPcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_296a7248
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "296a72481bfbddcfc395c8e0ed3b6c3c0489530f8c20c90f60c519c4cb73e3df"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 02:03:02"
  condition:
    hash.sha256(0, filesize) == "296a72481bfbddcfc395c8e0ed3b6c3c0489530f8c20c90f60c519c4cb73e3df"
}
```

### Sample 18: `f5084fcd2670db2e`

| Field | Value |
|---|---|
| SHA-256 | `f5084fcd2670db2e030285c84e99ed075fc99d22ef64585d61f39ea04391862f` |
| Family label | `Mirai` |
| File name | `tarm5` |
| File type | `elf` |
| First seen | `2026-07-18 01:59:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebc8a7e916fc1849ff7e3074e8e71b2f` |
| SHA-1 | `6ee7f42f9ac9d55b3812f554fc9a3e75f8bb3efb` |
| SHA-256 | `f5084fcd2670db2e030285c84e99ed075fc99d22ef64585d61f39ea04391862f` |
| SHA3-384 | `b3d34087ac3a02cb3a6c5590d04fe88280eb5b89eb265ff158573f68ae87f6e67c9e0011165c2ed3a501f52bddce67d2` |
| TLSH | `T145932BC4BC91A621C7C1167BEE5F018D336697E8D2EA33079D280FA0778A95B0E77705` |
| SSDEEP | `1536:OB6+LcdMNmMT0IUzSoBUhKVFiuTcgAdeLt4xiSDcSP7FGVPxe12ww:OtLcdMMMT0IOfSSFi+cgh6iSjBGhxJww` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_f5084fcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5084fcd2670db2e030285c84e99ed075fc99d22ef64585d61f39ea04391862f"
    family = "Mirai"
    file_name = "tarm5"
    file_type = "elf"
    first_seen = "2026-07-18 01:59:25"
  condition:
    hash.sha256(0, filesize) == "f5084fcd2670db2e030285c84e99ed075fc99d22ef64585d61f39ea04391862f"
}
```

### Sample 19: `f85c795e38bd714f`

| Field | Value |
|---|---|
| SHA-256 | `f85c795e38bd714fd320ce2888c6eb3d445723cd586c3db1411e443fb69edd7f` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-18 01:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e0e6fc873098ca705b15bf80ee22b64` |
| SHA-1 | `3bbe67845c033d712dd7b0f5c22a37e4d5ca390b` |
| SHA-256 | `f85c795e38bd714fd320ce2888c6eb3d445723cd586c3db1411e443fb69edd7f` |
| SHA3-384 | `f0270a574eee0d1bcf2848014d80f4cfbabc1edba9c840d5799631cc32844f2b348ffb3ddfd31818693d3baea703c705` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F4E63358A2D002FFE6B34138FEE1E059D2A1B4B90B33C98F4B4887669D572F1493DA57` |
| SSDEEP | `393216:6guLmmJA68r3dxLfqe1OKmXMCHWUjXlcuI3/PGTAI:6gO7A6+SXMb8XSH/O7` |
| ICON-DHASH | `38dcf8f8fcf8e040` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_f85c795e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f85c795e38bd714fd320ce2888c6eb3d445723cd586c3db1411e443fb69edd7f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 01:52:30"
  condition:
    hash.sha256(0, filesize) == "f85c795e38bd714fd320ce2888c6eb3d445723cd586c3db1411e443fb69edd7f"
}
```

### Sample 20: `e3763b1555c565bd`

| Field | Value |
|---|---|
| SHA-256 | `e3763b1555c565bdf4e4ad9c1ffd65f01b504f483375d8573ecba6b5467e2330` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-07-18 01:47:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `470181143901f40f04995fc65daf3d40` |
| SHA-1 | `566067b3dc2fc3c1faa83073d2f3bdcc78fe4db9` |
| SHA-256 | `e3763b1555c565bdf4e4ad9c1ffd65f01b504f483375d8573ecba6b5467e2330` |
| SHA3-384 | `bd6f23ada14276f729f74119f9d4ff8b8a1deca52909a707406b54037247d9c65b74038ee2d4b766abe0e15986d17100` |
| TLSH | `T148B31247DBD6381F473154A9FF249586B9E88EB0B05A70362F40239FAB01827B23EF45` |
| SSDEEP | `3072:E5XcaHM5dwI8mh1yJldq/Dqgs4e+BIN7pmNhfEe4y5a:cFTq/mLqU1mrfEe4y5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_e3763b15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3763b1555c565bdf4e4ad9c1ffd65f01b504f483375d8573ecba6b5467e2330"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-18 01:47:41"
  condition:
    hash.sha256(0, filesize) == "e3763b1555c565bdf4e4ad9c1ffd65f01b504f483375d8573ecba6b5467e2330"
}
```

### Sample 21: `7961c4cb8175e03c`

| Field | Value |
|---|---|
| SHA-256 | `7961c4cb8175e03c7a6ab0cef01d0b0feaecc2fe3b25b7c8a036ce3051135284` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-18 01:47:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d28f0fd133cddea07d46a5e907bc8c5` |
| SHA-1 | `fbc3d98c3b3440e7d4d6ab782476e8f611090724` |
| SHA-256 | `7961c4cb8175e03c7a6ab0cef01d0b0feaecc2fe3b25b7c8a036ce3051135284` |
| SHA3-384 | `610d2764edb77f0cc5e55487667deab4c6633e06fbabde072b2c207d7fe1981a675cfa7d9496f37a50899bad76bf93bf` |
| TLSH | `T10F236D661A857C14AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10971D` |
| SSDEEP | `768:/XRWNGxVy9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:5lx1cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_7961c4cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7961c4cb8175e03c7a6ab0cef01d0b0feaecc2fe3b25b7c8a036ce3051135284"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 01:47:39"
  condition:
    hash.sha256(0, filesize) == "7961c4cb8175e03c7a6ab0cef01d0b0feaecc2fe3b25b7c8a036ce3051135284"
}
```

### Sample 22: `41a5af65484f67cc`

| Field | Value |
|---|---|
| SHA-256 | `41a5af65484f67ccf26159a27523f6e5de98beeeebad69596fc76ccecc815304` |
| Family label | `Mirai` |
| File name | `aa` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dc827ece2271260cd23164c4ac601f1` |
| SHA-1 | `668ba50e838b11c8687fae32f0e15f119109106b` |
| SHA-256 | `41a5af65484f67ccf26159a27523f6e5de98beeeebad69596fc76ccecc815304` |
| SHA3-384 | `b9b7b2fb7c2b41c20d3e57f2fc8f3bd4f768cc0b79a10b6fd550cf0db3a91146b2ccd14c2be28b67ab1aaa898e2490b9` |
| TLSH | `T119C43949F8809F61C6D426B6F65D42AC730747B9D3EBB2069E145B343BDB86B0F3A601` |
| TELFHASH | `t19cf0c02158d5e3e0f2c76649d9ea9065ea212e859f427d010b40b73c5d57fc11053c33` |
| SSDEEP | `12288:QXFZFOnaJPJhgPjuP0SD6lG3Z9tQE4//caqcAbxq8p1OJO:wFZ8naJRCPjIel4ZzQB//ag` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_41a5af65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41a5af65484f67ccf26159a27523f6e5de98beeeebad69596fc76ccecc815304"
    family = "Mirai"
    file_name = "aa"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:54"
  condition:
    hash.sha256(0, filesize) == "41a5af65484f67ccf26159a27523f6e5de98beeeebad69596fc76ccecc815304"
}
```

### Sample 23: `16872e9e7b05e6e1`

| Field | Value |
|---|---|
| SHA-256 | `16872e9e7b05e6e155986cad43d36831b6513bcf3381ca53157669671d69a171` |
| Family label | `unknown` |
| File name | `m` |
| File type | `unknown` |
| First seen | `2026-07-18 01:42:45` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cd10bb4500f662d4b5a776b1b50e39a` |
| SHA-256 | `16872e9e7b05e6e155986cad43d36831b6513bcf3381ca53157669671d69a171` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_16872e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16872e9e7b05e6e155986cad43d36831b6513bcf3381ca53157669671d69a171"
    family = "unknown"
    file_name = "m"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:45"
  condition:
    hash.sha256(0, filesize) == "16872e9e7b05e6e155986cad43d36831b6513bcf3381ca53157669671d69a171"
}
```

### Sample 24: `aab0a6d8d9c29346`

| Field | Value |
|---|---|
| SHA-256 | `aab0a6d8d9c2934691ffda0d08aa903770cd556cfe02da7dd55f6106977a220a` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5ebbe192e9ebc424323c921c09fdcba` |
| SHA-1 | `64d8bb84ede931b0c7fcb0880fe58a46fd40a6c4` |
| SHA-256 | `aab0a6d8d9c2934691ffda0d08aa903770cd556cfe02da7dd55f6106977a220a` |
| SHA3-384 | `76bfce90b60d7a4b71fe7979c1a6364a5b5052c3511251078f16e1a3168018837f121518786b1232b59dc9e952f1f11d` |
| TLSH | `T186237C47E743D0B9F86702B5503B63535B32E83A4079E792DB756935ED23A00A72B3AC` |
| TELFHASH | `t135314be17d7608fcb390ad4edb0b86d39b0999b3463665be44f5270137f21759230830` |
| SSDEEP | `768:n9bdzNM5eokt6uATgX/42s5w0NuJTLUzyx89JG168sx+VqcSncIwq:nBGejtJMm0Nu9UzyCEQhcSnc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_aab0a6d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aab0a6d8d9c2934691ffda0d08aa903770cd556cfe02da7dd55f6106977a220a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:44"
  condition:
    hash.sha256(0, filesize) == "aab0a6d8d9c2934691ffda0d08aa903770cd556cfe02da7dd55f6106977a220a"
}
```

### Sample 25: `f178e00cb07dcd2a`

| Field | Value |
|---|---|
| SHA-256 | `f178e00cb07dcd2ad446c2dacdd1a313136d86e1cb6d883a5f6476811155e6ff` |
| Family label | `unknown` |
| File name | `g3` |
| File type | `unknown` |
| First seen | `2026-07-18 01:42:42` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdb957614a2784a43f3b1cf5e5ac593d` |
| SHA-256 | `f178e00cb07dcd2ad446c2dacdd1a313136d86e1cb6d883a5f6476811155e6ff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_f178e00c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f178e00cb07dcd2ad446c2dacdd1a313136d86e1cb6d883a5f6476811155e6ff"
    family = "unknown"
    file_name = "g3"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:42"
  condition:
    hash.sha256(0, filesize) == "f178e00cb07dcd2ad446c2dacdd1a313136d86e1cb6d883a5f6476811155e6ff"
}
```

### Sample 26: `e99b526cf03cf095`

| Field | Value |
|---|---|
| SHA-256 | `e99b526cf03cf0950237edca206f76dcdfb98ba7459a50e8ec5720d847b0427a` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e22701b42ac6230c9d733cf68b9e4c84` |
| SHA-1 | `2fe01185165d63cd47d9a5b7171593e5dfbce5c5` |
| SHA-256 | `e99b526cf03cf0950237edca206f76dcdfb98ba7459a50e8ec5720d847b0427a` |
| SHA3-384 | `7f2ebcfe3c11208efd89277ce883420d025063e37a76e138b91eabb668982f90c61936d00eb860691d4bf93616d8154b` |
| TLSH | `T1BB63D70AEF510EEBD86FDE3306E90B0235CC554722B43B7A3574D928B65E54B49E3CA8` |
| SSDEEP | `1536:aZ047lQZrqJt5kuR4SuRUwxhwtOQWAlPceUC0Rc:/47lzzR4+whIwXc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_e99b526c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e99b526cf03cf0950237edca206f76dcdfb98ba7459a50e8ec5720d847b0427a"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:41"
  condition:
    hash.sha256(0, filesize) == "e99b526cf03cf0950237edca206f76dcdfb98ba7459a50e8ec5720d847b0427a"
}
```

### Sample 27: `52d04addeae33131`

| Field | Value |
|---|---|
| SHA-256 | `52d04addeae331314cfb21fd5dc3287532b49f0dbdd4839de53cdcb52380b0b1` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47c42d9a6c64965b66c88d8ddf0c3b1a` |
| SHA-1 | `fa911c8f357c11681537620d374aa505d585dc3e` |
| SHA-256 | `52d04addeae331314cfb21fd5dc3287532b49f0dbdd4839de53cdcb52380b0b1` |
| SHA3-384 | `0e66dd5ab8089fd2f360abb6c0c2f3312c4c80d65c61e2f231fc866b037570342bdd70190aadb474b0409774c97dee92` |
| TLSH | `T15EB32989B8D29A22C5C3527FFA4F42DD7B3663E4D3DB7107CD196B20328652B0E7A211` |
| TELFHASH | `t144d02bd2dfa027c013c2005045dea10203dab05937090412b5f41cee1682092b86d890` |
| SSDEEP | `3072:NsnQuZ6xhcVpLs5bp4Hh+Zbtmg0Dttn5v:NsnQoEYw51XVtmhhv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_52d04add
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52d04addeae331314cfb21fd5dc3287532b49f0dbdd4839de53cdcb52380b0b1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:39"
  condition:
    hash.sha256(0, filesize) == "52d04addeae331314cfb21fd5dc3287532b49f0dbdd4839de53cdcb52380b0b1"
}
```

### Sample 28: `4a1e4bea7d063f12`

| Field | Value |
|---|---|
| SHA-256 | `4a1e4bea7d063f1282627878dfc3ecb8466bd2a96094ba8ce4c7879370a45c47` |
| Family label | `unknown` |
| File name | `m` |
| File type | `unknown` |
| First seen | `2026-07-18 01:42:37` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebcb855d018ba02b755b02fd2746fbb5` |
| SHA-256 | `4a1e4bea7d063f1282627878dfc3ecb8466bd2a96094ba8ce4c7879370a45c47` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_4a1e4bea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a1e4bea7d063f1282627878dfc3ecb8466bd2a96094ba8ce4c7879370a45c47"
    family = "unknown"
    file_name = "m"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:37"
  condition:
    hash.sha256(0, filesize) == "4a1e4bea7d063f1282627878dfc3ecb8466bd2a96094ba8ce4c7879370a45c47"
}
```

### Sample 29: `585adf9dbfc2eb5e`

| Field | Value |
|---|---|
| SHA-256 | `585adf9dbfc2eb5e36c033e376c659d67485c97f759d78b870227e10c58043b2` |
| Family label | `unknown` |
| File name | `r` |
| File type | `unknown` |
| First seen | `2026-07-18 01:42:36` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19e0adccf8f7ae9c12fea7b8ab5c1ab3` |
| SHA-256 | `585adf9dbfc2eb5e36c033e376c659d67485c97f759d78b870227e10c58043b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_585adf9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "585adf9dbfc2eb5e36c033e376c659d67485c97f759d78b870227e10c58043b2"
    family = "unknown"
    file_name = "r"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:36"
  condition:
    hash.sha256(0, filesize) == "585adf9dbfc2eb5e36c033e376c659d67485c97f759d78b870227e10c58043b2"
}
```

### Sample 30: `84b817443d7488ad`

| Field | Value |
|---|---|
| SHA-256 | `84b817443d7488ad8c899daa0a08a237536ffa9165de500922e579f136f86463` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9974a5839e22f5a9784099ef047d1718` |
| SHA-1 | `2c8eea44968baafb0b61571ad4d91c2bf20695c5` |
| SHA-256 | `84b817443d7488ad8c899daa0a08a237536ffa9165de500922e579f136f86463` |
| SHA3-384 | `0a7d4d54610c1ff9c52ae32975683fd9480596f6b23653dc2efacfd2e97b1900dec4db79554ff5928d4a092fd233b42d` |
| TLSH | `T174432A95FD429B12C6C555BBFF0E42887B27035CE2EA7303AE256F21378B42A0E3B555` |
| TELFHASH | `t1c8b012304cd30b7c16500403896941e2d15e40108d25240131fc1c19e34306048031ac` |
| SSDEEP | `768:a9v1ncSsyINdGMN3IQO2TxkWQJMxQnwHlAEOSu5gpqpeeVqwrblcBE5zzvZER+I5:AnCdNLDODUxQ0AEOSfqpxhO+nvZER+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_84b81744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b817443d7488ad8c899daa0a08a237536ffa9165de500922e579f136f86463"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:35"
  condition:
    hash.sha256(0, filesize) == "84b817443d7488ad8c899daa0a08a237536ffa9165de500922e579f136f86463"
}
```

### Sample 31: `4a6a7f3fc8aeb12a`

| Field | Value |
|---|---|
| SHA-256 | `4a6a7f3fc8aeb12a77a9c9e93e40a35ae33dae15634ca554395243b7064f68fe` |
| Family label | `unknown` |
| File name | `magic` |
| File type | `unknown` |
| First seen | `2026-07-18 01:42:33` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ef1d0012a8651cd1af1af7285c1bd48` |
| SHA-256 | `4a6a7f3fc8aeb12a77a9c9e93e40a35ae33dae15634ca554395243b7064f68fe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_4a6a7f3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a6a7f3fc8aeb12a77a9c9e93e40a35ae33dae15634ca554395243b7064f68fe"
    family = "unknown"
    file_name = "magic"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:33"
  condition:
    hash.sha256(0, filesize) == "4a6a7f3fc8aeb12a77a9c9e93e40a35ae33dae15634ca554395243b7064f68fe"
}
```

### Sample 32: `798f3c696c7642b3`

| Field | Value |
|---|---|
| SHA-256 | `798f3c696c7642b3cd47f47ff039150ee946dce877ee04cd36af64e63e27a2c1` |
| Family label | `Mirai` |
| File name | `dlr.mips` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7fa4d17fd286e95d499493dd9731267` |
| SHA-1 | `1ba8e12d2ffebf9c81e9f56af6cdc750726adab1` |
| SHA-256 | `798f3c696c7642b3cd47f47ff039150ee946dce877ee04cd36af64e63e27a2c1` |
| SHA3-384 | `566fcb9f21ed310b58b763ccb71f1a39f37d99fb381bd1426349d9f7388653e1ce22cb436a94b6f1a5f9a2759d93c77e` |
| TLSH | `T1D141CE8E5F714EF8F159D93847374B35679B924843C04249E1ACDA405EC430D899E7E9` |
| SSDEEP | `48:exgpEuQ2H7DEr1ErD/9LuEp8nn2L3qxMM:igpTHnE2MEpIn02MM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_798f3c69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "798f3c696c7642b3cd47f47ff039150ee946dce877ee04cd36af64e63e27a2c1"
    family = "Mirai"
    file_name = "dlr.mips"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:32"
  condition:
    hash.sha256(0, filesize) == "798f3c696c7642b3cd47f47ff039150ee946dce877ee04cd36af64e63e27a2c1"
}
```

### Sample 33: `70f341f6de13cd88`

| Field | Value |
|---|---|
| SHA-256 | `70f341f6de13cd88d681d64e2726afb96eb421a715e1ac29f7b62a4ae0d54be6` |
| Family label | `unknown` |
| File name | `f` |
| File type | `unknown` |
| First seen | `2026-07-18 01:42:30` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d10d22c5656c3992cdafef7312b3ceb` |
| SHA-256 | `70f341f6de13cd88d681d64e2726afb96eb421a715e1ac29f7b62a4ae0d54be6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_70f341f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70f341f6de13cd88d681d64e2726afb96eb421a715e1ac29f7b62a4ae0d54be6"
    family = "unknown"
    file_name = "f"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:30"
  condition:
    hash.sha256(0, filesize) == "70f341f6de13cd88d681d64e2726afb96eb421a715e1ac29f7b62a4ae0d54be6"
}
```

### Sample 34: `848f1546a84dd92c`

| Field | Value |
|---|---|
| SHA-256 | `848f1546a84dd92cce3c1463e3e964698533d93d6ea7be00e000db5efbb1d2f4` |
| Family label | `Mirai` |
| File name | `dlr.mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2134f87d40aeeee0a20edb47e698304f` |
| SHA-1 | `7f57d53ae2db7d3e19e0e11071430565d67a6b58` |
| SHA-256 | `848f1546a84dd92cce3c1463e3e964698533d93d6ea7be00e000db5efbb1d2f4` |
| SHA3-384 | `ec3811cba7a55b8e637e895cffcc745e8ea549eef6d1ba360663dd693c17f40eaa40a7d345e2dcb4c19935b557f28302` |
| TLSH | `T13941121E6F801F37DDB6CC36058B275139CC842BB16A63916334E960BD3E605A7D38A8` |
| SSDEEP | `48:kff22nuDW3l6df9HOScTLmPkOTb5FSXZ:kffjnuq8f9uS4LmrTb6J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_848f1546
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "848f1546a84dd92cce3c1463e3e964698533d93d6ea7be00e000db5efbb1d2f4"
    family = "Mirai"
    file_name = "dlr.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:28"
  condition:
    hash.sha256(0, filesize) == "848f1546a84dd92cce3c1463e3e964698533d93d6ea7be00e000db5efbb1d2f4"
}
```

### Sample 35: `541d02331c910b5c`

| Field | Value |
|---|---|
| SHA-256 | `541d02331c910b5c73bf2b5a5e744319f9bd2b42f716c9ba28c9105eab915bdc` |
| Family label | `Mirai` |
| File name | `umips` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6dd344828f4ffdb46f4eb258487ba54` |
| SHA-1 | `fe6e55984d30ea737dcb4fd2846d47fe51ad0fc9` |
| SHA-256 | `541d02331c910b5c73bf2b5a5e744319f9bd2b42f716c9ba28c9105eab915bdc` |
| SHA3-384 | `2a3684c3a8d76927aac9868eaa2985711a91b3671812a257970ec439fc1d506d2875c1eb36be00b2bc729d40c808aa97` |
| TLSH | `T107C3E50F6F258F6DF779C33487F78E21A758738626E0C649D16CE6111E2028E641FBA9` |
| TELFHASH | `t17f21991c4b7422e467315c9d1a5dff77d1a130df2b255d338e11a9aeabacd815e20c0c` |
| SSDEEP | `3072:VO8ETb452u5sNOYpVYjdZxDPnlFBEh1rFZkfv9INUi50G8L4Pin5uH:c8ETbu5fvcVVoU0uH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_541d0233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "541d02331c910b5c73bf2b5a5e744319f9bd2b42f716c9ba28c9105eab915bdc"
    family = "Mirai"
    file_name = "umips"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:25"
  condition:
    hash.sha256(0, filesize) == "541d02331c910b5c73bf2b5a5e744319f9bd2b42f716c9ba28c9105eab915bdc"
}
```

### Sample 36: `32248ab13cb51588`

| Field | Value |
|---|---|
| SHA-256 | `32248ab13cb51588769a70d7672bd98a200f1ede0067ae6193f56c74fc358321` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93d220bc13630dec8849d4823ad11a47` |
| SHA-1 | `0e1427b6279801a02291f8853a3f707e8f896476` |
| SHA-256 | `32248ab13cb51588769a70d7672bd98a200f1ede0067ae6193f56c74fc358321` |
| SHA3-384 | `7cd82fa6ed770ccac7a4d0bedd25b12e4e67a56017e6ba644504d0dcdb4eae74a34153658a77f944f92b3de07bc99521` |
| TLSH | `T1E663CA4A6E228FEDF26C873047B74B21E76963D623E1D685E29CC5041F7034D586FBA8` |
| TELFHASH | `t11d115b18883c43f097801ced6bddff76e4a150db4a219f338e50f9ae9a25a429e00c2c` |
| SSDEEP | `768:JAALZAXwkC7L4DI7F1LNLhLy2pOilgD7mpwTUKlxSMcgSfKIZzbmyMNleZM8iF2y:J/ZOwvhOilW6tKW/7ZaeZM88ODARya` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_32248ab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32248ab13cb51588769a70d7672bd98a200f1ede0067ae6193f56c74fc358321"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:22"
  condition:
    hash.sha256(0, filesize) == "32248ab13cb51588769a70d7672bd98a200f1ede0067ae6193f56c74fc358321"
}
```

### Sample 37: `e4377c8a0d26d984`

| Field | Value |
|---|---|
| SHA-256 | `e4377c8a0d26d9843a34644c145732c3d5179f9dbc87ae46d8cac66545b3ba8c` |
| Family label | `Mirai` |
| File name | `rmips` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6a4f8cc9fa2903d39664ee6bfbc6fe7` |
| SHA-1 | `428c4be79c29ab1d749ecc603578d81125ac178a` |
| SHA-256 | `e4377c8a0d26d9843a34644c145732c3d5179f9dbc87ae46d8cac66545b3ba8c` |
| SHA3-384 | `4aae48a3aee6e525c7b81daa2c27b05d4cb38124821d0ee0ce2b4923c5f726648a86ee583e26e73bc95eea600c16af91` |
| TLSH | `T12DD3D50E6F658F6DF379C33587F74E21A75873C626E0C649D26CE9111E2028E641FBA8` |
| TELFHASH | `t13821c31c497422f497311c8a1b5eef77e5a530cf1b367d338e01a96daabd8818e00c0c` |
| SSDEEP | `3072:H3k6y/GvzhNsQSlhYWp9E2aCkAXA/knsrO5robfDl3nOTM0Sn5YN:H3k6sWoMZ30TEYN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_e4377c8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4377c8a0d26d9843a34644c145732c3d5179f9dbc87ae46d8cac66545b3ba8c"
    family = "Mirai"
    file_name = "rmips"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:20"
  condition:
    hash.sha256(0, filesize) == "e4377c8a0d26d9843a34644c145732c3d5179f9dbc87ae46d8cac66545b3ba8c"
}
```

### Sample 38: `c569ae79cce6d17c`

| Field | Value |
|---|---|
| SHA-256 | `c569ae79cce6d17ccd35031c39c1b3d6c634e4e906b932fcce48ac0a0336fdbf` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a38e1daf9790f01c3f9c52eb797cb85` |
| SHA-1 | `ec92c67a450bc9fe82ac3120a262bef40612c675` |
| SHA-256 | `c569ae79cce6d17ccd35031c39c1b3d6c634e4e906b932fcce48ac0a0336fdbf` |
| SHA3-384 | `9393b456dd19a9e700184c31089e40f642e9f3e275635cb787831e0d34ef6003da49ea5532f1dc534f8b16bcc12a7565` |
| TLSH | `T148332A95FD42AB02C6C555BBFF0E42887727435CE2EE7303AA256F21378B46A0E3B545` |
| TELFHASH | `t1c8b012304cd30b7c16500403896941e2d15e40108d25240131fc1c19e34306048031ac` |
| SSDEEP | `768:C+3vlncS9yINJlGMDZXQj2T21WYTMv54wXlAEOCJKIOy7ieD1pvJj5P159zJERbI:FnPdN9ajZ6v5XAEOCmy7xDf1nVERb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_c569ae79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c569ae79cce6d17ccd35031c39c1b3d6c634e4e906b932fcce48ac0a0336fdbf"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:14"
  condition:
    hash.sha256(0, filesize) == "c569ae79cce6d17ccd35031c39c1b3d6c634e4e906b932fcce48ac0a0336fdbf"
}
```

### Sample 39: `561397d9a74f3923`

| Field | Value |
|---|---|
| SHA-256 | `561397d9a74f3923c8b4cfe955b0b4727e56fab6d1eba096964a172bfe14ed29` |
| Family label | `Mirai` |
| File name | `dlr.arm5` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0678c101d5d57affdafe807856303d8` |
| SHA-1 | `a691a5a221fa720a23a87d05e16631524b706ea1` |
| SHA-256 | `561397d9a74f3923c8b4cfe955b0b4727e56fab6d1eba096964a172bfe14ed29` |
| SHA3-384 | `c9c42878fafbf9b6fd8af51996c9aa252c8a813bd4495f8b50952954c51ce6dc625cb1f226b73c99f34cbe8fb909ebfa` |
| TLSH | `T150219E9AA7D36D6BCC540277DCAF5720E362AE84869EF513F32216150C6F21A1F2215A` |
| TELFHASH | `t19f900224424f44549a804241e0dd66018ed0e3131125289007d0444014033206005141` |
| SSDEEP | `24:JColMlgP9qD0at6EoKGlwrUlFSy4WzLCkIddx2HuGIDv1Nfc7:JColMOFqDPtSwrkFSy4WzLmGIr1Ny` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_561397d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "561397d9a74f3923c8b4cfe955b0b4727e56fab6d1eba096964a172bfe14ed29"
    family = "Mirai"
    file_name = "dlr.arm5"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:13"
  condition:
    hash.sha256(0, filesize) == "561397d9a74f3923c8b4cfe955b0b4727e56fab6d1eba096964a172bfe14ed29"
}
```

### Sample 40: `1e3c77937fbeb6c3`

| Field | Value |
|---|---|
| SHA-256 | `1e3c77937fbeb6c30db92b5f571623264260e71ddfae8b5c2f79a76c20057e23` |
| Family label | `Mirai` |
| File name | `rmpsl` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ab16a5b3f205f6aa2bc47f84cfb7cc3` |
| SHA-1 | `73c5bfe39f7de12efc981445b49d742056204356` |
| SHA-256 | `1e3c77937fbeb6c30db92b5f571623264260e71ddfae8b5c2f79a76c20057e23` |
| SHA3-384 | `763153e948f55ec22e0752f93305c82c5fb226f3459fa7efb23770be600d5f9511a18fd0d4655be16b1a49b07b9072cf` |
| TLSH | `T10AD30906BF601EF7E8ABCD3741B94B0A24CC645B22A83B753674D528B64B50F4AD3D74` |
| SSDEEP | `3072:RiwULpMwOu8knavsiMqEYNh9azHZcn5fp:8zMwJnavsiMqTh9aUf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_1e3c7793
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e3c77937fbeb6c30db92b5f571623264260e71ddfae8b5c2f79a76c20057e23"
    family = "Mirai"
    file_name = "rmpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:08"
  condition:
    hash.sha256(0, filesize) == "1e3c77937fbeb6c30db92b5f571623264260e71ddfae8b5c2f79a76c20057e23"
}
```

### Sample 41: `f8514ee48f0e84bb`

| Field | Value |
|---|---|
| SHA-256 | `f8514ee48f0e84bb0a1172f469b5efeeb89625b53689d2a6a0a1beeb584fe658` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3e7157750a5eaf2be237c57cbb069c2` |
| SHA-1 | `b22ef593a5af37c601ef40244597547231aa704b` |
| SHA-256 | `f8514ee48f0e84bb0a1172f469b5efeeb89625b53689d2a6a0a1beeb584fe658` |
| SHA3-384 | `29f007c388f36ccbfc84bf31b0ac91b498ba25291695ad806f425be9b3f376e4800dc9d96daede0f236a53016cb48ed4` |
| TLSH | `T14273195AFC806F11E5D625BAFF4E414933534B6CE3EE7212AE209B2527CA91B0F3B505` |
| TELFHASH | `t1c2b0122029e014c095c4093266057181b0342094614e9d1032035203008e0a908050dc` |
| SSDEEP | `1536:TABnAI7HJEGxMEW5avbi38FaI4MQiMrsVTZs/ZtgYHO3ERF:TWuGZW5avbi38Fas6rsVTZs/A5SF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_f8514ee4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8514ee48f0e84bb0a1172f469b5efeeb89625b53689d2a6a0a1beeb584fe658"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:06"
  condition:
    hash.sha256(0, filesize) == "f8514ee48f0e84bb0a1172f469b5efeeb89625b53689d2a6a0a1beeb584fe658"
}
```

### Sample 42: `fbf46de3022593c8`

| Field | Value |
|---|---|
| SHA-256 | `fbf46de3022593c85013ee66b07967bfa02a0d7f618532b6192722296331a43b` |
| Family label | `Mirai` |
| File name | `umpsl` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfb121288d2399d8ee0990a73fc85587` |
| SHA-1 | `385cb87b1aeea6ac11c70c296b8fc094ed657760` |
| SHA-256 | `fbf46de3022593c85013ee66b07967bfa02a0d7f618532b6192722296331a43b` |
| SHA3-384 | `6544eba89e40c6934d77104f5fe31c63e982b33f34f6f3a50a515fd0cec853268b1a168f75595da055a63bbaa7089473` |
| TLSH | `T144D30806FF600DFBD8AFCC3742B95B0A24CC655A22A82B753578D828B64B54F56D3CB4` |
| SSDEEP | `3072:uOZEckABJf98uiTIMhtRQit22Oyvfn5Z:PZJBJfziXhtRQc223Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_fbf46de3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbf46de3022593c85013ee66b07967bfa02a0d7f618532b6192722296331a43b"
    family = "Mirai"
    file_name = "umpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:04"
  condition:
    hash.sha256(0, filesize) == "fbf46de3022593c85013ee66b07967bfa02a0d7f618532b6192722296331a43b"
}
```

### Sample 43: `029e273cda07c75c`

| Field | Value |
|---|---|
| SHA-256 | `029e273cda07c75ccc3bd5b09ba4b622a732abf2bfe3cdc69c133de70813b7eb` |
| Family label | `Mirai` |
| File name | `aa` |
| File type | `elf` |
| First seen | `2026-07-18 01:42:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3a00eb825f17280eef4d1ffebae2d9e` |
| SHA-1 | `0b4265eab33c2493c5864cf9f4abd13a5650fda8` |
| SHA-256 | `029e273cda07c75ccc3bd5b09ba4b622a732abf2bfe3cdc69c133de70813b7eb` |
| SHA3-384 | `c11bdce2ea795489ba318f952af67425160e704fcc443eda4a234fa78d51bf9c83af9b91cc9068bfb46cc6d766045647` |
| TLSH | `T14B441277398F1CFFD1EA22280226E45235FCE6F401428DD672723AC582E97336EA5957` |
| SSDEEP | `6144:/JGuQHa43i2PlYvwlQ1vd7Xhv926iuHxuP+8dk0B93tP:oy2evBnXKuHm+8dkKP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_029e273c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "029e273cda07c75ccc3bd5b09ba4b622a732abf2bfe3cdc69c133de70813b7eb"
    family = "Mirai"
    file_name = "aa"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:01"
  condition:
    hash.sha256(0, filesize) == "029e273cda07c75ccc3bd5b09ba4b622a732abf2bfe3cdc69c133de70813b7eb"
}
```

### Sample 44: `2ed322830841e304`

| Field | Value |
|---|---|
| SHA-256 | `2ed322830841e3043f09476f755ca36da1d58324521924483b24c1fc2fb650cc` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-18 01:41:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8af46a6ba5db654b98b5bbb853d5a691` |
| SHA-1 | `acd0564760d19c5d84aa2788fd6648432712d618` |
| SHA-256 | `2ed322830841e3043f09476f755ca36da1d58324521924483b24c1fc2fb650cc` |
| SHA3-384 | `4db834a347174c33c0f2d2682714d1e6aa6eece81ae1d1dc526eb57b20681d4e4537fbf2e1730f9458b6b91f05b41e57` |
| TLSH | `T134D4B60B6E228F7DF674873147F74A24A7AD33D627E1D980D29DC1142F2128E591FBA8` |
| TELFHASH | `t11db14599293817e4ab555c8c46dcfe31cca228ef3a591c33de50e85ee71ba835e10c1c` |
| SSDEEP | `6144:KhK0Pj/1emCum2kL1RENCR6LcDVDj8l3N2DNbvsmZOfTSGEm51/U33b/Tn+cgBMG:K80Pj/2p2k/D3cLrAzAZNrqnRXE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_2ed32283
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed322830841e3043f09476f755ca36da1d58324521924483b24c1fc2fb650cc"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-18 01:41:57"
  condition:
    hash.sha256(0, filesize) == "2ed322830841e3043f09476f755ca36da1d58324521924483b24c1fc2fb650cc"
}
```

### Sample 45: `d03c0e897d5aef59`

| Field | Value |
|---|---|
| SHA-256 | `d03c0e897d5aef598330056653174ccb4d9213e006fa761f1330cebb209f050a` |
| Family label | `Mirai` |
| File name | `a6` |
| File type | `elf` |
| First seen | `2026-07-18 01:41:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b60f9c1322a439a205c36045bf6e7d7` |
| SHA-1 | `59a461a7f6231a2dad6a0d6c040cb7646cd48ae7` |
| SHA-256 | `d03c0e897d5aef598330056653174ccb4d9213e006fa761f1330cebb209f050a` |
| SHA3-384 | `b67e9d2108ec2a23c9a8bb4ef3f994e750a6cc3bb3035834ae52c2829b70c18d3f2f0c92a3740c6eb6364d99edd31277` |
| TLSH | `T129D31959F8D0DF63CAD436BAB95E018C336357B9C2DAB0029E146F3427DBD9A063E506` |
| SSDEEP | `3072:U7KEH+m8UiaPHfGKfrIcQF6iFBMChrMh4Xw8tr:U/aUMBFw4A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_d03c0e89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d03c0e897d5aef598330056653174ccb4d9213e006fa761f1330cebb209f050a"
    family = "Mirai"
    file_name = "a6"
    file_type = "elf"
    first_seen = "2026-07-18 01:41:56"
  condition:
    hash.sha256(0, filesize) == "d03c0e897d5aef598330056653174ccb4d9213e006fa761f1330cebb209f050a"
}
```

### Sample 46: `edaea93baed98567`

| Field | Value |
|---|---|
| SHA-256 | `edaea93baed98567c213668dc5b258d541623ce7358c0b7368fe8cdd07c54da1` |
| Family label | `Mirai` |
| File name | `dlr.arm4` |
| File type | `elf` |
| First seen | `2026-07-18 01:41:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25d9270e4067f6a29de1b3776dc83729` |
| SHA-1 | `aa8ed8e85a664f1e50dbed084940fad680e9b626` |
| SHA-256 | `edaea93baed98567c213668dc5b258d541623ce7358c0b7368fe8cdd07c54da1` |
| SHA3-384 | `118cd42d27d7adff7f6a7cf66c7cf6c7c5cf61c67c3626cc7832dfd62c998eaa846b35c00a029b96de4c48655eae343c` |
| TLSH | `T197219BE6A7D35E67CC540237DCEF5B10E322AE848A9FF513E35116250D3F21A5F22169` |
| TELFHASH | `t19f900224424f44549a804241e0dd66018ed0e3131125289007d0444014033206005141` |
| SSDEEP | `24:J6KFpV0gP9qD0at6EoKGlwrUlFSy4WzLCkIddgH9IkAYwNfm:J6KjFqDPtSwrkFSy4WzLT9IkAYwNe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_edaea93b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edaea93baed98567c213668dc5b258d541623ce7358c0b7368fe8cdd07c54da1"
    family = "Mirai"
    file_name = "dlr.arm4"
    file_type = "elf"
    first_seen = "2026-07-18 01:41:53"
  condition:
    hash.sha256(0, filesize) == "edaea93baed98567c213668dc5b258d541623ce7358c0b7368fe8cdd07c54da1"
}
```

### Sample 47: `02fd84fcefc193ac`

| Field | Value |
|---|---|
| SHA-256 | `02fd84fcefc193ac0af333f23ed8ddba75061da00f60c6c53836a39a73e28768` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 01:31:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddc448ff4f60916b3b3371326cb487a7` |
| SHA-1 | `5131304c8470aec79049019f46a5d314d1de9a69` |
| SHA-256 | `02fd84fcefc193ac0af333f23ed8ddba75061da00f60c6c53836a39a73e28768` |
| SHA3-384 | `b4d2b30feb7f7959697232c578026261d712f85ea711f0374b8b889e119d7d953bd3f11ef2b3597050c9dafc28b25aff` |
| TLSH | `T17DF3F805BB610EF7E85FCC3706E9270128CDA51622B97B36B534D958F64B28B26E3D70` |
| SSDEEP | `3072:ldrx+vzsw8TONAdQLty5l6Gm7UxbiuyZ6RlPP4FQQm8DrfIHW:lJx+vzXUONAdQLtKlTm7UxbiuyZ6RlPE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_02fd84fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02fd84fcefc193ac0af333f23ed8ddba75061da00f60c6c53836a39a73e28768"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:31:16"
  condition:
    hash.sha256(0, filesize) == "02fd84fcefc193ac0af333f23ed8ddba75061da00f60c6c53836a39a73e28768"
}
```

### Sample 48: `26228ffd4024016f`

| Field | Value |
|---|---|
| SHA-256 | `26228ffd4024016f5ac1391601ef229bfddd2a7a365875bc44605ee9aab6e6cf` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 01:30:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6572750a6f7d8bb94cd7bf39e9e00763` |
| SHA-1 | `e62ccb66cbe2f897ede48c23bcceb53a54cdeb8a` |
| SHA-256 | `26228ffd4024016f5ac1391601ef229bfddd2a7a365875bc44605ee9aab6e6cf` |
| SHA3-384 | `7fc16cb49c96792bcc5aff3b6b454274b39451ecd98eca291ab41b41358a330a0c5162ac81a94666fcab503bb658dfe9` |
| TLSH | `T1C733F1E7EA1B3881CAAC487D62ED5B799B5130F17227B34CD7656C4C970A7F82A9900C` |
| SSDEEP | `768:c4MsSKFz9Q3V71gRjZ6G7wxPiix0RGuoFhrzwexQa0fvIY0JjKE67PMHN15DkZpP:/FFOh157E81u+Wex5MX0J+E6AxDkeY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_26228ffd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26228ffd4024016f5ac1391601ef229bfddd2a7a365875bc44605ee9aab6e6cf"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:30:29"
  condition:
    hash.sha256(0, filesize) == "26228ffd4024016f5ac1391601ef229bfddd2a7a365875bc44605ee9aab6e6cf"
}
```

### Sample 49: `37ad8c225142d26d`

| Field | Value |
|---|---|
| SHA-256 | `37ad8c225142d26d12efbec05cf35cdba02664e1525b8cceab9e19a77312c224` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-18 01:30:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f1b7978cd2fb8814fcd305680d02043` |
| SHA-1 | `f41f47ceaf2dc54d41b97907bd563ebb6da92cb8` |
| SHA-256 | `37ad8c225142d26d12efbec05cf35cdba02664e1525b8cceab9e19a77312c224` |
| SHA3-384 | `15f958221d5e3705721c6b97ec6bf5e376716afe1c0f2017379f8b04509bf80eebd76777000bd8183ef3e5463c58a712` |
| TLSH | `T10DE39EA49E0FAD83D2C3E3FDAE5A0FA6303734744511D1F74D00A69DE59EED988A2522` |
| SSDEEP | `3072:2xLCVvd+4KE0baEpakd4zs0nsTblQl8E/r0v0sKhRcLz:24rn2bokGzs0sTbW8pvJKc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_37ad8c22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37ad8c225142d26d12efbec05cf35cdba02664e1525b8cceab9e19a77312c224"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-18 01:30:27"
  condition:
    hash.sha256(0, filesize) == "37ad8c225142d26d12efbec05cf35cdba02664e1525b8cceab9e19a77312c224"
}
```

### Sample 50: `c2726f5b5a72d939`

| Field | Value |
|---|---|
| SHA-256 | `c2726f5b5a72d93901efaec8c12d611c7d66c5b6d1994f2ee9a72418d1a54735` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-18 01:23:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea212bb398d466742c537bbaa992ceb2` |
| SHA-1 | `47a8d405653a240d67daf2820558b95743bfcb63` |
| SHA-256 | `c2726f5b5a72d93901efaec8c12d611c7d66c5b6d1994f2ee9a72418d1a54735` |
| SHA3-384 | `9cd1000efab438b9322f8aac1233c854adf4096c004621a9fbbd0673faddbd54d6912dc1723333ac310d2073570bf6b2` |
| TLSH | `T1AFB31907BDC18DFDC089C038477F753ED822F0ED0239B2AB67D4AE262D5DEA11A19A55` |
| TELFHASH | `t1cb2177b03ed27a5c20c3d39ab35ede7ae0b209241a92b1e58f0b6dd98e06fc80c41456` |
| SSDEEP | `3072:gHoE9uzAHZeQ9eAT9kkzyQtJGCvR0MeITI8IunXYUxze:gIE4zAHZeQ9XT9kKjGMeKIIXYUxze` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_c2726f5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2726f5b5a72d93901efaec8c12d611c7d66c5b6d1994f2ee9a72418d1a54735"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 01:23:40"
  condition:
    hash.sha256(0, filesize) == "c2726f5b5a72d93901efaec8c12d611c7d66c5b6d1994f2ee9a72418d1a54735"
}
```

### Sample 51: `426f394fee5882b8`

| Field | Value |
|---|---|
| SHA-256 | `426f394fee5882b8d70b37c6fc8ca9ba1ce3bb6eb7573550b6b55c16d343788a` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-18 01:22:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1c000d87854208fdab03ba2f7e7de38` |
| SHA-1 | `3566c2f798cc8bead82b1f7246ab53768c7464d4` |
| SHA-256 | `426f394fee5882b8d70b37c6fc8ca9ba1ce3bb6eb7573550b6b55c16d343788a` |
| SHA3-384 | `d2c0cd1e196ee234284214e0a2a2df0d15ec31ad4634bb58d62e5001374d2fc63f0e0fdcf18dfc01043b6efa07489509` |
| TLSH | `T1DA23E2D641AFFE3EC951D97680CF9760EE3E880A2951C7877EF821AC4FA7D462811E04` |
| SSDEEP | `768:k+an3RY7qKS4o2SeAgPBOAcLorb6T8/s/hOMBtE47fJmfHq2BwyNIaeapix0YM:03+7k4oZCAonl/aTE47BmAtagxM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_426f394f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "426f394fee5882b8d70b37c6fc8ca9ba1ce3bb6eb7573550b6b55c16d343788a"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 01:22:37"
  condition:
    hash.sha256(0, filesize) == "426f394fee5882b8d70b37c6fc8ca9ba1ce3bb6eb7573550b6b55c16d343788a"
}
```

### Sample 52: `1f880c07cf7f81f8`

| Field | Value |
|---|---|
| SHA-256 | `1f880c07cf7f81f86360513384a6ce443f06869fbfcde62614c523de0df28dc1` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-18 01:22:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `792927539ecca272b5dab6bdcfe88460` |
| SHA-1 | `52ec7434486b07eed96a3df03748294530fe332c` |
| SHA-256 | `1f880c07cf7f81f86360513384a6ce443f06869fbfcde62614c523de0df28dc1` |
| SHA3-384 | `2cbecc026ca86159f1472308cc8c045451331d9b2c8edd51f6b0d6e48f34eb0b504290dc38169d05f861baa0c074e087` |
| TLSH | `T185D31959BC829A12C6C3567BFE5F82CC332723A8E3EA7117DD155F25368B91A0E3B141` |
| TELFHASH | `t1f1d0a726c8840ae4b765821001e353a09a88f55b565104d0dac51f7fef119227125a31` |
| SSDEEP | `3072:2f3J9M9WP7Lp3b/SFQeeyxjBiSuH3+b8ajnbo:2f3J9Sa7LFbLe1VuHuYavo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_1f880c07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f880c07cf7f81f86360513384a6ce443f06869fbfcde62614c523de0df28dc1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-18 01:22:35"
  condition:
    hash.sha256(0, filesize) == "1f880c07cf7f81f86360513384a6ce443f06869fbfcde62614c523de0df28dc1"
}
```

### Sample 53: `81d60e52eaa3d9ca`

| Field | Value |
|---|---|
| SHA-256 | `81d60e52eaa3d9ca6373262d7921be49dccecbbceb8d436d2f3ddc7ff7ea8493` |
| Family label | `Mirai` |
| File name | `tmpsl` |
| File type | `elf` |
| First seen | `2026-07-18 01:18:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a851fc00f09602e7a37cf6f3f936df9d` |
| SHA-1 | `e0e4b778def87b057eb1edf50d973a2dbe5a2600` |
| SHA-256 | `81d60e52eaa3d9ca6373262d7921be49dccecbbceb8d436d2f3ddc7ff7ea8493` |
| SHA3-384 | `59a5c525903072751dca116e2a4b762c6a2ac0c72cd814ceffef7d1640c5de79b75f9df870a7bb4b439e83e20448a73a` |
| TLSH | `T10CC30807BF610FFBE85FDD3706A91B49259C950621EC7B7A7934C81CB64B28B09E3864` |
| SSDEEP | `1536:Y5nfrA6UIWVNZVjEByoQCxxYnF1S1UmHJwC82xgopL2yCSv2XWETw8CD:Y5nfryDnIpwmgopL2yC48w8C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_81d60e52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81d60e52eaa3d9ca6373262d7921be49dccecbbceb8d436d2f3ddc7ff7ea8493"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:18:11"
  condition:
    hash.sha256(0, filesize) == "81d60e52eaa3d9ca6373262d7921be49dccecbbceb8d436d2f3ddc7ff7ea8493"
}
```

### Sample 54: `b4af41047f9ff667`

| Field | Value |
|---|---|
| SHA-256 | `b4af41047f9ff667cbea568b8d78967b221d1da5375bd9bfa07769b75160cd0d` |
| Family label | `Mirai` |
| File name | `tarm6` |
| File type | `elf` |
| First seen | `2026-07-18 01:18:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2aa9e949d82032e300482f0237aa1c3` |
| SHA-1 | `ae9744e4c0089e0477806e4c4c140e4cc6e1b378` |
| SHA-256 | `b4af41047f9ff667cbea568b8d78967b221d1da5375bd9bfa07769b75160cd0d` |
| SHA3-384 | `597abe7d3ef874832118e3979a6bf0b7a5ed65283fd8d56b1bbbd037042c51364b04a749462be101ce58e63e99051e71` |
| TLSH | `T1C1A31A89B881AB24C6C2167BFE1F014E33135BA8D2EE735299145F7077CB96B0E37615` |
| TELFHASH | `t165e06807df25805a9394001580ed911742ed72a13f0224d341acef4d4640341b139d3f` |
| SSDEEP | `3072:CWH6dgeL0DnJr1dUeqWtd5GJqanV+cLSF3HuDww:CWaIDnJrDUbW/IqaV+crr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_b4af4104
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4af41047f9ff667cbea568b8d78967b221d1da5375bd9bfa07769b75160cd0d"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-07-18 01:18:10"
  condition:
    hash.sha256(0, filesize) == "b4af41047f9ff667cbea568b8d78967b221d1da5375bd9bfa07769b75160cd0d"
}
```

### Sample 55: `4917e42c0df49bc8`

| Field | Value |
|---|---|
| SHA-256 | `4917e42c0df49bc834c4d145cd57e2887dcd1e9b784953346fc707ea7aa51ae5` |
| Family label | `Mirai` |
| File name | `tarm7` |
| File type | `elf` |
| First seen | `2026-07-18 01:09:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d66ae25ed53df675704888f88799e207` |
| SHA-1 | `852b3cb3fb399c3df1ac9aa9d7bf1ba8b38dc628` |
| SHA-256 | `4917e42c0df49bc834c4d145cd57e2887dcd1e9b784953346fc707ea7aa51ae5` |
| SHA3-384 | `e9414184acf70b04110b5d277e5b2a7c153f94aadfadc409b462b7c11943948e7fd0da5795307cf6e4322ed3aa6a7a49` |
| TLSH | `T150B32A89B8816B20C2D326BBFE5F014E33534BA8D3EA72129D245F7077CA95B0E37605` |
| TELFHASH | `t107e0d811ae61a1582bd4049740de543b1fedf3a93b5118939aac7fca91409517c2a427` |
| SSDEEP | `3072:dRTntbI80tmnn1u8Ue8NLdMJ4Pya5DNIRK95O76rS0EYwL:dRTtwmnn1pUZNq4ya5DNIRK9E7yM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_4917e42c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4917e42c0df49bc834c4d145cd57e2887dcd1e9b784953346fc707ea7aa51ae5"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-18 01:09:43"
  condition:
    hash.sha256(0, filesize) == "4917e42c0df49bc834c4d145cd57e2887dcd1e9b784953346fc707ea7aa51ae5"
}
```

### Sample 56: `0e6da423fff9e817`

| Field | Value |
|---|---|
| SHA-256 | `0e6da423fff9e817b4adf79b75ca56f6528fa6d820b9cb716532becb96e798ac` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-18 01:09:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93af8be6603272b01c7db8e181365074` |
| SHA-1 | `9f18bd889aff6320a4fd974e938019ed0c0c78d4` |
| SHA-256 | `0e6da423fff9e817b4adf79b75ca56f6528fa6d820b9cb716532becb96e798ac` |
| SHA3-384 | `1cfba19344c1f920c087ae61a6da5b6be73b7039845c82c36b855c3a05b10e4947fe68a491cd8886f5752316814237c3` |
| TLSH | `T146C27D956A867C44BEC98B3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:F8vCB+25j6es8R+9FYpMSUpi+20qUpi+20YQX:F8l25JYd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_0e6da423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e6da423fff9e817b4adf79b75ca56f6528fa6d820b9cb716532becb96e798ac"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-18 01:09:41"
  condition:
    hash.sha256(0, filesize) == "0e6da423fff9e817b4adf79b75ca56f6528fa6d820b9cb716532becb96e798ac"
}
```

### Sample 57: `83ce591d7b27d202`

| Field | Value |
|---|---|
| SHA-256 | `83ce591d7b27d20266951ffa68fa339e4b1d85e30c46b4f962feaf02b6638fd6` |
| Family label | `AgentTesla` |
| File name | `NEW_ORDER_QUOTATION_202606001pdf.exe` |
| File type | `exe` |
| First seen | `2026-07-18 01:06:21` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e724c812b9a4f294eb89514929c10ae` |
| SHA-1 | `ea097e250612e20c37762fdd0df22c68dba58d36` |
| SHA-256 | `83ce591d7b27d20266951ffa68fa339e4b1d85e30c46b4f962feaf02b6638fd6` |
| SHA3-384 | `27e984e1f43729d4ff3aaaba1675c0b9c32cb94598aa03dce705dd369ae28577edc425ebd330135c6495341b88b02d00` |
| IMPHASH | `f469ac0906218570f79c54d1b58dc057` |
| TLSH | `T1A1F58D55ABD806F4E47AD630C9D6B332C6B1BCF70631824B0964E6CDDE735924FEA221` |
| SSDEEP | `49152:rHAHVFOQRRBIu4snPOiHnbw0ZgFfg1amjvMWyR6/QTQHVfAqndzj:KjlvEWyRnQHSa` |
| ICON-DHASH | `926d69b2696dd628` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_057_83ce591d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83ce591d7b27d20266951ffa68fa339e4b1d85e30c46b4f962feaf02b6638fd6"
    family = "AgentTesla"
    file_name = "NEW_ORDER_QUOTATION_202606001pdf.exe"
    file_type = "exe"
    first_seen = "2026-07-18 01:06:21"
  condition:
    hash.sha256(0, filesize) == "83ce591d7b27d20266951ffa68fa339e4b1d85e30c46b4f962feaf02b6638fd6"
}
```

### Sample 58: `c152fa31ad2a21f7`

| Field | Value |
|---|---|
| SHA-256 | `c152fa31ad2a21f79c0586b96c684a4725ca8b439e6944172bc97d6a6d9e83a9` |
| Family label | `Mirai` |
| File name | `tarm` |
| File type | `elf` |
| First seen | `2026-07-18 01:05:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `272b90de58f93a5b8b3e5709f3c506df` |
| SHA-1 | `cf52cc82a5d481c3eaa1e0f912755b91cceb23a4` |
| SHA-256 | `c152fa31ad2a21f79c0586b96c684a4725ca8b439e6944172bc97d6a6d9e83a9` |
| SHA3-384 | `eb9214853e384a3be6a79c02e9690ab6df98042457607e5422e5687d0a6714b96b76d21e661756733ba2987c4f0a6cc1` |
| TLSH | `T1EE932AC5B890A622C7C1527BFE5F018D37665BE8D2DA3207DD240FA0778A96B0E37752` |
| TELFHASH | `t10951ffabff352f9c47e9802442ceb4162ef974491f1a3843ca2d574b8582a43701e82b` |
| SSDEEP | `1536:5S+00EZP79o3X6vH5EILwmZQU1dSAVfIe1M7YxQxGk3DoM9Mkwk:5S+00EZP79o3QH5LLwmUIfH1fxQz3UJ0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_c152fa31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c152fa31ad2a21f79c0586b96c684a4725ca8b439e6944172bc97d6a6d9e83a9"
    family = "Mirai"
    file_name = "tarm"
    file_type = "elf"
    first_seen = "2026-07-18 01:05:17"
  condition:
    hash.sha256(0, filesize) == "c152fa31ad2a21f79c0586b96c684a4725ca8b439e6944172bc97d6a6d9e83a9"
}
```

### Sample 59: `f17815cd4111cdf8`

| Field | Value |
|---|---|
| SHA-256 | `f17815cd4111cdf8ead2b31c7fef4453b55b18202753495225a564c819ee1138` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-18 00:55:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `679e968d0526df42added970ee959ddf` |
| SHA-1 | `af6f71ffa23316a8bf7f34032af9a5257f328c2b` |
| SHA-256 | `f17815cd4111cdf8ead2b31c7fef4453b55b18202753495225a564c819ee1138` |
| SHA3-384 | `f6a6e2d111f4fa11a0c7d29b8280614f0274f8eb7381b328a965dfe6bfb2a965bafaca8f66079cb21698280329a8a886` |
| TLSH | `T1FAC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:jE8vCB+25j6es8R+t9FYpMSUpi+20qUpi+20YQX:jE8l25JCd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_f17815cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f17815cd4111cdf8ead2b31c7fef4453b55b18202753495225a564c819ee1138"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-18 00:55:40"
  condition:
    hash.sha256(0, filesize) == "f17815cd4111cdf8ead2b31c7fef4453b55b18202753495225a564c819ee1138"
}
```

### Sample 60: `77e74075645dd76b`

| Field | Value |
|---|---|
| SHA-256 | `77e74075645dd76bc4836bb5e8ffb6a6a1dbdfb520a5cd116b8e6848a6ec61ac` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-18 00:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18ad51d34f7092e6c87930c40cde319a` |
| SHA-1 | `7086f9d1f0f080219b5048418b91a03a9349be51` |
| SHA-256 | `77e74075645dd76bc4836bb5e8ffb6a6a1dbdfb520a5cd116b8e6848a6ec61ac` |
| SHA3-384 | `9668fe39969fd39b1c4246c95c51953316ac83b348fbe23acba6d00092fab44e74a40adb90daa269a32315fa23800abd` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T191E6339869E039FDFA73907C9DE19892E129B82507B3C6CB176483A65E171D0CD3EB13` |
| SSDEEP | `393216:09arm+y38sLWluhEncuv1ZPGTXMCHWUjXVcuI3/PGTAI:090xy3IlJc+ZPGTXMb8XiH/O7` |
| ICON-DHASH | `f0d88ea29ac6e4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_77e74075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77e74075645dd76bc4836bb5e8ffb6a6a1dbdfb520a5cd116b8e6848a6ec61ac"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 00:52:31"
  condition:
    hash.sha256(0, filesize) == "77e74075645dd76bc4836bb5e8ffb6a6a1dbdfb520a5cd116b8e6848a6ec61ac"
}
```

### Sample 61: `2168c23f2dcb38f7`

| Field | Value |
|---|---|
| SHA-256 | `2168c23f2dcb38f747d4919d37e6b8c82bb94999a05fad2649ab367e5c1851f0` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-18 00:50:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92c16a85a554efd0a41dae039dcd95f1` |
| SHA-1 | `a9577180806c44d2d773bf4926efb138eed4d7ea` |
| SHA-256 | `2168c23f2dcb38f747d4919d37e6b8c82bb94999a05fad2649ab367e5c1851f0` |
| SHA3-384 | `61495ff39888984f80f2794c0ec31c48781e39ea45dc342bfc913311dc42e8c35f1705735177bed20817e68c236016e7` |
| TLSH | `T1F4D32A59BC82DE12C6C2567BFE5F82CC371723A8E3EB7117DE155F25328B91A0E2A141` |
| TELFHASH | `t1f1d0a726c8840ae4b765821001e353a09a88f55b565104d0dac51f7fef119227125a31` |
| SSDEEP | `3072:pnWcJ7M91c7WqvTJwFieCbylij1pK02975abnbS:dWcJ7SG7Wktnj+iRo021wnS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_2168c23f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2168c23f2dcb38f747d4919d37e6b8c82bb94999a05fad2649ab367e5c1851f0"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-18 00:50:44"
  condition:
    hash.sha256(0, filesize) == "2168c23f2dcb38f747d4919d37e6b8c82bb94999a05fad2649ab367e5c1851f0"
}
```

### Sample 62: `1578e4e484bbaea2`

| Field | Value |
|---|---|
| SHA-256 | `1578e4e484bbaea2dbcc05bed28b9f507255a986e93c2854931b0020ec5ef04f` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-18 00:44:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b5f192e56b6da504953d53891bbb602` |
| SHA-1 | `c5df5d6bb9dcf49736e878118ec057f75c04d7ed` |
| SHA-256 | `1578e4e484bbaea2dbcc05bed28b9f507255a986e93c2854931b0020ec5ef04f` |
| SHA3-384 | `c5ee6cc5bf4ea655532a3933b29b2ad1ad0741bf99108f47cc1fab804b3081d57863a053970140aab6b5f9e37c6f354a` |
| TLSH | `T14BE3E80E7E218F7CF795823447B7DE1A965833C637E1C585D1ACEA012E2068E645FFA8` |
| TELFHASH | `t10d1179084d3823f097745c9e1adeff72e59170ef0a261d378e00e8adaa6c9429e00c2c` |
| SSDEEP | `3072:ZhdK+SE7ktsNOT8wR41M7qlkoKrMh8XQPr6elpURzrnPcH+14tTI7V7mFM7mYQrX:ndK+SE7ktsNOT8wR41M7qlkoKrMh8XQL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_1578e4e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1578e4e484bbaea2dbcc05bed28b9f507255a986e93c2854931b0020ec5ef04f"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-18 00:44:47"
  condition:
    hash.sha256(0, filesize) == "1578e4e484bbaea2dbcc05bed28b9f507255a986e93c2854931b0020ec5ef04f"
}
```

### Sample 63: `a5f088b577ee85ec`

| Field | Value |
|---|---|
| SHA-256 | `a5f088b577ee85ece2ee1cbca0606ba90331891d7532898f778d9c0bcec4d82d` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 00:43:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f90c5537e978450038900874ea431dc2` |
| SHA-1 | `5ffaebfbbd009af50d467fbb9ed467bcce6abc5b` |
| SHA-256 | `a5f088b577ee85ece2ee1cbca0606ba90331891d7532898f778d9c0bcec4d82d` |
| SHA3-384 | `07bd6315e6e4f71e5ec36cacb0cb195c471b006998321ed6f77957c0c118a4d7a3cf2deff631ecbbb154e5a4e008c8c3` |
| TLSH | `T1BD04080AAF600EF7D86FCC3B42E94B0625CC655722A43B757534E928F64A54F4AE3CB4` |
| SSDEEP | `3072:UiNGiCbqOX5pQWIX5gjdGR+N0tb3HCIW38HHJXfanbK:FNMEb5gjQR+WDiIQ8HHoK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_a5f088b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5f088b577ee85ece2ee1cbca0606ba90331891d7532898f778d9c0bcec4d82d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 00:43:57"
  condition:
    hash.sha256(0, filesize) == "a5f088b577ee85ece2ee1cbca0606ba90331891d7532898f778d9c0bcec4d82d"
}
```

### Sample 64: `8ebb41b0bfd24c9f`

| Field | Value |
|---|---|
| SHA-256 | `8ebb41b0bfd24c9f2525723c51b6612aade42f84591e2323417636886774d49a` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-18 00:43:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76ca2c0a9e8d009c5a52b0c4f93e890d` |
| SHA-1 | `4bb5dcb8db8c7705f6b618a417e24a7d0b46a57c` |
| SHA-256 | `8ebb41b0bfd24c9f2525723c51b6612aade42f84591e2323417636886774d49a` |
| SHA3-384 | `5a1155d263ed7fc40f22904160118ac5e3c9f08812ff5438b71002c05aded187eadf771f5fb1e38ef7570b558638a4ea` |
| TLSH | `T18733F1AC6F8D84AFF58AD1BBCDB3CFB02B220771F0839991798D698586855447DC3584` |
| SSDEEP | `768:0sq/h788rVWM1m+UcwUf8FkHBkcvATyba/05VSI3Hk590Wt9dcjczpoByoJgGlzR:Fq5QM1ttR8Ttybz5rI97POA6DVJu8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_8ebb41b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ebb41b0bfd24c9f2525723c51b6612aade42f84591e2323417636886774d49a"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-18 00:43:54"
  condition:
    hash.sha256(0, filesize) == "8ebb41b0bfd24c9f2525723c51b6612aade42f84591e2323417636886774d49a"
}
```

### Sample 65: `1265919aa72f3fa6`

| Field | Value |
|---|---|
| SHA-256 | `1265919aa72f3fa68c775fe66a60c286cccd79f46fd79424ad50ba204a94f5c4` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-18 00:40:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0b97d48187921f4d5fbab602ebb70ba` |
| SHA-1 | `7d01ef6c6e15424e0540b8dbbbb7fc974ae27f5b` |
| SHA-256 | `1265919aa72f3fa68c775fe66a60c286cccd79f46fd79424ad50ba204a94f5c4` |
| SHA3-384 | `cabb0386c27fc7a9bf3aa056d447f461ca53253d661126e6f5030df09e6d31cd00034f00c6c6ed64764537b96c56854e` |
| TLSH | `T1FE04D51E6E258F3DF679C73487F74E20975873C72AE1C545D1ACE9111E2028EA81FBA8` |
| TELFHASH | `t19e219d5c457823f097701d9d6beeef77e5a070df46262d338e10a96caaadd819e00c2c` |
| SSDEEP | `3072:QSCO3sBore1KU5wLI84N90OUyb3nINKGmVMWfCiNAmsnbzPjMV:QSCOQie1TwDA90OU4nMOXLPQz7MV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_1265919a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1265919aa72f3fa68c775fe66a60c286cccd79f46fd79424ad50ba204a94f5c4"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-18 00:40:12"
  condition:
    hash.sha256(0, filesize) == "1265919aa72f3fa68c775fe66a60c286cccd79f46fd79424ad50ba204a94f5c4"
}
```

### Sample 66: `e7ffadca7485550f`

| Field | Value |
|---|---|
| SHA-256 | `e7ffadca7485550fa00a049f12f3e7e957f7fc19dae3229927af7cc39b13ba46` |
| Family label | `Mirai` |
| File name | `nz.arc` |
| File type | `elf` |
| First seen | `2026-07-18 00:34:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b249d033409a189756cd15f43bc5309a` |
| SHA-1 | `13e5d50ec92b0baf79c960aff50f45f8b93a5c6d` |
| SHA-256 | `e7ffadca7485550fa00a049f12f3e7e957f7fc19dae3229927af7cc39b13ba46` |
| SHA3-384 | `7412a0230b9727a5c70559164567d3e7c009cae277ddc18fcea944f8969f65bd1ae7297ac3dd4c1d06ebba7d35303ef0` |
| TLSH | `T11DE3BE97F6472092C96302F407CB6BCD2E6362825F9BD9E7AD2F753B19360DB1402792` |
| SSDEEP | `3072:jfpcpGAcRtyMNJYPpQZE9wXyQbaYOdHgu7eq:jgGF7CIXfq7eq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_e7ffadca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7ffadca7485550fa00a049f12f3e7e957f7fc19dae3229927af7cc39b13ba46"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-18 00:34:48"
  condition:
    hash.sha256(0, filesize) == "e7ffadca7485550fa00a049f12f3e7e957f7fc19dae3229927af7cc39b13ba46"
}
```

### Sample 67: `154d5729d26ae38f`

| Field | Value |
|---|---|
| SHA-256 | `154d5729d26ae38ff37e7d1463a019d259da7c0f9a37e4482333e1e686ebe39e` |
| Family label | `Mirai` |
| File name | `tmips` |
| File type | `elf` |
| First seen | `2026-07-18 00:30:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ef22b34e8e79faecf2bf2f788ea4c2d` |
| SHA-1 | `a54439958aa6de6c7fac5d91354c1e2960dc8bf8` |
| SHA-256 | `154d5729d26ae38ff37e7d1463a019d259da7c0f9a37e4482333e1e686ebe39e` |
| SHA3-384 | `f08e4458a0b6d78a48e5f94b312b378c9a40c565e2b23c7abe671d681d773e9a11ab0201f398e8ba07f69e247d4150fb` |
| TLSH | `T146B3A61A2E219FBEF35D823547F78E25935C23C627F1D685D29CE9001E6038E685FBA4` |
| TELFHASH | `t10f115218593813f0ab761ddd6becff72e59170eb46206e3b8c00e9ad9a2dd425d00c1c` |
| SSDEEP | `3072:aW7WdO0y3a4myWgAR81tZB6VbsQT63dWlKwxp:aW7WdOb3a4myW+alsQON+p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_154d5729
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "154d5729d26ae38ff37e7d1463a019d259da7c0f9a37e4482333e1e686ebe39e"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-18 00:30:11"
  condition:
    hash.sha256(0, filesize) == "154d5729d26ae38ff37e7d1463a019d259da7c0f9a37e4482333e1e686ebe39e"
}
```

### Sample 68: `18cbee63748bff04`

| Field | Value |
|---|---|
| SHA-256 | `18cbee63748bff047d7d51ebc934409f8cb3ba1ea814daae638122272de1a314` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-18 00:21:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d2b141f8f5176505f1e44395f3ffcb7` |
| SHA-1 | `5cd3687f667523e1d8d280ece20eefcafebdf566` |
| SHA-256 | `18cbee63748bff047d7d51ebc934409f8cb3ba1ea814daae638122272de1a314` |
| SHA3-384 | `95159d07bf22a8b61c98cabf9441cd2256e7a579853878cee63e7e1848d78fc61c82fe2c230c807b0123c6492fc5bef4` |
| TLSH | `T14EB34BC4E243D0F9EC560534213AFB379A73E5BF212DDA43D3A49AB26C96AC1D40679C` |
| TELFHASH | `t12131d1fcb2770ce45bc09902f58e8b22cd0d7b2b296076a345b26924326755243bfc38` |
| SSDEEP | `3072:hd5qGekwumbRajd24Wg4I28xxfebx/S3HgGS:75qGek6bRaj4JI3GJS3HgGS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_18cbee63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cbee63748bff047d7d51ebc934409f8cb3ba1ea814daae638122272de1a314"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-18 00:21:40"
  condition:
    hash.sha256(0, filesize) == "18cbee63748bff047d7d51ebc934409f8cb3ba1ea814daae638122272de1a314"
}
```

### Sample 69: `7243738e2b27922c`

| Field | Value |
|---|---|
| SHA-256 | `7243738e2b27922cd5daed7bb1e9382e87196583976c7a54372f2f149eec3596` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-18 00:20:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24708f77ce099c695be8e2337a65f8ae` |
| SHA-1 | `404efa7c38976fa6b50add27743609711ca6c27c` |
| SHA-256 | `7243738e2b27922cd5daed7bb1e9382e87196583976c7a54372f2f149eec3596` |
| SHA3-384 | `9117ddec3c8eb4eb9ef3a0198e64bc4d3413953748a4492c228cc07415c33c00268aabe301e13a5a52cbe02aa48efa75` |
| TLSH | `T18923F156F9792E44D66BB23475AD31C314E0E08D7EA2807F8EA4B46A8575F58AC3C3C3` |
| SSDEEP | `768:VQKTOSNoekrlarmeqOskbRUXwE5L4owd3jdJZQc3WrqamIHDLn4aCMJ7V8nbcuyH:VQKTOGoeO1eqlXwOEowd50MTIjLnjZ7R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_7243738e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7243738e2b27922cd5daed7bb1e9382e87196583976c7a54372f2f149eec3596"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-18 00:20:55"
  condition:
    hash.sha256(0, filesize) == "7243738e2b27922cd5daed7bb1e9382e87196583976c7a54372f2f149eec3596"
}
```

### Sample 70: `1de6220fc4c3502a`

| Field | Value |
|---|---|
| SHA-256 | `1de6220fc4c3502a55fa5cc220b9a91cead25fc34bc7d3610edf1914f83bc379` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-18 00:03:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba47077313749af6c1f97dbb65b9e6a2` |
| SHA-1 | `40b7735e6ea705c3df915ef167c4a7a1f7ea9f8a` |
| SHA-256 | `1de6220fc4c3502a55fa5cc220b9a91cead25fc34bc7d3610edf1914f83bc379` |
| SHA3-384 | `9a8982dae0dc20746c8be73a24408eb51dec98b1d03710d09599fcf70f094a8017192fb5123fb7789a5f6b6724ac8a97` |
| TLSH | `T178B36C86E743D4F1ED160671143BA35B8A35ED310035EB86EBE52E72AC23F019A1BB5D` |
| TELFHASH | `t1c15159f86e7609ec7b80ac16f3ce2752de0ea7b7216432fa45f319a431e65415279c38` |
| SSDEEP | `1536:xVz0SuCEFpDoCM3zFuX5Bz1lKiMkqcdoss5AsoXtbuY4X4vBmrDtp9yI:QSuCU1vXPDKi8cdi5loXh54ftT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_1de6220f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1de6220fc4c3502a55fa5cc220b9a91cead25fc34bc7d3610edf1914f83bc379"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-18 00:03:42"
  condition:
    hash.sha256(0, filesize) == "1de6220fc4c3502a55fa5cc220b9a91cead25fc34bc7d3610edf1914f83bc379"
}
```

### Sample 71: `c1dd7a5673962d10`

| Field | Value |
|---|---|
| SHA-256 | `c1dd7a5673962d108ec8d1b12b50604a134cc52cc95de6c3bbf680198e8f9cb6` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-17 23:59:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `706896c05dcea348215278389689beb8` |
| SHA-1 | `f37c3668c8fbbc7ab69e31f9fc9cc929c26a2a1d` |
| SHA-256 | `c1dd7a5673962d108ec8d1b12b50604a134cc52cc95de6c3bbf680198e8f9cb6` |
| SHA3-384 | `d76be9e9729440a05efa1988532f12ac35efcb97eaa8b8b217098382bc2841f19e00dee68ba653be7612e0574552d97a` |
| TLSH | `T1D9C33BC0F98B81F6C40B88305166F73FDB7198A95123DA9DEF999F72DA73582912234C` |
| TELFHASH | `t1843124b1f9b21eec5bd08803c6cf4b02ec0de6bb356021bd09fa1a5032b2151517ac3a` |
| SSDEEP | `3072:6FjlzYNVoZXRgn4c30tItERjnDBBMesWrhK8HR:mYNVoZhkD3OItYzDjw8HR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_c1dd7a56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1dd7a5673962d108ec8d1b12b50604a134cc52cc95de6c3bbf680198e8f9cb6"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-17 23:59:36"
  condition:
    hash.sha256(0, filesize) == "c1dd7a5673962d108ec8d1b12b50604a134cc52cc95de6c3bbf680198e8f9cb6"
}
```

### Sample 72: `61eb8e47031b9c5a`

| Field | Value |
|---|---|
| SHA-256 | `61eb8e47031b9c5ac19f887926f3a03604ae1dec521dad76db3136a1469be7b6` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-17 23:58:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e261745902c9039c29cdc8e6e1c4c55c` |
| SHA-1 | `a9ecdb339591ebc296912bba8c4a1d32bb03f765` |
| SHA-256 | `61eb8e47031b9c5ac19f887926f3a03604ae1dec521dad76db3136a1469be7b6` |
| SHA3-384 | `b44941a347ad27fc14ed4eb5a6873ecfb839793b30ad83c7cf4dc1848c7dc7ec4a8fb1aeac8483a2ae75ef588227bff3` |
| TLSH | `T11323F12401F66E54B21F87F7595EFB1A2F2464566621C6C731E0E070A2F3B3F0B386A6` |
| SSDEEP | `768:vYcUTiSFnR+ZW54r03UK12jc8/xCrNhRQeccxdk05pHFFGxhUWVuA5cF/1nbcuyL:vYcUTiMnR+1rKm9gTRRcyplFGxn35cjI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_61eb8e47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61eb8e47031b9c5ac19f887926f3a03604ae1dec521dad76db3136a1469be7b6"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-17 23:58:38"
  condition:
    hash.sha256(0, filesize) == "61eb8e47031b9c5ac19f887926f3a03604ae1dec521dad76db3136a1469be7b6"
}
```

### Sample 73: `afaf5a58dd6e9586`

| Field | Value |
|---|---|
| SHA-256 | `afaf5a58dd6e9586701b97b9e5b454846f3ce0053a0aa44b196626d7f4a4e5d4` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-17 23:56:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bec04790ec99c1ca51a919a431abd32` |
| SHA-1 | `890fdcebd5b9142716115feb30b7ad80b0a208ac` |
| SHA-256 | `afaf5a58dd6e9586701b97b9e5b454846f3ce0053a0aa44b196626d7f4a4e5d4` |
| SHA3-384 | `472c6ef03838ca919d9b665ee491a2fdb851fad4ad37d05e6a248a696cedfde923ee8f69471ac12d6cac94efad4bb7c5` |
| TLSH | `T1A8148E01FB180953D4932EB44B3F07A6D379D88318F9E109190ABB561733EB7A6C7B89` |
| SSDEEP | `3072:kdqDIz5qCymAWY0+bcxwvyeyagZAAkQOpUoooS1qRZ1DrooER:HDZCyCY0+bcavRddAkQOpUoooS1+fQoq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_afaf5a58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afaf5a58dd6e9586701b97b9e5b454846f3ce0053a0aa44b196626d7f4a4e5d4"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 23:56:01"
  condition:
    hash.sha256(0, filesize) == "afaf5a58dd6e9586701b97b9e5b454846f3ce0053a0aa44b196626d7f4a4e5d4"
}
```

### Sample 74: `f0506419d1f60d71`

| Field | Value |
|---|---|
| SHA-256 | `f0506419d1f60d7180e72fdcca97d5446d3cc3218d61b11dcd39b49086553683` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-17 23:54:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1cb1044e428a4ace0ecdeddc8bd0310` |
| SHA-1 | `f3dfc49825a5b870d77cc4298326df10cdb6cd23` |
| SHA-256 | `f0506419d1f60d7180e72fdcca97d5446d3cc3218d61b11dcd39b49086553683` |
| SHA3-384 | `44639ce93168a39a68c1f1b7d525f11a4071663fc971609c6dd17a95c1fd4c6c453835107b66016f1b6e17abcdbb974d` |
| TLSH | `T1CF530240C0D39857C5ABD6B93A8DE75867E419527AA8CBE023EBFF49783A7C0317015A` |
| SSDEEP | `1536:8KUohruhQWQL/wB6E++BOpw1CYAPwJb1Jw7oI724u+qgw0rC:NruhQFHF+BOG9k2nw24u+qgwN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_f0506419
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0506419d1f60d7180e72fdcca97d5446d3cc3218d61b11dcd39b49086553683"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 23:54:30"
  condition:
    hash.sha256(0, filesize) == "f0506419d1f60d7180e72fdcca97d5446d3cc3218d61b11dcd39b49086553683"
}
```

### Sample 75: `448776210b0c1802`

| Field | Value |
|---|---|
| SHA-256 | `448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-17 23:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cec03a97aad76c90dd6676ba37ba1d29` |
| SHA-1 | `7915b613f7b28bbbc0f56b2205078d1048d90cfd` |
| SHA-256 | `448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a` |
| SHA3-384 | `df8853df0c74d49bc552dc8a5ec12fede81b386bb34b7b11bdd7637ebba6047ae94f9bc4252cdb1e6849f600d0a2a8c0` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C9E6331CAAC105FEE5B3017DB6B152A6E966F8761B31CD8B03984352BD231E05E3DB1B` |
| SSDEEP | `393216:fxg4SAKdBMvN/jAvkZqZNOy5WXMCHWUjXbcuI3/PGTAI:fW4SApvVjAvk2DWXMb8XYH/O7` |
| ICON-DHASH | `f4f8fcbc8cc47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_44877621
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 23:52:32"
  condition:
    hash.sha256(0, filesize) == "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
}
```

### Sample 76: `b25c3c740aead577`

| Field | Value |
|---|---|
| SHA-256 | `b25c3c740aead577c7c89894e80ee57c63d5acd78e62d789213fda023bfbaf3c` |
| Family label | `Mirai` |
| File name | `nz.sh` |
| File type | `sh` |
| First seen | `2026-07-17 23:50:08` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abdcc6b6768a43b65d95ac3344678938` |
| SHA-1 | `1e150c526760ca4ab4a490b2cdf9abd3ca3aadb3` |
| SHA-256 | `b25c3c740aead577c7c89894e80ee57c63d5acd78e62d789213fda023bfbaf3c` |
| SHA3-384 | `ee72c4ad03b661a8ce29e73c2c9042d8393fa82f03d8f9628c36470e08b2cfa60b407ee5dcad9c69f5951f3820bbc359` |
| TLSH | `T19A2162C7110503302EB6D9E6BBBB485970D0E1DE54C3BF6BA8D8B8E9828ED0C7C42653` |
| SSDEEP | `24:ItSTfsS3+3IhOESxW3SexASoZPsSwySxTnxTGFC:irNEJ3GQ4KTxTGFC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_b25c3c74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b25c3c740aead577c7c89894e80ee57c63d5acd78e62d789213fda023bfbaf3c"
    family = "Mirai"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:50:08"
  condition:
    hash.sha256(0, filesize) == "b25c3c740aead577c7c89894e80ee57c63d5acd78e62d789213fda023bfbaf3c"
}
```

### Sample 77: `55c28ae706e71466`

| Field | Value |
|---|---|
| SHA-256 | `55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe` |
| Family label | `WannaCry` |
| File name | `55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe` |
| File type | `exe` |
| First seen | `2026-07-17 23:15:29` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e904d175277278ea87b853235875fdc9` |
| SHA-1 | `d917862e4dc8f55819dfde493322481bc9c58ef9` |
| SHA-256 | `55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe` |
| SHA3-384 | `f21fac7fc332a5f53421143a45fbf19433cafe758b71a8999033e0dcbf3dfa0f665349ce4511d7c7beefbf11660e4534` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T17936234D32AC81FCD107167494B7CE26F3B3BC6E22B95B0F9B5085761D03B96AB64B12` |
| SSDEEP | `24576:jbLgKbLgdritdmMSirYbcMNgef0QeQjG/D8kIqRYoAdNLKz6626M+pSk+RdhAdmf:jnbn6MSPbcBVQej/1INRx+pARdhnvn` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_077_55c28ae7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe"
    family = "WannaCry"
    file_name = "55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe"
    file_type = "exe"
    first_seen = "2026-07-17 23:15:29"
  condition:
    hash.sha256(0, filesize) == "55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe"
}
```

### Sample 78: `fd0ff75925ea1576`

| Field | Value |
|---|---|
| SHA-256 | `fd0ff75925ea15760d72c1a9ffbcc0e751abebb2f4cd49f0bd11274a04706217` |
| Family label | `Mirai` |
| File name | `gmips` |
| File type | `elf` |
| First seen | `2026-07-17 23:14:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d3b8238ad92d6d863840ad22194fea7` |
| SHA-1 | `3a4653631a0cf18fd218daa4ae5a7bebe01e0c59` |
| SHA-256 | `fd0ff75925ea15760d72c1a9ffbcc0e751abebb2f4cd49f0bd11274a04706217` |
| SHA3-384 | `b74e7b6fcd941932d390420870058800759f3bde67ea105ac319e31aca476462ceb9de27776262b0e8f398fbf6ac09f9` |
| TLSH | `T13BE3B50E6F394F2DF3798335D7F749259B5872822AD1C649C27CF9121E2024E641FBAA` |
| TELFHASH | `t1fc217f0c497822e0a7755c992beeff73e5a130df56366d338e10adadaabd9424d00c1c` |
| SSDEEP | `3072:vHMGFeCUOsBxhj32yUP34+1Rb82Jh1WQot8d8fEda5FC10z5y535VfFmgqToRKV6:vH/FNUOs72WfGKT2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_fd0ff759
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0ff75925ea15760d72c1a9ffbcc0e751abebb2f4cd49f0bd11274a04706217"
    family = "Mirai"
    file_name = "gmips"
    file_type = "elf"
    first_seen = "2026-07-17 23:14:09"
  condition:
    hash.sha256(0, filesize) == "fd0ff75925ea15760d72c1a9ffbcc0e751abebb2f4cd49f0bd11274a04706217"
}
```

### Sample 79: `8689dd49ac380c1a`

| Field | Value |
|---|---|
| SHA-256 | `8689dd49ac380c1a3c15509eb1fa842ab69374c00f453a1f7f86e4693958606d` |
| Family label | `unknown` |
| File name | `dvr.sh` |
| File type | `sh` |
| First seen | `2026-07-17 23:09:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fdeaf02d78f931d20874f8bda9d7c98` |
| SHA-1 | `f99c5762f4deb50c119685a159f6d40de68d746d` |
| SHA-256 | `8689dd49ac380c1a3c15509eb1fa842ab69374c00f453a1f7f86e4693958606d` |
| SHA3-384 | `bd6a51d8897bfbb1c81cca5ff6449228bbbb1e2951ca7ed903332c1a0236944f29f754f6a6447783fa383998c9d16edb` |
| TLSH | `T1BC01C8AF805140D16F84E90879A34924B20ABBDA34F68F8C9C8E287511DD998F831F54` |
| SSDEEP | `12:t9hZDmHWxnHWxzvazMHW3IjDWIMHWyDiHWq:t9hZkWlWxzCzGW3rhWywWq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_8689dd49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8689dd49ac380c1a3c15509eb1fa842ab69374c00f453a1f7f86e4693958606d"
    family = "unknown"
    file_name = "dvr.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:38"
  condition:
    hash.sha256(0, filesize) == "8689dd49ac380c1a3c15509eb1fa842ab69374c00f453a1f7f86e4693958606d"
}
```

### Sample 80: `cc6964a4808fddb9`

| Field | Value |
|---|---|
| SHA-256 | `cc6964a4808fddb922b8889d83fd0724f6bab22125458690ab189a93978b2638` |
| Family label | `Mirai` |
| File name | `gmpsl` |
| File type | `elf` |
| First seen | `2026-07-17 23:09:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b343d6bc78b939a1ef24ea00a55a955` |
| SHA-1 | `3425c84e8595d2411bc81d7c4d4643d833862c3d` |
| SHA-256 | `cc6964a4808fddb922b8889d83fd0724f6bab22125458690ab189a93978b2638` |
| SHA3-384 | `1ce0435e22046a1c4ea2bdbab9bd09e52a93e23be7be762bb5104dddebd0eefd2ed1325c9c42327029d566060651219d` |
| TLSH | `T15EF3D716AF602EF7D8EBCC7791B9C70A34CC645A22A42BB57534E424B64B44F5AD38F0` |
| SSDEEP | `3072:1Mz0FY6Gkr81p0ABo1kgMcbFyRJlCrbNpdCCtnb+S:1TJGkKp0AC1k8FYCr5+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_cc6964a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc6964a4808fddb922b8889d83fd0724f6bab22125458690ab189a93978b2638"
    family = "Mirai"
    file_name = "gmpsl"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:36"
  condition:
    hash.sha256(0, filesize) == "cc6964a4808fddb922b8889d83fd0724f6bab22125458690ab189a93978b2638"
}
```

### Sample 81: `6bba47b8780a872f`

| Field | Value |
|---|---|
| SHA-256 | `6bba47b8780a872fca03c7776396e13def783ee4ce13deff1fdfce75e32f1346` |
| Family label | `unknown` |
| File name | `dvr.sh` |
| File type | `sh` |
| First seen | `2026-07-17 23:09:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15b9f1c2406640652b3c0a01afb27dc2` |
| SHA-1 | `083c3e96fa5f867554277a7588529d87dd525ae0` |
| SHA-256 | `6bba47b8780a872fca03c7776396e13def783ee4ce13deff1fdfce75e32f1346` |
| SHA3-384 | `e0240f6a65cec2bbd11bfb65f1dc4989cd376c4a708a3f26bb4bf34f058d3912f2bb60720414f2b92f6572091cdcec6c` |
| TLSH | `T1B201F4EF049808691641F90EF9638C36711FBFD964C62B8F9DCD6E75118DA18B421FD4` |
| SSDEEP | `12:t9Eh3DoZDeh3DhHWPh3uyeh3uhHWPh3a0zveh3a0zMHWPh3aQ5IjDeh3aQ5IMHWf:t9ExMZyx9WPxuLxuRWPxnz2xnzGWPx1I` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_6bba47b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bba47b8780a872fca03c7776396e13def783ee4ce13deff1fdfce75e32f1346"
    family = "unknown"
    file_name = "dvr.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:34"
  condition:
    hash.sha256(0, filesize) == "6bba47b8780a872fca03c7776396e13def783ee4ce13deff1fdfce75e32f1346"
}
```

### Sample 82: `a2dd8c859251c361`

| Field | Value |
|---|---|
| SHA-256 | `a2dd8c859251c361c46d3670536e81d85acaa44ac938f3057bcecdf50b2ad5ee` |
| Family label | `unknown` |
| File name | `telnet.sh` |
| File type | `sh` |
| First seen | `2026-07-17 23:09:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac6af3156b38400a15e7bcba1524bccd` |
| SHA-1 | `89f9503020ff989369627a45d786c56a11d6a40b` |
| SHA-256 | `a2dd8c859251c361c46d3670536e81d85acaa44ac938f3057bcecdf50b2ad5ee` |
| SHA3-384 | `0b93b512d27e736ebfd8502a64cc5e4168eaa628c22b5107e787199329497af16380f740b0a9d02f75807cdb4c0f47ed` |
| TLSH | `T10E3101CD32B09251C649FF01F3E1CBD6AE45FDC866940E7AE4C11CB1486DE8D3865A36` |
| SSDEEP | `12:+kfc0dtnNaKl6KODOmLxf/TK1Sk1YgVbVVb1LBCN0UN0KvtuFe77bLBNCSwlLPTX:TfxHFmDzLxKUkb3A2U2Mtrbr0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_a2dd8c85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2dd8c859251c361c46d3670536e81d85acaa44ac938f3057bcecdf50b2ad5ee"
    family = "unknown"
    file_name = "telnet.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:32"
  condition:
    hash.sha256(0, filesize) == "a2dd8c859251c361c46d3670536e81d85acaa44ac938f3057bcecdf50b2ad5ee"
}
```

### Sample 83: `2d355f96bab2d953`

| Field | Value |
|---|---|
| SHA-256 | `2d355f96bab2d9535a294cf0c1339779643091460447e1102debac8f58571bb2` |
| Family label | `unknown` |
| File name | `t` |
| File type | `unknown` |
| First seen | `2026-07-17 23:09:31` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8ec2eeaabc057f82c11e4d2af0aaa7a` |
| SHA-256 | `2d355f96bab2d9535a294cf0c1339779643091460447e1102debac8f58571bb2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_2d355f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d355f96bab2d9535a294cf0c1339779643091460447e1102debac8f58571bb2"
    family = "unknown"
    file_name = "t"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:31"
  condition:
    hash.sha256(0, filesize) == "2d355f96bab2d9535a294cf0c1339779643091460447e1102debac8f58571bb2"
}
```

### Sample 84: `f14c657d8667f1cc`

| Field | Value |
|---|---|
| SHA-256 | `f14c657d8667f1cc3733e380768a3020d6b56d5c9593817033d3930f2f4d30ca` |
| Family label | `unknown` |
| File name | `sh` |
| File type | `unknown` |
| First seen | `2026-07-17 23:09:29` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78070249db4b0467170c5bf3e4b36826` |
| SHA-256 | `f14c657d8667f1cc3733e380768a3020d6b56d5c9593817033d3930f2f4d30ca` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_f14c657d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f14c657d8667f1cc3733e380768a3020d6b56d5c9593817033d3930f2f4d30ca"
    family = "unknown"
    file_name = "sh"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:29"
  condition:
    hash.sha256(0, filesize) == "f14c657d8667f1cc3733e380768a3020d6b56d5c9593817033d3930f2f4d30ca"
}
```

### Sample 85: `1cf3b8d29609d0c4`

| Field | Value |
|---|---|
| SHA-256 | `1cf3b8d29609d0c4be3e81b39f83ca5de32f13b4ac309e397aca1d451a56339f` |
| Family label | `unknown` |
| File name | `t` |
| File type | `unknown` |
| First seen | `2026-07-17 23:09:28` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19a254a1c12a929b63cd0f97216a349c` |
| SHA-256 | `1cf3b8d29609d0c4be3e81b39f83ca5de32f13b4ac309e397aca1d451a56339f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_1cf3b8d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cf3b8d29609d0c4be3e81b39f83ca5de32f13b4ac309e397aca1d451a56339f"
    family = "unknown"
    file_name = "t"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:28"
  condition:
    hash.sha256(0, filesize) == "1cf3b8d29609d0c4be3e81b39f83ca5de32f13b4ac309e397aca1d451a56339f"
}
```

### Sample 86: `1a59dbd778699f8e`

| Field | Value |
|---|---|
| SHA-256 | `1a59dbd778699f8e4a4fe8ee82fe49cff516d76a9f59e9a212e9381cc2c46c29` |
| Family label | `unknown` |
| File name | `o` |
| File type | `unknown` |
| First seen | `2026-07-17 23:09:27` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5109fce9d4461bead35cb50219e4aacd` |
| SHA-256 | `1a59dbd778699f8e4a4fe8ee82fe49cff516d76a9f59e9a212e9381cc2c46c29` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_1a59dbd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a59dbd778699f8e4a4fe8ee82fe49cff516d76a9f59e9a212e9381cc2c46c29"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:27"
  condition:
    hash.sha256(0, filesize) == "1a59dbd778699f8e4a4fe8ee82fe49cff516d76a9f59e9a212e9381cc2c46c29"
}
```

### Sample 87: `c792b032fb1f7120`

| Field | Value |
|---|---|
| SHA-256 | `c792b032fb1f71205f9f3caf58437f8525d99ffca1530511c86ffd92fd22413b` |
| Family label | `unknown` |
| File name | `o` |
| File type | `unknown` |
| First seen | `2026-07-17 23:09:25` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `915bfc96306d854889017eda91ce1343` |
| SHA-256 | `c792b032fb1f71205f9f3caf58437f8525d99ffca1530511c86ffd92fd22413b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_c792b032
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c792b032fb1f71205f9f3caf58437f8525d99ffca1530511c86ffd92fd22413b"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:25"
  condition:
    hash.sha256(0, filesize) == "c792b032fb1f71205f9f3caf58437f8525d99ffca1530511c86ffd92fd22413b"
}
```

### Sample 88: `902b6affb47b3a6d`

| Field | Value |
|---|---|
| SHA-256 | `902b6affb47b3a6d9f8d618d4dae85730a6d6eadc3c4a8cf66c81f5375f9b8ba` |
| Family label | `Mirai` |
| File name | `dlr.arm7` |
| File type | `elf` |
| First seen | `2026-07-17 23:09:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6621db9c84163ec9dc1dd34ba567d93f` |
| SHA-1 | `fca6e34ac7cb27e1b092d6cc8bf977e7248445e4` |
| SHA-256 | `902b6affb47b3a6d9f8d618d4dae85730a6d6eadc3c4a8cf66c81f5375f9b8ba` |
| SHA3-384 | `a30c14380f75c4c524d8da5fd2eb694593d649e74c0d6c286c065e099f1397d26e1ba164cff330c10ce446e9d001d4ce` |
| TLSH | `T1C831CAA1A7D09DBDC4F451BE9E5B0310B3799F00E0C67222870C636A6C1AE3CAD27446` |
| TELFHASH | `t1cb900262474fbb68b245018048c90104c5e4e51b0460986145491c404852a107510210` |
| SSDEEP | `24:uTcRKGpa7Urz/jlfo+XK1hZVev3gRGaJ9ixBBuLlTO9gjSq:uARKGpa7UrLZos+JCBu1OZq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_902b6aff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "902b6affb47b3a6d9f8d618d4dae85730a6d6eadc3c4a8cf66c81f5375f9b8ba"
    family = "Mirai"
    file_name = "dlr.arm7"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:24"
  condition:
    hash.sha256(0, filesize) == "902b6affb47b3a6d9f8d618d4dae85730a6d6eadc3c4a8cf66c81f5375f9b8ba"
}
```

### Sample 89: `1cc57bc4e2443925`

| Field | Value |
|---|---|
| SHA-256 | `1cc57bc4e2443925408d907347346a8389ea4c55132e288dc5596fa29702dc60` |
| Family label | `Mirai` |
| File name | `dlr.x86` |
| File type | `elf` |
| First seen | `2026-07-17 23:09:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c145042af90426a45dfea751640e659` |
| SHA-1 | `d20330b7438fd03b5ad8bc9d29037b716e9da2fd` |
| SHA-256 | `1cc57bc4e2443925408d907347346a8389ea4c55132e288dc5596fa29702dc60` |
| SHA3-384 | `6fc2de40cf08ef1e74ae1ea127b4ff5abb39740125ba9c19927c739bd661782035971c5cf4dc2dc909c4f2ec0db6a3b6` |
| TLSH | `T191210E66E2DDE932E73200F652CAFF4727858E903467FF0B8A914502ED2A6D0C133274` |
| TELFHASH | `t116a002a12f4f44acb7c0334c1d56405145ed14f7175125c074b0760937c29095871110` |
| SSDEEP | `24:FlYbjMsWOJFHxgxEmceZGQleZ3eLt5AvB2wyGues9OXruQ63QKFNfvnw:fYbjoOL+coGQlo3eLt5AZKqssbHkQ6NQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_1cc57bc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cc57bc4e2443925408d907347346a8389ea4c55132e288dc5596fa29702dc60"
    family = "Mirai"
    file_name = "dlr.x86"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:22"
  condition:
    hash.sha256(0, filesize) == "1cc57bc4e2443925408d907347346a8389ea4c55132e288dc5596fa29702dc60"
}
```

### Sample 90: `b5b220b1dff259ef`

| Field | Value |
|---|---|
| SHA-256 | `b5b220b1dff259efdaf017b58aae836955096f6ffe8cdca658c1b6887b35dfbf` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-17 23:09:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a064dcdbc05bef30b19a4ea35834ea8c` |
| SHA-1 | `6ec0542779de680c589272e0e78e28e3051a7895` |
| SHA-256 | `b5b220b1dff259efdaf017b58aae836955096f6ffe8cdca658c1b6887b35dfbf` |
| SHA3-384 | `8df2fc6f5728cda7d4b1aedccfba976272a021bc2052edf905a144b38a7f6204ab79f809a1018372dc372882aa80324e` |
| TLSH | `T102E3075AF8829F11D4D625BEFE5E928D331327ACE3EA7112DD245B2533CA91B0E3B501` |
| TELFHASH | `t195d0a984640cd6fde386d061e9e263a61929b8d982a8084105e82f2b4f62ee1327481b` |
| SSDEEP | `3072:xWcSqfDrwUw5MVosA11P5Fe9YpZsuR0930ndaPhGQCw18/Uf7YK6f7KInbp:xNSq7rtw5Maswn66suskndaPhGQCw1az` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_b5b220b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5b220b1dff259efdaf017b58aae836955096f6ffe8cdca658c1b6887b35dfbf"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:20"
  condition:
    hash.sha256(0, filesize) == "b5b220b1dff259efdaf017b58aae836955096f6ffe8cdca658c1b6887b35dfbf"
}
```

### Sample 91: `93a9c2cbd2840685`

| Field | Value |
|---|---|
| SHA-256 | `93a9c2cbd2840685150eb1e794fad854df870b2a444c6049b6836340cad95d7f` |
| Family label | `unknown` |
| File name | `shell` |
| File type | `elf` |
| First seen | `2026-07-17 23:09:18` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76fb40944c1ab98f5cfcaf0d3517cfae` |
| SHA-1 | `23c98f0811ee210e59191f358dd4ee6e9cfda635` |
| SHA-256 | `93a9c2cbd2840685150eb1e794fad854df870b2a444c6049b6836340cad95d7f` |
| SHA3-384 | `c31bd29cc30734e7e67604a6a4ffa0c52a677ea4fc2989948c3df7824072d589a343df39e29653835318907c58162056` |
| TLSH | `T13E23FB127A61EFFBD45AD2304BF38A2016E476A51EA1534EF25CEB5C0F216CC2C5B7A4` |
| TELFHASH | `t171d02b47603b41653f615c7958344bda8843c62223e077b0af5bc3899837601a123f0f` |
| SSDEEP | `768:Zam4xZV0K2XLyyL/ee5y3r8IYW7hV/awLHv9Qhvp1+sG:ZamCZV0Jee5lGRv9Qhvp1+sG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_93a9c2cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93a9c2cbd2840685150eb1e794fad854df870b2a444c6049b6836340cad95d7f"
    family = "unknown"
    file_name = "shell"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:18"
  condition:
    hash.sha256(0, filesize) == "93a9c2cbd2840685150eb1e794fad854df870b2a444c6049b6836340cad95d7f"
}
```

### Sample 92: `9a55fb188177ac65`

| Field | Value |
|---|---|
| SHA-256 | `9a55fb188177ac65e7bdea528c6ed357fe333975de529539c60b233ee35379c5` |
| Family label | `unknown` |
| File name | `t` |
| File type | `unknown` |
| First seen | `2026-07-17 23:09:17` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86792834bdf2abb9b47d6eb6f7caeb01` |
| SHA-256 | `9a55fb188177ac65e7bdea528c6ed357fe333975de529539c60b233ee35379c5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_9a55fb18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a55fb188177ac65e7bdea528c6ed357fe333975de529539c60b233ee35379c5"
    family = "unknown"
    file_name = "t"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:17"
  condition:
    hash.sha256(0, filesize) == "9a55fb188177ac65e7bdea528c6ed357fe333975de529539c60b233ee35379c5"
}
```

### Sample 93: `39fdaaa503065403`

| Field | Value |
|---|---|
| SHA-256 | `39fdaaa503065403e9cca7ea29efd9d43f245b8b976cfadd70ddb1d364ddffe3` |
| Family label | `Mirai` |
| File name | `all.sh` |
| File type | `sh` |
| First seen | `2026-07-17 23:09:15` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df4bcc77165dce73df0b2ad004fff710` |
| SHA-1 | `a74a2dba577b4d73d81a641eaa2ce6f11a45dffd` |
| SHA-256 | `39fdaaa503065403e9cca7ea29efd9d43f245b8b976cfadd70ddb1d364ddffe3` |
| SHA3-384 | `d56f5407322b17cf91f50e388ea480f855d9b013a1dcfd8dfae1f88ffb22204861d234e1350a74fc8aebf5a091822957` |
| TLSH | `T15901B9E1217414F63AEEE4DA59731C1C318654753D865CF83C6EB4D6359DC84B0B2899` |
| SSDEEP | `24:ZDkH/FbfNHFJNHFoNHFWWFzFM5gFvWWFJFMDgFvaeD:hOFbfNLNyN06` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_39fdaaa5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39fdaaa503065403e9cca7ea29efd9d43f245b8b976cfadd70ddb1d364ddffe3"
    family = "Mirai"
    file_name = "all.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:15"
  condition:
    hash.sha256(0, filesize) == "39fdaaa503065403e9cca7ea29efd9d43f245b8b976cfadd70ddb1d364ddffe3"
}
```

### Sample 94: `63cf5ade63155747`

| Field | Value |
|---|---|
| SHA-256 | `63cf5ade631557478a2cf13fce75b593b76edfca7a991889b8b11f52fc05f631` |
| Family label | `unknown` |
| File name | `all.sh` |
| File type | `sh` |
| First seen | `2026-07-17 23:09:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `831da6b052361d372c7b31cfa23a3a45` |
| SHA-1 | `333d9dd910a2e54c5e3690c8b5953903c1095868` |
| SHA-256 | `63cf5ade631557478a2cf13fce75b593b76edfca7a991889b8b11f52fc05f631` |
| SHA3-384 | `3e02caca1f553c05830901e163094d1c99a226eb0f6ae6c95cf461bcafd4c46a160a65d5989d8e9f1107a23d3a4685d0` |
| TLSH | `T10DF0F4C4217120B075A7E8EA4A731C5C30E5A45A3ED72CFC3CB6F4DA56E5C14A0821ED` |
| SSDEEP | `12:YkF1kcClZF70SaHFgHF3HFWpFSpFM5gFrpFSXFMDgFvA1LRPb:ZDkH/FbaHFgHF3HFWpFQFM5gFrpF+FMV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_63cf5ade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63cf5ade631557478a2cf13fce75b593b76edfca7a991889b8b11f52fc05f631"
    family = "unknown"
    file_name = "all.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:14"
  condition:
    hash.sha256(0, filesize) == "63cf5ade631557478a2cf13fce75b593b76edfca7a991889b8b11f52fc05f631"
}
```

### Sample 95: `5ec1a4f708c09e43`

| Field | Value |
|---|---|
| SHA-256 | `5ec1a4f708c09e4382fe7af1ce9cb02524735f53409e53c27980e094d60d4296` |
| Family label | `unknown` |
| File name | `o` |
| File type | `unknown` |
| First seen | `2026-07-17 23:09:11` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `046c2cab0c7e91fd8837de14cb66a2ba` |
| SHA-256 | `5ec1a4f708c09e4382fe7af1ce9cb02524735f53409e53c27980e094d60d4296` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_5ec1a4f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ec1a4f708c09e4382fe7af1ce9cb02524735f53409e53c27980e094d60d4296"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:11"
  condition:
    hash.sha256(0, filesize) == "5ec1a4f708c09e4382fe7af1ce9cb02524735f53409e53c27980e094d60d4296"
}
```

### Sample 96: `e7c92caf850de1f3`

| Field | Value |
|---|---|
| SHA-256 | `e7c92caf850de1f30e8ba00d17025ff795bd9fdcdb346cb4f1b8915d534c57a2` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-17 22:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eec45dd828c3a40c158aa74b97f086f3` |
| SHA-1 | `a089d36cbc44b3f59aece3cb9477be9f71bc33a0` |
| SHA-256 | `e7c92caf850de1f30e8ba00d17025ff795bd9fdcdb346cb4f1b8915d534c57a2` |
| SHA3-384 | `6dc10d0b36849811cef29a93eeaea5db4e85bed7038c138b6eceee52f23a317b595967930a632dfccc00bc53b2d0657a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T13AE63308B6D423EEDA73817DEEE28552E5FA74640335CEDB875842A52D032F28C39797` |
| SSDEEP | `393216:01BK/WFsXvvA+xhDJXMCHWUjX6cuI3/PGTAI:0jWNfvA+NXMb8X3H/O7` |
| ICON-DHASH | `70f0e4c4c4e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_e7c92caf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7c92caf850de1f30e8ba00d17025ff795bd9fdcdb346cb4f1b8915d534c57a2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 22:52:32"
  condition:
    hash.sha256(0, filesize) == "e7c92caf850de1f30e8ba00d17025ff795bd9fdcdb346cb4f1b8915d534c57a2"
}
```

### Sample 97: `89ce478cd3190b04`

| Field | Value |
|---|---|
| SHA-256 | `89ce478cd3190b040eaab88adddfa43c166a00371d83b7875c08d109d7e5569a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-17 22:38:13` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c413d7a78b2830e89965c7b3e7e3139e` |
| SHA-1 | `ae72e3532aa10f18984fe5263f8297da85234dbe` |
| SHA-256 | `89ce478cd3190b040eaab88adddfa43c166a00371d83b7875c08d109d7e5569a` |
| SHA3-384 | `f1e04d27df4a346ee9b01e59d0cab4d429de27c38aad1868d7ac6c5abdae572b9f4415f5ab010a92ff2b97f8228dae98` |
| IMPHASH | `47e1b6c93da00245a33e9a81299262d5` |
| TLSH | `T1B4D512463F00E806D4951E759AA8CBF86371FD5C9B56934734E3AE2BBCDE6C32E01285` |
| SSDEEP | `49152:8SJ8j5Hk4plhcy/T3fX5ZoOLJj81ibk7OB4nTnyvBSss7Na9:7J0Bkghc2XxJj81ZT4BSFRa9` |
| ICON-DHASH | `f09682aaaa8296d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_89ce478c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89ce478cd3190b040eaab88adddfa43c166a00371d83b7875c08d109d7e5569a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-17 22:38:13"
  condition:
    hash.sha256(0, filesize) == "89ce478cd3190b040eaab88adddfa43c166a00371d83b7875c08d109d7e5569a"
}
```

### Sample 98: `bf2d153b1b6ac1df`

| Field | Value |
|---|---|
| SHA-256 | `bf2d153b1b6ac1dfb076c520195b283d9c353117005ef849ac146d98ec886192` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-17 22:27:52` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cf6c17d13156ec830da6ed2b0932873` |
| SHA-1 | `9dd9b2b1829612213cbe3a7cd67c34d648e74d69` |
| SHA-256 | `bf2d153b1b6ac1dfb076c520195b283d9c353117005ef849ac146d98ec886192` |
| SHA3-384 | `34ea6c116e5e74d3daf5dcc39e3b48359e2e865e03fe0e19b138838954ff5f1267cc227fbddbfae21d88d84d94a1f758` |
| IMPHASH | `d7cddda1d2ea4ee1d634f7b65dfe4a4d` |
| TLSH | `T179E501577F14D902D0564E319970CBF86721FC488B29838739D6BE6BBDEE6D28E022D4` |
| SSDEEP | `98304:PEX6JnJekZHtuD0TJbTKi4M9YgyFen+bQGratLiBJ:MX+Jze01Ki4Ne+QZiBJ` |
| ICON-DHASH | `9271e8d4cccce8f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_bf2d153b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf2d153b1b6ac1dfb076c520195b283d9c353117005ef849ac146d98ec886192"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-17 22:27:52"
  condition:
    hash.sha256(0, filesize) == "bf2d153b1b6ac1dfb076c520195b283d9c353117005ef849ac146d98ec886192"
}
```

### Sample 99: `c16785a165adcc88`

| Field | Value |
|---|---|
| SHA-256 | `c16785a165adcc885acca91f57c25090ee781705248ba535d889a135cc276b4f` |
| Family label | `unknown` |
| File name | `abe_extractor_amd64.bin` |
| File type | `exe` |
| First seen | `2026-07-17 22:27:52` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be1ff2fa3b9c4dbb64edf967b201decb` |
| SHA-1 | `cd3c097fac9161d1d6eca90fc093a4f54f5e91c7` |
| SHA-256 | `c16785a165adcc885acca91f57c25090ee781705248ba535d889a135cc276b4f` |
| SHA3-384 | `e6b55184266371f23ac2f5711c80c0c6461c8c4c99788dbc6836743d0fdf36dc5da2edcdd665c025fdbb7446a7614546` |
| IMPHASH | `d4af7c7127d0ce8764c777abc0e921ea` |
| TLSH | `T1B772C58AB29764FDC956C17CD2DB8B72F1B1BC4206397E3B4250D2B51D71D9B612C813` |
| SSDEEP | `192:nSfS96haJyylGrg6h5RuuC43hyUlDSHN8SzKOx+8Ce6FMM+0CU0CZ3ktcu:h6cz+DevM5lDSx30Re6xtCvCZ3kyu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_c16785a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c16785a165adcc885acca91f57c25090ee781705248ba535d889a135cc276b4f"
    family = "unknown"
    file_name = "abe_extractor_amd64.bin"
    file_type = "exe"
    first_seen = "2026-07-17 22:27:52"
  condition:
    hash.sha256(0, filesize) == "c16785a165adcc885acca91f57c25090ee781705248ba535d889a135cc276b4f"
}
```

### Sample 100: `10df86d8a7a3f56d`

| Field | Value |
|---|---|
| SHA-256 | `10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8` |
| Family label | `unknown` |
| File name | `10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8` |
| File type | `elf` |
| First seen | `2026-07-17 22:25:31` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59195a5f2cb1795af9d0779b70415995` |
| SHA-1 | `a6d6e58fce9d6fe60a2364e06ff3598fadc649cd` |
| SHA-256 | `10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8` |
| SHA3-384 | `d8105c3b791e0d1d53c1ec1550ea7e3b2552abf7ae84d5aa94d959484d05a8ba959282f8b452801dd794eb09bdf57368` |
| TLSH | `T17527CE77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ2:cqYUQuVDt0TZE1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_10df86d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8"
    family = "unknown"
    file_name = "10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8"
    file_type = "elf"
    first_seen = "2026-07-17 22:25:31"
  condition:
    hash.sha256(0, filesize) == "10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8"
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
 * Generated: 2026-07-18T03:37:55.123797+00:00
 */

rule MalwareBazaar_Prometei_001_b1a20cac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55"
    family = "Prometei"
    file_name = "b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55"
    file_type = "elf"
    first_seen = "2026-07-18 03:08:45"
  condition:
    hash.sha256(0, filesize) == "b1a20cacc85411c68ad770fa6220508a6befa55a2f16dc894c98eb02b96d3f55"
}

rule MalwareBazaar_unknown_002_3ef32ae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ef32ae4171c7a2da4aab0c7bdc9a31581e9e49365b96ea951f6c06625e0b7d7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 02:52:33"
  condition:
    hash.sha256(0, filesize) == "3ef32ae4171c7a2da4aab0c7bdc9a31581e9e49365b96ea951f6c06625e0b7d7"
}

rule MalwareBazaar_Prometei_003_701a6e78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5"
    family = "Prometei"
    file_name = "701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5"
    file_type = "elf"
    first_seen = "2026-07-18 02:49:10"
  condition:
    hash.sha256(0, filesize) == "701a6e782f4d2a96d5a1efeb52b79fe0d6005b9f389d9146c9fcd11f5b4763a5"
}

rule MalwareBazaar_Mirai_004_73deadae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73deadaedd02f160279aca69237debc6a66a46a6401180a12b172be08b0877ee"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 02:45:46"
  condition:
    hash.sha256(0, filesize) == "73deadaedd02f160279aca69237debc6a66a46a6401180a12b172be08b0877ee"
}

rule MalwareBazaar_unknown_005_87752540
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "877525407f4b6feafe8e16b736e9eaad24ef4df2ad142387cc005b3b0fba76f6"
    family = "unknown"
    file_name = "d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65"
    file_type = "elf"
    first_seen = "2026-07-18 02:26:57"
  condition:
    hash.sha256(0, filesize) == "877525407f4b6feafe8e16b736e9eaad24ef4df2ad142387cc005b3b0fba76f6"
}

rule MalwareBazaar_unknown_006_1e83be9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e83be9c9bcc879bbf68332b8c5b5fb5ab2591ae6098a4ed4fe65aee0780cfac"
    family = "unknown"
    file_name = "51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a"
    file_type = "elf"
    first_seen = "2026-07-18 02:26:44"
  condition:
    hash.sha256(0, filesize) == "1e83be9c9bcc879bbf68332b8c5b5fb5ab2591ae6098a4ed4fe65aee0780cfac"
}

rule MalwareBazaar_unknown_007_7df3cebf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7df3cebf5b779a0a266ca4fdb979fab474223505bfc9a63d27a1ff985ef9fffc"
    family = "unknown"
    file_name = "1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d"
    file_type = "elf"
    first_seen = "2026-07-18 02:26:25"
  condition:
    hash.sha256(0, filesize) == "7df3cebf5b779a0a266ca4fdb979fab474223505bfc9a63d27a1ff985ef9fffc"
}

rule MalwareBazaar_unknown_008_bed4780f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bed4780f7c726192443063214f085b9f93b89f736e25ab17e44c1aa77f667c2f"
    family = "unknown"
    file_name = "049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b"
    file_type = "elf"
    first_seen = "2026-07-18 02:26:03"
  condition:
    hash.sha256(0, filesize) == "bed4780f7c726192443063214f085b9f93b89f736e25ab17e44c1aa77f667c2f"
}

rule MalwareBazaar_unknown_009_d45935ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65"
    family = "unknown"
    file_name = "d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:43"
  condition:
    hash.sha256(0, filesize) == "d45935ba4fc0213cff236e68a531c80aef0e40c5149866ec8435130e512b5e65"
}

rule MalwareBazaar_unknown_010_cd6dc7a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f"
    family = "unknown"
    file_name = "cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:42"
  condition:
    hash.sha256(0, filesize) == "cd6dc7a2725ad8550e21cc16f471519e3e2abd32df2acb45804d5af6a078c44f"
}

rule MalwareBazaar_unknown_011_51228996
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a"
    family = "unknown"
    file_name = "51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:40"
  condition:
    hash.sha256(0, filesize) == "51228996cf0280efc9b4c45d499e8527029667335b7b26951990feac7f22595a"
}

rule MalwareBazaar_unknown_012_1858c51b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d"
    family = "unknown"
    file_name = "1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:39"
  condition:
    hash.sha256(0, filesize) == "1858c51b58e913ca8d868ea94493ad1c74fad15ce283d94c10c22ceb3e92541d"
}

rule MalwareBazaar_unknown_013_049a2ed3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b"
    family = "unknown"
    file_name = "049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b"
    file_type = "elf"
    first_seen = "2026-07-18 02:25:37"
  condition:
    hash.sha256(0, filesize) == "049a2ed3406e7c70ce358c108d1f57001d6f2f1f924215f06d9e43b6c213f62b"
}

rule MalwareBazaar_unknown_014_f84fab97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f84fab97acebb6a52e2e839403b8e3a7fe040dcc30e808b6198e02a3621015a8"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-18 02:17:53"
  condition:
    hash.sha256(0, filesize) == "f84fab97acebb6a52e2e839403b8e3a7fe040dcc30e808b6198e02a3621015a8"
}

rule MalwareBazaar_Mirai_015_ee28d48c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee28d48c9b22e4f02b8c61bc98af039df9cda6939b99fb71d9b0fd16e9fba14e"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-18 02:06:33"
  condition:
    hash.sha256(0, filesize) == "ee28d48c9b22e4f02b8c61bc98af039df9cda6939b99fb71d9b0fd16e9fba14e"
}

rule MalwareBazaar_Mirai_016_fe83fd60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe83fd60fa4682327eb66a1991685d427054af49f0bf0956546d77acc1f1db6a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-18 02:03:03"
  condition:
    hash.sha256(0, filesize) == "fe83fd60fa4682327eb66a1991685d427054af49f0bf0956546d77acc1f1db6a"
}

rule MalwareBazaar_unknown_017_296a7248
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "296a72481bfbddcfc395c8e0ed3b6c3c0489530f8c20c90f60c519c4cb73e3df"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 02:03:02"
  condition:
    hash.sha256(0, filesize) == "296a72481bfbddcfc395c8e0ed3b6c3c0489530f8c20c90f60c519c4cb73e3df"
}

rule MalwareBazaar_Mirai_018_f5084fcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5084fcd2670db2e030285c84e99ed075fc99d22ef64585d61f39ea04391862f"
    family = "Mirai"
    file_name = "tarm5"
    file_type = "elf"
    first_seen = "2026-07-18 01:59:25"
  condition:
    hash.sha256(0, filesize) == "f5084fcd2670db2e030285c84e99ed075fc99d22ef64585d61f39ea04391862f"
}

rule MalwareBazaar_unknown_019_f85c795e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f85c795e38bd714fd320ce2888c6eb3d445723cd586c3db1411e443fb69edd7f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 01:52:30"
  condition:
    hash.sha256(0, filesize) == "f85c795e38bd714fd320ce2888c6eb3d445723cd586c3db1411e443fb69edd7f"
}

rule MalwareBazaar_unknown_020_e3763b15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3763b1555c565bdf4e4ad9c1ffd65f01b504f483375d8573ecba6b5467e2330"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-18 01:47:41"
  condition:
    hash.sha256(0, filesize) == "e3763b1555c565bdf4e4ad9c1ffd65f01b504f483375d8573ecba6b5467e2330"
}

rule MalwareBazaar_unknown_021_7961c4cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7961c4cb8175e03c7a6ab0cef01d0b0feaecc2fe3b25b7c8a036ce3051135284"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 01:47:39"
  condition:
    hash.sha256(0, filesize) == "7961c4cb8175e03c7a6ab0cef01d0b0feaecc2fe3b25b7c8a036ce3051135284"
}

rule MalwareBazaar_Mirai_022_41a5af65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41a5af65484f67ccf26159a27523f6e5de98beeeebad69596fc76ccecc815304"
    family = "Mirai"
    file_name = "aa"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:54"
  condition:
    hash.sha256(0, filesize) == "41a5af65484f67ccf26159a27523f6e5de98beeeebad69596fc76ccecc815304"
}

rule MalwareBazaar_unknown_023_16872e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16872e9e7b05e6e155986cad43d36831b6513bcf3381ca53157669671d69a171"
    family = "unknown"
    file_name = "m"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:45"
  condition:
    hash.sha256(0, filesize) == "16872e9e7b05e6e155986cad43d36831b6513bcf3381ca53157669671d69a171"
}

rule MalwareBazaar_Mirai_024_aab0a6d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aab0a6d8d9c2934691ffda0d08aa903770cd556cfe02da7dd55f6106977a220a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:44"
  condition:
    hash.sha256(0, filesize) == "aab0a6d8d9c2934691ffda0d08aa903770cd556cfe02da7dd55f6106977a220a"
}

rule MalwareBazaar_unknown_025_f178e00c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f178e00cb07dcd2ad446c2dacdd1a313136d86e1cb6d883a5f6476811155e6ff"
    family = "unknown"
    file_name = "g3"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:42"
  condition:
    hash.sha256(0, filesize) == "f178e00cb07dcd2ad446c2dacdd1a313136d86e1cb6d883a5f6476811155e6ff"
}

rule MalwareBazaar_unknown_026_e99b526c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e99b526cf03cf0950237edca206f76dcdfb98ba7459a50e8ec5720d847b0427a"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:41"
  condition:
    hash.sha256(0, filesize) == "e99b526cf03cf0950237edca206f76dcdfb98ba7459a50e8ec5720d847b0427a"
}

rule MalwareBazaar_Mirai_027_52d04add
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52d04addeae331314cfb21fd5dc3287532b49f0dbdd4839de53cdcb52380b0b1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:39"
  condition:
    hash.sha256(0, filesize) == "52d04addeae331314cfb21fd5dc3287532b49f0dbdd4839de53cdcb52380b0b1"
}

rule MalwareBazaar_unknown_028_4a1e4bea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a1e4bea7d063f1282627878dfc3ecb8466bd2a96094ba8ce4c7879370a45c47"
    family = "unknown"
    file_name = "m"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:37"
  condition:
    hash.sha256(0, filesize) == "4a1e4bea7d063f1282627878dfc3ecb8466bd2a96094ba8ce4c7879370a45c47"
}

rule MalwareBazaar_unknown_029_585adf9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "585adf9dbfc2eb5e36c033e376c659d67485c97f759d78b870227e10c58043b2"
    family = "unknown"
    file_name = "r"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:36"
  condition:
    hash.sha256(0, filesize) == "585adf9dbfc2eb5e36c033e376c659d67485c97f759d78b870227e10c58043b2"
}

rule MalwareBazaar_Mirai_030_84b81744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b817443d7488ad8c899daa0a08a237536ffa9165de500922e579f136f86463"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:35"
  condition:
    hash.sha256(0, filesize) == "84b817443d7488ad8c899daa0a08a237536ffa9165de500922e579f136f86463"
}

rule MalwareBazaar_unknown_031_4a6a7f3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a6a7f3fc8aeb12a77a9c9e93e40a35ae33dae15634ca554395243b7064f68fe"
    family = "unknown"
    file_name = "magic"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:33"
  condition:
    hash.sha256(0, filesize) == "4a6a7f3fc8aeb12a77a9c9e93e40a35ae33dae15634ca554395243b7064f68fe"
}

rule MalwareBazaar_Mirai_032_798f3c69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "798f3c696c7642b3cd47f47ff039150ee946dce877ee04cd36af64e63e27a2c1"
    family = "Mirai"
    file_name = "dlr.mips"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:32"
  condition:
    hash.sha256(0, filesize) == "798f3c696c7642b3cd47f47ff039150ee946dce877ee04cd36af64e63e27a2c1"
}

rule MalwareBazaar_unknown_033_70f341f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70f341f6de13cd88d681d64e2726afb96eb421a715e1ac29f7b62a4ae0d54be6"
    family = "unknown"
    file_name = "f"
    file_type = "unknown"
    first_seen = "2026-07-18 01:42:30"
  condition:
    hash.sha256(0, filesize) == "70f341f6de13cd88d681d64e2726afb96eb421a715e1ac29f7b62a4ae0d54be6"
}

rule MalwareBazaar_Mirai_034_848f1546
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "848f1546a84dd92cce3c1463e3e964698533d93d6ea7be00e000db5efbb1d2f4"
    family = "Mirai"
    file_name = "dlr.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:28"
  condition:
    hash.sha256(0, filesize) == "848f1546a84dd92cce3c1463e3e964698533d93d6ea7be00e000db5efbb1d2f4"
}

rule MalwareBazaar_Mirai_035_541d0233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "541d02331c910b5c73bf2b5a5e744319f9bd2b42f716c9ba28c9105eab915bdc"
    family = "Mirai"
    file_name = "umips"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:25"
  condition:
    hash.sha256(0, filesize) == "541d02331c910b5c73bf2b5a5e744319f9bd2b42f716c9ba28c9105eab915bdc"
}

rule MalwareBazaar_unknown_036_32248ab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32248ab13cb51588769a70d7672bd98a200f1ede0067ae6193f56c74fc358321"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:22"
  condition:
    hash.sha256(0, filesize) == "32248ab13cb51588769a70d7672bd98a200f1ede0067ae6193f56c74fc358321"
}

rule MalwareBazaar_Mirai_037_e4377c8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4377c8a0d26d9843a34644c145732c3d5179f9dbc87ae46d8cac66545b3ba8c"
    family = "Mirai"
    file_name = "rmips"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:20"
  condition:
    hash.sha256(0, filesize) == "e4377c8a0d26d9843a34644c145732c3d5179f9dbc87ae46d8cac66545b3ba8c"
}

rule MalwareBazaar_Mirai_038_c569ae79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c569ae79cce6d17ccd35031c39c1b3d6c634e4e906b932fcce48ac0a0336fdbf"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:14"
  condition:
    hash.sha256(0, filesize) == "c569ae79cce6d17ccd35031c39c1b3d6c634e4e906b932fcce48ac0a0336fdbf"
}

rule MalwareBazaar_Mirai_039_561397d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "561397d9a74f3923c8b4cfe955b0b4727e56fab6d1eba096964a172bfe14ed29"
    family = "Mirai"
    file_name = "dlr.arm5"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:13"
  condition:
    hash.sha256(0, filesize) == "561397d9a74f3923c8b4cfe955b0b4727e56fab6d1eba096964a172bfe14ed29"
}

rule MalwareBazaar_Mirai_040_1e3c7793
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e3c77937fbeb6c30db92b5f571623264260e71ddfae8b5c2f79a76c20057e23"
    family = "Mirai"
    file_name = "rmpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:08"
  condition:
    hash.sha256(0, filesize) == "1e3c77937fbeb6c30db92b5f571623264260e71ddfae8b5c2f79a76c20057e23"
}

rule MalwareBazaar_Mirai_041_f8514ee4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8514ee48f0e84bb0a1172f469b5efeeb89625b53689d2a6a0a1beeb584fe658"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:06"
  condition:
    hash.sha256(0, filesize) == "f8514ee48f0e84bb0a1172f469b5efeeb89625b53689d2a6a0a1beeb584fe658"
}

rule MalwareBazaar_Mirai_042_fbf46de3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbf46de3022593c85013ee66b07967bfa02a0d7f618532b6192722296331a43b"
    family = "Mirai"
    file_name = "umpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:04"
  condition:
    hash.sha256(0, filesize) == "fbf46de3022593c85013ee66b07967bfa02a0d7f618532b6192722296331a43b"
}

rule MalwareBazaar_Mirai_043_029e273c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "029e273cda07c75ccc3bd5b09ba4b622a732abf2bfe3cdc69c133de70813b7eb"
    family = "Mirai"
    file_name = "aa"
    file_type = "elf"
    first_seen = "2026-07-18 01:42:01"
  condition:
    hash.sha256(0, filesize) == "029e273cda07c75ccc3bd5b09ba4b622a732abf2bfe3cdc69c133de70813b7eb"
}

rule MalwareBazaar_Mirai_044_2ed32283
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed322830841e3043f09476f755ca36da1d58324521924483b24c1fc2fb650cc"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-18 01:41:57"
  condition:
    hash.sha256(0, filesize) == "2ed322830841e3043f09476f755ca36da1d58324521924483b24c1fc2fb650cc"
}

rule MalwareBazaar_Mirai_045_d03c0e89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d03c0e897d5aef598330056653174ccb4d9213e006fa761f1330cebb209f050a"
    family = "Mirai"
    file_name = "a6"
    file_type = "elf"
    first_seen = "2026-07-18 01:41:56"
  condition:
    hash.sha256(0, filesize) == "d03c0e897d5aef598330056653174ccb4d9213e006fa761f1330cebb209f050a"
}

rule MalwareBazaar_Mirai_046_edaea93b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edaea93baed98567c213668dc5b258d541623ce7358c0b7368fe8cdd07c54da1"
    family = "Mirai"
    file_name = "dlr.arm4"
    file_type = "elf"
    first_seen = "2026-07-18 01:41:53"
  condition:
    hash.sha256(0, filesize) == "edaea93baed98567c213668dc5b258d541623ce7358c0b7368fe8cdd07c54da1"
}

rule MalwareBazaar_Mirai_047_02fd84fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02fd84fcefc193ac0af333f23ed8ddba75061da00f60c6c53836a39a73e28768"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:31:16"
  condition:
    hash.sha256(0, filesize) == "02fd84fcefc193ac0af333f23ed8ddba75061da00f60c6c53836a39a73e28768"
}

rule MalwareBazaar_Mirai_048_26228ffd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26228ffd4024016f5ac1391601ef229bfddd2a7a365875bc44605ee9aab6e6cf"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:30:29"
  condition:
    hash.sha256(0, filesize) == "26228ffd4024016f5ac1391601ef229bfddd2a7a365875bc44605ee9aab6e6cf"
}

rule MalwareBazaar_Mirai_049_37ad8c22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37ad8c225142d26d12efbec05cf35cdba02664e1525b8cceab9e19a77312c224"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-18 01:30:27"
  condition:
    hash.sha256(0, filesize) == "37ad8c225142d26d12efbec05cf35cdba02664e1525b8cceab9e19a77312c224"
}

rule MalwareBazaar_Mirai_050_c2726f5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2726f5b5a72d93901efaec8c12d611c7d66c5b6d1994f2ee9a72418d1a54735"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 01:23:40"
  condition:
    hash.sha256(0, filesize) == "c2726f5b5a72d93901efaec8c12d611c7d66c5b6d1994f2ee9a72418d1a54735"
}

rule MalwareBazaar_Mirai_051_426f394f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "426f394fee5882b8d70b37c6fc8ca9ba1ce3bb6eb7573550b6b55c16d343788a"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 01:22:37"
  condition:
    hash.sha256(0, filesize) == "426f394fee5882b8d70b37c6fc8ca9ba1ce3bb6eb7573550b6b55c16d343788a"
}

rule MalwareBazaar_Mirai_052_1f880c07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f880c07cf7f81f86360513384a6ce443f06869fbfcde62614c523de0df28dc1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-18 01:22:35"
  condition:
    hash.sha256(0, filesize) == "1f880c07cf7f81f86360513384a6ce443f06869fbfcde62614c523de0df28dc1"
}

rule MalwareBazaar_Mirai_053_81d60e52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81d60e52eaa3d9ca6373262d7921be49dccecbbceb8d436d2f3ddc7ff7ea8493"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-07-18 01:18:11"
  condition:
    hash.sha256(0, filesize) == "81d60e52eaa3d9ca6373262d7921be49dccecbbceb8d436d2f3ddc7ff7ea8493"
}

rule MalwareBazaar_Mirai_054_b4af4104
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4af41047f9ff667cbea568b8d78967b221d1da5375bd9bfa07769b75160cd0d"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-07-18 01:18:10"
  condition:
    hash.sha256(0, filesize) == "b4af41047f9ff667cbea568b8d78967b221d1da5375bd9bfa07769b75160cd0d"
}

rule MalwareBazaar_Mirai_055_4917e42c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4917e42c0df49bc834c4d145cd57e2887dcd1e9b784953346fc707ea7aa51ae5"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-18 01:09:43"
  condition:
    hash.sha256(0, filesize) == "4917e42c0df49bc834c4d145cd57e2887dcd1e9b784953346fc707ea7aa51ae5"
}

rule MalwareBazaar_unknown_056_0e6da423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e6da423fff9e817b4adf79b75ca56f6528fa6d820b9cb716532becb96e798ac"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-18 01:09:41"
  condition:
    hash.sha256(0, filesize) == "0e6da423fff9e817b4adf79b75ca56f6528fa6d820b9cb716532becb96e798ac"
}

rule MalwareBazaar_AgentTesla_057_83ce591d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83ce591d7b27d20266951ffa68fa339e4b1d85e30c46b4f962feaf02b6638fd6"
    family = "AgentTesla"
    file_name = "NEW_ORDER_QUOTATION_202606001pdf.exe"
    file_type = "exe"
    first_seen = "2026-07-18 01:06:21"
  condition:
    hash.sha256(0, filesize) == "83ce591d7b27d20266951ffa68fa339e4b1d85e30c46b4f962feaf02b6638fd6"
}

rule MalwareBazaar_Mirai_058_c152fa31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c152fa31ad2a21f79c0586b96c684a4725ca8b439e6944172bc97d6a6d9e83a9"
    family = "Mirai"
    file_name = "tarm"
    file_type = "elf"
    first_seen = "2026-07-18 01:05:17"
  condition:
    hash.sha256(0, filesize) == "c152fa31ad2a21f79c0586b96c684a4725ca8b439e6944172bc97d6a6d9e83a9"
}

rule MalwareBazaar_unknown_059_f17815cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f17815cd4111cdf8ead2b31c7fef4453b55b18202753495225a564c819ee1138"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-18 00:55:40"
  condition:
    hash.sha256(0, filesize) == "f17815cd4111cdf8ead2b31c7fef4453b55b18202753495225a564c819ee1138"
}

rule MalwareBazaar_unknown_060_77e74075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77e74075645dd76bc4836bb5e8ffb6a6a1dbdfb520a5cd116b8e6848a6ec61ac"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 00:52:31"
  condition:
    hash.sha256(0, filesize) == "77e74075645dd76bc4836bb5e8ffb6a6a1dbdfb520a5cd116b8e6848a6ec61ac"
}

rule MalwareBazaar_Mirai_061_2168c23f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2168c23f2dcb38f747d4919d37e6b8c82bb94999a05fad2649ab367e5c1851f0"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-18 00:50:44"
  condition:
    hash.sha256(0, filesize) == "2168c23f2dcb38f747d4919d37e6b8c82bb94999a05fad2649ab367e5c1851f0"
}

rule MalwareBazaar_Mirai_062_1578e4e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1578e4e484bbaea2dbcc05bed28b9f507255a986e93c2854931b0020ec5ef04f"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-18 00:44:47"
  condition:
    hash.sha256(0, filesize) == "1578e4e484bbaea2dbcc05bed28b9f507255a986e93c2854931b0020ec5ef04f"
}

rule MalwareBazaar_Mirai_063_a5f088b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5f088b577ee85ece2ee1cbca0606ba90331891d7532898f778d9c0bcec4d82d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 00:43:57"
  condition:
    hash.sha256(0, filesize) == "a5f088b577ee85ece2ee1cbca0606ba90331891d7532898f778d9c0bcec4d82d"
}

rule MalwareBazaar_Mirai_064_8ebb41b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ebb41b0bfd24c9f2525723c51b6612aade42f84591e2323417636886774d49a"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-18 00:43:54"
  condition:
    hash.sha256(0, filesize) == "8ebb41b0bfd24c9f2525723c51b6612aade42f84591e2323417636886774d49a"
}

rule MalwareBazaar_Mirai_065_1265919a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1265919aa72f3fa68c775fe66a60c286cccd79f46fd79424ad50ba204a94f5c4"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-18 00:40:12"
  condition:
    hash.sha256(0, filesize) == "1265919aa72f3fa68c775fe66a60c286cccd79f46fd79424ad50ba204a94f5c4"
}

rule MalwareBazaar_Mirai_066_e7ffadca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7ffadca7485550fa00a049f12f3e7e957f7fc19dae3229927af7cc39b13ba46"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-18 00:34:48"
  condition:
    hash.sha256(0, filesize) == "e7ffadca7485550fa00a049f12f3e7e957f7fc19dae3229927af7cc39b13ba46"
}

rule MalwareBazaar_Mirai_067_154d5729
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "154d5729d26ae38ff37e7d1463a019d259da7c0f9a37e4482333e1e686ebe39e"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-18 00:30:11"
  condition:
    hash.sha256(0, filesize) == "154d5729d26ae38ff37e7d1463a019d259da7c0f9a37e4482333e1e686ebe39e"
}

rule MalwareBazaar_Mirai_068_18cbee63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cbee63748bff047d7d51ebc934409f8cb3ba1ea814daae638122272de1a314"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-18 00:21:40"
  condition:
    hash.sha256(0, filesize) == "18cbee63748bff047d7d51ebc934409f8cb3ba1ea814daae638122272de1a314"
}

rule MalwareBazaar_Mirai_069_7243738e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7243738e2b27922cd5daed7bb1e9382e87196583976c7a54372f2f149eec3596"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-18 00:20:55"
  condition:
    hash.sha256(0, filesize) == "7243738e2b27922cd5daed7bb1e9382e87196583976c7a54372f2f149eec3596"
}

rule MalwareBazaar_Mirai_070_1de6220f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1de6220fc4c3502a55fa5cc220b9a91cead25fc34bc7d3610edf1914f83bc379"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-18 00:03:42"
  condition:
    hash.sha256(0, filesize) == "1de6220fc4c3502a55fa5cc220b9a91cead25fc34bc7d3610edf1914f83bc379"
}

rule MalwareBazaar_Mirai_071_c1dd7a56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1dd7a5673962d108ec8d1b12b50604a134cc52cc95de6c3bbf680198e8f9cb6"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-17 23:59:36"
  condition:
    hash.sha256(0, filesize) == "c1dd7a5673962d108ec8d1b12b50604a134cc52cc95de6c3bbf680198e8f9cb6"
}

rule MalwareBazaar_Mirai_072_61eb8e47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61eb8e47031b9c5ac19f887926f3a03604ae1dec521dad76db3136a1469be7b6"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-17 23:58:38"
  condition:
    hash.sha256(0, filesize) == "61eb8e47031b9c5ac19f887926f3a03604ae1dec521dad76db3136a1469be7b6"
}

rule MalwareBazaar_Mirai_073_afaf5a58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afaf5a58dd6e9586701b97b9e5b454846f3ce0053a0aa44b196626d7f4a4e5d4"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 23:56:01"
  condition:
    hash.sha256(0, filesize) == "afaf5a58dd6e9586701b97b9e5b454846f3ce0053a0aa44b196626d7f4a4e5d4"
}

rule MalwareBazaar_Mirai_074_f0506419
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0506419d1f60d7180e72fdcca97d5446d3cc3218d61b11dcd39b49086553683"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 23:54:30"
  condition:
    hash.sha256(0, filesize) == "f0506419d1f60d7180e72fdcca97d5446d3cc3218d61b11dcd39b49086553683"
}

rule MalwareBazaar_unknown_075_44877621
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 23:52:32"
  condition:
    hash.sha256(0, filesize) == "448776210b0c1802fd3e5da66813e90e7469bcd365d64e11b2a992547bc2fd4a"
}

rule MalwareBazaar_Mirai_076_b25c3c74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b25c3c740aead577c7c89894e80ee57c63d5acd78e62d789213fda023bfbaf3c"
    family = "Mirai"
    file_name = "nz.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:50:08"
  condition:
    hash.sha256(0, filesize) == "b25c3c740aead577c7c89894e80ee57c63d5acd78e62d789213fda023bfbaf3c"
}

rule MalwareBazaar_WannaCry_077_55c28ae7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe"
    family = "WannaCry"
    file_name = "55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe"
    file_type = "exe"
    first_seen = "2026-07-17 23:15:29"
  condition:
    hash.sha256(0, filesize) == "55c28ae706e71466105213f097ade42c5022792c67dcfc29e354a1ade36fd4fe"
}

rule MalwareBazaar_Mirai_078_fd0ff759
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0ff75925ea15760d72c1a9ffbcc0e751abebb2f4cd49f0bd11274a04706217"
    family = "Mirai"
    file_name = "gmips"
    file_type = "elf"
    first_seen = "2026-07-17 23:14:09"
  condition:
    hash.sha256(0, filesize) == "fd0ff75925ea15760d72c1a9ffbcc0e751abebb2f4cd49f0bd11274a04706217"
}

rule MalwareBazaar_unknown_079_8689dd49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8689dd49ac380c1a3c15509eb1fa842ab69374c00f453a1f7f86e4693958606d"
    family = "unknown"
    file_name = "dvr.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:38"
  condition:
    hash.sha256(0, filesize) == "8689dd49ac380c1a3c15509eb1fa842ab69374c00f453a1f7f86e4693958606d"
}

rule MalwareBazaar_Mirai_080_cc6964a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc6964a4808fddb922b8889d83fd0724f6bab22125458690ab189a93978b2638"
    family = "Mirai"
    file_name = "gmpsl"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:36"
  condition:
    hash.sha256(0, filesize) == "cc6964a4808fddb922b8889d83fd0724f6bab22125458690ab189a93978b2638"
}

rule MalwareBazaar_unknown_081_6bba47b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bba47b8780a872fca03c7776396e13def783ee4ce13deff1fdfce75e32f1346"
    family = "unknown"
    file_name = "dvr.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:34"
  condition:
    hash.sha256(0, filesize) == "6bba47b8780a872fca03c7776396e13def783ee4ce13deff1fdfce75e32f1346"
}

rule MalwareBazaar_unknown_082_a2dd8c85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2dd8c859251c361c46d3670536e81d85acaa44ac938f3057bcecdf50b2ad5ee"
    family = "unknown"
    file_name = "telnet.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:32"
  condition:
    hash.sha256(0, filesize) == "a2dd8c859251c361c46d3670536e81d85acaa44ac938f3057bcecdf50b2ad5ee"
}

rule MalwareBazaar_unknown_083_2d355f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d355f96bab2d9535a294cf0c1339779643091460447e1102debac8f58571bb2"
    family = "unknown"
    file_name = "t"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:31"
  condition:
    hash.sha256(0, filesize) == "2d355f96bab2d9535a294cf0c1339779643091460447e1102debac8f58571bb2"
}

rule MalwareBazaar_unknown_084_f14c657d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f14c657d8667f1cc3733e380768a3020d6b56d5c9593817033d3930f2f4d30ca"
    family = "unknown"
    file_name = "sh"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:29"
  condition:
    hash.sha256(0, filesize) == "f14c657d8667f1cc3733e380768a3020d6b56d5c9593817033d3930f2f4d30ca"
}

rule MalwareBazaar_unknown_085_1cf3b8d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cf3b8d29609d0c4be3e81b39f83ca5de32f13b4ac309e397aca1d451a56339f"
    family = "unknown"
    file_name = "t"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:28"
  condition:
    hash.sha256(0, filesize) == "1cf3b8d29609d0c4be3e81b39f83ca5de32f13b4ac309e397aca1d451a56339f"
}

rule MalwareBazaar_unknown_086_1a59dbd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a59dbd778699f8e4a4fe8ee82fe49cff516d76a9f59e9a212e9381cc2c46c29"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:27"
  condition:
    hash.sha256(0, filesize) == "1a59dbd778699f8e4a4fe8ee82fe49cff516d76a9f59e9a212e9381cc2c46c29"
}

rule MalwareBazaar_unknown_087_c792b032
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c792b032fb1f71205f9f3caf58437f8525d99ffca1530511c86ffd92fd22413b"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:25"
  condition:
    hash.sha256(0, filesize) == "c792b032fb1f71205f9f3caf58437f8525d99ffca1530511c86ffd92fd22413b"
}

rule MalwareBazaar_Mirai_088_902b6aff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "902b6affb47b3a6d9f8d618d4dae85730a6d6eadc3c4a8cf66c81f5375f9b8ba"
    family = "Mirai"
    file_name = "dlr.arm7"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:24"
  condition:
    hash.sha256(0, filesize) == "902b6affb47b3a6d9f8d618d4dae85730a6d6eadc3c4a8cf66c81f5375f9b8ba"
}

rule MalwareBazaar_Mirai_089_1cc57bc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cc57bc4e2443925408d907347346a8389ea4c55132e288dc5596fa29702dc60"
    family = "Mirai"
    file_name = "dlr.x86"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:22"
  condition:
    hash.sha256(0, filesize) == "1cc57bc4e2443925408d907347346a8389ea4c55132e288dc5596fa29702dc60"
}

rule MalwareBazaar_Mirai_090_b5b220b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5b220b1dff259efdaf017b58aae836955096f6ffe8cdca658c1b6887b35dfbf"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:20"
  condition:
    hash.sha256(0, filesize) == "b5b220b1dff259efdaf017b58aae836955096f6ffe8cdca658c1b6887b35dfbf"
}

rule MalwareBazaar_unknown_091_93a9c2cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93a9c2cbd2840685150eb1e794fad854df870b2a444c6049b6836340cad95d7f"
    family = "unknown"
    file_name = "shell"
    file_type = "elf"
    first_seen = "2026-07-17 23:09:18"
  condition:
    hash.sha256(0, filesize) == "93a9c2cbd2840685150eb1e794fad854df870b2a444c6049b6836340cad95d7f"
}

rule MalwareBazaar_unknown_092_9a55fb18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a55fb188177ac65e7bdea528c6ed357fe333975de529539c60b233ee35379c5"
    family = "unknown"
    file_name = "t"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:17"
  condition:
    hash.sha256(0, filesize) == "9a55fb188177ac65e7bdea528c6ed357fe333975de529539c60b233ee35379c5"
}

rule MalwareBazaar_Mirai_093_39fdaaa5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39fdaaa503065403e9cca7ea29efd9d43f245b8b976cfadd70ddb1d364ddffe3"
    family = "Mirai"
    file_name = "all.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:15"
  condition:
    hash.sha256(0, filesize) == "39fdaaa503065403e9cca7ea29efd9d43f245b8b976cfadd70ddb1d364ddffe3"
}

rule MalwareBazaar_unknown_094_63cf5ade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63cf5ade631557478a2cf13fce75b593b76edfca7a991889b8b11f52fc05f631"
    family = "unknown"
    file_name = "all.sh"
    file_type = "sh"
    first_seen = "2026-07-17 23:09:14"
  condition:
    hash.sha256(0, filesize) == "63cf5ade631557478a2cf13fce75b593b76edfca7a991889b8b11f52fc05f631"
}

rule MalwareBazaar_unknown_095_5ec1a4f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ec1a4f708c09e4382fe7af1ce9cb02524735f53409e53c27980e094d60d4296"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-17 23:09:11"
  condition:
    hash.sha256(0, filesize) == "5ec1a4f708c09e4382fe7af1ce9cb02524735f53409e53c27980e094d60d4296"
}

rule MalwareBazaar_unknown_096_e7c92caf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7c92caf850de1f30e8ba00d17025ff795bd9fdcdb346cb4f1b8915d534c57a2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 22:52:32"
  condition:
    hash.sha256(0, filesize) == "e7c92caf850de1f30e8ba00d17025ff795bd9fdcdb346cb4f1b8915d534c57a2"
}

rule MalwareBazaar_unknown_097_89ce478c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89ce478cd3190b040eaab88adddfa43c166a00371d83b7875c08d109d7e5569a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-17 22:38:13"
  condition:
    hash.sha256(0, filesize) == "89ce478cd3190b040eaab88adddfa43c166a00371d83b7875c08d109d7e5569a"
}

rule MalwareBazaar_unknown_098_bf2d153b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf2d153b1b6ac1dfb076c520195b283d9c353117005ef849ac146d98ec886192"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-17 22:27:52"
  condition:
    hash.sha256(0, filesize) == "bf2d153b1b6ac1dfb076c520195b283d9c353117005ef849ac146d98ec886192"
}

rule MalwareBazaar_unknown_099_c16785a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c16785a165adcc885acca91f57c25090ee781705248ba535d889a135cc276b4f"
    family = "unknown"
    file_name = "abe_extractor_amd64.bin"
    file_type = "exe"
    first_seen = "2026-07-17 22:27:52"
  condition:
    hash.sha256(0, filesize) == "c16785a165adcc885acca91f57c25090ee781705248ba535d889a135cc276b4f"
}

rule MalwareBazaar_unknown_100_10df86d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8"
    family = "unknown"
    file_name = "10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8"
    file_type = "elf"
    first_seen = "2026-07-17 22:25:31"
  condition:
    hash.sha256(0, filesize) == "10df86d8a7a3f56d2df33217da626c30e2e6005762f4427ef76c2815b40d8ce8"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

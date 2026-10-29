# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-29

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 679 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 679 |
| Unique family labels | 5 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| SalatStealer | 59 |
| unknown | 26 |
| Mirai | 12 |
| RemcosRAT | 2 |
| njrat | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 67 |
| elf | 16 |
| macho | 12 |
| sh | 2 |
| js | 1 |
| gz | 1 |
| rar | 1 |

## Per-Sample Analysis

### Sample 1: `ad61bd9bf203d67c`

| Field | Value |
|---|---|
| SHA-256 | `ad61bd9bf203d67cbf81c331b97fffed4f458f8ea0c38fefd0b3365cb326fc1c` |
| Family label | `unknown` |
| File name | `khide_6.8.0-101-generic.65fb47` |
| File type | `elf` |
| First seen | `2026-10-29 05:45:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7b75faebce3222e63efef6202ecef52` |
| SHA-1 | `c476ed4632e3624fa1b16e92824f2dd7ef36500f` |
| SHA-256 | `ad61bd9bf203d67cbf81c331b97fffed4f458f8ea0c38fefd0b3365cb326fc1c` |
| SHA3-384 | `2877a17f8e12c3f7ce62895de2b267a0ebee8ef26f9b98e828994843e4552a20bb4c291de78eaea48a2a9c9df6ea921d` |
| TLSH | `T18DC4391AEE30944BC89946316BFA532933B0D1C967429B0750FCB878DECB395ADC9D8D` |
| SSDEEP | `12288:BkF+/guh7ZrQhJktWMOCDO0UszGnUTPvQYMJ8U:BkF+/gq7K6PO1sKuvnU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_ad61bd9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad61bd9bf203d67cbf81c331b97fffed4f458f8ea0c38fefd0b3365cb326fc1c"
    family = "unknown"
    file_name = "khide_6.8.0-101-generic.65fb47"
    file_type = "elf"
    first_seen = "2026-10-29 05:45:54"
  condition:
    hash.sha256(0, filesize) == "ad61bd9bf203d67cbf81c331b97fffed4f458f8ea0c38fefd0b3365cb326fc1c"
}
```

### Sample 2: `772df17d8da21b06`

| Field | Value |
|---|---|
| SHA-256 | `772df17d8da21b06b66675f2dd8571d38d79fabca084e7e95b594697f45b02a1` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-29 05:30:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2d035e87052c2a1479483c47bcaf280` |
| SHA-1 | `c904173c5923bec01ea6ae2454ded92c7de89809` |
| SHA-256 | `772df17d8da21b06b66675f2dd8571d38d79fabca084e7e95b594697f45b02a1` |
| SHA3-384 | `fd0a53f56a9ac694f1574da3fa730e5ac2ea88cacda332f7e3aa1c482e01575401411376cefa6f98f565b4c192b8fa00` |
| TLSH | `T16174098892F2E3FEF154E5716305BD279C3646363083B18BF39E7A7352B618085E9A35` |
| TELFHASH | `t1479198f22dbe0ed9b3e0d803c10e7b81fd0ad677586535b245e3669032f7a52927a835` |
| SSDEEP | `6144:WpFEm+STN2YORCs6csuOnZU4O0vXMBFaUbRfGa9Dad:WkEN5RJvXwFaUbxGa9Da` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_772df17d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "772df17d8da21b06b66675f2dd8571d38d79fabca084e7e95b594697f45b02a1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-29 05:30:56"
  condition:
    hash.sha256(0, filesize) == "772df17d8da21b06b66675f2dd8571d38d79fabca084e7e95b594697f45b02a1"
}
```

### Sample 3: `067ff5c5937956ff`

| Field | Value |
|---|---|
| SHA-256 | `067ff5c5937956ff11faf4f507e53c7347486b238e5ba29af40cfa24cf7a67a6` |
| Family label | `SalatStealer` |
| File name | `2b10a1bb42b8b7aa.bin` |
| File type | `exe` |
| First seen | `2026-10-29 05:25:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d2da99584742561d21fd7ec2cce4bfb` |
| SHA-1 | `cc1c668a320bb1dc6a1770ec36700e1dd4944b8e` |
| SHA-256 | `067ff5c5937956ff11faf4f507e53c7347486b238e5ba29af40cfa24cf7a67a6` |
| SHA3-384 | `c446e01c216227ea03c43a2f251aeedf480491115970ab1a3e5aef8781fc753cd7f206c55de8a9c22cc11ba1f0c3bf10` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T195C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+G:yBkKr5rszpNDy+G` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_003_067ff5c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "067ff5c5937956ff11faf4f507e53c7347486b238e5ba29af40cfa24cf7a67a6"
    family = "SalatStealer"
    file_name = "2b10a1bb42b8b7aa.bin"
    file_type = "exe"
    first_seen = "2026-10-29 05:25:27"
  condition:
    hash.sha256(0, filesize) == "067ff5c5937956ff11faf4f507e53c7347486b238e5ba29af40cfa24cf7a67a6"
}
```

### Sample 4: `57a63ea3de36e0fd`

| Field | Value |
|---|---|
| SHA-256 | `57a63ea3de36e0fd0e8a4e1df7f48b472d4db86ccdeb125d297d0a331bad33b3` |
| Family label | `SalatStealer` |
| File name | `54a3d75e36078028.bin` |
| File type | `exe` |
| First seen | `2026-10-29 05:24:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6c71ecec3ca3711e907836672b38da6` |
| SHA-1 | `6937a775424006f36bbbf515100f41d4bd86a89a` |
| SHA-256 | `57a63ea3de36e0fd0e8a4e1df7f48b472d4db86ccdeb125d297d0a331bad33b3` |
| SHA3-384 | `ea64977695388d757ed7a5e804d8f1e3115abbb92a7d5166eb5fda207a3c603c7f9fb2e4cb0f84a02a936fa92664bbc4` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T170C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+k:yBkKr5rszpNDy+k` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_004_57a63ea3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a63ea3de36e0fd0e8a4e1df7f48b472d4db86ccdeb125d297d0a331bad33b3"
    family = "SalatStealer"
    file_name = "54a3d75e36078028.bin"
    file_type = "exe"
    first_seen = "2026-10-29 05:24:22"
  condition:
    hash.sha256(0, filesize) == "57a63ea3de36e0fd0e8a4e1df7f48b472d4db86ccdeb125d297d0a331bad33b3"
}
```

### Sample 5: `2b10a1bb42b8b7aa`

| Field | Value |
|---|---|
| SHA-256 | `2b10a1bb42b8b7aa44a37b1d48ce1324150217395842aed1a34c7ff91687a5b5` |
| Family label | `SalatStealer` |
| File name | `2b10a1bb42b8b7aa.bin` |
| File type | `exe` |
| First seen | `2026-10-29 05:24:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a83456edbd98f64340dc6031f5e3cd2a` |
| SHA-1 | `aab2d988c77b9ffedbe939bb90157dbd732a3cb2` |
| SHA-256 | `2b10a1bb42b8b7aa44a37b1d48ce1324150217395842aed1a34c7ff91687a5b5` |
| SHA3-384 | `fa37e68b50a3d5f87e9fe2d514249cd45e35460173eca45dd16c379af392d6e1f00489ba7c590e3d29eb1f4eda3e5cd1` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1CAF5335BF1AB47B3F7D9A875560FC66458B09FE40A20D38AD4DBAA9F0882FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oi:iJiafuIO7rhWEES4F` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_005_2b10a1bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b10a1bb42b8b7aa44a37b1d48ce1324150217395842aed1a34c7ff91687a5b5"
    family = "SalatStealer"
    file_name = "2b10a1bb42b8b7aa.bin"
    file_type = "exe"
    first_seen = "2026-10-29 05:24:18"
  condition:
    hash.sha256(0, filesize) == "2b10a1bb42b8b7aa44a37b1d48ce1324150217395842aed1a34c7ff91687a5b5"
}
```

### Sample 6: `54a3d75e36078028`

| Field | Value |
|---|---|
| SHA-256 | `54a3d75e360780280e8f427eb18aeb651c62914364e305a3e2f8922cd8bc9988` |
| Family label | `SalatStealer` |
| File name | `54a3d75e36078028.bin` |
| File type | `exe` |
| First seen | `2026-10-29 05:24:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `122a4bf196bc2b378d6a4930ce40be96` |
| SHA-1 | `745ac622787f4faa96077747c1ee64969ba33169` |
| SHA-256 | `54a3d75e360780280e8f427eb18aeb651c62914364e305a3e2f8922cd8bc9988` |
| SHA3-384 | `d24ac9b29ae59c468a0098e4be14029d10f369726a8c05e397aa75cdfe16c0777f2cf2765c44f5bdd93c604f08bc1678` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T183F5335BF1AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OQ:iJiafuIO7rhWEES4v` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_006_54a3d75e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54a3d75e360780280e8f427eb18aeb651c62914364e305a3e2f8922cd8bc9988"
    family = "SalatStealer"
    file_name = "54a3d75e36078028.bin"
    file_type = "exe"
    first_seen = "2026-10-29 05:24:08"
  condition:
    hash.sha256(0, filesize) == "54a3d75e360780280e8f427eb18aeb651c62914364e305a3e2f8922cd8bc9988"
}
```

### Sample 7: `5d4ea84b8561fc95`

| Field | Value |
|---|---|
| SHA-256 | `5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6` |
| Family label | `unknown` |
| File name | `5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6.exe` |
| File type | `exe` |
| First seen | `2026-10-29 05:18:27` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8b776a3f6cebff80094caa8d3a98529` |
| SHA-1 | `6e4be23938d9edfed1f81d1dd281d19f9248b2ab` |
| SHA-256 | `5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6` |
| SHA3-384 | `51059c844e1f8799526cf85d4194a94389fe87999a631ecec203a4ca419ef2b3125c02e756a59b14231495f2c84bf92a` |
| IMPHASH | `d12b7d365f36b5131fbd103c642e2b2e` |
| TLSH | `T19145F7B433C72BF4E24780B02489175DE40030BB37DB2E96AD4D3213D596A9B79F6B69` |
| SSDEEP | `24576:SuFd78/dD3YvGmZsdGrPd6vMqoTg23v7m:3FJC7YZvT7m` |
| ICON-DHASH | `0c7269b9b9491000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_5d4ea84b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6"
    family = "unknown"
    file_name = "5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6.exe"
    file_type = "exe"
    first_seen = "2026-10-29 05:18:27"
  condition:
    hash.sha256(0, filesize) == "5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6"
}
```

### Sample 8: `a9f3cea8de4211fc`

| Field | Value |
|---|---|
| SHA-256 | `a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-29 05:09:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de1bc3b889cd836daffe9bc9e4a1ca92` |
| SHA-1 | `742145dd489877ed8783188d7af9520f7f234d34` |
| SHA-256 | `a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155` |
| SHA3-384 | `5d2ca90eac22dbb84543785e4431437cf30c0cd26b568f64a1714940b037365b1c09f24fab23311aa0c3f8f02d63cdbe` |
| TLSH | `T10C740A88A1F1E7DED2D4EA75B31D780D3B230736B1D73146A51EAA3323EB1450AF9921` |
| TELFHASH | `t16cf0c0742b100a5c47f345868397d113c53c2a01078115f2ce40254e4d79ff5f9ca832` |
| SSDEEP | `6144:3hAtWD+iSFKDRp229yetexiUuIgYq+4wpqtOtQxDa9LCB:JDOFKNGet7H3tM8a9LCB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_a9f3cea8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-29 05:09:34"
  condition:
    hash.sha256(0, filesize) == "a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155"
}
```

### Sample 9: `f7f4aa82b8bed3d8`

| Field | Value |
|---|---|
| SHA-256 | `f7f4aa82b8bed3d8998579518c468337a021221393f7ff95577b66a53518078c` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-10-29 05:02:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1f0ae88a4466738f1370a8b0f65c4a6` |
| SHA-1 | `f0d2e885185d861da6b46722d960c1b9d732efa3` |
| SHA-256 | `f7f4aa82b8bed3d8998579518c468337a021221393f7ff95577b66a53518078c` |
| SHA3-384 | `43ec77ba1ef44d6454438270c81985770c10d2d017730e743e78067cfb28dd66052296621f45f7ec1aa9555e63ce25a6` |
| TLSH | `T11AC36C22D5BE6D09C5D0B57602E703B2E0E7970502A8EA0EFD951FACDF17780267B768` |
| TELFHASH | `t1e3012048ec7ece3d59e39830ec7843929053ca3250a28b349f59d6c9843e20af118e0f` |
| SSDEEP | `3072:ymr94xu3r94U/o0YXAyVuVoj8pZ1Q1qL3L9N:yCixu7iuoZj8pZ1n9N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_f7f4aa82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7f4aa82b8bed3d8998579518c468337a021221393f7ff95577b66a53518078c"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-10-29 05:02:59"
  condition:
    hash.sha256(0, filesize) == "f7f4aa82b8bed3d8998579518c468337a021221393f7ff95577b66a53518078c"
}
```

### Sample 10: `d8e492ea07fd77f9`

| Field | Value |
|---|---|
| SHA-256 | `d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d` |
| Family label | `unknown` |
| File name | `d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d` |
| File type | `elf` |
| First seen | `2026-10-29 05:00:14` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2dc002d8e2882fefa1da15634509370e` |
| SHA-1 | `d8855060297f0257f56d2e00cd0ca7175b01301b` |
| SHA-256 | `d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d` |
| SHA3-384 | `1e7330bebcf9336a63b15aec3f79a51e04664483d1c6fc017ad08613d590828ef18e0679e932b41a711055735ac6f10c` |
| TLSH | `T119F69D77914338E9E5A98CB4D11025426DAC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQz:cqYUQuVDt0TZE4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_d8e492ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d"
    family = "unknown"
    file_name = "d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d"
    file_type = "elf"
    first_seen = "2026-10-29 05:00:14"
  condition:
    hash.sha256(0, filesize) == "d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d"
}
```

### Sample 11: `4f1dcf5f02913db6`

| Field | Value |
|---|---|
| SHA-256 | `4f1dcf5f02913db699db8e9d138e2cca9d7e7657d7d9bb37c6eef23ab794b22f` |
| Family label | `RemcosRAT` |
| File name | `05002600357104880_KAWAN_LAMA_GROUP_PT.js` |
| File type | `js` |
| First seen | `2026-10-29 04:55:36` |
| Reporter | `qemped` |
| Tags | `js, malspam, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b681cefbb5176dd82549e3e607babd54` |
| SHA-1 | `2493bac1907d83a625151ea6ceea87ef89f8a9ba` |
| SHA-256 | `4f1dcf5f02913db699db8e9d138e2cca9d7e7657d7d9bb37c6eef23ab794b22f` |
| SHA3-384 | `feb6bcdb100adebac38638f226d8b99be62d90dfa104b0d579f229916e9571575c33f9d5202d966ae28f15d9455c5604` |
| TLSH | `T11CC3C00536E5403EB0F7AE54CBE654916BAF7AE27E3CC19B008D260E0B73456BC93766` |
| SSDEEP | `3072:UsQcCaEk0b/LhqdvsmVkvhDd7x9yUfT/yxti/ER7Zp7rt6OPMEwAcbn2O3qUc4Yc:KM8x9Q1t/sDnOgYU` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_011_4f1dcf5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f1dcf5f02913db699db8e9d138e2cca9d7e7657d7d9bb37c6eef23ab794b22f"
    family = "RemcosRAT"
    file_name = "05002600357104880_KAWAN_LAMA_GROUP_PT.js"
    file_type = "js"
    first_seen = "2026-10-29 04:55:36"
  condition:
    hash.sha256(0, filesize) == "4f1dcf5f02913db699db8e9d138e2cca9d7e7657d7d9bb37c6eef23ab794b22f"
}
```

### Sample 12: `8d7fae9ec5139cb7`

| Field | Value |
|---|---|
| SHA-256 | `8d7fae9ec5139cb7a184710ac445ebf16aeca23fd38c33eae63a2ff351570fd4` |
| Family label | `RemcosRAT` |
| File name | `05002600357104880_KAWAN_LAMA_GROUP_PT.Gz` |
| File type | `gz` |
| First seen | `2026-10-29 04:55:17` |
| Reporter | `qemped` |
| Tags | `gz, malspam, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc2f11905c77929a9b115bb02b3640fb` |
| SHA-1 | `56271690e079ce130ba96a067975662a3fb94664` |
| SHA-256 | `8d7fae9ec5139cb7a184710ac445ebf16aeca23fd38c33eae63a2ff351570fd4` |
| SHA3-384 | `be1108e916f0b740e871ee41b710a6f2e9b75f4eab274b4576317caa59428b35f3ceefab36c00ce3f0e8b766ac2fec5b` |
| TLSH | `T1FFC2E17DB21CCBEE2A6A5D0A0797BF09E52149F0BDD636111768D9A9909CCB3CC02E4C` |
| SSDEEP | `768:Nok3zaaf4vy+zbesbY/W+Yh7UV/GpqDa18XP:tjaaf46AeEY+lZUNG/8XP` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_012_8d7fae9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d7fae9ec5139cb7a184710ac445ebf16aeca23fd38c33eae63a2ff351570fd4"
    family = "RemcosRAT"
    file_name = "05002600357104880_KAWAN_LAMA_GROUP_PT.Gz"
    file_type = "gz"
    first_seen = "2026-10-29 04:55:17"
  condition:
    hash.sha256(0, filesize) == "8d7fae9ec5139cb7a184710ac445ebf16aeca23fd38c33eae63a2ff351570fd4"
}
```

### Sample 13: `6b5afe506c5b4db4`

| Field | Value |
|---|---|
| SHA-256 | `6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7` |
| Family label | `unknown` |
| File name | `6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7` |
| File type | `elf` |
| First seen | `2026-10-29 04:35:32` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot, miner.multiverze` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d430f3192dc4c3dac9592c7c11db729` |
| SHA-1 | `c6f0b5d69c55b07f77105b32bb12f1baf8a11455` |
| SHA-256 | `6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7` |
| SHA3-384 | `9c80c3e4d1db0c9d71f88a1a851e9ea5217bb61862c6c4572626d4a89b8a7149a36d6dff0f5bbdd995133e4a29a2799d` |
| TLSH | `T14847DF77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQY:cqYUQuVDt0TZE7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_6b5afe50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7"
    family = "unknown"
    file_name = "6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7"
    file_type = "elf"
    first_seen = "2026-10-29 04:35:32"
  condition:
    hash.sha256(0, filesize) == "6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7"
}
```

### Sample 14: `c14491979811b95f`

| Field | Value |
|---|---|
| SHA-256 | `c14491979811b95f025be5274feb90ff296bcd4438c99f9121c8a5a7de8c4274` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-29 04:26:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5ebf44bb71daa629c8ffb9b171cccc3` |
| SHA-1 | `15a8dc8fa000888f61abae3b7865dd83da3c205b` |
| SHA-256 | `c14491979811b95f025be5274feb90ff296bcd4438c99f9121c8a5a7de8c4274` |
| SHA3-384 | `71f9cb7d1571dabd88c337f384073c9f7a72b84370bdd75953a553e7b12fc8d64cab52b1ac234729621b0a0098e7668e` |
| TLSH | `T11DE33C56E6418B13C4D61779BAEF42453322A7A4D3DB730699246FF43F827AF0E23A05` |
| TELFHASH | `t1f2310c315721a5056aa1cc6088fe57b2262cc7262744ef33ce35c48c640a0dee62bc0f` |
| SSDEEP | `3072:p35fVRUEQMYS1LJay4NX19Vxou1JdEBZhCHfrpzM/9743iN6mcw/G2H:ffVRmMYSxJay4NX19zb1CPCHfr9M/97x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_c1449197
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c14491979811b95f025be5274feb90ff296bcd4438c99f9121c8a5a7de8c4274"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-29 04:26:56"
  condition:
    hash.sha256(0, filesize) == "c14491979811b95f025be5274feb90ff296bcd4438c99f9121c8a5a7de8c4274"
}
```

### Sample 15: `18cc64b5520b7221`

| Field | Value |
|---|---|
| SHA-256 | `18cc64b5520b7221d39f84072a91fbfd3af8997af90c135a301e50ab5ec6c09a` |
| Family label | `SalatStealer` |
| File name | `f2c4da25934bf744.bin` |
| File type | `exe` |
| First seen | `2026-10-29 04:25:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `606a702430f63b0d5fd5e38f03eef5be` |
| SHA-1 | `759d74b9339a48af920ba1a305c3e71975493976` |
| SHA-256 | `18cc64b5520b7221d39f84072a91fbfd3af8997af90c135a301e50ab5ec6c09a` |
| SHA3-384 | `24dc4841d72cb0516fc933bf0faeedad0348f531056fce25ff51137aeb6def871517910b56636316bca6a0ff32989019` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T157C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+A:yBkKr5rszpNDy+A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_015_18cc64b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cc64b5520b7221d39f84072a91fbfd3af8997af90c135a301e50ab5ec6c09a"
    family = "SalatStealer"
    file_name = "f2c4da25934bf744.bin"
    file_type = "exe"
    first_seen = "2026-10-29 04:25:35"
  condition:
    hash.sha256(0, filesize) == "18cc64b5520b7221d39f84072a91fbfd3af8997af90c135a301e50ab5ec6c09a"
}
```

### Sample 16: `11308a0ae3564419`

| Field | Value |
|---|---|
| SHA-256 | `11308a0ae3564419ff7d12914b5b390934af3fa9c7c29420d64022dd0722eafa` |
| Family label | `SalatStealer` |
| File name | `a92603bea54428c6.bin` |
| File type | `exe` |
| First seen | `2026-10-29 04:25:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `667b9c03558e715e538c645ae405e615` |
| SHA-1 | `10358d2d70c709e078a028aa34c5d6e87b705bf4` |
| SHA-256 | `11308a0ae3564419ff7d12914b5b390934af3fa9c7c29420d64022dd0722eafa` |
| SHA3-384 | `a4f8aa6d56caaf5601697489b607d05e6f63e1012b02cfee164581a17b3d709e60fae8d89adb252a1941ce0657decd9c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T167C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+k:yBkKr5rszpNDy+k` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_016_11308a0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11308a0ae3564419ff7d12914b5b390934af3fa9c7c29420d64022dd0722eafa"
    family = "SalatStealer"
    file_name = "a92603bea54428c6.bin"
    file_type = "exe"
    first_seen = "2026-10-29 04:25:28"
  condition:
    hash.sha256(0, filesize) == "11308a0ae3564419ff7d12914b5b390934af3fa9c7c29420d64022dd0722eafa"
}
```

### Sample 17: `f2c4da25934bf744`

| Field | Value |
|---|---|
| SHA-256 | `f2c4da25934bf744a2031f65b5ecd9be3b1a56ac5aad74f6a82c586bc8de12ba` |
| Family label | `SalatStealer` |
| File name | `f2c4da25934bf744.bin` |
| File type | `exe` |
| First seen | `2026-10-29 04:24:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7aca03d7c6e5a4c462a4f3a4a17e9fbf` |
| SHA-1 | `d5160caef252956ee268dc9d84019d5890789cd7` |
| SHA-256 | `f2c4da25934bf744a2031f65b5ecd9be3b1a56ac5aad74f6a82c586bc8de12ba` |
| SHA3-384 | `fc27471b7107f3162f6d824e4744ab8cc2eb898196c116db2dae82ac776a2ef19c3df3770c2c681b4f880b5d32b74878` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T15DF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ok:iJiafuIO7rhWEES4b` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_017_f2c4da25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2c4da25934bf744a2031f65b5ecd9be3b1a56ac5aad74f6a82c586bc8de12ba"
    family = "SalatStealer"
    file_name = "f2c4da25934bf744.bin"
    file_type = "exe"
    first_seen = "2026-10-29 04:24:58"
  condition:
    hash.sha256(0, filesize) == "f2c4da25934bf744a2031f65b5ecd9be3b1a56ac5aad74f6a82c586bc8de12ba"
}
```

### Sample 18: `a92603bea54428c6`

| Field | Value |
|---|---|
| SHA-256 | `a92603bea54428c6f479e62da9815dbbdcb4be3ed566a78f3e974529f006e52a` |
| Family label | `SalatStealer` |
| File name | `a92603bea54428c6.bin` |
| File type | `exe` |
| First seen | `2026-10-29 04:24:42` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d5522a1425146a4c5a9324e8dd5bb8f` |
| SHA-1 | `8fc99a059d433449f86845c23f8c2c7db3fdf84b` |
| SHA-256 | `a92603bea54428c6f479e62da9815dbbdcb4be3ed566a78f3e974529f006e52a` |
| SHA3-384 | `c2af2e272c187a6a223d96699ad7b2a962705eea0fa93836f53d67731c1f5811ec2fcf11f55ce8c6e28974a3c8ba5bb0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T173F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Og:iJiafuIO7rhWEES41` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_018_a92603be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a92603bea54428c6f479e62da9815dbbdcb4be3ed566a78f3e974529f006e52a"
    family = "SalatStealer"
    file_name = "a92603bea54428c6.bin"
    file_type = "exe"
    first_seen = "2026-10-29 04:24:42"
  condition:
    hash.sha256(0, filesize) == "a92603bea54428c6f479e62da9815dbbdcb4be3ed566a78f3e974529f006e52a"
}
```

### Sample 19: `3b878a40f7badc24`

| Field | Value |
|---|---|
| SHA-256 | `3b878a40f7badc24cd584d816c01e3d316efa2a57683ea1181e319ff8ee24e58` |
| Family label | `unknown` |
| File name | `siyuchat_setup.exe` |
| File type | `exe` |
| First seen | `2026-10-29 03:27:07` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `904dbb2f7edf793c2e32e9849e63aedc` |
| SHA-1 | `2cbc3d914a9ece059f9cebb5a41ab53cc523088f` |
| SHA-256 | `3b878a40f7badc24cd584d816c01e3d316efa2a57683ea1181e319ff8ee24e58` |
| SHA3-384 | `640ff99696da1849837b0bb61d915f07f40cfe16e14e89043df773965c1b3ad121a1a5ce5e9abffab54d95052237c1a6` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T14996123BB14B21EAD42A5A3575F2B164943B7E1165128C8A97E3B8CFCF31470292FE47` |
| SSDEEP | `196608:qd13f0isshMA4+WSR4ANs46ibPxnh/AwWYNavrMKL:qd1slpC4U9rPZh5WYan` |
| ICON-DHASH | `8eb2a8c8e4f4cab6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_3b878a40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b878a40f7badc24cd584d816c01e3d316efa2a57683ea1181e319ff8ee24e58"
    family = "unknown"
    file_name = "siyuchat_setup.exe"
    file_type = "exe"
    first_seen = "2026-10-29 03:27:07"
  condition:
    hash.sha256(0, filesize) == "3b878a40f7badc24cd584d816c01e3d316efa2a57683ea1181e319ff8ee24e58"
}
```

### Sample 20: `bde27af26c47f2a1`

| Field | Value |
|---|---|
| SHA-256 | `bde27af26c47f2a171e4dda867dca68ee294bfa83b46331295139df8faed1a07` |
| Family label | `unknown` |
| File name | `svvhost.exe` |
| File type | `exe` |
| First seen | `2026-10-29 03:26:35` |
| Reporter | `Parper` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d8e26e3da5f8b477e98a7b7ed973bb9` |
| SHA-1 | `cd85961ca05accfa49492ea1f4e6503067faf37c` |
| SHA-256 | `bde27af26c47f2a171e4dda867dca68ee294bfa83b46331295139df8faed1a07` |
| SHA3-384 | `c229bf819a14a68bbcd8cb376cb8457c4b5be6fd346c96dc8b345516be8c191042a7d6b0781257c9581146bb46944fc8` |
| IMPHASH | `da9463d63cbcade45504911f7abbc387` |
| TLSH | `T17DB5AE96F3BA65EDD423C0B0C9A68217FB757C1D03105BA767D18A667F277A04E2B302` |
| SSDEEP | `49152:SZsK69wAQ0K97mZZMPbDo2RxXmg9bkgkrCRopIJo3t7dmMld/hF:a0KVPI2F9bRgaoHZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_bde27af2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bde27af26c47f2a171e4dda867dca68ee294bfa83b46331295139df8faed1a07"
    family = "unknown"
    file_name = "svvhost.exe"
    file_type = "exe"
    first_seen = "2026-10-29 03:26:35"
  condition:
    hash.sha256(0, filesize) == "bde27af26c47f2a171e4dda867dca68ee294bfa83b46331295139df8faed1a07"
}
```

### Sample 21: `0cf9cfd671535a47`

| Field | Value |
|---|---|
| SHA-256 | `0cf9cfd671535a4770d10c022b3e9b1031ee56d8c9f0eed8b179cae48eae1602` |
| Family label | `SalatStealer` |
| File name | `77a32b9c95a8228d.bin` |
| File type | `exe` |
| First seen | `2026-10-29 03:25:51` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `079540a8069f187d4b96ffafc5360175` |
| SHA-1 | `1e88eea157c17707ef6f91735e79b1497ef806f4` |
| SHA-256 | `0cf9cfd671535a4770d10c022b3e9b1031ee56d8c9f0eed8b179cae48eae1602` |
| SHA3-384 | `4bcd5158b575eccd80f02e0a41183940f24a0a76e258353f03179330536db1d9bc0e852b783627f98fd173e97cad3a7b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T19DC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+l:yBkKr5rszpNDy+l` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_021_0cf9cfd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cf9cfd671535a4770d10c022b3e9b1031ee56d8c9f0eed8b179cae48eae1602"
    family = "SalatStealer"
    file_name = "77a32b9c95a8228d.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:51"
  condition:
    hash.sha256(0, filesize) == "0cf9cfd671535a4770d10c022b3e9b1031ee56d8c9f0eed8b179cae48eae1602"
}
```

### Sample 22: `e28b6e0ff5aa7211`

| Field | Value |
|---|---|
| SHA-256 | `e28b6e0ff5aa72119bd3e2e20a63c36299f6dc08236cb6a67c7ce878566d8038` |
| Family label | `SalatStealer` |
| File name | `231f4fe6cebf9cbe.bin` |
| File type | `exe` |
| First seen | `2026-10-29 03:25:45` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a5bbbdc0bc17878421d79e7a1f35b1a` |
| SHA-1 | `5db3fb1705f69e1b407bc8dbd6fdc064784dc01e` |
| SHA-256 | `e28b6e0ff5aa72119bd3e2e20a63c36299f6dc08236cb6a67c7ce878566d8038` |
| SHA3-384 | `a59c46eb3f0f89c468b2531885a702c9802f9f76d10212a687bda2608bd591eb2fdbf63f3dc90338d5855217eb16f4be` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1EDC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+0:yBkKr5rszpNDy+0` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_022_e28b6e0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e28b6e0ff5aa72119bd3e2e20a63c36299f6dc08236cb6a67c7ce878566d8038"
    family = "SalatStealer"
    file_name = "231f4fe6cebf9cbe.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:45"
  condition:
    hash.sha256(0, filesize) == "e28b6e0ff5aa72119bd3e2e20a63c36299f6dc08236cb6a67c7ce878566d8038"
}
```

### Sample 23: `a82dc8871f1c3b73`

| Field | Value |
|---|---|
| SHA-256 | `a82dc8871f1c3b73f543322435b14ad2ed5723a8e246364a48320b11ba46f616` |
| Family label | `SalatStealer` |
| File name | `66cfd97e739eed9e.bin` |
| File type | `exe` |
| First seen | `2026-10-29 03:25:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fd393df4f976c3d142310eab2306166` |
| SHA-1 | `b2ce65b9971688a8c740ab1b0e8a83498e1f0381` |
| SHA-256 | `a82dc8871f1c3b73f543322435b14ad2ed5723a8e246364a48320b11ba46f616` |
| SHA3-384 | `07f8e657fd4e55dfa4f5998ecf640a9e8df006a029919b6e027f366da575772c8a732ca4a43efc9068566ae7688d4669` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T151C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+N:yBkKr5rszpNDy+N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_023_a82dc887
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a82dc8871f1c3b73f543322435b14ad2ed5723a8e246364a48320b11ba46f616"
    family = "SalatStealer"
    file_name = "66cfd97e739eed9e.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:38"
  condition:
    hash.sha256(0, filesize) == "a82dc8871f1c3b73f543322435b14ad2ed5723a8e246364a48320b11ba46f616"
}
```

### Sample 24: `77a32b9c95a8228d`

| Field | Value |
|---|---|
| SHA-256 | `77a32b9c95a8228dcb6ab73d2c045e7b603837a1aac535ac31b465b7f1f256af` |
| Family label | `SalatStealer` |
| File name | `77a32b9c95a8228d.bin` |
| File type | `exe` |
| First seen | `2026-10-29 03:25:16` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0991b77d6e084b92ba6cc0f134a4126` |
| SHA-1 | `38dd27629ca162f0420f61912050e44dca4017a3` |
| SHA-256 | `77a32b9c95a8228dcb6ab73d2c045e7b603837a1aac535ac31b465b7f1f256af` |
| SHA3-384 | `075d44354e31aa3c67e9448b86eb47caa4a3307479c8c628b2f1035d87fabd86498269adf1ef257393bea64c718e2fa6` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10FF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OZ:iJiafuIO7rhWEES4m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_024_77a32b9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a32b9c95a8228dcb6ab73d2c045e7b603837a1aac535ac31b465b7f1f256af"
    family = "SalatStealer"
    file_name = "77a32b9c95a8228d.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:16"
  condition:
    hash.sha256(0, filesize) == "77a32b9c95a8228dcb6ab73d2c045e7b603837a1aac535ac31b465b7f1f256af"
}
```

### Sample 25: `231f4fe6cebf9cbe`

| Field | Value |
|---|---|
| SHA-256 | `231f4fe6cebf9cbe7d663503bd25b923d3daeebbac973f98ace8a9a770d9b59b` |
| Family label | `SalatStealer` |
| File name | `231f4fe6cebf9cbe.bin` |
| File type | `exe` |
| First seen | `2026-10-29 03:25:06` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad33b78d8415621a8569077290e177a0` |
| SHA-1 | `0d8877aed57cef3679ad0e546ced9008be9146d7` |
| SHA-256 | `231f4fe6cebf9cbe7d663503bd25b923d3daeebbac973f98ace8a9a770d9b59b` |
| SHA3-384 | `14d4d86c5c605a0e5934c4e789fa9f76fa50ab2202a04492a33c15ff0d736b28d3b089a1dd69695318eed0e233fbb8a9` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1EAF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OY:iJiafuIO7rhWEES4R` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_025_231f4fe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "231f4fe6cebf9cbe7d663503bd25b923d3daeebbac973f98ace8a9a770d9b59b"
    family = "SalatStealer"
    file_name = "231f4fe6cebf9cbe.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:06"
  condition:
    hash.sha256(0, filesize) == "231f4fe6cebf9cbe7d663503bd25b923d3daeebbac973f98ace8a9a770d9b59b"
}
```

### Sample 26: `66cfd97e739eed9e`

| Field | Value |
|---|---|
| SHA-256 | `66cfd97e739eed9e633a632eae81e24072399ff538e0dd85866cdc42cfa8557d` |
| Family label | `SalatStealer` |
| File name | `66cfd97e739eed9e.bin` |
| File type | `exe` |
| First seen | `2026-10-29 03:24:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d13d1713e2c3ad6d47a30f0ea5e6e3b` |
| SHA-1 | `6a246566cecade0837ba8667cc115cd9ddbf6689` |
| SHA-256 | `66cfd97e739eed9e633a632eae81e24072399ff538e0dd85866cdc42cfa8557d` |
| SHA3-384 | `be858eb9356f33a1d2f8941129792e7cfe07219ced4aa3f10581a63667bb397bd4c7e9fa3afb5b5f3954da67a40bdc02` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T199F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Op:iJiafuIO7rhWEES4M` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_026_66cfd97e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66cfd97e739eed9e633a632eae81e24072399ff538e0dd85866cdc42cfa8557d"
    family = "SalatStealer"
    file_name = "66cfd97e739eed9e.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:24:56"
  condition:
    hash.sha256(0, filesize) == "66cfd97e739eed9e633a632eae81e24072399ff538e0dd85866cdc42cfa8557d"
}
```

### Sample 27: `6e79e890c649ef6f`

| Field | Value |
|---|---|
| SHA-256 | `6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7` |
| Family label | `Mirai` |
| File name | `6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7.elf` |
| File type | `elf` |
| First seen | `2026-10-29 03:23:25` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08f967fcf3bedff6136648662fbdde45` |
| SHA-1 | `8b0d2bef99ffb21c1de28da43dddccdf30f81b51` |
| SHA-256 | `6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7` |
| SHA3-384 | `71c60a0d5a84f4679e9a50497ec50060af016a8c93302ca36b8ba03774b8854d38df41009bdf3209b4549aa9b9d525b4` |
| TLSH | `T157555D49B2F3B0FDD057D430831BEA629C35B43521237D7B71C5AA312E66EA01B69F62` |
| TELFHASH | `t162f1dd708ae635f0b3d7da01b312f1b5ae7228f552f836f46a239d94edc5e804d63426` |
| SSDEEP | `24576:BdvP+J6zAXhrcWwCCTrqdD2CKWQmC/jP:BdvWDXhrcWwCCTED2CAm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_6e79e890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7"
    family = "Mirai"
    file_name = "6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7.elf"
    file_type = "elf"
    first_seen = "2026-10-29 03:23:25"
  condition:
    hash.sha256(0, filesize) == "6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7"
}
```

### Sample 28: `af4acf4db03f73be`

| Field | Value |
|---|---|
| SHA-256 | `af4acf4db03f73be83613a4840aefbc14702d11906ec72953e2e17c39249b4c3` |
| Family label | `unknown` |
| File name | `FACEITInstaller_64.exe` |
| File type | `rar` |
| First seen | `2026-10-29 03:14:23` |
| Reporter | `Parper` |
| Tags | `exe, rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51fdcd601b54dfab22d85cd4f9ce6379` |
| SHA-1 | `026bd542b2541eb5f9de0221f45a781ea3f9f184` |
| SHA-256 | `af4acf4db03f73be83613a4840aefbc14702d11906ec72953e2e17c39249b4c3` |
| SHA3-384 | `547def8788f58eaa7e09b5a595b49d7223e5a332e70bbcb6f3ee632c4af191e215c1374077e42184547f9f1235e84b6a` |
| TLSH | `T18E67339B3A68F726F64823A98C5BD215DB50CDF901F8836D991005AADFDEE03C74706B` |
| SSDEEP | `786432:rDfm1UP+o3VLMe3CEWPWMWEkjLHrvw/lA:rbmA3VLMeyEWPrWEkjLHrMlA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_af4acf4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af4acf4db03f73be83613a4840aefbc14702d11906ec72953e2e17c39249b4c3"
    family = "unknown"
    file_name = "FACEITInstaller_64.exe"
    file_type = "rar"
    first_seen = "2026-10-29 03:14:23"
  condition:
    hash.sha256(0, filesize) == "af4acf4db03f73be83613a4840aefbc14702d11906ec72953e2e17c39249b4c3"
}
```

### Sample 29: `1382088ffa6ee9bb`

| Field | Value |
|---|---|
| SHA-256 | `1382088ffa6ee9bb02c4b8f6153c8a70f926d816c1f849a81aa51408870b09ac` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-29 02:35:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `115d3a7fcfc6be338629e914171ee32f` |
| SHA-1 | `b901a1261680f5c59e93e34388ad0f0777849137` |
| SHA-256 | `1382088ffa6ee9bb02c4b8f6153c8a70f926d816c1f849a81aa51408870b09ac` |
| SHA3-384 | `82b5e7ce815449b926a678f431bdd27a8de67c1d64e7719bf90b96002a6022a71683ae41900bc7e6bbabefdf01b8e88e` |
| TLSH | `T10E556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSo:SDjxB4m5n8XlaPWi+d+a4TjxQP4G` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_1382088f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1382088ffa6ee9bb02c4b8f6153c8a70f926d816c1f849a81aa51408870b09ac"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-29 02:35:50"
  condition:
    hash.sha256(0, filesize) == "1382088ffa6ee9bb02c4b8f6153c8a70f926d816c1f849a81aa51408870b09ac"
}
```

### Sample 30: `16e019fcfe4456e7`

| Field | Value |
|---|---|
| SHA-256 | `16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050` |
| Family label | `SalatStealer` |
| File name | `16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050.exe` |
| File type | `exe` |
| First seen | `2026-10-29 02:33:25` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d070775ff921fe44982726a4e455b2c` |
| SHA-1 | `7c2bb8302b53bb075d7c41972bca7a9e9d72a2b6` |
| SHA-256 | `16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050` |
| SHA3-384 | `039126b9158218be881d698ebb4859a9ba196ee543891dbc7e557e4a0fae46f106c76e15952371113a4ce350e44d5986` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T162C6BE07EDA155E8C0AAE23586679152BF717C485B3123D32BA0F7382F76BD0AE79740` |
| SSDEEP | `196608:wdCvnMpIkUPiA4ZQpWclBh0Qx30PXlmaHlMFgDnkoi6M:wdCvn9kUPvlBh0Qx3OX/HlMgb3iX` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_030_16e019fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050"
    family = "SalatStealer"
    file_name = "16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050.exe"
    file_type = "exe"
    first_seen = "2026-10-29 02:33:25"
  condition:
    hash.sha256(0, filesize) == "16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050"
}
```

### Sample 31: `9daea98c0ef4a998`

| Field | Value |
|---|---|
| SHA-256 | `9daea98c0ef4a998a9c8bec7299587b0dc127f078ced6f633a855ca60622a248` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-29 02:32:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `018aa6ec03032fdc937da4383832e373` |
| SHA-1 | `a4e9c8c60fd18f79990432a01db68636385eb258` |
| SHA-256 | `9daea98c0ef4a998a9c8bec7299587b0dc127f078ced6f633a855ca60622a248` |
| SHA3-384 | `3f0411b5c14a2ef54e6d377c0997a623f11df719f082408f2e82a96859bec848371dfb975f32db060fd5eed0037a1ee9` |
| TLSH | `T1FE556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS3:SDjxB4m5n8XlaPWi+d+a4TjxQP4B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_9daea98c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9daea98c0ef4a998a9c8bec7299587b0dc127f078ced6f633a855ca60622a248"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-29 02:32:56"
  condition:
    hash.sha256(0, filesize) == "9daea98c0ef4a998a9c8bec7299587b0dc127f078ced6f633a855ca60622a248"
}
```

### Sample 32: `d38888ef13080bcf`

| Field | Value |
|---|---|
| SHA-256 | `d38888ef13080bcf9a5ab92f19a4d3f2bf72860429216fa21db591f716f88ad0` |
| Family label | `SalatStealer` |
| File name | `5ced9afef6a7705b.bin` |
| File type | `exe` |
| First seen | `2026-10-29 02:26:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d30f31863da1dbcade2cde7129886908` |
| SHA-1 | `711d062fa87ddfd9a82d143ef4e6fa6e499c8da9` |
| SHA-256 | `d38888ef13080bcf9a5ab92f19a4d3f2bf72860429216fa21db591f716f88ad0` |
| SHA3-384 | `a5f2f6dcacb991dc8481f816a82ecc199809f79d4309cdf6268b605e321f93386d6ae796c8e08e33b590a5e5299111a9` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T170C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE++:yBkKr5rszpNDy++` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_032_d38888ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d38888ef13080bcf9a5ab92f19a4d3f2bf72860429216fa21db591f716f88ad0"
    family = "SalatStealer"
    file_name = "5ced9afef6a7705b.bin"
    file_type = "exe"
    first_seen = "2026-10-29 02:26:23"
  condition:
    hash.sha256(0, filesize) == "d38888ef13080bcf9a5ab92f19a4d3f2bf72860429216fa21db591f716f88ad0"
}
```

### Sample 33: `e191c70bd8c99caf`

| Field | Value |
|---|---|
| SHA-256 | `e191c70bd8c99caf21719463d4192ef498b9a52b625fe0879204fc4a7d05f37e` |
| Family label | `SalatStealer` |
| File name | `a0e2b9c5bcda769b.bin` |
| File type | `exe` |
| First seen | `2026-10-29 02:25:26` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ba0d5557b2db0a611aba2ea554a6a38` |
| SHA-1 | `063d961cdcc7c3df20d35e1a68a63686856455ff` |
| SHA-256 | `e191c70bd8c99caf21719463d4192ef498b9a52b625fe0879204fc4a7d05f37e` |
| SHA3-384 | `28eb278875484377b7ebdcac13d5526a80a0bedbf4dce00901e732a48352abdfcbcacb3ce2cb8a521073ab0a6591eced` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T118C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+y:yBkKr5rszpNDy+y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_033_e191c70b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e191c70bd8c99caf21719463d4192ef498b9a52b625fe0879204fc4a7d05f37e"
    family = "SalatStealer"
    file_name = "a0e2b9c5bcda769b.bin"
    file_type = "exe"
    first_seen = "2026-10-29 02:25:26"
  condition:
    hash.sha256(0, filesize) == "e191c70bd8c99caf21719463d4192ef498b9a52b625fe0879204fc4a7d05f37e"
}
```

### Sample 34: `5ced9afef6a7705b`

| Field | Value |
|---|---|
| SHA-256 | `5ced9afef6a7705b783ed2edda02a39452d391af6490087b0c32fdeaf4bea0f9` |
| Family label | `SalatStealer` |
| File name | `5ced9afef6a7705b.bin` |
| File type | `exe` |
| First seen | `2026-10-29 02:25:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df7bba20f0c94d5162588e73151dc15b` |
| SHA-1 | `9b6b1d58b5516b81e599f2c4031f63faedc63897` |
| SHA-256 | `5ced9afef6a7705b783ed2edda02a39452d391af6490087b0c32fdeaf4bea0f9` |
| SHA3-384 | `dad25452395467c0e6c7e32c15547df29c6c4a61f254b5bf9ec441a587023207c15b78bc50cf5ca5187f036a0fa5b5a5` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T15AF5335BF1AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OS:iJiafuIO7rhWEES4z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_034_5ced9afe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ced9afef6a7705b783ed2edda02a39452d391af6490087b0c32fdeaf4bea0f9"
    family = "SalatStealer"
    file_name = "5ced9afef6a7705b.bin"
    file_type = "exe"
    first_seen = "2026-10-29 02:25:26"
  condition:
    hash.sha256(0, filesize) == "5ced9afef6a7705b783ed2edda02a39452d391af6490087b0c32fdeaf4bea0f9"
}
```

### Sample 35: `a0e2b9c5bcda769b`

| Field | Value |
|---|---|
| SHA-256 | `a0e2b9c5bcda769b5ced07bca13da40f37ca6dcb16c3d5036b9089755dedf186` |
| Family label | `SalatStealer` |
| File name | `a0e2b9c5bcda769b.bin` |
| File type | `exe` |
| First seen | `2026-10-29 02:25:16` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ff224569aaef8764c10c5ddbf903d38` |
| SHA-1 | `a74f0e068ad40cada0e57a95b1869d9479906b96` |
| SHA-256 | `a0e2b9c5bcda769b5ced07bca13da40f37ca6dcb16c3d5036b9089755dedf186` |
| SHA3-384 | `f4ae60fe4c25684dc56439c035e20f7b656508ca112ff7fad7a36e2e706cc0c5dec684c826baf30d7d80e1e9c9e5cd06` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1D4F5335BF1AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OW:iJiafuIO7rhWEES4h` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_035_a0e2b9c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0e2b9c5bcda769b5ced07bca13da40f37ca6dcb16c3d5036b9089755dedf186"
    family = "SalatStealer"
    file_name = "a0e2b9c5bcda769b.bin"
    file_type = "exe"
    first_seen = "2026-10-29 02:25:16"
  condition:
    hash.sha256(0, filesize) == "a0e2b9c5bcda769b5ced07bca13da40f37ca6dcb16c3d5036b9089755dedf186"
}
```

### Sample 36: `eec3f1975eb72112`

| Field | Value |
|---|---|
| SHA-256 | `eec3f1975eb721121705ac3a478bade8a4c3d462615c2bfab7f2a035674cb3a9` |
| Family label | `Mirai` |
| File name | `arm8` |
| File type | `elf` |
| First seen | `2026-10-29 02:18:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d68c4e1e3e2da7f602c33cf7d8eeb89f` |
| SHA-1 | `b0785652e9a60a8baabf0831979b81e6af747538` |
| SHA-256 | `eec3f1975eb721121705ac3a478bade8a4c3d462615c2bfab7f2a035674cb3a9` |
| SHA3-384 | `36990e529bf72d1957973f5efc929a547dbd7fe5b0eb6dc0afc33057deef23a6412583f386601c797f67e8142004148f` |
| TLSH | `T17D746C8C52F6FBCEE298EA759315BC1668376536309371E6310FA66B43BB18449F9C30` |
| SSDEEP | `3072:tuOgTv8hQJ0OFbS9X0HHvJuNJoVezP1U6d9RKnEtqHMWS3DRRUGLfmKdjfa90QZT:tu0abIX8vJU6or9KnKqHsUGiK5a9DC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_eec3f197
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eec3f1975eb721121705ac3a478bade8a4c3d462615c2bfab7f2a035674cb3a9"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-10-29 02:18:01"
  condition:
    hash.sha256(0, filesize) == "eec3f1975eb721121705ac3a478bade8a4c3d462615c2bfab7f2a035674cb3a9"
}
```

### Sample 37: `1589043c3092d916`

| Field | Value |
|---|---|
| SHA-256 | `1589043c3092d916414efefec4de9ae15215a85983b13fc02f5e687994f3fd1c` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-29 02:14:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c3727ec46577a44811266e45ba976d2` |
| SHA-1 | `a5e924436c956b73a6d08560cb1664b5b9d0a911` |
| SHA-256 | `1589043c3092d916414efefec4de9ae15215a85983b13fc02f5e687994f3fd1c` |
| SHA3-384 | `f98af36d843f703894c4174f67da9a619d551a8bced1fe32bc51edeed6af466e3a9bdf4e59d16a4ba62150af171a7a55` |
| TLSH | `T13A740988A1F1E7DED2D4EA75B319780D3A230736B1D73146A51EBA3323EB1450AFD921` |
| TELFHASH | `t1eff0c99485343dee4b81614086b5706900ae389cb75120fad6cf078c4f125d8b4f8cfb` |
| SSDEEP | `6144:Ie7fcflyOnFNQlfBGs1F6xFkqFzbr3wkvddtDEWa9HT:Wf0SMMsS3RRNd3ta9HT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_1589043c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1589043c3092d916414efefec4de9ae15215a85983b13fc02f5e687994f3fd1c"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-29 02:14:55"
  condition:
    hash.sha256(0, filesize) == "1589043c3092d916414efefec4de9ae15215a85983b13fc02f5e687994f3fd1c"
}
```

### Sample 38: `ab4110850e3b9a86`

| Field | Value |
|---|---|
| SHA-256 | `ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23` |
| Family label | `unknown` |
| File name | `ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23.sh` |
| File type | `sh` |
| First seen | `2026-10-29 02:03:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e5c5c371056b288165124bb5b760321` |
| SHA-1 | `d0b08182710328e4067ca9e69581d34b4a32576d` |
| SHA-256 | `ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23` |
| SHA3-384 | `3cd931dd8a268e9f5832f385e8a8433c4bfb61f9b5ae0c91243c666304223546acba690d0b43d42f9406e64c65b828c1` |
| TLSH | `T1B902E03B11F08B71D7C421C9526656A54E72A71B992A14F8F4BF973A9B2CA0334E7F30` |
| SSDEEP | `96:cCuwKB657sht+O+v1fsn+h4+tIicqbA/GsGsioVbeezC:cCuwu65C4hvZ5mzjB2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_ab411085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23"
    family = "unknown"
    file_name = "ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23.sh"
    file_type = "sh"
    first_seen = "2026-10-29 02:03:00"
  condition:
    hash.sha256(0, filesize) == "ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23"
}
```

### Sample 39: `f64b3080432867f3`

| Field | Value |
|---|---|
| SHA-256 | `f64b3080432867f3778e62399cc109dfbc10ddc924bc5221daa3c1d54eecc831` |
| Family label | `unknown` |
| File name | `macho_f64b30804328.bin` |
| File type | `macho` |
| First seen | `2026-10-29 02:02:32` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46793f3611e5b446baf93ef5f783836e` |
| SHA-1 | `9d877290d2b3c0d54dcfe8365882b4bd7a327058` |
| SHA-256 | `f64b3080432867f3778e62399cc109dfbc10ddc924bc5221daa3c1d54eecc831` |
| SHA3-384 | `58725c8201e90c0ddb64462475c15869d298a137a28e8a6a34a999f67fb55409fb078fb5c47990a1295916db26bafb11` |
| TLSH | `T176A5F22421372239FC022472DA020BD556A065F9690DBEF77A25D736AC369D376E333E` |
| SSDEEP | `49152:duxYzFedRGcUeoLwO8qGEgDo159Uv+zv7Wt0q7q7p4QU+nlgOW2eSQwoV7VCEUZY:dN2RGRjvxg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_f64b3080
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64b3080432867f3778e62399cc109dfbc10ddc924bc5221daa3c1d54eecc831"
    family = "unknown"
    file_name = "macho_f64b30804328.bin"
    file_type = "macho"
    first_seen = "2026-10-29 02:02:32"
  condition:
    hash.sha256(0, filesize) == "f64b3080432867f3778e62399cc109dfbc10ddc924bc5221daa3c1d54eecc831"
}
```

### Sample 40: `5300c0e0296ae4d2`

| Field | Value |
|---|---|
| SHA-256 | `5300c0e0296ae4d2897ea72b5282b2fa57f8b824507e1a3d9dd80d6530395fdc` |
| Family label | `unknown` |
| File name | `macho_5300c0e0296a.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:57:59` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee38951125d32f0857251bc442a358f3` |
| SHA-1 | `c79491cf0e83d64f7bfb392f6dfefbdcd4399387` |
| SHA-256 | `5300c0e0296ae4d2897ea72b5282b2fa57f8b824507e1a3d9dd80d6530395fdc` |
| SHA3-384 | `a11b4e689b94aca688536d616c44e31ae50354b71892ea34644a9d870d49af17b4212df355c830972f7e0f0ec900911e` |
| TLSH | `T12995E0808F5F6087D94E11739C9A8B198574B081CE85CEDE6341A38ACE3A3E3B7575F6` |
| SSDEEP | `24576:gEIor/dVU9FKUVoU9PBIv+mq9tw2kwTVo1pVFxER1qZAGaw0fEEHpRSHGWI:gUEFLpXIv+5tw2kuo1jFxG1qkR9DSHGF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_5300c0e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5300c0e0296ae4d2897ea72b5282b2fa57f8b824507e1a3d9dd80d6530395fdc"
    family = "unknown"
    file_name = "macho_5300c0e0296a.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:57:59"
  condition:
    hash.sha256(0, filesize) == "5300c0e0296ae4d2897ea72b5282b2fa57f8b824507e1a3d9dd80d6530395fdc"
}
```

### Sample 41: `bca63a1f5c50cf79`

| Field | Value |
|---|---|
| SHA-256 | `bca63a1f5c50cf795e6bd12e1357ce3c52996a3ad2290970e9295c77c0ff0ad6` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-29 01:57:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a9a3e1795d43cfaa6f6bc95caaf4757` |
| SHA-1 | `b6dd432ff0892be1e374c87586f62fb41d2adff4` |
| SHA-256 | `bca63a1f5c50cf795e6bd12e1357ce3c52996a3ad2290970e9295c77c0ff0ad6` |
| SHA3-384 | `fa37d4f5f1abfdc3aa402e7eb5dbd88db0c375af8190d2254e8d17258f89bde0503c8ff191b063879857d48f9358c7c3` |
| TLSH | `T11C142859FD81AF11E5C126BAFB4E424933571B78E3EE7102AE182F2427CA95B0F7B501` |
| TELFHASH | `t14d1163618c4806a8f1cb9010eb7fb12740dc6148bf0a24de9bb0ae3c6d631e8b038c1f` |
| SSDEEP | `6144:lFCZMa49CHPlxHhtRcQMB0rdx6V7yVP2peMWmGa8/w/TCskJS3E4hISbml9L:nCZMa44HtthtRNMB0r/aOV4eMWmGa80i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_bca63a1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca63a1f5c50cf795e6bd12e1357ce3c52996a3ad2290970e9295c77c0ff0ad6"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-29 01:57:25"
  condition:
    hash.sha256(0, filesize) == "bca63a1f5c50cf795e6bd12e1357ce3c52996a3ad2290970e9295c77c0ff0ad6"
}
```

### Sample 42: `7f64ed4a05d8be4a`

| Field | Value |
|---|---|
| SHA-256 | `7f64ed4a05d8be4a2ed5a6fddbae3c51238aec601971d3eb7dabb8a2794aec13` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-29 01:56:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b718ed3dbb19b683721abaebb9867c9f` |
| SHA-1 | `edda4a86c1d6d495eac0cce72944471422d822f8` |
| SHA-256 | `7f64ed4a05d8be4a2ed5a6fddbae3c51238aec601971d3eb7dabb8a2794aec13` |
| SHA3-384 | `acc1316c6d4fc59fdfd31ee9d49789ea4249930ab0188d79e171ac5648b078ee7d990b0b83aef322d1fbb18043dc470e` |
| TLSH | `T1CC830262E0524296CBEACCB2DA3CB7461D555794DE9BBE4324DD115C7EAC32FCB2C044` |
| SSDEEP | `1536:X++HdxkPRUX0Xe+y/5ipuNp652zyid3acpa4szz5rLTb3ePpLF:X++Hdm5UXUmd37paZzh3QpLF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_7f64ed4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f64ed4a05d8be4a2ed5a6fddbae3c51238aec601971d3eb7dabb8a2794aec13"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-29 01:56:46"
  condition:
    hash.sha256(0, filesize) == "7f64ed4a05d8be4a2ed5a6fddbae3c51238aec601971d3eb7dabb8a2794aec13"
}
```

### Sample 43: `1c5efea856059fc5`

| Field | Value |
|---|---|
| SHA-256 | `1c5efea856059fc548f2b21e9e6e5079727949e5c86f8f428acfeef314ed1060` |
| Family label | `unknown` |
| File name | `macho_1c5efea85605.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:53:13` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60af3c043bb4f1eb1387b90f5686805f` |
| SHA-1 | `2f528fcb9a8c278256b92c711090ab0a90e6c631` |
| SHA-256 | `1c5efea856059fc548f2b21e9e6e5079727949e5c86f8f428acfeef314ed1060` |
| SHA3-384 | `1105eb19f8e16b1d7124e4efac8903152c3e4c3977d781926b753d4c89302b001f87cbe20fdec4975936bcd58ee745b3` |
| TLSH | `T1A985F1905A2D2326E0841432DCD24FAE54A477B16A08B5FB7627A7C63D386C3B7B7317` |
| SSDEEP | `24576:JyXVAMT4b33EbeuIgQCp3abVM/jSoAnwBmc5WvBnmXpE3q:zuzeuI9g3avoAnwBmtnmP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_1c5efea8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c5efea856059fc548f2b21e9e6e5079727949e5c86f8f428acfeef314ed1060"
    family = "unknown"
    file_name = "macho_1c5efea85605.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:53:13"
  condition:
    hash.sha256(0, filesize) == "1c5efea856059fc548f2b21e9e6e5079727949e5c86f8f428acfeef314ed1060"
}
```

### Sample 44: `8ac8e983086e7e35`

| Field | Value |
|---|---|
| SHA-256 | `8ac8e983086e7e35004a8ea6575a37e14b986c518b13bc5c906e3df89f37d8d3` |
| Family label | `unknown` |
| File name | `macho_8ac8e983086e.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:48:41` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d21b0e01f6d3166d362424834ea2e55` |
| SHA-1 | `7c2f0c790eda80596dc344cc5bb3a88cf91cfffe` |
| SHA-256 | `8ac8e983086e7e35004a8ea6575a37e14b986c518b13bc5c906e3df89f37d8d3` |
| SHA3-384 | `0d8f0f4949910983e3f87dfbc92b279fb52e1fe0844861cafc89e96ed7a72ec20075f0e7d196523c2ba3dc72234136e3` |
| TLSH | `T13695E040DF1FB0DBD80A11339C9A4B6981746080CA05DEF95381F36ADE377A77B529BA` |
| SSDEEP | `24576:7ZzXxtQr0HySdA0lAbDVe/bgbefW41YkF6gC7tBVqN+Ch6A/v/Vq3L174t3ovoim:dTJUDuotBVqNnh6cyLtO6Ygc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_8ac8e983
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ac8e983086e7e35004a8ea6575a37e14b986c518b13bc5c906e3df89f37d8d3"
    family = "unknown"
    file_name = "macho_8ac8e983086e.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:48:41"
  condition:
    hash.sha256(0, filesize) == "8ac8e983086e7e35004a8ea6575a37e14b986c518b13bc5c906e3df89f37d8d3"
}
```

### Sample 45: `8220416c319dfc51`

| Field | Value |
|---|---|
| SHA-256 | `8220416c319dfc519aaf6023ac5c50394d758e3ebe436f3e7c43ff7feb19c0a0` |
| Family label | `unknown` |
| File name | `macho_8220416c319d.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:43:53` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d89321a4911de28aa3e9f2455fc29c8` |
| SHA-1 | `78cf527642707908a6235a08920f39b88d036484` |
| SHA-256 | `8220416c319dfc519aaf6023ac5c50394d758e3ebe436f3e7c43ff7feb19c0a0` |
| SHA3-384 | `6364489833085c9385aa08b2d210723d799fccc01e2fe753ddfb0610a24108012b8c7c4ac5c2a34bdf294df33e2b1c32` |
| TLSH | `T18AA5E0104E1F609BD40A21339C990F5944F0AC80CD4DEEEA5392B796EE3B35777626BB` |
| SSDEEP | `24576:3Xhk8925Hc7RDyqb6YRd8Nh+Ke2BHHuyKOcRjLywdrkYYZG3XE6l+WRrT+dm8YwM:r7rj2DZG306EQT+dm+LS7LiC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_8220416c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8220416c319dfc519aaf6023ac5c50394d758e3ebe436f3e7c43ff7feb19c0a0"
    family = "unknown"
    file_name = "macho_8220416c319d.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:43:53"
  condition:
    hash.sha256(0, filesize) == "8220416c319dfc519aaf6023ac5c50394d758e3ebe436f3e7c43ff7feb19c0a0"
}
```

### Sample 46: `d590b52661f31fa0`

| Field | Value |
|---|---|
| SHA-256 | `d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9` |
| Family label | `njrat` |
| File name | `d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9.exe` |
| File type | `exe` |
| First seen | `2026-10-29 01:43:24` |
| Reporter | `Tuxxin` |
| Tags | `exe, njrat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `544b1ab834620eac813f276ebccc86d4` |
| SHA-1 | `8cc95527655598ac66e890e4d4f9de16c7acbf1d` |
| SHA-256 | `d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9` |
| SHA3-384 | `0577b969c9a6d78089e5faf1a4f9d858455468d4958286de7874c11088ec356a930ed9f31ce30ca7d380d48761c58417` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13593E74977E52524E5BF56F79871F2004E34B48B1602E39D48F219AA1B33AC44F89FEB` |
| SSDEEP | `768:nY3TypD9O/pBcxYsbae6GIXb9pDX2b9zPL0OXLeuXxrjEtCdnl2pi1Rz4Rk3rJso:6yLOx6baIa9RIj00ljEwzGi1dD1DLgS` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_046_d590b526
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9"
    family = "njrat"
    file_name = "d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:43:24"
  condition:
    hash.sha256(0, filesize) == "d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9"
}
```

### Sample 47: `bb4490884100ee84`

| Field | Value |
|---|---|
| SHA-256 | `bb4490884100ee84e132ea822d06da99508becdc16e434dcf11ade19b0971dd0` |
| Family label | `unknown` |
| File name | `macho_bb4490884100.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:39:25` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f504db5dd0b1d637ff2fc60fa49c84a` |
| SHA-1 | `fc7bc6cd99754a265a74f6936499bc2427174ed8` |
| SHA-256 | `bb4490884100ee84e132ea822d06da99508becdc16e434dcf11ade19b0971dd0` |
| SHA3-384 | `c0dffd23fd07286dd3831ac902bd7533814bbf4024880a9c7dd00ab949473c332f8022ea34de33f01b66c2fb0c02f5ec` |
| TLSH | `T1F485E050CF5BB1DBE54A02335C8A4F9984342160CD4AEEE92701E3AB9E367E33752677` |
| SSDEEP | `24576:iQTgnRHvQWXOl8TW9xcPXl8RaVZHlEig0Lt8TNW6AZ6uw5t+2Zwa61nc+nZphsEP:UN1XlnU0LwNKPAt+5a61PccLMTnU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_bb449088
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb4490884100ee84e132ea822d06da99508becdc16e434dcf11ade19b0971dd0"
    family = "unknown"
    file_name = "macho_bb4490884100.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:39:25"
  condition:
    hash.sha256(0, filesize) == "bb4490884100ee84e132ea822d06da99508becdc16e434dcf11ade19b0971dd0"
}
```

### Sample 48: `a2badf05b11de0f7`

| Field | Value |
|---|---|
| SHA-256 | `a2badf05b11de0f772600c9fef2357c1f514a0ca21feb43240f188dbf7522992` |
| Family label | `unknown` |
| File name | `macho_a2badf05b11d.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:35:01` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a5073659b9ca5a82c8cf2c59b7a21fb` |
| SHA-1 | `99c77775f89ced88c3e2d7fc3e560c2fe90b24b6` |
| SHA-256 | `a2badf05b11de0f772600c9fef2357c1f514a0ca21feb43240f188dbf7522992` |
| SHA3-384 | `56cd892ca8ab358eb29a4e3915318b3e0f33161eec9b8cdd9a6f54c8c0dd4c0090f53999cdc593569af2bfe877f3cfbf` |
| TLSH | `T1D895F1606E795269D08524F3DF108FC956A067A56E08B2F55E248F033D396C3BEB73A3` |
| SSDEEP | `24576:gpMdl06Lo1RyYcDfdHENJSFHwlU+22RIOdYg3AOPmtYsMBrwxD4ZQ+Pr5eATbmGd:aVqiKvO/TsMBrwt4Z1Pde0bMhk3R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_a2badf05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2badf05b11de0f772600c9fef2357c1f514a0ca21feb43240f188dbf7522992"
    family = "unknown"
    file_name = "macho_a2badf05b11d.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:35:01"
  condition:
    hash.sha256(0, filesize) == "a2badf05b11de0f772600c9fef2357c1f514a0ca21feb43240f188dbf7522992"
}
```

### Sample 49: `a066568d8f88f5b2`

| Field | Value |
|---|---|
| SHA-256 | `a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3` |
| Family label | `unknown` |
| File name | `a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3.exe` |
| File type | `exe` |
| First seen | `2026-10-29 01:30:46` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a4e424567f496dfd0070b72620f929c` |
| SHA-1 | `45b5e723dc751e3b0860d342de3442f5e64cc9a6` |
| SHA-256 | `a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3` |
| SHA3-384 | `7e343045eacf2e7a921f3b08bda23c7ad6c1e253e63a58032f0e63fd18b1d7cb3a419ba41572a9199ba86851f5b63653` |
| IMPHASH | `e3e80a143805ea18936c8f612e25d363` |
| TLSH | `T1B0D63356E3D598E8FEE7E6384A52511867B338400731D5EF06F88AA13E772E02935B73` |
| SSDEEP | `196608:8G2ecNTwhLNEgeurHmmeuhHToAUPNfGU5vXvEkiu4dk0ax8lLVkIeZ+ped7a/+4W:86LNEuC6hHTodRGkXMkSaxIhKAodm/` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_a066568d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3"
    family = "unknown"
    file_name = "a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:30:46"
  condition:
    hash.sha256(0, filesize) == "a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3"
}
```

### Sample 50: `643af4611e02c362`

| Field | Value |
|---|---|
| SHA-256 | `643af4611e02c36280cdf4a9b22be3488ec48278db7511e268c13d0c11a0daf9` |
| Family label | `unknown` |
| File name | `macho_643af4611e02.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:30:28` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f2ba44080e497e1e27376a119d1c642` |
| SHA-1 | `df42d6c1b8086532686393729416703d9b2c74cb` |
| SHA-256 | `643af4611e02c36280cdf4a9b22be3488ec48278db7511e268c13d0c11a0daf9` |
| SHA3-384 | `bfbb48c3c0812874b529c841956ba371314758118f0f4a83925d9ccf9d2e675862d84d9dce99f64b91f7083337f5965c` |
| TLSH | `T10885F1D3BB77926ED44254B79C10DF2DB1A0E7900A89BEF96220C7722D31B13BD63661` |
| SSDEEP | `24576:cof5SjJmQECnUIO+fl26VPXRHp4KrM2AMDcK05cjR0tFdNuN8H56XipwGPBWgt7s:bfXNUl26l+MIK05U2FdNuN8HOiBWgrC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_643af461
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "643af4611e02c36280cdf4a9b22be3488ec48278db7511e268c13d0c11a0daf9"
    family = "unknown"
    file_name = "macho_643af4611e02.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:30:28"
  condition:
    hash.sha256(0, filesize) == "643af4611e02c36280cdf4a9b22be3488ec48278db7511e268c13d0c11a0daf9"
}
```

### Sample 51: `4e6e1fbdb5313118`

| Field | Value |
|---|---|
| SHA-256 | `4e6e1fbdb531311849fa876c30969d6d0826f29b204daeec7c75f14ad51dbe33` |
| Family label | `SalatStealer` |
| File name | `ddffa002eb19cf53.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:26:26` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b4bdc4e186b4d4b7aedf7a0fe830861` |
| SHA-1 | `16abb402deff2dcc0de3179038363ad8b6eebfd6` |
| SHA-256 | `4e6e1fbdb531311849fa876c30969d6d0826f29b204daeec7c75f14ad51dbe33` |
| SHA3-384 | `e53cf961136265ae6d76980ef1f1d6881da0a5415a76137b4e78bc70551ac99d29db906a6997be2d140b134499a791bb` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T15BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+a:yBkKr5rszpNDy+a` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_051_4e6e1fbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e6e1fbdb531311849fa876c30969d6d0826f29b204daeec7c75f14ad51dbe33"
    family = "SalatStealer"
    file_name = "ddffa002eb19cf53.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:26:26"
  condition:
    hash.sha256(0, filesize) == "4e6e1fbdb531311849fa876c30969d6d0826f29b204daeec7c75f14ad51dbe33"
}
```

### Sample 52: `62907f8dfe5397ea`

| Field | Value |
|---|---|
| SHA-256 | `62907f8dfe5397eab2d8482c80b0544540d71ec95ae9ba3172a80f7dd09c7de9` |
| Family label | `unknown` |
| File name | `macho_62907f8dfe53.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:26:05` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `051cb102e6672d49dbba6fdf51628e8c` |
| SHA-1 | `4bfa26219c9b0d9f1d0b27283b56d9c4f9af0c8a` |
| SHA-256 | `62907f8dfe5397eab2d8482c80b0544540d71ec95ae9ba3172a80f7dd09c7de9` |
| SHA3-384 | `016d5c38f017746add82affe39c1c8d6c05ee2cac229ea7483453cbe184c8bc0b4a5c9245b5260ad3827c4080016910a` |
| TLSH | `T101A5F2905BBA027AFC4524B2EC150F4798B0664C1B4CBAF8923CD3566DB1793B6F3369` |
| SSDEEP | `49152:/uplei0xGO3QMsIKLRf8pLfcwwvUTnBldiMs:Clei0sf8JcwwvgU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_62907f8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62907f8dfe5397eab2d8482c80b0544540d71ec95ae9ba3172a80f7dd09c7de9"
    family = "unknown"
    file_name = "macho_62907f8dfe53.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:26:05"
  condition:
    hash.sha256(0, filesize) == "62907f8dfe5397eab2d8482c80b0544540d71ec95ae9ba3172a80f7dd09c7de9"
}
```

### Sample 53: `49915666d91df2ea`

| Field | Value |
|---|---|
| SHA-256 | `49915666d91df2ea63238c16a9c4479dbb72b7ea7c22f96a2f812de9d60b386c` |
| Family label | `SalatStealer` |
| File name | `88f7d11fe4ed196a.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:26:02` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49ba02745e0b0f41fda73e86f1f18cc3` |
| SHA-1 | `da3c6f66cfe711b72aaa8daa90d0a94a1f393627` |
| SHA-256 | `49915666d91df2ea63238c16a9c4479dbb72b7ea7c22f96a2f812de9d60b386c` |
| SHA3-384 | `28e2315261f278aa6d9125d14084a09c9937ee3a80d74be49488f5f3d6900df8d5bc599fb0865e9675be2c1ec9fc0399` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T125C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+0:yBkKr5rszpNDy+0` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_053_49915666
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49915666d91df2ea63238c16a9c4479dbb72b7ea7c22f96a2f812de9d60b386c"
    family = "SalatStealer"
    file_name = "88f7d11fe4ed196a.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:26:02"
  condition:
    hash.sha256(0, filesize) == "49915666d91df2ea63238c16a9c4479dbb72b7ea7c22f96a2f812de9d60b386c"
}
```

### Sample 54: `b8be9c98d82ebb62`

| Field | Value |
|---|---|
| SHA-256 | `b8be9c98d82ebb62ce09ec43940c07232dd11e6b3240064952848682c986edfa` |
| Family label | `SalatStealer` |
| File name | `97b0f79f66bf4656.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:25:54` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7241871dc52d46a9f6bc04a87552aa2e` |
| SHA-1 | `1feee136bea09c34299b7655c1f5407844481226` |
| SHA-256 | `b8be9c98d82ebb62ce09ec43940c07232dd11e6b3240064952848682c986edfa` |
| SHA3-384 | `e91963335297892a6d40b92036fbbd745af426c6e1de9fd072c689cbdff0c363ebc332c3b6961b5d92f1b9048fada495` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T161C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+i:yBkKr5rszpNDy+i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_054_b8be9c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8be9c98d82ebb62ce09ec43940c07232dd11e6b3240064952848682c986edfa"
    family = "SalatStealer"
    file_name = "97b0f79f66bf4656.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:25:54"
  condition:
    hash.sha256(0, filesize) == "b8be9c98d82ebb62ce09ec43940c07232dd11e6b3240064952848682c986edfa"
}
```

### Sample 55: `021e04edfe50d017`

| Field | Value |
|---|---|
| SHA-256 | `021e04edfe50d0172ec0a56fcb7ef854b26e7f7deb574f24c6e9e660cdbbd70a` |
| Family label | `SalatStealer` |
| File name | `d792764640539de0.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:25:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56425359a822511e12878240b13851f7` |
| SHA-1 | `08a4a85d84ace3075d03dfb5ff175958f1a9d7af` |
| SHA-256 | `021e04edfe50d0172ec0a56fcb7ef854b26e7f7deb574f24c6e9e660cdbbd70a` |
| SHA3-384 | `62496fc8b535fe598a308cdf789ffeddca6d713f0ab4153f2c322edb6c2a26cc2785d5cf74d7872faf74fc3883888c08` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T102C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+B:yBkKr5rszpNDy+B` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_055_021e04ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021e04edfe50d0172ec0a56fcb7ef854b26e7f7deb574f24c6e9e660cdbbd70a"
    family = "SalatStealer"
    file_name = "d792764640539de0.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:25:46"
  condition:
    hash.sha256(0, filesize) == "021e04edfe50d0172ec0a56fcb7ef854b26e7f7deb574f24c6e9e660cdbbd70a"
}
```

### Sample 56: `61bd412ff863ecfb`

| Field | Value |
|---|---|
| SHA-256 | `61bd412ff863ecfb8b1e558ee3356cc3fd72d0579dbdb4f30d322f0c40950499` |
| Family label | `SalatStealer` |
| File name | `5de3d9b327b1eca2.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:25:39` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74c2603a5b6764fc6273e52861f9e731` |
| SHA-1 | `7b3b3d78ab0195083e47aadaf868fbf597c127fb` |
| SHA-256 | `61bd412ff863ecfb8b1e558ee3356cc3fd72d0579dbdb4f30d322f0c40950499` |
| SHA3-384 | `b2811c2ac70c4d68832c45fc163a69f9765fc46f423fee9953542367dec755e2b2cca9f83e1b1308aa100cfde9aebb7a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T115C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+i:yBkKr5rszpNDy+i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_056_61bd412f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61bd412ff863ecfb8b1e558ee3356cc3fd72d0579dbdb4f30d322f0c40950499"
    family = "SalatStealer"
    file_name = "5de3d9b327b1eca2.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:25:39"
  condition:
    hash.sha256(0, filesize) == "61bd412ff863ecfb8b1e558ee3356cc3fd72d0579dbdb4f30d322f0c40950499"
}
```

### Sample 57: `ddffa002eb19cf53`

| Field | Value |
|---|---|
| SHA-256 | `ddffa002eb19cf535b4d7577d59207fbfd7cc04a693fd55fc9b9869324cd3d6f` |
| Family label | `SalatStealer` |
| File name | `ddffa002eb19cf53.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:25:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a61c8d62357c9dff6769a0d2ffec029` |
| SHA-1 | `c5c7ac91dad79ad0d8691c58711d1da9c85b1839` |
| SHA-256 | `ddffa002eb19cf535b4d7577d59207fbfd7cc04a693fd55fc9b9869324cd3d6f` |
| SHA3-384 | `73db77aee79de4cfc10dfcd3181f8cf7c244d36ea7c3fa035d589dce480366984c2e382ad49575df77284b9c3dad052c` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T160F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O2:iJiafuIO7rhWEES4N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_057_ddffa002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddffa002eb19cf535b4d7577d59207fbfd7cc04a693fd55fc9b9869324cd3d6f"
    family = "SalatStealer"
    file_name = "ddffa002eb19cf53.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:25:04"
  condition:
    hash.sha256(0, filesize) == "ddffa002eb19cf535b4d7577d59207fbfd7cc04a693fd55fc9b9869324cd3d6f"
}
```

### Sample 58: `88f7d11fe4ed196a`

| Field | Value |
|---|---|
| SHA-256 | `88f7d11fe4ed196af8931d065dcf91c71fda385fc1aec33f114a25c3b98990bf` |
| Family label | `SalatStealer` |
| File name | `88f7d11fe4ed196a.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:55` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1aed5f3a9a150c7ed30463af24ee4e5` |
| SHA-1 | `9c59d2e75912500bd177d3026cdf8ce4c05cf4f9` |
| SHA-256 | `88f7d11fe4ed196af8931d065dcf91c71fda385fc1aec33f114a25c3b98990bf` |
| SHA3-384 | `2ffaad02ec30b741ee108524c5195a65ddbe97c2e7c95aef4a7ff281bbc5ea420d26684390feeb08bfc3fd3e6265516e` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T110F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O4:iJiafuIO7rhWEES45` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_058_88f7d11f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88f7d11fe4ed196af8931d065dcf91c71fda385fc1aec33f114a25c3b98990bf"
    family = "SalatStealer"
    file_name = "88f7d11fe4ed196a.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:55"
  condition:
    hash.sha256(0, filesize) == "88f7d11fe4ed196af8931d065dcf91c71fda385fc1aec33f114a25c3b98990bf"
}
```

### Sample 59: `97b0f79f66bf4656`

| Field | Value |
|---|---|
| SHA-256 | `97b0f79f66bf46568ee6aa0ccaa24d95c46e6fa2fa7bdff2282b428fe96b7f32` |
| Family label | `SalatStealer` |
| File name | `97b0f79f66bf4656.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1370e55e2429d8f2b1dbc565da30dd2` |
| SHA-1 | `557282ea2ed5606de9aea0bd4ad70c3b695fa163` |
| SHA-256 | `97b0f79f66bf46568ee6aa0ccaa24d95c46e6fa2fa7bdff2282b428fe96b7f32` |
| SHA3-384 | `c632e35d50285bdcccb4b65badc36c582056bb808db05bd52df4723ad40681a902c4ca503680d7c66dba87f4732cc365` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T150F5335BF1AF47B3F7D9A931561FC66458B09FE40A20D38AD4DBAA9F0882BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OW:iJiafuIO7rhWEES4f` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_059_97b0f79f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b0f79f66bf46568ee6aa0ccaa24d95c46e6fa2fa7bdff2282b428fe96b7f32"
    family = "SalatStealer"
    file_name = "97b0f79f66bf4656.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:45"
  condition:
    hash.sha256(0, filesize) == "97b0f79f66bf46568ee6aa0ccaa24d95c46e6fa2fa7bdff2282b428fe96b7f32"
}
```

### Sample 60: `5fd4f7d292f67c21`

| Field | Value |
|---|---|
| SHA-256 | `5fd4f7d292f67c2117c18d580ee3f4b261599866a9c5251bc86055ab5d96518d` |
| Family label | `SalatStealer` |
| File name | `1550c0399429bebc.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:40` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3db6f95e6f3e9c70a157e3a71db6630` |
| SHA-1 | `188919b7cca1043ed9e03a583e66ade2f2b9411c` |
| SHA-256 | `5fd4f7d292f67c2117c18d580ee3f4b261599866a9c5251bc86055ab5d96518d` |
| SHA3-384 | `328f64a9f8dcbfe3bb6bdc48f58dfa4cd8e86fc5a001779e81b0c28ccf086498a84abb3b96a814847979cbebfa4ebc2d` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T19BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+s:yBkKr5rszpNDy+s` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_060_5fd4f7d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fd4f7d292f67c2117c18d580ee3f4b261599866a9c5251bc86055ab5d96518d"
    family = "SalatStealer"
    file_name = "1550c0399429bebc.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:40"
  condition:
    hash.sha256(0, filesize) == "5fd4f7d292f67c2117c18d580ee3f4b261599866a9c5251bc86055ab5d96518d"
}
```

### Sample 61: `d792764640539de0`

| Field | Value |
|---|---|
| SHA-256 | `d792764640539de0230ecd8213d9d5217ab43835943a8724e738eac0d96545e0` |
| Family label | `SalatStealer` |
| File name | `d792764640539de0.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d3ba27a8c68be5e0e9c889891e68b23` |
| SHA-1 | `0c37672fc80006af2bad5e6700d3f0ad08bf7364` |
| SHA-256 | `d792764640539de0230ecd8213d9d5217ab43835943a8724e738eac0d96545e0` |
| SHA3-384 | `581467f997b2e3b4771467419d277335dc3fb981b23d7e79bb858429d019278e76f8c241fd19db5079fd9d8a16e25841` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C9F5335BF5AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAADF0882BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O1:iJiafuIO7rhWEES4O` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_061_d7927646
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d792764640539de0230ecd8213d9d5217ab43835943a8724e738eac0d96545e0"
    family = "SalatStealer"
    file_name = "d792764640539de0.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:36"
  condition:
    hash.sha256(0, filesize) == "d792764640539de0230ecd8213d9d5217ab43835943a8724e738eac0d96545e0"
}
```

### Sample 62: `cd7bdbae081d8d4a`

| Field | Value |
|---|---|
| SHA-256 | `cd7bdbae081d8d4a55040d552691be6268c485fb4cdeb17515aec47bbcc8d594` |
| Family label | `SalatStealer` |
| File name | `364e0135bcf58580.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7574be70fbc60220248a3a194897100` |
| SHA-1 | `6293c2f714de6291d559ea596d43d53185243338` |
| SHA-256 | `cd7bdbae081d8d4a55040d552691be6268c485fb4cdeb17515aec47bbcc8d594` |
| SHA3-384 | `75274940ea990c9ec84697c21c1b10716c3d8701f02d2aa8e5817031282884ee1a5e71fd79747e6fca375260c3f9dbea` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T19FC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+J:yBkKr5rszpNDy+J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_062_cd7bdbae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd7bdbae081d8d4a55040d552691be6268c485fb4cdeb17515aec47bbcc8d594"
    family = "SalatStealer"
    file_name = "364e0135bcf58580.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:35"
  condition:
    hash.sha256(0, filesize) == "cd7bdbae081d8d4a55040d552691be6268c485fb4cdeb17515aec47bbcc8d594"
}
```

### Sample 63: `a951460a2d6a72d8`

| Field | Value |
|---|---|
| SHA-256 | `a951460a2d6a72d878844d65d60e62e1c4fd46a97bea1cabe6d35445664b8475` |
| Family label | `SalatStealer` |
| File name | `b8f71b5f6656298e.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0afc98e9edc20da3b61e3bd00af09a93` |
| SHA-1 | `ed4cc3d53d081af1e33d8a075270cfa11ff84472` |
| SHA-256 | `a951460a2d6a72d878844d65d60e62e1c4fd46a97bea1cabe6d35445664b8475` |
| SHA3-384 | `25ce94bc805b5608749964404bedec62d3e24f898838eadc032492744e29fedb42ebffb423b447aa8ea6828bb62a03ba` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T15AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+1:yBkKr5rszpNDy+1` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_063_a951460a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a951460a2d6a72d878844d65d60e62e1c4fd46a97bea1cabe6d35445664b8475"
    family = "SalatStealer"
    file_name = "b8f71b5f6656298e.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:28"
  condition:
    hash.sha256(0, filesize) == "a951460a2d6a72d878844d65d60e62e1c4fd46a97bea1cabe6d35445664b8475"
}
```

### Sample 64: `5de3d9b327b1eca2`

| Field | Value |
|---|---|
| SHA-256 | `5de3d9b327b1eca29867ab4a0d5c59302858302cf9091604658b9fc4995c5667` |
| Family label | `SalatStealer` |
| File name | `5de3d9b327b1eca2.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82d156e457509534e07709b9657e728f` |
| SHA-1 | `456b2d0733ed72b5b5f40b2630c3a90ca62c997b` |
| SHA-256 | `5de3d9b327b1eca29867ab4a0d5c59302858302cf9091604658b9fc4995c5667` |
| SHA3-384 | `2b0e8d3702fcfde7a0c5f3e50dce11cb4d85adfeb280f5939790910c4d92a23a2f6778099882fca0b9663cf94636d416` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1CBF5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Om:iJiafuIO7rhWEES4N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_064_5de3d9b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5de3d9b327b1eca29867ab4a0d5c59302858302cf9091604658b9fc4995c5667"
    family = "SalatStealer"
    file_name = "5de3d9b327b1eca2.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:26"
  condition:
    hash.sha256(0, filesize) == "5de3d9b327b1eca29867ab4a0d5c59302858302cf9091604658b9fc4995c5667"
}
```

### Sample 65: `1550c0399429bebc`

| Field | Value |
|---|---|
| SHA-256 | `1550c0399429bebc3aadb96a0de2f0550079434ffd643a7a76a47b9e47c9b4dd` |
| Family label | `SalatStealer` |
| File name | `1550c0399429bebc.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73bbca56929bb0abe34e8649ec19e679` |
| SHA-1 | `737e781f5390612600d3047869e758dbbc194bab` |
| SHA-256 | `1550c0399429bebc3aadb96a0de2f0550079434ffd643a7a76a47b9e47c9b4dd` |
| SHA3-384 | `816c09afe2ca1d04d5b8fbaa9e396a2f81dbe3f3b01bcbbf97b71c8c42dc2c580e3472a9f546e04814b56c09faf545e7` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T148F5335BF1AF47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O4:iJiafuIO7rhWEES4J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_065_1550c039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1550c0399429bebc3aadb96a0de2f0550079434ffd643a7a76a47b9e47c9b4dd"
    family = "SalatStealer"
    file_name = "1550c0399429bebc.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:17"
  condition:
    hash.sha256(0, filesize) == "1550c0399429bebc3aadb96a0de2f0550079434ffd643a7a76a47b9e47c9b4dd"
}
```

### Sample 66: `364e0135bcf58580`

| Field | Value |
|---|---|
| SHA-256 | `364e0135bcf585807f10fbe0e29cbd1df7586d90bf2bb3a512fdc005b0b59669` |
| Family label | `SalatStealer` |
| File name | `364e0135bcf58580.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:24:07` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c399e13077762792dad7e31c545d9e7` |
| SHA-1 | `c7b7d201c1997b9adc9653339d00609c21a06618` |
| SHA-256 | `364e0135bcf585807f10fbe0e29cbd1df7586d90bf2bb3a512fdc005b0b59669` |
| SHA3-384 | `e6c9bb3278763ac33d49c3b18c1ba8d2a834e9acfbfc9220b2c8ce5bd9cf86516b2ef03b1dd85da91ce7c8fa15bad6be` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T153F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ot:iJiafuIO7rhWEES4Q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_066_364e0135
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "364e0135bcf585807f10fbe0e29cbd1df7586d90bf2bb3a512fdc005b0b59669"
    family = "SalatStealer"
    file_name = "364e0135bcf58580.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:07"
  condition:
    hash.sha256(0, filesize) == "364e0135bcf585807f10fbe0e29cbd1df7586d90bf2bb3a512fdc005b0b59669"
}
```

### Sample 67: `b8f71b5f6656298e`

| Field | Value |
|---|---|
| SHA-256 | `b8f71b5f6656298e95013e75b955b9b49f0f236f30558aedb20f2f62aeddd782` |
| Family label | `SalatStealer` |
| File name | `b8f71b5f6656298e.bin` |
| File type | `exe` |
| First seen | `2026-10-29 01:23:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48d4cf73804b842f2ba1c3590393d00d` |
| SHA-1 | `a16ae4b97df5000e0b40294d9a928da40707c7ac` |
| SHA-256 | `b8f71b5f6656298e95013e75b955b9b49f0f236f30558aedb20f2f62aeddd782` |
| SHA3-384 | `b9ff1b1f90a2747756f1aa5a66f003ee1d54b7c1ce6aa10e78dcf397420971351802a44f2c364730b7cc6a9a098c9cf2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12AF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OR:iJiafuIO7rhWEES4G` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_067_b8f71b5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8f71b5f6656298e95013e75b955b9b49f0f236f30558aedb20f2f62aeddd782"
    family = "SalatStealer"
    file_name = "b8f71b5f6656298e.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:23:58"
  condition:
    hash.sha256(0, filesize) == "b8f71b5f6656298e95013e75b955b9b49f0f236f30558aedb20f2f62aeddd782"
}
```

### Sample 68: `e2fcffd2ce53fe38`

| Field | Value |
|---|---|
| SHA-256 | `e2fcffd2ce53fe38b555db86e14e96b706eb811367dba4725f96a248c667b9a8` |
| Family label | `unknown` |
| File name | `macho_e2fcffd2ce53.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:21:25` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00ac42e0d1a1899e69df7b62c0d4a856` |
| SHA-1 | `af0c6f98c39c7035591862fb64ec176a8198c8c3` |
| SHA-256 | `e2fcffd2ce53fe38b555db86e14e96b706eb811367dba4725f96a248c667b9a8` |
| SHA3-384 | `fc5f8efc88f3e39c853d76f7dfcfbae723f07b09783e20568061dbde24a588f9bb7a39c4dd1f8960117dd5997bea5705` |
| TLSH | `T10E75F1337E29125BE4852073E9158F870690A3E26B48B0F5B31586F7ED396D3B5A7323` |
| SSDEEP | `24576:sIM7kNpt6gHgM7BNQmWaW/U5GWA+M+pkCWR93goMQUhSW:nVLYgV8mNX5G7+goonpW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_e2fcffd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2fcffd2ce53fe38b555db86e14e96b706eb811367dba4725f96a248c667b9a8"
    family = "unknown"
    file_name = "macho_e2fcffd2ce53.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:21:25"
  condition:
    hash.sha256(0, filesize) == "e2fcffd2ce53fe38b555db86e14e96b706eb811367dba4725f96a248c667b9a8"
}
```

### Sample 69: `3d5df13b6db8ed55`

| Field | Value |
|---|---|
| SHA-256 | `3d5df13b6db8ed554e44c64db65a9797c5b6f220e34efa6e7b3904d8abb41d67` |
| Family label | `Mirai` |
| File name | `arm8` |
| File type | `elf` |
| First seen | `2026-10-29 01:17:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `286bacb8865d93552dd00c379a2d0b1e` |
| SHA-1 | `3c50ae45726ef1398fad0a309adba4b14a9872c7` |
| SHA-256 | `3d5df13b6db8ed554e44c64db65a9797c5b6f220e34efa6e7b3904d8abb41d67` |
| SHA3-384 | `63883ef72c2f24f0faa8f3f935d953a229f06d768f4ad62dff32ecbd72de38e908b6d3ca4e58901bf1d3d3a995da1192` |
| TLSH | `T13E744B8C92F6FBCEE298EA759315BD1668372636309371E6700EA66703FB18445F9D30` |
| SSDEEP | `6144:gdw+kW2RA2/TwWLzhLoGw0qq6KVa9WTP:1+kW2RA2/0WLtoJua9Wb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_3d5df13b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5df13b6db8ed554e44c64db65a9797c5b6f220e34efa6e7b3904d8abb41d67"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-10-29 01:17:43"
  condition:
    hash.sha256(0, filesize) == "3d5df13b6db8ed554e44c64db65a9797c5b6f220e34efa6e7b3904d8abb41d67"
}
```

### Sample 70: `87367d9c60bb5923`

| Field | Value |
|---|---|
| SHA-256 | `87367d9c60bb5923526138d10340a60d13d150f3280bba966d0ef8a335893635` |
| Family label | `unknown` |
| File name | `macho_87367d9c60bb.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:16:41` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `babc4eb49a070dda66ba9fd06cbc8b48` |
| SHA-1 | `9f7098040c3cc2980c3e95bcb09837f1dd2a578c` |
| SHA-256 | `87367d9c60bb5923526138d10340a60d13d150f3280bba966d0ef8a335893635` |
| SHA3-384 | `17a4f062bde32b0c0644e73c24e125b5de0142cb983e0e57064199c85f0cb80a0b6d3f4367403f332fee8d6291638d4d` |
| TLSH | `T1F785F150966752ADD84326F3DC100FE568D8678407486EF96231EB663E31F93BFA72B0` |
| SSDEEP | `24576:1n5ZbQEnro7r/vka1j8UetvCcgiJqR7CDCxuV6UV3tLSlIDjy0CBbu+R:JJEjJ8OiJfGIV6+3t9fy7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_87367d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87367d9c60bb5923526138d10340a60d13d150f3280bba966d0ef8a335893635"
    family = "unknown"
    file_name = "macho_87367d9c60bb.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:16:41"
  condition:
    hash.sha256(0, filesize) == "87367d9c60bb5923526138d10340a60d13d150f3280bba966d0ef8a335893635"
}
```

### Sample 71: `6335a4427566446e`

| Field | Value |
|---|---|
| SHA-256 | `6335a4427566446e65202fb47dac5bac3433308c5daabf2293afb3c795f5353c` |
| Family label | `unknown` |
| File name | `macho_6335a4427566.bin` |
| File type | `macho` |
| First seen | `2026-10-29 01:12:25` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd0e2015a61c38d89ad4f807a8ac4aa5` |
| SHA-1 | `c9ed03fc6d7f1215bb14ed30e14017ebc354308c` |
| SHA-256 | `6335a4427566446e65202fb47dac5bac3433308c5daabf2293afb3c795f5353c` |
| SHA3-384 | `8ef873440da603a1960397a9862be0389adf0753ea76c4eeeb162b16161697a46dbde73c45beb6a60ba70f5ee4c8ac33` |
| TLSH | `T19695F120117A2066EE423431E9140FF955D4A6B32A4EBAF76F12EB612D356C3E763373` |
| SSDEEP | `24576:qs/hjFbcoLkMGx2Kk23CemuYKzy6wKD3RLM5hCoOZhcvhpbNq5SNRNWGWY8wzyKy:quI4okHxHYZuZpc5S3N4pb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_6335a442
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6335a4427566446e65202fb47dac5bac3433308c5daabf2293afb3c795f5353c"
    family = "unknown"
    file_name = "macho_6335a4427566.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:12:25"
  condition:
    hash.sha256(0, filesize) == "6335a4427566446e65202fb47dac5bac3433308c5daabf2293afb3c795f5353c"
}
```

### Sample 72: `daf0623ef19b3618`

| Field | Value |
|---|---|
| SHA-256 | `daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322` |
| Family label | `unknown` |
| File name | `daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322.exe` |
| File type | `exe` |
| First seen | `2026-10-29 01:09:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f3c46f58ca0e40ab117991617abfe21` |
| SHA-1 | `18fd4b03b7093bc319f6636635022c32298d69c5` |
| SHA-256 | `daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322` |
| SHA3-384 | `649a0fd1e3aa7a78096750b331e89ed2c5b7fb0f043f75c81d30de92419fc11493979fad31925e5e2598d8b1b452b657` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T18A466C477F9154F8C09AEA30C9A64252B774BC8C473123EB1E60BB782E767C1A979F44` |
| SSDEEP | `49152:3ZN1bKe9sLVncB3jqUaLXKDAq1M7cTGGPMuUGTbQaECRq7u+T:p/FeWhX11M75GTJz2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_daf0623e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322"
    family = "unknown"
    file_name = "daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:09:26"
  condition:
    hash.sha256(0, filesize) == "daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322"
}
```

### Sample 73: `b1a84cfd4176a472`

| Field | Value |
|---|---|
| SHA-256 | `b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9` |
| Family label | `unknown` |
| File name | `loader.sh` |
| File type | `sh` |
| First seen | `2026-10-29 01:01:05` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef38b770bef2edfe47529229264fde1e` |
| SHA-1 | `57e64e12b878922a9f8b30ab28e89fc012b25dce` |
| SHA-256 | `b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9` |
| SHA3-384 | `c608ad6e9dbab3715656e7cbfda3cbdd7603e504c67dafec67d564ae3b7fc7dfbaa0226cb70222a788ad5d29bc838890` |
| TLSH | `T17C41BDCA7AA3D97197C7C4391FDAE101E35624430995A998B09EBC303F6D120FCB1E57` |
| SSDEEP | `48:8VdxxzGG1eCFeZdzVKN5Q1f/neHuDmmlBFInKIYgQAul4N7vGxQ:2dnIu2mQlGaL2nKI3QaTGC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_b1a84cfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9"
    family = "unknown"
    file_name = "loader.sh"
    file_type = "sh"
    first_seen = "2026-10-29 01:01:05"
  condition:
    hash.sha256(0, filesize) == "b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9"
}
```

### Sample 74: `3fb119de79ee89ec`

| Field | Value |
|---|---|
| SHA-256 | `3fb119de79ee89ec7e969e140fc53cd5de471e9891b67cbcbc8c9989bafb937a` |
| Family label | `SalatStealer` |
| File name | `2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648.exe` |
| File type | `exe` |
| First seen | `2026-10-29 01:00:52` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f661192bf3fa4c6a0c8071dca3747344` |
| SHA-1 | `62fcbd3fa5b5187d3e5b8da8290fab96ea231ad7` |
| SHA-256 | `3fb119de79ee89ec7e969e140fc53cd5de471e9891b67cbcbc8c9989bafb937a` |
| SHA3-384 | `94de1f48dd963dba0d390c57a4c3880f0274b4c3f7c89077e5277041a823a14d1d2c4ba28b7aa79f62ae13acd2234089` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F7C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Y:yBkKr5rszpNDy+Y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_074_3fb119de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb119de79ee89ec7e969e140fc53cd5de471e9891b67cbcbc8c9989bafb937a"
    family = "SalatStealer"
    file_name = "2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:00:52"
  condition:
    hash.sha256(0, filesize) == "3fb119de79ee89ec7e969e140fc53cd5de471e9891b67cbcbc8c9989bafb937a"
}
```

### Sample 75: `2ed145530149d789`

| Field | Value |
|---|---|
| SHA-256 | `2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648` |
| Family label | `SalatStealer` |
| File name | `2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648.exe` |
| File type | `exe` |
| First seen | `2026-10-29 01:00:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ec1a2d57f539f24a9be140276d427b6` |
| SHA-1 | `de4f8d9e8a6c4af627f8a42e5b28ca7bcfb32f31` |
| SHA-256 | `2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648` |
| SHA3-384 | `e2186344325e1844b4d4e3a96d622bd893a634cd8a90eea771cfcff61997b3922433683b8d42c19a236763906ff7f171` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T155F5335BF1AF47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OU:iJiafuIO7rhWEES4X` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_075_2ed14553
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648"
    family = "SalatStealer"
    file_name = "2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:00:18"
  condition:
    hash.sha256(0, filesize) == "2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648"
}
```

### Sample 76: `d36b6e6c034d47ac`

| Field | Value |
|---|---|
| SHA-256 | `d36b6e6c034d47ac22edb3c897b88d4f0682d79dcdb50d5821df009f7ac3ca4c` |
| Family label | `SalatStealer` |
| File name | `a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:54:41` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d911dea5a987442083ad9d1d09fb6eb` |
| SHA-1 | `3509b28021bb2d0e30a789f0be50346699a496c8` |
| SHA-256 | `d36b6e6c034d47ac22edb3c897b88d4f0682d79dcdb50d5821df009f7ac3ca4c` |
| SHA3-384 | `574da673cdcecce090f575f0ed134cbd77a165c1753aa363dad4c158c8d3590e1112d75c40ef9819b4b30db306a76784` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+A:yBkKr5rszpNDy+A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_076_d36b6e6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d36b6e6c034d47ac22edb3c897b88d4f0682d79dcdb50d5821df009f7ac3ca4c"
    family = "SalatStealer"
    file_name = "a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:54:41"
  condition:
    hash.sha256(0, filesize) == "d36b6e6c034d47ac22edb3c897b88d4f0682d79dcdb50d5821df009f7ac3ca4c"
}
```

### Sample 77: `a7c01cfc75676d08`

| Field | Value |
|---|---|
| SHA-256 | `a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf` |
| Family label | `SalatStealer` |
| File name | `a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:53:59` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b46c87e33af46b7918eb1d0a23838d4a` |
| SHA-1 | `eac02f193141611c453a9199fe1d925c0b3c7b2a` |
| SHA-256 | `a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf` |
| SHA3-384 | `ac63c2a498bb5f7eb20641e41277fab92331e3daf7d55c25c568fd7b8ba60a9918e0fee6dfb3b26718c4ddf14f690b43` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T191F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OU:iJiafuIO7rhWEES45` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_077_a7c01cfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf"
    family = "SalatStealer"
    file_name = "a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:53:59"
  condition:
    hash.sha256(0, filesize) == "a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf"
}
```

### Sample 78: `1e90ed1645b77c24`

| Field | Value |
|---|---|
| SHA-256 | `1e90ed1645b77c242a241a55dc68a995a621c6d243b29a506d44940848b06f75` |
| Family label | `SalatStealer` |
| File name | `ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:53:36` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36c6b5a511be0c5234cd087b547fc515` |
| SHA-1 | `878a801f62d74c75b5b5562cce4ac662066f2660` |
| SHA-256 | `1e90ed1645b77c242a241a55dc68a995a621c6d243b29a506d44940848b06f75` |
| SHA3-384 | `f6f713d0ad6be4198652d1ac32cef185fa1201598be38a4ce56ab64e039560a8a4fbf763563351851b5e2bb51fa66a32` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T11DC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_078_1e90ed16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e90ed1645b77c242a241a55dc68a995a621c6d243b29a506d44940848b06f75"
    family = "SalatStealer"
    file_name = "ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:53:36"
  condition:
    hash.sha256(0, filesize) == "1e90ed1645b77c242a241a55dc68a995a621c6d243b29a506d44940848b06f75"
}
```

### Sample 79: `3e983375c722a742`

| Field | Value |
|---|---|
| SHA-256 | `3e983375c722a7420a1106f060f2a2ea467c9b76803e285555b2ff6be172598c` |
| Family label | `SalatStealer` |
| File name | `d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:53:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `310b895793ae98a6b34be3311926c010` |
| SHA-1 | `e1465ce8473a4ecc65e8874bf7d079f89dafe1de` |
| SHA-256 | `3e983375c722a7420a1106f060f2a2ea467c9b76803e285555b2ff6be172598c` |
| SHA3-384 | `6a3408fed1f279c42a7279a996c17e8aeb0e275dcdc6cf64264b703820ae878934e85f0d4c6eb263e4a91fd21444ebfa` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1DBC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_079_3e983375
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e983375c722a7420a1106f060f2a2ea467c9b76803e285555b2ff6be172598c"
    family = "SalatStealer"
    file_name = "d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:53:25"
  condition:
    hash.sha256(0, filesize) == "3e983375c722a7420a1106f060f2a2ea467c9b76803e285555b2ff6be172598c"
}
```

### Sample 80: `ccb54c893ebd9a38`

| Field | Value |
|---|---|
| SHA-256 | `ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7` |
| Family label | `unknown` |
| File name | `ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7` |
| File type | `elf` |
| First seen | `2026-10-29 00:53:22` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `971993521767f193365bfa25c66e9d5b` |
| SHA-1 | `c89c1e9de4eb9b560a5d4f46e186e44d23eb886c` |
| SHA-256 | `ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7` |
| SHA3-384 | `50bc6084bb24ef8a673936e4423aa2fe07659a98ed24a7ea1834e144978bdb5c6138ab21c7e5d1d679a4f9c3ce9cb655` |
| TLSH | `T1D414392BF98184BDC0E5E1708BEFA127F521F99982343A2F27D41F411E29F12A75EB51` |
| SSDEEP | `3072:i82SfUvjjFknboK02OOPi3klLcOSTDbrpzUMLrfXCMdZgFaLQIgp4U5Kl6JLcNTo:MqUFub42OSuLvpQMnXdgt5J+o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_ccb54c89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7"
    family = "unknown"
    file_name = "ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7"
    file_type = "elf"
    first_seen = "2026-10-29 00:53:22"
  condition:
    hash.sha256(0, filesize) == "ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7"
}
```

### Sample 81: `dd8a80b797340dc5`

| Field | Value |
|---|---|
| SHA-256 | `dd8a80b797340dc5a59fb28e84d1c66991b4c9a93476bf1135ebaf72a08c2b7c` |
| Family label | `SalatStealer` |
| File name | `de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:53:00` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1768d00b58c25910371bd3e514218177` |
| SHA-1 | `010220f1b61ff7d8eb5f7c88aa268f1f7d0bd308` |
| SHA-256 | `dd8a80b797340dc5a59fb28e84d1c66991b4c9a93476bf1135ebaf72a08c2b7c` |
| SHA3-384 | `87c609ad030e5cd74681b03063317059595d9eb92637cfa5ff0be8e637a0b429564c9602c85e162b846bc02a9959597d` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T169C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+n:yBkKr5rszpNDy+n` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_081_dd8a80b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd8a80b797340dc5a59fb28e84d1c66991b4c9a93476bf1135ebaf72a08c2b7c"
    family = "SalatStealer"
    file_name = "de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:53:00"
  condition:
    hash.sha256(0, filesize) == "dd8a80b797340dc5a59fb28e84d1c66991b4c9a93476bf1135ebaf72a08c2b7c"
}
```

### Sample 82: `2246c9fe18c02eae`

| Field | Value |
|---|---|
| SHA-256 | `2246c9fe18c02eaebf758f7e380a7afb0e937d7ce346cfbd84590e519162f048` |
| Family label | `unknown` |
| File name | `8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:52:54` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b0ed6bf964c85b0c08ae655ffe29143` |
| SHA-1 | `f34bbfd889e5bbe90681cc5b39c8acec4c26d17c` |
| SHA-256 | `2246c9fe18c02eaebf758f7e380a7afb0e937d7ce346cfbd84590e519162f048` |
| SHA3-384 | `855fe50b0795959050cf01a13f52a421ccad5239f9f4887424e2ec19f6c1e54b83027c7132fc2876da6bbd66f6407212` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1BA7739A3F8A20DE4C4ACE539C16294523B71BC59473053D7BA99F7606F3ABD06E7A304` |
| SSDEEP | `196608:ULZSeA4QohsMDQtdLcIucT1lh8a+fVZVQW/b/DzZAH1q:cS+hNDQtdY8T/Z+dxbZx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_2246c9fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2246c9fe18c02eaebf758f7e380a7afb0e937d7ce346cfbd84590e519162f048"
    family = "unknown"
    file_name = "8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:52:54"
  condition:
    hash.sha256(0, filesize) == "2246c9fe18c02eaebf758f7e380a7afb0e937d7ce346cfbd84590e519162f048"
}
```

### Sample 83: `361b25f06372ce08`

| Field | Value |
|---|---|
| SHA-256 | `361b25f06372ce089a4c642d456ed79a3cff63be95a7284fa1f4c02179814539` |
| Family label | `SalatStealer` |
| File name | `2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:52:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c718d494cc95ffd5a3777401b366f7e8` |
| SHA-1 | `00d323dbef92f11a94a71350ebd1b92e4fd3c8b6` |
| SHA-256 | `361b25f06372ce089a4c642d456ed79a3cff63be95a7284fa1f4c02179814539` |
| SHA3-384 | `1c35a1f51bbd48ee0fc88b2250ef538c74301e949b519a8c261664e091b980b26e3635835665c2bfb79664d196ca25bb` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T104C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE++:yBkKr5rszpNDy++` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_083_361b25f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "361b25f06372ce089a4c642d456ed79a3cff63be95a7284fa1f4c02179814539"
    family = "SalatStealer"
    file_name = "2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:52:46"
  condition:
    hash.sha256(0, filesize) == "361b25f06372ce089a4c642d456ed79a3cff63be95a7284fa1f4c02179814539"
}
```

### Sample 84: `ae23ef8293a5ce43`

| Field | Value |
|---|---|
| SHA-256 | `ae23ef8293a5ce4389568b0d01f2ddd221257a5f7ac2bbc74afab2f22ddc1f57` |
| Family label | `SalatStealer` |
| File name | `9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:52:37` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86d5ec6c58d8846129d9f361a01deff9` |
| SHA-1 | `573c8f12fe5189b36637fc556beb988add1ec47b` |
| SHA-256 | `ae23ef8293a5ce4389568b0d01f2ddd221257a5f7ac2bbc74afab2f22ddc1f57` |
| SHA3-384 | `a1ec34d7e289fd0dad4a01b096a8552fc6ab10aa2e8cb65a01d68f1b1ebf8428e8f87f6b33bdd34dc88c7fc2cc54dc8b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F0C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE++:yBkKr5rszpNDy++` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_084_ae23ef82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae23ef8293a5ce4389568b0d01f2ddd221257a5f7ac2bbc74afab2f22ddc1f57"
    family = "SalatStealer"
    file_name = "9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:52:37"
  condition:
    hash.sha256(0, filesize) == "ae23ef8293a5ce4389568b0d01f2ddd221257a5f7ac2bbc74afab2f22ddc1f57"
}
```

### Sample 85: `5407d15d2a837159`

| Field | Value |
|---|---|
| SHA-256 | `5407d15d2a8371590d72d90e363a70875ef25c9783a36b2a000dc9e298384a33` |
| Family label | `SalatStealer` |
| File name | `12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:51:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ad1031f1b7a600fee4278b2aaa10234` |
| SHA-1 | `8a28885f9a685c28f8dd6c33c5e122320abe32ec` |
| SHA-256 | `5407d15d2a8371590d72d90e363a70875ef25c9783a36b2a000dc9e298384a33` |
| SHA3-384 | `f2d73ba998c8a955d2a2497bb71e3937d2bc9e4712d5b02acb5b4e46b9c3026d73508edb426fe0afb23cb36f169590a1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E9C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+m:yBkKr5rszpNDy+m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_085_5407d15d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5407d15d2a8371590d72d90e363a70875ef25c9783a36b2a000dc9e298384a33"
    family = "SalatStealer"
    file_name = "12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:38"
  condition:
    hash.sha256(0, filesize) == "5407d15d2a8371590d72d90e363a70875ef25c9783a36b2a000dc9e298384a33"
}
```

### Sample 86: `ba010a8ad4e125fe`

| Field | Value |
|---|---|
| SHA-256 | `ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b` |
| Family label | `SalatStealer` |
| File name | `ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:51:37` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fddc0cc4b705681dd738e3360894d1ab` |
| SHA-1 | `bb1fe9d3a2c6c3568766607097d47f1905bd8ac2` |
| SHA-256 | `ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b` |
| SHA3-384 | `13dea856f5846542259e247172219a5b8f40466baed8bccf8a17dd127c4baff8d83c1babb609766986c1d79b01d2c5d5` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1D2F5335BF1AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O/:iJiafuIO7rhWEES48` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_086_ba010a8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b"
    family = "SalatStealer"
    file_name = "ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:37"
  condition:
    hash.sha256(0, filesize) == "ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b"
}
```

### Sample 87: `c31031efad2d7fe4`

| Field | Value |
|---|---|
| SHA-256 | `c31031efad2d7fe4d436a5a8b962f5dd1b64f3026e96b5ebe2dd184987a8d83f` |
| Family label | `SalatStealer` |
| File name | `2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:51:30` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e99ccef4a88950422cc500e1af8c9e64` |
| SHA-1 | `9d9b04cb0467dfd2a1e40c8cfad5cc55a291e8d3` |
| SHA-256 | `c31031efad2d7fe4d436a5a8b962f5dd1b64f3026e96b5ebe2dd184987a8d83f` |
| SHA3-384 | `7573e9c16aa75bb9d39e94612c0cd69dd05fa0e9b4ff6907349dd779960d86b5a5019d05bdd96b92f73cb38a8427f1ea` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T129C65C11FACB54F6F9036831416BB27F23315D048B28DB9BEB583B6AF877691187A305` |
| SSDEEP | `49152:SBiYLtcEUP6VAs2Sf9JRToDCMChlxFlxqyr/6vgJsdbkkVew3mp03eZROdwvfZOG:DYRcNSfrd4CXlTRMzSXvkT4CrEvO/` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_087_c31031ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c31031efad2d7fe4d436a5a8b962f5dd1b64f3026e96b5ebe2dd184987a8d83f"
    family = "SalatStealer"
    file_name = "2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:30"
  condition:
    hash.sha256(0, filesize) == "c31031efad2d7fe4d436a5a8b962f5dd1b64f3026e96b5ebe2dd184987a8d83f"
}
```

### Sample 88: `d975b3ee5688134b`

| Field | Value |
|---|---|
| SHA-256 | `d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad` |
| Family label | `SalatStealer` |
| File name | `d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:51:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f44ecbed5ecdb576e7b110255bd1bef7` |
| SHA-1 | `e92b1ed976f22aa96f664c3fb9abb80138e5a2fe` |
| SHA-256 | `d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad` |
| SHA3-384 | `f555a0c24a1414dc83d499cafea8a4fd069d7bcd9a1494802eb220a2dacda3eda82c11bcf7b1f64f44448eb70fbe731b` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T13FF5335BF1AF47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OP:iJiafuIO7rhWEES4k` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_088_d975b3ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad"
    family = "SalatStealer"
    file_name = "d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:29"
  condition:
    hash.sha256(0, filesize) == "d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad"
}
```

### Sample 89: `de2acd1f5cb95f85`

| Field | Value |
|---|---|
| SHA-256 | `de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f` |
| Family label | `SalatStealer` |
| File name | `de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:51:23` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c8d85ce9e5cb6b5a38b593447f203c7` |
| SHA-1 | `b57299b86003f4c38c8d23e0921b6892b74cfbab` |
| SHA-256 | `de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f` |
| SHA3-384 | `96be2cdc1c03962f68a043989051b89c76e5234ad19766befd64178dddca05b25af3ad3a8c501f9178659d0282df67b0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12DF5335BF1AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oz:iJiafuIO7rhWEES4c` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_089_de2acd1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f"
    family = "SalatStealer"
    file_name = "de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:23"
  condition:
    hash.sha256(0, filesize) == "de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f"
}
```

### Sample 90: `8ce2cd98ef6ceeec`

| Field | Value |
|---|---|
| SHA-256 | `8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d` |
| Family label | `unknown` |
| File name | `8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:51:16` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8924b37f0a01a3fdf4bf228d0c0ef62c` |
| SHA-1 | `ad592543105a36d075c2479441268212ae52dfdc` |
| SHA-256 | `8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d` |
| SHA3-384 | `508860cd9121742e7a3c29a9e381fcc6c3f8a4b1533277b5dcdc548b4567d85754c609c085ab761dc48ffdd9776eb5c0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A5A63382E50B9C20E3B95C79F7711BB9C0C6B81BAD599134D4ECAB4252BFB50BB53213` |
| SSDEEP | `196608:s86zZSkMCZ0m1yj93PzovatWmoNULt3ss4CuUCH4NH0YztU:s8IZSkMPD8CBbOrGCUt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_8ce2cd98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d"
    family = "unknown"
    file_name = "8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:16"
  condition:
    hash.sha256(0, filesize) == "8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d"
}
```

### Sample 91: `2edc2fc9e82c7627`

| Field | Value |
|---|---|
| SHA-256 | `2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca` |
| Family label | `SalatStealer` |
| File name | `2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:51:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b57bb2784ad9b7683a736306973ecdb9` |
| SHA-1 | `564b18c61cd4f2abe204cdfdbd7324ef581e8ca8` |
| SHA-256 | `2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca` |
| SHA3-384 | `f89557e5ee0da5308f0007b416f161b53ee41bd486497c832ee3b9e25347368edcf640e096fb6ade93a10cd070b1617a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T18FF5335BF1AB4BB3F7D9A831561FC66458B09FE40A20D38AD4DBAADF0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oy:iJiafuIO7rhWEES4j` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_091_2edc2fc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca"
    family = "SalatStealer"
    file_name = "2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:10"
  condition:
    hash.sha256(0, filesize) == "2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca"
}
```

### Sample 92: `63ddfeae21aba49a`

| Field | Value |
|---|---|
| SHA-256 | `63ddfeae21aba49a10c0671baec865d0d3461fafdb684206cbdf9a0b39ba7055` |
| Family label | `SalatStealer` |
| File name | `05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:51:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `765f50d26eaf4be14990d56a232e97a5` |
| SHA-1 | `69360806174800068ff8bdace73fd3086c5c8b00` |
| SHA-256 | `63ddfeae21aba49a10c0671baec865d0d3461fafdb684206cbdf9a0b39ba7055` |
| SHA3-384 | `4b72a37c386cbfd7b604eb2bac4609012c28814a14b6aae3d9db7452cd5f31aa81e2c66c281ca8cb9968cf976346c960` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T15BC65C11FACB54F6F9036831416BB27F23315D048B28DB9BEB583B6AF8776911C6A305` |
| SSDEEP | `98304:BrN2aXdrjxCaTbqAEEC6C7L4fG2IflED:6axdTe0C68LxuD` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_092_63ddfeae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63ddfeae21aba49a10c0671baec865d0d3461fafdb684206cbdf9a0b39ba7055"
    family = "SalatStealer"
    file_name = "05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:06"
  condition:
    hash.sha256(0, filesize) == "63ddfeae21aba49a10c0671baec865d0d3461fafdb684206cbdf9a0b39ba7055"
}
```

### Sample 93: `b2badedf10ef5707`

| Field | Value |
|---|---|
| SHA-256 | `b2badedf10ef5707567ab632e5597691b63788540bb5beff9eda10681246d7d0` |
| Family label | `SalatStealer` |
| File name | `d24016826df7ae508b90fdb6c9e7b6e8305245595ecfc2b506513f2f971cebd0.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:50:56` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84644979323f1f7f1a9b1b3f9f2efdee` |
| SHA-1 | `f0e8f92f3809f9226e935e93511a2db3ca745d18` |
| SHA-256 | `b2badedf10ef5707567ab632e5597691b63788540bb5beff9eda10681246d7d0` |
| SHA3-384 | `c6fec9e80dca885959472d9aa93d55725ac99dea0e42261762852a6fe68af2e61f2afbd22f1c5fecafd5aef70c83022a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18EC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Z:yBkKr5rszpNDy+Z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_093_b2badedf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2badedf10ef5707567ab632e5597691b63788540bb5beff9eda10681246d7d0"
    family = "SalatStealer"
    file_name = "d24016826df7ae508b90fdb6c9e7b6e8305245595ecfc2b506513f2f971cebd0.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:56"
  condition:
    hash.sha256(0, filesize) == "b2badedf10ef5707567ab632e5597691b63788540bb5beff9eda10681246d7d0"
}
```

### Sample 94: `9f472cb0397fc125`

| Field | Value |
|---|---|
| SHA-256 | `9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff` |
| Family label | `SalatStealer` |
| File name | `9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:50:30` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c52ec33d3da669c47e4dfb0eca3f99f` |
| SHA-1 | `986389fd9f1d032ba74ccbe21b16fab088d3da00` |
| SHA-256 | `9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff` |
| SHA3-384 | `0629a2b6f5a059249b874ac7594c3308fe9d3d527a0397a7f5bb2f8223a6957f7e91daf55ad0647706fbc83608d17858` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T17AF5335BF1AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0882BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oq:iJiafuIO7rhWEES45` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_094_9f472cb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff"
    family = "SalatStealer"
    file_name = "9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:30"
  condition:
    hash.sha256(0, filesize) == "9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff"
}
```

### Sample 95: `12731350ac7d6cbe`

| Field | Value |
|---|---|
| SHA-256 | `12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f` |
| Family label | `SalatStealer` |
| File name | `12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:50:24` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccb1f41879a7f990f2632ad0b8327f03` |
| SHA-1 | `7007d5647bf155168b817b9fc73e7fb7144dc6e1` |
| SHA-256 | `12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f` |
| SHA3-384 | `e5ee7cc85ee5d38b1caf820c49dc54d23bc623f208af503dd43ce2cefa6ec0a2be16a7189504aee11af3fcda248ba57a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A7F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oy:iJiafuIO7rhWEES4f` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_095_12731350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f"
    family = "SalatStealer"
    file_name = "12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:24"
  condition:
    hash.sha256(0, filesize) == "12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f"
}
```

### Sample 96: `2f393bd2c6801381`

| Field | Value |
|---|---|
| SHA-256 | `2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b` |
| Family label | `SalatStealer` |
| File name | `2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:50:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c103b312b2a2bb0a185ca8e95cc3ee9` |
| SHA-1 | `32d3336495005d02f52025238f9577b7be81b361` |
| SHA-256 | `2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b` |
| SHA3-384 | `2793c8536e36ec4f936deaea064b8f4ef8ce8f25f3914b6c5cb5b167ee544cb0d82ae0f1cd26401bd535c16597f8aea3` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A6F533AA6199D2C5FAC7C1F990DB61D2C04649106E4EE10EDDBAC36CC9A71E28F71FC4` |
| SSDEEP | `98304:/OQt+BOGHx3sZL10EAAz0xvbxDB2BwqiYFJ:2QtXA3sv040n12BbF` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_096_2f393bd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b"
    family = "SalatStealer"
    file_name = "2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:17"
  condition:
    hash.sha256(0, filesize) == "2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b"
}
```

### Sample 97: `05cfac8008d88e13`

| Field | Value |
|---|---|
| SHA-256 | `05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004` |
| Family label | `SalatStealer` |
| File name | `05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:50:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `566259371135c22d2871ac500423d4ff` |
| SHA-1 | `8732b7a04997228b2b0b037d1e7b70ca72c0b843` |
| SHA-256 | `05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004` |
| SHA3-384 | `452a4dbe0beb34f8e568a28542de1c2c105ec668e57ccdd8e29ba2aae2ca422269bd0f2f3c12c58e21ba61e6c80dc0e2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T112F533E212CE593EC67B67F342B162ED975C9D4A12664B5ED71D2B3480AC183FE0C81B` |
| SSDEEP | `98304:CwJqa4bxklEayYfMqTpcJSWz4yb3/W3tKgZRQ:CwKilEafdcJSq4yb3qtKgs` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_097_05cfac80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004"
    family = "SalatStealer"
    file_name = "05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:09"
  condition:
    hash.sha256(0, filesize) == "05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004"
}
```

### Sample 98: `947768adbdf6fd08`

| Field | Value |
|---|---|
| SHA-256 | `947768adbdf6fd085afb7e191cdd9c1c85df467b61adb9a57ffb078fd3043a26` |
| Family label | `SalatStealer` |
| File name | `ec01c37f1b3e111eb0a75e7e267726c118677cb0064f1aeb97651e471351f128.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:49:47` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2e58432c08cc19e9c16865c2210b998` |
| SHA-1 | `1efa03ac4bf08eeda147085465b7ae9fa752b6c4` |
| SHA-256 | `947768adbdf6fd085afb7e191cdd9c1c85df467b61adb9a57ffb078fd3043a26` |
| SHA3-384 | `7b07830c947e6e1c84b5f2c56ad0a9a665baffcfb6db11a887cb73660eb12fe036495819e25906694ba0f906e3de8068` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1AAC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+7:yBkKr5rszpNDy+7` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_098_947768ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "947768adbdf6fd085afb7e191cdd9c1c85df467b61adb9a57ffb078fd3043a26"
    family = "SalatStealer"
    file_name = "ec01c37f1b3e111eb0a75e7e267726c118677cb0064f1aeb97651e471351f128.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:49:47"
  condition:
    hash.sha256(0, filesize) == "947768adbdf6fd085afb7e191cdd9c1c85df467b61adb9a57ffb078fd3043a26"
}
```

### Sample 99: `873aacdd29d787b3`

| Field | Value |
|---|---|
| SHA-256 | `873aacdd29d787b3bff0b4637b26b2155044c58bb86fab3dac7351e596692661` |
| Family label | `SalatStealer` |
| File name | `d20a70b97cfda84fd416a92de64625ea2f21d1ae3986bbcfb204a92f65a7cecc.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:49:42` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97ad9f9455e0ce5eaa26f53aba9991d3` |
| SHA-1 | `8bcf85fa3c91c670da715ef6bbbc58e90a614e47` |
| SHA-256 | `873aacdd29d787b3bff0b4637b26b2155044c58bb86fab3dac7351e596692661` |
| SHA3-384 | `98e3913edffbb50565cd6862f3b3a4f901d40fb1f808c1161a3b051dbc1fdcaf1250ecbefee846b13acfabc4bd9408b8` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T106C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+V:yBkKr5rszpNDy+V` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_099_873aacdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "873aacdd29d787b3bff0b4637b26b2155044c58bb86fab3dac7351e596692661"
    family = "SalatStealer"
    file_name = "d20a70b97cfda84fd416a92de64625ea2f21d1ae3986bbcfb204a92f65a7cecc.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:49:42"
  condition:
    hash.sha256(0, filesize) == "873aacdd29d787b3bff0b4637b26b2155044c58bb86fab3dac7351e596692661"
}
```

### Sample 100: `d6c1fad577dd6c24`

| Field | Value |
|---|---|
| SHA-256 | `d6c1fad577dd6c2464c13f83a1a7955bfaa6a6f6405a41fe963dd7505f04fbd3` |
| Family label | `SalatStealer` |
| File name | `b382f286a2a4499ea1fc55facd1989999dc3ffb405845744b99e1dd40ba4c397.exe` |
| File type | `exe` |
| First seen | `2026-10-29 00:49:36` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3677f3db5f12edce4ff995d7d822cf64` |
| SHA-1 | `7ee890b8026c2df203be1b4bc15c93c375a518e0` |
| SHA-256 | `d6c1fad577dd6c2464c13f83a1a7955bfaa6a6f6405a41fe963dd7505f04fbd3` |
| SHA3-384 | `b46d8729baaff2ab1607e83fa1718a0a36ee03adea08fcd25cb7689861a8b02f6296348035e12dbe5ca61d0a55e83022` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T11EC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+A:yBkKr5rszpNDy+A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_100_d6c1fad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6c1fad577dd6c2464c13f83a1a7955bfaa6a6f6405a41fe963dd7505f04fbd3"
    family = "SalatStealer"
    file_name = "b382f286a2a4499ea1fc55facd1989999dc3ffb405845744b99e1dd40ba4c397.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:49:36"
  condition:
    hash.sha256(0, filesize) == "d6c1fad577dd6c2464c13f83a1a7955bfaa6a6f6405a41fe963dd7505f04fbd3"
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
 * Generated: 2026-10-29T05:58:21.621625+00:00
 */

rule MalwareBazaar_unknown_001_ad61bd9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad61bd9bf203d67cbf81c331b97fffed4f458f8ea0c38fefd0b3365cb326fc1c"
    family = "unknown"
    file_name = "khide_6.8.0-101-generic.65fb47"
    file_type = "elf"
    first_seen = "2026-10-29 05:45:54"
  condition:
    hash.sha256(0, filesize) == "ad61bd9bf203d67cbf81c331b97fffed4f458f8ea0c38fefd0b3365cb326fc1c"
}

rule MalwareBazaar_Mirai_002_772df17d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "772df17d8da21b06b66675f2dd8571d38d79fabca084e7e95b594697f45b02a1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-29 05:30:56"
  condition:
    hash.sha256(0, filesize) == "772df17d8da21b06b66675f2dd8571d38d79fabca084e7e95b594697f45b02a1"
}

rule MalwareBazaar_SalatStealer_003_067ff5c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "067ff5c5937956ff11faf4f507e53c7347486b238e5ba29af40cfa24cf7a67a6"
    family = "SalatStealer"
    file_name = "2b10a1bb42b8b7aa.bin"
    file_type = "exe"
    first_seen = "2026-10-29 05:25:27"
  condition:
    hash.sha256(0, filesize) == "067ff5c5937956ff11faf4f507e53c7347486b238e5ba29af40cfa24cf7a67a6"
}

rule MalwareBazaar_SalatStealer_004_57a63ea3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a63ea3de36e0fd0e8a4e1df7f48b472d4db86ccdeb125d297d0a331bad33b3"
    family = "SalatStealer"
    file_name = "54a3d75e36078028.bin"
    file_type = "exe"
    first_seen = "2026-10-29 05:24:22"
  condition:
    hash.sha256(0, filesize) == "57a63ea3de36e0fd0e8a4e1df7f48b472d4db86ccdeb125d297d0a331bad33b3"
}

rule MalwareBazaar_SalatStealer_005_2b10a1bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b10a1bb42b8b7aa44a37b1d48ce1324150217395842aed1a34c7ff91687a5b5"
    family = "SalatStealer"
    file_name = "2b10a1bb42b8b7aa.bin"
    file_type = "exe"
    first_seen = "2026-10-29 05:24:18"
  condition:
    hash.sha256(0, filesize) == "2b10a1bb42b8b7aa44a37b1d48ce1324150217395842aed1a34c7ff91687a5b5"
}

rule MalwareBazaar_SalatStealer_006_54a3d75e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54a3d75e360780280e8f427eb18aeb651c62914364e305a3e2f8922cd8bc9988"
    family = "SalatStealer"
    file_name = "54a3d75e36078028.bin"
    file_type = "exe"
    first_seen = "2026-10-29 05:24:08"
  condition:
    hash.sha256(0, filesize) == "54a3d75e360780280e8f427eb18aeb651c62914364e305a3e2f8922cd8bc9988"
}

rule MalwareBazaar_unknown_007_5d4ea84b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6"
    family = "unknown"
    file_name = "5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6.exe"
    file_type = "exe"
    first_seen = "2026-10-29 05:18:27"
  condition:
    hash.sha256(0, filesize) == "5d4ea84b8561fc958a7bd86133e4085d5e0daa61edfd0e1426e4f5215dca27f6"
}

rule MalwareBazaar_Mirai_008_a9f3cea8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-29 05:09:34"
  condition:
    hash.sha256(0, filesize) == "a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155"
}

rule MalwareBazaar_Mirai_009_f7f4aa82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7f4aa82b8bed3d8998579518c468337a021221393f7ff95577b66a53518078c"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-10-29 05:02:59"
  condition:
    hash.sha256(0, filesize) == "f7f4aa82b8bed3d8998579518c468337a021221393f7ff95577b66a53518078c"
}

rule MalwareBazaar_unknown_010_d8e492ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d"
    family = "unknown"
    file_name = "d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d"
    file_type = "elf"
    first_seen = "2026-10-29 05:00:14"
  condition:
    hash.sha256(0, filesize) == "d8e492ea07fd77f98ed41d4f6ce9750556d12116b6d5efea32c9e5f7bde4763d"
}

rule MalwareBazaar_RemcosRAT_011_4f1dcf5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f1dcf5f02913db699db8e9d138e2cca9d7e7657d7d9bb37c6eef23ab794b22f"
    family = "RemcosRAT"
    file_name = "05002600357104880_KAWAN_LAMA_GROUP_PT.js"
    file_type = "js"
    first_seen = "2026-10-29 04:55:36"
  condition:
    hash.sha256(0, filesize) == "4f1dcf5f02913db699db8e9d138e2cca9d7e7657d7d9bb37c6eef23ab794b22f"
}

rule MalwareBazaar_RemcosRAT_012_8d7fae9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d7fae9ec5139cb7a184710ac445ebf16aeca23fd38c33eae63a2ff351570fd4"
    family = "RemcosRAT"
    file_name = "05002600357104880_KAWAN_LAMA_GROUP_PT.Gz"
    file_type = "gz"
    first_seen = "2026-10-29 04:55:17"
  condition:
    hash.sha256(0, filesize) == "8d7fae9ec5139cb7a184710ac445ebf16aeca23fd38c33eae63a2ff351570fd4"
}

rule MalwareBazaar_unknown_013_6b5afe50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7"
    family = "unknown"
    file_name = "6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7"
    file_type = "elf"
    first_seen = "2026-10-29 04:35:32"
  condition:
    hash.sha256(0, filesize) == "6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7"
}

rule MalwareBazaar_Mirai_014_c1449197
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c14491979811b95f025be5274feb90ff296bcd4438c99f9121c8a5a7de8c4274"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-29 04:26:56"
  condition:
    hash.sha256(0, filesize) == "c14491979811b95f025be5274feb90ff296bcd4438c99f9121c8a5a7de8c4274"
}

rule MalwareBazaar_SalatStealer_015_18cc64b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cc64b5520b7221d39f84072a91fbfd3af8997af90c135a301e50ab5ec6c09a"
    family = "SalatStealer"
    file_name = "f2c4da25934bf744.bin"
    file_type = "exe"
    first_seen = "2026-10-29 04:25:35"
  condition:
    hash.sha256(0, filesize) == "18cc64b5520b7221d39f84072a91fbfd3af8997af90c135a301e50ab5ec6c09a"
}

rule MalwareBazaar_SalatStealer_016_11308a0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11308a0ae3564419ff7d12914b5b390934af3fa9c7c29420d64022dd0722eafa"
    family = "SalatStealer"
    file_name = "a92603bea54428c6.bin"
    file_type = "exe"
    first_seen = "2026-10-29 04:25:28"
  condition:
    hash.sha256(0, filesize) == "11308a0ae3564419ff7d12914b5b390934af3fa9c7c29420d64022dd0722eafa"
}

rule MalwareBazaar_SalatStealer_017_f2c4da25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2c4da25934bf744a2031f65b5ecd9be3b1a56ac5aad74f6a82c586bc8de12ba"
    family = "SalatStealer"
    file_name = "f2c4da25934bf744.bin"
    file_type = "exe"
    first_seen = "2026-10-29 04:24:58"
  condition:
    hash.sha256(0, filesize) == "f2c4da25934bf744a2031f65b5ecd9be3b1a56ac5aad74f6a82c586bc8de12ba"
}

rule MalwareBazaar_SalatStealer_018_a92603be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a92603bea54428c6f479e62da9815dbbdcb4be3ed566a78f3e974529f006e52a"
    family = "SalatStealer"
    file_name = "a92603bea54428c6.bin"
    file_type = "exe"
    first_seen = "2026-10-29 04:24:42"
  condition:
    hash.sha256(0, filesize) == "a92603bea54428c6f479e62da9815dbbdcb4be3ed566a78f3e974529f006e52a"
}

rule MalwareBazaar_unknown_019_3b878a40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b878a40f7badc24cd584d816c01e3d316efa2a57683ea1181e319ff8ee24e58"
    family = "unknown"
    file_name = "siyuchat_setup.exe"
    file_type = "exe"
    first_seen = "2026-10-29 03:27:07"
  condition:
    hash.sha256(0, filesize) == "3b878a40f7badc24cd584d816c01e3d316efa2a57683ea1181e319ff8ee24e58"
}

rule MalwareBazaar_unknown_020_bde27af2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bde27af26c47f2a171e4dda867dca68ee294bfa83b46331295139df8faed1a07"
    family = "unknown"
    file_name = "svvhost.exe"
    file_type = "exe"
    first_seen = "2026-10-29 03:26:35"
  condition:
    hash.sha256(0, filesize) == "bde27af26c47f2a171e4dda867dca68ee294bfa83b46331295139df8faed1a07"
}

rule MalwareBazaar_SalatStealer_021_0cf9cfd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cf9cfd671535a4770d10c022b3e9b1031ee56d8c9f0eed8b179cae48eae1602"
    family = "SalatStealer"
    file_name = "77a32b9c95a8228d.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:51"
  condition:
    hash.sha256(0, filesize) == "0cf9cfd671535a4770d10c022b3e9b1031ee56d8c9f0eed8b179cae48eae1602"
}

rule MalwareBazaar_SalatStealer_022_e28b6e0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e28b6e0ff5aa72119bd3e2e20a63c36299f6dc08236cb6a67c7ce878566d8038"
    family = "SalatStealer"
    file_name = "231f4fe6cebf9cbe.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:45"
  condition:
    hash.sha256(0, filesize) == "e28b6e0ff5aa72119bd3e2e20a63c36299f6dc08236cb6a67c7ce878566d8038"
}

rule MalwareBazaar_SalatStealer_023_a82dc887
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a82dc8871f1c3b73f543322435b14ad2ed5723a8e246364a48320b11ba46f616"
    family = "SalatStealer"
    file_name = "66cfd97e739eed9e.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:38"
  condition:
    hash.sha256(0, filesize) == "a82dc8871f1c3b73f543322435b14ad2ed5723a8e246364a48320b11ba46f616"
}

rule MalwareBazaar_SalatStealer_024_77a32b9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a32b9c95a8228dcb6ab73d2c045e7b603837a1aac535ac31b465b7f1f256af"
    family = "SalatStealer"
    file_name = "77a32b9c95a8228d.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:16"
  condition:
    hash.sha256(0, filesize) == "77a32b9c95a8228dcb6ab73d2c045e7b603837a1aac535ac31b465b7f1f256af"
}

rule MalwareBazaar_SalatStealer_025_231f4fe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "231f4fe6cebf9cbe7d663503bd25b923d3daeebbac973f98ace8a9a770d9b59b"
    family = "SalatStealer"
    file_name = "231f4fe6cebf9cbe.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:25:06"
  condition:
    hash.sha256(0, filesize) == "231f4fe6cebf9cbe7d663503bd25b923d3daeebbac973f98ace8a9a770d9b59b"
}

rule MalwareBazaar_SalatStealer_026_66cfd97e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66cfd97e739eed9e633a632eae81e24072399ff538e0dd85866cdc42cfa8557d"
    family = "SalatStealer"
    file_name = "66cfd97e739eed9e.bin"
    file_type = "exe"
    first_seen = "2026-10-29 03:24:56"
  condition:
    hash.sha256(0, filesize) == "66cfd97e739eed9e633a632eae81e24072399ff538e0dd85866cdc42cfa8557d"
}

rule MalwareBazaar_Mirai_027_6e79e890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7"
    family = "Mirai"
    file_name = "6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7.elf"
    file_type = "elf"
    first_seen = "2026-10-29 03:23:25"
  condition:
    hash.sha256(0, filesize) == "6e79e890c649ef6f0cd238487fb56de717db6c60285d2c528464aa43bdd7bdc7"
}

rule MalwareBazaar_unknown_028_af4acf4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af4acf4db03f73be83613a4840aefbc14702d11906ec72953e2e17c39249b4c3"
    family = "unknown"
    file_name = "FACEITInstaller_64.exe"
    file_type = "rar"
    first_seen = "2026-10-29 03:14:23"
  condition:
    hash.sha256(0, filesize) == "af4acf4db03f73be83613a4840aefbc14702d11906ec72953e2e17c39249b4c3"
}

rule MalwareBazaar_Mirai_029_1382088f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1382088ffa6ee9bb02c4b8f6153c8a70f926d816c1f849a81aa51408870b09ac"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-29 02:35:50"
  condition:
    hash.sha256(0, filesize) == "1382088ffa6ee9bb02c4b8f6153c8a70f926d816c1f849a81aa51408870b09ac"
}

rule MalwareBazaar_SalatStealer_030_16e019fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050"
    family = "SalatStealer"
    file_name = "16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050.exe"
    file_type = "exe"
    first_seen = "2026-10-29 02:33:25"
  condition:
    hash.sha256(0, filesize) == "16e019fcfe4456e7a6b7ee7e3bc269779572e90fd8d895fef1945770e83fd050"
}

rule MalwareBazaar_Mirai_031_9daea98c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9daea98c0ef4a998a9c8bec7299587b0dc127f078ced6f633a855ca60622a248"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-29 02:32:56"
  condition:
    hash.sha256(0, filesize) == "9daea98c0ef4a998a9c8bec7299587b0dc127f078ced6f633a855ca60622a248"
}

rule MalwareBazaar_SalatStealer_032_d38888ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d38888ef13080bcf9a5ab92f19a4d3f2bf72860429216fa21db591f716f88ad0"
    family = "SalatStealer"
    file_name = "5ced9afef6a7705b.bin"
    file_type = "exe"
    first_seen = "2026-10-29 02:26:23"
  condition:
    hash.sha256(0, filesize) == "d38888ef13080bcf9a5ab92f19a4d3f2bf72860429216fa21db591f716f88ad0"
}

rule MalwareBazaar_SalatStealer_033_e191c70b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e191c70bd8c99caf21719463d4192ef498b9a52b625fe0879204fc4a7d05f37e"
    family = "SalatStealer"
    file_name = "a0e2b9c5bcda769b.bin"
    file_type = "exe"
    first_seen = "2026-10-29 02:25:26"
  condition:
    hash.sha256(0, filesize) == "e191c70bd8c99caf21719463d4192ef498b9a52b625fe0879204fc4a7d05f37e"
}

rule MalwareBazaar_SalatStealer_034_5ced9afe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ced9afef6a7705b783ed2edda02a39452d391af6490087b0c32fdeaf4bea0f9"
    family = "SalatStealer"
    file_name = "5ced9afef6a7705b.bin"
    file_type = "exe"
    first_seen = "2026-10-29 02:25:26"
  condition:
    hash.sha256(0, filesize) == "5ced9afef6a7705b783ed2edda02a39452d391af6490087b0c32fdeaf4bea0f9"
}

rule MalwareBazaar_SalatStealer_035_a0e2b9c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0e2b9c5bcda769b5ced07bca13da40f37ca6dcb16c3d5036b9089755dedf186"
    family = "SalatStealer"
    file_name = "a0e2b9c5bcda769b.bin"
    file_type = "exe"
    first_seen = "2026-10-29 02:25:16"
  condition:
    hash.sha256(0, filesize) == "a0e2b9c5bcda769b5ced07bca13da40f37ca6dcb16c3d5036b9089755dedf186"
}

rule MalwareBazaar_Mirai_036_eec3f197
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eec3f1975eb721121705ac3a478bade8a4c3d462615c2bfab7f2a035674cb3a9"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-10-29 02:18:01"
  condition:
    hash.sha256(0, filesize) == "eec3f1975eb721121705ac3a478bade8a4c3d462615c2bfab7f2a035674cb3a9"
}

rule MalwareBazaar_Mirai_037_1589043c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1589043c3092d916414efefec4de9ae15215a85983b13fc02f5e687994f3fd1c"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-29 02:14:55"
  condition:
    hash.sha256(0, filesize) == "1589043c3092d916414efefec4de9ae15215a85983b13fc02f5e687994f3fd1c"
}

rule MalwareBazaar_unknown_038_ab411085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23"
    family = "unknown"
    file_name = "ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23.sh"
    file_type = "sh"
    first_seen = "2026-10-29 02:03:00"
  condition:
    hash.sha256(0, filesize) == "ab4110850e3b9a86098e3682cd50c351f9eebc16229ce411e1a586384c379d23"
}

rule MalwareBazaar_unknown_039_f64b3080
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64b3080432867f3778e62399cc109dfbc10ddc924bc5221daa3c1d54eecc831"
    family = "unknown"
    file_name = "macho_f64b30804328.bin"
    file_type = "macho"
    first_seen = "2026-10-29 02:02:32"
  condition:
    hash.sha256(0, filesize) == "f64b3080432867f3778e62399cc109dfbc10ddc924bc5221daa3c1d54eecc831"
}

rule MalwareBazaar_unknown_040_5300c0e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5300c0e0296ae4d2897ea72b5282b2fa57f8b824507e1a3d9dd80d6530395fdc"
    family = "unknown"
    file_name = "macho_5300c0e0296a.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:57:59"
  condition:
    hash.sha256(0, filesize) == "5300c0e0296ae4d2897ea72b5282b2fa57f8b824507e1a3d9dd80d6530395fdc"
}

rule MalwareBazaar_Mirai_041_bca63a1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca63a1f5c50cf795e6bd12e1357ce3c52996a3ad2290970e9295c77c0ff0ad6"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-29 01:57:25"
  condition:
    hash.sha256(0, filesize) == "bca63a1f5c50cf795e6bd12e1357ce3c52996a3ad2290970e9295c77c0ff0ad6"
}

rule MalwareBazaar_Mirai_042_7f64ed4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f64ed4a05d8be4a2ed5a6fddbae3c51238aec601971d3eb7dabb8a2794aec13"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-29 01:56:46"
  condition:
    hash.sha256(0, filesize) == "7f64ed4a05d8be4a2ed5a6fddbae3c51238aec601971d3eb7dabb8a2794aec13"
}

rule MalwareBazaar_unknown_043_1c5efea8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c5efea856059fc548f2b21e9e6e5079727949e5c86f8f428acfeef314ed1060"
    family = "unknown"
    file_name = "macho_1c5efea85605.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:53:13"
  condition:
    hash.sha256(0, filesize) == "1c5efea856059fc548f2b21e9e6e5079727949e5c86f8f428acfeef314ed1060"
}

rule MalwareBazaar_unknown_044_8ac8e983
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ac8e983086e7e35004a8ea6575a37e14b986c518b13bc5c906e3df89f37d8d3"
    family = "unknown"
    file_name = "macho_8ac8e983086e.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:48:41"
  condition:
    hash.sha256(0, filesize) == "8ac8e983086e7e35004a8ea6575a37e14b986c518b13bc5c906e3df89f37d8d3"
}

rule MalwareBazaar_unknown_045_8220416c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8220416c319dfc519aaf6023ac5c50394d758e3ebe436f3e7c43ff7feb19c0a0"
    family = "unknown"
    file_name = "macho_8220416c319d.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:43:53"
  condition:
    hash.sha256(0, filesize) == "8220416c319dfc519aaf6023ac5c50394d758e3ebe436f3e7c43ff7feb19c0a0"
}

rule MalwareBazaar_njrat_046_d590b526
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9"
    family = "njrat"
    file_name = "d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:43:24"
  condition:
    hash.sha256(0, filesize) == "d590b52661f31fa0234e9f668e8d193f7d74906190283449daa39a739ad6cef9"
}

rule MalwareBazaar_unknown_047_bb449088
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb4490884100ee84e132ea822d06da99508becdc16e434dcf11ade19b0971dd0"
    family = "unknown"
    file_name = "macho_bb4490884100.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:39:25"
  condition:
    hash.sha256(0, filesize) == "bb4490884100ee84e132ea822d06da99508becdc16e434dcf11ade19b0971dd0"
}

rule MalwareBazaar_unknown_048_a2badf05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2badf05b11de0f772600c9fef2357c1f514a0ca21feb43240f188dbf7522992"
    family = "unknown"
    file_name = "macho_a2badf05b11d.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:35:01"
  condition:
    hash.sha256(0, filesize) == "a2badf05b11de0f772600c9fef2357c1f514a0ca21feb43240f188dbf7522992"
}

rule MalwareBazaar_unknown_049_a066568d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3"
    family = "unknown"
    file_name = "a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:30:46"
  condition:
    hash.sha256(0, filesize) == "a066568d8f88f5b2ffa9fdb028a326834035a43abeeda018f0aaecff2fc2f0c3"
}

rule MalwareBazaar_unknown_050_643af461
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "643af4611e02c36280cdf4a9b22be3488ec48278db7511e268c13d0c11a0daf9"
    family = "unknown"
    file_name = "macho_643af4611e02.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:30:28"
  condition:
    hash.sha256(0, filesize) == "643af4611e02c36280cdf4a9b22be3488ec48278db7511e268c13d0c11a0daf9"
}

rule MalwareBazaar_SalatStealer_051_4e6e1fbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e6e1fbdb531311849fa876c30969d6d0826f29b204daeec7c75f14ad51dbe33"
    family = "SalatStealer"
    file_name = "ddffa002eb19cf53.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:26:26"
  condition:
    hash.sha256(0, filesize) == "4e6e1fbdb531311849fa876c30969d6d0826f29b204daeec7c75f14ad51dbe33"
}

rule MalwareBazaar_unknown_052_62907f8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62907f8dfe5397eab2d8482c80b0544540d71ec95ae9ba3172a80f7dd09c7de9"
    family = "unknown"
    file_name = "macho_62907f8dfe53.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:26:05"
  condition:
    hash.sha256(0, filesize) == "62907f8dfe5397eab2d8482c80b0544540d71ec95ae9ba3172a80f7dd09c7de9"
}

rule MalwareBazaar_SalatStealer_053_49915666
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49915666d91df2ea63238c16a9c4479dbb72b7ea7c22f96a2f812de9d60b386c"
    family = "SalatStealer"
    file_name = "88f7d11fe4ed196a.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:26:02"
  condition:
    hash.sha256(0, filesize) == "49915666d91df2ea63238c16a9c4479dbb72b7ea7c22f96a2f812de9d60b386c"
}

rule MalwareBazaar_SalatStealer_054_b8be9c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8be9c98d82ebb62ce09ec43940c07232dd11e6b3240064952848682c986edfa"
    family = "SalatStealer"
    file_name = "97b0f79f66bf4656.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:25:54"
  condition:
    hash.sha256(0, filesize) == "b8be9c98d82ebb62ce09ec43940c07232dd11e6b3240064952848682c986edfa"
}

rule MalwareBazaar_SalatStealer_055_021e04ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021e04edfe50d0172ec0a56fcb7ef854b26e7f7deb574f24c6e9e660cdbbd70a"
    family = "SalatStealer"
    file_name = "d792764640539de0.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:25:46"
  condition:
    hash.sha256(0, filesize) == "021e04edfe50d0172ec0a56fcb7ef854b26e7f7deb574f24c6e9e660cdbbd70a"
}

rule MalwareBazaar_SalatStealer_056_61bd412f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61bd412ff863ecfb8b1e558ee3356cc3fd72d0579dbdb4f30d322f0c40950499"
    family = "SalatStealer"
    file_name = "5de3d9b327b1eca2.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:25:39"
  condition:
    hash.sha256(0, filesize) == "61bd412ff863ecfb8b1e558ee3356cc3fd72d0579dbdb4f30d322f0c40950499"
}

rule MalwareBazaar_SalatStealer_057_ddffa002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddffa002eb19cf535b4d7577d59207fbfd7cc04a693fd55fc9b9869324cd3d6f"
    family = "SalatStealer"
    file_name = "ddffa002eb19cf53.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:25:04"
  condition:
    hash.sha256(0, filesize) == "ddffa002eb19cf535b4d7577d59207fbfd7cc04a693fd55fc9b9869324cd3d6f"
}

rule MalwareBazaar_SalatStealer_058_88f7d11f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88f7d11fe4ed196af8931d065dcf91c71fda385fc1aec33f114a25c3b98990bf"
    family = "SalatStealer"
    file_name = "88f7d11fe4ed196a.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:55"
  condition:
    hash.sha256(0, filesize) == "88f7d11fe4ed196af8931d065dcf91c71fda385fc1aec33f114a25c3b98990bf"
}

rule MalwareBazaar_SalatStealer_059_97b0f79f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b0f79f66bf46568ee6aa0ccaa24d95c46e6fa2fa7bdff2282b428fe96b7f32"
    family = "SalatStealer"
    file_name = "97b0f79f66bf4656.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:45"
  condition:
    hash.sha256(0, filesize) == "97b0f79f66bf46568ee6aa0ccaa24d95c46e6fa2fa7bdff2282b428fe96b7f32"
}

rule MalwareBazaar_SalatStealer_060_5fd4f7d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fd4f7d292f67c2117c18d580ee3f4b261599866a9c5251bc86055ab5d96518d"
    family = "SalatStealer"
    file_name = "1550c0399429bebc.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:40"
  condition:
    hash.sha256(0, filesize) == "5fd4f7d292f67c2117c18d580ee3f4b261599866a9c5251bc86055ab5d96518d"
}

rule MalwareBazaar_SalatStealer_061_d7927646
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d792764640539de0230ecd8213d9d5217ab43835943a8724e738eac0d96545e0"
    family = "SalatStealer"
    file_name = "d792764640539de0.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:36"
  condition:
    hash.sha256(0, filesize) == "d792764640539de0230ecd8213d9d5217ab43835943a8724e738eac0d96545e0"
}

rule MalwareBazaar_SalatStealer_062_cd7bdbae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd7bdbae081d8d4a55040d552691be6268c485fb4cdeb17515aec47bbcc8d594"
    family = "SalatStealer"
    file_name = "364e0135bcf58580.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:35"
  condition:
    hash.sha256(0, filesize) == "cd7bdbae081d8d4a55040d552691be6268c485fb4cdeb17515aec47bbcc8d594"
}

rule MalwareBazaar_SalatStealer_063_a951460a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a951460a2d6a72d878844d65d60e62e1c4fd46a97bea1cabe6d35445664b8475"
    family = "SalatStealer"
    file_name = "b8f71b5f6656298e.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:28"
  condition:
    hash.sha256(0, filesize) == "a951460a2d6a72d878844d65d60e62e1c4fd46a97bea1cabe6d35445664b8475"
}

rule MalwareBazaar_SalatStealer_064_5de3d9b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5de3d9b327b1eca29867ab4a0d5c59302858302cf9091604658b9fc4995c5667"
    family = "SalatStealer"
    file_name = "5de3d9b327b1eca2.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:26"
  condition:
    hash.sha256(0, filesize) == "5de3d9b327b1eca29867ab4a0d5c59302858302cf9091604658b9fc4995c5667"
}

rule MalwareBazaar_SalatStealer_065_1550c039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1550c0399429bebc3aadb96a0de2f0550079434ffd643a7a76a47b9e47c9b4dd"
    family = "SalatStealer"
    file_name = "1550c0399429bebc.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:17"
  condition:
    hash.sha256(0, filesize) == "1550c0399429bebc3aadb96a0de2f0550079434ffd643a7a76a47b9e47c9b4dd"
}

rule MalwareBazaar_SalatStealer_066_364e0135
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "364e0135bcf585807f10fbe0e29cbd1df7586d90bf2bb3a512fdc005b0b59669"
    family = "SalatStealer"
    file_name = "364e0135bcf58580.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:24:07"
  condition:
    hash.sha256(0, filesize) == "364e0135bcf585807f10fbe0e29cbd1df7586d90bf2bb3a512fdc005b0b59669"
}

rule MalwareBazaar_SalatStealer_067_b8f71b5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8f71b5f6656298e95013e75b955b9b49f0f236f30558aedb20f2f62aeddd782"
    family = "SalatStealer"
    file_name = "b8f71b5f6656298e.bin"
    file_type = "exe"
    first_seen = "2026-10-29 01:23:58"
  condition:
    hash.sha256(0, filesize) == "b8f71b5f6656298e95013e75b955b9b49f0f236f30558aedb20f2f62aeddd782"
}

rule MalwareBazaar_unknown_068_e2fcffd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2fcffd2ce53fe38b555db86e14e96b706eb811367dba4725f96a248c667b9a8"
    family = "unknown"
    file_name = "macho_e2fcffd2ce53.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:21:25"
  condition:
    hash.sha256(0, filesize) == "e2fcffd2ce53fe38b555db86e14e96b706eb811367dba4725f96a248c667b9a8"
}

rule MalwareBazaar_Mirai_069_3d5df13b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d5df13b6db8ed554e44c64db65a9797c5b6f220e34efa6e7b3904d8abb41d67"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-10-29 01:17:43"
  condition:
    hash.sha256(0, filesize) == "3d5df13b6db8ed554e44c64db65a9797c5b6f220e34efa6e7b3904d8abb41d67"
}

rule MalwareBazaar_unknown_070_87367d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87367d9c60bb5923526138d10340a60d13d150f3280bba966d0ef8a335893635"
    family = "unknown"
    file_name = "macho_87367d9c60bb.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:16:41"
  condition:
    hash.sha256(0, filesize) == "87367d9c60bb5923526138d10340a60d13d150f3280bba966d0ef8a335893635"
}

rule MalwareBazaar_unknown_071_6335a442
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6335a4427566446e65202fb47dac5bac3433308c5daabf2293afb3c795f5353c"
    family = "unknown"
    file_name = "macho_6335a4427566.bin"
    file_type = "macho"
    first_seen = "2026-10-29 01:12:25"
  condition:
    hash.sha256(0, filesize) == "6335a4427566446e65202fb47dac5bac3433308c5daabf2293afb3c795f5353c"
}

rule MalwareBazaar_unknown_072_daf0623e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322"
    family = "unknown"
    file_name = "daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:09:26"
  condition:
    hash.sha256(0, filesize) == "daf0623ef19b3618788248c6786a60bf64fca4c6671b99583b7c7bab2be8c322"
}

rule MalwareBazaar_unknown_073_b1a84cfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9"
    family = "unknown"
    file_name = "loader.sh"
    file_type = "sh"
    first_seen = "2026-10-29 01:01:05"
  condition:
    hash.sha256(0, filesize) == "b1a84cfd4176a472e319ee7733e55998ae69b9752fd26f8c853cefd836a477b9"
}

rule MalwareBazaar_SalatStealer_074_3fb119de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb119de79ee89ec7e969e140fc53cd5de471e9891b67cbcbc8c9989bafb937a"
    family = "SalatStealer"
    file_name = "2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:00:52"
  condition:
    hash.sha256(0, filesize) == "3fb119de79ee89ec7e969e140fc53cd5de471e9891b67cbcbc8c9989bafb937a"
}

rule MalwareBazaar_SalatStealer_075_2ed14553
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648"
    family = "SalatStealer"
    file_name = "2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648.exe"
    file_type = "exe"
    first_seen = "2026-10-29 01:00:18"
  condition:
    hash.sha256(0, filesize) == "2ed145530149d78980b5018e7a018bb7d377b38ca5030760fb4154ddd5f49648"
}

rule MalwareBazaar_SalatStealer_076_d36b6e6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d36b6e6c034d47ac22edb3c897b88d4f0682d79dcdb50d5821df009f7ac3ca4c"
    family = "SalatStealer"
    file_name = "a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:54:41"
  condition:
    hash.sha256(0, filesize) == "d36b6e6c034d47ac22edb3c897b88d4f0682d79dcdb50d5821df009f7ac3ca4c"
}

rule MalwareBazaar_SalatStealer_077_a7c01cfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf"
    family = "SalatStealer"
    file_name = "a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:53:59"
  condition:
    hash.sha256(0, filesize) == "a7c01cfc75676d0810a8f82fa026e9dbf2a70a3d376bfd8fc9992c0d0f0de6cf"
}

rule MalwareBazaar_SalatStealer_078_1e90ed16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e90ed1645b77c242a241a55dc68a995a621c6d243b29a506d44940848b06f75"
    family = "SalatStealer"
    file_name = "ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:53:36"
  condition:
    hash.sha256(0, filesize) == "1e90ed1645b77c242a241a55dc68a995a621c6d243b29a506d44940848b06f75"
}

rule MalwareBazaar_SalatStealer_079_3e983375
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e983375c722a7420a1106f060f2a2ea467c9b76803e285555b2ff6be172598c"
    family = "SalatStealer"
    file_name = "d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:53:25"
  condition:
    hash.sha256(0, filesize) == "3e983375c722a7420a1106f060f2a2ea467c9b76803e285555b2ff6be172598c"
}

rule MalwareBazaar_unknown_080_ccb54c89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7"
    family = "unknown"
    file_name = "ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7"
    file_type = "elf"
    first_seen = "2026-10-29 00:53:22"
  condition:
    hash.sha256(0, filesize) == "ccb54c893ebd9a3818b1278f1a8863b6efbb7d637a7774a4a1f45d9c798ff4f7"
}

rule MalwareBazaar_SalatStealer_081_dd8a80b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd8a80b797340dc5a59fb28e84d1c66991b4c9a93476bf1135ebaf72a08c2b7c"
    family = "SalatStealer"
    file_name = "de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:53:00"
  condition:
    hash.sha256(0, filesize) == "dd8a80b797340dc5a59fb28e84d1c66991b4c9a93476bf1135ebaf72a08c2b7c"
}

rule MalwareBazaar_unknown_082_2246c9fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2246c9fe18c02eaebf758f7e380a7afb0e937d7ce346cfbd84590e519162f048"
    family = "unknown"
    file_name = "8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:52:54"
  condition:
    hash.sha256(0, filesize) == "2246c9fe18c02eaebf758f7e380a7afb0e937d7ce346cfbd84590e519162f048"
}

rule MalwareBazaar_SalatStealer_083_361b25f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "361b25f06372ce089a4c642d456ed79a3cff63be95a7284fa1f4c02179814539"
    family = "SalatStealer"
    file_name = "2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:52:46"
  condition:
    hash.sha256(0, filesize) == "361b25f06372ce089a4c642d456ed79a3cff63be95a7284fa1f4c02179814539"
}

rule MalwareBazaar_SalatStealer_084_ae23ef82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae23ef8293a5ce4389568b0d01f2ddd221257a5f7ac2bbc74afab2f22ddc1f57"
    family = "SalatStealer"
    file_name = "9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:52:37"
  condition:
    hash.sha256(0, filesize) == "ae23ef8293a5ce4389568b0d01f2ddd221257a5f7ac2bbc74afab2f22ddc1f57"
}

rule MalwareBazaar_SalatStealer_085_5407d15d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5407d15d2a8371590d72d90e363a70875ef25c9783a36b2a000dc9e298384a33"
    family = "SalatStealer"
    file_name = "12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:38"
  condition:
    hash.sha256(0, filesize) == "5407d15d2a8371590d72d90e363a70875ef25c9783a36b2a000dc9e298384a33"
}

rule MalwareBazaar_SalatStealer_086_ba010a8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b"
    family = "SalatStealer"
    file_name = "ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:37"
  condition:
    hash.sha256(0, filesize) == "ba010a8ad4e125febfc62dffc21858ee331940e2db684eb95c0c55ff9330fc2b"
}

rule MalwareBazaar_SalatStealer_087_c31031ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c31031efad2d7fe4d436a5a8b962f5dd1b64f3026e96b5ebe2dd184987a8d83f"
    family = "SalatStealer"
    file_name = "2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:30"
  condition:
    hash.sha256(0, filesize) == "c31031efad2d7fe4d436a5a8b962f5dd1b64f3026e96b5ebe2dd184987a8d83f"
}

rule MalwareBazaar_SalatStealer_088_d975b3ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad"
    family = "SalatStealer"
    file_name = "d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:29"
  condition:
    hash.sha256(0, filesize) == "d975b3ee5688134b43d13e08845623ae4ed7bcd57c6c2a3e139cb129b824e2ad"
}

rule MalwareBazaar_SalatStealer_089_de2acd1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f"
    family = "SalatStealer"
    file_name = "de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:23"
  condition:
    hash.sha256(0, filesize) == "de2acd1f5cb95f8525d2c96eb8bacc1cfd73dcd0550f382e60e73a1bc208151f"
}

rule MalwareBazaar_unknown_090_8ce2cd98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d"
    family = "unknown"
    file_name = "8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:16"
  condition:
    hash.sha256(0, filesize) == "8ce2cd98ef6ceeece8239936e4aea042c41807f632cd691d5091705bf6c0076d"
}

rule MalwareBazaar_SalatStealer_091_2edc2fc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca"
    family = "SalatStealer"
    file_name = "2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:10"
  condition:
    hash.sha256(0, filesize) == "2edc2fc9e82c7627a0d5e16cee1db326a8324701268d1af5bc5490fbbaae2eca"
}

rule MalwareBazaar_SalatStealer_092_63ddfeae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63ddfeae21aba49a10c0671baec865d0d3461fafdb684206cbdf9a0b39ba7055"
    family = "SalatStealer"
    file_name = "05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:51:06"
  condition:
    hash.sha256(0, filesize) == "63ddfeae21aba49a10c0671baec865d0d3461fafdb684206cbdf9a0b39ba7055"
}

rule MalwareBazaar_SalatStealer_093_b2badedf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2badedf10ef5707567ab632e5597691b63788540bb5beff9eda10681246d7d0"
    family = "SalatStealer"
    file_name = "d24016826df7ae508b90fdb6c9e7b6e8305245595ecfc2b506513f2f971cebd0.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:56"
  condition:
    hash.sha256(0, filesize) == "b2badedf10ef5707567ab632e5597691b63788540bb5beff9eda10681246d7d0"
}

rule MalwareBazaar_SalatStealer_094_9f472cb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff"
    family = "SalatStealer"
    file_name = "9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:30"
  condition:
    hash.sha256(0, filesize) == "9f472cb0397fc1255adb1a001a5424972c4f6547a72c7090cfefb0a48b5251ff"
}

rule MalwareBazaar_SalatStealer_095_12731350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f"
    family = "SalatStealer"
    file_name = "12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:24"
  condition:
    hash.sha256(0, filesize) == "12731350ac7d6cbe888e61b9754977bb85f2bbceb048170522237e94439cf17f"
}

rule MalwareBazaar_SalatStealer_096_2f393bd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b"
    family = "SalatStealer"
    file_name = "2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:17"
  condition:
    hash.sha256(0, filesize) == "2f393bd2c6801381eb8a2c78996ceef0355d4bc51d666769ab56ed3ffdef512b"
}

rule MalwareBazaar_SalatStealer_097_05cfac80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004"
    family = "SalatStealer"
    file_name = "05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:50:09"
  condition:
    hash.sha256(0, filesize) == "05cfac8008d88e131e7e81c7b58e783699080586792f54c9b0dfcda5738ed004"
}

rule MalwareBazaar_SalatStealer_098_947768ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "947768adbdf6fd085afb7e191cdd9c1c85df467b61adb9a57ffb078fd3043a26"
    family = "SalatStealer"
    file_name = "ec01c37f1b3e111eb0a75e7e267726c118677cb0064f1aeb97651e471351f128.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:49:47"
  condition:
    hash.sha256(0, filesize) == "947768adbdf6fd085afb7e191cdd9c1c85df467b61adb9a57ffb078fd3043a26"
}

rule MalwareBazaar_SalatStealer_099_873aacdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "873aacdd29d787b3bff0b4637b26b2155044c58bb86fab3dac7351e596692661"
    family = "SalatStealer"
    file_name = "d20a70b97cfda84fd416a92de64625ea2f21d1ae3986bbcfb204a92f65a7cecc.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:49:42"
  condition:
    hash.sha256(0, filesize) == "873aacdd29d787b3bff0b4637b26b2155044c58bb86fab3dac7351e596692661"
}

rule MalwareBazaar_SalatStealer_100_d6c1fad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6c1fad577dd6c2464c13f83a1a7955bfaa6a6f6405a41fe963dd7505f04fbd3"
    family = "SalatStealer"
    file_name = "b382f286a2a4499ea1fc55facd1989999dc3ffb405845744b99e1dd40ba4c397.exe"
    file_type = "exe"
    first_seen = "2026-10-29 00:49:36"
  condition:
    hash.sha256(0, filesize) == "d6c1fad577dd6c2464c13f83a1a7955bfaa6a6f6405a41fe963dd7505f04fbd3"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

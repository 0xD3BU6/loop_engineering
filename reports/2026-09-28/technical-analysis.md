# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-28

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 638 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 638 |
| Unique family labels | 5 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 61 |
| unknown | 29 |
| VShell | 7 |
| AgentTesla | 2 |
| Vidar | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 65 |
| exe | 23 |
| unknown | 7 |
| zip | 2 |
| macho | 1 |
| sh | 1 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `1cfb567d152cd29a`

| Field | Value |
|---|---|
| SHA-256 | `1cfb567d152cd29a387b15f700bb9c519421491d1a96595f5d1cec212817e5cd` |
| Family label | `unknown` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-09-28 05:32:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8d8b88f85b0fba2f68dea98209bbdf4` |
| SHA-1 | `70e7881dedf1616776ef902227fc9885658edbb3` |
| SHA-256 | `1cfb567d152cd29a387b15f700bb9c519421491d1a96595f5d1cec212817e5cd` |
| SHA3-384 | `12af6454ed32c65c0be7431718f1b1895b4ea1407a20d0a3013b1664420492a9f9c95fdf47556a3fe6b1da62780a1f5a` |
| TLSH | `T18BD37DC9F243D5F5E4960471003AAB265F32E47A643BEA42D77A3931EC639019E1FB6C` |
| TELFHASH | `t12b8115fa7e6e0de9b750ac05d70e1f12ee0aa6b724a031b905e3596136ffe4140b6c35` |
| SSDEEP | `3072:FrgyT0NoVJmKL4kLYefB36gKi4lzNnRfkVhe:FrgyYWJ/kC36gj4FXfkVhe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_1cfb567d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cfb567d152cd29a387b15f700bb9c519421491d1a96595f5d1cec212817e5cd"
    family = "unknown"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-09-28 05:32:15"
  condition:
    hash.sha256(0, filesize) == "1cfb567d152cd29a387b15f700bb9c519421491d1a96595f5d1cec212817e5cd"
}
```

### Sample 2: `cc89b568a8de9de0`

| Field | Value |
|---|---|
| SHA-256 | `cc89b568a8de9de006097c17fbbb07609ee9c7d9c05965f3212eae1274cd0077` |
| Family label | `Mirai` |
| File name | `f076c5f295a7c33a.bin` |
| File type | `elf` |
| First seen | `2026-09-28 05:25:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18d7dabfc2e6877f80951f9ceeade7f2` |
| SHA-1 | `0e0c90d97a10146d847aa34c8cda0afdf2ba4a69` |
| SHA-256 | `cc89b568a8de9de006097c17fbbb07609ee9c7d9c05965f3212eae1274cd0077` |
| SHA3-384 | `58129e9a3d0eb670d638bafcd4a9a2fd2875cb815aa751da106dace976a2255e67406726c867a29605e9c4e80f6770a4` |
| TLSH | `T12ED4F75A6E619F3DF274C7718BF38A30D26A279207E1C6C1E1ECE1054E2029D5D6FB68` |
| TELFHASH | `t1a5715ec77db632d87d8c424a47cdea300d5a085e1af61a3ace5651cb871b7c22fb6c12` |
| SSDEEP | `6144:fI8E8az72Gu4ZXOilcRlF+6cKJuvu8mo3OLu+UHd3ZYkMMkEqyNAhR23nuDHJL5H:f+PjV+vdcnvQucm6Visj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_cc89b568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc89b568a8de9de006097c17fbbb07609ee9c7d9c05965f3212eae1274cd0077"
    family = "Mirai"
    file_name = "f076c5f295a7c33a.bin"
    file_type = "elf"
    first_seen = "2026-09-28 05:25:37"
  condition:
    hash.sha256(0, filesize) == "cc89b568a8de9de006097c17fbbb07609ee9c7d9c05965f3212eae1274cd0077"
}
```

### Sample 3: `054eb80aa4339f1a`

| Field | Value |
|---|---|
| SHA-256 | `054eb80aa4339f1a8b875ccfd9d9af9b34a628d0ef993ea940bdfbb1d266f828` |
| Family label | `unknown` |
| File name | `054eb80aa4339f1a.bin` |
| File type | `macho` |
| First seen | `2026-09-28 05:25:18` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6f485d4b16cb8c3d657833b7be55685` |
| SHA-1 | `19d243665483221cbcfa9dcff840da91e85bf435` |
| SHA-256 | `054eb80aa4339f1a8b875ccfd9d9af9b34a628d0ef993ea940bdfbb1d266f828` |
| SHA3-384 | `07835bcfd28f9fe2049826d2e58a215bbea3e97bfaa420d76f177e5ea79b852fb3a333fa7653d17bef605a1f80594e99` |
| TLSH | `T11DE23E43AF4C9965C26D42301AF70BC6A616F5B09EE16B875350C7217EE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvURVZqDDt0TOTLZ0BbFw2DHKk6XrMclSibFqAMcl:z4ZZXvv4VZMt0TO2bVL/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_054eb80a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "054eb80aa4339f1a8b875ccfd9d9af9b34a628d0ef993ea940bdfbb1d266f828"
    family = "unknown"
    file_name = "054eb80aa4339f1a.bin"
    file_type = "macho"
    first_seen = "2026-09-28 05:25:18"
  condition:
    hash.sha256(0, filesize) == "054eb80aa4339f1a8b875ccfd9d9af9b34a628d0ef993ea940bdfbb1d266f828"
}
```

### Sample 4: `c1634055538b7bf7`

| Field | Value |
|---|---|
| SHA-256 | `c1634055538b7bf7d548c86b605f7f6be70f506a0ea7ae99ae6a1525fce0c9fd` |
| Family label | `unknown` |
| File name | `c1634055538b7bf7.bin` |
| File type | `unknown` |
| First seen | `2026-09-28 05:25:10` |
| Reporter | `Tuxxin` |
| Tags | `powershell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67a1779cb81ec77dfe0d5ba26176b1b3` |
| SHA-256 | `c1634055538b7bf7d548c86b605f7f6be70f506a0ea7ae99ae6a1525fce0c9fd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_c1634055
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1634055538b7bf7d548c86b605f7f6be70f506a0ea7ae99ae6a1525fce0c9fd"
    family = "unknown"
    file_name = "c1634055538b7bf7.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 05:25:10"
  condition:
    hash.sha256(0, filesize) == "c1634055538b7bf7d548c86b605f7f6be70f506a0ea7ae99ae6a1525fce0c9fd"
}
```

### Sample 5: `f076c5f295a7c33a`

| Field | Value |
|---|---|
| SHA-256 | `f076c5f295a7c33a39eea8a5047107c770832b8d6680f8b866795080b76ac853` |
| Family label | `Mirai` |
| File name | `f076c5f295a7c33a.bin` |
| File type | `elf` |
| First seen | `2026-09-28 05:25:00` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c17837665a34695495b08a7189311e30` |
| SHA-1 | `b10af69120f611ee043180ff0d48b8e998e9c80c` |
| SHA-256 | `f076c5f295a7c33a39eea8a5047107c770832b8d6680f8b866795080b76ac853` |
| SHA3-384 | `83f2725926b1c06db494557866d1bf7583606cfc638cc4ca0014da40b050bf94f01eeede58f617d401c85560d733fe99` |
| TLSH | `T13C3412ECC8201E8344490DB973DAE6879C9C553DEEDD9E661218FD11D6B230F2972AE3` |
| SSDEEP | `6144://FmixsF5mDbH9tCeQAa1TElsEz+xYtRrDogWvgIL1U:/G23H9tCeQFVa+xYt1bQgy1U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_f076c5f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f076c5f295a7c33a39eea8a5047107c770832b8d6680f8b866795080b76ac853"
    family = "Mirai"
    file_name = "f076c5f295a7c33a.bin"
    file_type = "elf"
    first_seen = "2026-09-28 05:25:00"
  condition:
    hash.sha256(0, filesize) == "f076c5f295a7c33a39eea8a5047107c770832b8d6680f8b866795080b76ac853"
}
```

### Sample 6: `8d0e82dc4ffc6012`

| Field | Value |
|---|---|
| SHA-256 | `8d0e82dc4ffc6012fb6f6513feb7324672b5b26436ccdf2fd237fc03084ae109` |
| Family label | `Mirai` |
| File name | `8d0e82dc4ffc6012.bin` |
| File type | `elf` |
| First seen | `2026-09-28 05:24:51` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e04a8fc82393ccd9e192d79db780a3b` |
| SHA-1 | `2dcb62a2ef62c44f5f4065cbe0986b2a4f606afc` |
| SHA-256 | `8d0e82dc4ffc6012fb6f6513feb7324672b5b26436ccdf2fd237fc03084ae109` |
| SHA3-384 | `cef330a1d562e8507f62ba2c425866530cb54e40a892bb5017d746f7552aa4561378997e94cd411ccd61e393b20b1249` |
| TLSH | `T1E9A4BF32C0B55CE5C0B39375BCB5D9744B22784452AB1DF3AADEEA190893ED8B7193B0` |
| SSDEEP | `6144:sks8/k8s0vRYfAvFSG3ttkONSI2g/IesUcj8rZQijghYVIYzWM3:skL/kuRYovF5wONSI2g/AwZDjgh8qM3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_8d0e82dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d0e82dc4ffc6012fb6f6513feb7324672b5b26436ccdf2fd237fc03084ae109"
    family = "Mirai"
    file_name = "8d0e82dc4ffc6012.bin"
    file_type = "elf"
    first_seen = "2026-09-28 05:24:51"
  condition:
    hash.sha256(0, filesize) == "8d0e82dc4ffc6012fb6f6513feb7324672b5b26436ccdf2fd237fc03084ae109"
}
```

### Sample 7: `a34872ae34ec6e4d`

| Field | Value |
|---|---|
| SHA-256 | `a34872ae34ec6e4de081cc9370d9f538348fd3403de9994f6fc60ec8a227a2c7` |
| Family label | `Mirai` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-09-28 05:23:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20cea8885287f58f9b9dcea517c100d4` |
| SHA-1 | `767478c4fd27fcb19c3308df2ff3e8fa872c451b` |
| SHA-256 | `a34872ae34ec6e4de081cc9370d9f538348fd3403de9994f6fc60ec8a227a2c7` |
| SHA3-384 | `620cd4869523f7ed891b5a166f12fbbefad0ceeae24d4d6ee3013da0cf5281113b0f2735c07e22eb033a4d8dde2067ff` |
| TLSH | `T1B9355C46EF406FEBC49FCD30492EC31721EDE8CB42D5A62971BC4A8C7A5D3590AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:ApvR6ZM35dQ4ZmHd7dcCoLJTxwpTmVXxTCnOKW8x:Y6QS97FixxxxTCnzx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_a34872ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a34872ae34ec6e4de081cc9370d9f538348fd3403de9994f6fc60ec8a227a2c7"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-28 05:23:25"
  condition:
    hash.sha256(0, filesize) == "a34872ae34ec6e4de081cc9370d9f538348fd3403de9994f6fc60ec8a227a2c7"
}
```

### Sample 8: `5044a47978851eaf`

| Field | Value |
|---|---|
| SHA-256 | `5044a47978851eaf608c27d3ba94199efbb9da8bb251d2c5134ae4ae340cf91e` |
| Family label | `unknown` |
| File name | `data.dat` |
| File type | `exe` |
| First seen | `2026-09-28 05:19:54` |
| Reporter | `ghozt` |
| Tags | `ClickFix, encrypter payload, exe, Loader, PLKG, umpdc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0951d496f235716166e90733ff239ab` |
| SHA-1 | `2606d74c0f7eea82c01dc4db15b2f7af7cea3aad` |
| SHA-256 | `5044a47978851eaf608c27d3ba94199efbb9da8bb251d2c5134ae4ae340cf91e` |
| SHA3-384 | `5538e16a0aadbd51a87d526ea32b00da4eec24144648c94460efc8850cd5c3a6bbe39523610c5a851d40a1688f4c454f` |
| IMPHASH | `17134faceb5251929dd81df8dee2c15d` |
| TLSH | `T16DE3C05E326434E5C47ED1BEC1938A5AE271B835132266FF46E0D27D1A37AD1223EF06` |
| SSDEEP | `3072:5GGd4wj+qJlDtXnnghbNbBzbGw9wJ9YWN2Z2MFJMq94URJg6bHxmVRBWXWs:cI4wj+qJlJnWbNbB3Gw9wT0ooJMqeU7z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_5044a479
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5044a47978851eaf608c27d3ba94199efbb9da8bb251d2c5134ae4ae340cf91e"
    family = "unknown"
    file_name = "data.dat"
    file_type = "exe"
    first_seen = "2026-09-28 05:19:54"
  condition:
    hash.sha256(0, filesize) == "5044a47978851eaf608c27d3ba94199efbb9da8bb251d2c5134ae4ae340cf91e"
}
```

### Sample 9: `68f32b5f08ba6234`

| Field | Value |
|---|---|
| SHA-256 | `68f32b5f08ba6234fdf9f8a08d6bb28dab2418b0af33010e3699b6155f4d4ea0` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-28 05:19:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5120974bc3c05d7b5ed06307a5f69dd1` |
| SHA-1 | `ece49dda960a7343e3914db0eb56ccb61650a9c6` |
| SHA-256 | `68f32b5f08ba6234fdf9f8a08d6bb28dab2418b0af33010e3699b6155f4d4ea0` |
| SHA3-384 | `c26de194c43169810b84af35031eab4447ca5edd8d2a4df1ababbe08529974dbc543290771a291c5a37e8df6a1b84f97` |
| TLSH | `T176456C5DFD0F3C43D2CAE23EDB4A83E47127B0D4D66311A336C2035DE68999D8B9295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:Jw9ghjWVQmLjFl1KQeu5fY4SJa6Shgk2g/HVh:JKWWpjxuNJI6ShgkzVh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_68f32b5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68f32b5f08ba6234fdf9f8a08d6bb28dab2418b0af33010e3699b6155f4d4ea0"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-28 05:19:15"
  condition:
    hash.sha256(0, filesize) == "68f32b5f08ba6234fdf9f8a08d6bb28dab2418b0af33010e3699b6155f4d4ea0"
}
```

### Sample 10: `8d53aad5ab3bc826`

| Field | Value |
|---|---|
| SHA-256 | `8d53aad5ab3bc826ce9de6540c591bcefc676b7b02258cc3a2dafd115d416b66` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-09-28 05:19:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ebf5a819e9b623215e2cac876a94329` |
| SHA-1 | `111d9f63da798ac0182e779dce1d8fcb66d6b88c` |
| SHA-256 | `8d53aad5ab3bc826ce9de6540c591bcefc676b7b02258cc3a2dafd115d416b66` |
| SHA3-384 | `bbe93accb0118a4a94ffbf5fb360960c32d576aacc020d92f738ee0580beb454a14871fe72f662ba92a47cd330e398fe` |
| TLSH | `T154F39DB7CC262E68C565D1B0F071DF781F53A99582471FAA95B7C2748083E8EF9093B8` |
| SSDEEP | `3072:e5gu36Q7vsD0WpuSuCCC/2Zw+CK0Wnrgq02ud:X0sgWoSuCCVLtnra2ud` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_8d53aad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d53aad5ab3bc826ce9de6540c591bcefc676b7b02258cc3a2dafd115d416b66"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-09-28 05:19:14"
  condition:
    hash.sha256(0, filesize) == "8d53aad5ab3bc826ce9de6540c591bcefc676b7b02258cc3a2dafd115d416b66"
}
```

### Sample 11: `e4fcc92bcfdeae15`

| Field | Value |
|---|---|
| SHA-256 | `e4fcc92bcfdeae1562afba403b309f5db516f5872cd4dc302a9975be4f0dbe91` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-09-28 05:19:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abd36214290972cd7434e91b6f0df72d` |
| SHA-1 | `1063cbc4fb8bb5d95f56269a0dbc20c5e481d290` |
| SHA-256 | `e4fcc92bcfdeae1562afba403b309f5db516f5872cd4dc302a9975be4f0dbe91` |
| SHA3-384 | `919ffab6341b4f8587c7d27e31ff28b5c131fa218158db05cee62efbd8a1988c0e374935fa8eb091de8d3a4fa1c2232d` |
| TLSH | `T173041745F8419B27C6D316BBFB5E428D372A17A8D3EE7202DD215B2037CB56B0E3A542` |
| TELFHASH | `t152e06812ff9417dd23c2802151ee63367694b4226b03385566d97d1e8b92e82b213817` |
| SSDEEP | `3072:pfce0o4l/8YsDpXLn0Q4tsRjDutbT2QMJJAwD:pfr0o26Fr0Q4eRjDutH2HJAw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_e4fcc92b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4fcc92bcfdeae1562afba403b309f5db516f5872cd4dc302a9975be4f0dbe91"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-09-28 05:19:12"
  condition:
    hash.sha256(0, filesize) == "e4fcc92bcfdeae1562afba403b309f5db516f5872cd4dc302a9975be4f0dbe91"
}
```

### Sample 12: `e6a22232324c004a`

| Field | Value |
|---|---|
| SHA-256 | `e6a22232324c004a57898e82cdc2a48dc34b4847476979c551f0b1db46b428b6` |
| Family label | `unknown` |
| File name | `umpdc.dll` |
| File type | `exe` |
| First seen | `2026-09-28 05:18:46` |
| Reporter | `ghozt` |
| Tags | `ClickFix, dll-sideloading, exe, Loader, PLKG, umpdc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0642ee51ce2a8e1f21c9ccdf65b06401` |
| SHA-1 | `37ecc940c95e366fced7547b522765083f51476e` |
| SHA-256 | `e6a22232324c004a57898e82cdc2a48dc34b4847476979c551f0b1db46b428b6` |
| SHA3-384 | `68a40cc480bca0df5bfbd2e6eb992e04c6beb3c4934b31da42e5e18a3210dbdeb09a43df8bfa73652f98790a9446e7af` |
| IMPHASH | `b777b26decbff8608d4e274aa267acc5` |
| TLSH | `T16DE2E885A05156FDD006D736C036B7E382A83C35072A4DFF8E9E99A92B364E23736476` |
| SSDEEP | `384:cKbpSJki6ycSC5iJV0DUVJ+WHNeKYkpEXPvTUjOQJr4fa:cSi6ycSC5cqUCRwwPvTUci` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_e6a22232
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6a22232324c004a57898e82cdc2a48dc34b4847476979c551f0b1db46b428b6"
    family = "unknown"
    file_name = "umpdc.dll"
    file_type = "exe"
    first_seen = "2026-09-28 05:18:46"
  condition:
    hash.sha256(0, filesize) == "e6a22232324c004a57898e82cdc2a48dc34b4847476979c551f0b1db46b428b6"
}
```

### Sample 13: `489b07a8572e53ce`

| Field | Value |
|---|---|
| SHA-256 | `489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9` |
| Family label | `unknown` |
| File name | `489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9` |
| File type | `elf` |
| First seen | `2026-09-28 05:17:19` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `722bf68d9fa7ed2db630800bb6b73dfd` |
| SHA-1 | `a80a83ec2b4f6e6f8eb4855107a185f6a1bf034c` |
| SHA-256 | `489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9` |
| SHA3-384 | `a0b449f0fd7a6912a334890e19c7a931f67e225573c00b2a98376ea5f139149f774dfc15dc4f66e6584d530e54b85f9d` |
| TLSH | `T1DCD3135293230C0FC02578FE7E5AE61A29862A7A24CE409D46F5D77A5FB7084DEB1723` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxI:biMYFJvw6Yh0b1gKobtCGCmCRlrisf4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_489b07a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9"
    family = "unknown"
    file_name = "489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9"
    file_type = "elf"
    first_seen = "2026-09-28 05:17:19"
  condition:
    hash.sha256(0, filesize) == "489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9"
}
```

### Sample 14: `8d379f234d9ca08f`

| Field | Value |
|---|---|
| SHA-256 | `8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897` |
| Family label | `Mirai` |
| File name | `8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897` |
| File type | `elf` |
| First seen | `2026-09-28 05:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dd54bc7c88a82fc35cd5604093e5c42` |
| SHA-1 | `d6de341c1876202de9d1d70f525a9de766abf22e` |
| SHA-256 | `8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897` |
| SHA3-384 | `0195f5aa41ecd8d0bf681cbd77d26fec8c14cb892dab4faab5084e11634fdb38b112f7951d8e835b0d514d3884509366` |
| TLSH | `T10924198AFC81AF5595C126BBFE2E418A331317B8E2EE71129D145F2477CA94F0F3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqF:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_8d379f23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897"
    family = "Mirai"
    file_name = "8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897"
    file_type = "elf"
    first_seen = "2026-09-28 05:17:13"
  condition:
    hash.sha256(0, filesize) == "8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897"
}
```

### Sample 15: `0a230b42310fbbb5`

| Field | Value |
|---|---|
| SHA-256 | `0a230b42310fbbb5655341fd2a2bf4eb680babf360f76c796f9e1df374ee396c` |
| Family label | `Mirai` |
| File name | `auroraint.spc` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:52` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a652bba6ee1f11166d64184df96d7bb` |
| SHA-1 | `cfa6098beb30d5e5d3de0f4cd2f2354cc9dc05d4` |
| SHA-256 | `0a230b42310fbbb5655341fd2a2bf4eb680babf360f76c796f9e1df374ee396c` |
| SHA3-384 | `c2b71f3492068ff780317bcbdd370ce61bfb26c8696c5dd49a124ecc356ab6e5d00296a5a19221974dcc46126bb65960` |
| TLSH | `T128335A22A9791E1BC0D0F47A62F78729B2F5070F25A88B5E3D620F4EFF214D0556B2B5` |
| SSDEEP | `768:gI4ojWM7N0h+q9G3xyJZEKmEOUp0yNNOCgvbmO+hZ2+IFmM:f4o3N0h+SG3xy7EKVOUp5NNGkhI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_0a230b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a230b42310fbbb5655341fd2a2bf4eb680babf360f76c796f9e1df374ee396c"
    family = "Mirai"
    file_name = "auroraint.spc"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:52"
  condition:
    hash.sha256(0, filesize) == "0a230b42310fbbb5655341fd2a2bf4eb680babf360f76c796f9e1df374ee396c"
}
```

### Sample 16: `e829956b213bfb5d`

| Field | Value |
|---|---|
| SHA-256 | `e829956b213bfb5d36b583b9fbd1a08bf1d1ee9a2942dac23f83fd0b08c1c605` |
| Family label | `Mirai` |
| File name | `auroraint.x86` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:52` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e15393cf401e888c39bea9890989b36f` |
| SHA-1 | `ebcf573cc18b3e77f1349beb34c097f3cead17c4` |
| SHA-256 | `e829956b213bfb5d36b583b9fbd1a08bf1d1ee9a2942dac23f83fd0b08c1c605` |
| SHA3-384 | `d6400b2164e945ba0d67f43ef3afd425ace2356293433fa948f88179f823aa9812a9f91fdbdc5ec27c1080130de7a886` |
| TLSH | `T1C0235CC5A447D9FCEC190A712177FF319AF6E93E1198DA83C3599D72E942602E9032AC` |
| TELFHASH | `t1a511483a1e364dd8f7d01540c75ddbe0483ee73714e1bae044b219155be1e5220bdc7a` |
| SSDEEP | `768:r+WtjNuFWGttXEsLk+sd6bVHUzFoeWfd/0g6SDZkoKo:r+csttXEsY+sdWVHUjWV/0g6OZk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_e829956b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e829956b213bfb5d36b583b9fbd1a08bf1d1ee9a2942dac23f83fd0b08c1c605"
    family = "Mirai"
    file_name = "auroraint.x86"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:52"
  condition:
    hash.sha256(0, filesize) == "e829956b213bfb5d36b583b9fbd1a08bf1d1ee9a2942dac23f83fd0b08c1c605"
}
```

### Sample 17: `35e93cbd08b07085`

| Field | Value |
|---|---|
| SHA-256 | `35e93cbd08b07085ca4d652ba6cf6e0402f64ed453717884231eb830d8e551ba` |
| Family label | `Mirai` |
| File name | `auroraint.sh4` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:52` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7dc4f1ae9fc738320d86f7ff2d6aba7` |
| SHA-1 | `73b0f0ab11cb8de22b3562704772395df0f19a45` |
| SHA-256 | `35e93cbd08b07085ca4d652ba6cf6e0402f64ed453717884231eb830d8e551ba` |
| SHA3-384 | `de7d6c0d6f08b3d182c410ede9642b7a2e6d23d9ccb376d093acce8f7e0f9ac80f0a4dc016ba972f5af45dfbeeeb72d6` |
| TLSH | `T196239EA7C43C7DD4D14992B8AD248A3C5B23E016A6933EF5BA4785628047EECF60D3F5` |
| SSDEEP | `768:Da1/jptstaT85n1OswtgZ40l7qZrKyP7GwQ9qB5m0GnxrACeoVJm1CtmE:Da1/3s+YDwtgF2KLe52xMC/m1Ct` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_35e93cbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e93cbd08b07085ca4d652ba6cf6e0402f64ed453717884231eb830d8e551ba"
    family = "Mirai"
    file_name = "auroraint.sh4"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:52"
  condition:
    hash.sha256(0, filesize) == "35e93cbd08b07085ca4d652ba6cf6e0402f64ed453717884231eb830d8e551ba"
}
```

### Sample 18: `a04ba45d395b13d7`

| Field | Value |
|---|---|
| SHA-256 | `a04ba45d395b13d7ef9f838711181f375bbb752bfc50d2aa33b0bc6ef8b30908` |
| Family label | `Mirai` |
| File name | `auroraint.mpsl` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:50` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7669a15737596f45ca124416713ef2bd` |
| SHA-1 | `7b569fbca2fd81bde0ab131f1d2552cff0d13e60` |
| SHA-256 | `a04ba45d395b13d7ef9f838711181f375bbb752bfc50d2aa33b0bc6ef8b30908` |
| SHA3-384 | `2a8f5f809e974d1a676285548d63e190106c67439ad74dc6939b9d41993bf7486b644b364c3cd50d880e4ea23230af98` |
| TLSH | `T103639209BF611FF7EC6FDC374AE9274525DD641A21A83B397A30D818F24A24B19E3874` |
| SSDEEP | `768:zlDScD5GY2ne8i2Sxt9yYExR15IaI5vTemle5Re5bbvuH5XiANe1j9WE:zlDSC5G9eb249FKnI5fl8RWbriq1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_a04ba45d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a04ba45d395b13d7ef9f838711181f375bbb752bfc50d2aa33b0bc6ef8b30908"
    family = "Mirai"
    file_name = "auroraint.mpsl"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:50"
  condition:
    hash.sha256(0, filesize) == "a04ba45d395b13d7ef9f838711181f375bbb752bfc50d2aa33b0bc6ef8b30908"
}
```

### Sample 19: `10c38bcfce904378`

| Field | Value |
|---|---|
| SHA-256 | `10c38bcfce9043786c8660f18d1cd4d8aef001923f841c4ef104b84d12244d65` |
| Family label | `Mirai` |
| File name | `auroraint.ppc` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:49` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a7b7f5f0ede37aeb83f9d9cd0e265ba` |
| SHA-1 | `18a7132dc74a581c87397d21509a6811423ab016` |
| SHA-256 | `10c38bcfce9043786c8660f18d1cd4d8aef001923f841c4ef104b84d12244d65` |
| SHA3-384 | `cdf070ce7a7b849f2993fdb4323fb4c4f180eb9de4520a377aa64544eb14356e241f03d1de09f691fbad389d0666ead8` |
| TLSH | `T1FD234B42365C0E47D1A65BF4293F27E083FEE9A020F4F588260F8A868575F77518AEDD` |
| SSDEEP | `768:EK4YZ3fcca/hDZrOERoFkVEEwPC12n+SG6cCBqO0/zttABU0sRW7GEZ:WcUZrDzEEwPC1Y7GpQM2vs87v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_10c38bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10c38bcfce9043786c8660f18d1cd4d8aef001923f841c4ef104b84d12244d65"
    family = "Mirai"
    file_name = "auroraint.ppc"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:49"
  condition:
    hash.sha256(0, filesize) == "10c38bcfce9043786c8660f18d1cd4d8aef001923f841c4ef104b84d12244d65"
}
```

### Sample 20: `a06fb076e98a4d81`

| Field | Value |
|---|---|
| SHA-256 | `a06fb076e98a4d81cfb5631bc9162ce01cdeab53b0a0f1afc5ead5ac1adfbda4` |
| Family label | `Mirai` |
| File name | `auroraint.mips` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:48` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1107f2aadd559aec7df8e77889c9f8ac` |
| SHA-1 | `7f3d02ab539b5bac0f8730ef0d8e8759e12c3010` |
| SHA-256 | `a06fb076e98a4d81cfb5631bc9162ce01cdeab53b0a0f1afc5ead5ac1adfbda4` |
| SHA3-384 | `6ed57341eed2d3e87dd5e26de93a5212363a6f426fb726933b3c4176a0f09a5bb65e87d5aa29ff83020773e1f6b4689a` |
| TLSH | `T11863954E6E719FBCFBA8873447B75F209248339666E1C684E15CEA011E7030E745FBA9` |
| TELFHASH | `t11f014f54183817f093844d9e6bddff35e4a544df9a691f3bcd40e59ba7216869c00c2c` |
| SSDEEP | `1536:d8aCKgyqz+SIjtr3st2jpoJtFH9g7rt9K01eev:2HhkJr3fCJtbg7rt9KkHv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_a06fb076
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a06fb076e98a4d81cfb5631bc9162ce01cdeab53b0a0f1afc5ead5ac1adfbda4"
    family = "Mirai"
    file_name = "auroraint.mips"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:48"
  condition:
    hash.sha256(0, filesize) == "a06fb076e98a4d81cfb5631bc9162ce01cdeab53b0a0f1afc5ead5ac1adfbda4"
}
```

### Sample 21: `6c126368093a4f96`

| Field | Value |
|---|---|
| SHA-256 | `6c126368093a4f965baf21bdc5458e5512e2dbcd83ff9c4e7e93707723fa4975` |
| Family label | `Mirai` |
| File name | `auroraint.m68k` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:47` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8aba024de38cfcedc0ffaf4539b4732d` |
| SHA-1 | `3890bd5a2669cb8bd4147e7a11ed97f603493a70` |
| SHA-256 | `6c126368093a4f965baf21bdc5458e5512e2dbcd83ff9c4e7e93707723fa4975` |
| SHA3-384 | `af5e697ea65d701fcc20a89dc4b09cc3f2c128d561848308069455761e83f0009b183652795fc70b6bc99323e206d724` |
| TLSH | `T1893318D6B4019E7CF85BEFBA81224909FA71621151930B3B237FFD93AC322648D52D47` |
| SSDEEP | `1536:OVrztlv7fl5LuSNwLLTCHnn2CP6V6579f84:yvllu/TAnk65xb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_6c126368
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c126368093a4f965baf21bdc5458e5512e2dbcd83ff9c4e7e93707723fa4975"
    family = "Mirai"
    file_name = "auroraint.m68k"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:47"
  condition:
    hash.sha256(0, filesize) == "6c126368093a4f965baf21bdc5458e5512e2dbcd83ff9c4e7e93707723fa4975"
}
```

### Sample 22: `d8037f6ab18f0bac`

| Field | Value |
|---|---|
| SHA-256 | `d8037f6ab18f0bac96cc409e0dbc247dc328f60ea63885e09c69010b954ed308` |
| Family label | `Mirai` |
| File name | `auroraint.arm7` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:47` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4527094b061db566fba21d7f25683501` |
| SHA-1 | `51518a6f13dbd25312d122b18130a5399f763e8a` |
| SHA-256 | `d8037f6ab18f0bac96cc409e0dbc247dc328f60ea63885e09c69010b954ed308` |
| SHA3-384 | `42e61f27cae5c024f3a157b770a0207bb689ea43ef7196bd4670275f48209c2a872a6c90205c81b690f7d264972d467a` |
| TLSH | `T16F53F946FC818A05C5C513BAFA2E118E33136779E2DF73129E106F2477CA96B0E7B952` |
| TELFHASH | `t1d1f00243dfcc465c27e00194818e01199bc83ce49a412342df7f3d4e4e10c90b025139` |
| SSDEEP | `1536:M5niA5dB9VT2iITmElkmU+WhQczKGk6VE6BJwLxIUiwnBdZWGJ:Sdphqm0/U+WOczKQVvunBdZWGJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_d8037f6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8037f6ab18f0bac96cc409e0dbc247dc328f60ea63885e09c69010b954ed308"
    family = "Mirai"
    file_name = "auroraint.arm7"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:47"
  condition:
    hash.sha256(0, filesize) == "d8037f6ab18f0bac96cc409e0dbc247dc328f60ea63885e09c69010b954ed308"
}
```

### Sample 23: `daa2fba016ccc40e`

| Field | Value |
|---|---|
| SHA-256 | `daa2fba016ccc40ea64e1f3377605d6e2d281efc850b323959eed26a99593289` |
| Family label | `Mirai` |
| File name | `auroraint.arm` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:46` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03b1b6960d7e594c4abe4875c787fb1b` |
| SHA-1 | `4b4b97d321fd5e336b96b7ece7a46d170b6f87b2` |
| SHA-256 | `daa2fba016ccc40ea64e1f3377605d6e2d281efc850b323959eed26a99593289` |
| SHA3-384 | `39f0cd12e798ba2010ab11839c07b3ec3d72e50f7a67f89ae1b6666b4d13c5d749b103853136bc05ea893bed46f0beef` |
| TLSH | `T180331991BC819902CAD82376FA2E01CD332263E9D1DF72579D226F1137DA82F0D7B652` |
| TELFHASH | `t17e11e3358d9a5ebcb7a0c189830e2258595d73f41600365ced6b6b8f97726c0768c42e` |
| SSDEEP | `768:h8GLInGoXP3624ILThNGzGUiTkVpCDL0IIesBJNoivtBRBNwoxBA1s39AxE:KMInGoX/r5xUiYVpu0IIeyJH3fxeC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_daa2fba0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daa2fba016ccc40ea64e1f3377605d6e2d281efc850b323959eed26a99593289"
    family = "Mirai"
    file_name = "auroraint.arm"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:46"
  condition:
    hash.sha256(0, filesize) == "daa2fba016ccc40ea64e1f3377605d6e2d281efc850b323959eed26a99593289"
}
```

### Sample 24: `64eeacfbc06e18ef`

| Field | Value |
|---|---|
| SHA-256 | `64eeacfbc06e18ef02a1e49948804f760c6b2869b88f7416a8737846114dca06` |
| Family label | `Mirai` |
| File name | `auroraint.arm5n` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:46` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2f04a647f28437a5b8ba7c11c2227bd` |
| SHA-1 | `efc18f2ce2a710a4b6732a5efab1b50d62b36341` |
| SHA-256 | `64eeacfbc06e18ef02a1e49948804f760c6b2869b88f7416a8737846114dca06` |
| SHA3-384 | `2a24112bb422db301dce4ecb8c35d4cee34d51cf8d5ca0864f65ac1518f400d54e39507e6f671e630a5bb499a0911771` |
| TLSH | `T11E231852BC828A56C6D42376FA6E418D3322B3E9D1DE7267CC205B013AC991F4D77B92` |
| TELFHASH | `t120e02600bc658b5988d79a74ad9d07b49901621254668b14cf10d6f0983f458a308e5a` |
| SSDEEP | `768:dbf1CAITb1lI4z8g8IgrgEVm9YrLOHsXBuepi0eRqh1V+6ogRvXjxBNyE9g:BYAITvBbHgJLOWB9pi0eRuP+GzB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_64eeacfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64eeacfbc06e18ef02a1e49948804f760c6b2869b88f7416a8737846114dca06"
    family = "Mirai"
    file_name = "auroraint.arm5n"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:46"
  condition:
    hash.sha256(0, filesize) == "64eeacfbc06e18ef02a1e49948804f760c6b2869b88f7416a8737846114dca06"
}
```

### Sample 25: `2ad4002ae9000abe`

| Field | Value |
|---|---|
| SHA-256 | `2ad4002ae9000abeca0cae4c69acb20df6b2eea07a03ac464443e5eaf2bee3ef` |
| Family label | `Mirai` |
| File name | `aurora.x86` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:46` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f41b1039e235817e42011cf2194f13e8` |
| SHA-1 | `9464e43f6b8298b382674c6b80d94daecd0d5cc5` |
| SHA-256 | `2ad4002ae9000abeca0cae4c69acb20df6b2eea07a03ac464443e5eaf2bee3ef` |
| SHA3-384 | `0cafd18533f573902bdc3c1f24ab054c235a7bcf4b020c317e33f0d04bc1742f8c60012f9ae26b0825b61c69f8067ff0` |
| TLSH | `T10E435BC5A563E9FCDC1015393077FF7256B6E93E1028EBC7D7A8AD32A941A02D80729D` |
| TELFHASH | `t17d115bfb2d7e0dd5b7d99840830e2f71197ae63b25a073a00572995422a3dc462bac3e` |
| SSDEEP | `768:CoXHT2eWv2WAb3Mn6zDjbr63UM7Jwv3U/HYlstWt1XfWA+LtOfRc3Eo:CojZWAb3O6zDHr63UywviJWTF+Lt+Rc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_2ad4002a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ad4002ae9000abeca0cae4c69acb20df6b2eea07a03ac464443e5eaf2bee3ef"
    family = "Mirai"
    file_name = "aurora.x86"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:46"
  condition:
    hash.sha256(0, filesize) == "2ad4002ae9000abeca0cae4c69acb20df6b2eea07a03ac464443e5eaf2bee3ef"
}
```

### Sample 26: `2ef818af2a9b1ae9`

| Field | Value |
|---|---|
| SHA-256 | `2ef818af2a9b1ae9990c10f919480c58c875b6ab8736a1c54e34557b259339d9` |
| Family label | `Mirai` |
| File name | `aurora.sh4` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:45` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50431e865369298ca28ab9f78d8d9218` |
| SHA-1 | `1201476068b8b1408c072b1465305efa7f680f52` |
| SHA-256 | `2ef818af2a9b1ae9990c10f919480c58c875b6ab8736a1c54e34557b259339d9` |
| SHA3-384 | `b2166744d169babea24484fad51600cef5669142701aa9012384743af9c5cedd6d133e38c2e248e0e02bebf052c9fd69` |
| TLSH | `T194338DA3C42E7D94F14AC278B9204B385B23D40692833EF5A68AC6974047EDCF6593F6` |
| SSDEEP | `768:QeoaI/HTfpYtWja5FLMWwtAbeIPdqVDoCPlc75CyFzKe174uNC9ooeQm8A0CsL9U:DoaI/rpY6OzwtA1So0c1fdKINuoACs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_2ef818af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ef818af2a9b1ae9990c10f919480c58c875b6ab8736a1c54e34557b259339d9"
    family = "Mirai"
    file_name = "aurora.sh4"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:45"
  condition:
    hash.sha256(0, filesize) == "2ef818af2a9b1ae9990c10f919480c58c875b6ab8736a1c54e34557b259339d9"
}
```

### Sample 27: `5c7b46ad5ffee665`

| Field | Value |
|---|---|
| SHA-256 | `5c7b46ad5ffee665aa02fc76d32343caf958614a9397eac2d48e75b6559e4e75` |
| Family label | `Mirai` |
| File name | `aurora.spc` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:45` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `318a8c5b19ad24d8631a93dda80fafe6` |
| SHA-1 | `26e5902b3d714f570c481f0be7c4692510262ff1` |
| SHA-256 | `5c7b46ad5ffee665aa02fc76d32343caf958614a9397eac2d48e75b6559e4e75` |
| SHA3-384 | `29c8ec223872c93106f349285caa3b66371251948ce8a6337d91866e01874f8460170f429e3f87decba6ea1675c03f79` |
| TLSH | `T122533921A9792E17C0D5F57B62F38324B2F61B4E24A8C71E7D710E8EFF1495065472B2` |
| SSDEEP | `768:0lov7IJXkMVq9XPAYb1RkXzk8VQwLtjkqo/apcJ6KeDuO+h8b2sFYV:0lKC0MVSXPAK1ijk8hLtjkqRch91` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_5c7b46ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c7b46ad5ffee665aa02fc76d32343caf958614a9397eac2d48e75b6559e4e75"
    family = "Mirai"
    file_name = "aurora.spc"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:45"
  condition:
    hash.sha256(0, filesize) == "5c7b46ad5ffee665aa02fc76d32343caf958614a9397eac2d48e75b6559e4e75"
}
```

### Sample 28: `96dba8e88c6c483b`

| Field | Value |
|---|---|
| SHA-256 | `96dba8e88c6c483bf79c9b28d81ef0f312c14c69e16572384967bac7c62de0fc` |
| Family label | `Mirai` |
| File name | `aurora.ppc` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:43` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7038166c4f2f093c3dadd0415de750d` |
| SHA-1 | `5c2332422a1e5f6dda783e6281fc5f4f9dab52f1` |
| SHA-256 | `96dba8e88c6c483bf79c9b28d81ef0f312c14c69e16572384967bac7c62de0fc` |
| SHA3-384 | `3f42fabe7a9cd914aeb7db7c98e6ce98885a11cace24097868efcbc4120d24012833db553ea12a783f1f6c7eaa909772` |
| TLSH | `T1F2436A0272280A47E1621FF4293F27E083EEE99121F4F588664FDA464275F77258AFD9` |
| SSDEEP | `768:UapBtbSHgJiWrrrP2SjBYBaRTFEMYrVXKk+tzqvMWyCGEgHs3f/3YwYtZAIsYsRN:U/AgWJjBYoar1KDnWyTJHs3fyDs/xx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_96dba8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96dba8e88c6c483bf79c9b28d81ef0f312c14c69e16572384967bac7c62de0fc"
    family = "Mirai"
    file_name = "aurora.ppc"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:43"
  condition:
    hash.sha256(0, filesize) == "96dba8e88c6c483bf79c9b28d81ef0f312c14c69e16572384967bac7c62de0fc"
}
```

### Sample 29: `e1a632b22ed08d7d`

| Field | Value |
|---|---|
| SHA-256 | `e1a632b22ed08d7d09256153c8215e8a0f4e323d45592a8591f4b1c6bfc65a3f` |
| Family label | `Mirai` |
| File name | `aurora.mpsl` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:43` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `682c33e8bb412b028c11b27634f75415` |
| SHA-1 | `b9d3afbf6194260e1575dce50be284c07a50f8f6` |
| SHA-256 | `e1a632b22ed08d7d09256153c8215e8a0f4e323d45592a8591f4b1c6bfc65a3f` |
| SHA3-384 | `20274a574a5a8692e4b507fb6b6c364cadcd2a3e145195806ea0345644c631fd8c11cf45cbd45a0e8010ba3e692538e3` |
| TLSH | `T16D73930ABF610FF7E8AFDC3789E91B45248D641A21993B797D34D818B24B24F49E3874` |
| SSDEEP | `1536:IlGFfut1GzBpR5Ygxmk+7GZsTefCqNuRHxb:IcFfut14Bugxm1Our` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_e1a632b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1a632b22ed08d7d09256153c8215e8a0f4e323d45592a8591f4b1c6bfc65a3f"
    family = "Mirai"
    file_name = "aurora.mpsl"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:43"
  condition:
    hash.sha256(0, filesize) == "e1a632b22ed08d7d09256153c8215e8a0f4e323d45592a8591f4b1c6bfc65a3f"
}
```

### Sample 30: `2f6e53269da938c4`

| Field | Value |
|---|---|
| SHA-256 | `2f6e53269da938c4514fa8f157af3fabccc1ceb59798de7be332c0e9589bfb9e` |
| Family label | `Mirai` |
| File name | `aurora.mips` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:42` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbea9f864bb0baad3a313ba894b7fc31` |
| SHA-1 | `1594c11447914b8604342e72caa19e49c5c845b6` |
| SHA-256 | `2f6e53269da938c4514fa8f157af3fabccc1ceb59798de7be332c0e9589bfb9e` |
| SHA3-384 | `6784d6bea14e545d5d3596458b77eb24793c8144c9b26c614911601a6d03f34b04dbca67a5d05753c490146a871ed864` |
| TLSH | `T17173840E2E619FBCFBAD863587B35F209248339226E1D545D19CFA011E7034E746FBA9` |
| TELFHASH | `t1e5013c58483813f083815d9e6becff75e4a140ef99261f3b8e10e9abd6215429d01c2c` |
| SSDEEP | `1536:D4Z8VUay6+vl/R1KIdysUmR9EiYHXwKt1dN63fJjzET0:E6Zy6+vdGIdysUKy1dN4fBzI0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_2f6e5326
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f6e53269da938c4514fa8f157af3fabccc1ceb59798de7be332c0e9589bfb9e"
    family = "Mirai"
    file_name = "aurora.mips"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:42"
  condition:
    hash.sha256(0, filesize) == "2f6e53269da938c4514fa8f157af3fabccc1ceb59798de7be332c0e9589bfb9e"
}
```

### Sample 31: `5c9092d329591862`

| Field | Value |
|---|---|
| SHA-256 | `5c9092d329591862af419a6abc283e66017b01762d5745089f54e95c4d4c0b8d` |
| Family label | `Mirai` |
| File name | `aurora.arm7` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71c6f12398796dca88818a0d54b7c71b` |
| SHA-1 | `d7e791e622c686b983106f9baa87b9b9804895a7` |
| SHA-256 | `5c9092d329591862af419a6abc283e66017b01762d5745089f54e95c4d4c0b8d` |
| SHA3-384 | `12839cd84c7dbf10c31e4e4dd25666b63eb46002d0dd569a3370d39cf746caa068956c33eca571abe816c92cce8cce51` |
| TLSH | `T131630746B8918A16C5D513BAFA2E118D331363B8D2DF7213DE106F24778A92F0E7B952` |
| TELFHASH | `t1f221be728ee509e87b80c389d0cb7139addc31b86b11159eda9e3f4a02b35c6b516020` |
| SSDEEP | `1536:m5naOjdJ4QLpoEDGmS3jh3l7nxczKSrY2Vy6efGEUreJn9eL4Iqi1Z5XZWr:mqQ1Ram0Rl1czKAVEfGEkeOZ5XZWr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_5c9092d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c9092d329591862af419a6abc283e66017b01762d5745089f54e95c4d4c0b8d"
    family = "Mirai"
    file_name = "aurora.arm7"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:40"
  condition:
    hash.sha256(0, filesize) == "5c9092d329591862af419a6abc283e66017b01762d5745089f54e95c4d4c0b8d"
}
```

### Sample 32: `b720c9c690e010b7`

| Field | Value |
|---|---|
| SHA-256 | `b720c9c690e010b7b98743d9c0005b14161715e19e9b640c3ef2f9ab1dcfffdf` |
| Family label | `Mirai` |
| File name | `aurora.m68k` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb115e9db90ebd25400b21069f264989` |
| SHA-1 | `46a5a2db07e37f52613eb83d67792b2161dfc223` |
| SHA-256 | `b720c9c690e010b7b98743d9c0005b14161715e19e9b640c3ef2f9ab1dcfffdf` |
| SHA3-384 | `1519fba85564c91433d3b07c12c025d9be7d95b833dc7e0fde9845303520fbefe9be9f3075d0c9551a6e7be55addaf4f` |
| TLSH | `T1A3435DD6B400DE7CF987EB7A81224A09F935722154A30F27A667FD93AC720564C2FD4B` |
| SSDEEP | `1536:TKgor9Y12sKBcpPQ+DwlrQCkRnKyQDVDqgF88A:RqsEcpGQLdGDqG2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_b720c9c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b720c9c690e010b7b98743d9c0005b14161715e19e9b640c3ef2f9ab1dcfffdf"
    family = "Mirai"
    file_name = "aurora.m68k"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:40"
  condition:
    hash.sha256(0, filesize) == "b720c9c690e010b7b98743d9c0005b14161715e19e9b640c3ef2f9ab1dcfffdf"
}
```

### Sample 33: `273a5dd08461ffe2`

| Field | Value |
|---|---|
| SHA-256 | `273a5dd08461ffe2e44ef07cafd6678a5789dbeefc68c316e337f95336af10d0` |
| Family label | `Mirai` |
| File name | `aurora.arm5n` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:39` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c47edbaa65c92c58803355159bff368` |
| SHA-1 | `5630b849a003701c1abc44ccdbf137faee9c9f8a` |
| SHA-256 | `273a5dd08461ffe2e44ef07cafd6678a5789dbeefc68c316e337f95336af10d0` |
| SHA3-384 | `71620f307e906b03a19251f3b33f6033d6a09f4a41614b12ee33ce9fc9503f5b3e16c74f313c2367b5e582ac1bbf4ff4` |
| TLSH | `T1D1331895BCD29A6AC5D423B6FA2E519E3321A3E8D0DB3217CC204B1477CA51F0DB7B91` |
| TELFHASH | `t120e02600bc658b5988d79a74ad9d07b49901621254668b14cf10d6f0983f458a308e5a` |
| SSDEEP | `1536:BVAzmE7OU0+BsGCPRD+agLb6rL2yBCNt5srDF:jAzmE6U0vwkvkbsvF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_273a5dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "273a5dd08461ffe2e44ef07cafd6678a5789dbeefc68c316e337f95336af10d0"
    family = "Mirai"
    file_name = "aurora.arm5n"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:39"
  condition:
    hash.sha256(0, filesize) == "273a5dd08461ffe2e44ef07cafd6678a5789dbeefc68c316e337f95336af10d0"
}
```

### Sample 34: `c2b60d1860f4cfe7`

| Field | Value |
|---|---|
| SHA-256 | `c2b60d1860f4cfe72124076a5866ea534cd069e13d0aa1f232d09d6631e8c1a5` |
| Family label | `unknown` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-09-28 05:15:38` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa73356cc0eff3dc4e937b0877cb23d8` |
| SHA-1 | `ea41e887f0f574183f677aec981eedbecea67814` |
| SHA-256 | `c2b60d1860f4cfe72124076a5866ea534cd069e13d0aa1f232d09d6631e8c1a5` |
| SHA3-384 | `5e509e7b85392a62f088bf00bcea5648411c7c97ca9c92cea1d3518f9233e4b3805257432614b48f9ff7d246542ab59b` |
| TLSH | `T122E02298304A269C7B02E51C6A23BDF091456024CFC11C9D93EBE803D22C7703F2D8C0` |
| SSDEEP | `6:hYqc4IKXEJsFQ3+CsOXsVGFECs0Vrw+JhyoTrYUo+qU5tRUtRm+qUZyyW:nc4IKXEJ9XH0+Jjr55v3uPo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_c2b60d18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2b60d1860f4cfe72124076a5866ea534cd069e13d0aa1f232d09d6631e8c1a5"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-09-28 05:15:38"
  condition:
    hash.sha256(0, filesize) == "c2b60d1860f4cfe72124076a5866ea534cd069e13d0aa1f232d09d6631e8c1a5"
}
```

### Sample 35: `d665a6826d9073dd`

| Field | Value |
|---|---|
| SHA-256 | `d665a6826d9073dd02c60a25a688dea778b8f7d78fa0933c72708eecd3e47725` |
| Family label | `Mirai` |
| File name | `aurora.arm` |
| File type | `elf` |
| First seen | `2026-09-28 05:15:38` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bea0180f0082d6c6daa42ed9548cbe0` |
| SHA-1 | `84f39fdc0b1e2f6c98a5f8977b0711786bab53a1` |
| SHA-256 | `d665a6826d9073dd02c60a25a688dea778b8f7d78fa0933c72708eecd3e47725` |
| SHA3-384 | `eb018e61f1eb53c7f3e03842178bd19d7072741a737e009c5b63b72b50ecc0b2cc668f414bcdc0002516671cbb38a314` |
| TLSH | `T177532895BC928A12CAD423B6FA2E518D372263E8D1DF3207DD216F1137CA82F0D7B556` |
| TELFHASH | `t17201dc2786a51ffcb7e0c34bd28a615488d972de270030bf996b179f82a24c2701b00a` |
| SSDEEP | `1536:BZ3r3+M5N6jxQ2BKLE2VrL2yBCtt5K43qx1B:BZ3r3r5nNlvYbKyqxD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_d665a682
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d665a6826d9073dd02c60a25a688dea778b8f7d78fa0933c72708eecd3e47725"
    family = "Mirai"
    file_name = "aurora.arm"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:38"
  condition:
    hash.sha256(0, filesize) == "d665a6826d9073dd02c60a25a688dea778b8f7d78fa0933c72708eecd3e47725"
}
```

### Sample 36: `809bfb1f22505bc6`

| Field | Value |
|---|---|
| SHA-256 | `809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07` |
| Family label | `unknown` |
| File name | `809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07.exe` |
| File type | `exe` |
| First seen | `2026-09-28 05:11:26` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `152bfe825c28026ebff1875f1ab1d9bc` |
| SHA-1 | `bddd49e7bef13105238b7693c315a1ce2c8d4924` |
| SHA-256 | `809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07` |
| SHA3-384 | `813f2f6a5a7ddd8729169403ace04107118a0d18d2edf43794e2534527844dc09c842d38e20bf783fa944ee5fdb6a792` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T10E864947ECA519E9C1EDD1308A62A113BB727C498B2127D71B90F6342F73BD0ADB9358` |
| SSDEEP | `49152:+D5dZbsb1qb1T+iu3D1fWn+h7QP0qx84kTJxjidSDAK5c+LNyHFoGUVAUab/gKCM:+nNsJwu3QnmQNWzNkF5PFHN/5r6XE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_809bfb1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07"
    family = "unknown"
    file_name = "809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07.exe"
    file_type = "exe"
    first_seen = "2026-09-28 05:11:26"
  condition:
    hash.sha256(0, filesize) == "809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07"
}
```

### Sample 37: `67436caa9df23693`

| Field | Value |
|---|---|
| SHA-256 | `67436caa9df23693d5a33616f8525d196f9c9e3e713a584f1f2e79a5b60ee7fc` |
| Family label | `Mirai` |
| File name | `bot.armv6` |
| File type | `elf` |
| First seen | `2026-09-28 05:11:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f3534e8d026dfc2e541b1fe7c6b4bdb` |
| SHA-1 | `65f8bf70fefb69d65b81355f0dec64637c43c4e0` |
| SHA-256 | `67436caa9df23693d5a33616f8525d196f9c9e3e713a584f1f2e79a5b60ee7fc` |
| SHA3-384 | `48a82f3b06d793b8fcd7cf43926ddbf3befe9057ac042d06181f1a5968bceb744c5c6a346fb922c855aef42489953765` |
| TLSH | `T1FE254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmh:KdM4DmUj657yDAmh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_67436caa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67436caa9df23693d5a33616f8525d196f9c9e3e713a584f1f2e79a5b60ee7fc"
    family = "Mirai"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-09-28 05:11:08"
  condition:
    hash.sha256(0, filesize) == "67436caa9df23693d5a33616f8525d196f9c9e3e713a584f1f2e79a5b60ee7fc"
}
```

### Sample 38: `be5f3755ebc22985`

| Field | Value |
|---|---|
| SHA-256 | `be5f3755ebc229859fc189e2fd8dae8dc900b4d8f27b3bb513e38d17a92e488b` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-09-28 05:11:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98175a3b1edd9e7fe34e4d3bc56eebe5` |
| SHA-1 | `76d12ad5074aeb112e0da74d2e1e8869a2712241` |
| SHA-256 | `be5f3755ebc229859fc189e2fd8dae8dc900b4d8f27b3bb513e38d17a92e488b` |
| SHA3-384 | `c7b3cf984c18fd590509b9d818429a6d7dba9d829e4cc366fc7a3bf5d9a03484589b06a5d433eadbe45d2f26ae7332a6` |
| TLSH | `T1CC144AC7F800DDBAF80EE3374413091AB130B7A244925A376257797BED3A1951A77F8A` |
| SSDEEP | `3072:vhrnOY+viZFvJlIKjjEwr12yUv/JykPNT6NU9lcLM9QDWU1jV5jbixLWuZYCic+S:JTOY+qZFvz7wJyk1T6NicdKU1qLRvf+S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_be5f3755
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be5f3755ebc229859fc189e2fd8dae8dc900b4d8f27b3bb513e38d17a92e488b"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-09-28 05:11:06"
  condition:
    hash.sha256(0, filesize) == "be5f3755ebc229859fc189e2fd8dae8dc900b4d8f27b3bb513e38d17a92e488b"
}
```

### Sample 39: `cb0d55da96bb67f9`

| Field | Value |
|---|---|
| SHA-256 | `cb0d55da96bb67f98f7812da0b25b508bc857569b52b6e271768063bcc386143` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-09-28 05:11:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7210b08e8c4b0ed3499a85239445cac2` |
| SHA-1 | `d2844ddc71999fa80dee514b372f9925a5998152` |
| SHA-256 | `cb0d55da96bb67f98f7812da0b25b508bc857569b52b6e271768063bcc386143` |
| SHA3-384 | `9db33f6f382aced6971ceddd4acbfacddd4fb0b839b00d560b97206c9013b31d4e981ecdaf3f58a99ef6258c24667dd0` |
| TLSH | `T1AD443D46E6418F13C0D61BBAFADF42453333A768D3DB73069528ABB43B8779E4E26501` |
| TELFHASH | `t16f515126a52891265bb0dc58edde6bb3111fdb136312be3aef35c4cc211948ae925c4f` |
| SSDEEP | `6144:zmhAsfkvUgC4PmL2iraLwQ8RG89osUEEJi2O8Xq6u/M/RamW2nTkbtQ:z50sx+L28aLSRG89PSJiK/uE/0mWcTkW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_cb0d55da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb0d55da96bb67f98f7812da0b25b508bc857569b52b6e271768063bcc386143"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-09-28 05:11:04"
  condition:
    hash.sha256(0, filesize) == "cb0d55da96bb67f98f7812da0b25b508bc857569b52b6e271768063bcc386143"
}
```

### Sample 40: `a1e4093de4aec764`

| Field | Value |
|---|---|
| SHA-256 | `a1e4093de4aec7643993a689c32a53472fce9bb21957e9d90153e9191dd53b12` |
| Family label | `Mirai` |
| File name | `bot.armv5tel` |
| File type | `elf` |
| First seen | `2026-09-28 05:03:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `103e29648ad18c3291e7ff39ab816be0` |
| SHA-1 | `ad875777c7feaf3e5f1fc355dcb78ce2c427e9b0` |
| SHA-256 | `a1e4093de4aec7643993a689c32a53472fce9bb21957e9d90153e9191dd53b12` |
| SHA3-384 | `e1dc70e71e8a94849d50a8ec8170c2d86d6a4249cca9b7cf2a01d6a4ddf068ebf29c1aa45df485b48beefd73dba5caf1` |
| TLSH | `T1C4254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmu:KdM4DmUj657yDAmu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_a1e4093d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1e4093de4aec7643993a689c32a53472fce9bb21957e9d90153e9191dd53b12"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-28 05:03:01"
  condition:
    hash.sha256(0, filesize) == "a1e4093de4aec7643993a689c32a53472fce9bb21957e9d90153e9191dd53b12"
}
```

### Sample 41: `43613c90d253ccaa`

| Field | Value |
|---|---|
| SHA-256 | `43613c90d253ccaa7eced571018d78702fab3d2e018fc865d727a51f092c2dd0` |
| Family label | `Mirai` |
| File name | `bot.i486` |
| File type | `elf` |
| First seen | `2026-09-28 05:02:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `237d81c4526fcc3899fd2f7a65ee0831` |
| SHA-1 | `63273d6461d547cfb8488b9181617ee9a78de687` |
| SHA-256 | `43613c90d253ccaa7eced571018d78702fab3d2e018fc865d727a51f092c2dd0` |
| SHA3-384 | `4f51132f2fc7f15b705e8453046f4ad074ff1ece2d6f6823fc7b5f407e384187d1e7e28fc826b6fbe860e8d319e309e9` |
| TLSH | `T1F2355C5BB2B374BCC557C834839BDA62BD35B46502226E7BB5C4CA302E26D702719F72` |
| TELFHASH | `t1d3e16b754ff934b862d6ca24b352f0769a33142b66ec35f52612ad98ef40fc04c6682b` |
| SSDEEP | `24576:FtmY2nvov46dWqbb+VXu5C6wGRTiY8mUMh8Utu+MBb:6BAv46dYXuo6lixmUMdkvBb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_43613c90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43613c90d253ccaa7eced571018d78702fab3d2e018fc865d727a51f092c2dd0"
    family = "Mirai"
    file_name = "bot.i486"
    file_type = "elf"
    first_seen = "2026-09-28 05:02:59"
  condition:
    hash.sha256(0, filesize) == "43613c90d253ccaa7eced571018d78702fab3d2e018fc865d727a51f092c2dd0"
}
```

### Sample 42: `7e8709629cd9930e`

| Field | Value |
|---|---|
| SHA-256 | `7e8709629cd9930ea6a55ef56b5364a50758385f11d40f83fb67e8ea5b05703d` |
| Family label | `Mirai` |
| File name | `bot.armv5tel` |
| File type | `elf` |
| First seen | `2026-09-28 04:58:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13256be97bfc497c554158d35fbbc09a` |
| SHA-1 | `68aff40a48681f0fb2d529ae369280de97e4affb` |
| SHA-256 | `7e8709629cd9930ea6a55ef56b5364a50758385f11d40f83fb67e8ea5b05703d` |
| SHA3-384 | `5c1955cdce9295d7f056d762585a99e400ac9a5b6c7deaddab5e7fb0d607bdf7ab6fdcf53e7b5887787ba31f836fbe89` |
| TLSH | `T1A0254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmF:KdM4DmUj657yDAmF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_7e870962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e8709629cd9930ea6a55ef56b5364a50758385f11d40f83fb67e8ea5b05703d"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-28 04:58:55"
  condition:
    hash.sha256(0, filesize) == "7e8709629cd9930ea6a55ef56b5364a50758385f11d40f83fb67e8ea5b05703d"
}
```

### Sample 43: `29cf954ce49e80ba`

| Field | Value |
|---|---|
| SHA-256 | `29cf954ce49e80ba1df846642a66f60a967e9c4e36fd10a2cedf4e5a8065e4dd` |
| Family label | `Mirai` |
| File name | `stub.x64` |
| File type | `elf` |
| First seen | `2026-09-28 04:54:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34667c574ab4a960f632d105090059ab` |
| SHA-1 | `0a0397966a6f005172d7dcbf7f708a3c3c6a6cd2` |
| SHA-256 | `29cf954ce49e80ba1df846642a66f60a967e9c4e36fd10a2cedf4e5a8065e4dd` |
| SHA3-384 | `d7cffcf988ced49e5e8e1bb48d45ed4e5531787d2e23ba01cea6ce1f49c1c8a1f1f7f2a7e8b5e6541611a5cd6c148083` |
| TLSH | `T108157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/1:7NP46S4QVs7l6A5Zji59k0jZz06FYRsK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_29cf954c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29cf954ce49e80ba1df846642a66f60a967e9c4e36fd10a2cedf4e5a8065e4dd"
    family = "Mirai"
    file_name = "stub.x64"
    file_type = "elf"
    first_seen = "2026-09-28 04:54:58"
  condition:
    hash.sha256(0, filesize) == "29cf954ce49e80ba1df846642a66f60a967e9c4e36fd10a2cedf4e5a8065e4dd"
}
```

### Sample 44: `4aa8d4e8955da834`

| Field | Value |
|---|---|
| SHA-256 | `4aa8d4e8955da8341f72c69b5df68d1fda2110dca0ff8798d4c72a6ade4aa2ce` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:32` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a19a1d656bd6437ec7d55d7f5dc50ee0` |
| SHA-1 | `249f80d02e2295002f2b9edebb7ff7fb824adcfc` |
| SHA-256 | `4aa8d4e8955da8341f72c69b5df68d1fda2110dca0ff8798d4c72a6ade4aa2ce` |
| SHA3-384 | `0848890f8213208f8228fc2887393f6f1d1c82c17298e1f5b6793f569ccafee54f5b4982ec58e111b91f667d86fcbf73` |
| TLSH | `T1A2E33AC7F800DEFEF80AE33748530905B230BBA145925B372257797BED3A1991967E86` |
| SSDEEP | `3072:wWyu85J1Va4Kyyvj0/mbSiWXLbI6FnVxjbiBLcWpYeC:wvunXyyr0/mbvWI6FSLWeC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_4aa8d4e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4aa8d4e8955da8341f72c69b5df68d1fda2110dca0ff8798d4c72a6ade4aa2ce"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:32"
  condition:
    hash.sha256(0, filesize) == "4aa8d4e8955da8341f72c69b5df68d1fda2110dca0ff8798d4c72a6ade4aa2ce"
}
```

### Sample 45: `04fac8188c7906b4`

| Field | Value |
|---|---|
| SHA-256 | `04fac8188c7906b441c173d7a377ea939227bbf0063a8bc681dcec53cb046b70` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:32` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b219d008e90857f7b3663acba329d9d` |
| SHA-1 | `52dcbb5f0a8d0cc57d16eb245965b0a779d49b00` |
| SHA-256 | `04fac8188c7906b441c173d7a377ea939227bbf0063a8bc681dcec53cb046b70` |
| SHA3-384 | `64fae780fbe2a16cd486b4810a804498af9fcbe492c593b62a3bddb657994f7f8be214d57a96d2b6315d679d3cf7ecfb` |
| TLSH | `T18CD31A45F8504F23C6D512BBFB5E428D772A17A8D2EE72039D256F20378796B0E3B246` |
| TELFHASH | `t10511e1b11f485e9e6fe0c04bcdcda632d7b878dcaf635422091ab85b0a57470307c196` |
| SSDEEP | `1536:irS4K8LEk/TvAfa6s8qAZHX4VbfwHTFHDyJMWVJO2tA5Nb4El4oAElXDwyweYLku:irSp8ICf8qO4NUlDyJNvaki6z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_04fac818
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04fac8188c7906b441c173d7a377ea939227bbf0063a8bc681dcec53cb046b70"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:32"
  condition:
    hash.sha256(0, filesize) == "04fac8188c7906b441c173d7a377ea939227bbf0063a8bc681dcec53cb046b70"
}
```

### Sample 46: `528a497f41491f59`

| Field | Value |
|---|---|
| SHA-256 | `528a497f41491f59758d3460f06c7e827c289a44bab39b864a7e9208c1ffe10d` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:32` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edd0d6e5ab3f16d718538a73d20e6b84` |
| SHA-1 | `f7504203609b7a8c6783a99b8b576a0bcd4cfeb5` |
| SHA-256 | `528a497f41491f59758d3460f06c7e827c289a44bab39b864a7e9208c1ffe10d` |
| SHA3-384 | `26f37c78b764ff56e8a519b55cea27ffd7c4664bc4a185bcec5d2e55bfc90fbf301682ceeccfa48030e5e2c8c23ee316` |
| TLSH | `T193D34B07B4C184FCC8D9C2748FABB13BED76B1691238B16B27D4AA275E89E305F1D640` |
| TELFHASH | `t14e51f2b136453994a1fbea66734ad9e4adb50f1104e071e2de736df3de263840cb1863` |
| SSDEEP | `3072:xYeLBug78AJT5UDpapYZYkqY4eog+MCufpy92ilt:xYeLBug78ABiDpSYaIU1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_528a497f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "528a497f41491f59758d3460f06c7e827c289a44bab39b864a7e9208c1ffe10d"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:32"
  condition:
    hash.sha256(0, filesize) == "528a497f41491f59758d3460f06c7e827c289a44bab39b864a7e9208c1ffe10d"
}
```

### Sample 47: `31b58d95a9ce2530`

| Field | Value |
|---|---|
| SHA-256 | `31b58d95a9ce2530aa523498c4d5fc055de44e893f2645c29c4aebfbad6abf57` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:31` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4d05a3332b22c68420452d995d4dd93` |
| SHA-1 | `16df1a55ec887de77b7ca37f2b9c7a0c2c5202ce` |
| SHA-256 | `31b58d95a9ce2530aa523498c4d5fc055de44e893f2645c29c4aebfbad6abf57` |
| SHA3-384 | `c745a85406dc51b8325db463099876dd8df6075ee176f77ad38700ee7e54bb1d82f346641bada2652abd18be39a5fd07` |
| TLSH | `T173D33A06730C0947D2632EB43A3F27E193EF9A8121F4F644355FAB8A9671E325586ECD` |
| SSDEEP | `1536:ExfM1+e8DsPFj2I2YvRxfjIVEP1RcvLVGa7vJr4VLvArjWE2+wpNtquG3uK:ECfsYvRxeEr87xr4erOK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_31b58d95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31b58d95a9ce2530aa523498c4d5fc055de44e893f2645c29c4aebfbad6abf57"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:31"
  condition:
    hash.sha256(0, filesize) == "31b58d95a9ce2530aa523498c4d5fc055de44e893f2645c29c4aebfbad6abf57"
}
```

### Sample 48: `608b16b89690afa9`

| Field | Value |
|---|---|
| SHA-256 | `608b16b89690afa9af52518a8863605b1ddf7d6d7b25ce3922482bd0d9e36d14` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:30` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e9e1ddaaa61142e9b29d30276edee64` |
| SHA-1 | `9040a8f2a3542248d3d876b7ac096807b0c69ffc` |
| SHA-256 | `608b16b89690afa9af52518a8863605b1ddf7d6d7b25ce3922482bd0d9e36d14` |
| SHA3-384 | `c356f0cbe21cfb542922d8c3734555e9899de28aeab1738f0c16a4bbe0244cc58adc5e797bad89d46614c2fb5a79deda` |
| TLSH | `T1BBE30A46B8818B15D5D111BAFE1E128E33231B7CE2DE73029D246F65778A9BF0E3B505` |
| TELFHASH | `t162d0c2059e5821cc66c4451484dc211abed8b4adab16414c33acac48c626a913120b45` |
| SSDEEP | `3072:a0WNcRHqUbWrhOXCNr34Ka2DvZJOuWInc:0yRKUmOX2r3/aoDWInc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_608b16b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "608b16b89690afa9af52518a8863605b1ddf7d6d7b25ce3922482bd0d9e36d14"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:30"
  condition:
    hash.sha256(0, filesize) == "608b16b89690afa9af52518a8863605b1ddf7d6d7b25ce3922482bd0d9e36d14"
}
```

### Sample 49: `7a76f9c6d0f7e0a7`

| Field | Value |
|---|---|
| SHA-256 | `7a76f9c6d0f7e0a71024295148943e88c60bed7187eeff53a79f897600b40407` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:30` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8208f155712b4929fa035a38e253eddd` |
| SHA-1 | `7f6516e7431f1aeb800ee73ee1278ffd784dde05` |
| SHA-256 | `7a76f9c6d0f7e0a71024295148943e88c60bed7187eeff53a79f897600b40407` |
| SHA3-384 | `75fbdd9b59d3e213b45887310e152b40f88a4434010f13a2cefae6e297084437e60b7a68f84e882d02117b097b9b4ecb` |
| TLSH | `T183B36B73C8266F58C669D1B4B0718FB86B63A91182871FBE19A7C2B54443DCCF6063F8` |
| SSDEEP | `1536:xEbch/VHuyEZ8yWBj0JlC4KMKlzpQqgSri9++sWpi8UrDBqy:xEbwtHujWFGlJKTloS2XsWw8Uw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_7a76f9c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a76f9c6d0f7e0a71024295148943e88c60bed7187eeff53a79f897600b40407"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:30"
  condition:
    hash.sha256(0, filesize) == "7a76f9c6d0f7e0a71024295148943e88c60bed7187eeff53a79f897600b40407"
}
```

### Sample 50: `80edaab25ec8e4aa`

| Field | Value |
|---|---|
| SHA-256 | `80edaab25ec8e4aa0d498601c8e9a62a90ee5af89d26bc55383c9a15c2003c69` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:29` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4caf98beb4390856c564c1c6f48bfee6` |
| SHA-1 | `aafd7ed3d15d46a92efe8cd3d532325b47821b8b` |
| SHA-256 | `80edaab25ec8e4aa0d498601c8e9a62a90ee5af89d26bc55383c9a15c2003c69` |
| SHA3-384 | `32c35685d1ecfb1b584fdeadc8a009269596b4efb001fbadca811b69debea97b90a292a2d501c64ae655a22d5f1ec98e` |
| TLSH | `T13104C706AB910FFBDCAFDD3746E9070139CC651B22A93B363674D528F54A50B4AE3C68` |
| SSDEEP | `1536:DKlPT/yQntbvN0LAsuAzPk/eDsydc5TcSuVWXbaupU93VMZnKOuYcwAUT/TmRY28:Oxpn/0ssuWOeD0NpWMX9AUTSRLexR1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_80edaab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80edaab25ec8e4aa0d498601c8e9a62a90ee5af89d26bc55383c9a15c2003c69"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:29"
  condition:
    hash.sha256(0, filesize) == "80edaab25ec8e4aa0d498601c8e9a62a90ee5af89d26bc55383c9a15c2003c69"
}
```

### Sample 51: `5ceb7a989bf18020`

| Field | Value |
|---|---|
| SHA-256 | `5ceb7a989bf180203d0e75813479eeee32c2b7a599b276f9cb51d584d079c0ca` |
| Family label | `Mirai` |
| File name | `main_arm5` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:29` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05309ff34922a631fc708749c6433df4` |
| SHA-1 | `5da1c08f92bdda2dc8c6fdb02df2d87aa9390671` |
| SHA-256 | `5ceb7a989bf180203d0e75813479eeee32c2b7a599b276f9cb51d584d079c0ca` |
| SHA3-384 | `8924b91a62324147521cff0341bc54771ab31393bec256dd0c5238f7b34a3e22d648febc401d41978ad17910f2692768` |
| TLSH | `T1BEC31B45FC504B23CAD522BBFB5E428D772A1769D3EE720399256F21378786B0E37602` |
| TELFHASH | `t16911107aef64cf0da7c1c19cc88eb26a067a34443f022402475c2e4b8f2299331a9452` |
| SSDEEP | `3072:a7IEKRsF+OIW0H4mW5kWFhZ7GMi6VXhue:a7CRm7I5H4mwkWzZ7Gvaxr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_5ceb7a98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ceb7a989bf180203d0e75813479eeee32c2b7a599b276f9cb51d584d079c0ca"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:29"
  condition:
    hash.sha256(0, filesize) == "5ceb7a989bf180203d0e75813479eeee32c2b7a599b276f9cb51d584d079c0ca"
}
```

### Sample 52: `f03cedddac00aa82`

| Field | Value |
|---|---|
| SHA-256 | `f03cedddac00aa827fa60629b38b90555bd66b702d4581f897dc4e06b6e3cbff` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:29` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8479bab39b80bc17be22b886fe9d4367` |
| SHA-1 | `48935e011dc5ccaf5bfc475c6d944722fea83f10` |
| SHA-256 | `f03cedddac00aa827fa60629b38b90555bd66b702d4581f897dc4e06b6e3cbff` |
| SHA3-384 | `8a576338f6724db6b68555ffadb0cb40f7a9c3a9b2d504f8af4af4a6bbce07aebdd0b64b20698acbe99f3c1242793c60` |
| TLSH | `T194042A46AA404B13C0D627BAF6DF42463333AB5497E773069528AFB43F8279E4F13606` |
| TELFHASH | `t107311171667851269aa1dc64d9ed97b2252ac7172340ff36df26c0cc281a44af62ac0f` |
| SSDEEP | `3072:E9kPec3XMm7YEcEaY7LC+dTmY0bRqh0s38juouM/R5GduC:yyeqMmUXEaY7LC+dTmf20s3sXuM/Rkd9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_f03ceddd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f03cedddac00aa827fa60629b38b90555bd66b702d4581f897dc4e06b6e3cbff"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:29"
  condition:
    hash.sha256(0, filesize) == "f03cedddac00aa827fa60629b38b90555bd66b702d4581f897dc4e06b6e3cbff"
}
```

### Sample 53: `c7dfef3d5e291d98`

| Field | Value |
|---|---|
| SHA-256 | `c7dfef3d5e291d98462858fc0b1703fcfccd071d3def1c3b215ac1e1cb4c17b9` |
| Family label | `Mirai` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:27` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c849dce783f84d3ebd22d25283fa2929` |
| SHA-1 | `5aa433d7f3e70c9f6ae2079116d7b0cba060213d` |
| SHA-256 | `c7dfef3d5e291d98462858fc0b1703fcfccd071d3def1c3b215ac1e1cb4c17b9` |
| SHA3-384 | `69e26738d9fd1d68f20865d6ffe18a1766b7fb1b75a58fc7f8433b0843a15a9213a06b7a3d2797e9a2b0114d114ff13e` |
| TLSH | `T107935BC0F683E0F6EC5705B16137E3368772E43A602AEA57C3695932EC91950DB1B76C` |
| TELFHASH | `t1c851d0f56eba0de8f3d0ac48c25e9fd2395ad73b246471b500a36ca123f3a569076c35` |
| SSDEEP | `1536:W0M502vLl2u28hzXvvFN0TlZCrvESBOKp4vTTHIClzgQS9fltT:Wp502zl2u1z3FeTlZCrv1d4/H7mt9D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_c7dfef3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7dfef3d5e291d98462858fc0b1703fcfccd071d3def1c3b215ac1e1cb4c17b9"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:27"
  condition:
    hash.sha256(0, filesize) == "c7dfef3d5e291d98462858fc0b1703fcfccd071d3def1c3b215ac1e1cb4c17b9"
}
```

### Sample 54: `cb79c944cc781d74`

| Field | Value |
|---|---|
| SHA-256 | `cb79c944cc781d7470f24eebf9f751c7819a47b75cb14acea72d8f1b4245439a` |
| Family label | `Mirai` |
| File name | `main_mips` |
| File type | `elf` |
| First seen | `2026-09-28 04:52:27` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfd40dcbe5cda6480ab451134a31450b` |
| SHA-1 | `07e7d7da9d6bec05f1b9ae8015a219f1e471a42c` |
| SHA-256 | `cb79c944cc781d7470f24eebf9f751c7819a47b75cb14acea72d8f1b4245439a` |
| SHA3-384 | `f5306513bcd45abeec888e82040f7e8b9ce535cc4b159c2c405b8ee49f1e07f4d8277f567d585347cba61357a07c9990` |
| TLSH | `T158E47C227721DFA1D355C67405F3C7915AE124A21AE3409AB378C3287E21B2D6E5FFE8` |
| TELFHASH | `t177b012b008f4280502e7ca10980e065271df1006584c16102f82da9942037561bd36dc` |
| SSDEEP | `12288:iQotVmQyFNu4PparDo64ILECLimFgpIFQ2OQmLbw7b5X1:ibVmQy7u4P8rDo6nICLimw2is7b5F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_cb79c944
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb79c944cc781d7470f24eebf9f751c7819a47b75cb14acea72d8f1b4245439a"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:27"
  condition:
    hash.sha256(0, filesize) == "cb79c944cc781d7470f24eebf9f751c7819a47b75cb14acea72d8f1b4245439a"
}
```

### Sample 55: `0f085328fc54df5b`

| Field | Value |
|---|---|
| SHA-256 | `0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b` |
| Family label | `Vidar` |
| File name | `0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b.bin` |
| File type | `exe` |
| First seen | `2026-09-28 04:51:14` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23ee4e6dcb414eae33ac3c0ef9582cf1` |
| SHA-1 | `6011ea32024365c95bb5bf10dea8ae9d0a7c3ce2` |
| SHA-256 | `0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b` |
| SHA3-384 | `05df83ce9196ce95c4eaab8ac909c735f5e54c54e86c12ed3a9bf8c7d21288120ec15836ce4747bbf7b333d850f1fda1` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T177168D07BF9419A8C1DE9331A86741AA3B3C7C4D8B3723EB2E54B6762E723C15935B50` |
| SSDEEP | `49152:rB/zY0huEvIocChnWClGvuX22xgg4YMPK0zb7BcD5aO0q4B+J97n:rbrhnWrJkNapcD5P0C97n` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_055_0f085328
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b"
    family = "Vidar"
    file_name = "0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b.bin"
    file_type = "exe"
    first_seen = "2026-09-28 04:51:14"
  condition:
    hash.sha256(0, filesize) == "0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b"
}
```

### Sample 56: `dad5fa8aeeb15ed7`

| Field | Value |
|---|---|
| SHA-256 | `dad5fa8aeeb15ed7c27f13b4d20b2f1ad56bfb180a5fd54bb7e3d7daf9a3dd0f` |
| Family label | `Mirai` |
| File name | `stub.armv5tel` |
| File type | `elf` |
| First seen | `2026-09-28 04:51:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3956c17c8c42d4ab321d655dbabd0492` |
| SHA-1 | `b97f576378281692eac429505d55dfaefad9b1bf` |
| SHA-256 | `dad5fa8aeeb15ed7c27f13b4d20b2f1ad56bfb180a5fd54bb7e3d7daf9a3dd0f` |
| SHA3-384 | `93ca273ebbdb43720f2a9674b0ff97a3eef83b665c1f89e987415243dfe880f254d08ca37c21e6fcfbbcdbb5f031b59e` |
| TLSH | `T1E8D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKi3:YCp7mXtni6aBh321eSiVWKS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_dad5fa8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dad5fa8aeeb15ed7c27f13b4d20b2f1ad56bfb180a5fd54bb7e3d7daf9a3dd0f"
    family = "Mirai"
    file_name = "stub.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-28 04:51:01"
  condition:
    hash.sha256(0, filesize) == "dad5fa8aeeb15ed7c27f13b4d20b2f1ad56bfb180a5fd54bb7e3d7daf9a3dd0f"
}
```

### Sample 57: `4966419c32ba8687`

| Field | Value |
|---|---|
| SHA-256 | `4966419c32ba868733ab7c001765e0670c66d9f9ca01fc1d799fb398493d4258` |
| Family label | `Mirai` |
| File name | `stub.aarch64` |
| File type | `elf` |
| First seen | `2026-09-28 04:46:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb8ccd8d6dce9d8b505c940c7be8f373` |
| SHA-1 | `3404204aecb86be9a56d883edaae321e34357e75` |
| SHA-256 | `4966419c32ba868733ab7c001765e0670c66d9f9ca01fc1d799fb398493d4258` |
| SHA3-384 | `02720c762b5c8f91c24b49fbc2e93eb96f84c0fc84018a95ea7d8a73ad5aa8e88b2b861502d7cf9214256497af4c1177` |
| TLSH | `T119F46C5DFD5F3D43C2C6E23ADB8AC3957227B0D8D61311A321C1021DE6CADAD8B5299E` |
| SSDEEP | `12288:qaOMNE5N3B76xF+y0ZdNd7JOSwa5YAmdlStnWtVfkHzG:qaReBKRU9r1aOnQfkHC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_4966419c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4966419c32ba868733ab7c001765e0670c66d9f9ca01fc1d799fb398493d4258"
    family = "Mirai"
    file_name = "stub.aarch64"
    file_type = "elf"
    first_seen = "2026-09-28 04:46:40"
  condition:
    hash.sha256(0, filesize) == "4966419c32ba868733ab7c001765e0670c66d9f9ca01fc1d799fb398493d4258"
}
```

### Sample 58: `44dd2764561c2369`

| Field | Value |
|---|---|
| SHA-256 | `44dd2764561c2369e3958cf9f96942dfe7511c78bf6bb40b2e93219d24438ca0` |
| Family label | `Mirai` |
| File name | `stub.mipsel` |
| File type | `elf` |
| First seen | `2026-09-28 04:42:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f99694a30000deef9c71dee11840d39` |
| SHA-1 | `11439b67b44e9c07327d8fd1388ae088935a7b75` |
| SHA-256 | `44dd2764561c2369e3958cf9f96942dfe7511c78bf6bb40b2e93219d24438ca0` |
| SHA3-384 | `e564d3b0f1933eef0442fecc6e342f60ca5d067440e4e129529c90e022952e6385980cd6e7910075cfd92726ec4597c4` |
| TLSH | `T1BCF45B07FF815FEBC09FCD30852EC31721E9D48656C1A62A72FC4A8CBA5D6694BE3494` |
| SSDEEP | `12288:cAsRZePvWEwcj1b4D7QAEjYHZ6fxd8mg2cSAH07FFMk/mKsuSxzOTl1aplHPPhGh:GZwv1jJ4/9UZnQ28N+0JTxC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_44dd2764
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44dd2764561c2369e3958cf9f96942dfe7511c78bf6bb40b2e93219d24438ca0"
    family = "Mirai"
    file_name = "stub.mipsel"
    file_type = "elf"
    first_seen = "2026-09-28 04:42:28"
  condition:
    hash.sha256(0, filesize) == "44dd2764561c2369e3958cf9f96942dfe7511c78bf6bb40b2e93219d24438ca0"
}
```

### Sample 59: `f11b0d8298043a6f`

| Field | Value |
|---|---|
| SHA-256 | `f11b0d8298043a6fac57c092454dc83dfe38c003c964782c80ef34ccfd81c5a9` |
| Family label | `Mirai` |
| File name | `stub.mips64` |
| File type | `elf` |
| First seen | `2026-09-28 04:42:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab239323d8e8031c60a77f6bb603716a` |
| SHA-1 | `bc747cc5e42b5760fc2856dded53974d0f4883d5` |
| SHA-256 | `f11b0d8298043a6fac57c092454dc83dfe38c003c964782c80ef34ccfd81c5a9` |
| SHA3-384 | `7ddfcb3106b22d4e7cfa019d7cbd10ca1945e7e8a624ccb490737e24add33bc2c66f3ca940a0047d736dec12f0afe430` |
| TLSH | `T1C9F48D273B21DF65D355D67049F3C7914AE920A20AE340D6B2A8C3287E6172D2D9FFE4` |
| SSDEEP | `12288:4EO7hT7XQRW4tWl9B11U+bs/w7iGtgpiGGhQi3BF1PNMBHUJTxVf:o7Vh4t+9B1do/w7iG+SQiZa0JTxF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_f11b0d82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f11b0d8298043a6fac57c092454dc83dfe38c003c964782c80ef34ccfd81c5a9"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-28 04:42:26"
  condition:
    hash.sha256(0, filesize) == "f11b0d8298043a6fac57c092454dc83dfe38c003c964782c80ef34ccfd81c5a9"
}
```

### Sample 60: `67d081050f574cc9`

| Field | Value |
|---|---|
| SHA-256 | `67d081050f574cc9c30b7876f13915522683ca0d37c854321012d9c87c10b185` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-09-28 04:38:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdae73c3f70f4dd71a03e634cc788f42` |
| SHA-1 | `3339eb0e979302f2c01d83c4d462b22bf387b3b1` |
| SHA-256 | `67d081050f574cc9c30b7876f13915522683ca0d37c854321012d9c87c10b185` |
| SHA3-384 | `add5966efbee308206baa2cb993524ec1c3156fa649411266fe83dedfae74ce4d81f2a1f645794f9da64e41694040d32` |
| TLSH | `T1EE34D90AAF610EFBD86FDD3706E90B0625CCA54722A53B353278D524F95A50B4EE3C78` |
| SSDEEP | `3072:neYwQjdvxwqb+mPhSbwZ0d68wZaeI7MyO5tqLIuxK/P:eYwQjdvxim5SbwLLNI7MbYIuo/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_67d08105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67d081050f574cc9c30b7876f13915522683ca0d37c854321012d9c87c10b185"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-09-28 04:38:27"
  condition:
    hash.sha256(0, filesize) == "67d081050f574cc9c30b7876f13915522683ca0d37c854321012d9c87c10b185"
}
```

### Sample 61: `e6302aad7ada4598`

| Field | Value |
|---|---|
| SHA-256 | `e6302aad7ada45983d3a22c525b47e5c5ab6000daab5febcc0a414fbc49a1a32` |
| Family label | `Mirai` |
| File name | `bot.armv7` |
| File type | `elf` |
| First seen | `2026-09-28 04:38:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bc52d4f4198c723b3762770e1ea55b9` |
| SHA-1 | `5797cd4f790452831a1cd0c73f580061d360c433` |
| SHA-256 | `e6302aad7ada45983d3a22c525b47e5c5ab6000daab5febcc0a414fbc49a1a32` |
| SHA3-384 | `72582d19e4c84f4d553142a0b3bdd9ddefa8777a6c96ca85c17d84d34e49d87b2a83566428b418e05c32c6ba642c4445` |
| TLSH | `T1A1254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:+WmNVQHYP+SmAC+MqR9p4Wrii7j657yD/hGnmr:KdM4DmUj657yDAmr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_e6302aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6302aad7ada45983d3a22c525b47e5c5ab6000daab5febcc0a414fbc49a1a32"
    family = "Mirai"
    file_name = "bot.armv7"
    file_type = "elf"
    first_seen = "2026-09-28 04:38:25"
  condition:
    hash.sha256(0, filesize) == "e6302aad7ada45983d3a22c525b47e5c5ab6000daab5febcc0a414fbc49a1a32"
}
```

### Sample 62: `9ca5e62c6d31fa8d`

| Field | Value |
|---|---|
| SHA-256 | `9ca5e62c6d31fa8d77360a8e6c5d2602cd57e8b50d89309ab7728e2e133e7043` |
| Family label | `Mirai` |
| File name | `9ca5e62c6d31fa8d.bin` |
| File type | `elf` |
| First seen | `2026-09-28 04:25:45` |
| Reporter | `Tuxxin` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88290402f787aa0b61c6ec5c395c6907` |
| SHA-1 | `0e7a8d81ba428afdcf1568fc435261d62e16d69b` |
| SHA-256 | `9ca5e62c6d31fa8d77360a8e6c5d2602cd57e8b50d89309ab7728e2e133e7043` |
| SHA3-384 | `7979ffe8f8da245d3ef62f5b2ad14c3d9d1293efa57408382f57d7cb7c3307da3feaed2b5a390f540b9dfa1fa98b20e3` |
| TLSH | `T120355C46EF406FEBC49FCD30492EC31721EDE8CB42D5A62971BC4A8C7A5D3590AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:ApvR6ZM35dQ4ZmHd7dcCoLJTxwpTmVXxTCnOKW8p:Y6QS97FixxxxTCnzp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_9ca5e62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ca5e62c6d31fa8d77360a8e6c5d2602cd57e8b50d89309ab7728e2e133e7043"
    family = "Mirai"
    file_name = "9ca5e62c6d31fa8d.bin"
    file_type = "elf"
    first_seen = "2026-09-28 04:25:45"
  condition:
    hash.sha256(0, filesize) == "9ca5e62c6d31fa8d77360a8e6c5d2602cd57e8b50d89309ab7728e2e133e7043"
}
```

### Sample 63: `5871b0701002cbbd`

| Field | Value |
|---|---|
| SHA-256 | `5871b0701002cbbdd2a7ca290f724d69bbe2b0350bb459c02d2215b5364f4d64` |
| Family label | `Mirai` |
| File name | `5871b0701002cbbd.bin` |
| File type | `elf` |
| First seen | `2026-09-28 04:25:34` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b0270cf69c6854067dea92504e09534` |
| SHA-1 | `90cc20f4e933cb631ddeb435662ed8db9215df97` |
| SHA-256 | `5871b0701002cbbdd2a7ca290f724d69bbe2b0350bb459c02d2215b5364f4d64` |
| SHA3-384 | `71a9aa6b79180dda26eacfe23effb5af4ae78df751d91d8430f481cfe710f1f68b4107f255ec3e4514a0b6ce20c9f697` |
| TLSH | `T15EA48EC574408C7EEC46A67A8B171A06A231D33120C3971FB36FBD6A6E7B1B56A31F41` |
| SSDEEP | `12288:1nsIuS6NcDrjJJEzR+5IS3ih7hvu35gP264t9Yp+VVBA:9sIuNcrrEt+5IS3iC35gP264UQ/C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_5871b070
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5871b0701002cbbdd2a7ca290f724d69bbe2b0350bb459c02d2215b5364f4d64"
    family = "Mirai"
    file_name = "5871b0701002cbbd.bin"
    file_type = "elf"
    first_seen = "2026-09-28 04:25:34"
  condition:
    hash.sha256(0, filesize) == "5871b0701002cbbdd2a7ca290f724d69bbe2b0350bb459c02d2215b5364f4d64"
}
```

### Sample 64: `e2d46a6b81986511`

| Field | Value |
|---|---|
| SHA-256 | `e2d46a6b819865112dd88b7ccbcc34379d2c5711acadd0c6720fcd91b4909096` |
| Family label | `Mirai` |
| File name | `e2d46a6b81986511.bin` |
| File type | `elf` |
| First seen | `2026-09-28 04:25:26` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4b21386b05ddc530816334efbc8bd10` |
| SHA-1 | `81fa3e3e60ecd71bb1e1fd12aafa5c9cb830f1d0` |
| SHA-256 | `e2d46a6b819865112dd88b7ccbcc34379d2c5711acadd0c6720fcd91b4909096` |
| SHA3-384 | `d8d44dc28a68ad40128315bbd027f126775b8fb22ebb452575f04229d86bda86dc522193cdb51ba603498733293b3960` |
| TLSH | `T189B47C22B97D0D2BC4C4A27621F34336F1FB078A20B8961A7ED15F5D6F24A9076173B9` |
| SSDEEP | `6144:4pWNlymnRriNDvlIJ284fTZQYg5ctiQWBGYk6vulibFsit898kbpL5Df:4CTChmUEcOkculibFsE898aVDf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_e2d46a6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2d46a6b819865112dd88b7ccbcc34379d2c5711acadd0c6720fcd91b4909096"
    family = "Mirai"
    file_name = "e2d46a6b81986511.bin"
    file_type = "elf"
    first_seen = "2026-09-28 04:25:26"
  condition:
    hash.sha256(0, filesize) == "e2d46a6b819865112dd88b7ccbcc34379d2c5711acadd0c6720fcd91b4909096"
}
```

### Sample 65: `d2308ce690cdcc2a`

| Field | Value |
|---|---|
| SHA-256 | `d2308ce690cdcc2a36398b46275c093afb4cfb8360324516f331cde41b5280e3` |
| Family label | `unknown` |
| File name | `d2308ce690cdcc2a.bin` |
| File type | `exe` |
| First seen | `2026-09-28 04:25:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bac9ba849e5f0de203e9c11363c15676` |
| SHA-1 | `72a663a9bb8da8505ab154401fba9e64347dcb52` |
| SHA-256 | `d2308ce690cdcc2a36398b46275c093afb4cfb8360324516f331cde41b5280e3` |
| SHA3-384 | `5b5f8d72fa25feb6d9176ec70e2841274239dc5a65fb28636143309abfb46d2cb6419b5213f0ae22f2b79f68350c45c2` |
| IMPHASH | `8e634bf18a2cb3c72ea1a67a6bf93841` |
| TLSH | `T160E633E16AF16427ED87B4B4D40482613A504AB8437676C8A194E6AF4C3D60BCD3DFFB` |
| SSDEEP | `393216:bgtsDjfCwjdVcC6IkI1Jy7Yukl4er794USdwZjffoOKQ:bmsDjHAIkMJy7der+US4fog` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_d2308ce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2308ce690cdcc2a36398b46275c093afb4cfb8360324516f331cde41b5280e3"
    family = "unknown"
    file_name = "d2308ce690cdcc2a.bin"
    file_type = "exe"
    first_seen = "2026-09-28 04:25:18"
  condition:
    hash.sha256(0, filesize) == "d2308ce690cdcc2a36398b46275c093afb4cfb8360324516f331cde41b5280e3"
}
```

### Sample 66: `9278510531077f07`

| Field | Value |
|---|---|
| SHA-256 | `9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b` |
| Family label | `Mirai` |
| File name | `9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b` |
| File type | `elf` |
| First seen | `2026-09-28 04:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd82c86224ca20f626a21a7bd78999c8` |
| SHA-1 | `cb654e1fe687505030d621d52b0f58560cbce38e` |
| SHA-256 | `9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b` |
| SHA3-384 | `134e63d88984e0a0c9c231db263d8ef4648bfc93b817e07baa5ffed5c9f18896a777076dd9a35a6fe55e32b9da0619d0` |
| TLSH | `T15944398AFD80AF25D5C5267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJd:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_92785105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b"
    family = "Mirai"
    file_name = "9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b"
    file_type = "elf"
    first_seen = "2026-09-28 04:17:14"
  condition:
    hash.sha256(0, filesize) == "9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b"
}
```

### Sample 67: `65117fae4f2948dd`

| Field | Value |
|---|---|
| SHA-256 | `65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b` |
| Family label | `unknown` |
| File name | `65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b.exe` |
| File type | `exe` |
| First seen | `2026-09-28 04:10:46` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9e750a9601149126e056104f3c70c06` |
| SHA-1 | `3a6dc92a149a2a223b0ef730d2f2c7ab965d95fc` |
| SHA-256 | `65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b` |
| SHA3-384 | `bb5f2e126c9b203973d3592ae0d5906c63594eccfceb78c83393e33bc0d9acc46b03560bcdc89b3eb64dd573985df0ce` |
| IMPHASH | `5a594319a0d69dbc452e748bcf05892e` |
| TLSH | `T1D0B6233BE15B633DC4AA06313473967488377F24A56A9C1A83E83D2DDF364616E3B217` |
| SSDEEP | `196608:DvBJMmyCZkmIxfiwepxBseO12N5eh3hD+d0JcBD+ilXt84cc0tCknL1wgp5ek3M:VqG+tMqn2beh3hD+WG+ild6CkJb5JM` |
| ICON-DHASH | `f0cc9a90a4a6d870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_65117fae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b"
    family = "unknown"
    file_name = "65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b.exe"
    file_type = "exe"
    first_seen = "2026-09-28 04:10:46"
  condition:
    hash.sha256(0, filesize) == "65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b"
}
```

### Sample 68: `0593552ee0df53f8`

| Field | Value |
|---|---|
| SHA-256 | `0593552ee0df53f8e2fb80f5748606403989d14536d076d4328e4956f5455a46` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-28 04:04:07` |
| Reporter | `Bitsight` |
| Tags | `B, BB3.file, dropped-by-GCleaner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7267e72a761be150e0a555c3d9e045a9` |
| SHA-1 | `cfe8fcdd4d69d038de2aa9f6cdad25d40a221da9` |
| SHA-256 | `0593552ee0df53f8e2fb80f5748606403989d14536d076d4328e4956f5455a46` |
| SHA3-384 | `ab5ee8ad5fe42d3a1062289e42a0778b3fcdda20f0da5b4f70575fd053e427875f872e9542ff492095ec89c5168bcb9e` |
| IMPHASH | `be0b837795c83809073fce17d1dbc4b9` |
| TLSH | `T15715AC65A36C0CB8FF61843685A43E628399BC508BDB6BDF411DC628AD65B8C15F7F30` |
| SSDEEP | `12288:cfK2XiYkjoMXXZrOihsN2xFum/umH/HQX9qjK+QB6yJ9N+zd:uX2HR122yorvQtf+nu9s` |
| ICON-DHASH | `2854b27171b25428` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_0593552e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0593552ee0df53f8e2fb80f5748606403989d14536d076d4328e4956f5455a46"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-28 04:04:07"
  condition:
    hash.sha256(0, filesize) == "0593552ee0df53f8e2fb80f5748606403989d14536d076d4328e4956f5455a46"
}
```

### Sample 69: `cdcd92f9e3af2925`

| Field | Value |
|---|---|
| SHA-256 | `cdcd92f9e3af2925829eaf9e8d366ae2e750bded64d212484995378eb1839025` |
| Family label | `unknown` |
| File name | `z1OCTOBERINQUIRY2_PDF.bat` |
| File type | `exe` |
| First seen | `2026-09-28 04:00:08` |
| Reporter | `fabiodemartin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba950d395281c35af36d1cf375a27687` |
| SHA-1 | `8e6683d52091766cc83c79f8cac5b2a80ff05657` |
| SHA-256 | `cdcd92f9e3af2925829eaf9e8d366ae2e750bded64d212484995378eb1839025` |
| SHA3-384 | `08193ef4822bf63b2daacd3664f0c781ff91df5ebecc559274916ba3b09930a185e459777f56ef728736f0cf7957b028` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1EA05D02C22949E03C13E83B98575E27423F05D4AE416D70A9ED9FCEB3D21BD13D4A6A7` |
| SSDEEP | `12288:BvPn/NKHwreWhIbKk6cNPV/JfSS1aHTgyn/HqsW2t6P3d1aB4e/jVwd82GAWF0h9:B83dRlAbAy0Iftv1/PSeIGAT` |
| ICON-DHASH | `c0c292f070de8e00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_cdcd92f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdcd92f9e3af2925829eaf9e8d366ae2e750bded64d212484995378eb1839025"
    family = "unknown"
    file_name = "z1OCTOBERINQUIRY2_PDF.bat"
    file_type = "exe"
    first_seen = "2026-09-28 04:00:08"
  condition:
    hash.sha256(0, filesize) == "cdcd92f9e3af2925829eaf9e8d366ae2e750bded64d212484995378eb1839025"
}
```

### Sample 70: `7c1deaf3dd4d1181`

| Field | Value |
|---|---|
| SHA-256 | `7c1deaf3dd4d11811fff1d221fe4944a89cd98d8e48f3435c6fe374aadc9ec45` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-28 03:46:24` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX9.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `337d04b37ee145232aedef18df8dea1e` |
| SHA-1 | `7d29c3d5303fd8bdc1d5f3d04f9a52d2a926f1d8` |
| SHA-256 | `7c1deaf3dd4d11811fff1d221fe4944a89cd98d8e48f3435c6fe374aadc9ec45` |
| SHA3-384 | `2f51f895edc885ec840b6247fff9609eece3343137c1eaac77b679b2de5ea75e13fb0b7f4787f116f40b8bf1cf2dfa8c` |
| IMPHASH | `fd6f6d07cc33ee9a2b65bda58a07bb94` |
| TLSH | `T102286C43A2E751D8F0BBD17496E65323E933BC490B3469EF12944B312F72AE0A779B11` |
| SSDEEP | `1572864:fZa7hmguP2nG0/Vyv7UhgxIabc/97Awb0:fZa7hmguP2nUOTAwb0` |
| ICON-DHASH | `9170cc9296cc7001` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_7c1deaf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c1deaf3dd4d11811fff1d221fe4944a89cd98d8e48f3435c6fe374aadc9ec45"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-28 03:46:24"
  condition:
    hash.sha256(0, filesize) == "7c1deaf3dd4d11811fff1d221fe4944a89cd98d8e48f3435c6fe374aadc9ec45"
}
```

### Sample 71: `9b0a0e395124d4a6`

| Field | Value |
|---|---|
| SHA-256 | `9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685` |
| Family label | `unknown` |
| File name | `9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685.bin` |
| File type | `zip` |
| First seen | `2026-09-28 03:37:07` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `506a1e21a51988f3feb4b4c0ba615d68` |
| SHA-1 | `b1af8f1419093a0f544fb64b71fb9989960da2df` |
| SHA-256 | `9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685` |
| SHA3-384 | `a4b9f10c2a04745c1615a01b4534a47723f25be0fab31c2a58c84f469b3a621ef9ed9c3152e4942744c4d8c2cb86b052` |
| TLSH | `T1D9F53396377C3502612B7AC13FE821E61DB5374A948C283581DBD26A9403BF6ABFF1D1` |
| SSDEEP | `98304:Je52OBlXuTjUrgZuvOSciUg5KKg8tjNiFCDH+tJ/cnS:5E4UrzvtwK1HD4tQS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_9b0a0e39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685"
    family = "unknown"
    file_name = "9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685.bin"
    file_type = "zip"
    first_seen = "2026-09-28 03:37:07"
  condition:
    hash.sha256(0, filesize) == "9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685"
}
```

### Sample 72: `74a104cfcea6ea63`

| Field | Value |
|---|---|
| SHA-256 | `74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6` |
| Family label | `unknown` |
| File name | `74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6.bin` |
| File type | `unknown` |
| First seen | `2026-09-28 03:37:02` |
| Reporter | `Tuxxin` |
| Tags | `jpg, stego` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90da90b90834026eabde0b8377fb82aa` |
| SHA-256 | `74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_74a104cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6"
    family = "unknown"
    file_name = "74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 03:37:02"
  condition:
    hash.sha256(0, filesize) == "74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6"
}
```

### Sample 73: `a43565efdc71fc93`

| Field | Value |
|---|---|
| SHA-256 | `a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b` |
| Family label | `VShell` |
| File name | `a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:36:16` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f1f9feaed98efec49a5eaa2ff9291a0` |
| SHA-1 | `65000b14f5e9d0727810b8b8b01cd783d92667ac` |
| SHA-256 | `a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b` |
| SHA3-384 | `e56c3b2a4cc28ce7f107b608d09393d54d5033cf67a9e93a7dcc8a5fa20c261a49643179ffc93757fc926b74c1a82a22` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T11791C64270B999E7E85C41BB4C0FB8A0B919780A41C483B60338A5953E3957BF5BCB0E` |
| SSDEEP | `48:6IIF9BlQaexMgZS7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMV70cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_073_a43565ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b"
    family = "VShell"
    file_name = "a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:16"
  condition:
    hash.sha256(0, filesize) == "a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b"
}
```

### Sample 74: `af1311d7cf8a15a8`

| Field | Value |
|---|---|
| SHA-256 | `af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d` |
| Family label | `VShell` |
| File name | `af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:36:12` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba3240e72d9f54bead3c25e5734804ce` |
| SHA-1 | `b236650f63aab312930ca04185e100ed7294f9bb` |
| SHA-256 | `af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d` |
| SHA3-384 | `1e7f1229ac9eb94693fa2eb04ee5095f5151f260b1720039b380d79bcc1d248a4e038ac13549580e7ef938d8a391752f` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F79195C5F757E6B6EC1C07F500A37994C4682E14926C9B564FA16F1C3C111AA3C3DA12` |
| SSDEEP | `48:6I7lwe7ea08SEJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1H092q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_074_af1311d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d"
    family = "VShell"
    file_name = "af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:12"
  condition:
    hash.sha256(0, filesize) == "af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d"
}
```

### Sample 75: `8137187c5c9266b9`

| Field | Value |
|---|---|
| SHA-256 | `8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea` |
| Family label | `VShell` |
| File name | `8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:36:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `702a6dfef3a27f5aa02cea0618005dbf` |
| SHA-1 | `891d1343b3654202c6d0c1f00f42b76c8d5d14b2` |
| SHA-256 | `8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea` |
| SHA3-384 | `e7076c7e0ce401fc3cb1efe2abd761d48eff49367d34cba76efa8aabf3498d21194594a1e2df6f0cfa98768196eb2c2b` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1B771B54160545AF2D94CA37F8487B8A5FD4EB248A2C80B0F03D8981A3F7547BB0DD613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DfF/8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6Df9G++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_075_8137187c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea"
    family = "VShell"
    file_name = "8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:09"
  condition:
    hash.sha256(0, filesize) == "8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea"
}
```

### Sample 76: `bc4633b53ce18d54`

| Field | Value |
|---|---|
| SHA-256 | `bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8` |
| Family label | `VShell` |
| File name | `bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:36:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64738c7925b8a9391c0dbc3350c241cc` |
| SHA-1 | `61772558d023a483e7425e2f1c8d38679208e21d` |
| SHA-256 | `bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8` |
| SHA3-384 | `f02a41d9af1f2c158baf9de263a3aded3119ba1483542e80cc6f769d5887934bc81bfe24a5069fd48a4dcc9d6957393a` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T12991C64170B989E7E85C82BF4C0FB8A4B919740A41C483A70378A5953F3957BF57CB0E` |
| SSDEEP | `48:6IIF9BlQaexqgZU7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaML90cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_076_bc4633b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8"
    family = "VShell"
    file_name = "bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:05"
  condition:
    hash.sha256(0, filesize) == "bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8"
}
```

### Sample 77: `99a9b6e21b5ef547`

| Field | Value |
|---|---|
| SHA-256 | `99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c` |
| Family label | `VShell` |
| File name | `99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:36:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fd749f487fa56317682edf7def16e59` |
| SHA-1 | `8381cab199ea519253fbccfdb5cc327385f7e5f9` |
| SHA-256 | `99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c` |
| SHA3-384 | `f1556b87b5cdd01753173c57f6dd0cc0593672d26776910d6aacf129a4ab11ecacf66172bc6bfacee01c08bfa09acc6b` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T15B91A5C5F757E6B2EC1C07F500A3B9A8C8682E14927C9B464FA16F1C3C111AA3C3DA52` |
| SSDEEP | `48:6I7lwe7HH08SFbJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1L09Flq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_077_99a9b6e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c"
    family = "VShell"
    file_name = "99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:01"
  condition:
    hash.sha256(0, filesize) == "99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c"
}
```

### Sample 78: `156587f7d2c1c5be`

| Field | Value |
|---|---|
| SHA-256 | `156587f7d2c1c5bec5deaeabf16cbce6c23bad000f47bb3f1c93ccc68fb347e3` |
| Family label | `AgentTesla` |
| File name | `SecuriteInfo.com.Trojan.Siggen34.18774.960.2461` |
| File type | `exe` |
| First seen | `2026-09-28 03:34:48` |
| Reporter | `SecuriteInfoCom` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9c0334d9bd44828d901585f52e4ca75` |
| SHA-1 | `be3c7c02e48c1f22ceebd0db93d407f5dfbcaa43` |
| SHA-256 | `156587f7d2c1c5bec5deaeabf16cbce6c23bad000f47bb3f1c93ccc68fb347e3` |
| SHA3-384 | `bc45d01d0ebad983134ac9b2097abdd19d92aa7cc53a859c35af149e1cc9b6e35a2c2dd398e5f5ac64246014ee6b006d` |
| IMPHASH | `e5a02d39d303ad3ced050f9b5d3b67d8` |
| TLSH | `T16BF5AE11E7D405E4E4A7DA30CE6AC332D772B8961731974B0564D31A2E7BAD28F7B322` |
| SSDEEP | `49152:xFstbQOlUEGj9xRz/ZZj1tUHtZC4gFiDmXgHN07FhZ9J94H444tr:Yif1gtZ0YIhXz4H444t` |
| ICON-DHASH | `36c29292b2e88c82` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_078_156587f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "156587f7d2c1c5bec5deaeabf16cbce6c23bad000f47bb3f1c93ccc68fb347e3"
    family = "AgentTesla"
    file_name = "SecuriteInfo.com.Trojan.Siggen34.18774.960.2461"
    file_type = "exe"
    first_seen = "2026-09-28 03:34:48"
  condition:
    hash.sha256(0, filesize) == "156587f7d2c1c5bec5deaeabf16cbce6c23bad000f47bb3f1c93ccc68fb347e3"
}
```

### Sample 79: `bd8204ba17d68dd6`

| Field | Value |
|---|---|
| SHA-256 | `bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3` |
| Family label | `unknown` |
| File name | `bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3.bin` |
| File type | `zip` |
| First seen | `2026-09-28 03:27:28` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bc8893502696c18a993e00a3ec6b987` |
| SHA-1 | `9bc692fc29ef942ac6c7d44d9e7684bfd39ec2bb` |
| SHA-256 | `bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3` |
| SHA3-384 | `7db95e36f64a5d8ae11f4eb267e596e7f29fdf20b84983a534633b5afe5397bd500eead93b7084208cd150bf40944ed3` |
| TLSH | `T124B42378AE4A00F0D643EF5308D59B8773B0B6E9958387B377E4419D852AF2E9707AC1` |
| SSDEEP | `12288:bsReyv+Two5LY75Fi9noIA7oBg/aBqOTzNjF54SrIou4e:bgJ+TwmYTM5Bg/2qGRjF5NMoc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_bd8204ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3"
    family = "unknown"
    file_name = "bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3.bin"
    file_type = "zip"
    first_seen = "2026-09-28 03:27:28"
  condition:
    hash.sha256(0, filesize) == "bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3"
}
```

### Sample 80: `2e9abac78aa18468`

| Field | Value |
|---|---|
| SHA-256 | `2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc` |
| Family label | `unknown` |
| File name | `2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:26:39` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bdf4d745aa90adc5bc0028368190fe9` |
| SHA-1 | `caf30f5ffce93e9afd245e9df7cd72b12d42f0a2` |
| SHA-256 | `2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc` |
| SHA3-384 | `5aa95740f63cf0f5ab1cc6d2ea4de9b64d50564081184369ff0ad44ab46039ca2d683e5042ad254fdb2f67dc504391ad` |
| IMPHASH | `51f452a5729c88fc9e654d9753692e61` |
| TLSH | `T1F5F4AE2CF626CFF2D6A7507E4D93CD02A2F07A0A7351FBC78E2146A86A135D58573386` |
| SSDEEP | `12288:EKBSIvLx1cphYcQduB8lVlQK/+l+F6DGRg8O:E8dx1c4duKDeK/+lEg8` |
| ICON-DHASH | `b0bcd0a2aaece96b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_2e9abac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc"
    family = "unknown"
    file_name = "2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:26:39"
  condition:
    hash.sha256(0, filesize) == "2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc"
}
```

### Sample 81: `33a65343384128e0`

| Field | Value |
|---|---|
| SHA-256 | `33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d` |
| Family label | `VShell` |
| File name | `33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:26:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4304d2489f2c460a93bfca18ca302873` |
| SHA-1 | `c1b3971100cd925f0f2b8449dc850dda9cc07532` |
| SHA-256 | `33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d` |
| SHA3-384 | `1a283f450b43eeae110303cf9db2ab78f1a8790e9b6b940b0b48dab867fbedc922a35348598964a8f9f841edd2310289` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1C291B6C5F75BE6B2EC1C17F500A3B9A4C8682E14927C9B474FA16F0C3C111AA3D7EA12` |
| SSDEEP | `48:6I7lwe75ti08SCJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1NM098q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_081_33a65343
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d"
    family = "VShell"
    file_name = "33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:26:18"
  condition:
    hash.sha256(0, filesize) == "33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d"
}
```

### Sample 82: `8a464667e80d48e4`

| Field | Value |
|---|---|
| SHA-256 | `8a464667e80d48e4fe7bcbc98faaf5e3e306d8ee3f4986f9d24b5ce58144f59c` |
| Family label | `unknown` |
| File name | `8a464667e80d48e4.bin` |
| File type | `unknown` |
| First seen | `2026-09-28 03:26:00` |
| Reporter | `Tuxxin` |
| Tags | `powershell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edd2b33f24c5d959b47c4b699d72b80d` |
| SHA-256 | `8a464667e80d48e4fe7bcbc98faaf5e3e306d8ee3f4986f9d24b5ce58144f59c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_8a464667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a464667e80d48e4fe7bcbc98faaf5e3e306d8ee3f4986f9d24b5ce58144f59c"
    family = "unknown"
    file_name = "8a464667e80d48e4.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 03:26:00"
  condition:
    hash.sha256(0, filesize) == "8a464667e80d48e4fe7bcbc98faaf5e3e306d8ee3f4986f9d24b5ce58144f59c"
}
```

### Sample 83: `8b690a6e3b6f301b`

| Field | Value |
|---|---|
| SHA-256 | `8b690a6e3b6f301bf0bf6b6ee123933333c8c6036af5633b934c0b0e6cf27fb5` |
| Family label | `Mirai` |
| File name | `8b690a6e3b6f301b.bin` |
| File type | `elf` |
| First seen | `2026-09-28 03:25:52` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab30bcf794c02082a6385b9fba9ca426` |
| SHA-1 | `0f05f8b1bd8b4af405844a0ea7b880d20810d048` |
| SHA-256 | `8b690a6e3b6f301bf0bf6b6ee123933333c8c6036af5633b934c0b0e6cf27fb5` |
| SHA3-384 | `bf233233edf37e45e0e270b1a233cd8b8325002f4fc4abe346e731122cc2d5e92f2287698d46e57aec10985f75fbe6dc` |
| TLSH | `T129F13256BAEBCD73CCAD233A07678714337588D2AB42AB13611C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8Dt/WC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7X4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_8b690a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b690a6e3b6f301bf0bf6b6ee123933333c8c6036af5633b934c0b0e6cf27fb5"
    family = "Mirai"
    file_name = "8b690a6e3b6f301b.bin"
    file_type = "elf"
    first_seen = "2026-09-28 03:25:52"
  condition:
    hash.sha256(0, filesize) == "8b690a6e3b6f301bf0bf6b6ee123933333c8c6036af5633b934c0b0e6cf27fb5"
}
```

### Sample 84: `1c9dd1d98bbb1022`

| Field | Value |
|---|---|
| SHA-256 | `1c9dd1d98bbb1022bbf1ac02952be2c53b8fbf69b9428c4b2fc59c422b72fa03` |
| Family label | `unknown` |
| File name | `1c9dd1d98bbb1022.bin` |
| File type | `unknown` |
| First seen | `2026-09-28 03:25:45` |
| Reporter | `Tuxxin` |
| Tags | `powershell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebce85596539ea769c1ac2823b246eab` |
| SHA-256 | `1c9dd1d98bbb1022bbf1ac02952be2c53b8fbf69b9428c4b2fc59c422b72fa03` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_1c9dd1d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c9dd1d98bbb1022bbf1ac02952be2c53b8fbf69b9428c4b2fc59c422b72fa03"
    family = "unknown"
    file_name = "1c9dd1d98bbb1022.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 03:25:45"
  condition:
    hash.sha256(0, filesize) == "1c9dd1d98bbb1022bbf1ac02952be2c53b8fbf69b9428c4b2fc59c422b72fa03"
}
```

### Sample 85: `0acc12e3993609d5`

| Field | Value |
|---|---|
| SHA-256 | `0acc12e3993609d539bb2c1c7f0543c7ca6b03158c9f8e265e57650a4f9d9ee2` |
| Family label | `unknown` |
| File name | `0acc12e3993609d5.bin` |
| File type | `unknown` |
| First seen | `2026-09-28 03:25:38` |
| Reporter | `Tuxxin` |
| Tags | `powershell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fef10f844aaeb566c0b59dc66a8088d0` |
| SHA-256 | `0acc12e3993609d539bb2c1c7f0543c7ca6b03158c9f8e265e57650a4f9d9ee2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_0acc12e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0acc12e3993609d539bb2c1c7f0543c7ca6b03158c9f8e265e57650a4f9d9ee2"
    family = "unknown"
    file_name = "0acc12e3993609d5.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 03:25:38"
  condition:
    hash.sha256(0, filesize) == "0acc12e3993609d539bb2c1c7f0543c7ca6b03158c9f8e265e57650a4f9d9ee2"
}
```

### Sample 86: `32a6d9badcd78d83`

| Field | Value |
|---|---|
| SHA-256 | `32a6d9badcd78d8313b9437f14030192ceb40b4926ec6d4b0c457f2edb6f09ec` |
| Family label | `unknown` |
| File name | `32a6d9badcd78d83.bin` |
| File type | `elf` |
| First seen | `2026-09-28 03:25:31` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80d809da2e3b71fc386d7f4062430754` |
| SHA-1 | `e9656ade4e16c032807915457eb6f88475dbffec` |
| SHA-256 | `32a6d9badcd78d8313b9437f14030192ceb40b4926ec6d4b0c457f2edb6f09ec` |
| SHA3-384 | `a4e491c4e0ed9d0bc04eb655d2799027b6f1eceebfa34e6b50ad5735086b3f14cb715f47a6b6ab60811b338cc7e73d3f` |
| TLSH | `T149E13382BDD6CE3BCCE9627A1673C6203372C551AB439B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScs3Lmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvqg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_32a6d9ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32a6d9badcd78d8313b9437f14030192ceb40b4926ec6d4b0c457f2edb6f09ec"
    family = "unknown"
    file_name = "32a6d9badcd78d83.bin"
    file_type = "elf"
    first_seen = "2026-09-28 03:25:31"
  condition:
    hash.sha256(0, filesize) == "32a6d9badcd78d8313b9437f14030192ceb40b4926ec6d4b0c457f2edb6f09ec"
}
```

### Sample 87: `3147f3315cdac01c`

| Field | Value |
|---|---|
| SHA-256 | `3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4` |
| Family label | `unknown` |
| File name | `3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4` |
| File type | `elf` |
| First seen | `2026-09-28 03:18:42` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, x64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c30f1de728c47d19ad03f44f2afd3a4` |
| SHA-1 | `6f7a45b592223c650f40eb1077cc3d1127c4c80b` |
| SHA-256 | `3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4` |
| SHA3-384 | `90ea52a05bdfde3cb2475bde371fb72314cfea91f2ef46834ce8709a83f4da0a2bdba87ae3fb1f441e69576f7cbd8eea` |
| TLSH | `T13B866C73905224D8E1ADC974D5141652BDB83C8B573863CBBAC476F61BBABE48E78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQg:cqYUQuVDt0TZEr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_3147f331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4"
    family = "unknown"
    file_name = "3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4"
    file_type = "elf"
    first_seen = "2026-09-28 03:18:42"
  condition:
    hash.sha256(0, filesize) == "3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4"
}
```

### Sample 88: `6b041a9a83d4ed55`

| Field | Value |
|---|---|
| SHA-256 | `6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc` |
| Family label | `Mirai` |
| File name | `6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc` |
| File type | `elf` |
| First seen | `2026-09-28 03:18:34` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91d95ee2d98d0afbf1070cb73e81ee34` |
| SHA-1 | `342b10b8f83bf93d8d934ff8a7061e4b642e52b7` |
| SHA-256 | `6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc` |
| SHA3-384 | `1d70fc333115c36604909f59333f8fbb0cfbca3d28e30f7f13d7a5260b4bab3e75d1fe70906af0007cc3134b4ed6ac2a` |
| TLSH | `T15F04198AFD81AF5585C527BBFE2E418A331317B8D2EE71129D141F2877CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwKSDPG:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZR5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_6b041a9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc"
    family = "Mirai"
    file_name = "6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc"
    file_type = "elf"
    first_seen = "2026-09-28 03:18:34"
  condition:
    hash.sha256(0, filesize) == "6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc"
}
```

### Sample 89: `c5b8ac5d26a96a9f`

| Field | Value |
|---|---|
| SHA-256 | `c5b8ac5d26a96a9ff4d628603e06c2fb5a40914b8fdd8b6b429a90cb72bc6828` |
| Family label | `AgentTesla` |
| File name | `Comprobante de pago.js` |
| File type | `js` |
| First seen | `2026-09-28 03:16:27` |
| Reporter | `nat` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa5be1f6677562d0bb27fad94cff2866` |
| SHA-1 | `84965309ea373556aa1a985d31b5e0dd8be6a706` |
| SHA-256 | `c5b8ac5d26a96a9ff4d628603e06c2fb5a40914b8fdd8b6b429a90cb72bc6828` |
| SHA3-384 | `55855d7aa20203bdcd430a8c558eac180f2eb1fe6732cc5c96cd8b11217f7559fa902cf3afe9cc73772a1e2ae3d0c01b` |
| TLSH | `T1EDE24C8B28C23D4593F1373D2572629BDC1B56E2045AE8EF2B4C323BD958A435CDB51B` |
| SSDEEP | `96:AGIzhAtOdouW0gZaZlgVdas4yztZAD3XrU7yjhAL2CQNo88enkVDkg/RM4tV:/IytOdouX8KlN6+3bU72AL2FqtenE1b` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_089_c5b8ac5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5b8ac5d26a96a9ff4d628603e06c2fb5a40914b8fdd8b6b429a90cb72bc6828"
    family = "AgentTesla"
    file_name = "Comprobante de pago.js"
    file_type = "js"
    first_seen = "2026-09-28 03:16:27"
  condition:
    hash.sha256(0, filesize) == "c5b8ac5d26a96a9ff4d628603e06c2fb5a40914b8fdd8b6b429a90cb72bc6828"
}
```

### Sample 90: `04ef5c970c0f02f7`

| Field | Value |
|---|---|
| SHA-256 | `04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5` |
| Family label | `unknown` |
| File name | `04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:11:10` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a13552f4d6924a905734bcd794da46fe` |
| SHA-1 | `2804154770ba9b1757f677565195aaa0e39fff7d` |
| SHA-256 | `04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5` |
| SHA3-384 | `f9855390823fb55dbfd24c170c6e9296e1e190bd7bd3ad6e6baab117f550ec714cda1df8071a71b150b687db9732693e` |
| IMPHASH | `351592d5ead6df0859b0cc0056827c95` |
| TLSH | `T16BC6338423D10990F89FB23D69D1966B83E174311B21C6DB1BF08DA52E632F6EF35B91` |
| SSDEEP | `196608:XdAAEmvtbW897G6x7eovq5XMP6PzFc3W1/zMkKFcaPuxVHsoq1bRjMFQ7:aFA1bdq1B7nrhKmaPWHsoq1bpi8` |
| ICON-DHASH | `aebc385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_04ef5c97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5"
    family = "unknown"
    file_name = "04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:11:10"
  condition:
    hash.sha256(0, filesize) == "04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5"
}
```

### Sample 91: `7a391650af7b6018`

| Field | Value |
|---|---|
| SHA-256 | `7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b` |
| Family label | `unknown` |
| File name | `7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b.exe` |
| File type | `exe` |
| First seen | `2026-09-28 03:11:04` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `603b21e8f3c6f84e38dcf9b015e00e25` |
| SHA-1 | `11b59d05125f25999c50cee664f1faf1ee9445dd` |
| SHA-256 | `7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b` |
| SHA3-384 | `5e656f34b5eeaabf7b6cfee530ed914d55ef12daafac323e192bdaa804333b4783497f3c77d95ea8a85efcca42739e0b` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T1BDB6331D7548CCE9D23B4B339E6B96D89EA4D23857C742BB878FA6DC484A4007B3F509` |
| SSDEEP | `196608:9w+yrU8VbkjitJP3lrAzfDxcqoGnnng6I6cvo9Xgmz8aQZLX:9wjtkW/hAz7xcknnb1XgmzfELX` |
| ICON-DHASH | `c4dadadad2f492c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_7a391650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b"
    family = "unknown"
    file_name = "7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:11:04"
  condition:
    hash.sha256(0, filesize) == "7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b"
}
```

### Sample 92: `92e29d3fc00ab0cb`

| Field | Value |
|---|---|
| SHA-256 | `92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077` |
| Family label | `VShell` |
| File name | `92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077.exe` |
| File type | `exe` |
| First seen | `2026-09-28 02:35:21` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `486458bb4b2c6e9428283475eefb6737` |
| SHA-1 | `942bafeeebad9afd4e5215a3cb47a5172c8dd958` |
| SHA-256 | `92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077` |
| SHA3-384 | `076b8b2e768db60890359c39a5d79d593777c85b0c6be09c76030972417e546da2c3f5393e85cd67250ce183dc1ab2f7` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1239194C5F757E6B2EC1C07F500A3B9A4C4A82E18827C9B464FA16F1C3C111AA3C3DA52` |
| SSDEEP | `48:6I7lwe7Bj8z08SOJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1djg09gq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_092_92e29d3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077"
    family = "VShell"
    file_name = "92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077.exe"
    file_type = "exe"
    first_seen = "2026-09-28 02:35:21"
  condition:
    hash.sha256(0, filesize) == "92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077"
}
```

### Sample 93: `c26b798fa5d4e7a5`

| Field | Value |
|---|---|
| SHA-256 | `c26b798fa5d4e7a5b9dc5478ccdc7f57af8d5d66f343cf4ed86c32e5ef2d1dcb` |
| Family label | `unknown` |
| File name | `c26b798fa5d4e7a5.bin` |
| File type | `unknown` |
| First seen | `2026-09-28 02:26:00` |
| Reporter | `Tuxxin` |
| Tags | `powershell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d59ae3012ed62ce8947fd000e1d56ba1` |
| SHA-256 | `c26b798fa5d4e7a5b9dc5478ccdc7f57af8d5d66f343cf4ed86c32e5ef2d1dcb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_c26b798f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c26b798fa5d4e7a5b9dc5478ccdc7f57af8d5d66f343cf4ed86c32e5ef2d1dcb"
    family = "unknown"
    file_name = "c26b798fa5d4e7a5.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 02:26:00"
  condition:
    hash.sha256(0, filesize) == "c26b798fa5d4e7a5b9dc5478ccdc7f57af8d5d66f343cf4ed86c32e5ef2d1dcb"
}
```

### Sample 94: `431f3f1064aa30ef`

| Field | Value |
|---|---|
| SHA-256 | `431f3f1064aa30efe9df89246dbfac78edb1a1b82b1adadfce500540c002949f` |
| Family label | `unknown` |
| File name | `431f3f1064aa30ef.bin` |
| File type | `unknown` |
| First seen | `2026-09-28 02:25:53` |
| Reporter | `Tuxxin` |
| Tags | `powershell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `776e3ae75e06edbfd0b702521b89950c` |
| SHA-256 | `431f3f1064aa30efe9df89246dbfac78edb1a1b82b1adadfce500540c002949f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_431f3f10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "431f3f1064aa30efe9df89246dbfac78edb1a1b82b1adadfce500540c002949f"
    family = "unknown"
    file_name = "431f3f1064aa30ef.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 02:25:53"
  condition:
    hash.sha256(0, filesize) == "431f3f1064aa30efe9df89246dbfac78edb1a1b82b1adadfce500540c002949f"
}
```

### Sample 95: `52f3a917a988edf3`

| Field | Value |
|---|---|
| SHA-256 | `52f3a917a988edf3cd5b32260681e8f7496a20582cf8a845cbb570775032af04` |
| Family label | `unknown` |
| File name | `52f3a917a988edf3.bin` |
| File type | `exe` |
| First seen | `2026-09-28 02:25:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c08591e806a1f35f1b659499eeba7452` |
| SHA-1 | `9867607c39c75ba39fa2c6a97e807d75dfb04d2b` |
| SHA-256 | `52f3a917a988edf3cd5b32260681e8f7496a20582cf8a845cbb570775032af04` |
| SHA3-384 | `f752934d06c43a93261c405a7835137ebff21e143bc5396a0b7014e370cfd548f950690fe0a2db85663288d199349b23` |
| IMPHASH | `272e95a7f66a2a74f00027e0ceec895d` |
| TLSH | `T16ED30229B30364ECE2264278B6EBC777DD70BF610E7A272D45A0C53A2E606411E3CE57` |
| SSDEEP | `3072:vdyDGs0CHlsjLnYnqZ0hNQAYKJIKqKd3uP78S2RL43:bAsjTAqZ07jJ7q2+PAL43` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_52f3a917
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52f3a917a988edf3cd5b32260681e8f7496a20582cf8a845cbb570775032af04"
    family = "unknown"
    file_name = "52f3a917a988edf3.bin"
    file_type = "exe"
    first_seen = "2026-09-28 02:25:46"
  condition:
    hash.sha256(0, filesize) == "52f3a917a988edf3cd5b32260681e8f7496a20582cf8a845cbb570775032af04"
}
```

### Sample 96: `2547138e7138b877`

| Field | Value |
|---|---|
| SHA-256 | `2547138e7138b87794fa01aa287fff646cedc5b486ec855de526a36d0222f846` |
| Family label | `unknown` |
| File name | `2547138e7138b877.bin` |
| File type | `exe` |
| First seen | `2026-09-28 02:25:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd2f02f3e8d2ea744b4476a2406bdf98` |
| SHA-1 | `ee9852df24d1a8120311c88ae6b68ba18b123c45` |
| SHA-256 | `2547138e7138b87794fa01aa287fff646cedc5b486ec855de526a36d0222f846` |
| SHA3-384 | `dd49e18da6750b4b41358e24a520dab7d2a3947f771e73e2472e8d781571d21860627db70a285c2cee702c76c9fe58c8` |
| IMPHASH | `8e634bf18a2cb3c72ea1a67a6bf93841` |
| TLSH | `T1E0E6339A8361B0B0C3770DB0829F35BA557665D36B867538030BAB3D2C1FF629DA4B74` |
| SSDEEP | `393216:hdzfl/DqWUPi9EFfzbVGrCNF7uWoyH5y9Rz:hVl/DqWUM6lCTpIG` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_2547138e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2547138e7138b87794fa01aa287fff646cedc5b486ec855de526a36d0222f846"
    family = "unknown"
    file_name = "2547138e7138b877.bin"
    file_type = "exe"
    first_seen = "2026-09-28 02:25:39"
  condition:
    hash.sha256(0, filesize) == "2547138e7138b87794fa01aa287fff646cedc5b486ec855de526a36d0222f846"
}
```

### Sample 97: `692581e015122cbe`

| Field | Value |
|---|---|
| SHA-256 | `692581e015122cbee3e114e510c07982731fd084eaf1a875482b122163d01e1e` |
| Family label | `unknown` |
| File name | `692581e015122cbe.bin` |
| File type | `exe` |
| First seen | `2026-09-28 02:25:20` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `594894687a709f5414a42cb714c040d0` |
| SHA-1 | `7e5f516598b2c79d5dad4efebc56bdb6d8d046ad` |
| SHA-256 | `692581e015122cbee3e114e510c07982731fd084eaf1a875482b122163d01e1e` |
| SHA3-384 | `c0dc900526a99d38d3b3ebf9425631ab45d52ad12b95bb3c936599317981e59363d269abc4d4bc965cf6c1810241ad6a` |
| IMPHASH | `8e634bf18a2cb3c72ea1a67a6bf93841` |
| TLSH | `T195E63316F5DA4773FF6D843866DABB101384CB28D148777E6AB88DED0C1332E6AE6141` |
| SSDEEP | `393216:U1nAlAGnhhAGB6Fvb5aWlHpkLmi29XLp3F6QpSGk4W:UmlAGh6Go1AUHBi297p16WSJ` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_692581e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "692581e015122cbee3e114e510c07982731fd084eaf1a875482b122163d01e1e"
    family = "unknown"
    file_name = "692581e015122cbe.bin"
    file_type = "exe"
    first_seen = "2026-09-28 02:25:20"
  condition:
    hash.sha256(0, filesize) == "692581e015122cbee3e114e510c07982731fd084eaf1a875482b122163d01e1e"
}
```

### Sample 98: `d7afb964c38aa721`

| Field | Value |
|---|---|
| SHA-256 | `d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd` |
| Family label | `Mirai` |
| File name | `d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd` |
| File type | `elf` |
| First seen | `2026-09-28 02:17:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01d6c6476520d5b35e65f11d8bc6bf4d` |
| SHA-1 | `8346ede456df6946a513857c19f7ed39f3d2e968` |
| SHA-256 | `d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd` |
| SHA3-384 | `f4739632e015d1fc3b105f0a6e703c2f1d08b9496f6886f72cd598fd426504a05d680bb2503e246ad75e9b271d82aa15` |
| TLSH | `T1F9C3088BFC81DE6946C0277BFE2E418A330327B4D1DF71539D141F68B68A94F0E6A652` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJe:T2s/gAWuboqsJ9xcJxspJBqQgTuaJe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_d7afb964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd"
    family = "Mirai"
    file_name = "d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd"
    file_type = "elf"
    first_seen = "2026-09-28 02:17:14"
  condition:
    hash.sha256(0, filesize) == "d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd"
}
```

### Sample 99: `a8cf66a587dfd8b7`

| Field | Value |
|---|---|
| SHA-256 | `a8cf66a587dfd8b72903c8a4dad059b8c829e5818f7cd5675583b03a7a2b9112` |
| Family label | `Mirai` |
| File name | `stub.armv7` |
| File type | `elf` |
| First seen | `2026-09-28 01:45:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `579ddc4de24e62d6392930e5c50a0355` |
| SHA-1 | `a01855a838c6cb7ccc674db239d8714ee08f3e3f` |
| SHA-256 | `a8cf66a587dfd8b72903c8a4dad059b8c829e5818f7cd5675583b03a7a2b9112` |
| SHA3-384 | `917c586fe0db1037effdc0664ef4dcab258fce93146d47a5f01074ca3ef4d1a0837f4debcd2e44d7f182faed33cba03e` |
| TLSH | `T197D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiEz:YCp7mXtni6aBh321eSiVWK/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_a8cf66a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8cf66a587dfd8b72903c8a4dad059b8c829e5818f7cd5675583b03a7a2b9112"
    family = "Mirai"
    file_name = "stub.armv7"
    file_type = "elf"
    first_seen = "2026-09-28 01:45:13"
  condition:
    hash.sha256(0, filesize) == "a8cf66a587dfd8b72903c8a4dad059b8c829e5818f7cd5675583b03a7a2b9112"
}
```

### Sample 100: `81a9d12af89234da`

| Field | Value |
|---|---|
| SHA-256 | `81a9d12af89234da1c9b51996a9c8607a1fd1a4f0d83a394ab49d70452f6fcfa` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-09-28 01:28:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f39b33cc215218777d4ac40970bf2926` |
| SHA-1 | `95f5143c5a9b95607ea46d5577497f7677cd4272` |
| SHA-256 | `81a9d12af89234da1c9b51996a9c8607a1fd1a4f0d83a394ab49d70452f6fcfa` |
| SHA3-384 | `db6de882c37c437dcce93906ff55dfdadb8d1643674a03dd18c940e9ae3b479813da0c5961825ee44d18b8f3c095f2d6` |
| TLSH | `T1FD142A56F8819F16D5C112BAFE0E528E33131B7CE2DE72129E246B60778B96F0E3B505` |
| SSDEEP | `6144:YChkw0XO9fUfXw7x4JacLw6YvZT6ct1iDrkuwRk:Ym0XOliX3JacM+01iDrkZk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_81a9d12a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81a9d12af89234da1c9b51996a9c8607a1fd1a4f0d83a394ab49d70452f6fcfa"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-09-28 01:28:22"
  condition:
    hash.sha256(0, filesize) == "81a9d12af89234da1c9b51996a9c8607a1fd1a4f0d83a394ab49d70452f6fcfa"
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
 * Generated: 2026-09-28T05:33:19.737862+00:00
 */

rule MalwareBazaar_unknown_001_1cfb567d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cfb567d152cd29a387b15f700bb9c519421491d1a96595f5d1cec212817e5cd"
    family = "unknown"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-09-28 05:32:15"
  condition:
    hash.sha256(0, filesize) == "1cfb567d152cd29a387b15f700bb9c519421491d1a96595f5d1cec212817e5cd"
}

rule MalwareBazaar_Mirai_002_cc89b568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc89b568a8de9de006097c17fbbb07609ee9c7d9c05965f3212eae1274cd0077"
    family = "Mirai"
    file_name = "f076c5f295a7c33a.bin"
    file_type = "elf"
    first_seen = "2026-09-28 05:25:37"
  condition:
    hash.sha256(0, filesize) == "cc89b568a8de9de006097c17fbbb07609ee9c7d9c05965f3212eae1274cd0077"
}

rule MalwareBazaar_unknown_003_054eb80a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "054eb80aa4339f1a8b875ccfd9d9af9b34a628d0ef993ea940bdfbb1d266f828"
    family = "unknown"
    file_name = "054eb80aa4339f1a.bin"
    file_type = "macho"
    first_seen = "2026-09-28 05:25:18"
  condition:
    hash.sha256(0, filesize) == "054eb80aa4339f1a8b875ccfd9d9af9b34a628d0ef993ea940bdfbb1d266f828"
}

rule MalwareBazaar_unknown_004_c1634055
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1634055538b7bf7d548c86b605f7f6be70f506a0ea7ae99ae6a1525fce0c9fd"
    family = "unknown"
    file_name = "c1634055538b7bf7.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 05:25:10"
  condition:
    hash.sha256(0, filesize) == "c1634055538b7bf7d548c86b605f7f6be70f506a0ea7ae99ae6a1525fce0c9fd"
}

rule MalwareBazaar_Mirai_005_f076c5f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f076c5f295a7c33a39eea8a5047107c770832b8d6680f8b866795080b76ac853"
    family = "Mirai"
    file_name = "f076c5f295a7c33a.bin"
    file_type = "elf"
    first_seen = "2026-09-28 05:25:00"
  condition:
    hash.sha256(0, filesize) == "f076c5f295a7c33a39eea8a5047107c770832b8d6680f8b866795080b76ac853"
}

rule MalwareBazaar_Mirai_006_8d0e82dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d0e82dc4ffc6012fb6f6513feb7324672b5b26436ccdf2fd237fc03084ae109"
    family = "Mirai"
    file_name = "8d0e82dc4ffc6012.bin"
    file_type = "elf"
    first_seen = "2026-09-28 05:24:51"
  condition:
    hash.sha256(0, filesize) == "8d0e82dc4ffc6012fb6f6513feb7324672b5b26436ccdf2fd237fc03084ae109"
}

rule MalwareBazaar_Mirai_007_a34872ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a34872ae34ec6e4de081cc9370d9f538348fd3403de9994f6fc60ec8a227a2c7"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-28 05:23:25"
  condition:
    hash.sha256(0, filesize) == "a34872ae34ec6e4de081cc9370d9f538348fd3403de9994f6fc60ec8a227a2c7"
}

rule MalwareBazaar_unknown_008_5044a479
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5044a47978851eaf608c27d3ba94199efbb9da8bb251d2c5134ae4ae340cf91e"
    family = "unknown"
    file_name = "data.dat"
    file_type = "exe"
    first_seen = "2026-09-28 05:19:54"
  condition:
    hash.sha256(0, filesize) == "5044a47978851eaf608c27d3ba94199efbb9da8bb251d2c5134ae4ae340cf91e"
}

rule MalwareBazaar_Mirai_009_68f32b5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68f32b5f08ba6234fdf9f8a08d6bb28dab2418b0af33010e3699b6155f4d4ea0"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-28 05:19:15"
  condition:
    hash.sha256(0, filesize) == "68f32b5f08ba6234fdf9f8a08d6bb28dab2418b0af33010e3699b6155f4d4ea0"
}

rule MalwareBazaar_Mirai_010_8d53aad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d53aad5ab3bc826ce9de6540c591bcefc676b7b02258cc3a2dafd115d416b66"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-09-28 05:19:14"
  condition:
    hash.sha256(0, filesize) == "8d53aad5ab3bc826ce9de6540c591bcefc676b7b02258cc3a2dafd115d416b66"
}

rule MalwareBazaar_Mirai_011_e4fcc92b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4fcc92bcfdeae1562afba403b309f5db516f5872cd4dc302a9975be4f0dbe91"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-09-28 05:19:12"
  condition:
    hash.sha256(0, filesize) == "e4fcc92bcfdeae1562afba403b309f5db516f5872cd4dc302a9975be4f0dbe91"
}

rule MalwareBazaar_unknown_012_e6a22232
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6a22232324c004a57898e82cdc2a48dc34b4847476979c551f0b1db46b428b6"
    family = "unknown"
    file_name = "umpdc.dll"
    file_type = "exe"
    first_seen = "2026-09-28 05:18:46"
  condition:
    hash.sha256(0, filesize) == "e6a22232324c004a57898e82cdc2a48dc34b4847476979c551f0b1db46b428b6"
}

rule MalwareBazaar_unknown_013_489b07a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9"
    family = "unknown"
    file_name = "489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9"
    file_type = "elf"
    first_seen = "2026-09-28 05:17:19"
  condition:
    hash.sha256(0, filesize) == "489b07a8572e53ce73f6274c27201da89d1108ff793d021bc8c2ee4f437497b9"
}

rule MalwareBazaar_Mirai_014_8d379f23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897"
    family = "Mirai"
    file_name = "8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897"
    file_type = "elf"
    first_seen = "2026-09-28 05:17:13"
  condition:
    hash.sha256(0, filesize) == "8d379f234d9ca08faa09c19f10d6b204a44cb3e2bd2bdc94b56b2dad54f3f897"
}

rule MalwareBazaar_Mirai_015_0a230b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a230b42310fbbb5655341fd2a2bf4eb680babf360f76c796f9e1df374ee396c"
    family = "Mirai"
    file_name = "auroraint.spc"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:52"
  condition:
    hash.sha256(0, filesize) == "0a230b42310fbbb5655341fd2a2bf4eb680babf360f76c796f9e1df374ee396c"
}

rule MalwareBazaar_Mirai_016_e829956b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e829956b213bfb5d36b583b9fbd1a08bf1d1ee9a2942dac23f83fd0b08c1c605"
    family = "Mirai"
    file_name = "auroraint.x86"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:52"
  condition:
    hash.sha256(0, filesize) == "e829956b213bfb5d36b583b9fbd1a08bf1d1ee9a2942dac23f83fd0b08c1c605"
}

rule MalwareBazaar_Mirai_017_35e93cbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e93cbd08b07085ca4d652ba6cf6e0402f64ed453717884231eb830d8e551ba"
    family = "Mirai"
    file_name = "auroraint.sh4"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:52"
  condition:
    hash.sha256(0, filesize) == "35e93cbd08b07085ca4d652ba6cf6e0402f64ed453717884231eb830d8e551ba"
}

rule MalwareBazaar_Mirai_018_a04ba45d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a04ba45d395b13d7ef9f838711181f375bbb752bfc50d2aa33b0bc6ef8b30908"
    family = "Mirai"
    file_name = "auroraint.mpsl"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:50"
  condition:
    hash.sha256(0, filesize) == "a04ba45d395b13d7ef9f838711181f375bbb752bfc50d2aa33b0bc6ef8b30908"
}

rule MalwareBazaar_Mirai_019_10c38bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10c38bcfce9043786c8660f18d1cd4d8aef001923f841c4ef104b84d12244d65"
    family = "Mirai"
    file_name = "auroraint.ppc"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:49"
  condition:
    hash.sha256(0, filesize) == "10c38bcfce9043786c8660f18d1cd4d8aef001923f841c4ef104b84d12244d65"
}

rule MalwareBazaar_Mirai_020_a06fb076
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a06fb076e98a4d81cfb5631bc9162ce01cdeab53b0a0f1afc5ead5ac1adfbda4"
    family = "Mirai"
    file_name = "auroraint.mips"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:48"
  condition:
    hash.sha256(0, filesize) == "a06fb076e98a4d81cfb5631bc9162ce01cdeab53b0a0f1afc5ead5ac1adfbda4"
}

rule MalwareBazaar_Mirai_021_6c126368
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c126368093a4f965baf21bdc5458e5512e2dbcd83ff9c4e7e93707723fa4975"
    family = "Mirai"
    file_name = "auroraint.m68k"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:47"
  condition:
    hash.sha256(0, filesize) == "6c126368093a4f965baf21bdc5458e5512e2dbcd83ff9c4e7e93707723fa4975"
}

rule MalwareBazaar_Mirai_022_d8037f6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8037f6ab18f0bac96cc409e0dbc247dc328f60ea63885e09c69010b954ed308"
    family = "Mirai"
    file_name = "auroraint.arm7"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:47"
  condition:
    hash.sha256(0, filesize) == "d8037f6ab18f0bac96cc409e0dbc247dc328f60ea63885e09c69010b954ed308"
}

rule MalwareBazaar_Mirai_023_daa2fba0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daa2fba016ccc40ea64e1f3377605d6e2d281efc850b323959eed26a99593289"
    family = "Mirai"
    file_name = "auroraint.arm"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:46"
  condition:
    hash.sha256(0, filesize) == "daa2fba016ccc40ea64e1f3377605d6e2d281efc850b323959eed26a99593289"
}

rule MalwareBazaar_Mirai_024_64eeacfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64eeacfbc06e18ef02a1e49948804f760c6b2869b88f7416a8737846114dca06"
    family = "Mirai"
    file_name = "auroraint.arm5n"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:46"
  condition:
    hash.sha256(0, filesize) == "64eeacfbc06e18ef02a1e49948804f760c6b2869b88f7416a8737846114dca06"
}

rule MalwareBazaar_Mirai_025_2ad4002a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ad4002ae9000abeca0cae4c69acb20df6b2eea07a03ac464443e5eaf2bee3ef"
    family = "Mirai"
    file_name = "aurora.x86"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:46"
  condition:
    hash.sha256(0, filesize) == "2ad4002ae9000abeca0cae4c69acb20df6b2eea07a03ac464443e5eaf2bee3ef"
}

rule MalwareBazaar_Mirai_026_2ef818af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ef818af2a9b1ae9990c10f919480c58c875b6ab8736a1c54e34557b259339d9"
    family = "Mirai"
    file_name = "aurora.sh4"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:45"
  condition:
    hash.sha256(0, filesize) == "2ef818af2a9b1ae9990c10f919480c58c875b6ab8736a1c54e34557b259339d9"
}

rule MalwareBazaar_Mirai_027_5c7b46ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c7b46ad5ffee665aa02fc76d32343caf958614a9397eac2d48e75b6559e4e75"
    family = "Mirai"
    file_name = "aurora.spc"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:45"
  condition:
    hash.sha256(0, filesize) == "5c7b46ad5ffee665aa02fc76d32343caf958614a9397eac2d48e75b6559e4e75"
}

rule MalwareBazaar_Mirai_028_96dba8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96dba8e88c6c483bf79c9b28d81ef0f312c14c69e16572384967bac7c62de0fc"
    family = "Mirai"
    file_name = "aurora.ppc"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:43"
  condition:
    hash.sha256(0, filesize) == "96dba8e88c6c483bf79c9b28d81ef0f312c14c69e16572384967bac7c62de0fc"
}

rule MalwareBazaar_Mirai_029_e1a632b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1a632b22ed08d7d09256153c8215e8a0f4e323d45592a8591f4b1c6bfc65a3f"
    family = "Mirai"
    file_name = "aurora.mpsl"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:43"
  condition:
    hash.sha256(0, filesize) == "e1a632b22ed08d7d09256153c8215e8a0f4e323d45592a8591f4b1c6bfc65a3f"
}

rule MalwareBazaar_Mirai_030_2f6e5326
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f6e53269da938c4514fa8f157af3fabccc1ceb59798de7be332c0e9589bfb9e"
    family = "Mirai"
    file_name = "aurora.mips"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:42"
  condition:
    hash.sha256(0, filesize) == "2f6e53269da938c4514fa8f157af3fabccc1ceb59798de7be332c0e9589bfb9e"
}

rule MalwareBazaar_Mirai_031_5c9092d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c9092d329591862af419a6abc283e66017b01762d5745089f54e95c4d4c0b8d"
    family = "Mirai"
    file_name = "aurora.arm7"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:40"
  condition:
    hash.sha256(0, filesize) == "5c9092d329591862af419a6abc283e66017b01762d5745089f54e95c4d4c0b8d"
}

rule MalwareBazaar_Mirai_032_b720c9c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b720c9c690e010b7b98743d9c0005b14161715e19e9b640c3ef2f9ab1dcfffdf"
    family = "Mirai"
    file_name = "aurora.m68k"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:40"
  condition:
    hash.sha256(0, filesize) == "b720c9c690e010b7b98743d9c0005b14161715e19e9b640c3ef2f9ab1dcfffdf"
}

rule MalwareBazaar_Mirai_033_273a5dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "273a5dd08461ffe2e44ef07cafd6678a5789dbeefc68c316e337f95336af10d0"
    family = "Mirai"
    file_name = "aurora.arm5n"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:39"
  condition:
    hash.sha256(0, filesize) == "273a5dd08461ffe2e44ef07cafd6678a5789dbeefc68c316e337f95336af10d0"
}

rule MalwareBazaar_unknown_034_c2b60d18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2b60d1860f4cfe72124076a5866ea534cd069e13d0aa1f232d09d6631e8c1a5"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-09-28 05:15:38"
  condition:
    hash.sha256(0, filesize) == "c2b60d1860f4cfe72124076a5866ea534cd069e13d0aa1f232d09d6631e8c1a5"
}

rule MalwareBazaar_Mirai_035_d665a682
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d665a6826d9073dd02c60a25a688dea778b8f7d78fa0933c72708eecd3e47725"
    family = "Mirai"
    file_name = "aurora.arm"
    file_type = "elf"
    first_seen = "2026-09-28 05:15:38"
  condition:
    hash.sha256(0, filesize) == "d665a6826d9073dd02c60a25a688dea778b8f7d78fa0933c72708eecd3e47725"
}

rule MalwareBazaar_unknown_036_809bfb1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07"
    family = "unknown"
    file_name = "809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07.exe"
    file_type = "exe"
    first_seen = "2026-09-28 05:11:26"
  condition:
    hash.sha256(0, filesize) == "809bfb1f22505bc6d2fe5399958e00c2a3c90bded7bac9c281a4c83e5725af07"
}

rule MalwareBazaar_Mirai_037_67436caa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67436caa9df23693d5a33616f8525d196f9c9e3e713a584f1f2e79a5b60ee7fc"
    family = "Mirai"
    file_name = "bot.armv6"
    file_type = "elf"
    first_seen = "2026-09-28 05:11:08"
  condition:
    hash.sha256(0, filesize) == "67436caa9df23693d5a33616f8525d196f9c9e3e713a584f1f2e79a5b60ee7fc"
}

rule MalwareBazaar_Mirai_038_be5f3755
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be5f3755ebc229859fc189e2fd8dae8dc900b4d8f27b3bb513e38d17a92e488b"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-09-28 05:11:06"
  condition:
    hash.sha256(0, filesize) == "be5f3755ebc229859fc189e2fd8dae8dc900b4d8f27b3bb513e38d17a92e488b"
}

rule MalwareBazaar_Mirai_039_cb0d55da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb0d55da96bb67f98f7812da0b25b508bc857569b52b6e271768063bcc386143"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-09-28 05:11:04"
  condition:
    hash.sha256(0, filesize) == "cb0d55da96bb67f98f7812da0b25b508bc857569b52b6e271768063bcc386143"
}

rule MalwareBazaar_Mirai_040_a1e4093d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1e4093de4aec7643993a689c32a53472fce9bb21957e9d90153e9191dd53b12"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-28 05:03:01"
  condition:
    hash.sha256(0, filesize) == "a1e4093de4aec7643993a689c32a53472fce9bb21957e9d90153e9191dd53b12"
}

rule MalwareBazaar_Mirai_041_43613c90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43613c90d253ccaa7eced571018d78702fab3d2e018fc865d727a51f092c2dd0"
    family = "Mirai"
    file_name = "bot.i486"
    file_type = "elf"
    first_seen = "2026-09-28 05:02:59"
  condition:
    hash.sha256(0, filesize) == "43613c90d253ccaa7eced571018d78702fab3d2e018fc865d727a51f092c2dd0"
}

rule MalwareBazaar_Mirai_042_7e870962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e8709629cd9930ea6a55ef56b5364a50758385f11d40f83fb67e8ea5b05703d"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-28 04:58:55"
  condition:
    hash.sha256(0, filesize) == "7e8709629cd9930ea6a55ef56b5364a50758385f11d40f83fb67e8ea5b05703d"
}

rule MalwareBazaar_Mirai_043_29cf954c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29cf954ce49e80ba1df846642a66f60a967e9c4e36fd10a2cedf4e5a8065e4dd"
    family = "Mirai"
    file_name = "stub.x64"
    file_type = "elf"
    first_seen = "2026-09-28 04:54:58"
  condition:
    hash.sha256(0, filesize) == "29cf954ce49e80ba1df846642a66f60a967e9c4e36fd10a2cedf4e5a8065e4dd"
}

rule MalwareBazaar_Mirai_044_4aa8d4e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4aa8d4e8955da8341f72c69b5df68d1fda2110dca0ff8798d4c72a6ade4aa2ce"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:32"
  condition:
    hash.sha256(0, filesize) == "4aa8d4e8955da8341f72c69b5df68d1fda2110dca0ff8798d4c72a6ade4aa2ce"
}

rule MalwareBazaar_Mirai_045_04fac818
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04fac8188c7906b441c173d7a377ea939227bbf0063a8bc681dcec53cb046b70"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:32"
  condition:
    hash.sha256(0, filesize) == "04fac8188c7906b441c173d7a377ea939227bbf0063a8bc681dcec53cb046b70"
}

rule MalwareBazaar_Mirai_046_528a497f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "528a497f41491f59758d3460f06c7e827c289a44bab39b864a7e9208c1ffe10d"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:32"
  condition:
    hash.sha256(0, filesize) == "528a497f41491f59758d3460f06c7e827c289a44bab39b864a7e9208c1ffe10d"
}

rule MalwareBazaar_Mirai_047_31b58d95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31b58d95a9ce2530aa523498c4d5fc055de44e893f2645c29c4aebfbad6abf57"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:31"
  condition:
    hash.sha256(0, filesize) == "31b58d95a9ce2530aa523498c4d5fc055de44e893f2645c29c4aebfbad6abf57"
}

rule MalwareBazaar_Mirai_048_608b16b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "608b16b89690afa9af52518a8863605b1ddf7d6d7b25ce3922482bd0d9e36d14"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:30"
  condition:
    hash.sha256(0, filesize) == "608b16b89690afa9af52518a8863605b1ddf7d6d7b25ce3922482bd0d9e36d14"
}

rule MalwareBazaar_Mirai_049_7a76f9c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a76f9c6d0f7e0a71024295148943e88c60bed7187eeff53a79f897600b40407"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:30"
  condition:
    hash.sha256(0, filesize) == "7a76f9c6d0f7e0a71024295148943e88c60bed7187eeff53a79f897600b40407"
}

rule MalwareBazaar_Mirai_050_80edaab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80edaab25ec8e4aa0d498601c8e9a62a90ee5af89d26bc55383c9a15c2003c69"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:29"
  condition:
    hash.sha256(0, filesize) == "80edaab25ec8e4aa0d498601c8e9a62a90ee5af89d26bc55383c9a15c2003c69"
}

rule MalwareBazaar_Mirai_051_5ceb7a98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ceb7a989bf180203d0e75813479eeee32c2b7a599b276f9cb51d584d079c0ca"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:29"
  condition:
    hash.sha256(0, filesize) == "5ceb7a989bf180203d0e75813479eeee32c2b7a599b276f9cb51d584d079c0ca"
}

rule MalwareBazaar_Mirai_052_f03ceddd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f03cedddac00aa827fa60629b38b90555bd66b702d4581f897dc4e06b6e3cbff"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:29"
  condition:
    hash.sha256(0, filesize) == "f03cedddac00aa827fa60629b38b90555bd66b702d4581f897dc4e06b6e3cbff"
}

rule MalwareBazaar_Mirai_053_c7dfef3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7dfef3d5e291d98462858fc0b1703fcfccd071d3def1c3b215ac1e1cb4c17b9"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:27"
  condition:
    hash.sha256(0, filesize) == "c7dfef3d5e291d98462858fc0b1703fcfccd071d3def1c3b215ac1e1cb4c17b9"
}

rule MalwareBazaar_Mirai_054_cb79c944
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb79c944cc781d7470f24eebf9f751c7819a47b75cb14acea72d8f1b4245439a"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-09-28 04:52:27"
  condition:
    hash.sha256(0, filesize) == "cb79c944cc781d7470f24eebf9f751c7819a47b75cb14acea72d8f1b4245439a"
}

rule MalwareBazaar_Vidar_055_0f085328
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b"
    family = "Vidar"
    file_name = "0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b.bin"
    file_type = "exe"
    first_seen = "2026-09-28 04:51:14"
  condition:
    hash.sha256(0, filesize) == "0f085328fc54df5bf77c16d30a838d7dcaf629f5cabf29eddbbb683bcc64d83b"
}

rule MalwareBazaar_Mirai_056_dad5fa8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dad5fa8aeeb15ed7c27f13b4d20b2f1ad56bfb180a5fd54bb7e3d7daf9a3dd0f"
    family = "Mirai"
    file_name = "stub.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-28 04:51:01"
  condition:
    hash.sha256(0, filesize) == "dad5fa8aeeb15ed7c27f13b4d20b2f1ad56bfb180a5fd54bb7e3d7daf9a3dd0f"
}

rule MalwareBazaar_Mirai_057_4966419c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4966419c32ba868733ab7c001765e0670c66d9f9ca01fc1d799fb398493d4258"
    family = "Mirai"
    file_name = "stub.aarch64"
    file_type = "elf"
    first_seen = "2026-09-28 04:46:40"
  condition:
    hash.sha256(0, filesize) == "4966419c32ba868733ab7c001765e0670c66d9f9ca01fc1d799fb398493d4258"
}

rule MalwareBazaar_Mirai_058_44dd2764
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44dd2764561c2369e3958cf9f96942dfe7511c78bf6bb40b2e93219d24438ca0"
    family = "Mirai"
    file_name = "stub.mipsel"
    file_type = "elf"
    first_seen = "2026-09-28 04:42:28"
  condition:
    hash.sha256(0, filesize) == "44dd2764561c2369e3958cf9f96942dfe7511c78bf6bb40b2e93219d24438ca0"
}

rule MalwareBazaar_Mirai_059_f11b0d82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f11b0d8298043a6fac57c092454dc83dfe38c003c964782c80ef34ccfd81c5a9"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-28 04:42:26"
  condition:
    hash.sha256(0, filesize) == "f11b0d8298043a6fac57c092454dc83dfe38c003c964782c80ef34ccfd81c5a9"
}

rule MalwareBazaar_Mirai_060_67d08105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67d081050f574cc9c30b7876f13915522683ca0d37c854321012d9c87c10b185"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-09-28 04:38:27"
  condition:
    hash.sha256(0, filesize) == "67d081050f574cc9c30b7876f13915522683ca0d37c854321012d9c87c10b185"
}

rule MalwareBazaar_Mirai_061_e6302aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6302aad7ada45983d3a22c525b47e5c5ab6000daab5febcc0a414fbc49a1a32"
    family = "Mirai"
    file_name = "bot.armv7"
    file_type = "elf"
    first_seen = "2026-09-28 04:38:25"
  condition:
    hash.sha256(0, filesize) == "e6302aad7ada45983d3a22c525b47e5c5ab6000daab5febcc0a414fbc49a1a32"
}

rule MalwareBazaar_Mirai_062_9ca5e62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ca5e62c6d31fa8d77360a8e6c5d2602cd57e8b50d89309ab7728e2e133e7043"
    family = "Mirai"
    file_name = "9ca5e62c6d31fa8d.bin"
    file_type = "elf"
    first_seen = "2026-09-28 04:25:45"
  condition:
    hash.sha256(0, filesize) == "9ca5e62c6d31fa8d77360a8e6c5d2602cd57e8b50d89309ab7728e2e133e7043"
}

rule MalwareBazaar_Mirai_063_5871b070
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5871b0701002cbbdd2a7ca290f724d69bbe2b0350bb459c02d2215b5364f4d64"
    family = "Mirai"
    file_name = "5871b0701002cbbd.bin"
    file_type = "elf"
    first_seen = "2026-09-28 04:25:34"
  condition:
    hash.sha256(0, filesize) == "5871b0701002cbbdd2a7ca290f724d69bbe2b0350bb459c02d2215b5364f4d64"
}

rule MalwareBazaar_Mirai_064_e2d46a6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2d46a6b819865112dd88b7ccbcc34379d2c5711acadd0c6720fcd91b4909096"
    family = "Mirai"
    file_name = "e2d46a6b81986511.bin"
    file_type = "elf"
    first_seen = "2026-09-28 04:25:26"
  condition:
    hash.sha256(0, filesize) == "e2d46a6b819865112dd88b7ccbcc34379d2c5711acadd0c6720fcd91b4909096"
}

rule MalwareBazaar_unknown_065_d2308ce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2308ce690cdcc2a36398b46275c093afb4cfb8360324516f331cde41b5280e3"
    family = "unknown"
    file_name = "d2308ce690cdcc2a.bin"
    file_type = "exe"
    first_seen = "2026-09-28 04:25:18"
  condition:
    hash.sha256(0, filesize) == "d2308ce690cdcc2a36398b46275c093afb4cfb8360324516f331cde41b5280e3"
}

rule MalwareBazaar_Mirai_066_92785105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b"
    family = "Mirai"
    file_name = "9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b"
    file_type = "elf"
    first_seen = "2026-09-28 04:17:14"
  condition:
    hash.sha256(0, filesize) == "9278510531077f0774d4a9d47f1b7bc116b56d972ba85f3230a23a158eb8410b"
}

rule MalwareBazaar_unknown_067_65117fae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b"
    family = "unknown"
    file_name = "65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b.exe"
    file_type = "exe"
    first_seen = "2026-09-28 04:10:46"
  condition:
    hash.sha256(0, filesize) == "65117fae4f2948dd3780cfb678741b74905769c833f15c95b897c8cd82691e1b"
}

rule MalwareBazaar_unknown_068_0593552e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0593552ee0df53f8e2fb80f5748606403989d14536d076d4328e4956f5455a46"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-28 04:04:07"
  condition:
    hash.sha256(0, filesize) == "0593552ee0df53f8e2fb80f5748606403989d14536d076d4328e4956f5455a46"
}

rule MalwareBazaar_unknown_069_cdcd92f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdcd92f9e3af2925829eaf9e8d366ae2e750bded64d212484995378eb1839025"
    family = "unknown"
    file_name = "z1OCTOBERINQUIRY2_PDF.bat"
    file_type = "exe"
    first_seen = "2026-09-28 04:00:08"
  condition:
    hash.sha256(0, filesize) == "cdcd92f9e3af2925829eaf9e8d366ae2e750bded64d212484995378eb1839025"
}

rule MalwareBazaar_unknown_070_7c1deaf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c1deaf3dd4d11811fff1d221fe4944a89cd98d8e48f3435c6fe374aadc9ec45"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-28 03:46:24"
  condition:
    hash.sha256(0, filesize) == "7c1deaf3dd4d11811fff1d221fe4944a89cd98d8e48f3435c6fe374aadc9ec45"
}

rule MalwareBazaar_unknown_071_9b0a0e39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685"
    family = "unknown"
    file_name = "9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685.bin"
    file_type = "zip"
    first_seen = "2026-09-28 03:37:07"
  condition:
    hash.sha256(0, filesize) == "9b0a0e395124d4a68c37fe1b7b749c07eb324bba183435ce67e1e6faef2bd685"
}

rule MalwareBazaar_unknown_072_74a104cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6"
    family = "unknown"
    file_name = "74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 03:37:02"
  condition:
    hash.sha256(0, filesize) == "74a104cfcea6ea63097cf3d92a7723f17b89c20b89ea1a550d5ff9a5bd3169f6"
}

rule MalwareBazaar_VShell_073_a43565ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b"
    family = "VShell"
    file_name = "a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:16"
  condition:
    hash.sha256(0, filesize) == "a43565efdc71fc93f0267a6937a22d8ec0598bf666a329299436401c619e5f6b"
}

rule MalwareBazaar_VShell_074_af1311d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d"
    family = "VShell"
    file_name = "af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:12"
  condition:
    hash.sha256(0, filesize) == "af1311d7cf8a15a8a9457a9d27bff4f17857c7492eb54d926884b5eb61bb0f8d"
}

rule MalwareBazaar_VShell_075_8137187c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea"
    family = "VShell"
    file_name = "8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:09"
  condition:
    hash.sha256(0, filesize) == "8137187c5c9266b90bb5db000ff7e50cb25214dd8fb3236653abbddb468081ea"
}

rule MalwareBazaar_VShell_076_bc4633b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8"
    family = "VShell"
    file_name = "bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:05"
  condition:
    hash.sha256(0, filesize) == "bc4633b53ce18d54ef98e80e72f0e53a63398dab48c01c3eb1a49f7ec57e0af8"
}

rule MalwareBazaar_VShell_077_99a9b6e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c"
    family = "VShell"
    file_name = "99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:36:01"
  condition:
    hash.sha256(0, filesize) == "99a9b6e21b5ef54733a1385425e3d58f56e285d609eea91432963aa4ca3d076c"
}

rule MalwareBazaar_AgentTesla_078_156587f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "156587f7d2c1c5bec5deaeabf16cbce6c23bad000f47bb3f1c93ccc68fb347e3"
    family = "AgentTesla"
    file_name = "SecuriteInfo.com.Trojan.Siggen34.18774.960.2461"
    file_type = "exe"
    first_seen = "2026-09-28 03:34:48"
  condition:
    hash.sha256(0, filesize) == "156587f7d2c1c5bec5deaeabf16cbce6c23bad000f47bb3f1c93ccc68fb347e3"
}

rule MalwareBazaar_unknown_079_bd8204ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3"
    family = "unknown"
    file_name = "bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3.bin"
    file_type = "zip"
    first_seen = "2026-09-28 03:27:28"
  condition:
    hash.sha256(0, filesize) == "bd8204ba17d68dd6528fc59d71c2701131267778b54425aeeaf2eb365a4018a3"
}

rule MalwareBazaar_unknown_080_2e9abac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc"
    family = "unknown"
    file_name = "2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:26:39"
  condition:
    hash.sha256(0, filesize) == "2e9abac78aa184685c44e3b9dadaf347fdc9a2844f35df8961049ea9869ff3cc"
}

rule MalwareBazaar_VShell_081_33a65343
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d"
    family = "VShell"
    file_name = "33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:26:18"
  condition:
    hash.sha256(0, filesize) == "33a65343384128e0851130c0fc9a38e9eb7d85f9efc4a6c60a5cc148383edd4d"
}

rule MalwareBazaar_unknown_082_8a464667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a464667e80d48e4fe7bcbc98faaf5e3e306d8ee3f4986f9d24b5ce58144f59c"
    family = "unknown"
    file_name = "8a464667e80d48e4.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 03:26:00"
  condition:
    hash.sha256(0, filesize) == "8a464667e80d48e4fe7bcbc98faaf5e3e306d8ee3f4986f9d24b5ce58144f59c"
}

rule MalwareBazaar_Mirai_083_8b690a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b690a6e3b6f301bf0bf6b6ee123933333c8c6036af5633b934c0b0e6cf27fb5"
    family = "Mirai"
    file_name = "8b690a6e3b6f301b.bin"
    file_type = "elf"
    first_seen = "2026-09-28 03:25:52"
  condition:
    hash.sha256(0, filesize) == "8b690a6e3b6f301bf0bf6b6ee123933333c8c6036af5633b934c0b0e6cf27fb5"
}

rule MalwareBazaar_unknown_084_1c9dd1d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c9dd1d98bbb1022bbf1ac02952be2c53b8fbf69b9428c4b2fc59c422b72fa03"
    family = "unknown"
    file_name = "1c9dd1d98bbb1022.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 03:25:45"
  condition:
    hash.sha256(0, filesize) == "1c9dd1d98bbb1022bbf1ac02952be2c53b8fbf69b9428c4b2fc59c422b72fa03"
}

rule MalwareBazaar_unknown_085_0acc12e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0acc12e3993609d539bb2c1c7f0543c7ca6b03158c9f8e265e57650a4f9d9ee2"
    family = "unknown"
    file_name = "0acc12e3993609d5.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 03:25:38"
  condition:
    hash.sha256(0, filesize) == "0acc12e3993609d539bb2c1c7f0543c7ca6b03158c9f8e265e57650a4f9d9ee2"
}

rule MalwareBazaar_unknown_086_32a6d9ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32a6d9badcd78d8313b9437f14030192ceb40b4926ec6d4b0c457f2edb6f09ec"
    family = "unknown"
    file_name = "32a6d9badcd78d83.bin"
    file_type = "elf"
    first_seen = "2026-09-28 03:25:31"
  condition:
    hash.sha256(0, filesize) == "32a6d9badcd78d8313b9437f14030192ceb40b4926ec6d4b0c457f2edb6f09ec"
}

rule MalwareBazaar_unknown_087_3147f331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4"
    family = "unknown"
    file_name = "3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4"
    file_type = "elf"
    first_seen = "2026-09-28 03:18:42"
  condition:
    hash.sha256(0, filesize) == "3147f3315cdac01c6eae3ee0df01d2bf5bf01172af037668a46f65be876d8cc4"
}

rule MalwareBazaar_Mirai_088_6b041a9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc"
    family = "Mirai"
    file_name = "6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc"
    file_type = "elf"
    first_seen = "2026-09-28 03:18:34"
  condition:
    hash.sha256(0, filesize) == "6b041a9a83d4ed55d26670fba476c1d402380f0dbf5965795eaec977484092bc"
}

rule MalwareBazaar_AgentTesla_089_c5b8ac5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5b8ac5d26a96a9ff4d628603e06c2fb5a40914b8fdd8b6b429a90cb72bc6828"
    family = "AgentTesla"
    file_name = "Comprobante de pago.js"
    file_type = "js"
    first_seen = "2026-09-28 03:16:27"
  condition:
    hash.sha256(0, filesize) == "c5b8ac5d26a96a9ff4d628603e06c2fb5a40914b8fdd8b6b429a90cb72bc6828"
}

rule MalwareBazaar_unknown_090_04ef5c97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5"
    family = "unknown"
    file_name = "04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:11:10"
  condition:
    hash.sha256(0, filesize) == "04ef5c970c0f02f7644930b79c63fd915a68e0b996fdb8cd481a6ef1395a57b5"
}

rule MalwareBazaar_unknown_091_7a391650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b"
    family = "unknown"
    file_name = "7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b.exe"
    file_type = "exe"
    first_seen = "2026-09-28 03:11:04"
  condition:
    hash.sha256(0, filesize) == "7a391650af7b60189621d30486291cbb7bf78e06a4e80b277b28954a08d5908b"
}

rule MalwareBazaar_VShell_092_92e29d3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077"
    family = "VShell"
    file_name = "92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077.exe"
    file_type = "exe"
    first_seen = "2026-09-28 02:35:21"
  condition:
    hash.sha256(0, filesize) == "92e29d3fc00ab0cb637db589807a1df9f8a9ce55d50a90bababf6a23f866a077"
}

rule MalwareBazaar_unknown_093_c26b798f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c26b798fa5d4e7a5b9dc5478ccdc7f57af8d5d66f343cf4ed86c32e5ef2d1dcb"
    family = "unknown"
    file_name = "c26b798fa5d4e7a5.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 02:26:00"
  condition:
    hash.sha256(0, filesize) == "c26b798fa5d4e7a5b9dc5478ccdc7f57af8d5d66f343cf4ed86c32e5ef2d1dcb"
}

rule MalwareBazaar_unknown_094_431f3f10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "431f3f1064aa30efe9df89246dbfac78edb1a1b82b1adadfce500540c002949f"
    family = "unknown"
    file_name = "431f3f1064aa30ef.bin"
    file_type = "unknown"
    first_seen = "2026-09-28 02:25:53"
  condition:
    hash.sha256(0, filesize) == "431f3f1064aa30efe9df89246dbfac78edb1a1b82b1adadfce500540c002949f"
}

rule MalwareBazaar_unknown_095_52f3a917
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52f3a917a988edf3cd5b32260681e8f7496a20582cf8a845cbb570775032af04"
    family = "unknown"
    file_name = "52f3a917a988edf3.bin"
    file_type = "exe"
    first_seen = "2026-09-28 02:25:46"
  condition:
    hash.sha256(0, filesize) == "52f3a917a988edf3cd5b32260681e8f7496a20582cf8a845cbb570775032af04"
}

rule MalwareBazaar_unknown_096_2547138e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2547138e7138b87794fa01aa287fff646cedc5b486ec855de526a36d0222f846"
    family = "unknown"
    file_name = "2547138e7138b877.bin"
    file_type = "exe"
    first_seen = "2026-09-28 02:25:39"
  condition:
    hash.sha256(0, filesize) == "2547138e7138b87794fa01aa287fff646cedc5b486ec855de526a36d0222f846"
}

rule MalwareBazaar_unknown_097_692581e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "692581e015122cbee3e114e510c07982731fd084eaf1a875482b122163d01e1e"
    family = "unknown"
    file_name = "692581e015122cbe.bin"
    file_type = "exe"
    first_seen = "2026-09-28 02:25:20"
  condition:
    hash.sha256(0, filesize) == "692581e015122cbee3e114e510c07982731fd084eaf1a875482b122163d01e1e"
}

rule MalwareBazaar_Mirai_098_d7afb964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd"
    family = "Mirai"
    file_name = "d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd"
    file_type = "elf"
    first_seen = "2026-09-28 02:17:14"
  condition:
    hash.sha256(0, filesize) == "d7afb964c38aa72128236ad069f4fa84d0986435643253cb570d376af73615fd"
}

rule MalwareBazaar_Mirai_099_a8cf66a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8cf66a587dfd8b72903c8a4dad059b8c829e5818f7cd5675583b03a7a2b9112"
    family = "Mirai"
    file_name = "stub.armv7"
    file_type = "elf"
    first_seen = "2026-09-28 01:45:13"
  condition:
    hash.sha256(0, filesize) == "a8cf66a587dfd8b72903c8a4dad059b8c829e5818f7cd5675583b03a7a2b9112"
}

rule MalwareBazaar_Mirai_100_81a9d12a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81a9d12af89234da1c9b51996a9c8607a1fd1a4f0d83a394ab49d70452f6fcfa"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-09-28 01:28:22"
  condition:
    hash.sha256(0, filesize) == "81a9d12af89234da1c9b51996a9c8607a1fd1a4f0d83a394ab49d70452f6fcfa"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

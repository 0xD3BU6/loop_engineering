# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-22

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 662 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 662 |
| Unique family labels | 12 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 66 |
| Mirai | 22 |
| CoinMiner | 2 |
| AsyncRAT | 2 |
| BlackMatter | 1 |
| Phorpiex | 1 |
| AgentTesla | 1 |
| ConnectWise | 1 |
| ValleyRAT | 1 |
| N-W0rm | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 44 |
| elf | 39 |
| sh | 11 |
| unknown | 3 |
| msi | 2 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `6209b9f4af44f71e`

| Field | Value |
|---|---|
| SHA-256 | `6209b9f4af44f71e7b319c5b406603a6f15da3c7d8ca6bd06d434af65269990e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 03:42:12` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da0389526f86ac97819f464e3f1e8955` |
| SHA-1 | `c5f87d73051dcaddc335c2afee83178da9c5dc13` |
| SHA-256 | `6209b9f4af44f71e7b319c5b406603a6f15da3c7d8ca6bd06d434af65269990e` |
| SHA3-384 | `15ac817d219adfd3b4de5b484d45a4b52c7b8988b749a1a00166919110c6512a08b9cf591857a1e03e1b531b11be54f6` |
| IMPHASH | `9bf3f5698d1c8e5d8bbe8d194ac5d544` |
| TLSH | `T19D187D03B3A705D5E8F7DA3196E65223A932BC066F3085DF324C17262F73AE05A76B51` |
| SSDEEP | `786432:eAZqtFi3zQzwBs6vNtcZY5Dfw3pgPVlcmXW:eAZui3zQz2jOZKft` |
| ICON-DHASH | `58d8ccd9f0708898` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_6209b9f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6209b9f4af44f71e7b319c5b406603a6f15da3c7d8ca6bd06d434af65269990e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 03:42:12"
  condition:
    hash.sha256(0, filesize) == "6209b9f4af44f71e7b319c5b406603a6f15da3c7d8ca6bd06d434af65269990e"
}
```

### Sample 2: `480bdd66621a0869`

| Field | Value |
|---|---|
| SHA-256 | `480bdd66621a0869dff575523f7e4ad5b7528744c1dc40f6f80bc85233433186` |
| Family label | `unknown` |
| File name | `MV.LOWLANDS.WEALTH.VESSEL.PARTICULARSpdf.exe` |
| File type | `exe` |
| First seen | `2026-07-22 03:39:21` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8c5b5e6688f1b2ff4d72025e94e7b62` |
| SHA-1 | `1f76ccce7f9bd948bfaa9e8fce0932951fe6e10d` |
| SHA-256 | `480bdd66621a0869dff575523f7e4ad5b7528744c1dc40f6f80bc85233433186` |
| SHA3-384 | `cfa88b3edbbf33fc9c24a6e1e56c2fdd3e32fd9b011d3715aad7a5980eea661a5da350a3731e342fa6223f2cc3484ea2` |
| IMPHASH | `46d844d880996af2766416e3e2079244` |
| TLSH | `T1E8C5BF15E3C865E9D467DA78C714A232D2B2B8534B76D1CF0A9AC30A1F77E918F3A701` |
| SSDEEP | `49152:/FuIkqh6ecsNpqRvtZzt1aWD0SCZn3gGQsBLWsZuT9t2HiWqFG:/5NgCZn3gGQsBLWsZuT9t2HiWqFG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_480bdd66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "480bdd66621a0869dff575523f7e4ad5b7528744c1dc40f6f80bc85233433186"
    family = "unknown"
    file_name = "MV.LOWLANDS.WEALTH.VESSEL.PARTICULARSpdf.exe"
    file_type = "exe"
    first_seen = "2026-07-22 03:39:21"
  condition:
    hash.sha256(0, filesize) == "480bdd66621a0869dff575523f7e4ad5b7528744c1dc40f6f80bc85233433186"
}
```

### Sample 3: `792c62d5d1c2b14b`

| Field | Value |
|---|---|
| SHA-256 | `792c62d5d1c2b14b8f88b6d4f076197c09be903d66b6f882cebffe7be9c0bc77` |
| Family label | `Mirai` |
| File name | `8Mty` |
| File type | `elf` |
| First seen | `2026-07-22 03:37:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afcf2a79b07a3b4975ec6aec72878105` |
| SHA-1 | `7b8c50db1243b63ab113efaf5644ce9a1e2cfd63` |
| SHA-256 | `792c62d5d1c2b14b8f88b6d4f076197c09be903d66b6f882cebffe7be9c0bc77` |
| SHA3-384 | `24d35feec0665abe72c72916c4f63e79f923bd1f9d92819c087f4ddc1b748a69c9a65d1f9328869a4a9445f3d25931db` |
| TLSH | `T16C83F72ABD819F05D4D526BAFE1E538933535BBCE3EE7103DE141B65278AA1B0F3A401` |
| TELFHASH | `t16ee061b64a4185fc93e44559d05f711a430ce052051045d8bafc5e1fd173886760e40a` |
| SSDEEP | `1536:abn0lQJEGwp8q0UIlkvkCRd3cwqDdGggiHYtNLRMipVuVbllWki0N8zjO6F:fKEH8Jg3vClgiHYtNLRMipsWuN8Gi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_792c62d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "792c62d5d1c2b14b8f88b6d4f076197c09be903d66b6f882cebffe7be9c0bc77"
    family = "Mirai"
    file_name = "8Mty"
    file_type = "elf"
    first_seen = "2026-07-22 03:37:33"
  condition:
    hash.sha256(0, filesize) == "792c62d5d1c2b14b8f88b6d4f076197c09be903d66b6f882cebffe7be9c0bc77"
}
```

### Sample 4: `e4d2ddc80e1c236a`

| Field | Value |
|---|---|
| SHA-256 | `e4d2ddc80e1c236ae22bec38090883648b411e140e94a2a5d554aac66bae030e` |
| Family label | `Mirai` |
| File name | `WgR` |
| File type | `elf` |
| First seen | `2026-07-22 03:35:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4e0f4c0454dfbd35c0329c11018d7ce` |
| SHA-1 | `1466ded9638bd13138478e877455246798489e99` |
| SHA-256 | `e4d2ddc80e1c236ae22bec38090883648b411e140e94a2a5d554aac66bae030e` |
| SHA3-384 | `47930184899991c519d501c3197bf8af3d25c5d8eb8a983715627af71d24f7731cebf801c8ea50377d8585122a6a71d9` |
| TLSH | `T167A3D70AAF611DBBD81BDD3705AC0B0278CCA657716837793538C528BB8A54F8AD3CB5` |
| SSDEEP | `1536:7K4tIZ2+Fy7KXz6XnAbOOKoubmSFCyLlPAJ1U02Ux+2gvvO7er23:tW4+Fy7KXGXAbPEbm2cxbJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_e4d2ddc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4d2ddc80e1c236ae22bec38090883648b411e140e94a2a5d554aac66bae030e"
    family = "Mirai"
    file_name = "WgR"
    file_type = "elf"
    first_seen = "2026-07-22 03:35:59"
  condition:
    hash.sha256(0, filesize) == "e4d2ddc80e1c236ae22bec38090883648b411e140e94a2a5d554aac66bae030e"
}
```

### Sample 5: `76d7bbf2d95d2404`

| Field | Value |
|---|---|
| SHA-256 | `76d7bbf2d95d24046a8ae3a9b64c63ee280700434ce642df02d2530e13bcd8f2` |
| Family label | `unknown` |
| File name | `uteZ` |
| File type | `elf` |
| First seen | `2026-07-22 03:35:57` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88b62bf7a3107f0db2db295b77e89bb7` |
| SHA-1 | `af04f9eb5b1ae56bf9328685c191e83c5320abb3` |
| SHA-256 | `76d7bbf2d95d24046a8ae3a9b64c63ee280700434ce642df02d2530e13bcd8f2` |
| SHA3-384 | `9621590cb9461afc3188922abc4d3e7fb73b4e03113df9349baa1f50aeb3202535f22145ee8abf1f7e21a46942db4993` |
| TLSH | `T1BA631875BC858B16C5C52277FF2D8388331723B8E3EA7113EA195F6537CB92A0E2A151` |
| TELFHASH | `t1cde06873074619dc5fc0c09681ee3a584b1df0322701194ec2fc9d0434e3886fa01c08` |
| SSDEEP | `1536:5Vbe7guylQNy3b6yPCbmeT1yO3ytkcrhyfZZcjgFm1UQkdl:51Cgu8ZjOm81yO3ckcrhUDogFm1UQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_76d7bbf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76d7bbf2d95d24046a8ae3a9b64c63ee280700434ce642df02d2530e13bcd8f2"
    family = "unknown"
    file_name = "uteZ"
    file_type = "elf"
    first_seen = "2026-07-22 03:35:57"
  condition:
    hash.sha256(0, filesize) == "76d7bbf2d95d24046a8ae3a9b64c63ee280700434ce642df02d2530e13bcd8f2"
}
```

### Sample 6: `db9e55535159db14`

| Field | Value |
|---|---|
| SHA-256 | `db9e55535159db148bef69090be530fd01408c303b67f0f16f658d01c7c5ee6d` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Adware.GenericKD.61155092.527.27382` |
| File type | `exe` |
| First seen | `2026-07-22 03:35:31` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1733c79bc9d392d200ae90726154d54f` |
| SHA-1 | `07da26b2f7fc6bf0a1f14b9c31c125259c8324e7` |
| SHA-256 | `db9e55535159db148bef69090be530fd01408c303b67f0f16f658d01c7c5ee6d` |
| SHA3-384 | `c437e060f936f76d13764db9e3e0f9b163cfb7f9cc2ede4ad72692a763d4127d2da786f8d7da0ade2f28812ac6e915b7` |
| IMPHASH | `5d79c27709f823d77f8028442a671a99` |
| TLSH | `T14402F943BA484A86D5BAC8F408576E17F991713341E59E79FA8CC4900F3932AB3BC16E` |
| SSDEEP | `96:vDn/TpzBoLpNnHRPOtYyL9A7elvD0MEwULVh9Z0Grh0DLcy0jhAuD/Elif/4/qd:7LpzUNn1O3L32MT6cchDD/zf/4/+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_db9e5553
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db9e55535159db148bef69090be530fd01408c303b67f0f16f658d01c7c5ee6d"
    family = "unknown"
    file_name = "SecuriteInfo.com.Adware.GenericKD.61155092.527.27382"
    file_type = "exe"
    first_seen = "2026-07-22 03:35:31"
  condition:
    hash.sha256(0, filesize) == "db9e55535159db148bef69090be530fd01408c303b67f0f16f658d01c7c5ee6d"
}
```

### Sample 7: `f9cc910e56e63b80`

| Field | Value |
|---|---|
| SHA-256 | `f9cc910e56e63b80fc8d357374daf473655ef4e4f3ff28e8f0b04f717e9fb78d` |
| Family label | `Mirai` |
| File name | `sora.x86` |
| File type | `elf` |
| First seen | `2026-07-22 02:55:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1481ee89e78aa844452e7776711575f2` |
| SHA-1 | `3614e05d8f8dcabecb8ad759596dc89ca5c0cce4` |
| SHA-256 | `f9cc910e56e63b80fc8d357374daf473655ef4e4f3ff28e8f0b04f717e9fb78d` |
| SHA3-384 | `602ede2918c9f0f7ffa45de180bef9c512457f694751af8d2dd55132664054a11abccf237759017d3817a900e822e437` |
| TLSH | `T1174349C4B183F9F1DC05017C306AEB325E33F0B6713AED9BD7E455B3A855606960AA9C` |
| TELFHASH | `t1ae11e9fa1a7f18ecfbd8a180c29daf125d5ee13b15d133a45522a9292293c81517ecb8` |
| SSDEEP | `1536:MOssuiundFq4ZthwLi/pXUfx0WbVGoPCdgZl7dbFfGf:xzuXndFq4ZthB/VUfOWhGoPKgj7dpOf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_f9cc910e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9cc910e56e63b80fc8d357374daf473655ef4e4f3ff28e8f0b04f717e9fb78d"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-07-22 02:55:53"
  condition:
    hash.sha256(0, filesize) == "f9cc910e56e63b80fc8d357374daf473655ef4e4f3ff28e8f0b04f717e9fb78d"
}
```

### Sample 8: `a804ec4400e8da43`

| Field | Value |
|---|---|
| SHA-256 | `a804ec4400e8da43e2d7e0a3429a3b85abff41f383a9d07041c5730492f8bce1` |
| Family label | `Mirai` |
| File name | `sora.x86` |
| File type | `elf` |
| First seen | `2026-07-22 02:55:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03bcd0dfe8eb604d3db8cf929415e883` |
| SHA-1 | `00140df8601bf15f6530103fbbc626f74ed74f48` |
| SHA-256 | `a804ec4400e8da43e2d7e0a3429a3b85abff41f383a9d07041c5730492f8bce1` |
| SHA3-384 | `603fc0cc7b4e8acbef62e2fb9c13c1d5c723b490a442d2acc034e4790a9cb421eeb3bec4e945003d32323477ad9761d5` |
| TLSH | `T194C2D19394A9CD06C862423B6E1F159B61242439134DFE2E373FEFEC62464B8A235DC3` |
| SSDEEP | `384:MRGW9WXUx5+bkbRaliVErjrL9VD9jPwrSaf5dwapDyCTYHHJC8oytPFnAqV/LlFe:45+Kcrb9VDJe5FLTYTlPFnz/rANb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_a804ec44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a804ec4400e8da43e2d7e0a3429a3b85abff41f383a9d07041c5730492f8bce1"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-07-22 02:55:27"
  condition:
    hash.sha256(0, filesize) == "a804ec4400e8da43e2d7e0a3429a3b85abff41f383a9d07041c5730492f8bce1"
}
```

### Sample 9: `74f0e8132ae338ff`

| Field | Value |
|---|---|
| SHA-256 | `74f0e8132ae338ff8054359b17d9d599cd802d9d0137bab5218137c9ed289f8f` |
| Family label | `unknown` |
| File name | `Zd2` |
| File type | `elf` |
| First seen | `2026-07-22 02:53:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2004a9430c33a021a5c699509ee29d5c` |
| SHA-1 | `09ad529c0a8928bf3525caf39a211eaa4c521065` |
| SHA-256 | `74f0e8132ae338ff8054359b17d9d599cd802d9d0137bab5218137c9ed289f8f` |
| SHA3-384 | `01e64735468a3c5259900c0b0f4ec4b73e54fb7e44e9eb92c3f3b99de4b10c456c84c3d7199dc3fff32d08d112790e03` |
| TLSH | `T1EA631A76BC819B16C1C51677FF2D4388331723B8E3EA7113EA196F6537CB82A0E2A141` |
| TELFHASH | `t141018972458d48edaaf4c28653ef62194a2df1ed37a0591fb5fc9e0e16c38d3f221904` |
| SSDEEP | `1536:yfjOLmZ6Lqw1TAyKsYChNPSbAb1Sno/S7v8WnBZc7dF21UdlTQB+cuF:yfjOLmQqIcolNu+1So/Sb8grgdF21U/x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_74f0e813
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f0e8132ae338ff8054359b17d9d599cd802d9d0137bab5218137c9ed289f8f"
    family = "unknown"
    file_name = "Zd2"
    file_type = "elf"
    first_seen = "2026-07-22 02:53:50"
  condition:
    hash.sha256(0, filesize) == "74f0e8132ae338ff8054359b17d9d599cd802d9d0137bab5218137c9ed289f8f"
}
```

### Sample 10: `671b70f36717d438`

| Field | Value |
|---|---|
| SHA-256 | `671b70f36717d438960f7d923f5d0a78621aebbb97a403de4496c7633a07a697` |
| Family label | `unknown` |
| File name | `MoO` |
| File type | `elf` |
| First seen | `2026-07-22 02:53:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ad752d93e622d8f4a8daff660a5f54e` |
| SHA-1 | `eaa9e766ef79dba1a17df2d891dd9f13f189ce4b` |
| SHA-256 | `671b70f36717d438960f7d923f5d0a78621aebbb97a403de4496c7633a07a697` |
| SHA3-384 | `75cdf070a5f35fb45094614f7af18c8992f31084bc33364251796a048df33f8ada1bf378e0c7e818565993b47dcae82d` |
| TLSH | `T1F383082ABD419F05D5D526BAFF1E538933536BBCE3EE7102EE141B2527CA91B0F2A401` |
| TELFHASH | `t1ba01f13506c44cdc9bd0c106e1ef152ac98ef8b93720098eb5fdef8a92a36d5b312409` |
| SSDEEP | `1536:BbnTFiGHuYu5ks5PynmUXeQhDIzLOP3DNHpUDRRuW5llikiYV0bvOE2:tFimekiwjdwOP3DNHpUDRzsiV0Cn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_671b70f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "671b70f36717d438960f7d923f5d0a78621aebbb97a403de4496c7633a07a697"
    family = "unknown"
    file_name = "MoO"
    file_type = "elf"
    first_seen = "2026-07-22 02:53:49"
  condition:
    hash.sha256(0, filesize) == "671b70f36717d438960f7d923f5d0a78621aebbb97a403de4496c7633a07a697"
}
```

### Sample 11: `a8908e6188e828c3`

| Field | Value |
|---|---|
| SHA-256 | `a8908e6188e828c37eb51771ec60f7468dfbae22c00e0737825c4b97d0004411` |
| Family label | `Mirai` |
| File name | `oeC6` |
| File type | `elf` |
| First seen | `2026-07-22 02:52:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fac71ec093c24565c5c72ac2a3af2e7b` |
| SHA-1 | `51af14ae139df08040217c37df67d766258a310f` |
| SHA-256 | `a8908e6188e828c37eb51771ec60f7468dfbae22c00e0737825c4b97d0004411` |
| SHA3-384 | `6d1dfc8a49fd2b36c272d048b0102b3db16342c12534b88c5f235c8f510262f89160851f46ef9d360591dc2c2524edcf` |
| TLSH | `T134A3FA1EAF611DBBD81BDD3305AC070274CCA61772643B793538C528BB8A54B8AD3CB9` |
| SSDEEP | `1536:zKAeGLVAMtCde3xXi60QAzVm7qauTKN810g5lU02kxXBgz04EE7:7L+ywe3xXD0nzVyioYxX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_a8908e61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8908e6188e828c37eb51771ec60f7468dfbae22c00e0737825c4b97d0004411"
    family = "Mirai"
    file_name = "oeC6"
    file_type = "elf"
    first_seen = "2026-07-22 02:52:24"
  condition:
    hash.sha256(0, filesize) == "a8908e6188e828c37eb51771ec60f7468dfbae22c00e0737825c4b97d0004411"
}
```

### Sample 12: `efadd757ffcdc156`

| Field | Value |
|---|---|
| SHA-256 | `efadd757ffcdc156c9dbcac6745e70be5ca5174636d8853518839da82cf7e7b6` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-22 02:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb223174213a026c0dea090fc60de840` |
| SHA-1 | `f464e40ef739466b9a836b725575c4c396a6cb9f` |
| SHA-256 | `efadd757ffcdc156c9dbcac6745e70be5ca5174636d8853518839da82cf7e7b6` |
| SHA3-384 | `78c9201c5052fc2d1c0482b7dca90f25700b13d06ff371031699868b5f63748ed4fc760226b9373d6132f429c4ff9d72` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T14DE6330CAAD041FDEA624039EEE14696DAA474B54B72CE9B27789328FF475E40D3C743` |
| SSDEEP | `393216:oCejAgyimIDE4eR95QXMCHWUjXwcuI3/PGTAI:okglbSrQXMb8XlH/O7` |
| ICON-DHASH | `b2f1e8cccce871b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_efadd757
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efadd757ffcdc156c9dbcac6745e70be5ca5174636d8853518839da82cf7e7b6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 02:52:08"
  condition:
    hash.sha256(0, filesize) == "efadd757ffcdc156c9dbcac6745e70be5ca5174636d8853518839da82cf7e7b6"
}
```

### Sample 13: `1490e65be0e21b94`

| Field | Value |
|---|---|
| SHA-256 | `1490e65be0e21b946e6128846e30dba08b7f8efbd4a1f8f1adf863c5fc93f974` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.85894993` |
| File type | `exe` |
| First seen | `2026-07-22 02:39:52` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58911b28ea02eecca641d17ff7e1e264` |
| SHA-1 | `58bd88564e96dac078f10f671188afa2fc26cc93` |
| SHA-256 | `1490e65be0e21b946e6128846e30dba08b7f8efbd4a1f8f1adf863c5fc93f974` |
| SHA3-384 | `96e93463697e7221075873b5c21e7bb80a0355b35520f42c91b8f696d0f4afa3aa1ec3ecd523f039b35f9fbb7b99c4ae` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T19CD52399FCB605B5E032C3F68893B0BDB11937868E748C4E76CD6B102E526186C7E776` |
| SSDEEP | `49152:Xti3sFkPT+LpHIHI6IMerwcTnJbXFGruuNWjqzcuH5hqJBIn7t:di8GPTKHIo+rw6uuNWkZht` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_1490e65b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1490e65be0e21b946e6128846e30dba08b7f8efbd4a1f8f1adf863c5fc93f974"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.85894993"
    file_type = "exe"
    first_seen = "2026-07-22 02:39:52"
  condition:
    hash.sha256(0, filesize) == "1490e65be0e21b946e6128846e30dba08b7f8efbd4a1f8f1adf863c5fc93f974"
}
```

### Sample 14: `73db8e9a1b49daa0`

| Field | Value |
|---|---|
| SHA-256 | `73db8e9a1b49daa01f362573eeb79a0b7ac9455f581e79d49a1c99734181d65f` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.57653523` |
| File type | `exe` |
| First seen | `2026-07-22 02:39:50` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bc71a095bfa877ccd3036c8751468f4` |
| SHA-1 | `5a26f05258240fef106471e5e8ed4557177d8917` |
| SHA-256 | `73db8e9a1b49daa01f362573eeb79a0b7ac9455f581e79d49a1c99734181d65f` |
| SHA3-384 | `c5f60876a529d69db14b6f95ac0170d2be9f12d0f8ed456d2f1c062f4db74f843d067237fea9eb520ea55047204112bb` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1B4D52389BDF70970D83BC3B58D83E46D727637409BB18E4B3A8D6A108E536685C36379` |
| SSDEEP | `49152:J+Z00oPVKgcopmQ8m0r1yGShJuJl5y+Ly6qL+iIkKS2MUSS5sJTaVk6A+cMUCcmq:4gcob8m08t+kuq+iIqBssIt+Z3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_73db8e9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73db8e9a1b49daa01f362573eeb79a0b7ac9455f581e79d49a1c99734181d65f"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.57653523"
    file_type = "exe"
    first_seen = "2026-07-22 02:39:50"
  condition:
    hash.sha256(0, filesize) == "73db8e9a1b49daa01f362573eeb79a0b7ac9455f581e79d49a1c99734181d65f"
}
```

### Sample 15: `85142e27e44b83ae`

| Field | Value |
|---|---|
| SHA-256 | `85142e27e44b83ae26230454694d1666652e718e3764e57a1d6539c83e448402` |
| Family label | `CoinMiner` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.64268345` |
| File type | `exe` |
| First seen | `2026-07-22 02:39:49` |
| Reporter | `SecuriteInfoCom` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eba7c112a3522d28fc665e6384945ffc` |
| SHA-1 | `69ecc978c6058b4c17f68693228c72a198757635` |
| SHA-256 | `85142e27e44b83ae26230454694d1666652e718e3764e57a1d6539c83e448402` |
| SHA3-384 | `ae67065ca9d95e025edf3e7e2fb0eeee5888a76788db0e4551656335d91f3e4d4a702735d0f4bce88c6e801b17627a66` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T19236338ABEC6A574D067C37D5566606DB23F3BA4DAA03C4A768C2E0C482BF0D497D3C0` |
| SSDEEP | `98304:8CycSycpRtQVRurwGALKrbaAZh2+sopKUGDI081Dh7FDHIn:rc7Qurnz/IopKU60DhpDHIn` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_015_85142e27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85142e27e44b83ae26230454694d1666652e718e3764e57a1d6539c83e448402"
    family = "CoinMiner"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.64268345"
    file_type = "exe"
    first_seen = "2026-07-22 02:39:49"
  condition:
    hash.sha256(0, filesize) == "85142e27e44b83ae26230454694d1666652e718e3764e57a1d6539c83e448402"
}
```

### Sample 16: `55a47a54228736d7`

| Field | Value |
|---|---|
| SHA-256 | `55a47a54228736d7dad743a053f6c7a832b06efe94ae2c6645d5f0df034cff58` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.65237985` |
| File type | `exe` |
| First seen | `2026-07-22 02:39:47` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b55e3e76c407170c3c6b8193989c83d9` |
| SHA-1 | `9549f4ae06357d7fa827878d46aa7fc1e375dc80` |
| SHA-256 | `55a47a54228736d7dad743a053f6c7a832b06efe94ae2c6645d5f0df034cff58` |
| SHA3-384 | `48ccb897d6921116ad7a09b5427bde375a802fbadf6f7c3ea8fc7417f016eb51aa4eef4130d167a50b614e23c1b39c40` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T185D523CA78F21974C432C7D68F93E47DB16A7B954B358E63BBCD6A108D528891C7A330` |
| SSDEEP | `49152:WYDW6Ybz1gpk6XiVt4+KdKn45UdqQnej2t4LUupHxKpoBlBgNLfuAzI3Z7SnX+n7:CGtXiVu++2GUHeS2L9CpoBlBYL8bgSD3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_55a47a54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a47a54228736d7dad743a053f6c7a832b06efe94ae2c6645d5f0df034cff58"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.65237985"
    file_type = "exe"
    first_seen = "2026-07-22 02:39:47"
  condition:
    hash.sha256(0, filesize) == "55a47a54228736d7dad743a053f6c7a832b06efe94ae2c6645d5f0df034cff58"
}
```

### Sample 17: `2cb2ced283d72a73`

| Field | Value |
|---|---|
| SHA-256 | `2cb2ced283d72a7323be7e4c95c1563ff5f26546794e602e58c2701f2b3c623a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 02:35:27` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ddbc6c25176e1b5b32f242f1f336e6f` |
| SHA-1 | `0778c4b49cf9f1931a81200574d6e4a4448804f6` |
| SHA-256 | `2cb2ced283d72a7323be7e4c95c1563ff5f26546794e602e58c2701f2b3c623a` |
| SHA3-384 | `d6919d77761bde7eaa677284431751c591c5c9f755a2b0be909ad95744c01cecce15043429bff1b681a464988ac4ae06` |
| IMPHASH | `14b2c1037c7b350f17a09784b21d3824` |
| TLSH | `T170D38095F2D61CCBE66592BC42D5E222763DBCE10213CB574A246A374F9AFC37AE0143` |
| SSDEEP | `1536:SgmN86v2wtsHDvqh8bYtChC+PeAHCMgArhByuy6aif/D50TIpIvSUbmLW/KfABkA:SgmNlymybYtChrIMgArXyVi1sSsmLVE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_2cb2ced2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cb2ced283d72a7323be7e4c95c1563ff5f26546794e602e58c2701f2b3c623a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 02:35:27"
  condition:
    hash.sha256(0, filesize) == "2cb2ced283d72a7323be7e4c95c1563ff5f26546794e602e58c2701f2b3c623a"
}
```

### Sample 18: `4f09b4b24d59d2db`

| Field | Value |
|---|---|
| SHA-256 | `4f09b4b24d59d2db69f9fe5b4b7b1fcb4f65e8412728d1c9d8ceb636358f7207` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 02:35:18` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX10.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `250ab84cd2e77519bb7ae2800551f313` |
| SHA-1 | `17dc28450826ff0d8f500102e1cecb940699f034` |
| SHA-256 | `4f09b4b24d59d2db69f9fe5b4b7b1fcb4f65e8412728d1c9d8ceb636358f7207` |
| SHA3-384 | `c14af8b1757795ab0984f6135ed4737bc0449a9ad8a2777b11c713068ec5c3a1f5c9002ee42794936b391d8239e8c9a3` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T19775239386F846B6F7F777B9A9F2026362763C5457B767EF060046980D237C29231B22` |
| SSDEEP | `24576:qidlODrEVSRTxQ3H+IQmNAqRLWFeM9Drx8CK0X+QA+Jv9hGVFpv6cuos:qi2DwaxCH/WmLWoi3xS0TASv9hiXScH` |
| ICON-DHASH | `e8d4b2f0f0b2f0e8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_4f09b4b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f09b4b24d59d2db69f9fe5b4b7b1fcb4f65e8412728d1c9d8ceb636358f7207"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 02:35:18"
  condition:
    hash.sha256(0, filesize) == "4f09b4b24d59d2db69f9fe5b4b7b1fcb4f65e8412728d1c9d8ceb636358f7207"
}
```

### Sample 19: `8f0637cd0ceefdd4`

| Field | Value |
|---|---|
| SHA-256 | `8f0637cd0ceefdd4a98b8d33c7ab50ca6664647f8e979d23b43f3c56329ab269` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-22 02:27:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `691a7c469efa2ba0eb10c6fe5acdf957` |
| SHA-1 | `9d0c4e3ab13a247a61aac38c5a55b9207972b5f3` |
| SHA-256 | `8f0637cd0ceefdd4a98b8d33c7ab50ca6664647f8e979d23b43f3c56329ab269` |
| SHA3-384 | `728c7cd1eaf15732821a56470a366a82236ba6e7ec00ef1b86af560056b8a09ca063a26e3e0f286c784499cbd91026bb` |
| TLSH | `T1D6016BC68650A90051599A9E669792A0F490C3CE198A0B68BFEC5D3DFB9C814F026F94` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaEECxCCOrFLYC8CxZO1esDCBIqmCGsRauD:kXCKysE2hi0ziQvZohaEE59UYZMr1mR7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_8f0637cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f0637cd0ceefdd4a98b8d33c7ab50ca6664647f8e979d23b43f3c56329ab269"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-22 02:27:32"
  condition:
    hash.sha256(0, filesize) == "8f0637cd0ceefdd4a98b8d33c7ab50ca6664647f8e979d23b43f3c56329ab269"
}
```

### Sample 20: `47f8790c9b5b9aab`

| Field | Value |
|---|---|
| SHA-256 | `47f8790c9b5b9aab6ae179a192a91d4a5b4e6aac17c14f103858fa3b72ceba25` |
| Family label | `BlackMatter` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 02:10:12` |
| Reporter | `Bitsight` |
| Tags | `BlackMatter, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4af3347681b6ef41b4d8a444c03ac6ce` |
| SHA-1 | `ac22c26cae3ae7842b8e60eb3ec23a0cdc16b88d` |
| SHA-256 | `47f8790c9b5b9aab6ae179a192a91d4a5b4e6aac17c14f103858fa3b72ceba25` |
| SHA3-384 | `30b1f9828a5c88aafb16616a72547ad38c1418fce02263ac58e8f05dac679958daa161a29d961f2525aabf36bc839562` |
| IMPHASH | `41fb8cb2943df6de998b35a9d28668e8` |
| TLSH | `T12AE36D21F212D0B3C8771CF12736B572B39E8D2C19A95817EAD80F5DBCA58236F45A87` |
| SSDEEP | `3072:E6glyuxE4GsUPnliByocWepngstnC51HOfbZ:E6gDBGpvEByocWeTtCDH` |

#### Technical Assessment

- The sample is tracked as `BlackMatter` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlackMatter_020_47f8790c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47f8790c9b5b9aab6ae179a192a91d4a5b4e6aac17c14f103858fa3b72ceba25"
    family = "BlackMatter"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 02:10:12"
  condition:
    hash.sha256(0, filesize) == "47f8790c9b5b9aab6ae179a192a91d4a5b4e6aac17c14f103858fa3b72ceba25"
}
```

### Sample 21: `56819d1e3fb265c8`

| Field | Value |
|---|---|
| SHA-256 | `56819d1e3fb265c80e117800fd1df93744135ca391a311250d0221e7ecc9fd81` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-22 01:52:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2688dbe613f744f03b334524b6357eb3` |
| SHA-1 | `45dae35f1a1312dfc4d4cccb18c0f23e474e209e` |
| SHA-256 | `56819d1e3fb265c80e117800fd1df93744135ca391a311250d0221e7ecc9fd81` |
| SHA3-384 | `73ef40b6db9c50b145d5be30ac632c2d05ff1722774c66a7603fe6ea906a82f32be35c9c893e20584b5e37190437d1b6` |
| TLSH | `T1B1C27D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CC618B1A` |
| SSDEEP | `768:q8vCB+25j6es8ROf9FYpMSUpi+20qUpi+20YQX:q8l25J+d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_56819d1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56819d1e3fb265c80e117800fd1df93744135ca391a311250d0221e7ecc9fd81"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-22 01:52:27"
  condition:
    hash.sha256(0, filesize) == "56819d1e3fb265c80e117800fd1df93744135ca391a311250d0221e7ecc9fd81"
}
```

### Sample 22: `fb881f10b82cd577`

| Field | Value |
|---|---|
| SHA-256 | `fb881f10b82cd577893fc57375fcfa43a5650c395f82ab42c18eca04874679d4` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-22 01:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7a1013cd426ba6847ed608ea7128584` |
| SHA-1 | `b4887b506b23eab809e9ba44c7733697ee82173c` |
| SHA-256 | `fb881f10b82cd577893fc57375fcfa43a5650c395f82ab42c18eca04874679d4` |
| SHA3-384 | `a3f24867e240013b18fd7b56b92edbcfae45923d3ae3ebaad926c9fff1386a3937dca8ef283cc621b9fdd3ca6d2fb32c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T10AE63358F6E015EEFAA7503CDEA35160F5B474764B72CAAB47944264BE132E08C3D32B` |
| SSDEEP | `393216:wDz8RrzCYvoekgsLYUCvlMG7XMCHWUjX0cuI3/PGTAI:wDOrzD9kgsLvG7XMb8XhH/O7` |
| ICON-DHASH | `71f0e4d4c4e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_fb881f10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb881f10b82cd577893fc57375fcfa43a5650c395f82ab42c18eca04874679d4"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 01:52:08"
  condition:
    hash.sha256(0, filesize) == "fb881f10b82cd577893fc57375fcfa43a5650c395f82ab42c18eca04874679d4"
}
```

### Sample 23: `e5dda4e7dc6b9583`

| Field | Value |
|---|---|
| SHA-256 | `e5dda4e7dc6b95830c066b519383e71abd4fb0a2340c0def898f635d9cfa13e7` |
| Family label | `AsyncRAT` |
| File name | `e-dekont_html.exe` |
| File type | `exe` |
| First seen | `2026-07-22 01:45:21` |
| Reporter | `threatcat_ch` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24f1c6fbb6cd28d53117bfbef3e9ec08` |
| SHA-1 | `056db76657f3108c8db03a33c59db1fa8ee1cd14` |
| SHA-256 | `e5dda4e7dc6b95830c066b519383e71abd4fb0a2340c0def898f635d9cfa13e7` |
| SHA3-384 | `1e17b3b01def9203df4956f6254de6889e55aa972b1fde480d25e444065eebfc4c2027cf01c35d010dda3f6f7840e3ea` |
| IMPHASH | `46d844d880996af2766416e3e2079244` |
| TLSH | `T1D2A5AE19E3D812A8E167DA74CB51A332D6B178534771E19F0A99D70A2F73E908F3B312` |
| SSDEEP | `49152:W0ao7zY6iUSzvEHTf1PLudGRSY3yOZ2S+oeATrfK:WqeY3yOZ2S+oeATrfK` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_023_e5dda4e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5dda4e7dc6b95830c066b519383e71abd4fb0a2340c0def898f635d9cfa13e7"
    family = "AsyncRAT"
    file_name = "e-dekont_html.exe"
    file_type = "exe"
    first_seen = "2026-07-22 01:45:21"
  condition:
    hash.sha256(0, filesize) == "e5dda4e7dc6b95830c066b519383e71abd4fb0a2340c0def898f635d9cfa13e7"
}
```

### Sample 24: `5da46290c303a3ac`

| Field | Value |
|---|---|
| SHA-256 | `5da46290c303a3acb2b8f5ec1792f33728903b7700e742c9e37aac026270245b` |
| Family label | `unknown` |
| File name | `拼多多.exe` |
| File type | `exe` |
| First seen | `2026-07-22 01:39:08` |
| Reporter | `CNGaoLing` |
| Tags | `exe, KillMBR, MBRlock, MBRLocker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef696834a9cae24973bb0d5f42d0d5d9` |
| SHA-1 | `218c38724c6d59921894b98c15ed431e1ce17a3a` |
| SHA-256 | `5da46290c303a3acb2b8f5ec1792f33728903b7700e742c9e37aac026270245b` |
| SHA3-384 | `917de2c7d4dfe607b67eb18e8ab9e712beca3526ead8b98fef381baf410e80b8becb32bcf43c0ad3d469bb36ff0b0d5a` |
| TLSH | `T18D663383D2C300F5DB86297125BF6B3BDA3AC7464B2AEFD39394ED105D72641E03625A` |
| SSDEEP | `196608:JLyWj9MVWw/ZO3HS56RVDeYavZGqaSxCx9/kEfEY0V:7vwh0E2e3vYqHsx98EfEYA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_5da46290
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5da46290c303a3acb2b8f5ec1792f33728903b7700e742c9e37aac026270245b"
    family = "unknown"
    file_name = "拼多多.exe"
    file_type = "exe"
    first_seen = "2026-07-22 01:39:08"
  condition:
    hash.sha256(0, filesize) == "5da46290c303a3acb2b8f5ec1792f33728903b7700e742c9e37aac026270245b"
}
```

### Sample 25: `5711be9cf97b2b68`

| Field | Value |
|---|---|
| SHA-256 | `5711be9cf97b2b68e39b35852491329197352fb561c8f7d3e6212d4cc1ecf9a5` |
| Family label | `unknown` |
| File name | `putty_trojanized.exe` |
| File type | `msi` |
| First seen | `2026-07-22 01:30:08` |
| Reporter | `och0` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddaa8aee018b34f0ddb6353e32506b9f` |
| SHA-256 | `5711be9cf97b2b68e39b35852491329197352fb561c8f7d3e6212d4cc1ecf9a5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_5711be9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5711be9cf97b2b68e39b35852491329197352fb561c8f7d3e6212d4cc1ecf9a5"
    family = "unknown"
    file_name = "putty_trojanized.exe"
    file_type = "msi"
    first_seen = "2026-07-22 01:30:08"
  condition:
    hash.sha256(0, filesize) == "5711be9cf97b2b68e39b35852491329197352fb561c8f7d3e6212d4cc1ecf9a5"
}
```

### Sample 26: `7f9826fd3e5026c5`

| Field | Value |
|---|---|
| SHA-256 | `7f9826fd3e5026c5aae9a4672a977415ca8090d0653c4636a304130bd26b9382` |
| Family label | `unknown` |
| File name | `winscp_trojanized.exe` |
| File type | `exe` |
| First seen | `2026-07-22 01:30:05` |
| Reporter | `och0` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de234604fe0bf3f75ba60a67430811bc` |
| SHA-256 | `7f9826fd3e5026c5aae9a4672a977415ca8090d0653c4636a304130bd26b9382` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_7f9826fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f9826fd3e5026c5aae9a4672a977415ca8090d0653c4636a304130bd26b9382"
    family = "unknown"
    file_name = "winscp_trojanized.exe"
    file_type = "exe"
    first_seen = "2026-07-22 01:30:05"
  condition:
    hash.sha256(0, filesize) == "7f9826fd3e5026c5aae9a4672a977415ca8090d0653c4636a304130bd26b9382"
}
```

### Sample 27: `a80abf352e9f3524`

| Field | Value |
|---|---|
| SHA-256 | `a80abf352e9f35244aec83f4b82b221a6b0c3ef0cd10c87acc4168d60abca723` |
| Family label | `unknown` |
| File name | `filezilla_trojanized_download` |
| File type | `exe` |
| First seen | `2026-07-22 01:30:03` |
| Reporter | `och0` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97e9a969a9009b695b80f10e6eb26ae7` |
| SHA-256 | `a80abf352e9f35244aec83f4b82b221a6b0c3ef0cd10c87acc4168d60abca723` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_a80abf35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a80abf352e9f35244aec83f4b82b221a6b0c3ef0cd10c87acc4168d60abca723"
    family = "unknown"
    file_name = "filezilla_trojanized_download"
    file_type = "exe"
    first_seen = "2026-07-22 01:30:03"
  condition:
    hash.sha256(0, filesize) == "a80abf352e9f35244aec83f4b82b221a6b0c3ef0cd10c87acc4168d60abca723"
}
```

### Sample 28: `9c4d1d8077938fef`

| Field | Value |
|---|---|
| SHA-256 | `9c4d1d8077938fef89508c207e5fc0c56544d84ac34c08c7ffe7a9c107e68237` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-22 01:10:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a1938d0b98691454ba4b6d8d122be7e` |
| SHA-1 | `05773ad8937d2e33b4fb318358347738174bda47` |
| SHA-256 | `9c4d1d8077938fef89508c207e5fc0c56544d84ac34c08c7ffe7a9c107e68237` |
| SHA3-384 | `d33433f8586b87a671e665cfacb5359e3e7eba6ad2334062daab70b213360007076b0bae35d17226ffd7ae909e6d0e66` |
| TLSH | `T1DE236C651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69DD10972D` |
| SSDEEP | `768:gXRWNGxVh/9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:0lxv4cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_9c4d1d80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c4d1d8077938fef89508c207e5fc0c56544d84ac34c08c7ffe7a9c107e68237"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-22 01:10:53"
  condition:
    hash.sha256(0, filesize) == "9c4d1d8077938fef89508c207e5fc0c56544d84ac34c08c7ffe7a9c107e68237"
}
```

### Sample 29: `ac59f3d4e4536927`

| Field | Value |
|---|---|
| SHA-256 | `ac59f3d4e45369275a7c9fc49bacb32fbc4348e57b5af5f3a12a018904d386ea` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-22 01:07:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e47a765a7316c12f481db1e622510df7` |
| SHA-1 | `d12ea3d30ae780eec51982095f9f0ad8b8e1d53a` |
| SHA-256 | `ac59f3d4e45369275a7c9fc49bacb32fbc4348e57b5af5f3a12a018904d386ea` |
| SHA3-384 | `70a66837403beb237fe6531e656ff054e3013629fd7247545def63f8aeb67ccf006c1bd6daa2532c5d1b9a79771ff6a5` |
| TLSH | `T1FA237D652A817C14AA98C4371D7E2F0CB9AD43E6320452ED7FCF3CF68C5A69D921871D` |
| SSDEEP | `768:YXOGVvn9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:OLIcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_ac59f3d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac59f3d4e45369275a7c9fc49bacb32fbc4348e57b5af5f3a12a018904d386ea"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-22 01:07:37"
  condition:
    hash.sha256(0, filesize) == "ac59f3d4e45369275a7c9fc49bacb32fbc4348e57b5af5f3a12a018904d386ea"
}
```

### Sample 30: `dab034d5e6609eee`

| Field | Value |
|---|---|
| SHA-256 | `dab034d5e6609eee42d40f4d61a0b95aa9dc4765c15d3d3dff81a2a16d7315bd` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 01:04:57` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `218561da1c8f6b975d088e8ac4976795` |
| SHA-1 | `65ecb0ec3954700dc5a7f9759996032e08c653e5` |
| SHA-256 | `dab034d5e6609eee42d40f4d61a0b95aa9dc4765c15d3d3dff81a2a16d7315bd` |
| SHA3-384 | `43674248c3798fdc727e4e44704d98aa8048de3004f4eeffb02627f29d04967a2ad02ab26a38179ac5cc061531f5cb3b` |
| IMPHASH | `cf1136126b3340920376499ac9490ff7` |
| TLSH | `T18FB38D2034C1C432E567217988EAC7B58A6DF8310F7566D7BFC406AE4F276D29A36387` |
| SSDEEP | `1536:q3L/ED9LEo5D+ZPJ4m6G+zZTATLu3dKVI7IYM5XDd4i5cAOy:oL/cl5Mi9G+zhWLqwZ5Xei5cAOy` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_030_dab034d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dab034d5e6609eee42d40f4d61a0b95aa9dc4765c15d3d3dff81a2a16d7315bd"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 01:04:57"
  condition:
    hash.sha256(0, filesize) == "dab034d5e6609eee42d40f4d61a0b95aa9dc4765c15d3d3dff81a2a16d7315bd"
}
```

### Sample 31: `ac197dc54bf1c690`

| Field | Value |
|---|---|
| SHA-256 | `ac197dc54bf1c690dce6eff2024651fee1c57f3273ef4deb253854fe2b0afba7` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-22 00:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `710f0942c75f9b12c61f55c166b50fc4` |
| SHA-1 | `e433cca452309f84f87100208fd3354d643643b5` |
| SHA-256 | `ac197dc54bf1c690dce6eff2024651fee1c57f3273ef4deb253854fe2b0afba7` |
| SHA3-384 | `55cc802a106ebfebb5125d3613e0fd29fd58d32dd69a7a4cfb824fccec105b13ca3d8f741460c53dfc1912f3292c465b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T194E633488AE001EDE5FB403CEEA156A1E572747453B3C6CB47AC43E26E571E09E3E61B` |
| SSDEEP | `393216:OdubvQoZsJjr3rXMCHWUjXWcuI3/PGTAI:Ow7TAr3rXMb8XrH/O7` |
| ICON-DHASH | `18dcf8f8fcf8e040` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_ac197dc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac197dc54bf1c690dce6eff2024651fee1c57f3273ef4deb253854fe2b0afba7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 00:52:08"
  condition:
    hash.sha256(0, filesize) == "ac197dc54bf1c690dce6eff2024651fee1c57f3273ef4deb253854fe2b0afba7"
}
```

### Sample 32: `a54c005d853b1e80`

| Field | Value |
|---|---|
| SHA-256 | `a54c005d853b1e8085c6cb4289561bd16365181e8441b204bea491425b0b3cd4` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-22 00:48:01` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ce852b26b4116d9ab05ef7a527e0ba7` |
| SHA-1 | `31a07f54d4f371c2b89e4367419f42ac01457aff` |
| SHA-256 | `a54c005d853b1e8085c6cb4289561bd16365181e8441b204bea491425b0b3cd4` |
| SHA3-384 | `88ba15cff323fdcec57942e44ae16def1f3105da3a23d67ddc4774b0c649d0fd7ea821e62e75d8f14703f555fc5ca70c` |
| TLSH | `T1CEC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:f8vCB+25j6es8RL9FYpMSUpi+20qUpi+20YQX:f8l25Jdd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_a54c005d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a54c005d853b1e8085c6cb4289561bd16365181e8441b204bea491425b0b3cd4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-22 00:48:01"
  condition:
    hash.sha256(0, filesize) == "a54c005d853b1e8085c6cb4289561bd16365181e8441b204bea491425b0b3cd4"
}
```

### Sample 33: `f08dd221aabdc54d`

| Field | Value |
|---|---|
| SHA-256 | `f08dd221aabdc54de26f51b466ae2cdf5b242b918d27bc02eaa1a18fc6a4113d` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-22 00:38:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2d569d4cbc57ec985af41968bec6d50` |
| SHA-1 | `620d723d4bc37375275fdc7dec59777eee2526ab` |
| SHA-256 | `f08dd221aabdc54de26f51b466ae2cdf5b242b918d27bc02eaa1a18fc6a4113d` |
| SHA3-384 | `f718b2be8575ba9d52003006d79c1e640adab729bf3f78428139d23c28ebc7c80355e82aef1304f50fc738ab41a5afe0` |
| TLSH | `T15CD097AB0A3300301432AC54F1CBF41074084F3F6C1D872DB4A718302F42308F5E1396` |
| SSDEEP | `6:hTDpcF7bFfxGtOpAulNXYq4HvXDG+NjVsNXYrkJ:VDyF7bF5G2Piq4HvXDGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_f08dd221
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f08dd221aabdc54de26f51b466ae2cdf5b242b918d27bc02eaa1a18fc6a4113d"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-22 00:38:32"
  condition:
    hash.sha256(0, filesize) == "f08dd221aabdc54de26f51b466ae2cdf5b242b918d27bc02eaa1a18fc6a4113d"
}
```

### Sample 34: `253938f54a9938d1`

| Field | Value |
|---|---|
| SHA-256 | `253938f54a9938d1a2d9ce6622f1a3aecdf856961603c3faa6523467af6f3373` |
| Family label | `unknown` |
| File name | `bot` |
| File type | `unknown` |
| First seen | `2026-07-22 00:22:54` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39fe596815959429ed70115099426b25` |
| SHA-1 | `363b999a1b003da1d407419bccb382139e45ac42` |
| SHA-256 | `253938f54a9938d1a2d9ce6622f1a3aecdf856961603c3faa6523467af6f3373` |
| SHA3-384 | `ae90954a3ed98740556312c110497fad14bf4ac4e3bd0329f7a457e83823fc45ccae4c03417e1cc5f6e86e0056471a2e` |
| TLSH | `T1E85311094DE3595173B3B0BA97DE945A7AA7C0C74F8B9E203C8D439AEFA103485F85D8` |
| SSDEEP | `768:dsJEryYUeNMZeZr2H3iFF9J50A8XZqP99pJW3gObz/P:MEr1UeNsc2HEBGBZqNigQ/P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_253938f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "253938f54a9938d1a2d9ce6622f1a3aecdf856961603c3faa6523467af6f3373"
    family = "unknown"
    file_name = "bot"
    file_type = "unknown"
    first_seen = "2026-07-22 00:22:54"
  condition:
    hash.sha256(0, filesize) == "253938f54a9938d1a2d9ce6622f1a3aecdf856961603c3faa6523467af6f3373"
}
```

### Sample 35: `87c155878e8aa527`

| Field | Value |
|---|---|
| SHA-256 | `87c155878e8aa527a3976649fb9bdb511bcd9f0e1507744c69804b2af597dcfd` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-22 00:14:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6efe7bd1cc67ea1c25f0ceebeb4ee4fe` |
| SHA-1 | `083c88edec59a5301d2865ee979ec3acb5760996` |
| SHA-256 | `87c155878e8aa527a3976649fb9bdb511bcd9f0e1507744c69804b2af597dcfd` |
| SHA3-384 | `b73c7a4b5fa12539877337b0e8c82f9586e1cd7c150905b5566ccdf29a1340003f46e959165ff8784618d091e34a2aaa` |
| TLSH | `T1D40112C9C100AC10009EEAAC22D75190F410C3CF568A4F25BF6D2D3EEB88C10F067F84` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaDCW6mXCzatH8CSkC4DzUFCuHZ6X:kXCKysE2hi0ziQvZohaDb6O8eupZ6X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_87c15587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87c155878e8aa527a3976649fb9bdb511bcd9f0e1507744c69804b2af597dcfd"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-22 00:14:32"
  condition:
    hash.sha256(0, filesize) == "87c155878e8aa527a3976649fb9bdb511bcd9f0e1507744c69804b2af597dcfd"
}
```

### Sample 36: `8cb552bced9f715c`

| Field | Value |
|---|---|
| SHA-256 | `8cb552bced9f715c2c24e058d5f589710e185991af4552e9f22d15d1249ca271` |
| Family label | `Mirai` |
| File name | `pDY` |
| File type | `elf` |
| First seen | `2026-07-22 00:14:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e18ec4eb89a970bac2c723658a4b5932` |
| SHA-1 | `103cbc756e510be712259f4a2a7477f7293ba0c7` |
| SHA-256 | `8cb552bced9f715c2c24e058d5f589710e185991af4552e9f22d15d1249ca271` |
| SHA3-384 | `7af2f7478567df88d44e7b0f0e2351c85ced2241500eb447ac37593a1383dca4c029d9ee5eb839b99961fc8b241d377f` |
| TLSH | `T18683082ABD819F05D4D526BAFF1E924933535BBCE3EE7102DE146B2527CA91B0F3A401` |
| TELFHASH | `t16ee061b64a4185fc93e44559d05f711a430ce052051045d8bafc5e1fd173886760e40a` |
| SSDEEP | `1536:Mjn/sQkEG/DKYUIlkvkCCd3cHqDdGg32Hd6NouPAxwuH5llUbiuNa4kZHh:6OEID9g2ICl32Hd6NouPAxRK7NaD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_8cb552bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cb552bced9f715c2c24e058d5f589710e185991af4552e9f22d15d1249ca271"
    family = "Mirai"
    file_name = "pDY"
    file_type = "elf"
    first_seen = "2026-07-22 00:14:31"
  condition:
    hash.sha256(0, filesize) == "8cb552bced9f715c2c24e058d5f589710e185991af4552e9f22d15d1249ca271"
}
```

### Sample 37: `9348f83dd5875168`

| Field | Value |
|---|---|
| SHA-256 | `9348f83dd587516806782a5bb4cb0a87c4c904152f07c2958e0275b9ce8c63ac` |
| Family label | `unknown` |
| File name | `rev` |
| File type | `elf` |
| First seen | `2026-07-22 00:13:55` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1707cb5397c121b767fe6ca40d4897ba` |
| SHA-1 | `3ad4c94b62330e25aaaf65bdc8e38a70eb928ca7` |
| SHA-256 | `9348f83dd587516806782a5bb4cb0a87c4c904152f07c2958e0275b9ce8c63ac` |
| SHA3-384 | `836aae22f56acc72bfbbf86f71d5e7b0a349e08fbebd06c9f374a8eda877cf2fece067c762420f989ecee276f9330b39` |
| TLSH | `T15D056B1BB2B334FCC16BC030479BDB636835F46601226EB761C4AA352D53EA11B5AF67` |
| TELFHASH | `t16e6185719afa35b0a2d7ca01e362f0f4a97b2c7661e1387057276ac0ef06f810ca3413` |
| SSDEEP | `12288:gu2Lj6HaI/Di80JWm+eKFE0KWQyyaOBgmDeDr:gu2L2HaI/DiNWm9KFhmA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_9348f83d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9348f83dd587516806782a5bb4cb0a87c4c904152f07c2958e0275b9ce8c63ac"
    family = "unknown"
    file_name = "rev"
    file_type = "elf"
    first_seen = "2026-07-22 00:13:55"
  condition:
    hash.sha256(0, filesize) == "9348f83dd587516806782a5bb4cb0a87c4c904152f07c2958e0275b9ce8c63ac"
}
```

### Sample 38: `8c7334c6455f4e7d`

| Field | Value |
|---|---|
| SHA-256 | `8c7334c6455f4e7d62a9eac56532463b06c50ddf8755610b71af7d062f0739ae` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 00:13:28` |
| Reporter | `Bitsight` |
| Tags | `6e7868436f4d3b49f375773379ba9022, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f2e5fcc62332488c7719734e17fdfb6` |
| SHA-1 | `452f597bf23f1e02f0452ee02ecebea81911e6a6` |
| SHA-256 | `8c7334c6455f4e7d62a9eac56532463b06c50ddf8755610b71af7d062f0739ae` |
| SHA3-384 | `d76b82fbc2c46549bf9dee52e8dd841c889ab299b4c0849883ea9c03492e4bb58a5a808e317f23920a550bdc6b3a3634` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T113D5239E7DF529B0D836C7768FA3F43DB02977898B208D837ACD66004D622580D797B9` |
| SSDEEP | `49152:feuv5UBFzm7raanrljR51kwk7UjsLNTOtyH6EfCqIxuKsXlcca8QlVA:feu+zm/JtVjsx8JEfCVHs1V/Qc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_8c7334c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7334c6455f4e7d62a9eac56532463b06c50ddf8755610b71af7d062f0739ae"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:13:28"
  condition:
    hash.sha256(0, filesize) == "8c7334c6455f4e7d62a9eac56532463b06c50ddf8755610b71af7d062f0739ae"
}
```

### Sample 39: `e580389c650f257f`

| Field | Value |
|---|---|
| SHA-256 | `e580389c650f257fa14de379ebe93eb86ea56a123557c7eadb0a2ef4a6a37303` |
| Family label | `unknown` |
| File name | `9a0L` |
| File type | `elf` |
| First seen | `2026-07-22 00:12:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `768a64cc044e28cd8b6e32ced93817f7` |
| SHA-1 | `dc6e5d38a045b640c84f1d111718eecab2c5c11c` |
| SHA-256 | `e580389c650f257fa14de379ebe93eb86ea56a123557c7eadb0a2ef4a6a37303` |
| SHA3-384 | `0bc4db25f744f50505090557f29a71c82ccf5b05194c71f16c76295ea64c9689503a95c159daf2c1960e9539512b325e` |
| TLSH | `T102631935BC819F16C5D52677FF1D8348335B23A8E3EA7213EA156F6537CB82A0E2A141` |
| TELFHASH | `t1cde06873074619dc5fc0c09681ee3a584b1df0322701194ec2fc9d0434e3886fa01c08` |
| SSDEEP | `1536:ZVbW7juSBQNy3bJZPCbmeT1yz3y5ocidWmsZcOzkFS1UPbi4p:Z1qjuwZ3Om81yz3oocidV+ZAFS1UP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_e580389c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e580389c650f257fa14de379ebe93eb86ea56a123557c7eadb0a2ef4a6a37303"
    family = "unknown"
    file_name = "9a0L"
    file_type = "elf"
    first_seen = "2026-07-22 00:12:53"
  condition:
    hash.sha256(0, filesize) == "e580389c650f257fa14de379ebe93eb86ea56a123557c7eadb0a2ef4a6a37303"
}
```

### Sample 40: `6eff7333743c1285`

| Field | Value |
|---|---|
| SHA-256 | `6eff7333743c1285e911154a0eb3725c53fd53d954e21419af03ae47e8d4bf43` |
| Family label | `Mirai` |
| File name | `MjsG` |
| File type | `elf` |
| First seen | `2026-07-22 00:12:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99b22d0b1ec5773dcd5995d88450efa3` |
| SHA-1 | `93f654e400e7bcdde1635e469a6668ec5b8cefbe` |
| SHA-256 | `6eff7333743c1285e911154a0eb3725c53fd53d954e21419af03ae47e8d4bf43` |
| SHA3-384 | `b816e6877c02049a481b10de84ed2cc4821e92f84ac2117a832be6613ecaf91eedd1a523f2f403835126566a430f409f` |
| TLSH | `T152A3E90AAF611DBBD81BDD3705AD0B0238CCA617716437793638D52CBB8A54B8AD3CB5` |
| SSDEEP | `1536:nsloqsj+IlagXA6hZAYcdKou7N3Ub4OkIMfO6m0I/V5g22VTzZU23:aJ4+IlagXNh6YKE7NloVm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_6eff7333
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eff7333743c1285e911154a0eb3725c53fd53d954e21419af03ae47e8d4bf43"
    family = "Mirai"
    file_name = "MjsG"
    file_type = "elf"
    first_seen = "2026-07-22 00:12:52"
  condition:
    hash.sha256(0, filesize) == "6eff7333743c1285e911154a0eb3725c53fd53d954e21419af03ae47e8d4bf43"
}
```

### Sample 41: `1501fb778e9ceefc`

| Field | Value |
|---|---|
| SHA-256 | `1501fb778e9ceefc0dca1f8cfe8c9fdd1738db5f6dbb0032348f3e161391d016` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 00:10:59` |
| Reporter | `Bitsight` |
| Tags | `6e7868436f4d3b49f375773379ba9022, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a998a470d68a17d1912685639320fd3d` |
| SHA-1 | `85ba9dadb71f696bd751ad5a031801f6704a34ed` |
| SHA-256 | `1501fb778e9ceefc0dca1f8cfe8c9fdd1738db5f6dbb0032348f3e161391d016` |
| SHA3-384 | `5581d47192bd6ee9edeb985e90285f68a500af306824494143199f1486684cc549309dfe0ecea5cce8f873f085c13338` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T19A3633E63CC97474D81AC7B88643646CF23DFBD08965BC173AC669115EABE24293E3C1` |
| SSDEEP | `98304:A/FwkMheyeKI1AwoKQz95RM8PE768V67qIk7VdJ5szd8h5UlmYRtm:SFwI19M71K6FqVdJ5sz+HUlPRM` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_041_1501fb77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1501fb778e9ceefc0dca1f8cfe8c9fdd1738db5f6dbb0032348f3e161391d016"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:10:59"
  condition:
    hash.sha256(0, filesize) == "1501fb778e9ceefc0dca1f8cfe8c9fdd1738db5f6dbb0032348f3e161391d016"
}
```

### Sample 42: `23494415bafe76ea`

| Field | Value |
|---|---|
| SHA-256 | `23494415bafe76ea0729d47f7bbd1fb0b91aa747b0c45296713b41c1b63c24a6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 00:10:48` |
| Reporter | `Bitsight` |
| Tags | `6e7868436f4d3b49f375773379ba9022, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d241d1444068af963f3fe4bd7f8dc0c` |
| SHA-1 | `d21e1576c2e510a105df678816b7eba84909839f` |
| SHA-256 | `23494415bafe76ea0729d47f7bbd1fb0b91aa747b0c45296713b41c1b63c24a6` |
| SHA3-384 | `c95fb7be9818a9e6ec0cd6b685f474d594385c43c388ceeb3eece8b976b67f8efe0d17c02d0f0ab824e7214604a6d2e1` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1DFD5239235F649B4D43BC3B1CFA7F15DB07A3B944A628E1AF9DCA900DE22550543B3B2` |
| SSDEEP | `49152:f+Azmvcoe6mK80flwgGiiIgoJJsKPNV/RnxmPHuJViSOCEIsijHYeUkIHm8njc:fxo0K8uDGrIgKPXRxGO7iSOHADRIHBjc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_23494415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23494415bafe76ea0729d47f7bbd1fb0b91aa747b0c45296713b41c1b63c24a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:10:48"
  condition:
    hash.sha256(0, filesize) == "23494415bafe76ea0729d47f7bbd1fb0b91aa747b0c45296713b41c1b63c24a6"
}
```

### Sample 43: `441a9bd8a0f93eae`

| Field | Value |
|---|---|
| SHA-256 | `441a9bd8a0f93eae564b2e4397990f5d91479e18601ddcb5241afa7d559b4e77` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 00:10:38` |
| Reporter | `Bitsight` |
| Tags | `6e7868436f4d3b49f375773379ba9022, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8051c2c784ca3897c5f3937edd8f887a` |
| SHA-1 | `c119d46007b11ca666ccaa399492d832643cc861` |
| SHA-256 | `441a9bd8a0f93eae564b2e4397990f5d91479e18601ddcb5241afa7d559b4e77` |
| SHA3-384 | `80ba0079c2e0252a76f800d4dd580f396ec8e32fa3201319096afaaa1767c74856dda04712af149d80ea6b09a7b5407e` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T13BD5239DBCE21034F432C3F78383A1BDB12A77459BB14C4665CDAB50AC529286C7B77A` |
| SSDEEP | `49152:8SqyanGD4rv/0ElX+lrlP1msT0GvT+vYmddW807ji5bVMixoMPdW9t/vub:8yaG+v/0E+NV1msT06IZwf1ird8/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_441a9bd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "441a9bd8a0f93eae564b2e4397990f5d91479e18601ddcb5241afa7d559b4e77"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:10:38"
  condition:
    hash.sha256(0, filesize) == "441a9bd8a0f93eae564b2e4397990f5d91479e18601ddcb5241afa7d559b4e77"
}
```

### Sample 44: `6dc941968b3bc93e`

| Field | Value |
|---|---|
| SHA-256 | `6dc941968b3bc93e3f5709972f0ce23395eb65465fa23ddd68b8cb6ca52ddd0c` |
| Family label | `AgentTesla` |
| File name | `PO101-07212006.exe` |
| File type | `exe` |
| First seen | `2026-07-22 00:05:45` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d59e6476c4022f7dbb738d7207cad30` |
| SHA-1 | `38a59765e43a7ea47ee773f001742c75670a8579` |
| SHA-256 | `6dc941968b3bc93e3f5709972f0ce23395eb65465fa23ddd68b8cb6ca52ddd0c` |
| SHA3-384 | `837a20f341a7f191c8b87deaaf0c249d626c27cd30056d674b8dd60fa296c07db19710b349fff432ec335a50ab585346` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1032501541316CA82E0D68BFAB971D73536744DCFB9D2C3924FEA6FEBB8193C02454292` |
| SSDEEP | `24576:Gp50ktAhObgc1/+5B8rUdY0i+uZzMHfx33BtD3iU5:GpLWhO0q/nUdY0De0ht` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_044_6dc94196
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dc941968b3bc93e3f5709972f0ce23395eb65465fa23ddd68b8cb6ca52ddd0c"
    family = "AgentTesla"
    file_name = "PO101-07212006.exe"
    file_type = "exe"
    first_seen = "2026-07-22 00:05:45"
  condition:
    hash.sha256(0, filesize) == "6dc941968b3bc93e3f5709972f0ce23395eb65465fa23ddd68b8cb6ca52ddd0c"
}
```

### Sample 45: `6cfe4697bd8bc150`

| Field | Value |
|---|---|
| SHA-256 | `6cfe4697bd8bc1509ac9ce6db874c2f0c2dba396167f92e89953bf2c71ba002d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-22 00:04:28` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `148c0d6f40d8c3bab6429761dd04fdd2` |
| SHA-1 | `bf93fdd033e13cfcc64e7a165210ea239997dff3` |
| SHA-256 | `6cfe4697bd8bc1509ac9ce6db874c2f0c2dba396167f92e89953bf2c71ba002d` |
| SHA3-384 | `2f0d1faf7bd1a3e9e04bb0e5d67406274702a6d208dd26c06157bf7288b466d61c363bac8e587aa76221be94037322bf` |
| IMPHASH | `a4f5d0326b7d22eae00281de1ea0104e` |
| TLSH | `T10825F112B15546FCE0A7C0B4C2454AE2AA3178960F72BEFF079112262F7ABE15F3CB55` |
| SSDEEP | `24576:8PvkwoKUW+JireQ5diwzkbY6c8zHj+VLW:2vkQKwOcBW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_6cfe4697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cfe4697bd8bc1509ac9ce6db874c2f0c2dba396167f92e89953bf2c71ba002d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:04:28"
  condition:
    hash.sha256(0, filesize) == "6cfe4697bd8bc1509ac9ce6db874c2f0c2dba396167f92e89953bf2c71ba002d"
}
```

### Sample 46: `e747deb0d49a53cd`

| Field | Value |
|---|---|
| SHA-256 | `e747deb0d49a53cda8ebc02a97c5eeb875d6b5b07e1be8dfac5545adb78760f6` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Siggen33.1331.16114.201` |
| File type | `exe` |
| First seen | `2026-07-22 00:04:25` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e50e48152dc0ebb9a3b469b92db24480` |
| SHA-1 | `b83bc08928caa895748990ac65c1756d742c9519` |
| SHA-256 | `e747deb0d49a53cda8ebc02a97c5eeb875d6b5b07e1be8dfac5545adb78760f6` |
| SHA3-384 | `072dedada4a118a4b009eb067de4d3f0695f4ccebe7bcceb0036e2d8a2c5a60c0ab31575ae2827a68e080cf0d93b31e6` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T13D655A55A6A441B8E0A29578CB5EC933E7727CC60F70968F02D47DA73F33250BA297D2` |
| SSDEEP | `24576:JRSfrAEH9XIYpj0BEHBwSQJWAXPGfjuIb1iN1Eob4d:JgTbH94YxV9QI521o` |
| ICON-DHASH | `30e88ea2b2cce8b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_e747deb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e747deb0d49a53cda8ebc02a97c5eeb875d6b5b07e1be8dfac5545adb78760f6"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Siggen33.1331.16114.201"
    file_type = "exe"
    first_seen = "2026-07-22 00:04:25"
  condition:
    hash.sha256(0, filesize) == "e747deb0d49a53cda8ebc02a97c5eeb875d6b5b07e1be8dfac5545adb78760f6"
}
```

### Sample 47: `13ee006f629843e9`

| Field | Value |
|---|---|
| SHA-256 | `13ee006f629843e9d74482b9b6a5cc2a7deb7c343729e69bc92d5f10c0c1879d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-21 23:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd348ba303af14edfbf64a1ee1b67150` |
| SHA-1 | `62fe7c80aac811faf12b6c35f494ce0e3ab0a274` |
| SHA-256 | `13ee006f629843e9d74482b9b6a5cc2a7deb7c343729e69bc92d5f10c0c1879d` |
| SHA3-384 | `ea389d17d02e4a35723307d30291148d0dc22ebf34ae9dd71b898473c50671ca69911045963c51d010c2ac8af7b18008` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T18AE63318EEE001FAEAB7917CDEC181C1F96974A11772CACB4BFC92A19E971E1453C613` |
| SSDEEP | `393216:09XcFO8EziPzbn+ZhztuG2HXMCHWUjXRcuI3/PGTAI:0V98EuPzCLstXMb8XGH/O7` |
| ICON-DHASH | `5471d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_13ee006f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13ee006f629843e9d74482b9b6a5cc2a7deb7c343729e69bc92d5f10c0c1879d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 23:52:08"
  condition:
    hash.sha256(0, filesize) == "13ee006f629843e9d74482b9b6a5cc2a7deb7c343729e69bc92d5f10c0c1879d"
}
```

### Sample 48: `839ac20629dbb944`

| Field | Value |
|---|---|
| SHA-256 | `839ac20629dbb94451871be5133dded462f9452a905b276fad46e4956e974277` |
| Family label | `unknown` |
| File name | `agent_linux_amd64` |
| File type | `elf` |
| First seen | `2026-07-21 23:44:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b4749bb50c6dd126241b57dd59e6737` |
| SHA-1 | `a9ea794fdbcad021d083516af06099cee15e2bd9` |
| SHA-256 | `839ac20629dbb94451871be5133dded462f9452a905b276fad46e4956e974277` |
| SHA3-384 | `45044f27adef80d532a598ee6824c99000d380c60a85951d5274c7702f61144f3e7c5420ac5726a842d2fe94f2d2bf00` |
| TLSH | `T1FE666B03EC5965E9C0AE96308A629553BB717C491F3123D72B90F23A3F73BE069B9744` |
| TELFHASH | `t13f32467149bc76b5b6a5da10b362b4f895372c6572f878b01063e984ffc1e801ce283b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:dSjbWQs5ZsQNNk93jzPxlyCfjYqtzXFT8OJxCVfaK8IGV8ZA8yNWIV2KKlK1KcmM:dSuQUOC4rS58eEV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_839ac206
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839ac20629dbb94451871be5133dded462f9452a905b276fad46e4956e974277"
    family = "unknown"
    file_name = "agent_linux_amd64"
    file_type = "elf"
    first_seen = "2026-07-21 23:44:41"
  condition:
    hash.sha256(0, filesize) == "839ac20629dbb94451871be5133dded462f9452a905b276fad46e4956e974277"
}
```

### Sample 49: `1e6df1d48fa798f8`

| Field | Value |
|---|---|
| SHA-256 | `1e6df1d48fa798f8791b2a9473655f7bb91006c52e77f760c758850a57c8ab3a` |
| Family label | `unknown` |
| File name | `agent_windows_amd64.exe` |
| File type | `exe` |
| First seen | `2026-07-21 23:43:53` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f42db6ffdf93e601e7fd8de6087a9bc2` |
| SHA-1 | `f4dddf0fee73465efbfaf305482c9b4c1480a529` |
| SHA-256 | `1e6df1d48fa798f8791b2a9473655f7bb91006c52e77f760c758850a57c8ab3a` |
| SHA3-384 | `26fb84cb9cfd386e845c8aeaae017f70919ffe1ae79e7279c26410b835c24654d5defabc1b6328ecd47ff069c0598888` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T15B664A17FCA524E5C1ADD1308AB69653BB727C891B3123D32B90F6282F76BD0AD79350` |
| SSDEEP | `49152:eiQMUqtiuVHM8VogQ8MXiQQLhD+qBC+8hVvALe+MaPujoTpIASRrs7ZGPwL3l+Ng:eirPI4qDAWoTn7xpLtiUKnE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_1e6df1d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e6df1d48fa798f8791b2a9473655f7bb91006c52e77f760c758850a57c8ab3a"
    family = "unknown"
    file_name = "agent_windows_amd64.exe"
    file_type = "exe"
    first_seen = "2026-07-21 23:43:53"
  condition:
    hash.sha256(0, filesize) == "1e6df1d48fa798f8791b2a9473655f7bb91006c52e77f760c758850a57c8ab3a"
}
```

### Sample 50: `9c285fe3a491ee6a`

| Field | Value |
|---|---|
| SHA-256 | `9c285fe3a491ee6a6f872ae71d47dfe29e44a40b9e7fcba85a39a2368584333a` |
| Family label | `unknown` |
| File name | `agent_linux_amd64` |
| File type | `elf` |
| First seen | `2026-07-21 23:43:53` |
| Reporter | `1ZRR4H` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2c26477c7019fcfeb969c052e71b735` |
| SHA-1 | `07135c099597ecaedb84b9d8ba7e85980b887d9d` |
| SHA-256 | `9c285fe3a491ee6a6f872ae71d47dfe29e44a40b9e7fcba85a39a2368584333a` |
| SHA3-384 | `5cb88206da5fa294ca87968a485cdfcb374231410b40416b8c1949455dcf0d508d8ab339e114eb2e91c4aaf09f527714` |
| TLSH | `T17EC533F0F4D3CE21E9AD31DEFEA39AB106B5102989B39906C944526ADC35DD7C67088F` |
| SSDEEP | `49152:L9aI/YyfNnduwHOZzexbttkUyt6XNAoTelU9VVeodi93xm07/eHgUQsxkoq:UnOduwHI4ZtkY9AoCuAodcmLHgUQsxk5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_9c285fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c285fe3a491ee6a6f872ae71d47dfe29e44a40b9e7fcba85a39a2368584333a"
    family = "unknown"
    file_name = "agent_linux_amd64"
    file_type = "elf"
    first_seen = "2026-07-21 23:43:53"
  condition:
    hash.sha256(0, filesize) == "9c285fe3a491ee6a6f872ae71d47dfe29e44a40b9e7fcba85a39a2368584333a"
}
```

### Sample 51: `4ff527e0d8fc36a9`

| Field | Value |
|---|---|
| SHA-256 | `4ff527e0d8fc36a99a491bc69a9cabeb055a4be470e22ec3da8e8bb741be9efc` |
| Family label | `unknown` |
| File name | `agent_windows_amd64.exe` |
| File type | `exe` |
| First seen | `2026-07-21 23:43:29` |
| Reporter | `1ZRR4H` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84163301bc3d9ddd85644e17db5073b7` |
| SHA-1 | `6c699c8797e9cd9f5b7214ac79d1f8518141169e` |
| SHA-256 | `4ff527e0d8fc36a99a491bc69a9cabeb055a4be470e22ec3da8e8bb741be9efc` |
| SHA3-384 | `758104b4703f7ebaf5771cdbf71d447c90f650805ac7b089d8bde1c573cc7d1d39660608b1033e2062768a2ca017cbf0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12AD512B98821F087C065195BB8489D24C682A9F955057F31040B97B23FFDBDE6FFA60E` |
| SSDEEP | `49152:g4D7pqqOeyEkEJxH6t685JLRxULe8G8qGtH+rRdCaN0DOS9wue5p:g4gqOeDkEbG6CJNcFJHqdCa666ve5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_4ff527e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ff527e0d8fc36a99a491bc69a9cabeb055a4be470e22ec3da8e8bb741be9efc"
    family = "unknown"
    file_name = "agent_windows_amd64.exe"
    file_type = "exe"
    first_seen = "2026-07-21 23:43:29"
  condition:
    hash.sha256(0, filesize) == "4ff527e0d8fc36a99a491bc69a9cabeb055a4be470e22ec3da8e8bb741be9efc"
}
```

### Sample 52: `ba05cace3369229c`

| Field | Value |
|---|---|
| SHA-256 | `ba05cace3369229c81af123cce385c78295c642918327df7a14a547b158fda84` |
| Family label | `unknown` |
| File name | `1FSL` |
| File type | `elf` |
| First seen | `2026-07-21 23:29:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bdcbe64da06445fa30757aeaf63ca28` |
| SHA-1 | `f5845009fcaeac30eef4b922c13816087ecf78d4` |
| SHA-256 | `ba05cace3369229c81af123cce385c78295c642918327df7a14a547b158fda84` |
| SHA3-384 | `f911cb3ec79c9ddf496dff74adf7b159fab37fe3dc83dd2f43a29ae32ed4bf782e17aa01bbebbefcbb6d2c6e9234889a` |
| TLSH | `T13D631A7A7D819B26C1C52677FF2D4388331723B8D3EA7113DA195F6537CB82A0E2A141` |
| TELFHASH | `t141018972458d48edaaf4c28653ef62194a2df1ed37a0591fb5fc9e0e16c38d3f221904` |
| SSDEEP | `1536:hFCfDOxNmi6L61w1LAyKsYc7NPSbAb1SNy/m7hIWhfZcRZFi1URyWixF:KfDO7m/UIUo9Nu+1SE/m9IKxGZFi1URy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_ba05cace
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba05cace3369229c81af123cce385c78295c642918327df7a14a547b158fda84"
    family = "unknown"
    file_name = "1FSL"
    file_type = "elf"
    first_seen = "2026-07-21 23:29:29"
  condition:
    hash.sha256(0, filesize) == "ba05cace3369229c81af123cce385c78295c642918327df7a14a547b158fda84"
}
```

### Sample 53: `9d5db6a00c6ebf23`

| Field | Value |
|---|---|
| SHA-256 | `9d5db6a00c6ebf232c2b75d649e73b4eeb28b88d830059db3ecd041ed377ee77` |
| Family label | `unknown` |
| File name | `PrA` |
| File type | `elf` |
| First seen | `2026-07-21 23:27:44` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d508acf1b819def1189d6a651aea6383` |
| SHA-1 | `02673d2fad0f979ee459fa60647db38e6bc9a28e` |
| SHA-256 | `9d5db6a00c6ebf232c2b75d649e73b4eeb28b88d830059db3ecd041ed377ee77` |
| SHA3-384 | `64d668785a9a24c56b7447d2089cb76d4d23f630488fb3657f0a62c52fbbaf0d3fa4da29fff21cf7ef1f5af55767e7fa` |
| TLSH | `T15FA3E90AAF611DBBDC1BDD3709E80B0635CCA61B716937753538C928FA4A90B4AD3CB5` |
| SSDEEP | `1536:48xuh/R0h4XErXS60hAlbl/a+uH/8HF+EC4Wsb0tiz0Z4G1tbV8:2pW4XErXT0ilbNWU+t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_9d5db6a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d5db6a00c6ebf232c2b75d649e73b4eeb28b88d830059db3ecd041ed377ee77"
    family = "unknown"
    file_name = "PrA"
    file_type = "elf"
    first_seen = "2026-07-21 23:27:44"
  condition:
    hash.sha256(0, filesize) == "9d5db6a00c6ebf232c2b75d649e73b4eeb28b88d830059db3ecd041ed377ee77"
}
```

### Sample 54: `cd52cdfa71d79872`

| Field | Value |
|---|---|
| SHA-256 | `cd52cdfa71d798723e057c1d069edb77f4ed3e54ac7edc6e6a5a924d0567efe0` |
| Family label | `Mirai` |
| File name | `4Hep` |
| File type | `elf` |
| First seen | `2026-07-21 23:27:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b055598062b9cbfbd5f61e76e8769f64` |
| SHA-1 | `9b662c185a0e40129716a9376db56bb86ea6a1c1` |
| SHA-256 | `cd52cdfa71d798723e057c1d069edb77f4ed3e54ac7edc6e6a5a924d0567efe0` |
| SHA3-384 | `54b8efff1d4a0d9c879467eeddb03728332898e06721a58bb9a8d20c12d1d212a165f79c1fe980e53a1d70cd953bca0b` |
| TLSH | `T10783072AB9419F05D4D526BAFF1E538933536BBCE3EE7102EE141F2527CA91B0F2A501` |
| TELFHASH | `t1ba01f13506c44cdc9bd0c106e1ef152ac98ef8b93720098eb5fdef8a92a36d5b312409` |
| SSDEEP | `1536:gKnKCvaQPuYuOkY5PynmiXeShDIzLDPkENhTa9c2uZjllc2i1XrekZll:sCvaIJkOehdwDPkENhTa9chUdXrR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_cd52cdfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd52cdfa71d798723e057c1d069edb77f4ed3e54ac7edc6e6a5a924d0567efe0"
    family = "Mirai"
    file_name = "4Hep"
    file_type = "elf"
    first_seen = "2026-07-21 23:27:43"
  condition:
    hash.sha256(0, filesize) == "cd52cdfa71d798723e057c1d069edb77f4ed3e54ac7edc6e6a5a924d0567efe0"
}
```

### Sample 55: `5bcc88a01ec83f5f`

| Field | Value |
|---|---|
| SHA-256 | `5bcc88a01ec83f5fb45d0c329e6e16e8b6e74ffbb9b59d739507244604f16b53` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-21 23:10:26` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `742e2171bb80e2aeed2f74a50d018cc3` |
| SHA-1 | `99d8a43baa68071ce5a0e5977b38bd346d5a87ba` |
| SHA-256 | `5bcc88a01ec83f5fb45d0c329e6e16e8b6e74ffbb9b59d739507244604f16b53` |
| SHA3-384 | `81fca0eadcd8f93150bbfe48c01b79561669d127409b087bdbbc02bd1e2a035716c070b37c0ca9cfd252a098d6d76a37` |
| IMPHASH | `ca5fe54375b88153a623494bcd8bdfd2` |
| TLSH | `T172350147BA95947CC11AC034D30AA673EA32BC8A0631BDBF17E596703F66E512F1CB19` |
| SSDEEP | `24576:sfmr7Byb3Oghde+uNaEoJ/5rc9kPaRcpGlspXleJAYJiqFYqH:0mrtycaEoZ9cAScpyspXlezt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_5bcc88a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bcc88a01ec83f5fb45d0c329e6e16e8b6e74ffbb9b59d739507244604f16b53"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 23:10:26"
  condition:
    hash.sha256(0, filesize) == "5bcc88a01ec83f5fb45d0c329e6e16e8b6e74ffbb9b59d739507244604f16b53"
}
```

### Sample 56: `3cad6c354f21c3fc`

| Field | Value |
|---|---|
| SHA-256 | `3cad6c354f21c3fc885fdb96f6f7d45fe25e66e0ee5ac435c54ad89fab93db70` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-21 23:09:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebb0df984c97baf6273edb4ccf75a328` |
| SHA-1 | `00557793ab3ca472c000084c37508e543e8b1704` |
| SHA-256 | `3cad6c354f21c3fc885fdb96f6f7d45fe25e66e0ee5ac435c54ad89fab93db70` |
| SHA3-384 | `4ebbe0e6938586fdee3563623965c236186baaeb2c23b1a0c56b98e9e0949cb1261576cd372f72d09372b2bb8a6ad7f0` |
| TLSH | `T1BEC27D966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:f78vCB+25j6es8Rq9FYpMSUpi+20qUpi+20YQX:f78l25Jcd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_3cad6c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cad6c354f21c3fc885fdb96f6f7d45fe25e66e0ee5ac435c54ad89fab93db70"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-21 23:09:26"
  condition:
    hash.sha256(0, filesize) == "3cad6c354f21c3fc885fdb96f6f7d45fe25e66e0ee5ac435c54ad89fab93db70"
}
```

### Sample 57: `8319f644ea7e62f6`

| Field | Value |
|---|---|
| SHA-256 | `8319f644ea7e62f69665389100b0a35cd4c1a8dc8670934772271fcb33ba4576` |
| Family label | `unknown` |
| File name | `arc` |
| File type | `sh` |
| First seen | `2026-07-21 22:59:48` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c1f0b1e4f25bb9a55ec805f13cc252b` |
| SHA-1 | `f4169ae97ff7e1b6d6034c511bec50f2b5bd508e` |
| SHA-256 | `8319f644ea7e62f69665389100b0a35cd4c1a8dc8670934772271fcb33ba4576` |
| SHA3-384 | `e61732ce3228e29a8c0580b3ce727dcbcb0b5915feffeae6e112dd67346ab5144642431f5384d91fb255fc4932b901b1` |
| TLSH | `T1CD234C62F98376B03F510279DF91A9667F5B9C3B4E682B41F0866D1CA1346BCB0B24D3` |
| SSDEEP | `768:i991WnWydzUKO8EorVM/MN0NBF7Ssr6cYtNGTiPax+dFVcglW:4MnWYUKV9K7JahW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_8319f644
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8319f644ea7e62f69665389100b0a35cd4c1a8dc8670934772271fcb33ba4576"
    family = "unknown"
    file_name = "arc"
    file_type = "sh"
    first_seen = "2026-07-21 22:59:48"
  condition:
    hash.sha256(0, filesize) == "8319f644ea7e62f69665389100b0a35cd4c1a8dc8670934772271fcb33ba4576"
}
```

### Sample 58: `baa51e381015b39c`

| Field | Value |
|---|---|
| SHA-256 | `baa51e381015b39cab7df22296f3e7fa754d323d1e820524ab92f596c625b1d9` |
| Family label | `unknown` |
| File name | `co` |
| File type | `unknown` |
| First seen | `2026-07-21 22:57:57` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1eef8a1d08189f85e73745867e4f50e` |
| SHA-256 | `baa51e381015b39cab7df22296f3e7fa754d323d1e820524ab92f596c625b1d9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_baa51e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baa51e381015b39cab7df22296f3e7fa754d323d1e820524ab92f596c625b1d9"
    family = "unknown"
    file_name = "co"
    file_type = "unknown"
    first_seen = "2026-07-21 22:57:57"
  condition:
    hash.sha256(0, filesize) == "baa51e381015b39cab7df22296f3e7fa754d323d1e820524ab92f596c625b1d9"
}
```

### Sample 59: `b98a782207a2826f`

| Field | Value |
|---|---|
| SHA-256 | `b98a782207a2826f3e1482fc5c9adabd35018f96a1e01c07b072b979208a5503` |
| Family label | `unknown` |
| File name | `y` |
| File type | `sh` |
| First seen | `2026-07-21 22:56:45` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81648e86a23a25b472d5aac5278d75b5` |
| SHA-1 | `997c72f105550f0fbb93d20ae3eee015cb7875a2` |
| SHA-256 | `b98a782207a2826f3e1482fc5c9adabd35018f96a1e01c07b072b979208a5503` |
| SHA3-384 | `044da79d53b9677c41bfdd0e67d7ebabc04d5d8d495d0bd2423170e6d636abe3b695ceeaab3546d9bb7099efbfe26882` |
| TLSH | `T118235C62F98376B03F5142789F91A9667F5BDC3B4E682B41F0866D1CA1346BCB0B24D3` |
| SSDEEP | `768:i990HuydzUKO8EorVMuMN0NBF7SsA6cYtNGTiPax+dFVcglW:40HuYUKV9x7aahW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_b98a7822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98a782207a2826f3e1482fc5c9adabd35018f96a1e01c07b072b979208a5503"
    family = "unknown"
    file_name = "y"
    file_type = "sh"
    first_seen = "2026-07-21 22:56:45"
  condition:
    hash.sha256(0, filesize) == "b98a782207a2826f3e1482fc5c9adabd35018f96a1e01c07b072b979208a5503"
}
```

### Sample 60: `bfca8d582b0e2436`

| Field | Value |
|---|---|
| SHA-256 | `bfca8d582b0e243642dbb6f9cd945fc4f2c60d33e17062e8438c7820ac1372fa` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-21 22:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85a032fedb8609b1bdc827115a5f5804` |
| SHA-1 | `b1019c19f9bf41b61abaa63c56089f76a8ce8884` |
| SHA-256 | `bfca8d582b0e243642dbb6f9cd945fc4f2c60d33e17062e8438c7820ac1372fa` |
| SHA3-384 | `739726f74d501b80e7da86e6fefec750cf5173df1ef5207b0f09ad7ba855832f33e5f7d7fc113567dd837f39aec6555d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T178E6331D66F002EEFAB3403CB9E25555E22AB8665771C6E7837887615E4B3F4483E323` |
| SSDEEP | `393216:xSaRocDpGBZh4OHHcDxdaXMCHWUjXIcuI3/PGTAI:xSyoceh2DxUXMb8X9H/O7` |
| ICON-DHASH | `30f8fcdccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_bfca8d58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfca8d582b0e243642dbb6f9cd945fc4f2c60d33e17062e8438c7820ac1372fa"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 22:52:09"
  condition:
    hash.sha256(0, filesize) == "bfca8d582b0e243642dbb6f9cd945fc4f2c60d33e17062e8438c7820ac1372fa"
}
```

### Sample 61: `0f09c681e525e89b`

| Field | Value |
|---|---|
| SHA-256 | `0f09c681e525e89b72c1a714c6cb52702aea52aa0db6217ea7a6886b3bf45894` |
| Family label | `unknown` |
| File name | `tvCr` |
| File type | `elf` |
| First seen | `2026-07-21 22:42:26` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8060d80e528f962a6411316941b7dde` |
| SHA-1 | `ef7ea56dcb3ec85dc738d6aa395d9d7820e7a8f7` |
| SHA-256 | `0f09c681e525e89b72c1a714c6cb52702aea52aa0db6217ea7a6886b3bf45894` |
| SHA3-384 | `bdf8e3755bf5fd1c203806b98d0ec7ae50c90d8bd239b34023bc70dae10a5f780da2cbb0b4ca410ecd546786d7a57e58` |
| TLSH | `T1ED631975B8819F56C1D52677FF1D8388331723B8E3EA7113EA196F6137CB92A0E2A141` |
| TELFHASH | `t1cde06873074619dc5fc0c09681ee3a584b1df0322701194ec2fc9d0434e3886fa01c08` |
| SSDEEP | `1536:YVbe7DuaBQNy3biqPCbmeT1yCn3yBYcHZWyRZceWU7Fa1UbLOip:Y1CDu4ZTOm81yCn3gYcHZB7pL7Fa1Ub6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_0f09c681
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f09c681e525e89b72c1a714c6cb52702aea52aa0db6217ea7a6886b3bf45894"
    family = "unknown"
    file_name = "tvCr"
    file_type = "elf"
    first_seen = "2026-07-21 22:42:26"
  condition:
    hash.sha256(0, filesize) == "0f09c681e525e89b72c1a714c6cb52702aea52aa0db6217ea7a6886b3bf45894"
}
```

### Sample 62: `bc56faa396b8b6f6`

| Field | Value |
|---|---|
| SHA-256 | `bc56faa396b8b6f6487e925a19c3cfa0a1daeaa36e774615db56a7664fa7ad4d` |
| Family label | `Mirai` |
| File name | `xWr` |
| File type | `elf` |
| First seen | `2026-07-21 22:42:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45aea77d76cf4f6424b39576de98d6ed` |
| SHA-1 | `913c4d9c15123a189e6a7107c59198f2c429cb96` |
| SHA-256 | `bc56faa396b8b6f6487e925a19c3cfa0a1daeaa36e774615db56a7664fa7ad4d` |
| SHA3-384 | `8f816ac763c9b7faa6102c8d37bcbb332be7337cac4b27b1ba9b60f5ab7728acf6228e5d991fd6781f67daa77c75c4d0` |
| TLSH | `T1A983086ABD419F05D4D526BAFF1E9289335357BCE3EE7102DE142B2527CAA1B0F3A401` |
| TELFHASH | `t16ee061b64a4185fc93e44559d05f711a430ce052051045d8bafc5e1fd173886760e40a` |
| SSDEEP | `1536:+knXPQEE2PvaYUIlkvkCWd3cbqDdGgbOHB2Nk6z8VTuC5llGviHe1PkZdz:95EwvNgy0ClbOHB2Nk6z8V1AWe1kd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_bc56faa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc56faa396b8b6f6487e925a19c3cfa0a1daeaa36e774615db56a7664fa7ad4d"
    family = "Mirai"
    file_name = "xWr"
    file_type = "elf"
    first_seen = "2026-07-21 22:42:25"
  condition:
    hash.sha256(0, filesize) == "bc56faa396b8b6f6487e925a19c3cfa0a1daeaa36e774615db56a7664fa7ad4d"
}
```

### Sample 63: `62e51ed3f589dc44`

| Field | Value |
|---|---|
| SHA-256 | `62e51ed3f589dc4463b830e736a7c161e33af159fe79a338affb20caaf548735` |
| Family label | `Mirai` |
| File name | `6zq` |
| File type | `elf` |
| First seen | `2026-07-21 22:42:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccae8419704f93b631f7f3db0d0e5d58` |
| SHA-1 | `6bcd0b92ab7afdc79d7cd8dd9def63530e2d1e03` |
| SHA-256 | `62e51ed3f589dc4463b830e736a7c161e33af159fe79a338affb20caaf548735` |
| SHA3-384 | `fbeec72dbedd5d03f42b56d5ce8ed7e4441679be97d4bc88ac04c66ce6861aa8a65d504c075cfc45ce9d93af1fd13db6` |
| TLSH | `T1EBA3E80AAF611DBBD81BDC3305AC0B0278CCA61771643B797538D528BB8A54F8AD3CB5` |
| SSDEEP | `1536:AiB3QerROySqoXT6sqQA7yZKoubeyKioFbx6oa0fvxugBE1UQyVp:L91OySqoXmXn7IEbepxM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_62e51ed3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62e51ed3f589dc4463b830e736a7c161e33af159fe79a338affb20caaf548735"
    family = "Mirai"
    file_name = "6zq"
    file_type = "elf"
    first_seen = "2026-07-21 22:42:24"
  condition:
    hash.sha256(0, filesize) == "62e51ed3f589dc4463b830e736a7c161e33af159fe79a338affb20caaf548735"
}
```

### Sample 64: `a9ff4fbde5bb2798`

| Field | Value |
|---|---|
| SHA-256 | `a9ff4fbde5bb27981136ca2902000af76636fa327fdfcae50f3de411cbb9f5e1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-21 22:40:34` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17b4bda9f4dcec2f5e698776e7e4b9e1` |
| SHA-1 | `46d50c56d58b714f4bbc65b8aa43ddf9636c2262` |
| SHA-256 | `a9ff4fbde5bb27981136ca2902000af76636fa327fdfcae50f3de411cbb9f5e1` |
| SHA3-384 | `370b1e638a6aff30d6426c39e4f59ce919e8c852645598fe8f0b5c4823651a5b91dfb335edd5bfa118a1599457668bb6` |
| TLSH | `T188F30EE06746C435D4AF99B9C4BBA6A7A833A21F9C18450D2CD2FF4B7D323464417CAB` |
| SSDEEP | `3072:yELIb0+wW1a++9bx7UM+lmsolAIrRuw+mqv9j1MWLQ5:yEL0hwW1u9bt+lDAA` |
| ICON-DHASH | `6cecccccb4c2f2b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_a9ff4fbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9ff4fbde5bb27981136ca2902000af76636fa327fdfcae50f3de411cbb9f5e1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 22:40:34"
  condition:
    hash.sha256(0, filesize) == "a9ff4fbde5bb27981136ca2902000af76636fa327fdfcae50f3de411cbb9f5e1"
}
```

### Sample 65: `d8ee53ef0d913418`

| Field | Value |
|---|---|
| SHA-256 | `d8ee53ef0d9134184542e57c74109a45047a6de148226e73b8f6579a1f09a2e6` |
| Family label | `unknown` |
| File name | `svc.exe` |
| File type | `exe` |
| First seen | `2026-07-21 22:37:49` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efb65064775fba878366ee1cc9749c67` |
| SHA-1 | `046b89b190420bae3a3a323c5d5507b078220b7e` |
| SHA-256 | `d8ee53ef0d9134184542e57c74109a45047a6de148226e73b8f6579a1f09a2e6` |
| SHA3-384 | `ff7f016e63c588cfaa766985e696a57e4aeb324c27d73cade0d0c5cd2ff271f97bf3fbe1e99d47eec06e44d87afd8f6a` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T1C6E6AE01F3F842A9E5BFC278C5625517EBB278491720EBDF055489A92F33BD09E39362` |
| SSDEEP | `196608:7dvIyQs3CY9eO8OwcPFGUec4Ifzl7vlf4mAswlYQP:7drz7whr9ILxvlfz0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_d8ee53ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8ee53ef0d9134184542e57c74109a45047a6de148226e73b8f6579a1f09a2e6"
    family = "unknown"
    file_name = "svc.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:37:49"
  condition:
    hash.sha256(0, filesize) == "d8ee53ef0d9134184542e57c74109a45047a6de148226e73b8f6579a1f09a2e6"
}
```

### Sample 66: `8b50f23c7f095752`

| Field | Value |
|---|---|
| SHA-256 | `8b50f23c7f09575224f6ff713d72b67382103f24d5c6e91ab2c74c556b729185` |
| Family label | `unknown` |
| File name | `main.exe` |
| File type | `exe` |
| First seen | `2026-07-21 22:35:48` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b09b63589e5c0cc81394b1b54819de9c` |
| SHA-1 | `6ccd0538e005c563d4b5b480c16f60dab29acb35` |
| SHA-256 | `8b50f23c7f09575224f6ff713d72b67382103f24d5c6e91ab2c74c556b729185` |
| SHA3-384 | `6d152005cd17cabd4dd178dd667033950b88c3e8179aa35fb0e7c1cbfc31147f9c164efdb9afe1f0f446c3d3e7037197` |
| IMPHASH | `351592d5ead6df0859b0cc0056827c95` |
| TLSH | `T10496339993A408AAD877A53F5D25D063D371B8224760D8CF1BE4872B3F572EA3C3A354` |
| SSDEEP | `196608:TQpoYtbW897GXPHMe81SF2RPUewytKZ22HsMRqabRgFeDU2:I11wPsZg2Ke3K42HsMRqabYew2` |
| ICON-DHASH | `aebc385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_8b50f23c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b50f23c7f09575224f6ff713d72b67382103f24d5c6e91ab2c74c556b729185"
    family = "unknown"
    file_name = "main.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:35:48"
  condition:
    hash.sha256(0, filesize) == "8b50f23c7f09575224f6ff713d72b67382103f24d5c6e91ab2c74c556b729185"
}
```

### Sample 67: `bbdb4e10ba2e085d`

| Field | Value |
|---|---|
| SHA-256 | `bbdb4e10ba2e085d83eeb97b10efc6f446cf040cfd10deb0ee48c375f4805953` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-07-21 22:35:46` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `702503357d409579fe658b1a518d93a2` |
| SHA-1 | `3d4a32be0683889cb04ac6b4bcd979da84f34115` |
| SHA-256 | `bbdb4e10ba2e085d83eeb97b10efc6f446cf040cfd10deb0ee48c375f4805953` |
| SHA3-384 | `bf057505cc5a8932bbbcf4ac1f32f732bb6d72cb6a2a49890ce63d9251d2fa58de94f1299a3df95af0fe4c555a947656` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T164C61211B3E585B5E0BF0A38D87A86562A34BC049716C6BF57A4BD292D32FC09E31377` |
| SSDEEP | `196608:c1EfefPkBKaLNkbgMi4QWKaLNkbgRKaLNkbgBKaLNkbgv:c+WgMiH4Wg1WglWgv` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_067_bbdb4e10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbdb4e10ba2e085d83eeb97b10efc6f446cf040cfd10deb0ee48c375f4805953"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:35:46"
  condition:
    hash.sha256(0, filesize) == "bbdb4e10ba2e085d83eeb97b10efc6f446cf040cfd10deb0ee48c375f4805953"
}
```

### Sample 68: `bd9324f4a2f381a9`

| Field | Value |
|---|---|
| SHA-256 | `bd9324f4a2f381a9f17cea58e0bb4a43d56ae55478cea07854440d07cd7e1102` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-21 22:35:23` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcfe67b91d19cafd0b65697a58c4218f` |
| SHA-1 | `6147841e8450f185a64d1fdef515293f3e327e7a` |
| SHA-256 | `bd9324f4a2f381a9f17cea58e0bb4a43d56ae55478cea07854440d07cd7e1102` |
| SHA3-384 | `8d4e5a5abbb3582734e83171f2c882153d00e294937ad3d3d9a4cc6966a51c9a2948b4a4f52201df44c39915b196b182` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BB0410E06742C425D4AF9679D477A6A7A833A21F9C18850D2CD2FF5B3D32347841BCAB` |
| SSDEEP | `3072:TWDGYPbtpBjsi8h9b2kfjF7iM+lmsolAIrRuw+mqv9j1MWLQb:TWVPbHWL9bF3+lDAA` |
| ICON-DHASH | `6cecccccb4c2f2b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_bd9324f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd9324f4a2f381a9f17cea58e0bb4a43d56ae55478cea07854440d07cd7e1102"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 22:35:23"
  condition:
    hash.sha256(0, filesize) == "bd9324f4a2f381a9f17cea58e0bb4a43d56ae55478cea07854440d07cd7e1102"
}
```

### Sample 69: `b7b1d0186b23713f`

| Field | Value |
|---|---|
| SHA-256 | `b7b1d0186b23713f11d0872ace4c43c109120c0c99f0b1f98051c546a1016d13` |
| Family label | `Mirai` |
| File name | `tTd` |
| File type | `elf` |
| First seen | `2026-07-21 22:30:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75a7ad802a9be80c2963e0449789ef19` |
| SHA-1 | `7fbeb4f71568941e77cdd412b2e2b04a6fa5266a` |
| SHA-256 | `b7b1d0186b23713f11d0872ace4c43c109120c0c99f0b1f98051c546a1016d13` |
| SHA3-384 | `1060cbb457b737cb2d74b5ead0d3422eee8f4f280218189248b6e32b57dc49546d168b37e8cdcdfddf65ff6aad70e7b4` |
| TLSH | `T18583091ABD419F05D4D526BAFF1E538933535BBCE3EEB102EE141F25278A95B0F2A401` |
| TELFHASH | `t1ba01f13506c44cdc9bd0c106e1ef152ac98ef8b93720098eb5fdef8a92a36d5b312409` |
| SSDEEP | `1536:xfnZma+3aYubkQ5PynmWXeWhDIzLyPlkNdfupg7uiDll5niimuHkZkPeM:jmaCMkGK9dwyPlkNdfupgNxbmusQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_b7b1d018
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7b1d0186b23713f11d0872ace4c43c109120c0c99f0b1f98051c546a1016d13"
    family = "Mirai"
    file_name = "tTd"
    file_type = "elf"
    first_seen = "2026-07-21 22:30:23"
  condition:
    hash.sha256(0, filesize) == "b7b1d0186b23713f11d0872ace4c43c109120c0c99f0b1f98051c546a1016d13"
}
```

### Sample 70: `053f32ed6a86050a`

| Field | Value |
|---|---|
| SHA-256 | `053f32ed6a86050a782b96a51e4194287fa9e7985b992f32a69aa06ee562f929` |
| Family label | `unknown` |
| File name | `dNPT` |
| File type | `elf` |
| First seen | `2026-07-21 22:28:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4512b6167da0f15c08dc7528814df840` |
| SHA-1 | `047cfea5ef681a799b62e60a2995d75bd85b0eac` |
| SHA-256 | `053f32ed6a86050a782b96a51e4194287fa9e7985b992f32a69aa06ee562f929` |
| SHA3-384 | `1e219d080ded0311a55891b6c498029dcd6fde3e517fe133d83fc2964a82b4cd1702b061a22e149eca243eadd74a543e` |
| TLSH | `T16863197ABD819F16C5C52677FF1D8389331723A8E3EA7113EA152F6537CB82A0D2A141` |
| TELFHASH | `t141018972458d48edaaf4c28653ef62194a2df1ed37a0591fb5fc9e0e16c38d3f221904` |
| SSDEEP | `1536:KfrOjmOWL3w13AyKsYBgNPSbAb1S6R/W76cWNQZcytFZ1Uyl/PSFZ:KfrOjm33IwoxNu+1S6/WGcWi1tFZ1UyA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_053f32ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "053f32ed6a86050a782b96a51e4194287fa9e7985b992f32a69aa06ee562f929"
    family = "unknown"
    file_name = "dNPT"
    file_type = "elf"
    first_seen = "2026-07-21 22:28:51"
  condition:
    hash.sha256(0, filesize) == "053f32ed6a86050a782b96a51e4194287fa9e7985b992f32a69aa06ee562f929"
}
```

### Sample 71: `a4a4f6bb57b72bb6`

| Field | Value |
|---|---|
| SHA-256 | `a4a4f6bb57b72bb64de6a93b8de5a114f265f2802c046695595355353e1509a5` |
| Family label | `Mirai` |
| File name | `Wznp` |
| File type | `elf` |
| First seen | `2026-07-21 22:28:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3a11aa9f8ea13d27b246370bf7aefe0` |
| SHA-1 | `05927fc89de0af9401fc3e00c7a5b5697cb19cf5` |
| SHA-256 | `a4a4f6bb57b72bb64de6a93b8de5a114f265f2802c046695595355353e1509a5` |
| SHA3-384 | `0940c51b3278715173a34bb83eadff3bbd6ab87d8298556d91fe7bd97034e8e47318f9e4117e0ef85d76cd04ec7487d2` |
| TLSH | `T1B8A3E90AAF611EBFD81BDD3705AC0B0234CCA61771693B793638D528BB4654B8AD3CB5` |
| SSDEEP | `1536:/sQxwvYLFBWZX/6/hAlVAuqauDJREI+mOJm0TqVGgjzxz8PkLc+t:z04FBWZXC/ilVtiLlVJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_a4a4f6bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4a4f6bb57b72bb64de6a93b8de5a114f265f2802c046695595355353e1509a5"
    family = "Mirai"
    file_name = "Wznp"
    file_type = "elf"
    first_seen = "2026-07-21 22:28:49"
  condition:
    hash.sha256(0, filesize) == "a4a4f6bb57b72bb64de6a93b8de5a114f265f2802c046695595355353e1509a5"
}
```

### Sample 72: `310fcb28fd0a6616`

| Field | Value |
|---|---|
| SHA-256 | `310fcb28fd0a6616bea7db2a16414117507e449e0d7c27bf5fb1651b0e13ba7b` |
| Family label | `ValleyRAT` |
| File name | `310fcb28fd0a6616bea7db2a16414117507e449e0d7c2.dll` |
| File type | `exe` |
| First seen | `2026-07-21 22:25:21` |
| Reporter | `abuse_ch` |
| Tags | `dll, exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de7490e3bc31ad29ece7a3e275588d18` |
| SHA-1 | `31ec4759a1e9fa2714eab2772a607fe36356fb7a` |
| SHA-256 | `310fcb28fd0a6616bea7db2a16414117507e449e0d7c27bf5fb1651b0e13ba7b` |
| SHA3-384 | `6992f7dbbdb269f7f028f426a9003e5bf6b9756a8f8544f2f65d6d9bd33a06642470381018e3291900f349babd1dd49f` |
| IMPHASH | `8e2d33ccc73ed51abd14b6951ffbefa6` |
| TLSH | `T15C348C15B7A50CBAEDB78539C9530906DA737C4247A0EADF03900AA6DF2F7E0963E711` |
| SSDEEP | `3072:IjLFXq1GEfQw1ZWafRk0r+Ki/qs/ZFVIK5TTdp5nAzCgTXgKTgtuRghqSt:nfQw1ZWaJkp5i0nDTygogqS` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_072_310fcb28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310fcb28fd0a6616bea7db2a16414117507e449e0d7c27bf5fb1651b0e13ba7b"
    family = "ValleyRAT"
    file_name = "310fcb28fd0a6616bea7db2a16414117507e449e0d7c2.dll"
    file_type = "exe"
    first_seen = "2026-07-21 22:25:21"
  condition:
    hash.sha256(0, filesize) == "310fcb28fd0a6616bea7db2a16414117507e449e0d7c27bf5fb1651b0e13ba7b"
}
```

### Sample 73: `9236af4b0d79c2cd`

| Field | Value |
|---|---|
| SHA-256 | `9236af4b0d79c2cd99e098b7e599106d85f377af7f2cab91e2cf733bfaeea43b` |
| Family label | `N-W0rm` |
| File name | `9236af4b0d79c2cd99e098b7e599106d85f377af7f2ca.exe` |
| File type | `exe` |
| First seen | `2026-07-21 22:25:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, N-W0rm, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `895c99e22e6da193dcdc7b895f53217b` |
| SHA-1 | `65a887df163d492e207378e28962c059d5f075ee` |
| SHA-256 | `9236af4b0d79c2cd99e098b7e599106d85f377af7f2cab91e2cf733bfaeea43b` |
| SHA3-384 | `b3565156e46c3a62eccff13c1cd2ee3b97365cfc8158ce2fe3fd317417c14162aa09a1901d84cf2e1573c55a33a13944` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1AD66223FB28B653EE17E5A367AB2E110583B766165124C1696F0C88CCF164B02E3F797` |
| SSDEEP | `98304:z5Od2hNc2L7LiQhKlSmHQKzwpmwPFfdMA/Ky/4ZwD8GD95nXXgnov1M9tTG7rkQY:NlXKz5HPzwpmaPwZwFZ9tv1eWoQZNo` |
| ICON-DHASH | `33b270f0f0f0e0e4` |

#### Technical Assessment

- The sample is tracked as `N-W0rm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_N_W0rm_073_9236af4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9236af4b0d79c2cd99e098b7e599106d85f377af7f2cab91e2cf733bfaeea43b"
    family = "N-W0rm"
    file_name = "9236af4b0d79c2cd99e098b7e599106d85f377af7f2ca.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:25:17"
  condition:
    hash.sha256(0, filesize) == "9236af4b0d79c2cd99e098b7e599106d85f377af7f2cab91e2cf733bfaeea43b"
}
```

### Sample 74: `ad5a8f0a70678395`

| Field | Value |
|---|---|
| SHA-256 | `ad5a8f0a70678395eee394dbe48b2508784e06f37e7a980f4bd61599d180360d` |
| Family label | `DCRat` |
| File name | `22ce9b4f200c32eeb293116301e97307.exe` |
| File type | `exe` |
| First seen | `2026-07-21 22:25:14` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22ce9b4f200c32eeb293116301e97307` |
| SHA-1 | `7c68c908dddecfa9ad6b4096f81127d46f1ca0d3` |
| SHA-256 | `ad5a8f0a70678395eee394dbe48b2508784e06f37e7a980f4bd61599d180360d` |
| SHA3-384 | `77acef358518b6306656f99faa4374ab9e4f2425583215567eceb738b7f0cf28907e854f3b93f0d3e291b1736e02e5e8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19FD5DF017E46CA01F4191633C2EF855847B1A9516AE6F32BBDBE336D95223973C0E9CB` |
| SSDEEP | `49152:KYWPh3V0cH0kRHPcEsz/gw3inptdNuW9xLWiYkIX+RPKYwwMz:KTV8APRg/byptdPWcIORPZwX` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_074_ad5a8f0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad5a8f0a70678395eee394dbe48b2508784e06f37e7a980f4bd61599d180360d"
    family = "DCRat"
    file_name = "22ce9b4f200c32eeb293116301e97307.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:25:14"
  condition:
    hash.sha256(0, filesize) == "ad5a8f0a70678395eee394dbe48b2508784e06f37e7a980f4bd61599d180360d"
}
```

### Sample 75: `67a7464500fdeba2`

| Field | Value |
|---|---|
| SHA-256 | `67a7464500fdeba256b9f596b6308d0a84f91e7b2ac0b7f8192ce07c2804e874` |
| Family label | `unknown` |
| File name | `PO#8700983.vbs` |
| File type | `unknown` |
| First seen | `2026-07-21 22:25:11` |
| Reporter | `abuse_ch` |
| Tags | `RAT, RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae869be240b705d75b4e64123d22517f` |
| SHA-256 | `67a7464500fdeba256b9f596b6308d0a84f91e7b2ac0b7f8192ce07c2804e874` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_67a74645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67a7464500fdeba256b9f596b6308d0a84f91e7b2ac0b7f8192ce07c2804e874"
    family = "unknown"
    file_name = "PO#8700983.vbs"
    file_type = "unknown"
    first_seen = "2026-07-21 22:25:11"
  condition:
    hash.sha256(0, filesize) == "67a7464500fdeba256b9f596b6308d0a84f91e7b2ac0b7f8192ce07c2804e874"
}
```

### Sample 76: `18d22205fc172fcb`

| Field | Value |
|---|---|
| SHA-256 | `18d22205fc172fcb534505791d7b6ddb08d58fa31063be642e9fafb415ba3891` |
| Family label | `Adwind` |
| File name | `QUOTATION #POPO996574620775800000.pdf.jar` |
| File type | `jar` |
| First seen | `2026-07-21 22:25:07` |
| Reporter | `abuse_ch` |
| Tags | `Adwind, jar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8103660c25c02cc557ddd355f83cc432` |
| SHA-1 | `4ce114be49a9a3f55895389efd318f6c136425ff` |
| SHA-256 | `18d22205fc172fcb534505791d7b6ddb08d58fa31063be642e9fafb415ba3891` |
| SHA3-384 | `62089bc3ebde5104a64145099f4d2080ba09b6e9032ef0332f34ef2fe5bf1ed32790c72eb844f3d827b905c39ebb7f9a` |
| TLSH | `T199B423761238D7A47613FDCE96595F302B63F91C6F8D222D65C61CF153A8388AD2223B` |
| SSDEEP | `12288:oZ4MC20jN8+EAHRdYwCFH/I3n9uGdWSuCMILMm02PzQgJBDggCYVRUv:Ku3hBHH7CJI39Hd2CdYm02PUYBD5NrI` |

#### Technical Assessment

- The sample is tracked as `Adwind` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adwind_076_18d22205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18d22205fc172fcb534505791d7b6ddb08d58fa31063be642e9fafb415ba3891"
    family = "Adwind"
    file_name = "QUOTATION #POPO996574620775800000.pdf.jar"
    file_type = "jar"
    first_seen = "2026-07-21 22:25:07"
  condition:
    hash.sha256(0, filesize) == "18d22205fc172fcb534505791d7b6ddb08d58fa31063be642e9fafb415ba3891"
}
```

### Sample 77: `5fd493615b731c76`

| Field | Value |
|---|---|
| SHA-256 | `5fd493615b731c767be670d33a4e48ec89ad264bf583c2b087d7645a4727986b` |
| Family label | `AsyncRAT` |
| File name | `47E1B3A9FE7BD09242ACBCBD0D515DED.exe` |
| File type | `exe` |
| First seen | `2026-07-21 22:25:05` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47e1b3a9fe7bd09242acbcbd0d515ded` |
| SHA-1 | `311cad9a898b4f64dfdeae1c5128fb81f2fb34cc` |
| SHA-256 | `5fd493615b731c767be670d33a4e48ec89ad264bf583c2b087d7645a4727986b` |
| SHA3-384 | `95a87d71caa76af3f2018f351498fec7450e532d77d7ba403822bacc36b486963d96a673be69194c71cfbcb4adff3963` |
| IMPHASH | `86c440bbb7b36db9c31512e18ca8b5b6` |
| TLSH | `T1C7C3E12D13A3A9F6C243C8348AE748F0BD71F8255B20997D1750DD312E16E316F997AB` |
| SSDEEP | `3072:wFGj7BWSYC/u2S1frUxLoFnFeplfdMtJbbBkCSV:wFMHYJ1AxfytJb6NV` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_077_5fd49361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fd493615b731c767be670d33a4e48ec89ad264bf583c2b087d7645a4727986b"
    family = "AsyncRAT"
    file_name = "47E1B3A9FE7BD09242ACBCBD0D515DED.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:25:05"
  condition:
    hash.sha256(0, filesize) == "5fd493615b731c767be670d33a4e48ec89ad264bf583c2b087d7645a4727986b"
}
```

### Sample 78: `ee5c5c69bb1c0d96`

| Field | Value |
|---|---|
| SHA-256 | `ee5c5c69bb1c0d961dff49dd3bcfcef923406e1c2d80b662b76c611cd6fb94a3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-21 22:04:53` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a669f1310368bf8fa9478ede9632a9f` |
| SHA-1 | `aefe7a849a853eaff1979268d64864ff85eabfff` |
| SHA-256 | `ee5c5c69bb1c0d961dff49dd3bcfcef923406e1c2d80b662b76c611cd6fb94a3` |
| SHA3-384 | `ad6c6ae13d5c43a98c734fe05588e5cf37d67ee0773c22f72eaad717d89ace8cb45a09bf3c70faaa452ed37db2c38340` |
| IMPHASH | `69d04b283251e75ebf7bdd628fba938f` |
| TLSH | `T195068E03E2A250ECC12BC17D8A579672B631B82DC534FE7B9694DF311E31F509A6EB24` |
| SSDEEP | `98304:n1DLMVtjANF8oC4xEyrTVhm8bILHGWCv5IjjPmgDfwR:n1XUWXC4xEUegv5IjjPmgDfi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_ee5c5c69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee5c5c69bb1c0d961dff49dd3bcfcef923406e1c2d80b662b76c611cd6fb94a3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 22:04:53"
  condition:
    hash.sha256(0, filesize) == "ee5c5c69bb1c0d961dff49dd3bcfcef923406e1c2d80b662b76c611cd6fb94a3"
}
```

### Sample 79: `243a16f7868aaac2`

| Field | Value |
|---|---|
| SHA-256 | `243a16f7868aaac29db90690c5315a94e850b5e150dddc72814a2c064155324d` |
| Family label | `unknown` |
| File name | `23N` |
| File type | `elf` |
| First seen | `2026-07-21 21:56:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4298f1dd49ab388a5e94e931abcca293` |
| SHA-1 | `24542922b0144eb22bdadf4c8c15a31761b1fd45` |
| SHA-256 | `243a16f7868aaac29db90690c5315a94e850b5e150dddc72814a2c064155324d` |
| SHA3-384 | `c10af0e42c5e3ca7c62a63a9d8e8c058128abc3d4ee3d256f85756b5a6d86e1649450b1d9d6857ef8f0e5a68d4a5a0c7` |
| TLSH | `T1CF631979B9819F1AC1C51677FF2D4388331723B8E3EA7113EA156F6137CB82A0E2A545` |
| TELFHASH | `t141018972458d48edaaf4c28653ef62194a2df1ed37a0591fb5fc9e0e16c38d3f221904` |
| SSDEEP | `1536:efDOLmOmLuw1vAyKsYFMNPSbAb1SOE/S77cWGMZcu1FS1UvnwayF:efDOLmXuIIoJNu+1SL/Svc1e51FS1Uv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_243a16f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "243a16f7868aaac29db90690c5315a94e850b5e150dddc72814a2c064155324d"
    family = "unknown"
    file_name = "23N"
    file_type = "elf"
    first_seen = "2026-07-21 21:56:40"
  condition:
    hash.sha256(0, filesize) == "243a16f7868aaac29db90690c5315a94e850b5e150dddc72814a2c064155324d"
}
```

### Sample 80: `96d70bdb60493448`

| Field | Value |
|---|---|
| SHA-256 | `96d70bdb604934486925179ec1113832e0492b8fc5048f4f1e0b3c30ea2891f6` |
| Family label | `Mirai` |
| File name | `Chfd` |
| File type | `elf` |
| First seen | `2026-07-21 21:56:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `797ec97c7e2d568cf24c012fe9660b0b` |
| SHA-1 | `a6da87865bfcd8ac7b358305adb87119524cc09e` |
| SHA-256 | `96d70bdb604934486925179ec1113832e0492b8fc5048f4f1e0b3c30ea2891f6` |
| SHA3-384 | `8126d63cb2fb973e8a4f4dc73dec667e2b37df9ace670fd606d86746f9c75c2e84de0955441fc74d5912a6b3f939ac6d` |
| TLSH | `T15C83092ABD409F05D4D526BAFF1E434933535BBCE3EEB112EE141B25278A92B0F3A505` |
| TELFHASH | `t1ba01f13506c44cdc9bd0c106e1ef152ac98ef8b93720098eb5fdef8a92a36d5b312409` |
| SSDEEP | `1536:hDn4Qa8T2Yu0kE5PynmXXe3hDIzLAP6FNIOvgRzuqTllG7iDN6akZ9a+:6Qa4jkaVcdwAP6FNIOvgR1OWN6N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_96d70bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96d70bdb604934486925179ec1113832e0492b8fc5048f4f1e0b3c30ea2891f6"
    family = "Mirai"
    file_name = "Chfd"
    file_type = "elf"
    first_seen = "2026-07-21 21:56:39"
  condition:
    hash.sha256(0, filesize) == "96d70bdb604934486925179ec1113832e0492b8fc5048f4f1e0b3c30ea2891f6"
}
```

### Sample 81: `e55977d62b523894`

| Field | Value |
|---|---|
| SHA-256 | `e55977d62b523894693b08e9a9113f777f3667ccb05d8c17f1fde6b46b46d959` |
| Family label | `Mirai` |
| File name | `oDh` |
| File type | `elf` |
| First seen | `2026-07-21 21:55:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c45937d5493547ec8bd429cfc7175a3` |
| SHA-1 | `de348750ce64104bff7a73b626bdd93cf4b1ddd7` |
| SHA-256 | `e55977d62b523894693b08e9a9113f777f3667ccb05d8c17f1fde6b46b46d959` |
| SHA3-384 | `70845068fb2e7f19319c91e467c4eb628c626024543dbf4da475c0a04f5221ba252dd43602b7a314d730771c310d788c` |
| TLSH | `T1C5A3E90AAF611DBBD81BDD3705BC070234CCA617716837793678D528BB8A54B8AE3CB5` |
| SSDEEP | `1536:6NZ8nh7M7He34Xf6SvAz8mjqauqKcU5orvvtQ0IfVigjWUdgUa8kG:hhkHe34XiSIz8aiSUHVu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_e55977d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e55977d62b523894693b08e9a9113f777f3667ccb05d8c17f1fde6b46b46d959"
    family = "Mirai"
    file_name = "oDh"
    file_type = "elf"
    first_seen = "2026-07-21 21:55:19"
  condition:
    hash.sha256(0, filesize) == "e55977d62b523894693b08e9a9113f777f3667ccb05d8c17f1fde6b46b46d959"
}
```

### Sample 82: `b32527764b33b758`

| Field | Value |
|---|---|
| SHA-256 | `b32527764b33b7584ab9466b5c34efe0e4c24daf2e19e792ce2bca59bd3bc4f1` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-21 21:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96d9b2e24488bf537a17b488e4aadc19` |
| SHA-1 | `65cd9bfca4f1326afa72ea4051cc72f9b8395ae1` |
| SHA-256 | `b32527764b33b7584ab9466b5c34efe0e4c24daf2e19e792ce2bca59bd3bc4f1` |
| SHA3-384 | `aa10537804c0c469af3ff0e85101699daa56d6da060d7cbb6576333ca5aff92bb193678a39cc5ae3fdda492ce6051f05` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T189E63348E5E002FEDAB361BC9EF25654E42178B41B32C6CF576496A66E531D0DC3CB23` |
| SSDEEP | `393216:O7K0QlrVggBivhgtl/9hXMCHWUjX4cuI3/PGTAI:O7KlrVJtl1hXMb8XNH/O7` |
| ICON-DHASH | `71f0f8d8f8e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_b3252776
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b32527764b33b7584ab9466b5c34efe0e4c24daf2e19e792ce2bca59bd3bc4f1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 21:52:08"
  condition:
    hash.sha256(0, filesize) == "b32527764b33b7584ab9466b5c34efe0e4c24daf2e19e792ce2bca59bd3bc4f1"
}
```

### Sample 83: `65600a05592216cd`

| Field | Value |
|---|---|
| SHA-256 | `65600a05592216cdef98173f4202b141dec19b2955e59dc518b2efc46f5969fc` |
| Family label | `Mirai` |
| File name | `Z31w` |
| File type | `elf` |
| First seen | `2026-07-21 21:06:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9eaf56040489437d2e8460d3563ca11` |
| SHA-1 | `a8cea764ae279f4ec291eb523fd42532adf2a293` |
| SHA-256 | `65600a05592216cdef98173f4202b141dec19b2955e59dc518b2efc46f5969fc` |
| SHA3-384 | `1c34526341cb8aaea24a2f42fd22af5ccebf114d3ada743c44e1e73b41339112db35d2cbb6bd8ae741a29412af2e4761` |
| TLSH | `T1BD83096ABD809F05D4D526BAFF1E538933535BBCE3EE7112DE142B25278A91B0F3A401` |
| TELFHASH | `t16ee061b64a4185fc93e44559d05f711a430ce052051045d8bafc5e1fd173886760e40a` |
| SSDEEP | `1536:4SnJNQaEmXBaYUIlkvkCod3cZqDdGgp6Hj8Nq4x+7juqxlla+iNqzHkZUc:jBEgBNgcOClp6Hj8Nq4x+7dENqzsU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_65600a05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65600a05592216cdef98173f4202b141dec19b2955e59dc518b2efc46f5969fc"
    family = "Mirai"
    file_name = "Z31w"
    file_type = "elf"
    first_seen = "2026-07-21 21:06:38"
  condition:
    hash.sha256(0, filesize) == "65600a05592216cdef98173f4202b141dec19b2955e59dc518b2efc46f5969fc"
}
```

### Sample 84: `5606abbe1c787722`

| Field | Value |
|---|---|
| SHA-256 | `5606abbe1c7877225704f709f95854ded5d384cbc06dc1a55230f31c26e485bd` |
| Family label | `unknown` |
| File name | `K6U` |
| File type | `elf` |
| First seen | `2026-07-21 21:04:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a89e0dc6a7ef9d934e3e0a9657c57cec` |
| SHA-1 | `4c165f70ed5340ab643a114890d0682faac88900` |
| SHA-256 | `5606abbe1c7877225704f709f95854ded5d384cbc06dc1a55230f31c26e485bd` |
| SHA3-384 | `021af737f1f4c6006f70dea38cebae1164f03c88da6f41ea5790fcec167f5f68f60719363dbb857753ed4e4ff4d36582` |
| TLSH | `T1EBA3E81AAF611DBBDC1BDD3709E8070638CCA60771A937753538D92CBA4A90B4AD3CB5` |
| SSDEEP | `1536:veVMSEoURBnxCLfaXD6KHALGSqMuC4AGxmVFalyZLsSEttz0sf9bEEq:gSfnxCLSX2KgLLYC4htm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_5606abbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5606abbe1c7877225704f709f95854ded5d384cbc06dc1a55230f31c26e485bd"
    family = "unknown"
    file_name = "K6U"
    file_type = "elf"
    first_seen = "2026-07-21 21:04:36"
  condition:
    hash.sha256(0, filesize) == "5606abbe1c7877225704f709f95854ded5d384cbc06dc1a55230f31c26e485bd"
}
```

### Sample 85: `86a058d461cdc548`

| Field | Value |
|---|---|
| SHA-256 | `86a058d461cdc5486430c2f6b1800235a8fbfdbe7d1af4af5d2d2d2f003c7634` |
| Family label | `unknown` |
| File name | `03W7` |
| File type | `elf` |
| First seen | `2026-07-21 21:04:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e8ca089db68c887def4d1177fce9137` |
| SHA-1 | `febe8c12554f76d279faebef79e2fbb2153983bc` |
| SHA-256 | `86a058d461cdc5486430c2f6b1800235a8fbfdbe7d1af4af5d2d2d2f003c7634` |
| SHA3-384 | `1d79f296ffb04a23a85b399aaabf982ea986b49e742850ab23488c9c11fa9f37eb5b5e645f060fd1998aae340ba05902` |
| TLSH | `T1C3632A75B9818B56C1D52677FF1D8388331723B8E3EB7113DA196F6137CB82A0E2A142` |
| TELFHASH | `t1cde06873074619dc5fc0c09681ee3a584b1df0322701194ec2fc9d0434e3886fa01c08` |
| SSDEEP | `1536:qVbm7Ju6BQNy3bEkPCbmeT1yQ3yN8clJW0nZcJdNFL1Udcfdp:q1aJuYZXOm81yQ388clJrZuLFL1UdM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_86a058d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86a058d461cdc5486430c2f6b1800235a8fbfdbe7d1af4af5d2d2d2f003c7634"
    family = "unknown"
    file_name = "03W7"
    file_type = "elf"
    first_seen = "2026-07-21 21:04:34"
  condition:
    hash.sha256(0, filesize) == "86a058d461cdc5486430c2f6b1800235a8fbfdbe7d1af4af5d2d2d2f003c7634"
}
```

### Sample 86: `08916c59ba59c089`

| Field | Value |
|---|---|
| SHA-256 | `08916c59ba59c089e9d1140b6efa03611785e5c40d907cbb797e0f958be2dc29` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-21 20:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44ef192c90d9ea302acceb3a7c70d8c2` |
| SHA-1 | `7bfc9791f8645400f209a638810c0fb321bb8fbd` |
| SHA-256 | `08916c59ba59c089e9d1140b6efa03611785e5c40d907cbb797e0f958be2dc29` |
| SHA3-384 | `b79e75daaf20890e0605ef82b0e81f1f9b2eec138f153cb446c93d5922ae6b5dab1991aaa14f713cae644ddab1a4d3f1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1CCE6330C6ED012EEE6B3603DFED469D2D16934751735CAEB03AC82E21E572E0C53E696` |
| SSDEEP | `393216:pRXTTCw3J58zURNt2HXMCHWUjXscuI3/PGTAI:pRPwHHXMb8X5H/O7` |
| ICON-DHASH | `e86864e1d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_08916c59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08916c59ba59c089e9d1140b6efa03611785e5c40d907cbb797e0f958be2dc29"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 20:52:08"
  condition:
    hash.sha256(0, filesize) == "08916c59ba59c089e9d1140b6efa03611785e5c40d907cbb797e0f958be2dc29"
}
```

### Sample 87: `4977440daf9c3c16`

| Field | Value |
|---|---|
| SHA-256 | `4977440daf9c3c16cd86e641233a44c581c020ef538e7212e7b68eb4910ca7cd` |
| Family label | `Mirai` |
| File name | `30HR` |
| File type | `elf` |
| First seen | `2026-07-21 20:51:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68b31bfc398195439d15436e361dfcc4` |
| SHA-1 | `5bc4c220830cb29b6dc3767b6297c446bbeea118` |
| SHA-256 | `4977440daf9c3c16cd86e641233a44c581c020ef538e7212e7b68eb4910ca7cd` |
| SHA3-384 | `aaaebc44b92862056f39e83ffc000617761d170a40f550fb862ca53ed3cefa8ed03c20f832ea960a965b2f89c7550e53` |
| TLSH | `T1EBA3C70ABF611DBBD81BDD3705AD0B0234CCA6177264377A3538D918BB4A54B8AD3CB5` |
| SSDEEP | `1536:eK3Qe607xFVKLXz6XQAbSZKoubxW2q7l7df9w0fP13gvkSLcxr/pfj7:Z9zVKLXGXnboEbiD1nRh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_4977440d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4977440daf9c3c16cd86e641233a44c581c020ef538e7212e7b68eb4910ca7cd"
    family = "Mirai"
    file_name = "30HR"
    file_type = "elf"
    first_seen = "2026-07-21 20:51:55"
  condition:
    hash.sha256(0, filesize) == "4977440daf9c3c16cd86e641233a44c581c020ef538e7212e7b68eb4910ca7cd"
}
```

### Sample 88: `522f6221c4e04ddf`

| Field | Value |
|---|---|
| SHA-256 | `522f6221c4e04ddffafba732722abba1b5000736d380bd779c67e6fe69f743e1` |
| Family label | `Mirai` |
| File name | `Qlz` |
| File type | `elf` |
| First seen | `2026-07-21 20:51:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba81c87fd2b15a7dc9e0c70c3e4c40cb` |
| SHA-1 | `1ff3160cbee2e440ca7c648e4f4814ee297a90a3` |
| SHA-256 | `522f6221c4e04ddffafba732722abba1b5000736d380bd779c67e6fe69f743e1` |
| SHA3-384 | `2bd910c2faa06b7ed12ac719ea7b695de56eac1a6688194ff8476cd6e63bc259e93483ca3aac035628517d5dc9b03116` |
| TLSH | `T1AD83072ABD419F05D4D526BAFF1E538933531BBCE3EE7112EE142B25278A95B0F3A401` |
| TELFHASH | `t16ee061b64a4185fc93e44559d05f711a430ce052051045d8bafc5e1fd173886760e40a` |
| SSDEEP | `1536:+4nT+Q1E/AuMUIlkvkCSd3cXqDdGgHZHR6NM+fQBzuqRll2LivtlEkZ+xXy:95EItgGYClHZHR6NM+fQBVY6tlf+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_522f6221
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "522f6221c4e04ddffafba732722abba1b5000736d380bd779c67e6fe69f743e1"
    family = "Mirai"
    file_name = "Qlz"
    file_type = "elf"
    first_seen = "2026-07-21 20:51:54"
  condition:
    hash.sha256(0, filesize) == "522f6221c4e04ddffafba732722abba1b5000736d380bd779c67e6fe69f743e1"
}
```

### Sample 89: `773fc40e2f9d7576`

| Field | Value |
|---|---|
| SHA-256 | `773fc40e2f9d7576f597d501744e4397da0da71d4cbf1c05aeccf0b0e7048492` |
| Family label | `unknown` |
| File name | `cHz` |
| File type | `elf` |
| First seen | `2026-07-21 20:51:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3fef8301e1992952d5a8b7ac41f4054` |
| SHA-1 | `6f82a6fcd1496e32360e5e1d154f27aba2885b79` |
| SHA-256 | `773fc40e2f9d7576f597d501744e4397da0da71d4cbf1c05aeccf0b0e7048492` |
| SHA3-384 | `9f078a1892f7e4cec6cb30ab676208d4ac3acb96c8d4b28935b41120139764f1ac26c0f441e3f1dfcf2e5643310b23fc` |
| TLSH | `T1D8631975BD819F16C5C56677FF1E4388331B23A8E3EA7113EA156F6137CB82A0E2A141` |
| TELFHASH | `t1cde06873074619dc5fc0c09681ee3a584b1df0322701194ec2fc9d0434e3886fa01c08` |
| SSDEEP | `1536:PVb27rujdQNy3b5pPCbmeT1yj3y0IcfZqWlZcSUFy1UbL3x39S:P1KruZZ3Om81yj39IcfZBflUFy1Ubz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_773fc40e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "773fc40e2f9d7576f597d501744e4397da0da71d4cbf1c05aeccf0b0e7048492"
    family = "unknown"
    file_name = "cHz"
    file_type = "elf"
    first_seen = "2026-07-21 20:51:53"
  condition:
    hash.sha256(0, filesize) == "773fc40e2f9d7576f597d501744e4397da0da71d4cbf1c05aeccf0b0e7048492"
}
```

### Sample 90: `34dcd1d45a2d5021`

| Field | Value |
|---|---|
| SHA-256 | `34dcd1d45a2d5021378d51deb542b6220cb203dd6711b369eeb4035c50f57016` |
| Family label | `Mirai` |
| File name | `b7g` |
| File type | `elf` |
| First seen | `2026-07-21 20:37:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `821bedb0285cb46dea19d5c05c2b72c0` |
| SHA-1 | `36f30711d80e588b6d6fee2e8a67d31993cc4c4f` |
| SHA-256 | `34dcd1d45a2d5021378d51deb542b6220cb203dd6711b369eeb4035c50f57016` |
| SHA3-384 | `051a4ac17f129770ef130548443fb665e4ed9de62b0cb8c21e4563568b7aef289ea96eec8bf39287f8753bc9b985ca18` |
| TLSH | `T17583196AB9419F05D4D526BAFF1E438933535BBCE3EE7112DE142F2527CA92B0F2A401` |
| TELFHASH | `t1ba01f13506c44cdc9bd0c106e1ef152ac98ef8b93720098eb5fdef8a92a36d5b312409` |
| SSDEEP | `1536:ZjnrtCAXuYuhkc5PynmMXeIhDIzLOPPbN/BsbpBuxZllKsiwlcrvOkbC0zS:FtCQWkSY7dwOPPbN/BsbpM8ilcygD+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_34dcd1d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34dcd1d45a2d5021378d51deb542b6220cb203dd6711b369eeb4035c50f57016"
    family = "Mirai"
    file_name = "b7g"
    file_type = "elf"
    first_seen = "2026-07-21 20:37:28"
  condition:
    hash.sha256(0, filesize) == "34dcd1d45a2d5021378d51deb542b6220cb203dd6711b369eeb4035c50f57016"
}
```

### Sample 91: `9539c6ce1df04714`

| Field | Value |
|---|---|
| SHA-256 | `9539c6ce1df04714b2d3d44813611a6b7c39afa2be5a592ab9a16361d0a3445a` |
| Family label | `unknown` |
| File name | `PYdl` |
| File type | `elf` |
| First seen | `2026-07-21 20:37:26` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae959a98f0f477b1009ddebbee7cdf38` |
| SHA-1 | `9cc8d32da3609b26b989b8a5c2391952fb942c89` |
| SHA-256 | `9539c6ce1df04714b2d3d44813611a6b7c39afa2be5a592ab9a16361d0a3445a` |
| SHA3-384 | `c8ee106fad12f0c4a077d624a9d8559e9b49fd5668afb187474c18652ab8a30304879b7ac2f819791c50a9e3473a1757` |
| TLSH | `T1A9632A76B9919F1AC5C52277FF1D4388335723B8E3EA7113EA156F6137CB82A0D2A141` |
| TELFHASH | `t141018972458d48edaaf4c28653ef62194a2df1ed37a0591fb5fc9e0e16c38d3f221904` |
| SSDEEP | `1536:yfjOrmV4LSw1zAyKsYapNPSbAb1Svg/S7H8WvJZczdFG1UU7ibC0fF:yfjOrmSSI8o1Nu+1So/Sj8ozYdFG1UUi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_9539c6ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9539c6ce1df04714b2d3d44813611a6b7c39afa2be5a592ab9a16361d0a3445a"
    family = "unknown"
    file_name = "PYdl"
    file_type = "elf"
    first_seen = "2026-07-21 20:37:26"
  condition:
    hash.sha256(0, filesize) == "9539c6ce1df04714b2d3d44813611a6b7c39afa2be5a592ab9a16361d0a3445a"
}
```

### Sample 92: `70e4229a67b7459a`

| Field | Value |
|---|---|
| SHA-256 | `70e4229a67b7459a9e361ac0e855130902239517766b2d0001277eb8d62d5a85` |
| Family label | `Mirai` |
| File name | `hXz8` |
| File type | `elf` |
| First seen | `2026-07-21 20:35:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5abac9febd4263d94af3e174a75f933` |
| SHA-1 | `e334f0aebb9463e5bad266975cfe7c6b137d2a02` |
| SHA-256 | `70e4229a67b7459a9e361ac0e855130902239517766b2d0001277eb8d62d5a85` |
| SHA3-384 | `13fd97fa56ba6b8ec43b0e9c86c39755f8c75ddd615f7659674fc6c04f4bf7e768859a8dd48e8dc5d2391b2f8b378c63` |
| TLSH | `T1CEA3E91ABF611EBBD81BDD3705AC070234CCA617726837793534D928BB8A54B8AD3CB5` |
| SSDEEP | `1536:AKcmxw2l0btQnXRXC60QAz1J7qau3+4uVfRZFU02ExCg2f5kybC0iP:lAhQnXRXj0nz1FiOBx+D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_70e4229a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70e4229a67b7459a9e361ac0e855130902239517766b2d0001277eb8d62d5a85"
    family = "Mirai"
    file_name = "hXz8"
    file_type = "elf"
    first_seen = "2026-07-21 20:35:40"
  condition:
    hash.sha256(0, filesize) == "70e4229a67b7459a9e361ac0e855130902239517766b2d0001277eb8d62d5a85"
}
```

### Sample 93: `8c1654ad1df9e9bf`

| Field | Value |
|---|---|
| SHA-256 | `8c1654ad1df9e9bf1c450657b12eb269d999934b83bbfdd59cbb886c6550f283` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-21 20:30:38` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c82496049dd65950f842b02171b32c0` |
| SHA-1 | `c79f3ffc6e55121710bcb850f3e6e9d20b0eba61` |
| SHA-256 | `8c1654ad1df9e9bf1c450657b12eb269d999934b83bbfdd59cbb886c6550f283` |
| SHA3-384 | `782e479d970ffe627cd3c47f74bd4879956cce53bb6a3ff559a5ed4376aed290bc6095dac7f4e6b3db3cf9216516aca1` |
| IMPHASH | `69d04b283251e75ebf7bdd628fba938f` |
| TLSH | `T1D4268D43D65291E9C02BC2BC9E175A727A21781CD834FEBF5590DF233E31B105E6EA29` |
| SSDEEP | `98304:Z1DLMVtjANF8oC4xEyrTVYm8bILHGWCv5IjjPmgDfwxfH+YEO:Z1XUWXC4xEXegv5IjjPmgDfOfH7EO` |
| ICON-DHASH | `6cecccccb4c2f2b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_8c1654ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c1654ad1df9e9bf1c450657b12eb269d999934b83bbfdd59cbb886c6550f283"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 20:30:38"
  condition:
    hash.sha256(0, filesize) == "8c1654ad1df9e9bf1c450657b12eb269d999934b83bbfdd59cbb886c6550f283"
}
```

### Sample 94: `ee727d639eaa4ee2`

| Field | Value |
|---|---|
| SHA-256 | `ee727d639eaa4ee2e0d7cafbe496e14aaac8df0955d9fb599f2c11dfa1d0f8f2` |
| Family label | `unknown` |
| File name | `malware.msi` |
| File type | `msi` |
| First seen | `2026-07-21 20:18:39` |
| Reporter | `SquiblydooBlog` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `752db4b87198eff1979ebf07156b20ae` |
| SHA-1 | `674fcfc27b430a88091475991ebb8d96a4d81fae` |
| SHA-256 | `ee727d639eaa4ee2e0d7cafbe496e14aaac8df0955d9fb599f2c11dfa1d0f8f2` |
| SHA3-384 | `cb4c8f064b1a320a1a04be747837697ffb7836a804c2caef3a40f2fd6994e1032fb5ec25ed906c696ef5b6a600db0e0a` |
| TLSH | `T112C4231637A9823BE1C66734902CF3848E287C6C6F1E18167275715E1DB33E0DAB2BD6` |
| SSDEEP | `12288:eIRrmyV1eJvNIGMevuspubrA8oDqT5EEbDWJWlH+oNQ99oD:ZTmdLPpuv5EEyGNQ99U` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_ee727d63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee727d639eaa4ee2e0d7cafbe496e14aaac8df0955d9fb599f2c11dfa1d0f8f2"
    family = "unknown"
    file_name = "malware.msi"
    file_type = "msi"
    first_seen = "2026-07-21 20:18:39"
  condition:
    hash.sha256(0, filesize) == "ee727d639eaa4ee2e0d7cafbe496e14aaac8df0955d9fb599f2c11dfa1d0f8f2"
}
```

### Sample 95: `46b426b6e25231d7`

| Field | Value |
|---|---|
| SHA-256 | `46b426b6e25231d731d7cb2822f1435f65778f168c9d838568e9012d3507abda` |
| Family label | `unknown` |
| File name | `rnp.dll` |
| File type | `exe` |
| First seen | `2026-07-21 20:17:05` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9feb502c7ec6907dd2adabd782b61b88` |
| SHA-1 | `d812878aba17e6fc8cc7fbc4ccaad2dc66b1624d` |
| SHA-256 | `46b426b6e25231d731d7cb2822f1435f65778f168c9d838568e9012d3507abda` |
| SHA3-384 | `7a2952818f376863cb0b125af70f8123a30ca992647001c4d13daa187b7727dc109d30fe2c2677386afe6ec19733e037` |
| IMPHASH | `f9e79734109d56f4dd73964feeaeffc0` |
| TLSH | `T12644EE6163EA1104F7FB5FB76EF6A084DAB579B10A76C21E5168C00F2C75F81E8A4732` |
| SSDEEP | `3072:Dg8P+Xx+OOWToreKtPvSFl3WkFB1xTO7wm:DH+X1oqK5m0kFB12R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_46b426b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46b426b6e25231d731d7cb2822f1435f65778f168c9d838568e9012d3507abda"
    family = "unknown"
    file_name = "rnp.dll"
    file_type = "exe"
    first_seen = "2026-07-21 20:17:05"
  condition:
    hash.sha256(0, filesize) == "46b426b6e25231d731d7cb2822f1435f65778f168c9d838568e9012d3507abda"
}
```

### Sample 96: `6e94135ab277c295`

| Field | Value |
|---|---|
| SHA-256 | `6e94135ab277c29528467561e79cbacf505d6fe36808757b88a6449950614e64` |
| Family label | `unknown` |
| File name | `ssJw` |
| File type | `elf` |
| First seen | `2026-07-21 20:16:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4665b8ab81ab6fc0de7e431d930224be` |
| SHA-1 | `d5c837081b0f5cdd42440d48079fa85e1221e43a` |
| SHA-256 | `6e94135ab277c29528467561e79cbacf505d6fe36808757b88a6449950614e64` |
| SHA3-384 | `ed2024bdabfbbdf64221673d7f8c055e8331999db4b967355367b5accd068ae09c15ac8daefa18ab2d43f3988f33638c` |
| TLSH | `T1C8630976B9819B16C5C52277FF2D8388331723B8E3EE7113EA156F6537CB52A0E2A141` |
| TELFHASH | `t141018972458d48edaaf4c28653ef62194a2df1ed37a0591fb5fc9e0e16c38d3f221904` |
| SSDEEP | `1536:yfjOrmV6Lyw1zAyKsY6JNPSbAb1SPA/S7n8WPpZc7oMlLFG1UnzxsF:yfjOrm0yI8o1Nu+1So/SD8ITjMlLFG1C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_6e94135a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e94135ab277c29528467561e79cbacf505d6fe36808757b88a6449950614e64"
    family = "unknown"
    file_name = "ssJw"
    file_type = "elf"
    first_seen = "2026-07-21 20:16:22"
  condition:
    hash.sha256(0, filesize) == "6e94135ab277c29528467561e79cbacf505d6fe36808757b88a6449950614e64"
}
```

### Sample 97: `d71578b74b7d7d65`

| Field | Value |
|---|---|
| SHA-256 | `d71578b74b7d7d6513292e2d4cae8e8518f49e321fbed3d2812a6712da7dc241` |
| Family label | `Mirai` |
| File name | `hytC` |
| File type | `elf` |
| First seen | `2026-07-21 20:14:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4043bba93d74924557d6c4ef50d32b22` |
| SHA-1 | `dbb64950729bacaf399d6bb4a4bbb859d2530214` |
| SHA-256 | `d71578b74b7d7d6513292e2d4cae8e8518f49e321fbed3d2812a6712da7dc241` |
| SHA3-384 | `5c1c9620e1558a5a5c01751b303e8cc3e9a28fe6c8e49e6d4fbacb31f76bc0fdec299c85bbb7e14c8c4713ad869c4316` |
| TLSH | `T16683072AB9419F05D4D526BAFF1E934933536BBCE3EE7103DE142B6527CA91B0F2A401` |
| TELFHASH | `t1ba01f13506c44cdc9bd0c106e1ef152ac98ef8b93720098eb5fdef8a92a36d5b312409` |
| SSDEEP | `1536:5DnLNCSXuYuBkc5PynmsXeohDIzLOPv7NfhM7JBuxZllDMiQl8rvOv4z:lNCC2kS4bdwOPv7NfhM7JMZil8ym` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_d71578b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d71578b74b7d7d6513292e2d4cae8e8518f49e321fbed3d2812a6712da7dc241"
    family = "Mirai"
    file_name = "hytC"
    file_type = "elf"
    first_seen = "2026-07-21 20:14:36"
  condition:
    hash.sha256(0, filesize) == "d71578b74b7d7d6513292e2d4cae8e8518f49e321fbed3d2812a6712da7dc241"
}
```

### Sample 98: `692757b81ed8e5c1`

| Field | Value |
|---|---|
| SHA-256 | `692757b81ed8e5c17634d5c95e91d6201a9329e232281e8eda98d502ea821837` |
| Family label | `Mirai` |
| File name | `KXV` |
| File type | `elf` |
| First seen | `2026-07-21 20:14:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c43cff623cec4b02e503a0fcbddbe70` |
| SHA-1 | `7bd96d8f6a8720ebb3eaae6a4fe43a26494e4af4` |
| SHA-256 | `692757b81ed8e5c17634d5c95e91d6201a9329e232281e8eda98d502ea821837` |
| SHA3-384 | `a71973482941f3433cb5757e9261a03a98528e42383df5ff8b2497f6d5e3d83630ec676cf5c419d8775f2dddd9a710b5` |
| TLSH | `T166A3FB1AAF611DBBD81BDD3305AC070235CCA60772693B793534D528FB8A54B8AD3CB9` |
| SSDEEP | `1536:zKARGLVAMtCde3xXi60QAzVm7qauTKN810g5lU02kxXBgz04EoN7:cL+ywe3xXD0nzVyioYxX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_692757b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "692757b81ed8e5c17634d5c95e91d6201a9329e232281e8eda98d502ea821837"
    family = "Mirai"
    file_name = "KXV"
    file_type = "elf"
    first_seen = "2026-07-21 20:14:35"
  condition:
    hash.sha256(0, filesize) == "692757b81ed8e5c17634d5c95e91d6201a9329e232281e8eda98d502ea821837"
}
```

### Sample 99: `721d764d2d1985ee`

| Field | Value |
|---|---|
| SHA-256 | `721d764d2d1985eefb42fee9e1e2f05d4f4f35bbec216b952cdad74b0ac90cd1` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-21 20:05:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `695ea7aa314c4478a06aa48945bfd561` |
| SHA-1 | `b2ca1aebb0c04a794ccc69397b59f1bfb4d4109e` |
| SHA-256 | `721d764d2d1985eefb42fee9e1e2f05d4f4f35bbec216b952cdad74b0ac90cd1` |
| SHA3-384 | `e13a9ed68ddaa77e9b649bc930635dbbe3620354cc977d25fe2a959478ca6f554c001affd338e053a66d492cf80cadf2` |
| TLSH | `T136C30845FC509B12C6C255BBFF4E828D7B261758E3EE72039D256F64378B86B0E3A042` |
| TELFHASH | `t136b01278674c192804e001c258f3351005f2300d1d451c04b07c591d65514e13062197` |
| SSDEEP | `1536:dqtcHkQ2uce3J5M2rj74VSfqTaHBQK4ayOqONdESzFppluZwywYZMLttj6D+3tlg:dqtchDZ5MO44qsBQ14+SZpVr7Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_721d764d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "721d764d2d1985eefb42fee9e1e2f05d4f4f35bbec216b952cdad74b0ac90cd1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-21 20:05:19"
  condition:
    hash.sha256(0, filesize) == "721d764d2d1985eefb42fee9e1e2f05d4f4f35bbec216b952cdad74b0ac90cd1"
}
```

### Sample 100: `d475c3caf477bd0e`

| Field | Value |
|---|---|
| SHA-256 | `d475c3caf477bd0e4aebbce33f062d4d42a3533e28b76d2ad23c709d013e7926` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-21 20:00:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be71d936a939e65ab5135e8b4c7ce73c` |
| SHA-1 | `366f8c2aa78438df22bccb66e4c6971f988f7063` |
| SHA-256 | `d475c3caf477bd0e4aebbce33f062d4d42a3533e28b76d2ad23c709d013e7926` |
| SHA3-384 | `f2c3127cb75830b6a20cf1bf091cfa813e8c0ca401c0863f871453eb32a18213c6fb91acea410b38cfc7f5a704d80c33` |
| TLSH | `T1F3011EC695006D406029C95E72DB2290B852C3CF1A8A0F787FDC2E2DFBACD04B026F9C` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHka/CzSdUjAFCCLnC5NXCFG9MLCQKTuauD:kXCKysE2hi0ziQvZoha/wx0duXYtKTu7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_d475c3ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d475c3caf477bd0e4aebbce33f062d4d42a3533e28b76d2ad23c709d013e7926"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-21 20:00:36"
  condition:
    hash.sha256(0, filesize) == "d475c3caf477bd0e4aebbce33f062d4d42a3533e28b76d2ad23c709d013e7926"
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
 * Generated: 2026-07-22T03:51:31.050764+00:00
 */

rule MalwareBazaar_unknown_001_6209b9f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6209b9f4af44f71e7b319c5b406603a6f15da3c7d8ca6bd06d434af65269990e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 03:42:12"
  condition:
    hash.sha256(0, filesize) == "6209b9f4af44f71e7b319c5b406603a6f15da3c7d8ca6bd06d434af65269990e"
}

rule MalwareBazaar_unknown_002_480bdd66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "480bdd66621a0869dff575523f7e4ad5b7528744c1dc40f6f80bc85233433186"
    family = "unknown"
    file_name = "MV.LOWLANDS.WEALTH.VESSEL.PARTICULARSpdf.exe"
    file_type = "exe"
    first_seen = "2026-07-22 03:39:21"
  condition:
    hash.sha256(0, filesize) == "480bdd66621a0869dff575523f7e4ad5b7528744c1dc40f6f80bc85233433186"
}

rule MalwareBazaar_Mirai_003_792c62d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "792c62d5d1c2b14b8f88b6d4f076197c09be903d66b6f882cebffe7be9c0bc77"
    family = "Mirai"
    file_name = "8Mty"
    file_type = "elf"
    first_seen = "2026-07-22 03:37:33"
  condition:
    hash.sha256(0, filesize) == "792c62d5d1c2b14b8f88b6d4f076197c09be903d66b6f882cebffe7be9c0bc77"
}

rule MalwareBazaar_Mirai_004_e4d2ddc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4d2ddc80e1c236ae22bec38090883648b411e140e94a2a5d554aac66bae030e"
    family = "Mirai"
    file_name = "WgR"
    file_type = "elf"
    first_seen = "2026-07-22 03:35:59"
  condition:
    hash.sha256(0, filesize) == "e4d2ddc80e1c236ae22bec38090883648b411e140e94a2a5d554aac66bae030e"
}

rule MalwareBazaar_unknown_005_76d7bbf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76d7bbf2d95d24046a8ae3a9b64c63ee280700434ce642df02d2530e13bcd8f2"
    family = "unknown"
    file_name = "uteZ"
    file_type = "elf"
    first_seen = "2026-07-22 03:35:57"
  condition:
    hash.sha256(0, filesize) == "76d7bbf2d95d24046a8ae3a9b64c63ee280700434ce642df02d2530e13bcd8f2"
}

rule MalwareBazaar_unknown_006_db9e5553
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db9e55535159db148bef69090be530fd01408c303b67f0f16f658d01c7c5ee6d"
    family = "unknown"
    file_name = "SecuriteInfo.com.Adware.GenericKD.61155092.527.27382"
    file_type = "exe"
    first_seen = "2026-07-22 03:35:31"
  condition:
    hash.sha256(0, filesize) == "db9e55535159db148bef69090be530fd01408c303b67f0f16f658d01c7c5ee6d"
}

rule MalwareBazaar_Mirai_007_f9cc910e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9cc910e56e63b80fc8d357374daf473655ef4e4f3ff28e8f0b04f717e9fb78d"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-07-22 02:55:53"
  condition:
    hash.sha256(0, filesize) == "f9cc910e56e63b80fc8d357374daf473655ef4e4f3ff28e8f0b04f717e9fb78d"
}

rule MalwareBazaar_Mirai_008_a804ec44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a804ec4400e8da43e2d7e0a3429a3b85abff41f383a9d07041c5730492f8bce1"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-07-22 02:55:27"
  condition:
    hash.sha256(0, filesize) == "a804ec4400e8da43e2d7e0a3429a3b85abff41f383a9d07041c5730492f8bce1"
}

rule MalwareBazaar_unknown_009_74f0e813
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f0e8132ae338ff8054359b17d9d599cd802d9d0137bab5218137c9ed289f8f"
    family = "unknown"
    file_name = "Zd2"
    file_type = "elf"
    first_seen = "2026-07-22 02:53:50"
  condition:
    hash.sha256(0, filesize) == "74f0e8132ae338ff8054359b17d9d599cd802d9d0137bab5218137c9ed289f8f"
}

rule MalwareBazaar_unknown_010_671b70f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "671b70f36717d438960f7d923f5d0a78621aebbb97a403de4496c7633a07a697"
    family = "unknown"
    file_name = "MoO"
    file_type = "elf"
    first_seen = "2026-07-22 02:53:49"
  condition:
    hash.sha256(0, filesize) == "671b70f36717d438960f7d923f5d0a78621aebbb97a403de4496c7633a07a697"
}

rule MalwareBazaar_Mirai_011_a8908e61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8908e6188e828c37eb51771ec60f7468dfbae22c00e0737825c4b97d0004411"
    family = "Mirai"
    file_name = "oeC6"
    file_type = "elf"
    first_seen = "2026-07-22 02:52:24"
  condition:
    hash.sha256(0, filesize) == "a8908e6188e828c37eb51771ec60f7468dfbae22c00e0737825c4b97d0004411"
}

rule MalwareBazaar_unknown_012_efadd757
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efadd757ffcdc156c9dbcac6745e70be5ca5174636d8853518839da82cf7e7b6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 02:52:08"
  condition:
    hash.sha256(0, filesize) == "efadd757ffcdc156c9dbcac6745e70be5ca5174636d8853518839da82cf7e7b6"
}

rule MalwareBazaar_unknown_013_1490e65b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1490e65be0e21b946e6128846e30dba08b7f8efbd4a1f8f1adf863c5fc93f974"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.85894993"
    file_type = "exe"
    first_seen = "2026-07-22 02:39:52"
  condition:
    hash.sha256(0, filesize) == "1490e65be0e21b946e6128846e30dba08b7f8efbd4a1f8f1adf863c5fc93f974"
}

rule MalwareBazaar_unknown_014_73db8e9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73db8e9a1b49daa01f362573eeb79a0b7ac9455f581e79d49a1c99734181d65f"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.57653523"
    file_type = "exe"
    first_seen = "2026-07-22 02:39:50"
  condition:
    hash.sha256(0, filesize) == "73db8e9a1b49daa01f362573eeb79a0b7ac9455f581e79d49a1c99734181d65f"
}

rule MalwareBazaar_CoinMiner_015_85142e27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85142e27e44b83ae26230454694d1666652e718e3764e57a1d6539c83e448402"
    family = "CoinMiner"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.64268345"
    file_type = "exe"
    first_seen = "2026-07-22 02:39:49"
  condition:
    hash.sha256(0, filesize) == "85142e27e44b83ae26230454694d1666652e718e3764e57a1d6539c83e448402"
}

rule MalwareBazaar_unknown_016_55a47a54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a47a54228736d7dad743a053f6c7a832b06efe94ae2c6645d5f0df034cff58"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.65237985"
    file_type = "exe"
    first_seen = "2026-07-22 02:39:47"
  condition:
    hash.sha256(0, filesize) == "55a47a54228736d7dad743a053f6c7a832b06efe94ae2c6645d5f0df034cff58"
}

rule MalwareBazaar_unknown_017_2cb2ced2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cb2ced283d72a7323be7e4c95c1563ff5f26546794e602e58c2701f2b3c623a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 02:35:27"
  condition:
    hash.sha256(0, filesize) == "2cb2ced283d72a7323be7e4c95c1563ff5f26546794e602e58c2701f2b3c623a"
}

rule MalwareBazaar_unknown_018_4f09b4b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f09b4b24d59d2db69f9fe5b4b7b1fcb4f65e8412728d1c9d8ceb636358f7207"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 02:35:18"
  condition:
    hash.sha256(0, filesize) == "4f09b4b24d59d2db69f9fe5b4b7b1fcb4f65e8412728d1c9d8ceb636358f7207"
}

rule MalwareBazaar_unknown_019_8f0637cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f0637cd0ceefdd4a98b8d33c7ab50ca6664647f8e979d23b43f3c56329ab269"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-22 02:27:32"
  condition:
    hash.sha256(0, filesize) == "8f0637cd0ceefdd4a98b8d33c7ab50ca6664647f8e979d23b43f3c56329ab269"
}

rule MalwareBazaar_BlackMatter_020_47f8790c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47f8790c9b5b9aab6ae179a192a91d4a5b4e6aac17c14f103858fa3b72ceba25"
    family = "BlackMatter"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 02:10:12"
  condition:
    hash.sha256(0, filesize) == "47f8790c9b5b9aab6ae179a192a91d4a5b4e6aac17c14f103858fa3b72ceba25"
}

rule MalwareBazaar_unknown_021_56819d1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56819d1e3fb265c80e117800fd1df93744135ca391a311250d0221e7ecc9fd81"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-22 01:52:27"
  condition:
    hash.sha256(0, filesize) == "56819d1e3fb265c80e117800fd1df93744135ca391a311250d0221e7ecc9fd81"
}

rule MalwareBazaar_unknown_022_fb881f10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb881f10b82cd577893fc57375fcfa43a5650c395f82ab42c18eca04874679d4"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 01:52:08"
  condition:
    hash.sha256(0, filesize) == "fb881f10b82cd577893fc57375fcfa43a5650c395f82ab42c18eca04874679d4"
}

rule MalwareBazaar_AsyncRAT_023_e5dda4e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5dda4e7dc6b95830c066b519383e71abd4fb0a2340c0def898f635d9cfa13e7"
    family = "AsyncRAT"
    file_name = "e-dekont_html.exe"
    file_type = "exe"
    first_seen = "2026-07-22 01:45:21"
  condition:
    hash.sha256(0, filesize) == "e5dda4e7dc6b95830c066b519383e71abd4fb0a2340c0def898f635d9cfa13e7"
}

rule MalwareBazaar_unknown_024_5da46290
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5da46290c303a3acb2b8f5ec1792f33728903b7700e742c9e37aac026270245b"
    family = "unknown"
    file_name = "拼多多.exe"
    file_type = "exe"
    first_seen = "2026-07-22 01:39:08"
  condition:
    hash.sha256(0, filesize) == "5da46290c303a3acb2b8f5ec1792f33728903b7700e742c9e37aac026270245b"
}

rule MalwareBazaar_unknown_025_5711be9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5711be9cf97b2b68e39b35852491329197352fb561c8f7d3e6212d4cc1ecf9a5"
    family = "unknown"
    file_name = "putty_trojanized.exe"
    file_type = "msi"
    first_seen = "2026-07-22 01:30:08"
  condition:
    hash.sha256(0, filesize) == "5711be9cf97b2b68e39b35852491329197352fb561c8f7d3e6212d4cc1ecf9a5"
}

rule MalwareBazaar_unknown_026_7f9826fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f9826fd3e5026c5aae9a4672a977415ca8090d0653c4636a304130bd26b9382"
    family = "unknown"
    file_name = "winscp_trojanized.exe"
    file_type = "exe"
    first_seen = "2026-07-22 01:30:05"
  condition:
    hash.sha256(0, filesize) == "7f9826fd3e5026c5aae9a4672a977415ca8090d0653c4636a304130bd26b9382"
}

rule MalwareBazaar_unknown_027_a80abf35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a80abf352e9f35244aec83f4b82b221a6b0c3ef0cd10c87acc4168d60abca723"
    family = "unknown"
    file_name = "filezilla_trojanized_download"
    file_type = "exe"
    first_seen = "2026-07-22 01:30:03"
  condition:
    hash.sha256(0, filesize) == "a80abf352e9f35244aec83f4b82b221a6b0c3ef0cd10c87acc4168d60abca723"
}

rule MalwareBazaar_unknown_028_9c4d1d80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c4d1d8077938fef89508c207e5fc0c56544d84ac34c08c7ffe7a9c107e68237"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-22 01:10:53"
  condition:
    hash.sha256(0, filesize) == "9c4d1d8077938fef89508c207e5fc0c56544d84ac34c08c7ffe7a9c107e68237"
}

rule MalwareBazaar_unknown_029_ac59f3d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac59f3d4e45369275a7c9fc49bacb32fbc4348e57b5af5f3a12a018904d386ea"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-22 01:07:37"
  condition:
    hash.sha256(0, filesize) == "ac59f3d4e45369275a7c9fc49bacb32fbc4348e57b5af5f3a12a018904d386ea"
}

rule MalwareBazaar_Phorpiex_030_dab034d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dab034d5e6609eee42d40f4d61a0b95aa9dc4765c15d3d3dff81a2a16d7315bd"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 01:04:57"
  condition:
    hash.sha256(0, filesize) == "dab034d5e6609eee42d40f4d61a0b95aa9dc4765c15d3d3dff81a2a16d7315bd"
}

rule MalwareBazaar_unknown_031_ac197dc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac197dc54bf1c690dce6eff2024651fee1c57f3273ef4deb253854fe2b0afba7"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-22 00:52:08"
  condition:
    hash.sha256(0, filesize) == "ac197dc54bf1c690dce6eff2024651fee1c57f3273ef4deb253854fe2b0afba7"
}

rule MalwareBazaar_unknown_032_a54c005d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a54c005d853b1e8085c6cb4289561bd16365181e8441b204bea491425b0b3cd4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-22 00:48:01"
  condition:
    hash.sha256(0, filesize) == "a54c005d853b1e8085c6cb4289561bd16365181e8441b204bea491425b0b3cd4"
}

rule MalwareBazaar_unknown_033_f08dd221
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f08dd221aabdc54de26f51b466ae2cdf5b242b918d27bc02eaa1a18fc6a4113d"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-22 00:38:32"
  condition:
    hash.sha256(0, filesize) == "f08dd221aabdc54de26f51b466ae2cdf5b242b918d27bc02eaa1a18fc6a4113d"
}

rule MalwareBazaar_unknown_034_253938f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "253938f54a9938d1a2d9ce6622f1a3aecdf856961603c3faa6523467af6f3373"
    family = "unknown"
    file_name = "bot"
    file_type = "unknown"
    first_seen = "2026-07-22 00:22:54"
  condition:
    hash.sha256(0, filesize) == "253938f54a9938d1a2d9ce6622f1a3aecdf856961603c3faa6523467af6f3373"
}

rule MalwareBazaar_unknown_035_87c15587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87c155878e8aa527a3976649fb9bdb511bcd9f0e1507744c69804b2af597dcfd"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-22 00:14:32"
  condition:
    hash.sha256(0, filesize) == "87c155878e8aa527a3976649fb9bdb511bcd9f0e1507744c69804b2af597dcfd"
}

rule MalwareBazaar_Mirai_036_8cb552bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cb552bced9f715c2c24e058d5f589710e185991af4552e9f22d15d1249ca271"
    family = "Mirai"
    file_name = "pDY"
    file_type = "elf"
    first_seen = "2026-07-22 00:14:31"
  condition:
    hash.sha256(0, filesize) == "8cb552bced9f715c2c24e058d5f589710e185991af4552e9f22d15d1249ca271"
}

rule MalwareBazaar_unknown_037_9348f83d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9348f83dd587516806782a5bb4cb0a87c4c904152f07c2958e0275b9ce8c63ac"
    family = "unknown"
    file_name = "rev"
    file_type = "elf"
    first_seen = "2026-07-22 00:13:55"
  condition:
    hash.sha256(0, filesize) == "9348f83dd587516806782a5bb4cb0a87c4c904152f07c2958e0275b9ce8c63ac"
}

rule MalwareBazaar_unknown_038_8c7334c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7334c6455f4e7d62a9eac56532463b06c50ddf8755610b71af7d062f0739ae"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:13:28"
  condition:
    hash.sha256(0, filesize) == "8c7334c6455f4e7d62a9eac56532463b06c50ddf8755610b71af7d062f0739ae"
}

rule MalwareBazaar_unknown_039_e580389c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e580389c650f257fa14de379ebe93eb86ea56a123557c7eadb0a2ef4a6a37303"
    family = "unknown"
    file_name = "9a0L"
    file_type = "elf"
    first_seen = "2026-07-22 00:12:53"
  condition:
    hash.sha256(0, filesize) == "e580389c650f257fa14de379ebe93eb86ea56a123557c7eadb0a2ef4a6a37303"
}

rule MalwareBazaar_Mirai_040_6eff7333
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eff7333743c1285e911154a0eb3725c53fd53d954e21419af03ae47e8d4bf43"
    family = "Mirai"
    file_name = "MjsG"
    file_type = "elf"
    first_seen = "2026-07-22 00:12:52"
  condition:
    hash.sha256(0, filesize) == "6eff7333743c1285e911154a0eb3725c53fd53d954e21419af03ae47e8d4bf43"
}

rule MalwareBazaar_CoinMiner_041_1501fb77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1501fb778e9ceefc0dca1f8cfe8c9fdd1738db5f6dbb0032348f3e161391d016"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:10:59"
  condition:
    hash.sha256(0, filesize) == "1501fb778e9ceefc0dca1f8cfe8c9fdd1738db5f6dbb0032348f3e161391d016"
}

rule MalwareBazaar_unknown_042_23494415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23494415bafe76ea0729d47f7bbd1fb0b91aa747b0c45296713b41c1b63c24a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:10:48"
  condition:
    hash.sha256(0, filesize) == "23494415bafe76ea0729d47f7bbd1fb0b91aa747b0c45296713b41c1b63c24a6"
}

rule MalwareBazaar_unknown_043_441a9bd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "441a9bd8a0f93eae564b2e4397990f5d91479e18601ddcb5241afa7d559b4e77"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:10:38"
  condition:
    hash.sha256(0, filesize) == "441a9bd8a0f93eae564b2e4397990f5d91479e18601ddcb5241afa7d559b4e77"
}

rule MalwareBazaar_AgentTesla_044_6dc94196
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dc941968b3bc93e3f5709972f0ce23395eb65465fa23ddd68b8cb6ca52ddd0c"
    family = "AgentTesla"
    file_name = "PO101-07212006.exe"
    file_type = "exe"
    first_seen = "2026-07-22 00:05:45"
  condition:
    hash.sha256(0, filesize) == "6dc941968b3bc93e3f5709972f0ce23395eb65465fa23ddd68b8cb6ca52ddd0c"
}

rule MalwareBazaar_unknown_045_6cfe4697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cfe4697bd8bc1509ac9ce6db874c2f0c2dba396167f92e89953bf2c71ba002d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-22 00:04:28"
  condition:
    hash.sha256(0, filesize) == "6cfe4697bd8bc1509ac9ce6db874c2f0c2dba396167f92e89953bf2c71ba002d"
}

rule MalwareBazaar_unknown_046_e747deb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e747deb0d49a53cda8ebc02a97c5eeb875d6b5b07e1be8dfac5545adb78760f6"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Siggen33.1331.16114.201"
    file_type = "exe"
    first_seen = "2026-07-22 00:04:25"
  condition:
    hash.sha256(0, filesize) == "e747deb0d49a53cda8ebc02a97c5eeb875d6b5b07e1be8dfac5545adb78760f6"
}

rule MalwareBazaar_unknown_047_13ee006f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13ee006f629843e9d74482b9b6a5cc2a7deb7c343729e69bc92d5f10c0c1879d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 23:52:08"
  condition:
    hash.sha256(0, filesize) == "13ee006f629843e9d74482b9b6a5cc2a7deb7c343729e69bc92d5f10c0c1879d"
}

rule MalwareBazaar_unknown_048_839ac206
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839ac20629dbb94451871be5133dded462f9452a905b276fad46e4956e974277"
    family = "unknown"
    file_name = "agent_linux_amd64"
    file_type = "elf"
    first_seen = "2026-07-21 23:44:41"
  condition:
    hash.sha256(0, filesize) == "839ac20629dbb94451871be5133dded462f9452a905b276fad46e4956e974277"
}

rule MalwareBazaar_unknown_049_1e6df1d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e6df1d48fa798f8791b2a9473655f7bb91006c52e77f760c758850a57c8ab3a"
    family = "unknown"
    file_name = "agent_windows_amd64.exe"
    file_type = "exe"
    first_seen = "2026-07-21 23:43:53"
  condition:
    hash.sha256(0, filesize) == "1e6df1d48fa798f8791b2a9473655f7bb91006c52e77f760c758850a57c8ab3a"
}

rule MalwareBazaar_unknown_050_9c285fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c285fe3a491ee6a6f872ae71d47dfe29e44a40b9e7fcba85a39a2368584333a"
    family = "unknown"
    file_name = "agent_linux_amd64"
    file_type = "elf"
    first_seen = "2026-07-21 23:43:53"
  condition:
    hash.sha256(0, filesize) == "9c285fe3a491ee6a6f872ae71d47dfe29e44a40b9e7fcba85a39a2368584333a"
}

rule MalwareBazaar_unknown_051_4ff527e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ff527e0d8fc36a99a491bc69a9cabeb055a4be470e22ec3da8e8bb741be9efc"
    family = "unknown"
    file_name = "agent_windows_amd64.exe"
    file_type = "exe"
    first_seen = "2026-07-21 23:43:29"
  condition:
    hash.sha256(0, filesize) == "4ff527e0d8fc36a99a491bc69a9cabeb055a4be470e22ec3da8e8bb741be9efc"
}

rule MalwareBazaar_unknown_052_ba05cace
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba05cace3369229c81af123cce385c78295c642918327df7a14a547b158fda84"
    family = "unknown"
    file_name = "1FSL"
    file_type = "elf"
    first_seen = "2026-07-21 23:29:29"
  condition:
    hash.sha256(0, filesize) == "ba05cace3369229c81af123cce385c78295c642918327df7a14a547b158fda84"
}

rule MalwareBazaar_unknown_053_9d5db6a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d5db6a00c6ebf232c2b75d649e73b4eeb28b88d830059db3ecd041ed377ee77"
    family = "unknown"
    file_name = "PrA"
    file_type = "elf"
    first_seen = "2026-07-21 23:27:44"
  condition:
    hash.sha256(0, filesize) == "9d5db6a00c6ebf232c2b75d649e73b4eeb28b88d830059db3ecd041ed377ee77"
}

rule MalwareBazaar_Mirai_054_cd52cdfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd52cdfa71d798723e057c1d069edb77f4ed3e54ac7edc6e6a5a924d0567efe0"
    family = "Mirai"
    file_name = "4Hep"
    file_type = "elf"
    first_seen = "2026-07-21 23:27:43"
  condition:
    hash.sha256(0, filesize) == "cd52cdfa71d798723e057c1d069edb77f4ed3e54ac7edc6e6a5a924d0567efe0"
}

rule MalwareBazaar_unknown_055_5bcc88a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bcc88a01ec83f5fb45d0c329e6e16e8b6e74ffbb9b59d739507244604f16b53"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 23:10:26"
  condition:
    hash.sha256(0, filesize) == "5bcc88a01ec83f5fb45d0c329e6e16e8b6e74ffbb9b59d739507244604f16b53"
}

rule MalwareBazaar_unknown_056_3cad6c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cad6c354f21c3fc885fdb96f6f7d45fe25e66e0ee5ac435c54ad89fab93db70"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-21 23:09:26"
  condition:
    hash.sha256(0, filesize) == "3cad6c354f21c3fc885fdb96f6f7d45fe25e66e0ee5ac435c54ad89fab93db70"
}

rule MalwareBazaar_unknown_057_8319f644
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8319f644ea7e62f69665389100b0a35cd4c1a8dc8670934772271fcb33ba4576"
    family = "unknown"
    file_name = "arc"
    file_type = "sh"
    first_seen = "2026-07-21 22:59:48"
  condition:
    hash.sha256(0, filesize) == "8319f644ea7e62f69665389100b0a35cd4c1a8dc8670934772271fcb33ba4576"
}

rule MalwareBazaar_unknown_058_baa51e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baa51e381015b39cab7df22296f3e7fa754d323d1e820524ab92f596c625b1d9"
    family = "unknown"
    file_name = "co"
    file_type = "unknown"
    first_seen = "2026-07-21 22:57:57"
  condition:
    hash.sha256(0, filesize) == "baa51e381015b39cab7df22296f3e7fa754d323d1e820524ab92f596c625b1d9"
}

rule MalwareBazaar_unknown_059_b98a7822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b98a782207a2826f3e1482fc5c9adabd35018f96a1e01c07b072b979208a5503"
    family = "unknown"
    file_name = "y"
    file_type = "sh"
    first_seen = "2026-07-21 22:56:45"
  condition:
    hash.sha256(0, filesize) == "b98a782207a2826f3e1482fc5c9adabd35018f96a1e01c07b072b979208a5503"
}

rule MalwareBazaar_unknown_060_bfca8d58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfca8d582b0e243642dbb6f9cd945fc4f2c60d33e17062e8438c7820ac1372fa"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 22:52:09"
  condition:
    hash.sha256(0, filesize) == "bfca8d582b0e243642dbb6f9cd945fc4f2c60d33e17062e8438c7820ac1372fa"
}

rule MalwareBazaar_unknown_061_0f09c681
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f09c681e525e89b72c1a714c6cb52702aea52aa0db6217ea7a6886b3bf45894"
    family = "unknown"
    file_name = "tvCr"
    file_type = "elf"
    first_seen = "2026-07-21 22:42:26"
  condition:
    hash.sha256(0, filesize) == "0f09c681e525e89b72c1a714c6cb52702aea52aa0db6217ea7a6886b3bf45894"
}

rule MalwareBazaar_Mirai_062_bc56faa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc56faa396b8b6f6487e925a19c3cfa0a1daeaa36e774615db56a7664fa7ad4d"
    family = "Mirai"
    file_name = "xWr"
    file_type = "elf"
    first_seen = "2026-07-21 22:42:25"
  condition:
    hash.sha256(0, filesize) == "bc56faa396b8b6f6487e925a19c3cfa0a1daeaa36e774615db56a7664fa7ad4d"
}

rule MalwareBazaar_Mirai_063_62e51ed3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62e51ed3f589dc4463b830e736a7c161e33af159fe79a338affb20caaf548735"
    family = "Mirai"
    file_name = "6zq"
    file_type = "elf"
    first_seen = "2026-07-21 22:42:24"
  condition:
    hash.sha256(0, filesize) == "62e51ed3f589dc4463b830e736a7c161e33af159fe79a338affb20caaf548735"
}

rule MalwareBazaar_unknown_064_a9ff4fbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9ff4fbde5bb27981136ca2902000af76636fa327fdfcae50f3de411cbb9f5e1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 22:40:34"
  condition:
    hash.sha256(0, filesize) == "a9ff4fbde5bb27981136ca2902000af76636fa327fdfcae50f3de411cbb9f5e1"
}

rule MalwareBazaar_unknown_065_d8ee53ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8ee53ef0d9134184542e57c74109a45047a6de148226e73b8f6579a1f09a2e6"
    family = "unknown"
    file_name = "svc.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:37:49"
  condition:
    hash.sha256(0, filesize) == "d8ee53ef0d9134184542e57c74109a45047a6de148226e73b8f6579a1f09a2e6"
}

rule MalwareBazaar_unknown_066_8b50f23c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b50f23c7f09575224f6ff713d72b67382103f24d5c6e91ab2c74c556b729185"
    family = "unknown"
    file_name = "main.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:35:48"
  condition:
    hash.sha256(0, filesize) == "8b50f23c7f09575224f6ff713d72b67382103f24d5c6e91ab2c74c556b729185"
}

rule MalwareBazaar_ConnectWise_067_bbdb4e10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbdb4e10ba2e085d83eeb97b10efc6f446cf040cfd10deb0ee48c375f4805953"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:35:46"
  condition:
    hash.sha256(0, filesize) == "bbdb4e10ba2e085d83eeb97b10efc6f446cf040cfd10deb0ee48c375f4805953"
}

rule MalwareBazaar_unknown_068_bd9324f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd9324f4a2f381a9f17cea58e0bb4a43d56ae55478cea07854440d07cd7e1102"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 22:35:23"
  condition:
    hash.sha256(0, filesize) == "bd9324f4a2f381a9f17cea58e0bb4a43d56ae55478cea07854440d07cd7e1102"
}

rule MalwareBazaar_Mirai_069_b7b1d018
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7b1d0186b23713f11d0872ace4c43c109120c0c99f0b1f98051c546a1016d13"
    family = "Mirai"
    file_name = "tTd"
    file_type = "elf"
    first_seen = "2026-07-21 22:30:23"
  condition:
    hash.sha256(0, filesize) == "b7b1d0186b23713f11d0872ace4c43c109120c0c99f0b1f98051c546a1016d13"
}

rule MalwareBazaar_unknown_070_053f32ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "053f32ed6a86050a782b96a51e4194287fa9e7985b992f32a69aa06ee562f929"
    family = "unknown"
    file_name = "dNPT"
    file_type = "elf"
    first_seen = "2026-07-21 22:28:51"
  condition:
    hash.sha256(0, filesize) == "053f32ed6a86050a782b96a51e4194287fa9e7985b992f32a69aa06ee562f929"
}

rule MalwareBazaar_Mirai_071_a4a4f6bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4a4f6bb57b72bb64de6a93b8de5a114f265f2802c046695595355353e1509a5"
    family = "Mirai"
    file_name = "Wznp"
    file_type = "elf"
    first_seen = "2026-07-21 22:28:49"
  condition:
    hash.sha256(0, filesize) == "a4a4f6bb57b72bb64de6a93b8de5a114f265f2802c046695595355353e1509a5"
}

rule MalwareBazaar_ValleyRAT_072_310fcb28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310fcb28fd0a6616bea7db2a16414117507e449e0d7c27bf5fb1651b0e13ba7b"
    family = "ValleyRAT"
    file_name = "310fcb28fd0a6616bea7db2a16414117507e449e0d7c2.dll"
    file_type = "exe"
    first_seen = "2026-07-21 22:25:21"
  condition:
    hash.sha256(0, filesize) == "310fcb28fd0a6616bea7db2a16414117507e449e0d7c27bf5fb1651b0e13ba7b"
}

rule MalwareBazaar_N_W0rm_073_9236af4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9236af4b0d79c2cd99e098b7e599106d85f377af7f2cab91e2cf733bfaeea43b"
    family = "N-W0rm"
    file_name = "9236af4b0d79c2cd99e098b7e599106d85f377af7f2ca.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:25:17"
  condition:
    hash.sha256(0, filesize) == "9236af4b0d79c2cd99e098b7e599106d85f377af7f2cab91e2cf733bfaeea43b"
}

rule MalwareBazaar_DCRat_074_ad5a8f0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad5a8f0a70678395eee394dbe48b2508784e06f37e7a980f4bd61599d180360d"
    family = "DCRat"
    file_name = "22ce9b4f200c32eeb293116301e97307.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:25:14"
  condition:
    hash.sha256(0, filesize) == "ad5a8f0a70678395eee394dbe48b2508784e06f37e7a980f4bd61599d180360d"
}

rule MalwareBazaar_unknown_075_67a74645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67a7464500fdeba256b9f596b6308d0a84f91e7b2ac0b7f8192ce07c2804e874"
    family = "unknown"
    file_name = "PO#8700983.vbs"
    file_type = "unknown"
    first_seen = "2026-07-21 22:25:11"
  condition:
    hash.sha256(0, filesize) == "67a7464500fdeba256b9f596b6308d0a84f91e7b2ac0b7f8192ce07c2804e874"
}

rule MalwareBazaar_Adwind_076_18d22205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18d22205fc172fcb534505791d7b6ddb08d58fa31063be642e9fafb415ba3891"
    family = "Adwind"
    file_name = "QUOTATION #POPO996574620775800000.pdf.jar"
    file_type = "jar"
    first_seen = "2026-07-21 22:25:07"
  condition:
    hash.sha256(0, filesize) == "18d22205fc172fcb534505791d7b6ddb08d58fa31063be642e9fafb415ba3891"
}

rule MalwareBazaar_AsyncRAT_077_5fd49361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fd493615b731c767be670d33a4e48ec89ad264bf583c2b087d7645a4727986b"
    family = "AsyncRAT"
    file_name = "47E1B3A9FE7BD09242ACBCBD0D515DED.exe"
    file_type = "exe"
    first_seen = "2026-07-21 22:25:05"
  condition:
    hash.sha256(0, filesize) == "5fd493615b731c767be670d33a4e48ec89ad264bf583c2b087d7645a4727986b"
}

rule MalwareBazaar_unknown_078_ee5c5c69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee5c5c69bb1c0d961dff49dd3bcfcef923406e1c2d80b662b76c611cd6fb94a3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 22:04:53"
  condition:
    hash.sha256(0, filesize) == "ee5c5c69bb1c0d961dff49dd3bcfcef923406e1c2d80b662b76c611cd6fb94a3"
}

rule MalwareBazaar_unknown_079_243a16f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "243a16f7868aaac29db90690c5315a94e850b5e150dddc72814a2c064155324d"
    family = "unknown"
    file_name = "23N"
    file_type = "elf"
    first_seen = "2026-07-21 21:56:40"
  condition:
    hash.sha256(0, filesize) == "243a16f7868aaac29db90690c5315a94e850b5e150dddc72814a2c064155324d"
}

rule MalwareBazaar_Mirai_080_96d70bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96d70bdb604934486925179ec1113832e0492b8fc5048f4f1e0b3c30ea2891f6"
    family = "Mirai"
    file_name = "Chfd"
    file_type = "elf"
    first_seen = "2026-07-21 21:56:39"
  condition:
    hash.sha256(0, filesize) == "96d70bdb604934486925179ec1113832e0492b8fc5048f4f1e0b3c30ea2891f6"
}

rule MalwareBazaar_Mirai_081_e55977d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e55977d62b523894693b08e9a9113f777f3667ccb05d8c17f1fde6b46b46d959"
    family = "Mirai"
    file_name = "oDh"
    file_type = "elf"
    first_seen = "2026-07-21 21:55:19"
  condition:
    hash.sha256(0, filesize) == "e55977d62b523894693b08e9a9113f777f3667ccb05d8c17f1fde6b46b46d959"
}

rule MalwareBazaar_unknown_082_b3252776
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b32527764b33b7584ab9466b5c34efe0e4c24daf2e19e792ce2bca59bd3bc4f1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 21:52:08"
  condition:
    hash.sha256(0, filesize) == "b32527764b33b7584ab9466b5c34efe0e4c24daf2e19e792ce2bca59bd3bc4f1"
}

rule MalwareBazaar_Mirai_083_65600a05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65600a05592216cdef98173f4202b141dec19b2955e59dc518b2efc46f5969fc"
    family = "Mirai"
    file_name = "Z31w"
    file_type = "elf"
    first_seen = "2026-07-21 21:06:38"
  condition:
    hash.sha256(0, filesize) == "65600a05592216cdef98173f4202b141dec19b2955e59dc518b2efc46f5969fc"
}

rule MalwareBazaar_unknown_084_5606abbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5606abbe1c7877225704f709f95854ded5d384cbc06dc1a55230f31c26e485bd"
    family = "unknown"
    file_name = "K6U"
    file_type = "elf"
    first_seen = "2026-07-21 21:04:36"
  condition:
    hash.sha256(0, filesize) == "5606abbe1c7877225704f709f95854ded5d384cbc06dc1a55230f31c26e485bd"
}

rule MalwareBazaar_unknown_085_86a058d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86a058d461cdc5486430c2f6b1800235a8fbfdbe7d1af4af5d2d2d2f003c7634"
    family = "unknown"
    file_name = "03W7"
    file_type = "elf"
    first_seen = "2026-07-21 21:04:34"
  condition:
    hash.sha256(0, filesize) == "86a058d461cdc5486430c2f6b1800235a8fbfdbe7d1af4af5d2d2d2f003c7634"
}

rule MalwareBazaar_unknown_086_08916c59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08916c59ba59c089e9d1140b6efa03611785e5c40d907cbb797e0f958be2dc29"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-21 20:52:08"
  condition:
    hash.sha256(0, filesize) == "08916c59ba59c089e9d1140b6efa03611785e5c40d907cbb797e0f958be2dc29"
}

rule MalwareBazaar_Mirai_087_4977440d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4977440daf9c3c16cd86e641233a44c581c020ef538e7212e7b68eb4910ca7cd"
    family = "Mirai"
    file_name = "30HR"
    file_type = "elf"
    first_seen = "2026-07-21 20:51:55"
  condition:
    hash.sha256(0, filesize) == "4977440daf9c3c16cd86e641233a44c581c020ef538e7212e7b68eb4910ca7cd"
}

rule MalwareBazaar_Mirai_088_522f6221
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "522f6221c4e04ddffafba732722abba1b5000736d380bd779c67e6fe69f743e1"
    family = "Mirai"
    file_name = "Qlz"
    file_type = "elf"
    first_seen = "2026-07-21 20:51:54"
  condition:
    hash.sha256(0, filesize) == "522f6221c4e04ddffafba732722abba1b5000736d380bd779c67e6fe69f743e1"
}

rule MalwareBazaar_unknown_089_773fc40e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "773fc40e2f9d7576f597d501744e4397da0da71d4cbf1c05aeccf0b0e7048492"
    family = "unknown"
    file_name = "cHz"
    file_type = "elf"
    first_seen = "2026-07-21 20:51:53"
  condition:
    hash.sha256(0, filesize) == "773fc40e2f9d7576f597d501744e4397da0da71d4cbf1c05aeccf0b0e7048492"
}

rule MalwareBazaar_Mirai_090_34dcd1d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34dcd1d45a2d5021378d51deb542b6220cb203dd6711b369eeb4035c50f57016"
    family = "Mirai"
    file_name = "b7g"
    file_type = "elf"
    first_seen = "2026-07-21 20:37:28"
  condition:
    hash.sha256(0, filesize) == "34dcd1d45a2d5021378d51deb542b6220cb203dd6711b369eeb4035c50f57016"
}

rule MalwareBazaar_unknown_091_9539c6ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9539c6ce1df04714b2d3d44813611a6b7c39afa2be5a592ab9a16361d0a3445a"
    family = "unknown"
    file_name = "PYdl"
    file_type = "elf"
    first_seen = "2026-07-21 20:37:26"
  condition:
    hash.sha256(0, filesize) == "9539c6ce1df04714b2d3d44813611a6b7c39afa2be5a592ab9a16361d0a3445a"
}

rule MalwareBazaar_Mirai_092_70e4229a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70e4229a67b7459a9e361ac0e855130902239517766b2d0001277eb8d62d5a85"
    family = "Mirai"
    file_name = "hXz8"
    file_type = "elf"
    first_seen = "2026-07-21 20:35:40"
  condition:
    hash.sha256(0, filesize) == "70e4229a67b7459a9e361ac0e855130902239517766b2d0001277eb8d62d5a85"
}

rule MalwareBazaar_unknown_093_8c1654ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c1654ad1df9e9bf1c450657b12eb269d999934b83bbfdd59cbb886c6550f283"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-21 20:30:38"
  condition:
    hash.sha256(0, filesize) == "8c1654ad1df9e9bf1c450657b12eb269d999934b83bbfdd59cbb886c6550f283"
}

rule MalwareBazaar_unknown_094_ee727d63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee727d639eaa4ee2e0d7cafbe496e14aaac8df0955d9fb599f2c11dfa1d0f8f2"
    family = "unknown"
    file_name = "malware.msi"
    file_type = "msi"
    first_seen = "2026-07-21 20:18:39"
  condition:
    hash.sha256(0, filesize) == "ee727d639eaa4ee2e0d7cafbe496e14aaac8df0955d9fb599f2c11dfa1d0f8f2"
}

rule MalwareBazaar_unknown_095_46b426b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46b426b6e25231d731d7cb2822f1435f65778f168c9d838568e9012d3507abda"
    family = "unknown"
    file_name = "rnp.dll"
    file_type = "exe"
    first_seen = "2026-07-21 20:17:05"
  condition:
    hash.sha256(0, filesize) == "46b426b6e25231d731d7cb2822f1435f65778f168c9d838568e9012d3507abda"
}

rule MalwareBazaar_unknown_096_6e94135a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e94135ab277c29528467561e79cbacf505d6fe36808757b88a6449950614e64"
    family = "unknown"
    file_name = "ssJw"
    file_type = "elf"
    first_seen = "2026-07-21 20:16:22"
  condition:
    hash.sha256(0, filesize) == "6e94135ab277c29528467561e79cbacf505d6fe36808757b88a6449950614e64"
}

rule MalwareBazaar_Mirai_097_d71578b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d71578b74b7d7d6513292e2d4cae8e8518f49e321fbed3d2812a6712da7dc241"
    family = "Mirai"
    file_name = "hytC"
    file_type = "elf"
    first_seen = "2026-07-21 20:14:36"
  condition:
    hash.sha256(0, filesize) == "d71578b74b7d7d6513292e2d4cae8e8518f49e321fbed3d2812a6712da7dc241"
}

rule MalwareBazaar_Mirai_098_692757b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "692757b81ed8e5c17634d5c95e91d6201a9329e232281e8eda98d502ea821837"
    family = "Mirai"
    file_name = "KXV"
    file_type = "elf"
    first_seen = "2026-07-21 20:14:35"
  condition:
    hash.sha256(0, filesize) == "692757b81ed8e5c17634d5c95e91d6201a9329e232281e8eda98d502ea821837"
}

rule MalwareBazaar_Mirai_099_721d764d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "721d764d2d1985eefb42fee9e1e2f05d4f4f35bbec216b952cdad74b0ac90cd1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-21 20:05:19"
  condition:
    hash.sha256(0, filesize) == "721d764d2d1985eefb42fee9e1e2f05d4f4f35bbec216b952cdad74b0ac90cd1"
}

rule MalwareBazaar_unknown_100_d475c3ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d475c3caf477bd0e4aebbce33f062d4d42a3533e28b76d2ad23c709d013e7926"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-21 20:00:36"
  condition:
    hash.sha256(0, filesize) == "d475c3caf477bd0e4aebbce33f062d4d42a3533e28b76d2ad23c709d013e7926"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

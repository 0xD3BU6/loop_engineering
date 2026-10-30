# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-30

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 668 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 668 |
| Unique family labels | 9 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| SalatStealer | 46 |
| unknown | 28 |
| Mirai | 15 |
| GuLoader | 4 |
| WannaCry | 2 |
| OverlordRAT | 2 |
| RemcosRAT | 1 |
| Formbook | 1 |
| ConnectWise | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 59 |
| elf | 16 |
| macho | 12 |
| vbs | 5 |
| js | 2 |
| sh | 2 |
| py | 1 |
| cmd | 1 |
| zsh | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `5e002592660e4f81`

| Field | Value |
|---|---|
| SHA-256 | `5e002592660e4f81cbbc369c59bdeef59f75a0ada044178417f99197c14521af` |
| Family label | `GuLoader` |
| File name | `Bioclimatologies.vbs` |
| File type | `vbs` |
| First seen | `2026-10-30 05:45:01` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4aec8fa1dfc15e0815f6798c87babc01` |
| SHA-1 | `f1831d0bc53b15ec7a94e3bdad29ddbf84f2383a` |
| SHA-256 | `5e002592660e4f81cbbc369c59bdeef59f75a0ada044178417f99197c14521af` |
| SHA3-384 | `e03f0348c83fa797247d04676b05aa7c92fa56d2b58d6ee4e417b4bf76595f326de8c2a333e6d941993a932f96781f93` |
| TLSH | `T1AF83F530ED1009148E8E16FDA85D2D5D85F981DBD33900ECE9D8E2499E061BBBFBE356` |
| SSDEEP | `1536:Eaiws9mSQMP3qhgEjfBE4DEYf95KGFxMgMC7/+R+jmL8tsy+gs5pzE8nLCngNoBS:ECu7E1ai5SJyGkbtoIWakBPD` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_001_5e002592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e002592660e4f81cbbc369c59bdeef59f75a0ada044178417f99197c14521af"
    family = "GuLoader"
    file_name = "Bioclimatologies.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 05:45:01"
  condition:
    hash.sha256(0, filesize) == "5e002592660e4f81cbbc369c59bdeef59f75a0ada044178417f99197c14521af"
}
```

### Sample 2: `d95018b094979898`

| Field | Value |
|---|---|
| SHA-256 | `d95018b09497989840be69c39fff5bc4c98cfebefe0bb4733fcc8b195a647abd` |
| Family label | `SalatStealer` |
| File name | `c8cdca64a0d8ab3f.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:26:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af339d36b4b4357061118d36ee39d1d7` |
| SHA-1 | `5b027f2d48785379aa5eeec3d3174b1a5f560992` |
| SHA-256 | `d95018b09497989840be69c39fff5bc4c98cfebefe0bb4733fcc8b195a647abd` |
| SHA3-384 | `32e6471b4c2a5ab65868c2f0e336d4ca0bcf87ae85d9ed71ce3e664225673666179a1a8254c55140fb10f753e19e4cdf` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E1C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+s:yBkKr5rszpNDy+s` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_002_d95018b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95018b09497989840be69c39fff5bc4c98cfebefe0bb4733fcc8b195a647abd"
    family = "SalatStealer"
    file_name = "c8cdca64a0d8ab3f.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:26:59"
  condition:
    hash.sha256(0, filesize) == "d95018b09497989840be69c39fff5bc4c98cfebefe0bb4733fcc8b195a647abd"
}
```

### Sample 3: `0886fff0dd90b3ed`

| Field | Value |
|---|---|
| SHA-256 | `0886fff0dd90b3ed167d7b8f0bce41108582d6e773f19049a32816ffc34800a8` |
| Family label | `SalatStealer` |
| File name | `75481e44b026106c.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:26:50` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `924169f8788b0ff18f76851171d25459` |
| SHA-1 | `2ab69f186c89ae3eeae03ff2c6855f1a06a56f91` |
| SHA-256 | `0886fff0dd90b3ed167d7b8f0bce41108582d6e773f19049a32816ffc34800a8` |
| SHA3-384 | `88e3cb537d73d1d4f4a986f1d38a9f9902bacf70a9c8c1449f1917b7b2690cdb8ccfdafdef31ab864c401aee4e709ed1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E8C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+8:yBkKr5rszpNDy+8` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_003_0886fff0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0886fff0dd90b3ed167d7b8f0bce41108582d6e773f19049a32816ffc34800a8"
    family = "SalatStealer"
    file_name = "75481e44b026106c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:26:50"
  condition:
    hash.sha256(0, filesize) == "0886fff0dd90b3ed167d7b8f0bce41108582d6e773f19049a32816ffc34800a8"
}
```

### Sample 4: `b68881372c797ff5`

| Field | Value |
|---|---|
| SHA-256 | `b68881372c797ff50184731c060e0e63e85850d5a44f468b778a38f62329f8b5` |
| Family label | `SalatStealer` |
| File name | `6dad3f2bba6b2da7.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:26:39` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `237e18bfc3dd04e2b033a8dfe01e13da` |
| SHA-1 | `fbaf3f0ae9a9be6b0276be683a52d1b4ddb31a28` |
| SHA-256 | `b68881372c797ff50184731c060e0e63e85850d5a44f468b778a38f62329f8b5` |
| SHA3-384 | `ade075d35b33eddae625b61682b56a6417c8062d5eaf3df7259779bde9eac4c4bc07fb1dc5346cf32fda654db35baab1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T111C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+p:yBkKr5rszpNDy+p` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_004_b6888137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b68881372c797ff50184731c060e0e63e85850d5a44f468b778a38f62329f8b5"
    family = "SalatStealer"
    file_name = "6dad3f2bba6b2da7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:26:39"
  condition:
    hash.sha256(0, filesize) == "b68881372c797ff50184731c060e0e63e85850d5a44f468b778a38f62329f8b5"
}
```

### Sample 5: `8f53fd954525f1e9`

| Field | Value |
|---|---|
| SHA-256 | `8f53fd954525f1e941eb7ccd6244ec0ea03f2209a96ec48f65b2e72e8200d684` |
| Family label | `SalatStealer` |
| File name | `d193e33c97583d36.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9041b8656311e50f3f56e6fa4baecb6` |
| SHA-1 | `3f341e734f9fde9af1165602a5be409483a37497` |
| SHA-256 | `8f53fd954525f1e941eb7ccd6244ec0ea03f2209a96ec48f65b2e72e8200d684` |
| SHA3-384 | `d28d83cabcac258336d8ca1310ccb9e8948113403471967b0d4197d7f7f6ec4ae5ac6fb850499673f9c15223d2acbf3f` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T10AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+K:yBkKr5rszpNDy+K` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_005_8f53fd95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f53fd954525f1e941eb7ccd6244ec0ea03f2209a96ec48f65b2e72e8200d684"
    family = "SalatStealer"
    file_name = "d193e33c97583d36.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:59"
  condition:
    hash.sha256(0, filesize) == "8f53fd954525f1e941eb7ccd6244ec0ea03f2209a96ec48f65b2e72e8200d684"
}
```

### Sample 6: `620659195b33b307`

| Field | Value |
|---|---|
| SHA-256 | `620659195b33b307299a439e28a8398c4221627c1df14e7c89b9dea39897e44f` |
| Family label | `SalatStealer` |
| File name | `771670ebf0cba43b.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:53` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecec9b5b6a9448a6720dc15d6db0c6d4` |
| SHA-1 | `0548ae7802ee161b03a7e7634dceca512c9450f7` |
| SHA-256 | `620659195b33b307299a439e28a8398c4221627c1df14e7c89b9dea39897e44f` |
| SHA3-384 | `8103570904c72d550b992787a9dc3b9df649918d04424248c4df852791bbca7aa6dfdf4a8a7c78aa8c62d6df349d19f6` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A6C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+d:yBkKr5rszpNDy+d` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_006_62065919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "620659195b33b307299a439e28a8398c4221627c1df14e7c89b9dea39897e44f"
    family = "SalatStealer"
    file_name = "771670ebf0cba43b.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:53"
  condition:
    hash.sha256(0, filesize) == "620659195b33b307299a439e28a8398c4221627c1df14e7c89b9dea39897e44f"
}
```

### Sample 7: `c8cdca64a0d8ab3f`

| Field | Value |
|---|---|
| SHA-256 | `c8cdca64a0d8ab3f6c44196563509091c65b0bfa66f101c49f320a5df929c4c8` |
| Family label | `SalatStealer` |
| File name | `c8cdca64a0d8ab3f.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `947523caca6b733b16312da977c5bf76` |
| SHA-1 | `53fa3d1513ace85c4ba55fbcdbe47b2838c52efa` |
| SHA-256 | `c8cdca64a0d8ab3f6c44196563509091c65b0bfa66f101c49f320a5df929c4c8` |
| SHA3-384 | `0c59c99ca2985a9a0477906668595e9af437ceeb0245db4e100e613865a77bc305bbe068cc712e543bec320d49049452` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1FEF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OY:iJiafuIO7rhWEES4z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_007_c8cdca64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8cdca64a0d8ab3f6c44196563509091c65b0bfa66f101c49f320a5df929c4c8"
    family = "SalatStealer"
    file_name = "c8cdca64a0d8ab3f.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:48"
  condition:
    hash.sha256(0, filesize) == "c8cdca64a0d8ab3f6c44196563509091c65b0bfa66f101c49f320a5df929c4c8"
}
```

### Sample 8: `8484b5d5e7ab96ec`

| Field | Value |
|---|---|
| SHA-256 | `8484b5d5e7ab96ec903699bff316e3ba82b192b874b70e97a9a034f58c863712` |
| Family label | `SalatStealer` |
| File name | `2daf5f51807550ef.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:47` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28ff4b3ea552a10d058dea1ad12108a9` |
| SHA-1 | `388b148f68e436c98322397827008dff993389ad` |
| SHA-256 | `8484b5d5e7ab96ec903699bff316e3ba82b192b874b70e97a9a034f58c863712` |
| SHA3-384 | `622f787359989adcbd96d327ce12ce5b565031763f4643cc35681b52c56dff704eec87176b47f90d547f9d0ef45878b1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A0C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+S:yBkKr5rszpNDy+S` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_008_8484b5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8484b5d5e7ab96ec903699bff316e3ba82b192b874b70e97a9a034f58c863712"
    family = "SalatStealer"
    file_name = "2daf5f51807550ef.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:47"
  condition:
    hash.sha256(0, filesize) == "8484b5d5e7ab96ec903699bff316e3ba82b192b874b70e97a9a034f58c863712"
}
```

### Sample 9: `870b4e6a56890671`

| Field | Value |
|---|---|
| SHA-256 | `870b4e6a56890671098629b17ac2c55396aed7edc041a4e628801397315d5fa4` |
| Family label | `SalatStealer` |
| File name | `b592a23662fd9db7.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:40` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3038faf01f75db3035c21499f14041c` |
| SHA-1 | `f1c3c47ae2143dd8112e1587449733d10cfd7b85` |
| SHA-256 | `870b4e6a56890671098629b17ac2c55396aed7edc041a4e628801397315d5fa4` |
| SHA3-384 | `bc6f967edb530e0252a48d634d89a3961adc8f08045e4824bc466b61ed4075a845b3a4f221ee700142ffb962759841ee` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1CAC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+g:yBkKr5rszpNDy+g` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_009_870b4e6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870b4e6a56890671098629b17ac2c55396aed7edc041a4e628801397315d5fa4"
    family = "SalatStealer"
    file_name = "b592a23662fd9db7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:40"
  condition:
    hash.sha256(0, filesize) == "870b4e6a56890671098629b17ac2c55396aed7edc041a4e628801397315d5fa4"
}
```

### Sample 10: `75481e44b026106c`

| Field | Value |
|---|---|
| SHA-256 | `75481e44b026106cc688fffe05e08d0593c133f0cb505b69f0987542fd89cdd3` |
| Family label | `SalatStealer` |
| File name | `75481e44b026106c.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63c4ba6a295a732b1a486b1f67a89cdd` |
| SHA-1 | `8a1753d8e4b06d53b8fc7ae501116b6ad3d74144` |
| SHA-256 | `75481e44b026106cc688fffe05e08d0593c133f0cb505b69f0987542fd89cdd3` |
| SHA3-384 | `4cee8e451bfee2ff7808f78ade6c61f4944279e8c86e61bf5633cb5780618416aac8c53932ade1897ef2a84dc1b9cef0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C5F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ow:iJiafuIO7rhWEES4P` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_010_75481e44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75481e44b026106cc688fffe05e08d0593c133f0cb505b69f0987542fd89cdd3"
    family = "SalatStealer"
    file_name = "75481e44b026106c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:38"
  condition:
    hash.sha256(0, filesize) == "75481e44b026106cc688fffe05e08d0593c133f0cb505b69f0987542fd89cdd3"
}
```

### Sample 11: `376ea4423d3a38db`

| Field | Value |
|---|---|
| SHA-256 | `376ea4423d3a38dbe09aab41362b84a6213b57a6146ade2ce817ec4c15d2db7f` |
| Family label | `SalatStealer` |
| File name | `57d55ef78975070a.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c5d053d9e4f06bf0667f9bb8b35f5a6` |
| SHA-1 | `51c7c3c2e2c7f127158a9d583ee7e875a12d5cc9` |
| SHA-256 | `376ea4423d3a38dbe09aab41362b84a6213b57a6146ade2ce817ec4c15d2db7f` |
| SHA3-384 | `6e34a8b713a8921e2588ab3b7b741829b184232d60d9417f39a819966bc10b0e9251a19407597c12561fef6911e1f479` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T12AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+f:yBkKr5rszpNDy+f` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_011_376ea442
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "376ea4423d3a38dbe09aab41362b84a6213b57a6146ade2ce817ec4c15d2db7f"
    family = "SalatStealer"
    file_name = "57d55ef78975070a.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:33"
  condition:
    hash.sha256(0, filesize) == "376ea4423d3a38dbe09aab41362b84a6213b57a6146ade2ce817ec4c15d2db7f"
}
```

### Sample 12: `6dad3f2bba6b2da7`

| Field | Value |
|---|---|
| SHA-256 | `6dad3f2bba6b2da7c7ad7e04f6f68259f17930c5bfb3eaa5c17c0209ba8e234a` |
| Family label | `SalatStealer` |
| File name | `6dad3f2bba6b2da7.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:28` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6fe9b96c0163e133ca8357234a1101e` |
| SHA-1 | `e03fc48cc2647497f0dba7456a81be07e611e4f5` |
| SHA-256 | `6dad3f2bba6b2da7c7ad7e04f6f68259f17930c5bfb3eaa5c17c0209ba8e234a` |
| SHA3-384 | `4fc86d9a10235cbab04c934a9ff1845d88c10279484f73b701fdf7e9a64214ee29ce56cc2e7cdf40f0af5b9a61e03bb3` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14DF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ot:iJiafuIO7rhWEES4i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_012_6dad3f2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dad3f2bba6b2da7c7ad7e04f6f68259f17930c5bfb3eaa5c17c0209ba8e234a"
    family = "SalatStealer"
    file_name = "6dad3f2bba6b2da7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:28"
  condition:
    hash.sha256(0, filesize) == "6dad3f2bba6b2da7c7ad7e04f6f68259f17930c5bfb3eaa5c17c0209ba8e234a"
}
```

### Sample 13: `d193e33c97583d36`

| Field | Value |
|---|---|
| SHA-256 | `d193e33c97583d368b16c384c9cd266828ebb4d910c5e9713e0c6bc2ed95a3dc` |
| Family label | `SalatStealer` |
| File name | `d193e33c97583d36.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `253ee8ccbfd20af8fca4eed0194e9fc8` |
| SHA-1 | `6c08f19ff8c1cfad6c7198f2a78d84ff4af2d476` |
| SHA-256 | `d193e33c97583d368b16c384c9cd266828ebb4d910c5e9713e0c6bc2ed95a3dc` |
| SHA3-384 | `43b424ec6e7a658c09a02603ff0fbf6f4f9669000e4a0a644a969300965f27e449199cc065b0ca394d6a939a3dfe61a7` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T188F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ou:iJiafuIO7rhWEES49` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_013_d193e33c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d193e33c97583d368b16c384c9cd266828ebb4d910c5e9713e0c6bc2ed95a3dc"
    family = "SalatStealer"
    file_name = "d193e33c97583d36.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:18"
  condition:
    hash.sha256(0, filesize) == "d193e33c97583d368b16c384c9cd266828ebb4d910c5e9713e0c6bc2ed95a3dc"
}
```

### Sample 14: `641f902317c84654`

| Field | Value |
|---|---|
| SHA-256 | `641f902317c84654c988c224abfd1c54671db7bcd56f0bda0c6a230f7292b114` |
| Family label | `RemcosRAT` |
| File name | `Purchase Order.JS.js` |
| File type | `js` |
| First seen | `2026-10-30 05:25:09` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0eb78c4a0dbdbedea9d7ae2a752748b` |
| SHA-1 | `d61a5627ca99616c8a9ff4e545f10bc58cb1e947` |
| SHA-256 | `641f902317c84654c988c224abfd1c54671db7bcd56f0bda0c6a230f7292b114` |
| SHA3-384 | `ac713f1fdff6009ee6a9d39d579dd3935c523772783634f4abb271c3392af1fde1cb7c9bc408d2abca3eda304501157c` |
| TLSH | `T16A36D3451FC7F6327B21AB5C5237C922994A689319C6CF3D386CD218F75CC4BA358AE2` |
| SSDEEP | `98304:GXmOO5P7OOoLMMKDt2VbOkgWPmcs+ZuZ7H+Yczgabz+crljqFfg/XVaTVJf8XYfj:D3R7OoDtxzGZytH9czgabRrljqFfUXVu` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_014_641f9023
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "641f902317c84654c988c224abfd1c54671db7bcd56f0bda0c6a230f7292b114"
    family = "RemcosRAT"
    file_name = "Purchase Order.JS.js"
    file_type = "js"
    first_seen = "2026-10-30 05:25:09"
  condition:
    hash.sha256(0, filesize) == "641f902317c84654c988c224abfd1c54671db7bcd56f0bda0c6a230f7292b114"
}
```

### Sample 15: `771670ebf0cba43b`

| Field | Value |
|---|---|
| SHA-256 | `771670ebf0cba43bc47449e8f40c892c232d93a45442f6cf1c72dc77053adb21` |
| Family label | `SalatStealer` |
| File name | `771670ebf0cba43b.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:25:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c35068df0dfca627f225ec49d282e77c` |
| SHA-1 | `2e07af730fe6f24cb768231f93d1b1563367fc0c` |
| SHA-256 | `771670ebf0cba43bc47449e8f40c892c232d93a45442f6cf1c72dc77053adb21` |
| SHA3-384 | `6c50b2782c74e3bd9516ebbab86cd074b280768e29fe46093d210b53227eb8bdfb4c59e6ad1eadd9b1da4d07f5dcd056` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1B5F5335BF5AB47B3F7D9A831560FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oh:iJiafuIO7rhWEES4A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_015_771670eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "771670ebf0cba43bc47449e8f40c892c232d93a45442f6cf1c72dc77053adb21"
    family = "SalatStealer"
    file_name = "771670ebf0cba43b.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:08"
  condition:
    hash.sha256(0, filesize) == "771670ebf0cba43bc47449e8f40c892c232d93a45442f6cf1c72dc77053adb21"
}
```

### Sample 16: `2daf5f51807550ef`

| Field | Value |
|---|---|
| SHA-256 | `2daf5f51807550efe14cfb6cd99eb305f2b1bd6e726404335ed61267d6f8603a` |
| Family label | `SalatStealer` |
| File name | `2daf5f51807550ef.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:24:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f783ff7670b84a44e4f837225176c18` |
| SHA-1 | `2f001b3467e0c8234f78b847ee7007ea2357889e` |
| SHA-256 | `2daf5f51807550efe14cfb6cd99eb305f2b1bd6e726404335ed61267d6f8603a` |
| SHA3-384 | `7ec958cc4848892a19cfd8e08c40607ab806eaba707034ebb168790ad02d79f46975658c626fd0ab32d77ac135d810ef` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C7F5335BF1AF47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Om:iJiafuIO7rhWEES4R` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_016_2daf5f51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2daf5f51807550efe14cfb6cd99eb305f2b1bd6e726404335ed61267d6f8603a"
    family = "SalatStealer"
    file_name = "2daf5f51807550ef.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:24:58"
  condition:
    hash.sha256(0, filesize) == "2daf5f51807550efe14cfb6cd99eb305f2b1bd6e726404335ed61267d6f8603a"
}
```

### Sample 17: `b592a23662fd9db7`

| Field | Value |
|---|---|
| SHA-256 | `b592a23662fd9db7b33d1c92a8ddf2d35a7709e94fc5b9fafbac609540ff76e1` |
| Family label | `SalatStealer` |
| File name | `b592a23662fd9db7.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:24:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0abbe5ab4442eeea5127643df151d593` |
| SHA-1 | `fd7d92249314523d6b620786106e21ecac635da4` |
| SHA-256 | `b592a23662fd9db7b33d1c92a8ddf2d35a7709e94fc5b9fafbac609540ff76e1` |
| SHA3-384 | `abc60b030ccc769292f277024674b427ab32a3d52350c4752272a723e02a448df9882c5a30c46bc64feb3d59798f91ac` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1BBF5335BF1AB47B3F7D9A935560FC66458B09FE40A20D38AD4DBAA9F0882FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OU:iJiafuIO7rhWEES4t` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_017_b592a236
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b592a23662fd9db7b33d1c92a8ddf2d35a7709e94fc5b9fafbac609540ff76e1"
    family = "SalatStealer"
    file_name = "b592a23662fd9db7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:24:48"
  condition:
    hash.sha256(0, filesize) == "b592a23662fd9db7b33d1c92a8ddf2d35a7709e94fc5b9fafbac609540ff76e1"
}
```

### Sample 18: `57d55ef78975070a`

| Field | Value |
|---|---|
| SHA-256 | `57d55ef78975070a9a4147756d213185d9dea0a0170536767cd0b9988715fafb` |
| Family label | `SalatStealer` |
| File name | `57d55ef78975070a.bin` |
| File type | `exe` |
| First seen | `2026-10-30 05:24:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59207ca63e98fe99a26de12dab5a9877` |
| SHA-1 | `e91192c917ecaa466ff80ec53b38c903a2c7d7ab` |
| SHA-256 | `57d55ef78975070a9a4147756d213185d9dea0a0170536767cd0b9988715fafb` |
| SHA3-384 | `be87f603971a9d20cd62ff579e33cb0becc0e795a1ffde09de013d5a9eb047aed338788e6846e8a8641a33f324471391` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1FCF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OD:iJiafuIO7rhWEES4w` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_018_57d55ef7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57d55ef78975070a9a4147756d213185d9dea0a0170536767cd0b9988715fafb"
    family = "SalatStealer"
    file_name = "57d55ef78975070a.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:24:38"
  condition:
    hash.sha256(0, filesize) == "57d55ef78975070a9a4147756d213185d9dea0a0170536767cd0b9988715fafb"
}
```

### Sample 19: `0c32e41265d77469`

| Field | Value |
|---|---|
| SHA-256 | `0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d` |
| Family label | `unknown` |
| File name | `0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d.sh` |
| File type | `sh` |
| First seen | `2026-10-30 04:59:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfc21a4b46a2e29f804f7ae8ba8a06e7` |
| SHA-1 | `811e556ac2bc14acc59a1f319f2ded371177b9cb` |
| SHA-256 | `0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d` |
| SHA3-384 | `c2f51292f7b3a70a473f139eea7cc1def3442329622b2ec34f8c1c56d20977a6959486c3d309cae9ae409de3eae82c2f` |
| TLSH | `T16752773720F18B7397D064C8A27A0A614EB2D61B456620B8F4FE27356F5DA0375E7B21` |
| SSDEEP | `384:fJp4hvZ5m5FGGoKNpivJWQCGCndIgDIos:xpUiVN8J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_0c32e412
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d"
    family = "unknown"
    file_name = "0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d.sh"
    file_type = "sh"
    first_seen = "2026-10-30 04:59:26"
  condition:
    hash.sha256(0, filesize) == "0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d"
}
```

### Sample 20: `c3eec7ca615e2891`

| Field | Value |
|---|---|
| SHA-256 | `c3eec7ca615e28918446d87032d4630279a77979a8e863cc43456b109d664d48` |
| Family label | `unknown` |
| File name | `macho_c3eec7ca615e.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:59:23` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a1fd48d11240cfe77f82329f3e349c5` |
| SHA-1 | `64203163a8872b226267b61261359d59b2f82ebb` |
| SHA-256 | `c3eec7ca615e28918446d87032d4630279a77979a8e863cc43456b109d664d48` |
| SHA3-384 | `5728daf58512870e84a9690382fad9cdc7322c16ed689aa17439d361b1a857c503c7244aa6f42e62f0091ea68d20e79f` |
| TLSH | `T1BE85F1602AB20166EC526473DE390F0150A0AFE36AD8F7F66762C6075D33693B5BB317` |
| SSDEEP | `24576:zYZxCYu5CYWguX7x85fQk+bDWBYDg3StJ0RVcoSeaVkesLyXUToV+Qc+VFyFwnYM:hYukrLMoRWQtJ0RVlBaGQEER1yMth` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_c3eec7ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3eec7ca615e28918446d87032d4630279a77979a8e863cc43456b109d664d48"
    family = "unknown"
    file_name = "macho_c3eec7ca615e.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:59:23"
  condition:
    hash.sha256(0, filesize) == "c3eec7ca615e28918446d87032d4630279a77979a8e863cc43456b109d664d48"
}
```

### Sample 21: `2e3305a363e07974`

| Field | Value |
|---|---|
| SHA-256 | `2e3305a363e07974160046dfc9d033f88697dccbdb54a41ce15cfe6ee8648580` |
| Family label | `unknown` |
| File name | `macho_2e3305a363e0.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:54:40` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6a447035296404f29db0ed9e3383f7d` |
| SHA-1 | `005e17868415799e7814dab29ad9a0616b104b95` |
| SHA-256 | `2e3305a363e07974160046dfc9d033f88697dccbdb54a41ce15cfe6ee8648580` |
| SHA3-384 | `ea66d56f000bb430e2c0c7d5cc9d8df8a878e91513a1198eef81820b1a903696658e3b72de0e5e5d93c36c8b93807998` |
| TLSH | `T1ECA5E0404E9EA217D48910B39C9B8F5A447432A0CE88DDD95306A3DADE3D3D37B672B7` |
| SSDEEP | `49152:oUjBGdZ6/YzeMg9shY2Gyrq4FBl40csssXw5sSCAch24sXE86KAAFK6FxynZiU7q:okE56` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_2e3305a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e3305a363e07974160046dfc9d033f88697dccbdb54a41ce15cfe6ee8648580"
    family = "unknown"
    file_name = "macho_2e3305a363e0.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:54:40"
  condition:
    hash.sha256(0, filesize) == "2e3305a363e07974160046dfc9d033f88697dccbdb54a41ce15cfe6ee8648580"
}
```

### Sample 22: `03a680cd8b8c2323`

| Field | Value |
|---|---|
| SHA-256 | `03a680cd8b8c2323d4f78bf578220aec930188a98143b3878160f0d9b8335b40` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-10-30 04:53:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baba5c766fa348b62aab027e703d3fcc` |
| SHA-1 | `30dd5dcc91b4204281dd31af47ab8fac015d0e8b` |
| SHA-256 | `03a680cd8b8c2323d4f78bf578220aec930188a98143b3878160f0d9b8335b40` |
| SHA3-384 | `a2e0f3d63b4149b8c441a0a8d3d12d4a481ee844f70fc9578369e939b60edb8566926ecb6468a871a897a3e21cc8afd1` |
| TLSH | `T13024CFA3F71B2490DC6106F41BCB076D2AA321028D5FD5F3782E79366B674DF29267A0` |
| SSDEEP | `6144:yF9AenM82zog0L60ks/zbpNvuOpCsyIo93q:ybAekzB0fksfpQJz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_03a680cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03a680cd8b8c2323d4f78bf578220aec930188a98143b3878160f0d9b8335b40"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-10-30 04:53:57"
  condition:
    hash.sha256(0, filesize) == "03a680cd8b8c2323d4f78bf578220aec930188a98143b3878160f0d9b8335b40"
}
```

### Sample 23: `25d276912d13fe51`

| Field | Value |
|---|---|
| SHA-256 | `25d276912d13fe510558f6e4382bd4cfd4b94cdfa84f5080dfee082cdc5fdcc4` |
| Family label | `unknown` |
| File name | `.16` |
| File type | `elf` |
| First seen | `2026-10-30 04:50:24` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ada204aa3fccd0414f309c3b5c63a632` |
| SHA-1 | `64f536c57ac3969d8a124dbf921485b8ac19df05` |
| SHA-256 | `25d276912d13fe510558f6e4382bd4cfd4b94cdfa84f5080dfee082cdc5fdcc4` |
| SHA3-384 | `d8bc54bea86fab13851f136ee5cda3b0209fc533e60a0d7a2e20e02d97d4881aad5576a2e30e00b0c881d7e7bdf986ee` |
| TLSH | `T15E455A1BB59250FDC1E6D070879B9233AA32B49952347E7F22C4AF312E26F20675DF61` |
| SSDEEP | `24576:MOWkFlK+FsHoFSMdVnFmyJJd0qO/49CIIe2q:MOpFRF8oFPvnl50p+0eX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_25d27691
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25d276912d13fe510558f6e4382bd4cfd4b94cdfa84f5080dfee082cdc5fdcc4"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-10-30 04:50:24"
  condition:
    hash.sha256(0, filesize) == "25d276912d13fe510558f6e4382bd4cfd4b94cdfa84f5080dfee082cdc5fdcc4"
}
```

### Sample 24: `fa0007391da2cbd9`

| Field | Value |
|---|---|
| SHA-256 | `fa0007391da2cbd9c0b15937f1ce0e389f4d2d7f392f50331a4e831d2516834c` |
| Family label | `unknown` |
| File name | `.16` |
| File type | `elf` |
| First seen | `2026-10-30 04:50:07` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c4cbb5a0f3f8a5b44e0302a0a922a3e` |
| SHA-1 | `7338b636bae38ef29335a5643102d34143c9517d` |
| SHA-256 | `fa0007391da2cbd9c0b15937f1ce0e389f4d2d7f392f50331a4e831d2516834c` |
| SHA3-384 | `4dcfaca8afeb89b3dc3e9785fb3b3ae94378c1db054ea3c3aeca1e1f6df966ec99800a5e0d16229ba5c03b0cd64ca1e6` |
| TLSH | `T153F34A2BB98184FDC0E5E1704BEFF523E922F99582343A1F26D41B411F29F21A75EB52` |
| SSDEEP | `3072:i82SfUvjjFknboK02OOPi3klLcOSTDbrpzUMLrfXCMdZgFaLQIgpu:MqUFub42OSuLvpQMnXdgE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_fa000739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa0007391da2cbd9c0b15937f1ce0e389f4d2d7f392f50331a4e831d2516834c"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-10-30 04:50:07"
  condition:
    hash.sha256(0, filesize) == "fa0007391da2cbd9c0b15937f1ce0e389f4d2d7f392f50331a4e831d2516834c"
}
```

### Sample 25: `2a93e929b69caa6d`

| Field | Value |
|---|---|
| SHA-256 | `2a93e929b69caa6dc56901cda012b0073d83a4682a025193a0fc7234fedff83f` |
| Family label | `unknown` |
| File name | `macho_2a93e929b69c.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:49:56` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95912603371324f18c05ad817a3af74c` |
| SHA-1 | `e85c0bf89102371b2f6f0c1c7c11a9b88c64fa08` |
| SHA-256 | `2a93e929b69caa6dc56901cda012b0073d83a4682a025193a0fc7234fedff83f` |
| SHA3-384 | `725cac9eaa0afe4def21593b6c64e737be371d006e0b7ff3fb005ed1d4d79233690e383c7da259b9f25b5d16c4eb18f8` |
| TLSH | `T10795E014525F5179D4823432EC240FBA50E0BDD26988FFF963B6DB276C3E642B6A3361` |
| SSDEEP | `24576:SY/krk80vm8DL97AFfTEPMxHwvQjX9nuw9nJ/jj8AkP2MfrZcWJYxyxl8HwzX9/L:fkrgMavuJBf8X26CO4ywHmtL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_2a93e929
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a93e929b69caa6dc56901cda012b0073d83a4682a025193a0fc7234fedff83f"
    family = "unknown"
    file_name = "macho_2a93e929b69c.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:49:56"
  condition:
    hash.sha256(0, filesize) == "2a93e929b69caa6dc56901cda012b0073d83a4682a025193a0fc7234fedff83f"
}
```

### Sample 26: `905e2e48e90e0d4a`

| Field | Value |
|---|---|
| SHA-256 | `905e2e48e90e0d4aa332e7c39e9d7a41407fdc5bc78bad14c46294ec5c08b784` |
| Family label | `unknown` |
| File name | `905e2e48e90e0d4a.py` |
| File type | `py` |
| First seen | `2026-10-30 04:48:14` |
| Reporter | `Tuxxin` |
| Tags | `EtherSnake, py` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94b79c4a60864b05ddcbab2f619df1b9` |
| SHA-1 | `b5490b2fad8512fb769a6eb5966bfc68fed591da` |
| SHA-256 | `905e2e48e90e0d4aa332e7c39e9d7a41407fdc5bc78bad14c46294ec5c08b784` |
| SHA3-384 | `de074ab9136e5ab742cd77edf7f6d629f9ccf986c2c54fee8db8dd7e967e5ceb961f64613a2f1a149cc0dbd5ac870b7e` |
| TLSH | `T150E0C0B186BD0CBEC3A2F62DCA0122E313D5A566C20660035F24B2B4C0864F9B464FC0` |
| SSDEEP | `6:a6CHaTNHcrHXQ0TvfWXlewDMVSAXFuR+FDWFMctA8viH1fdDB5YLKVoSRghLd1JP:pCeN8XXvf/wDMVHuMqFMctA8uVfNrRgr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `py`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_905e2e48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "905e2e48e90e0d4aa332e7c39e9d7a41407fdc5bc78bad14c46294ec5c08b784"
    family = "unknown"
    file_name = "905e2e48e90e0d4a.py"
    file_type = "py"
    first_seen = "2026-10-30 04:48:14"
  condition:
    hash.sha256(0, filesize) == "905e2e48e90e0d4aa332e7c39e9d7a41407fdc5bc78bad14c46294ec5c08b784"
}
```

### Sample 27: `61d6b309d9774d13`

| Field | Value |
|---|---|
| SHA-256 | `61d6b309d9774d13d632322816260e082f96293087333e7a379310e7b0796be0` |
| Family label | `unknown` |
| File name | `61d6b309d9774d13.vbs` |
| File type | `vbs` |
| First seen | `2026-10-30 04:48:05` |
| Reporter | `Tuxxin` |
| Tags | `EtherSnake, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6f7e0c809407421b65a41a3dfc92ceb` |
| SHA-1 | `8678101ba3a71470904ae125816b8e8f7235754c` |
| SHA-256 | `61d6b309d9774d13d632322816260e082f96293087333e7a379310e7b0796be0` |
| SHA3-384 | `bc6eb68a9a26b4f313fa34d7b6de49bb23ffb5c9a5805a5dfddf2c619d37897f20d057bcfc2dbe97e81b0a7ada6346bd` |
| TLSH | `T144D0221EFC09EC63035A002314B2DC8FEF808738F00680F87E0ECCE435045080E82812` |
| SSDEEP | `3:iFcXM7Bs7ZF2AISJRhNKMmRm8nhMFQLFnFZ3BsO+HHHHFZlDHnFZ3BsPEZHHJcQI:iyYB04SJYnwqhMFeFzB3+ndBRZSQ4jB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_61d6b309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61d6b309d9774d13d632322816260e082f96293087333e7a379310e7b0796be0"
    family = "unknown"
    file_name = "61d6b309d9774d13.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 04:48:05"
  condition:
    hash.sha256(0, filesize) == "61d6b309d9774d13d632322816260e082f96293087333e7a379310e7b0796be0"
}
```

### Sample 28: `3aaaa49a0c4b139a`

| Field | Value |
|---|---|
| SHA-256 | `3aaaa49a0c4b139a8098b27dba31235571f68b32d96e25669e7febe6c82976d9` |
| Family label | `unknown` |
| File name | `3aaaa49a0c4b139a.cmd` |
| File type | `cmd` |
| First seen | `2026-10-30 04:47:56` |
| Reporter | `Tuxxin` |
| Tags | `cmd, EtherSnake` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02b37c45931bd417fa067d78f1fd6043` |
| SHA-1 | `32c22a3e97460d78aae445e976c5018f812e8b05` |
| SHA-256 | `3aaaa49a0c4b139a8098b27dba31235571f68b32d96e25669e7febe6c82976d9` |
| SHA3-384 | `00ae9aa58e9857cc837be94026c036241ce6a9122f435f56f7e6177ed83f398a8cdda35d80138feed345cfff4d5789eb` |
| TLSH | `T1EAE1C57929A4B90A08791B65573222C43F1FC14B332DFFE494998A96E08F46539FE3E0` |
| SSDEEP | `192:2qNReJhIZAP7CwV3a6XKng/65ODNHKCvn9bVRVoKW+vaECo6ozRo3J:pnkArOnh/9Zk3+vNCo6ozRSJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `cmd`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_3aaaa49a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aaaa49a0c4b139a8098b27dba31235571f68b32d96e25669e7febe6c82976d9"
    family = "unknown"
    file_name = "3aaaa49a0c4b139a.cmd"
    file_type = "cmd"
    first_seen = "2026-10-30 04:47:56"
  condition:
    hash.sha256(0, filesize) == "3aaaa49a0c4b139a8098b27dba31235571f68b32d96e25669e7febe6c82976d9"
}
```

### Sample 29: `eb38f2f91b58545f`

| Field | Value |
|---|---|
| SHA-256 | `eb38f2f91b58545f0511de0954534472e65de8b07abb57cee40a73576b0318af` |
| Family label | `unknown` |
| File name | `macho_eb38f2f91b58.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:45:18` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `635d0f15b6d17180248caa3e97945caa` |
| SHA-1 | `7a2e9dbd9685f43e054fcae6a62716b9cb202aa2` |
| SHA-256 | `eb38f2f91b58545f0511de0954534472e65de8b07abb57cee40a73576b0318af` |
| SHA3-384 | `320ff6d887fd078e2d8de008ebcae173aec1eaec8e88f2168a43c033b5344bb00c28cf27df51d963c35f2b215753b8f2` |
| TLSH | `T19195E0204A1F619AD00A12335C850F9D45B429B0DD0FEAEF5742B366DE3A2DB776237B` |
| SSDEEP | `49152:je+AcelImvgel0NUWFNHDSL39mdcSNApf:jBAJlREUl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_eb38f2f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb38f2f91b58545f0511de0954534472e65de8b07abb57cee40a73576b0318af"
    family = "unknown"
    file_name = "macho_eb38f2f91b58.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:45:18"
  condition:
    hash.sha256(0, filesize) == "eb38f2f91b58545f0511de0954534472e65de8b07abb57cee40a73576b0318af"
}
```

### Sample 30: `cb0062fa365e815c`

| Field | Value |
|---|---|
| SHA-256 | `cb0062fa365e815cd28c5ac8237a241b7a50ffb9d2aefc772cec784785a59ad0` |
| Family label | `unknown` |
| File name | `cb0062fa365e815c_decoded-stage.zsh` |
| File type | `zsh` |
| First seen | `2026-10-30 04:42:26` |
| Reporter | `Dense` |
| Tags | `zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `696eac098a2623232ab86d7583419de1` |
| SHA-1 | `9fa3158e507a36bcad8be3fb42ace5895620cdb1` |
| SHA-256 | `cb0062fa365e815cd28c5ac8237a241b7a50ffb9d2aefc772cec784785a59ad0` |
| SHA3-384 | `788830b220ff028b5a357e62f706e7688d48db13b39d48fbd65f610b2d3ef0b33b18f0f9a60b4f07280789724a584a42` |
| TLSH | `T1703163F0581425B490F71CC4EE2BA8E6B1B211C85F57E3CF4F2092E8196DA86C98FD34` |
| SSDEEP | `48:mt14pAQpsBE/UAosLt14S9g4DDZuor0efa:mt14iQ1/UAosLt14S9g4DDZuEs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zsh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_cb0062fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb0062fa365e815cd28c5ac8237a241b7a50ffb9d2aefc772cec784785a59ad0"
    family = "unknown"
    file_name = "cb0062fa365e815c_decoded-stage.zsh"
    file_type = "zsh"
    first_seen = "2026-10-30 04:42:26"
  condition:
    hash.sha256(0, filesize) == "cb0062fa365e815cd28c5ac8237a241b7a50ffb9d2aefc772cec784785a59ad0"
}
```

### Sample 31: `9eabb901cc361b1b`

| Field | Value |
|---|---|
| SHA-256 | `9eabb901cc361b1b74cda3d7449ccc45d4b142c822c5e78b47246b0d8bbf7bee` |
| Family label | `unknown` |
| File name | `macho_9eabb901cc36.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:40:35` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f61636f5320a415f6b08e32f711233b` |
| SHA-1 | `75512ef212dbbd9a0f6b4afb239e52d841e452e6` |
| SHA-256 | `9eabb901cc361b1b74cda3d7449ccc45d4b142c822c5e78b47246b0d8bbf7bee` |
| SHA3-384 | `cfc337fc209fcbaebc77d8ec7ba966cd1d19b1c7ab0382fdc17d2ec36d1fdbe6b93b4e84e856e2e317bff04baac4cc57` |
| TLSH | `T1E285F190CE76B269F0872473BC550F4140A0A7A19F74A6E7AA10D2527D367E3B6F3336` |
| SSDEEP | `49152:sSpREFBOqTwPYlOEGoleS5nxUJPIsTSLS:FpuiSi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_9eabb901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eabb901cc361b1b74cda3d7449ccc45d4b142c822c5e78b47246b0d8bbf7bee"
    family = "unknown"
    file_name = "macho_9eabb901cc36.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:40:35"
  condition:
    hash.sha256(0, filesize) == "9eabb901cc361b1b74cda3d7449ccc45d4b142c822c5e78b47246b0d8bbf7bee"
}
```

### Sample 32: `a8ee26aaa41e04b8`

| Field | Value |
|---|---|
| SHA-256 | `a8ee26aaa41e04b86cdeebd2c3748171bec0f8e4fab02f9a48cd5bbedd5db544` |
| Family label | `unknown` |
| File name | `macho_a8ee26aaa41e.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:35:48` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `629bbf882bebd0045f63699295300927` |
| SHA-1 | `a42a42077f04973e739dae8214b04791e22bfe74` |
| SHA-256 | `a8ee26aaa41e04b86cdeebd2c3748171bec0f8e4fab02f9a48cd5bbedd5db544` |
| SHA3-384 | `785c532eabe003d27c4a193b049be10e214ef5abfb69c052dc602680759fb98fdb693f2e1d80f43c9fc0a6604d38d1dc` |
| TLSH | `T12CA5F120656B3279D2063933E8120B9C53F469A5290CBEF5B775DB26FE33643A663331` |
| SSDEEP | `24576:zMe9Ec5Zvow6J5B2j3s6qpVQT1tarKltJf7rj6gaK/01HtE5wuNLW69MIQOev2Lb:zlnlZOoJj6gti6wuoEMMLmrD+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_a8ee26aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ee26aaa41e04b86cdeebd2c3748171bec0f8e4fab02f9a48cd5bbedd5db544"
    family = "unknown"
    file_name = "macho_a8ee26aaa41e.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:35:48"
  condition:
    hash.sha256(0, filesize) == "a8ee26aaa41e04b86cdeebd2c3748171bec0f8e4fab02f9a48cd5bbedd5db544"
}
```

### Sample 33: `bb4568b5a0a179f5`

| Field | Value |
|---|---|
| SHA-256 | `bb4568b5a0a179f5391be75ac164900363133b29c24b225438f66c17a741d2dd` |
| Family label | `unknown` |
| File name | `macho_bb4568b5a0a1.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:30:42` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74ec28e377dd8715546a6a53f2227b79` |
| SHA-1 | `af2b01ae261da87f23e7815711cc47ce7b0b9a0e` |
| SHA-256 | `bb4568b5a0a179f5391be75ac164900363133b29c24b225438f66c17a741d2dd` |
| SHA3-384 | `ad3c261f455a4fecd26b23e2df72a7bde785219bdc6ee455ea8b7f7fc75375ea8dc3c72f4b3d7d9531bbba70e76149e6` |
| TLSH | `T10E7502049B26029ADC566C32FC1C0F0595A0B6838E49FFE96260D7577E36B43B6773E2` |
| SSDEEP | `24576:nRiOictvQ6KXXz5NwvvXXhOU/kBB9zWyGDkOnxZP+eEPqKLfkrv5fHEoHehjvd:b660WPkSZP+eECKOw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_bb4568b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb4568b5a0a179f5391be75ac164900363133b29c24b225438f66c17a741d2dd"
    family = "unknown"
    file_name = "macho_bb4568b5a0a1.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:30:42"
  condition:
    hash.sha256(0, filesize) == "bb4568b5a0a179f5391be75ac164900363133b29c24b225438f66c17a741d2dd"
}
```

### Sample 34: `d86551d45a34c794`

| Field | Value |
|---|---|
| SHA-256 | `d86551d45a34c7941768dd04e8cbb96f8ab4344bed2ad13f9a993cb2d3731812` |
| Family label | `SalatStealer` |
| File name | `2d4caec37be793fa.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:26:41` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `631f2958c8160211bd6bf4bacd68a916` |
| SHA-1 | `f01776ee8a6d315eee9e5346d02e00fa02ee2023` |
| SHA-256 | `d86551d45a34c7941768dd04e8cbb96f8ab4344bed2ad13f9a993cb2d3731812` |
| SHA3-384 | `defc37b30a8d479dc1a9abb44d27728cdc9d50271134aca7fdd32fa92f07074ba6e91e5970bfe44e23b123d459b3720a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F2C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+/:yBkKr5rszpNDy+/` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_034_d86551d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d86551d45a34c7941768dd04e8cbb96f8ab4344bed2ad13f9a993cb2d3731812"
    family = "SalatStealer"
    file_name = "2d4caec37be793fa.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:26:41"
  condition:
    hash.sha256(0, filesize) == "d86551d45a34c7941768dd04e8cbb96f8ab4344bed2ad13f9a993cb2d3731812"
}
```

### Sample 35: `f9713062c7f48d96`

| Field | Value |
|---|---|
| SHA-256 | `f9713062c7f48d9689b2f921def5c3ebcb35e036b2ab694d625102dbadce8b52` |
| Family label | `unknown` |
| File name | `macho_f9713062c7f4.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:26:05` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b533c42012ada2cc610ff8221fe7ea1` |
| SHA-1 | `7f9f65ce310a711eae3ccd2d841c373c3b5f93f3` |
| SHA-256 | `f9713062c7f48d9689b2f921def5c3ebcb35e036b2ab694d625102dbadce8b52` |
| SHA3-384 | `830d47008f883278c4a5caa1df9b8149e502cdaea89ac8e0de5901dba991ad10bc545a8059f03795c55ae66965dba2d8` |
| TLSH | `T17495E040DF4FA0EBE94A15339C9A4B6984746080CD48DEED5341F3AADE367A337528B7` |
| SSDEEP | `49152:DDvfrGY0CVPbZUBGrpBuQ35xtrPEE+voB60SVftbI:DDvfX9BF5xt4E+Qt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_f9713062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9713062c7f48d9689b2f921def5c3ebcb35e036b2ab694d625102dbadce8b52"
    family = "unknown"
    file_name = "macho_f9713062c7f4.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:26:05"
  condition:
    hash.sha256(0, filesize) == "f9713062c7f48d9689b2f921def5c3ebcb35e036b2ab694d625102dbadce8b52"
}
```

### Sample 36: `40b3daa9cf994704`

| Field | Value |
|---|---|
| SHA-256 | `40b3daa9cf994704313ee59bc8cfbd6807d5a174173fa07b2056e2693999ae59` |
| Family label | `SalatStealer` |
| File name | `92854c890d6fe100.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:25:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4dad61a94ec2fdd4ffbf0c50949517d` |
| SHA-1 | `0d42b46be2bcde9d887341aef0c0a5045f049645` |
| SHA-256 | `40b3daa9cf994704313ee59bc8cfbd6807d5a174173fa07b2056e2693999ae59` |
| SHA3-384 | `1cab2df6e25ecb85bed955dc1f04deb22c534440a8fb7c270b65b8c6e0e016ebc20f3723a01009fa5627ac8769956da6` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T111C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+G:yBkKr5rszpNDy+G` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_036_40b3daa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40b3daa9cf994704313ee59bc8cfbd6807d5a174173fa07b2056e2693999ae59"
    family = "SalatStealer"
    file_name = "92854c890d6fe100.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:59"
  condition:
    hash.sha256(0, filesize) == "40b3daa9cf994704313ee59bc8cfbd6807d5a174173fa07b2056e2693999ae59"
}
```

### Sample 37: `a9588db7e895e28c`

| Field | Value |
|---|---|
| SHA-256 | `a9588db7e895e28cd1cd7fb2e46ea08a626800fedd549fae9845c35db8b00691` |
| Family label | `SalatStealer` |
| File name | `a41edbb52c94d58c.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:25:53` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c922f4e3e674f505986e08eb37574f5b` |
| SHA-1 | `4b00a8c57b03022b6ae247cb5aa84d3a89183f71` |
| SHA-256 | `a9588db7e895e28cd1cd7fb2e46ea08a626800fedd549fae9845c35db8b00691` |
| SHA3-384 | `e6e08c5936ac2ec304b72c9655e68ce4099a4e3cc1cf23c7b949adad616d065aadc099843a01bee0113c82beb8dd59af` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T189C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+F:yBkKr5rszpNDy+F` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_037_a9588db7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9588db7e895e28cd1cd7fb2e46ea08a626800fedd549fae9845c35db8b00691"
    family = "SalatStealer"
    file_name = "a41edbb52c94d58c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:53"
  condition:
    hash.sha256(0, filesize) == "a9588db7e895e28cd1cd7fb2e46ea08a626800fedd549fae9845c35db8b00691"
}
```

### Sample 38: `fa1c4e3c842df81f`

| Field | Value |
|---|---|
| SHA-256 | `fa1c4e3c842df81fae1772046eb456d67ef95afd9dca58dbae9dd33b8d907af1` |
| Family label | `SalatStealer` |
| File name | `95424c6f72424f3b.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:25:48` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f44d1a658e716e4efeeef8c0894438f` |
| SHA-1 | `2718a2b20188f2e0a84b75e0ec0f2472734a6f16` |
| SHA-256 | `fa1c4e3c842df81fae1772046eb456d67ef95afd9dca58dbae9dd33b8d907af1` |
| SHA3-384 | `4fb6af92f15df6f23e30badea8feec16df6f1a13d6bb0d3d499767adbc5e52da5d2435509f49fdb0adcc2f5da77ee623` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T195C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+4:yBkKr5rszpNDy+4` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_038_fa1c4e3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa1c4e3c842df81fae1772046eb456d67ef95afd9dca58dbae9dd33b8d907af1"
    family = "SalatStealer"
    file_name = "95424c6f72424f3b.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:48"
  condition:
    hash.sha256(0, filesize) == "fa1c4e3c842df81fae1772046eb456d67ef95afd9dca58dbae9dd33b8d907af1"
}
```

### Sample 39: `2613303e7488c440`

| Field | Value |
|---|---|
| SHA-256 | `2613303e7488c44063180a9d7d958efe8c72652f187ea2bbcd2e67984a6cb642` |
| Family label | `SalatStealer` |
| File name | `d74572351d353e4e.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:25:40` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbcac097406b4c94025512b95da53856` |
| SHA-1 | `47e36b55099812fb18ebd4faad49f1d457621f3e` |
| SHA-256 | `2613303e7488c44063180a9d7d958efe8c72652f187ea2bbcd2e67984a6cb642` |
| SHA3-384 | `e93ffa0b609c74c110dc38e9c8896c317727964baf167c32fcf6ec4c68dc3d2115481e28027ad218c5a6e3f47daa96af` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T142C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+j:yBkKr5rszpNDy+j` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_039_2613303e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2613303e7488c44063180a9d7d958efe8c72652f187ea2bbcd2e67984a6cb642"
    family = "SalatStealer"
    file_name = "d74572351d353e4e.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:40"
  condition:
    hash.sha256(0, filesize) == "2613303e7488c44063180a9d7d958efe8c72652f187ea2bbcd2e67984a6cb642"
}
```

### Sample 40: `1912921e15be201b`

| Field | Value |
|---|---|
| SHA-256 | `1912921e15be201b33e39053ff27945c22e7719713eca66589c8c8da65133a81` |
| Family label | `SalatStealer` |
| File name | `cb41fdc089dd9303.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:25:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8331fc5eb567c030271551edce735233` |
| SHA-1 | `f8d93134c95ade02a1a91fbf208c6a5720872495` |
| SHA-256 | `1912921e15be201b33e39053ff27945c22e7719713eca66589c8c8da65133a81` |
| SHA3-384 | `64bd76c0002c513ff3f3a0dc1c9be2fe7a520a44b1d288ca64aaf971a26fc5fbce4f8d5f3dc3a2f9a7ae22fa42d46ba5` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T176C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+S:yBkKr5rszpNDy+S` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_040_1912921e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1912921e15be201b33e39053ff27945c22e7719713eca66589c8c8da65133a81"
    family = "SalatStealer"
    file_name = "cb41fdc089dd9303.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:34"
  condition:
    hash.sha256(0, filesize) == "1912921e15be201b33e39053ff27945c22e7719713eca66589c8c8da65133a81"
}
```

### Sample 41: `2d4caec37be793fa`

| Field | Value |
|---|---|
| SHA-256 | `2d4caec37be793fa0cea5f370c7a06ab62f8325f3154e20be6f544d94bb3ad19` |
| Family label | `SalatStealer` |
| File name | `2d4caec37be793fa.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:25:24` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f172ea9545d894234713ca6f5887c7f` |
| SHA-1 | `4f5f9debc5fc3db4d4e9a9deb0db9185e73cc630` |
| SHA-256 | `2d4caec37be793fa0cea5f370c7a06ab62f8325f3154e20be6f544d94bb3ad19` |
| SHA3-384 | `79cee9df87c34d7a2750187b0fb48c6da94db2935233f70f89188809d78e636fef88096ec977d4c3b6a5cc60ef851f7d` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T168F5335BF1AB4BB3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Or:iJiafuIO7rhWEES4w` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_041_2d4caec3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d4caec37be793fa0cea5f370c7a06ab62f8325f3154e20be6f544d94bb3ad19"
    family = "SalatStealer"
    file_name = "2d4caec37be793fa.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:24"
  condition:
    hash.sha256(0, filesize) == "2d4caec37be793fa0cea5f370c7a06ab62f8325f3154e20be6f544d94bb3ad19"
}
```

### Sample 42: `92854c890d6fe100`

| Field | Value |
|---|---|
| SHA-256 | `92854c890d6fe100858ffae5f213eb89ece3cdd4f72984adca1eb3439f240458` |
| Family label | `SalatStealer` |
| File name | `92854c890d6fe100.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:25:14` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94810e6f7dcd8314de6a8b5455273cbb` |
| SHA-1 | `82c7d4d4cae71a53b7cb28fe4110e58ae80b5ced` |
| SHA-256 | `92854c890d6fe100858ffae5f213eb89ece3cdd4f72984adca1eb3439f240458` |
| SHA3-384 | `ec9cbfec9ba040cac7d7b72c040759941913c3f6b411385a92733e1a8dcc58563f261890dae9343cd0700e1ddadd36a2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E1F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O6:iJiafuIO7rhWEES4J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_042_92854c89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92854c890d6fe100858ffae5f213eb89ece3cdd4f72984adca1eb3439f240458"
    family = "SalatStealer"
    file_name = "92854c890d6fe100.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:14"
  condition:
    hash.sha256(0, filesize) == "92854c890d6fe100858ffae5f213eb89ece3cdd4f72984adca1eb3439f240458"
}
```

### Sample 43: `a41edbb52c94d58c`

| Field | Value |
|---|---|
| SHA-256 | `a41edbb52c94d58ca11aa599b0e168336537444fa55bc0597ccc25ce18ee2ad8` |
| Family label | `SalatStealer` |
| File name | `a41edbb52c94d58c.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:25:03` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afb80f16c8942d69bcd692221a0846b7` |
| SHA-1 | `d55e9329d4cf7db69e26b3a32ff302f918361d8c` |
| SHA-256 | `a41edbb52c94d58ca11aa599b0e168336537444fa55bc0597ccc25ce18ee2ad8` |
| SHA3-384 | `09839a5c9a9494b0f01607c39065f6a052a17d8ae543358b0cfa082b9d334cc3e1828e48874251eab75249dec9ad6fcb` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10BF5335BF1AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OJ:iJiafuIO7rhWEES40` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_043_a41edbb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a41edbb52c94d58ca11aa599b0e168336537444fa55bc0597ccc25ce18ee2ad8"
    family = "SalatStealer"
    file_name = "a41edbb52c94d58c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:03"
  condition:
    hash.sha256(0, filesize) == "a41edbb52c94d58ca11aa599b0e168336537444fa55bc0597ccc25ce18ee2ad8"
}
```

### Sample 44: `95424c6f72424f3b`

| Field | Value |
|---|---|
| SHA-256 | `95424c6f72424f3b1f0ec1b3d3a3f89b9623b41a9ad828c8c9a97386c4d6d76f` |
| Family label | `SalatStealer` |
| File name | `95424c6f72424f3b.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:24:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f37a0e1f2c020177f6126135a98b8da` |
| SHA-1 | `8206f008823c40a5a1c6214cf8fbfece2b5e064b` |
| SHA-256 | `95424c6f72424f3b1f0ec1b3d3a3f89b9623b41a9ad828c8c9a97386c4d6d76f` |
| SHA3-384 | `f2efbd436c3644138a3252c24fb0765fce3130336e214f07ea35f2bd5f05bf5685512d5323f8061f72a49ace7fe98937` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1DAF5335BF1AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OU:iJiafuIO7rhWEES4H` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_044_95424c6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95424c6f72424f3b1f0ec1b3d3a3f89b9623b41a9ad828c8c9a97386c4d6d76f"
    family = "SalatStealer"
    file_name = "95424c6f72424f3b.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:24:54"
  condition:
    hash.sha256(0, filesize) == "95424c6f72424f3b1f0ec1b3d3a3f89b9623b41a9ad828c8c9a97386c4d6d76f"
}
```

### Sample 45: `d74572351d353e4e`

| Field | Value |
|---|---|
| SHA-256 | `d74572351d353e4e3df810c99361baddce5b966ce0c5e8c833f31612140f9024` |
| Family label | `SalatStealer` |
| File name | `d74572351d353e4e.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:24:44` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f33002bdce90b949d9727f4997731908` |
| SHA-1 | `c81e048a0a6dd2f5c16284be1625c7502895e5cb` |
| SHA-256 | `d74572351d353e4e3df810c99361baddce5b966ce0c5e8c833f31612140f9024` |
| SHA3-384 | `5b20da06ab245d2b5f77cc2654f689ea359c35748ea42780f39d4db887abbf278e5d44e99d4b7ae1d193d0b6502c72c9` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1BFF5335BF5AB4BB3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OX:iJiafuIO7rhWEES4A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_045_d7457235
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d74572351d353e4e3df810c99361baddce5b966ce0c5e8c833f31612140f9024"
    family = "SalatStealer"
    file_name = "d74572351d353e4e.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:24:44"
  condition:
    hash.sha256(0, filesize) == "d74572351d353e4e3df810c99361baddce5b966ce0c5e8c833f31612140f9024"
}
```

### Sample 46: `cb41fdc089dd9303`

| Field | Value |
|---|---|
| SHA-256 | `cb41fdc089dd930349d1ab001d506a62153473621c8555b77a59dd5943a07874` |
| Family label | `SalatStealer` |
| File name | `cb41fdc089dd9303.bin` |
| File type | `exe` |
| First seen | `2026-10-30 04:24:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5599a519473189f8836bf4dbafca06b3` |
| SHA-1 | `03a0c555d5eec41a43804fda63499ba1caa59ee6` |
| SHA-256 | `cb41fdc089dd930349d1ab001d506a62153473621c8555b77a59dd5943a07874` |
| SHA3-384 | `dddd38f9e41e567faa6761ab7f5028ac25cb4106e8796bdfa0f6b1581b2b8783c7ef6c5a6538d07986a4f32571b11631` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T178F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OG:iJiafuIO7rhWEES4T` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_046_cb41fdc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb41fdc089dd930349d1ab001d506a62153473621c8555b77a59dd5943a07874"
    family = "SalatStealer"
    file_name = "cb41fdc089dd9303.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:24:34"
  condition:
    hash.sha256(0, filesize) == "cb41fdc089dd930349d1ab001d506a62153473621c8555b77a59dd5943a07874"
}
```

### Sample 47: `23746b451646aeae`

| Field | Value |
|---|---|
| SHA-256 | `23746b451646aeaec0e56f813c7654fd75cb3c5a6d7c0e75fcda66c6287e5df2` |
| Family label | `unknown` |
| File name | `macho_23746b451646.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:21:13` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8af4bba71cab259ead5aa004e58f416c` |
| SHA-1 | `cdd9d9fe5b4dad3a34ec1d94b5d002b87c1c9bb9` |
| SHA-256 | `23746b451646aeaec0e56f813c7654fd75cb3c5a6d7c0e75fcda66c6287e5df2` |
| SHA3-384 | `55636dc4d967804e5e6806095a340637e6e777b2b0f106e8363392e33f21337724a12a3581fce41c0192824bf5a04eeb` |
| TLSH | `T1F385E0408E9BA157D98D41739C958B1945B971C0CE88CEDA6301738ACE3A3E3B7571FB` |
| SSDEEP | `24576:S47LcwD1hLFimSvPZbxeA9RwOi7a6F2RT7hG9Nblx8An1qySvyX:6IMmSvPZTo7a6F2RfhGNbZyvyX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_23746b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23746b451646aeaec0e56f813c7654fd75cb3c5a6d7c0e75fcda66c6287e5df2"
    family = "unknown"
    file_name = "macho_23746b451646.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:21:13"
  condition:
    hash.sha256(0, filesize) == "23746b451646aeaec0e56f813c7654fd75cb3c5a6d7c0e75fcda66c6287e5df2"
}
```

### Sample 48: `54c7ebe70c5981d1`

| Field | Value |
|---|---|
| SHA-256 | `54c7ebe70c5981d14bda4f2ed99adbac28fcf390e4ddd0e0f272dd893f6caa1b` |
| Family label | `unknown` |
| File name | `macho_54c7ebe70c59.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:16:26` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a830000e5524d5569db83b865e7ad17` |
| SHA-1 | `e56819713aaea51effa2fa5072ed9f725b37e79b` |
| SHA-256 | `54c7ebe70c5981d14bda4f2ed99adbac28fcf390e4ddd0e0f272dd893f6caa1b` |
| SHA3-384 | `995baa67c80746c85e895a3134f0ec215424f6d85405cc2ea08a43a14807c36a84bc07e874326c23e30e8eaa95ccd06e` |
| TLSH | `T15195F1B4066F26A9E4016672DC100FDDDC9876B1BE8CB9F6A715DB222C319D361E3732` |
| SSDEEP | `24576:FkkZaNJcJ2pm5OXVaZkhtOqy9J0AciSCOCxMeWfwHjUKz5WSOtXtWQi97624685:uGar0IYZk/fNCOFe5T5WSOt9Db5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_54c7ebe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54c7ebe70c5981d14bda4f2ed99adbac28fcf390e4ddd0e0f272dd893f6caa1b"
    family = "unknown"
    file_name = "macho_54c7ebe70c59.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:16:26"
  condition:
    hash.sha256(0, filesize) == "54c7ebe70c5981d14bda4f2ed99adbac28fcf390e4ddd0e0f272dd893f6caa1b"
}
```

### Sample 49: `f5524521df17eb50`

| Field | Value |
|---|---|
| SHA-256 | `f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822` |
| Family label | `WannaCry` |
| File name | `f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822` |
| File type | `exe` |
| First seen | `2026-10-30 04:15:24` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cb0de092cdf1b3991fadcea548818d7` |
| SHA-1 | `b3a140905945bcfe62cb09468ee7a7bd9d8ead4e` |
| SHA-256 | `f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822` |
| SHA3-384 | `dac4f89da352f0b921d6afb68fba7fb6a0ba8a94f1e0075be4d516f1b0cbe529036c0d3e78e9732128dc12201cb8150b` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1A9360141D2D51AA4D9F10AF715AADB10933EBE5196ABA72F1621410F0C73F0CAEE5F2C` |
| SSDEEP | `98304:DyDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp:DyDqPe1Cxcxk3ZAEUadzR8yc` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_049_f5524521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822"
    family = "WannaCry"
    file_name = "f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822"
    file_type = "exe"
    first_seen = "2026-10-30 04:15:24"
  condition:
    hash.sha256(0, filesize) == "f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822"
}
```

### Sample 50: `85279394e95efea3`

| Field | Value |
|---|---|
| SHA-256 | `85279394e95efea3d2678c9561021cb4a9f7a4d88dbafc74668ee918fff0fd0a` |
| Family label | `unknown` |
| File name | `macho_85279394e95e.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:11:47` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5aa91fd307bf8c70ab5460e15abd611` |
| SHA-1 | `e59b736fefcb861ce250301047b9f6db614aff13` |
| SHA-256 | `85279394e95efea3d2678c9561021cb4a9f7a4d88dbafc74668ee918fff0fd0a` |
| SHA3-384 | `0320bd31f536bac65b2870b51bb4203841c0b9b6d1491c8c776edd9bcbea06a2ed6dae99eb2a8e2d4fc1176eef94a41c` |
| TLSH | `T18E95E050DE4FA1DBD94E11338D9D0B6880706480CD09DEED5391F3AADE363A37B529BA` |
| SSDEEP | `24576:ykstJpQU4JoglfUviKpzV8W/t70BKWaPvhuR9zbYLcZdRlBlo0ftdFk1A+3A7Puc:ywEABWENRlzo01zeA+3Hax` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_85279394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85279394e95efea3d2678c9561021cb4a9f7a4d88dbafc74668ee918fff0fd0a"
    family = "unknown"
    file_name = "macho_85279394e95e.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:11:47"
  condition:
    hash.sha256(0, filesize) == "85279394e95efea3d2678c9561021cb4a9f7a4d88dbafc74668ee918fff0fd0a"
}
```

### Sample 51: `69092c70e390ba31`

| Field | Value |
|---|---|
| SHA-256 | `69092c70e390ba31429d4bbd08ca01eef3415e665551d3d3a66b673f36ed48d3` |
| Family label | `unknown` |
| File name | `macho_69092c70e390.bin` |
| File type | `macho` |
| First seen | `2026-10-30 04:07:17` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb1ca848090eb80ea2398090983c5f18` |
| SHA-1 | `80d6d6023b29421a786bd574f3eeea529a3cc105` |
| SHA-256 | `69092c70e390ba31429d4bbd08ca01eef3415e665551d3d3a66b673f36ed48d3` |
| SHA3-384 | `9b38fa93357200528673a9db1cc5a77280a17cce0ccd56d4b8b9fb571b685d6193b5d71a2b8b118cbcbb9444bd293b66` |
| TLSH | `T10485F1608EF5027BE48324339C150F4545A0A3F26E58A6F66B1096297E3B6F3B5F3F16` |
| SSDEEP | `49152:Y9mh0rS8CuM9MI15AjUtj+t6dT6zWbcGiQknN:4BIr7Y7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_69092c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69092c70e390ba31429d4bbd08ca01eef3415e665551d3d3a66b673f36ed48d3"
    family = "unknown"
    file_name = "macho_69092c70e390.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:07:17"
  condition:
    hash.sha256(0, filesize) == "69092c70e390ba31429d4bbd08ca01eef3415e665551d3d3a66b673f36ed48d3"
}
```

### Sample 52: `fca13846d30c1235`

| Field | Value |
|---|---|
| SHA-256 | `fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419` |
| Family label | `unknown` |
| File name | `fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419` |
| File type | `elf` |
| First seen | `2026-10-30 03:50:06` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8de940796f8de661d1a683fc1889d0f` |
| SHA-1 | `8a9fce439f89e995fdc26b1356e3519c71d24aec` |
| SHA-256 | `fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419` |
| SHA3-384 | `b009e8444b429f5f5c8c90c054a9bf64e9414635c6cbe091b9034378dff4f6932b77b15dc32c06f0e333405e7198d345` |
| TLSH | `T1A9F4291AB59250BCC1E6D070839F9233BA72B86451347EBF62C5AF302E26F11675EF61` |
| SSDEEP | `12288:MxwzO77nk5J1IsK+Fs0VmLVocwSM5HVnagjn7fu1STqyJy4d06:MOWkFlK+FsHoFSMdVnFmyJJd06` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_fca13846
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419"
    family = "unknown"
    file_name = "fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419"
    file_type = "elf"
    first_seen = "2026-10-30 03:50:06"
  condition:
    hash.sha256(0, filesize) == "fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419"
}
```

### Sample 53: `2c496e41d45ee787`

| Field | Value |
|---|---|
| SHA-256 | `2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6` |
| Family label | `OverlordRAT` |
| File name | `2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6.exe` |
| File type | `exe` |
| First seen | `2026-10-30 03:45:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, OverlordRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccbeecc96f564e1a1dfbaf7e7fdf884b` |
| SHA-1 | `b8a5697b4eb41405a191c084087d42ab2ab0337e` |
| SHA-256 | `2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6` |
| SHA3-384 | `5a35a2cac7f3666fff696c11e997a1f1007eb56ae1e26b284d7065f15c6eebee4a1fa1c98ddb423b21f8a491fcc2c672` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1C176390BFCA519E8C1AED1358AA6D1537F717C895B2123E31B90F6282F36BD06DB9344` |
| SSDEEP | `98304:9d69ZCHQrM5ViBfDXBUizumvBh8huT7Eqfd:98ivYfziDql` |

#### Technical Assessment

- The sample is tracked as `OverlordRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_OverlordRAT_053_2c496e41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6"
    family = "OverlordRAT"
    file_name = "2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6.exe"
    file_type = "exe"
    first_seen = "2026-10-30 03:45:45"
  condition:
    hash.sha256(0, filesize) == "2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6"
}
```

### Sample 54: `782cdb174d91a2c9`

| Field | Value |
|---|---|
| SHA-256 | `782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8` |
| Family label | `OverlordRAT` |
| File name | `782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8.exe` |
| File type | `exe` |
| First seen | `2026-10-30 03:45:37` |
| Reporter | `Tuxxin` |
| Tags | `exe, OverlordRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e466ff670d3102a8d1c47db63d9cb25` |
| SHA-1 | `92bc5ab0990e064ce22efcd1b797711d09258425` |
| SHA-256 | `782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8` |
| SHA3-384 | `897e0028cfd2e1e35288ca00585e7e7583e37e7fb1e87b79a5ea45684dae2fc0915a4106ffac6dde6fa4d68e74ecf3fc` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1CE764907ECA558E9C0ADD13189729123BF717C481B2163D72B90F6287F76BD4AEBA344` |
| SSDEEP | `49152:4/lzbx7uD/HMxGidK/8cS8j+zo+o2b5CWSSsyWUIGNT1VCuSntJyV3pm7umXKVKA:4/J14qEdaZxmYwumvBh8huTmEO` |

#### Technical Assessment

- The sample is tracked as `OverlordRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_OverlordRAT_054_782cdb17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8"
    family = "OverlordRAT"
    file_name = "782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8.exe"
    file_type = "exe"
    first_seen = "2026-10-30 03:45:37"
  condition:
    hash.sha256(0, filesize) == "782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8"
}
```

### Sample 55: `058a59adc40cfa2e`

| Field | Value |
|---|---|
| SHA-256 | `058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5` |
| Family label | `unknown` |
| File name | `058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5.exe` |
| File type | `exe` |
| First seen | `2026-10-30 03:38:32` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e0e079e3913581ff6539df62b7b53b3` |
| SHA-1 | `866b0e0c3a85064f1268829b0c6b6316e9ff9909` |
| SHA-256 | `058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5` |
| SHA3-384 | `15a1250df7fd8126d330aaf7c52b7bb939ef16493f68282402f061dd4b7ce58e69bf415104f48ff86b0afc1e5cc3dfd3` |
| IMPHASH | `5a6983d66b332fba3e2f7d42eab331a3` |
| TLSH | `T13B068D2236C081F9E34282708E98BAAC47ACBB7497FF54F777A518E949319C17125B4F` |
| SSDEEP | `98304:je5BEiF9m9G9o93RPenm2xQCl3oSMLs8L3pTP:jUui9kG9KpPoQCsga` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_058a59ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5"
    family = "unknown"
    file_name = "058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5.exe"
    file_type = "exe"
    first_seen = "2026-10-30 03:38:32"
  condition:
    hash.sha256(0, filesize) == "058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5"
}
```

### Sample 56: `a8c8c65f81460cc3`

| Field | Value |
|---|---|
| SHA-256 | `a8c8c65f81460cc3a93f8c1e4d366c2299119e5c570054a9c9d5658df9319530` |
| Family label | `unknown` |
| File name | `FACEITInstaller_64.exe` |
| File type | `exe` |
| First seen | `2026-10-30 03:27:50` |
| Reporter | `Parper` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5f18166aeedcfc232d3f633409759a2` |
| SHA-1 | `b02b6934daea9b0efeadc21ed31e95088b55ad91` |
| SHA-256 | `a8c8c65f81460cc3a93f8c1e4d366c2299119e5c570054a9c9d5658df9319530` |
| SHA3-384 | `07b0b1ef65f6ff202e5fad0195c6e15f676a9a62d58034696c0337679367fef3b588e9370e6df4bcc73685746dba5cb7` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T19A483361F6D75EACE602AB3E888D8509E730B8890ED29FCFD7518E797E4619447243C3` |
| SSDEEP | `3145728:H91MR3nBMoPM6CosBbdKXO3LWeEmu2iMnooXQc:H9yWoP4osBuSqea23oE` |
| ICON-DHASH | `30a88ea2b6cc6970` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_a8c8c65f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c8c65f81460cc3a93f8c1e4d366c2299119e5c570054a9c9d5658df9319530"
    family = "unknown"
    file_name = "FACEITInstaller_64.exe"
    file_type = "exe"
    first_seen = "2026-10-30 03:27:50"
  condition:
    hash.sha256(0, filesize) == "a8c8c65f81460cc3a93f8c1e4d366c2299119e5c570054a9c9d5658df9319530"
}
```

### Sample 57: `58a6d06873b5773a`

| Field | Value |
|---|---|
| SHA-256 | `58a6d06873b5773ae10d442cd8fda21b5dc79fb7ca340dc3062f48ec2d280a8c` |
| Family label | `SalatStealer` |
| File name | `a12e5c2fac9e0204.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:27:41` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c4e7078e24044c922e79bc70e9742e2` |
| SHA-1 | `597123d3a2dbf7ad8272f027aaeedbebb1987d3c` |
| SHA-256 | `58a6d06873b5773ae10d442cd8fda21b5dc79fb7ca340dc3062f48ec2d280a8c` |
| SHA3-384 | `5b3e6721f061dfdb40120e2c5aa360d4553f4c5e0826863e7d37f257fd73707a4e4524d17be4d903d1ce5492ec07a29d` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T11CC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+T:yBkKr5rszpNDy+T` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_057_58a6d068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58a6d06873b5773ae10d442cd8fda21b5dc79fb7ca340dc3062f48ec2d280a8c"
    family = "SalatStealer"
    file_name = "a12e5c2fac9e0204.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:27:41"
  condition:
    hash.sha256(0, filesize) == "58a6d06873b5773ae10d442cd8fda21b5dc79fb7ca340dc3062f48ec2d280a8c"
}
```

### Sample 58: `b8b1c14015de8e04`

| Field | Value |
|---|---|
| SHA-256 | `b8b1c14015de8e04efa1fcfcd95a71b79c89cdc788aacfb2e91cff5b6604772c` |
| Family label | `SalatStealer` |
| File name | `47fd48ccfadd4246.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:26:58` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59df9a6b47989a7b16096e58a8a057ab` |
| SHA-1 | `c396f7eadc14d76aab0983ef86e975a150f596fd` |
| SHA-256 | `b8b1c14015de8e04efa1fcfcd95a71b79c89cdc788aacfb2e91cff5b6604772c` |
| SHA3-384 | `e06cfbf0ee38e9d8036bdba94c5d92b06676318454e5c7bb599017d55f441d2cbe8308b1c4f64d1220beced1e999112e` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T129C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+a:yBkKr5rszpNDy+a` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_058_b8b1c140
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8b1c14015de8e04efa1fcfcd95a71b79c89cdc788aacfb2e91cff5b6604772c"
    family = "SalatStealer"
    file_name = "47fd48ccfadd4246.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:58"
  condition:
    hash.sha256(0, filesize) == "b8b1c14015de8e04efa1fcfcd95a71b79c89cdc788aacfb2e91cff5b6604772c"
}
```

### Sample 59: `318a039986594d58`

| Field | Value |
|---|---|
| SHA-256 | `318a039986594d58b3b669c716d8f7a13a261699f10ed82f8b5ef14234bbb4da` |
| Family label | `SalatStealer` |
| File name | `b83bb0bedf80fdc7.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:26:52` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38e7296fd193aba630d1fd59b4762b53` |
| SHA-1 | `104ff6510a6d71d909d50faeb0353a4a020055f4` |
| SHA-256 | `318a039986594d58b3b669c716d8f7a13a261699f10ed82f8b5ef14234bbb4da` |
| SHA3-384 | `0c3ab9337e8f7ed0af78ce8ef37079789dcbc3fb1b86c7ac9cf88109c6277f14a1828c7e6243120bf0ec0c43d3cd8ddd` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T103C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+m:yBkKr5rszpNDy+m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_059_318a0399
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "318a039986594d58b3b669c716d8f7a13a261699f10ed82f8b5ef14234bbb4da"
    family = "SalatStealer"
    file_name = "b83bb0bedf80fdc7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:52"
  condition:
    hash.sha256(0, filesize) == "318a039986594d58b3b669c716d8f7a13a261699f10ed82f8b5ef14234bbb4da"
}
```

### Sample 60: `bb32aad3a82e3f60`

| Field | Value |
|---|---|
| SHA-256 | `bb32aad3a82e3f608aabb57e1b2744f97e18373872b8fee7749abd5500bf4ff5` |
| Family label | `SalatStealer` |
| File name | `20ca642dc72d3b2e.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:26:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e1ca3f36b6d13832465d2a72e42921b` |
| SHA-1 | `911c2fd5fa36dedfde3b2f6aa659bc90b646c715` |
| SHA-256 | `bb32aad3a82e3f608aabb57e1b2744f97e18373872b8fee7749abd5500bf4ff5` |
| SHA3-384 | `13788a3cecb84b27ccccca0706e181cd55810c64474b88aa97d5f3658ecf140f06d8be889bce5b2ed98954b95cf4c18f` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T105C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+R:yBkKr5rszpNDy+R` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_060_bb32aad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb32aad3a82e3f608aabb57e1b2744f97e18373872b8fee7749abd5500bf4ff5"
    family = "SalatStealer"
    file_name = "20ca642dc72d3b2e.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:46"
  condition:
    hash.sha256(0, filesize) == "bb32aad3a82e3f608aabb57e1b2744f97e18373872b8fee7749abd5500bf4ff5"
}
```

### Sample 61: `d13b1625624298fa`

| Field | Value |
|---|---|
| SHA-256 | `d13b1625624298fa966c3f63bc29db048111c03219d6f9a732b63b951f14e385` |
| Family label | `SalatStealer` |
| File name | `78a9600e16431eb0.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:26:39` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b87a3a5b659156205e978a21cc695cca` |
| SHA-1 | `2c2ca6c06394d59606591098c97f1b6aeee12b5b` |
| SHA-256 | `d13b1625624298fa966c3f63bc29db048111c03219d6f9a732b63b951f14e385` |
| SHA3-384 | `2e7e2a98a21ec9be343b220ffc065d360adff107bdf44b7f253a0fe3c2907661a7c4786f7b3f7e90cac26a6ae874cb19` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E7C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+s:yBkKr5rszpNDy+s` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_061_d13b1625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d13b1625624298fa966c3f63bc29db048111c03219d6f9a732b63b951f14e385"
    family = "SalatStealer"
    file_name = "78a9600e16431eb0.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:39"
  condition:
    hash.sha256(0, filesize) == "d13b1625624298fa966c3f63bc29db048111c03219d6f9a732b63b951f14e385"
}
```

### Sample 62: `7b1e6a0f78057136`

| Field | Value |
|---|---|
| SHA-256 | `7b1e6a0f78057136d95643a801652649afb64b25798d6b296ee2b58025093eef` |
| Family label | `SalatStealer` |
| File name | `219fe381157b3a2c.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:26:31` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd742fcf2122be35f8aaaa2cf27be52f` |
| SHA-1 | `106300139bdf54dd588996a4cd9c16efa0b47bb3` |
| SHA-256 | `7b1e6a0f78057136d95643a801652649afb64b25798d6b296ee2b58025093eef` |
| SHA3-384 | `247347f85a1f8bdf34efcc2b748a6238cffc40236fcc6e06b3de20848c26c06ae669708bc040955798df7bc47c2b4bf0` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A1C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+I:yBkKr5rszpNDy+I` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_062_7b1e6a0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b1e6a0f78057136d95643a801652649afb64b25798d6b296ee2b58025093eef"
    family = "SalatStealer"
    file_name = "219fe381157b3a2c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:31"
  condition:
    hash.sha256(0, filesize) == "7b1e6a0f78057136d95643a801652649afb64b25798d6b296ee2b58025093eef"
}
```

### Sample 63: `9bd124b714e997c7`

| Field | Value |
|---|---|
| SHA-256 | `9bd124b714e997c744465e74d644ac7df44fe2a348c6b06cfd903dbe06a5c735` |
| Family label | `SalatStealer` |
| File name | `d83a81b346d53f24.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:26:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e55f8cb3c09a62a01f678502f00cf1b` |
| SHA-1 | `57830389a6c08fa083b16b44ed9f17fef08e8cbb` |
| SHA-256 | `9bd124b714e997c744465e74d644ac7df44fe2a348c6b06cfd903dbe06a5c735` |
| SHA3-384 | `8951060c0475f3de28aa62c3917da784f1820b2a976a368e51bc1c12500d304eb1059bf7abe048a90bbedf45b8df2664` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T127C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+p:yBkKr5rszpNDy+p` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_063_9bd124b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd124b714e997c744465e74d644ac7df44fe2a348c6b06cfd903dbe06a5c735"
    family = "SalatStealer"
    file_name = "d83a81b346d53f24.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:25"
  condition:
    hash.sha256(0, filesize) == "9bd124b714e997c744465e74d644ac7df44fe2a348c6b06cfd903dbe06a5c735"
}
```

### Sample 64: `a12e5c2fac9e0204`

| Field | Value |
|---|---|
| SHA-256 | `a12e5c2fac9e020414e8e2fe54ade89a0ced1aedb47999869f587cdde687e50c` |
| Family label | `SalatStealer` |
| File name | `a12e5c2fac9e0204.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:26:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99c479e105e60ad8cfc6029a9b339be9` |
| SHA-1 | `c25a6b126ce5f3dd103ab4cdaa9234977bbc4256` |
| SHA-256 | `a12e5c2fac9e020414e8e2fe54ade89a0ced1aedb47999869f587cdde687e50c` |
| SHA3-384 | `437d3033c8a0723162577d27c550911b0a3b03d7267b0dde6613056383dfb46f12f2a48a9c04f6075aa42ef577fd09c2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E7F5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OX:iJiafuIO7rhWEES42` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_064_a12e5c2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a12e5c2fac9e020414e8e2fe54ade89a0ced1aedb47999869f587cdde687e50c"
    family = "SalatStealer"
    file_name = "a12e5c2fac9e0204.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:17"
  condition:
    hash.sha256(0, filesize) == "a12e5c2fac9e020414e8e2fe54ade89a0ced1aedb47999869f587cdde687e50c"
}
```

### Sample 65: `47fd48ccfadd4246`

| Field | Value |
|---|---|
| SHA-256 | `47fd48ccfadd4246158e201272f754d2ed530bbcd06a8d60005aca8504b5c1e6` |
| Family label | `SalatStealer` |
| File name | `47fd48ccfadd4246.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:26:07` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3068e73171cc56ef3bdae73412351463` |
| SHA-1 | `e0d53dc84713bb9a3b64fde12c1601d5631e06c5` |
| SHA-256 | `47fd48ccfadd4246158e201272f754d2ed530bbcd06a8d60005aca8504b5c1e6` |
| SHA3-384 | `c5a39cecc415e0bd2b31fc0a805e093464124f52ce9c242d3baf83e68e8efbc77d1dc0344cab578c40fbffb4345bcca6` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T11FF5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OO:iJiafuIO7rhWEES4X` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_065_47fd48cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47fd48ccfadd4246158e201272f754d2ed530bbcd06a8d60005aca8504b5c1e6"
    family = "SalatStealer"
    file_name = "47fd48ccfadd4246.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:07"
  condition:
    hash.sha256(0, filesize) == "47fd48ccfadd4246158e201272f754d2ed530bbcd06a8d60005aca8504b5c1e6"
}
```

### Sample 66: `b83bb0bedf80fdc7`

| Field | Value |
|---|---|
| SHA-256 | `b83bb0bedf80fdc7a85314c50ca2f438075eb24bd737988d4fdeb37b2ba32e04` |
| Family label | `SalatStealer` |
| File name | `b83bb0bedf80fdc7.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:25:57` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d22c01594fe740758cdab43b8557645` |
| SHA-1 | `3fef927746799c72f789433c62813cad2a039cd6` |
| SHA-256 | `b83bb0bedf80fdc7a85314c50ca2f438075eb24bd737988d4fdeb37b2ba32e04` |
| SHA3-384 | `13c4c4b2e332711eb1b7d9bc6884cd5110bf9906ab0caceaf5a28a57d3c43168d19fcb6fedcfa8cc39fa0b9393893009` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T177F5335BF1AF4BB3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oy:iJiafuIO7rhWEES4D` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_066_b83bb0be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b83bb0bedf80fdc7a85314c50ca2f438075eb24bd737988d4fdeb37b2ba32e04"
    family = "SalatStealer"
    file_name = "b83bb0bedf80fdc7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:57"
  condition:
    hash.sha256(0, filesize) == "b83bb0bedf80fdc7a85314c50ca2f438075eb24bd737988d4fdeb37b2ba32e04"
}
```

### Sample 67: `20ca642dc72d3b2e`

| Field | Value |
|---|---|
| SHA-256 | `20ca642dc72d3b2e260eedae8be9e63afcbe43844140fd0148d91fb328dfb18c` |
| Family label | `SalatStealer` |
| File name | `20ca642dc72d3b2e.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:25:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5c664505daa92716d6d60f04ced6380` |
| SHA-1 | `634f699580595bf11932e3de293adaf378a67e66` |
| SHA-256 | `20ca642dc72d3b2e260eedae8be9e63afcbe43844140fd0148d91fb328dfb18c` |
| SHA3-384 | `586c60e42c7801da21219a22ea1e619dc69d35fd8ed1694c114cdff691e0227c2a396cd90965acc39e5b1b44e9254446` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T19EF5335BF1AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ol:iJiafuIO7rhWEES4O` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_067_20ca642d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20ca642dc72d3b2e260eedae8be9e63afcbe43844140fd0148d91fb328dfb18c"
    family = "SalatStealer"
    file_name = "20ca642dc72d3b2e.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:47"
  condition:
    hash.sha256(0, filesize) == "20ca642dc72d3b2e260eedae8be9e63afcbe43844140fd0148d91fb328dfb18c"
}
```

### Sample 68: `78a9600e16431eb0`

| Field | Value |
|---|---|
| SHA-256 | `78a9600e16431eb0e2469b8c7eed2540c351a92e1204d0f4016307e0ec8da1e6` |
| Family label | `SalatStealer` |
| File name | `78a9600e16431eb0.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:25:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48f9846130e0ee6aefb10b245f4c3b43` |
| SHA-1 | `ed3fed238406b8de2164817ce4f021fd0d620330` |
| SHA-256 | `78a9600e16431eb0e2469b8c7eed2540c351a92e1204d0f4016307e0ec8da1e6` |
| SHA3-384 | `8caafb94e7c5ef3558b129600a285522b47a7e1948ff12a9a79d2bb5c43e7ba195222203a789cdd8219b583a333cb02c` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T100F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OI:iJiafuIO7rhWEES4b` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_068_78a9600e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a9600e16431eb0e2469b8c7eed2540c351a92e1204d0f4016307e0ec8da1e6"
    family = "SalatStealer"
    file_name = "78a9600e16431eb0.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:38"
  condition:
    hash.sha256(0, filesize) == "78a9600e16431eb0e2469b8c7eed2540c351a92e1204d0f4016307e0ec8da1e6"
}
```

### Sample 69: `63223cfe6e860c59`

| Field | Value |
|---|---|
| SHA-256 | `63223cfe6e860c5945971bf36e6782bb5e5c801638dc980062302c25337398f7` |
| Family label | `SalatStealer` |
| File name | `a3021d32d573bb4a.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:25:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83b3e6f3827e445a55ac74b7d1a785af` |
| SHA-1 | `4d42f80b353a4868d69f25123ffda5212c4fb999` |
| SHA-256 | `63223cfe6e860c5945971bf36e6782bb5e5c801638dc980062302c25337398f7` |
| SHA3-384 | `307553b4ba7917d66beb4ae088d0ce84c847dcae483c6958bf70f47fc9a4823e011fd1481f98aa41e4e17985d250bb5f` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E9C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+B:yBkKr5rszpNDy+B` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_069_63223cfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63223cfe6e860c5945971bf36e6782bb5e5c801638dc980062302c25337398f7"
    family = "SalatStealer"
    file_name = "a3021d32d573bb4a.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:28"
  condition:
    hash.sha256(0, filesize) == "63223cfe6e860c5945971bf36e6782bb5e5c801638dc980062302c25337398f7"
}
```

### Sample 70: `219fe381157b3a2c`

| Field | Value |
|---|---|
| SHA-256 | `219fe381157b3a2c9149a96dc7ebdf1ed088bb444a2244e9c5b3bebdf6308522` |
| Family label | `SalatStealer` |
| File name | `219fe381157b3a2c.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:25:28` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd2e369be14ba31cf4839db0a0a0b419` |
| SHA-1 | `18390e06ca6a63d02e923b9997a79e273478dcb8` |
| SHA-256 | `219fe381157b3a2c9149a96dc7ebdf1ed088bb444a2244e9c5b3bebdf6308522` |
| SHA3-384 | `73bc778139676d8e830ea2d442f3aaed5d346210dce5e4dbd47342947ae701295aa1a14189d3f09bf21135c805affc60` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1B7F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O8:iJiafuIO7rhWEES4N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_070_219fe381
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "219fe381157b3a2c9149a96dc7ebdf1ed088bb444a2244e9c5b3bebdf6308522"
    family = "SalatStealer"
    file_name = "219fe381157b3a2c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:28"
  condition:
    hash.sha256(0, filesize) == "219fe381157b3a2c9149a96dc7ebdf1ed088bb444a2244e9c5b3bebdf6308522"
}
```

### Sample 71: `d83a81b346d53f24`

| Field | Value |
|---|---|
| SHA-256 | `d83a81b346d53f24152535604b0087fa88eb7f9214dc996141b5778820bcb91b` |
| Family label | `SalatStealer` |
| File name | `d83a81b346d53f24.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:25:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13d119d05725660960d76c878d940e31` |
| SHA-1 | `c1e7b26d7e21e06ea5fbff4590468f622dbae461` |
| SHA-256 | `d83a81b346d53f24152535604b0087fa88eb7f9214dc996141b5778820bcb91b` |
| SHA3-384 | `46d99fb1d17dbb706b1238fbd1f0ac298a274cd70c4f54cf6809790bfe8e548e0d7b3df48a8eeacca96af3d882fd6cfc` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T15FF5335BF1AB4BB3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0846FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ol:iJiafuIO7rhWEES4m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_071_d83a81b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d83a81b346d53f24152535604b0087fa88eb7f9214dc996141b5778820bcb91b"
    family = "SalatStealer"
    file_name = "d83a81b346d53f24.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:18"
  condition:
    hash.sha256(0, filesize) == "d83a81b346d53f24152535604b0087fa88eb7f9214dc996141b5778820bcb91b"
}
```

### Sample 72: `a3021d32d573bb4a`

| Field | Value |
|---|---|
| SHA-256 | `a3021d32d573bb4a64c3804fcc6bf95d756784e80c88dc0fe6223aada7ab2cb8` |
| Family label | `SalatStealer` |
| File name | `a3021d32d573bb4a.bin` |
| File type | `exe` |
| First seen | `2026-10-30 03:25:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cca0e36730452b9e0cfd06ec3a6abcfb` |
| SHA-1 | `743580274bc04ec59bd337a4e16b9e58e32230d1` |
| SHA-256 | `a3021d32d573bb4a64c3804fcc6bf95d756784e80c88dc0fe6223aada7ab2cb8` |
| SHA3-384 | `2a5d5de06746d2ccba236563874b6c04c0c1f2796efb17114e1dbd6bb6351f1e46b7a0a0c7051f4b1b976aaa6f9b81da` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A4F5335BF1AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O1:iJiafuIO7rhWEES4U` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_072_a3021d32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3021d32d573bb4a64c3804fcc6bf95d756784e80c88dc0fe6223aada7ab2cb8"
    family = "SalatStealer"
    file_name = "a3021d32d573bb4a.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:08"
  condition:
    hash.sha256(0, filesize) == "a3021d32d573bb4a64c3804fcc6bf95d756784e80c88dc0fe6223aada7ab2cb8"
}
```

### Sample 73: `027ee20166749752`

| Field | Value |
|---|---|
| SHA-256 | `027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-30 03:18:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4214770c2cbc21ae31e9ff5acd0ac005` |
| SHA-1 | `d62b4301425bdf844030a99735a84b79b04d8133` |
| SHA-256 | `027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f` |
| SHA3-384 | `68ab09a90c7ba5d5b5b73e70be27b02d7bf188478f23d6e730f83ceaf26440a5f3aec7b982fea12f191ba454053b69e8` |
| TLSH | `T1D0556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSM:SDjxB4m5n8XlaPWi+d+a4TjxQP4K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_027ee201
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-30 03:18:16"
  condition:
    hash.sha256(0, filesize) == "027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f"
}
```

### Sample 74: `ac29dd46f9347e2a`

| Field | Value |
|---|---|
| SHA-256 | `ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1` |
| Family label | `WannaCry` |
| File name | `ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1` |
| File type | `exe` |
| First seen | `2026-10-30 03:15:15` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c94fc05e40e73c41054fcb9717241cf` |
| SHA-1 | `ab485798406c84cc8e57d282635c8fed9786e25b` |
| SHA-256 | `ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1` |
| SHA3-384 | `8e9938022109c79840d2325e8d11e5e6314d25ce4c8b4e3d3d321cc8607864c6edc75b12705c301c422aa69d1760047a` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1F7360205FA9195D5C0725A730CE7CE96BBB67C419E608B0B7616331F8CFB7C6A942238` |
| SSDEEP | `98304:DXDqPoBhz1aRxcSUDk36SA471rO8avnp/:DXDqPe1Cxcxk3ZA4Zla` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_074_ac29dd46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1"
    family = "WannaCry"
    file_name = "ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1"
    file_type = "exe"
    first_seen = "2026-10-30 03:15:15"
  condition:
    hash.sha256(0, filesize) == "ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1"
}
```

### Sample 75: `fd3bf0098efb117f`

| Field | Value |
|---|---|
| SHA-256 | `fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d` |
| Family label | `unknown` |
| File name | `fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d.bin` |
| File type | `sh` |
| First seen | `2026-10-30 02:59:16` |
| Reporter | `Tuxxin` |
| Tags | `script, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a426262a08e9eeb3860feb604a1851bd` |
| SHA-1 | `30c168b0e6bfc47539963f46f3957b12b3de9ca0` |
| SHA-256 | `fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d` |
| SHA3-384 | `a701a60c2f1e0168e240a7e4b2b29ba28dbf184fa7f09d55c6f497130a44c94105bd6f770104ee45fb28159ef447a55d` |
| TLSH | `T148E0F165FB0851B823D0877494C8F08339171FF00FC01476F14B3512206085D3436561` |
| SSDEEP | `12:+9m+OuyLCEUavQMUI3Dvs+4k/uMUI3Dvzd:amGWlvQI3o+qXI3Xd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_fd3bf009
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d"
    family = "unknown"
    file_name = "fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d.bin"
    file_type = "sh"
    first_seen = "2026-10-30 02:59:16"
  condition:
    hash.sha256(0, filesize) == "fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d"
}
```

### Sample 76: `50467b69921dd34c`

| Field | Value |
|---|---|
| SHA-256 | `50467b69921dd34c67ddcbbdb529f81159844c6e80effe4b4ccb06725b14f26e` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-30 02:53:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e26c7eddd4006818e4b313037edb739` |
| SHA-1 | `0802e2a01fb11725cec0ed45102f6a58053fa9c9` |
| SHA-256 | `50467b69921dd34c67ddcbbdb529f81159844c6e80effe4b4ccb06725b14f26e` |
| SHA3-384 | `dc6e6fcb664e9be184e7f79474bf2b0419db9a71a1ea258db139b0f5482871ebb9c0fd8cc038912f7455633f6d7a0502` |
| TLSH | `T11954D719AB610FFBE86FDD3706E90B0625CC640722983F793674E914F64A64B4AE3C74` |
| SSDEEP | `3072:awAmjtBl0QEGQnivHRT/2nhHKdh5pxBa5R/MTXuLJJpYwQnvYKt7YhHe98yZ3P:hAW0QEfifsnhhj+uLJSvxtcw98ytP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_50467b69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50467b69921dd34c67ddcbbdb529f81159844c6e80effe4b4ccb06725b14f26e"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-30 02:53:19"
  condition:
    hash.sha256(0, filesize) == "50467b69921dd34c67ddcbbdb529f81159844c6e80effe4b4ccb06725b14f26e"
}
```

### Sample 77: `278bd6ea4a998a12`

| Field | Value |
|---|---|
| SHA-256 | `278bd6ea4a998a126fc59102a339d2f2ad879de6c99addcc532465a11cce67bf` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-30 02:52:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fef926869ea5db058d75e20d0804cc27` |
| SHA-1 | `a48af5f385a227e9d20555ab9b8b090c267673ed` |
| SHA-256 | `278bd6ea4a998a126fc59102a339d2f2ad879de6c99addcc532465a11cce67bf` |
| SHA3-384 | `0256b7295ab51492f0d47cb37e9739dcbb42a2684df5603a497a1fc6c21e817abc107a460ce0e7de4713faf19180728d` |
| TLSH | `T15E93024FEB9EF594C1986EF0F4F70230D645B24CE59BA2C413958462E98F74B5A0C3E9` |
| SSDEEP | `1536:3qCwbzGALrPbObSdbkSv0di3XvCkFGcqv9Q1kJ7rCO8TIGrqbEQ254hi:6CwbzGEPbt5yWvkvv91oRpuq4hi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_278bd6ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "278bd6ea4a998a126fc59102a339d2f2ad879de6c99addcc532465a11cce67bf"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-30 02:52:59"
  condition:
    hash.sha256(0, filesize) == "278bd6ea4a998a126fc59102a339d2f2ad879de6c99addcc532465a11cce67bf"
}
```

### Sample 78: `db5a90a147265bf5`

| Field | Value |
|---|---|
| SHA-256 | `db5a90a147265bf5f253ce1e8f7a40a8cf5197f5d90f0a6c4cbe4c2328f18f14` |
| Family label | `Formbook` |
| File name | `Permintan Penawaran Harga CV. ANUGRAH M.js` |
| File type | `js` |
| First seen | `2026-10-30 02:48:02` |
| Reporter | `threatcat_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `513e169276450488b887c096939c506e` |
| SHA-1 | `bde749eabea2af03f3f412cbcf29ed1bb129298c` |
| SHA-256 | `db5a90a147265bf5f253ce1e8f7a40a8cf5197f5d90f0a6c4cbe4c2328f18f14` |
| SHA3-384 | `3130ccf5d16d6b20197b54b5a2d98acc7b06dbe28202ca76d5471344a0919ffb1a7a8285fe3c41365afce91096fd60c1` |
| TLSH | `T1FE61EEDD6C9AB0584A337338CB6F6409F7A28A93110AC754B58CA3842FB0514C5E9FED` |
| SSDEEP | `24:2nPZYZDXBFeqC5eBPw3gyupBApl0ntD6Ihq31r3XJWA68a5dWiYQZx/6LDiyuy1I:gsYeqYApPpdXJWAFp1NpUkaYM9J` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_078_db5a90a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db5a90a147265bf5f253ce1e8f7a40a8cf5197f5d90f0a6c4cbe4c2328f18f14"
    family = "Formbook"
    file_name = "Permintan Penawaran Harga CV. ANUGRAH M.js"
    file_type = "js"
    first_seen = "2026-10-30 02:48:02"
  condition:
    hash.sha256(0, filesize) == "db5a90a147265bf5f253ce1e8f7a40a8cf5197f5d90f0a6c4cbe4c2328f18f14"
}
```

### Sample 79: `2ec5493be911c869`

| Field | Value |
|---|---|
| SHA-256 | `2ec5493be911c869dc4729f77e6b0daa8c775aa972bcfb18a427074270fe587f` |
| Family label | `GuLoader` |
| File name | `Argante.vbs` |
| File type | `vbs` |
| First seen | `2026-10-30 02:40:20` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8a4bf11fa8910b89f78d985a5b5c250` |
| SHA-1 | `3ca97c19b077aec2b6c9e25735d96f613a2d79f2` |
| SHA-256 | `2ec5493be911c869dc4729f77e6b0daa8c775aa972bcfb18a427074270fe587f` |
| SHA3-384 | `b699133a125f48aec97c34226d44644bdf17a1fcbb7a59bca09996aeb87302944cd2857aca47094c39af9bfbd5db1e36` |
| TLSH | `T10C83071E9F8201180FEF9695A845A653827B31EF11913C6CEAFAE64933C337C936F165` |
| SSDEEP | `1536:NFf6rMkeZj6u57DIka1wDjITcfxGE3syag89C1UNZ:NFirMkeZN5bIwDsTkx93PdqeUNZ` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_079_2ec5493b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec5493be911c869dc4729f77e6b0daa8c775aa972bcfb18a427074270fe587f"
    family = "GuLoader"
    file_name = "Argante.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 02:40:20"
  condition:
    hash.sha256(0, filesize) == "2ec5493be911c869dc4729f77e6b0daa8c775aa972bcfb18a427074270fe587f"
}
```

### Sample 80: `fc5eeacaf8c54538`

| Field | Value |
|---|---|
| SHA-256 | `fc5eeacaf8c5453827a864a4895628118c9f08df780f3f961a592152b3ca0137` |
| Family label | `SalatStealer` |
| File name | `a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d.exe` |
| File type | `exe` |
| First seen | `2026-10-30 02:39:20` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f95d10428effcc815db2b0b937b8a84` |
| SHA-1 | `8078e00b4ad71a1fc6d2b1e2e89621544fc3b232` |
| SHA-256 | `fc5eeacaf8c5453827a864a4895628118c9f08df780f3f961a592152b3ca0137` |
| SHA3-384 | `2fff7386694f6a8e049b7d6f8471b54c26ccb451c04e4c798db55665f87d8412affe47fc08dc30b8609d7d1143ac4f01` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1CCC66B11FADB95F1E903183141ABB37F23315D048B28DB9BEB547B2AF87B6A11C66305` |
| SSDEEP | `98304:Fc1iqDbN96C1H23opJa2l8m54tG20CEEDS:rq/RH+aa2O4HAO` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_080_fc5eeaca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc5eeacaf8c5453827a864a4895628118c9f08df780f3f961a592152b3ca0137"
    family = "SalatStealer"
    file_name = "a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:39:20"
  condition:
    hash.sha256(0, filesize) == "fc5eeacaf8c5453827a864a4895628118c9f08df780f3f961a592152b3ca0137"
}
```

### Sample 81: `a0150547114a3b5d`

| Field | Value |
|---|---|
| SHA-256 | `a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d` |
| Family label | `SalatStealer` |
| File name | `a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d.exe` |
| File type | `exe` |
| First seen | `2026-10-30 02:38:33` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd81f72c80163a9f2b5e8debf48294db` |
| SHA-1 | `b33ed482e831fc6cd4e8cd785e70fb091365a464` |
| SHA-256 | `a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d` |
| SHA3-384 | `294739b479f1d9c5dc3e8ce650336eacfdeae2d27aa9f43cf077c147a1ec681fb828035ed0812c2c471f91baa08dffe8` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T17FF53380464181E4F2E1637BF3996851E82A0F9E53239FBB2D6CF86A87D07D1F1B7152` |
| SSDEEP | `98304:4rftowsSFWUSQqq7IQIgJ327j/ec0qAmxGgI:4rFTsSFzS/q7isG3e7oGR` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_081_a0150547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d"
    family = "SalatStealer"
    file_name = "a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:38:33"
  condition:
    hash.sha256(0, filesize) == "a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d"
}
```

### Sample 82: `ea04ba910ce5fd98`

| Field | Value |
|---|---|
| SHA-256 | `ea04ba910ce5fd987031377d8e17faaae855f8c9743f550a045f800820ecace4` |
| Family label | `Mirai` |
| File name | `e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48.exe` |
| File type | `exe` |
| First seen | `2026-10-30 02:24:21` |
| Reporter | `abuse_ch` |
| Tags | `exe, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4be9035d2ab956be33945bb818f8dc0` |
| SHA-1 | `f7032da159c4eeced1adb4dac45e1e6bade10698` |
| SHA-256 | `ea04ba910ce5fd987031377d8e17faaae855f8c9743f550a045f800820ecace4` |
| SHA3-384 | `15da9644662d0598e02414ecf963976fa29532c315312555406d32c73de0d6362222e573f92564d04adef8cf556d0314` |
| IMPHASH | `81824563619d328306a47941613ac9ab` |
| TLSH | `T12B844D50F245FDF5EC868BB410E2631A93B9F0C1971AEF2F6920FE3C091AB54997354A` |
| SSDEEP | `6144:E0Z5yMmAaS+tKnke2Ruk2iKVu3iEjHy5ivLOzz7mogOKvALAQ:0/a7kNIX1lFg2iBqAQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_ea04ba91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea04ba910ce5fd987031377d8e17faaae855f8c9743f550a045f800820ecace4"
    family = "Mirai"
    file_name = "e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:24:21"
  condition:
    hash.sha256(0, filesize) == "ea04ba910ce5fd987031377d8e17faaae855f8c9743f550a045f800820ecace4"
}
```

### Sample 83: `e0805ad4034a37cb`

| Field | Value |
|---|---|
| SHA-256 | `e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48` |
| Family label | `Mirai` |
| File name | `e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48.exe` |
| File type | `exe` |
| First seen | `2026-10-30 02:23:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8e1d19a2c0c448ac644d0652f247049` |
| SHA-1 | `d01101c16398fb4fcc1c66a6763fe568a4f0b8af` |
| SHA-256 | `e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48` |
| SHA3-384 | `cdfa1e54bcca0f3e1a102e9ea109ee7b85cd6ef90cd65824a8bf49ddf6e86a2901982417fb323f9b4994934f03527f77` |
| IMPHASH | `b920d0991f4648fe46f38cb48270d268` |
| TLSH | `T194B318E07AE45C9AEA60537D41DBE222773CF6D19B438B03493076361A53BD13ED262A` |
| SSDEEP | `1536:18l/SQzhCc6oDzmDnkXh0gdHuh4hxUkH3Q+cYbMG6Hor9shYdxtKAQ:18nhCcXDaDnkXhrtu+xUkHRWCiAQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_e0805ad4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48"
    family = "Mirai"
    file_name = "e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:23:32"
  condition:
    hash.sha256(0, filesize) == "e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48"
}
```

### Sample 84: `6e20b1859bf3072a`

| Field | Value |
|---|---|
| SHA-256 | `6e20b1859bf3072a5e6fbdd81d3e03279becbf1dee8503207b4ea1d86e569d3a` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-10-30 02:15:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb43d77428f70616c4ac5dfe0ec153a5` |
| SHA-1 | `9a1eb864fbc8cba463f1a7d279108ba1c862150d` |
| SHA-256 | `6e20b1859bf3072a5e6fbdd81d3e03279becbf1dee8503207b4ea1d86e569d3a` |
| SHA3-384 | `982bd9d7b2b0904dd78cb352e3934e48a57d67e9dcf4ec93a6222f2f50d775f51f8c9c5111364c55b28b929e99b63d9a` |
| TLSH | `T138149D72CC2A6EE8D52495B0B0F1DFBD5B13D56152871FBEA4AFC2744183C89B2097B8` |
| SSDEEP | `3072:pmckS1KillqGnSLWwQqw0Ae2kyZy0RvF+FWBjzU9ZmHf9R:pdTpl04dqw0F2krRwBjqZ49R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_6e20b185
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e20b1859bf3072a5e6fbdd81d3e03279becbf1dee8503207b4ea1d86e569d3a"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-30 02:15:29"
  condition:
    hash.sha256(0, filesize) == "6e20b1859bf3072a5e6fbdd81d3e03279becbf1dee8503207b4ea1d86e569d3a"
}
```

### Sample 85: `db6edde280746449`

| Field | Value |
|---|---|
| SHA-256 | `db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014` |
| Family label | `unknown` |
| File name | `db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014.exe` |
| File type | `exe` |
| First seen | `2026-10-30 02:13:36` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa077b75a963e44284ee0d298018f359` |
| SHA-1 | `16d2049390a8e70249a02ff6f2247bd94e72892e` |
| SHA-256 | `db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014` |
| SHA3-384 | `2cae32fafcdb4ec6948231319d3f63beed154ec7f68841c63fdbe0d01d23f2e8b54c5dfd5bc5f08adf370269c3011960` |
| IMPHASH | `791d5a7e1939a1f39df11cef9d6e675b` |
| TLSH | `T1D6243B13312198B6E42643B651BA5338E5B8BF3039F3C457EBE0BD73AD71125E71A60A` |
| SSDEEP | `3072:tMBSA1vJcAGOziLEIfYOcZwcHPtNjRw7pllC0WDQjv1yk/t9jCZ+QxYbdVQlllll:tHAJJcAGO/IfYOcyKRw7` |
| ICON-DHASH | `e0e0e4c6f0f8f839` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_db6edde2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014"
    family = "unknown"
    file_name = "db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:13:36"
  condition:
    hash.sha256(0, filesize) == "db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014"
}
```

### Sample 86: `230675c608fc6f82`

| Field | Value |
|---|---|
| SHA-256 | `230675c608fc6f82517f6c1733dc24d643007f206d2f2bd26ee1123ab9d4ff2b` |
| Family label | `GuLoader` |
| File name | `likeways.vbs` |
| File type | `vbs` |
| First seen | `2026-10-30 02:10:36` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4b5b07451a6ccc89a68079c99bd1c1f` |
| SHA-1 | `eb554845104cf77b24c6cd682aa1d89c072f15a2` |
| SHA-256 | `230675c608fc6f82517f6c1733dc24d643007f206d2f2bd26ee1123ab9d4ff2b` |
| SHA3-384 | `c0db72add49b5bb969e2a24c216bb18c2b7316e5383a81406ced1532c02aa99f3b094c2ff618c1eca8f19ff7747b4e77` |
| TLSH | `T1528329E0B9D03614CE06B799A88435978DFD031563F3C0E8AB9DB67D1807DACD27925E` |
| SSDEEP | `1536:7zTDAGJZKRJxh5H3REIR5auZG+Eeaf40qINSqGqpEe:7zTUGJZKRF5hEIOuZ9ETwPINf` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_086_230675c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "230675c608fc6f82517f6c1733dc24d643007f206d2f2bd26ee1123ab9d4ff2b"
    family = "GuLoader"
    file_name = "likeways.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 02:10:36"
  condition:
    hash.sha256(0, filesize) == "230675c608fc6f82517f6c1733dc24d643007f206d2f2bd26ee1123ab9d4ff2b"
}
```

### Sample 87: `7c00572008134d39`

| Field | Value |
|---|---|
| SHA-256 | `7c00572008134d39687755c03cf38a6dc57ae970922ea4aab6b7ec8c15fac9df` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-30 01:56:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3050e12877ce72e5c11a6d489b2c9fd1` |
| SHA-1 | `aeb279a7610e1bcd0f97c4ec54c4d7c7191caecc` |
| SHA-256 | `7c00572008134d39687755c03cf38a6dc57ae970922ea4aab6b7ec8c15fac9df` |
| SHA3-384 | `039abd682b9b81daf2f3fa10a6ce32294bca75e499dae1a052575871c920eedc437ce3d6e8b5217c5f7718604c297294` |
| TLSH | `T17A556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSi:SDjxB4m5n8XlaPWi+d+a4TjxQP4M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_7c005720
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c00572008134d39687755c03cf38a6dc57ae970922ea4aab6b7ec8c15fac9df"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-30 01:56:17"
  condition:
    hash.sha256(0, filesize) == "7c00572008134d39687755c03cf38a6dc57ae970922ea4aab6b7ec8c15fac9df"
}
```

### Sample 88: `31592658015dacf0`

| Field | Value |
|---|---|
| SHA-256 | `31592658015dacf038dffbf98b41d0eca512a310f60094ac676179c5aaa0f57e` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win32.MalwareX-gen.1259.29265` |
| File type | `exe` |
| First seen | `2026-10-30 01:30:19` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0e0af67ffac0a2f9ed2c54e7659f0f2` |
| SHA-1 | `2fd58096f78d7a0037d0a2878bdfcc289198d382` |
| SHA-256 | `31592658015dacf038dffbf98b41d0eca512a310f60094ac676179c5aaa0f57e` |
| SHA3-384 | `c1416e34c52417336b6ff4ca02086b6e7c65a1f4b6b59742cfd6a4d6a3b6b79b0440b126445abdd361d88487010ef2d1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FC55E0182226C752C9697BF3CE71D8F013772CA6D1A2C2DB4EE13CEA7972B616905713` |
| SSDEEP | `24576:S+JsXLDTmER8PEv6qj67dnwIXqN1QeBCzfK4xNeZYLJUsqPboNa/28RmHU/fV/nI:FsXXT5j25wI6N1QeB4fK4yqxqjZ2I/fd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_31592658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31592658015dacf038dffbf98b41d0eca512a310f60094ac676179c5aaa0f57e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win32.MalwareX-gen.1259.29265"
    file_type = "exe"
    first_seen = "2026-10-30 01:30:19"
  condition:
    hash.sha256(0, filesize) == "31592658015dacf038dffbf98b41d0eca512a310f60094ac676179c5aaa0f57e"
}
```

### Sample 89: `376549b7dea66fb5`

| Field | Value |
|---|---|
| SHA-256 | `376549b7dea66fb5aed231cb1e3637147f21278593886ef7292351e05f39a412` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-10-30 01:27:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f5692e8a422269cb59c8f56c87e664c` |
| SHA-1 | `4fcea0c6368377c942410e975eabf84259d3532f` |
| SHA-256 | `376549b7dea66fb5aed231cb1e3637147f21278593886ef7292351e05f39a412` |
| SHA3-384 | `f0863c2eaf0bb604b22e35fb44f1504754dc9d97c9413ed238e2b85042f73c60699aac6c0c141da683a265c74c017e70` |
| TLSH | `T118242A55FC519E17CAC2167BFB5E428C372B1768D2EE71039D292F20378B86B0E7A641` |
| TELFHASH | `t1cb11bd30d4485de4b7d5d0a582eb7231a2a8a0adb7051d90d2b9db6f4d13df43829963` |
| SSDEEP | `6144:JucN1QaHNfobLj2vR3fP3f6Kwd39Tgwo7wvNFAfF65I9uF9H:IcNawNfoXj2vR3fP3f4d3Cw0wvvN5uG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_376549b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "376549b7dea66fb5aed231cb1e3637147f21278593886ef7292351e05f39a412"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-10-30 01:27:18"
  condition:
    hash.sha256(0, filesize) == "376549b7dea66fb5aed231cb1e3637147f21278593886ef7292351e05f39a412"
}
```

### Sample 90: `763a76c9d818a670`

| Field | Value |
|---|---|
| SHA-256 | `763a76c9d818a6706ebda12b09d57f5596a564debaa7bcade80d4db409b89473` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-10-30 01:26:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc83621e81ea0dd6a2116c1440d9cd38` |
| SHA-1 | `5d8bc97ed832bc102628ee11332a408ddad6b4d2` |
| SHA-256 | `763a76c9d818a6706ebda12b09d57f5596a564debaa7bcade80d4db409b89473` |
| SHA3-384 | `7c6ab043e21b6fda8d5d18a87b030342400710ecea7ec428c17c610fca9470456512690bda9fb23baf1490fb91baf1cd` |
| TLSH | `T1EF83027407A73F6085E4CC3922E996430B9996F2479EA132C0571E14348EDDD79D87AF` |
| SSDEEP | `1536:ZCECbqyWIJ6cqVPWOswHNr+ZiWl+EQ0dM0NQVR08FAnv0UvJuygJtTj04zl:2qyB9qxWOswHNSZj+VP0NmHY9JuygJtr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_763a76c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "763a76c9d818a6706ebda12b09d57f5596a564debaa7bcade80d4db409b89473"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-10-30 01:26:32"
  condition:
    hash.sha256(0, filesize) == "763a76c9d818a6706ebda12b09d57f5596a564debaa7bcade80d4db409b89473"
}
```

### Sample 91: `c0f61b3eef8b8100`

| Field | Value |
|---|---|
| SHA-256 | `c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e` |
| Family label | `unknown` |
| File name | `c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e.exe` |
| File type | `exe` |
| First seen | `2026-10-30 01:25:22` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3d43b7ce6bc97753ac7856c3ab1ba70` |
| SHA-1 | `7bb8a3d3f92c872d6c0d4031e940618963fcb39b` |
| SHA-256 | `c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e` |
| SHA3-384 | `78b423069f15e502cb8369a005937fd5296204c579cd67dfaf15fb89edd5a096262ac0b5f76a23b2e2de4075cb9d8950` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T163C46C2736A60E50C2951F73C59BA50083A6DA86B9E3F70FB28513661D033FEDE47693` |
| SSDEEP | `6144:Eo4XIeJJuusyWEI2jy7DOuglHRHw3c/VtaSxxOb5SiUQWoabtXmbLYUpwD+vAdTS:p44Ape2j93dRHwy+CU5/WoKX1hThHQJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_c0f61b3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e"
    family = "unknown"
    file_name = "c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e.exe"
    file_type = "exe"
    first_seen = "2026-10-30 01:25:22"
  condition:
    hash.sha256(0, filesize) == "c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e"
}
```

### Sample 92: `5db3f505afe99561`

| Field | Value |
|---|---|
| SHA-256 | `5db3f505afe99561ab98e028186867f578eac2186467150887865c93565850a4` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-10-30 01:10:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d156ac48da9cfd7e47af5ad67cceecfd` |
| SHA-1 | `c8907ca721a8a5d1fa2481a0f65b24fa4a2d9d02` |
| SHA-256 | `5db3f505afe99561ab98e028186867f578eac2186467150887865c93565850a4` |
| SHA3-384 | `3ca7ad7ee10d877ebc6fc7f98650a1428f6409a665a87d47bf76f8a71abb5baaf3f96f9e44ef637c1c30d3f61cf87f59` |
| TLSH | `T17A242A56FD819F11D5C016BAFF0E528E33131B78D2DE7213AE186F646B8B86B0E7A504` |
| TELFHASH | `t12b11d010931919f4b296946140ef6536766a218573193c25a2b8d9bf5e23ef0741080f` |
| SSDEEP | `6144:p3WynLP/2gmJfCw9zKxANulJfjVJUKiEetq2OaBXg920b/B0y5CK+W9KN:pWynLPOgwfCw9zaANulh5KK0tBOaBXYU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_5db3f505
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5db3f505afe99561ab98e028186867f578eac2186467150887865c93565850a4"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-30 01:10:20"
  condition:
    hash.sha256(0, filesize) == "5db3f505afe99561ab98e028186867f578eac2186467150887865c93565850a4"
}
```

### Sample 93: `414e138f6d5ee5b8`

| Field | Value |
|---|---|
| SHA-256 | `414e138f6d5ee5b863029e29ad0405bd2fa10a4f5f4401b9a06ac134873158c7` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-10-30 01:09:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99399548b2e0d87e970bf011ee949ca7` |
| SHA-1 | `cb7564643ba90c3c163ccd7c54fea3313269a7d5` |
| SHA-256 | `414e138f6d5ee5b863029e29ad0405bd2fa10a4f5f4401b9a06ac134873158c7` |
| SHA3-384 | `93d9fa6ffe72c6ec4b410923aaea6c31142dc0e8cb5a85a39fdb1adb303018cbd61b207cea0c4993da8fe42a9fb92c8f` |
| TLSH | `T1CA8312BCB6B1DC70D98008FA708C98CA60383F74B566795747A9C9157EDFA7028E4787` |
| SSDEEP | `1536:4eZTMCTefGMekr7MFGfww/1ZrCEQx/af4bpsg3lUg7LlGiOlAeduqpX8suPwcAxz:4sxvknMFGx1ZryxSf4bGg3lUgXlGitAZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_414e138f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "414e138f6d5ee5b863029e29ad0405bd2fa10a4f5f4401b9a06ac134873158c7"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-30 01:09:14"
  condition:
    hash.sha256(0, filesize) == "414e138f6d5ee5b863029e29ad0405bd2fa10a4f5f4401b9a06ac134873158c7"
}
```

### Sample 94: `98bd848f7e6f37ff`

| Field | Value |
|---|---|
| SHA-256 | `98bd848f7e6f37ffe9108bd5410f8f95250f928bc27d3cf65a79d22bfd208e81` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-10-30 00:46:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `554195d27c1cf2b99b120e9725b4fb4d` |
| SHA-1 | `2e4972dfa32c843bbc77a2d576c258eab65c06ad` |
| SHA-256 | `98bd848f7e6f37ffe9108bd5410f8f95250f928bc27d3cf65a79d22bfd208e81` |
| SHA3-384 | `5cf7539f8dd8e66b8c6560283cfd35d9dd745031553c2ed24c63b4a6648db837fb299d080d7ffbacb097843cfa0b6b60` |
| TLSH | `T17DC37C22D5BE6C0AC5D0B97602E703B3E0E797051298DA0EBD551FACEF17790396B728` |
| TELFHASH | `t1e3012048ec7ece3d59e39830ec7843929053ca3250a28b349f59d6c9843e20af118e0f` |
| SSDEEP | `3072:Irr94gZ3r940/+r+O8KFVoPeKVQBPxBfWRr379h:IHigZ7iO+XmeRB7a9h` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_98bd848f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98bd848f7e6f37ffe9108bd5410f8f95250f928bc27d3cf65a79d22bfd208e81"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-10-30 00:46:11"
  condition:
    hash.sha256(0, filesize) == "98bd848f7e6f37ffe9108bd5410f8f95250f928bc27d3cf65a79d22bfd208e81"
}
```

### Sample 95: `038fb6a3b1cbb208`

| Field | Value |
|---|---|
| SHA-256 | `038fb6a3b1cbb208f05b372e085a1588a8d6701ff247b1700eae01008b7b9752` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-10-30 00:45:39` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e3442e667e61a2462d9516a98ad1713` |
| SHA-1 | `61f2a2db1f55fc69577c252b95ddf14b4c5adfce` |
| SHA-256 | `038fb6a3b1cbb208f05b372e085a1588a8d6701ff247b1700eae01008b7b9752` |
| SHA3-384 | `d6791576173fe478af82aa3106c5c09e54ce5ef15e2e75e370d570be25f6312543886a69d7b5c9757f3800716f388c8c` |
| IMPHASH | `5a594319a0d69dbc452e748bcf05892e` |
| TLSH | `T16A47333BF268643EC59A0B314AB396109D3BBB2178598C6F17F0850DCF279611E3B766` |
| SSDEEP | `393216:HVNXTMr0o/Gym+fF4WjSV1X0vHQL1e4prTJkyyMRAvUTHTcpKfLkzG9uU48YYC:HjX4r0jkfF901X0s3JCcAtp6YJL` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_038fb6a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "038fb6a3b1cbb208f05b372e085a1588a8d6701ff247b1700eae01008b7b9752"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-30 00:45:39"
  condition:
    hash.sha256(0, filesize) == "038fb6a3b1cbb208f05b372e085a1588a8d6701ff247b1700eae01008b7b9752"
}
```

### Sample 96: `7ecb1e48abd98523`

| Field | Value |
|---|---|
| SHA-256 | `7ecb1e48abd985233e3b70fee0fc648e05ae5e1df2685c30903a30262de3dac8` |
| Family label | `GuLoader` |
| File name | `Paatrykkes.vbs` |
| File type | `vbs` |
| First seen | `2026-10-30 00:43:01` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a978560ebd16a8c7decf2c7c26e788a` |
| SHA-1 | `9b2655612da31738c90973b1841b34670733d141` |
| SHA-256 | `7ecb1e48abd985233e3b70fee0fc648e05ae5e1df2685c30903a30262de3dac8` |
| SHA3-384 | `26fb83bfef2cfd73323ccc1a0fc4c626e5f9b0a334a958993a9b6b5864161ab144e34a545dad3fc2fa4001b39ed4584e` |
| TLSH | `T14DA33A1AFABE3D242F8F9F5D7C680B5887E48D0DDB13286CE8A453C7120B95CF1A8955` |
| SSDEEP | `1536:+csUBU96g0aE5INYgLrtbix4uY3AKLJ7YYyy63o:+cx06ge5HgLrMx4uURpYY9Go` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_096_7ecb1e48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ecb1e48abd985233e3b70fee0fc648e05ae5e1df2685c30903a30262de3dac8"
    family = "GuLoader"
    file_name = "Paatrykkes.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 00:43:01"
  condition:
    hash.sha256(0, filesize) == "7ecb1e48abd985233e3b70fee0fc648e05ae5e1df2685c30903a30262de3dac8"
}
```

### Sample 97: `03df0e485f3e3e83`

| Field | Value |
|---|---|
| SHA-256 | `03df0e485f3e3e8388810b650459a92268da897f226c2c5af3331e22498eba99` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-10-30 00:40:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35f0b5661d7f6d0ddd1522fa9c6577ad` |
| SHA-1 | `321bb5613becc22a5c9d7c1950a26be3dca9c5dd` |
| SHA-256 | `03df0e485f3e3e8388810b650459a92268da897f226c2c5af3331e22498eba99` |
| SHA3-384 | `b5bbe76286d80f690af97be191a8cabea375994d8149ec6eec946f3567848c839a04880712371f55fd4682c76de1bdba` |
| TLSH | `T1E4244B01B71D0943E2A32DF03A3F27E1D3DE95D131E8AA443A0EB7859272D326595EDE` |
| SSDEEP | `3072:UyezKy0bd8GfQSYcbCdkmxR9ZT1Fk6eBdan3Y4sByNHj9LYKP:UyeMBsdjdkmx1T1Fk6Ada3YO9Lp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_03df0e48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03df0e485f3e3e8388810b650459a92268da897f226c2c5af3331e22498eba99"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-30 00:40:28"
  condition:
    hash.sha256(0, filesize) == "03df0e485f3e3e8388810b650459a92268da897f226c2c5af3331e22498eba99"
}
```

### Sample 98: `c064f815d1d28b34`

| Field | Value |
|---|---|
| SHA-256 | `c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c` |
| Family label | `ConnectWise` |
| File name | `c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c.msi` |
| File type | `msi` |
| First seen | `2026-10-30 00:39:50` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0c874bf5ab6955aa08bfc23a0da5b18` |
| SHA-1 | `4ed3c216d20498cbd2e03249eb2eaf3713feb00a` |
| SHA-256 | `c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c` |
| SHA3-384 | `5af2f93c16cb8122118e059346b390bc42291f112bcdc25b92e3ce0bc462ef964aab448932f7d716df511c519ccd210d` |
| TLSH | `T168D623116BF89278F0F26A39E87AA071A5377D115E22D12E2324791E2C75EC0C9B3777` |
| SSDEEP | `196608:AHxcp9ym3nltDUJV6Hxcp9ym3dHxcp9ym3DHxcp9ym3BHxcp9ym3QHxcp9ym30Hk:uGplp9GpPGptGpzGp+GpSGp` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_098_c064f815
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c"
    family = "ConnectWise"
    file_name = "c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c.msi"
    file_type = "msi"
    first_seen = "2026-10-30 00:39:50"
  condition:
    hash.sha256(0, filesize) == "c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c"
}
```

### Sample 99: `8296537d43829b79`

| Field | Value |
|---|---|
| SHA-256 | `8296537d43829b79e0eef4236768a20a5d2c28a3f4436af6fbeab7688ae04045` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-10-30 00:39:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15db499a2e2d4e4167f384cfdea9e89b` |
| SHA-1 | `2ffdfa7b86a28ce31cf1ee5c994893c0c4288e32` |
| SHA-256 | `8296537d43829b79e0eef4236768a20a5d2c28a3f4436af6fbeab7688ae04045` |
| SHA3-384 | `2359b38ca0a6d6903482c2f1f432aac6ce660dcfb35ad7deb48648805c4f5ac6bcd4fa86346a3b2a85ba78f33ba8ffd7` |
| TLSH | `T1D2830221D54D1A59CFB4CE66B870B58063E07FCE274AC870794DC317EAA3C529BC58EA` |
| SSDEEP | `1536:QN72oXfr+/5urLxv2QT6pTP06cxI7e/BZxCGv9JkNdwSJaaSJ4u+qgw099:QN77XfY52Yg6cuSZxCGVJkNdLMPJ4u+7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_8296537d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8296537d43829b79e0eef4236768a20a5d2c28a3f4436af6fbeab7688ae04045"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-30 00:39:24"
  condition:
    hash.sha256(0, filesize) == "8296537d43829b79e0eef4236768a20a5d2c28a3f4436af6fbeab7688ae04045"
}
```

### Sample 100: `28550f9ba7f4791b`

| Field | Value |
|---|---|
| SHA-256 | `28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece` |
| Family label | `unknown` |
| File name | `28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece.exe` |
| File type | `exe` |
| First seen | `2026-10-30 00:35:46` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cc041f7c877c85e87d4130963842b6d` |
| SHA-1 | `2965fb319d26740f269c453cc3ef64dc787743be` |
| SHA-256 | `28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece` |
| SHA3-384 | `e2426763dd8eeb5c64eb52ca65c0b439722b371fe6a9d596673a92a86085036e35d63186364af42a57d3887d488e07e1` |
| IMPHASH | `e109e3dc9a35d66a19913489f828b335` |
| TLSH | `T18D94C1836291C0E7D0EE43B178516BD0B621BC313653BE7A07B07EE95E33B5D7A26219` |
| SSDEEP | `6144:QzEHYyBdKEo5L1T+fcxTPxeP7R/JfW84ff:0AYyBdKEo1t+fUxeP7RJWTf` |
| ICON-DHASH | `e08cd0c96ac69ce0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_28550f9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece"
    family = "unknown"
    file_name = "28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece.exe"
    file_type = "exe"
    first_seen = "2026-10-30 00:35:46"
  condition:
    hash.sha256(0, filesize) == "28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece"
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
 * Generated: 2026-10-30T05:59:26.453158+00:00
 */

rule MalwareBazaar_GuLoader_001_5e002592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e002592660e4f81cbbc369c59bdeef59f75a0ada044178417f99197c14521af"
    family = "GuLoader"
    file_name = "Bioclimatologies.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 05:45:01"
  condition:
    hash.sha256(0, filesize) == "5e002592660e4f81cbbc369c59bdeef59f75a0ada044178417f99197c14521af"
}

rule MalwareBazaar_SalatStealer_002_d95018b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d95018b09497989840be69c39fff5bc4c98cfebefe0bb4733fcc8b195a647abd"
    family = "SalatStealer"
    file_name = "c8cdca64a0d8ab3f.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:26:59"
  condition:
    hash.sha256(0, filesize) == "d95018b09497989840be69c39fff5bc4c98cfebefe0bb4733fcc8b195a647abd"
}

rule MalwareBazaar_SalatStealer_003_0886fff0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0886fff0dd90b3ed167d7b8f0bce41108582d6e773f19049a32816ffc34800a8"
    family = "SalatStealer"
    file_name = "75481e44b026106c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:26:50"
  condition:
    hash.sha256(0, filesize) == "0886fff0dd90b3ed167d7b8f0bce41108582d6e773f19049a32816ffc34800a8"
}

rule MalwareBazaar_SalatStealer_004_b6888137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b68881372c797ff50184731c060e0e63e85850d5a44f468b778a38f62329f8b5"
    family = "SalatStealer"
    file_name = "6dad3f2bba6b2da7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:26:39"
  condition:
    hash.sha256(0, filesize) == "b68881372c797ff50184731c060e0e63e85850d5a44f468b778a38f62329f8b5"
}

rule MalwareBazaar_SalatStealer_005_8f53fd95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f53fd954525f1e941eb7ccd6244ec0ea03f2209a96ec48f65b2e72e8200d684"
    family = "SalatStealer"
    file_name = "d193e33c97583d36.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:59"
  condition:
    hash.sha256(0, filesize) == "8f53fd954525f1e941eb7ccd6244ec0ea03f2209a96ec48f65b2e72e8200d684"
}

rule MalwareBazaar_SalatStealer_006_62065919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "620659195b33b307299a439e28a8398c4221627c1df14e7c89b9dea39897e44f"
    family = "SalatStealer"
    file_name = "771670ebf0cba43b.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:53"
  condition:
    hash.sha256(0, filesize) == "620659195b33b307299a439e28a8398c4221627c1df14e7c89b9dea39897e44f"
}

rule MalwareBazaar_SalatStealer_007_c8cdca64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8cdca64a0d8ab3f6c44196563509091c65b0bfa66f101c49f320a5df929c4c8"
    family = "SalatStealer"
    file_name = "c8cdca64a0d8ab3f.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:48"
  condition:
    hash.sha256(0, filesize) == "c8cdca64a0d8ab3f6c44196563509091c65b0bfa66f101c49f320a5df929c4c8"
}

rule MalwareBazaar_SalatStealer_008_8484b5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8484b5d5e7ab96ec903699bff316e3ba82b192b874b70e97a9a034f58c863712"
    family = "SalatStealer"
    file_name = "2daf5f51807550ef.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:47"
  condition:
    hash.sha256(0, filesize) == "8484b5d5e7ab96ec903699bff316e3ba82b192b874b70e97a9a034f58c863712"
}

rule MalwareBazaar_SalatStealer_009_870b4e6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870b4e6a56890671098629b17ac2c55396aed7edc041a4e628801397315d5fa4"
    family = "SalatStealer"
    file_name = "b592a23662fd9db7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:40"
  condition:
    hash.sha256(0, filesize) == "870b4e6a56890671098629b17ac2c55396aed7edc041a4e628801397315d5fa4"
}

rule MalwareBazaar_SalatStealer_010_75481e44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75481e44b026106cc688fffe05e08d0593c133f0cb505b69f0987542fd89cdd3"
    family = "SalatStealer"
    file_name = "75481e44b026106c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:38"
  condition:
    hash.sha256(0, filesize) == "75481e44b026106cc688fffe05e08d0593c133f0cb505b69f0987542fd89cdd3"
}

rule MalwareBazaar_SalatStealer_011_376ea442
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "376ea4423d3a38dbe09aab41362b84a6213b57a6146ade2ce817ec4c15d2db7f"
    family = "SalatStealer"
    file_name = "57d55ef78975070a.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:33"
  condition:
    hash.sha256(0, filesize) == "376ea4423d3a38dbe09aab41362b84a6213b57a6146ade2ce817ec4c15d2db7f"
}

rule MalwareBazaar_SalatStealer_012_6dad3f2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dad3f2bba6b2da7c7ad7e04f6f68259f17930c5bfb3eaa5c17c0209ba8e234a"
    family = "SalatStealer"
    file_name = "6dad3f2bba6b2da7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:28"
  condition:
    hash.sha256(0, filesize) == "6dad3f2bba6b2da7c7ad7e04f6f68259f17930c5bfb3eaa5c17c0209ba8e234a"
}

rule MalwareBazaar_SalatStealer_013_d193e33c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d193e33c97583d368b16c384c9cd266828ebb4d910c5e9713e0c6bc2ed95a3dc"
    family = "SalatStealer"
    file_name = "d193e33c97583d36.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:18"
  condition:
    hash.sha256(0, filesize) == "d193e33c97583d368b16c384c9cd266828ebb4d910c5e9713e0c6bc2ed95a3dc"
}

rule MalwareBazaar_RemcosRAT_014_641f9023
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "641f902317c84654c988c224abfd1c54671db7bcd56f0bda0c6a230f7292b114"
    family = "RemcosRAT"
    file_name = "Purchase Order.JS.js"
    file_type = "js"
    first_seen = "2026-10-30 05:25:09"
  condition:
    hash.sha256(0, filesize) == "641f902317c84654c988c224abfd1c54671db7bcd56f0bda0c6a230f7292b114"
}

rule MalwareBazaar_SalatStealer_015_771670eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "771670ebf0cba43bc47449e8f40c892c232d93a45442f6cf1c72dc77053adb21"
    family = "SalatStealer"
    file_name = "771670ebf0cba43b.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:25:08"
  condition:
    hash.sha256(0, filesize) == "771670ebf0cba43bc47449e8f40c892c232d93a45442f6cf1c72dc77053adb21"
}

rule MalwareBazaar_SalatStealer_016_2daf5f51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2daf5f51807550efe14cfb6cd99eb305f2b1bd6e726404335ed61267d6f8603a"
    family = "SalatStealer"
    file_name = "2daf5f51807550ef.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:24:58"
  condition:
    hash.sha256(0, filesize) == "2daf5f51807550efe14cfb6cd99eb305f2b1bd6e726404335ed61267d6f8603a"
}

rule MalwareBazaar_SalatStealer_017_b592a236
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b592a23662fd9db7b33d1c92a8ddf2d35a7709e94fc5b9fafbac609540ff76e1"
    family = "SalatStealer"
    file_name = "b592a23662fd9db7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:24:48"
  condition:
    hash.sha256(0, filesize) == "b592a23662fd9db7b33d1c92a8ddf2d35a7709e94fc5b9fafbac609540ff76e1"
}

rule MalwareBazaar_SalatStealer_018_57d55ef7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57d55ef78975070a9a4147756d213185d9dea0a0170536767cd0b9988715fafb"
    family = "SalatStealer"
    file_name = "57d55ef78975070a.bin"
    file_type = "exe"
    first_seen = "2026-10-30 05:24:38"
  condition:
    hash.sha256(0, filesize) == "57d55ef78975070a9a4147756d213185d9dea0a0170536767cd0b9988715fafb"
}

rule MalwareBazaar_unknown_019_0c32e412
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d"
    family = "unknown"
    file_name = "0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d.sh"
    file_type = "sh"
    first_seen = "2026-10-30 04:59:26"
  condition:
    hash.sha256(0, filesize) == "0c32e41265d77469e9fe3b14af5b9cc32ae2a333ebf6fc16d383df9b0bd30f8d"
}

rule MalwareBazaar_unknown_020_c3eec7ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3eec7ca615e28918446d87032d4630279a77979a8e863cc43456b109d664d48"
    family = "unknown"
    file_name = "macho_c3eec7ca615e.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:59:23"
  condition:
    hash.sha256(0, filesize) == "c3eec7ca615e28918446d87032d4630279a77979a8e863cc43456b109d664d48"
}

rule MalwareBazaar_unknown_021_2e3305a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e3305a363e07974160046dfc9d033f88697dccbdb54a41ce15cfe6ee8648580"
    family = "unknown"
    file_name = "macho_2e3305a363e0.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:54:40"
  condition:
    hash.sha256(0, filesize) == "2e3305a363e07974160046dfc9d033f88697dccbdb54a41ce15cfe6ee8648580"
}

rule MalwareBazaar_Mirai_022_03a680cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03a680cd8b8c2323d4f78bf578220aec930188a98143b3878160f0d9b8335b40"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-10-30 04:53:57"
  condition:
    hash.sha256(0, filesize) == "03a680cd8b8c2323d4f78bf578220aec930188a98143b3878160f0d9b8335b40"
}

rule MalwareBazaar_unknown_023_25d27691
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25d276912d13fe510558f6e4382bd4cfd4b94cdfa84f5080dfee082cdc5fdcc4"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-10-30 04:50:24"
  condition:
    hash.sha256(0, filesize) == "25d276912d13fe510558f6e4382bd4cfd4b94cdfa84f5080dfee082cdc5fdcc4"
}

rule MalwareBazaar_unknown_024_fa000739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa0007391da2cbd9c0b15937f1ce0e389f4d2d7f392f50331a4e831d2516834c"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-10-30 04:50:07"
  condition:
    hash.sha256(0, filesize) == "fa0007391da2cbd9c0b15937f1ce0e389f4d2d7f392f50331a4e831d2516834c"
}

rule MalwareBazaar_unknown_025_2a93e929
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a93e929b69caa6dc56901cda012b0073d83a4682a025193a0fc7234fedff83f"
    family = "unknown"
    file_name = "macho_2a93e929b69c.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:49:56"
  condition:
    hash.sha256(0, filesize) == "2a93e929b69caa6dc56901cda012b0073d83a4682a025193a0fc7234fedff83f"
}

rule MalwareBazaar_unknown_026_905e2e48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "905e2e48e90e0d4aa332e7c39e9d7a41407fdc5bc78bad14c46294ec5c08b784"
    family = "unknown"
    file_name = "905e2e48e90e0d4a.py"
    file_type = "py"
    first_seen = "2026-10-30 04:48:14"
  condition:
    hash.sha256(0, filesize) == "905e2e48e90e0d4aa332e7c39e9d7a41407fdc5bc78bad14c46294ec5c08b784"
}

rule MalwareBazaar_unknown_027_61d6b309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61d6b309d9774d13d632322816260e082f96293087333e7a379310e7b0796be0"
    family = "unknown"
    file_name = "61d6b309d9774d13.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 04:48:05"
  condition:
    hash.sha256(0, filesize) == "61d6b309d9774d13d632322816260e082f96293087333e7a379310e7b0796be0"
}

rule MalwareBazaar_unknown_028_3aaaa49a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aaaa49a0c4b139a8098b27dba31235571f68b32d96e25669e7febe6c82976d9"
    family = "unknown"
    file_name = "3aaaa49a0c4b139a.cmd"
    file_type = "cmd"
    first_seen = "2026-10-30 04:47:56"
  condition:
    hash.sha256(0, filesize) == "3aaaa49a0c4b139a8098b27dba31235571f68b32d96e25669e7febe6c82976d9"
}

rule MalwareBazaar_unknown_029_eb38f2f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb38f2f91b58545f0511de0954534472e65de8b07abb57cee40a73576b0318af"
    family = "unknown"
    file_name = "macho_eb38f2f91b58.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:45:18"
  condition:
    hash.sha256(0, filesize) == "eb38f2f91b58545f0511de0954534472e65de8b07abb57cee40a73576b0318af"
}

rule MalwareBazaar_unknown_030_cb0062fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb0062fa365e815cd28c5ac8237a241b7a50ffb9d2aefc772cec784785a59ad0"
    family = "unknown"
    file_name = "cb0062fa365e815c_decoded-stage.zsh"
    file_type = "zsh"
    first_seen = "2026-10-30 04:42:26"
  condition:
    hash.sha256(0, filesize) == "cb0062fa365e815cd28c5ac8237a241b7a50ffb9d2aefc772cec784785a59ad0"
}

rule MalwareBazaar_unknown_031_9eabb901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eabb901cc361b1b74cda3d7449ccc45d4b142c822c5e78b47246b0d8bbf7bee"
    family = "unknown"
    file_name = "macho_9eabb901cc36.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:40:35"
  condition:
    hash.sha256(0, filesize) == "9eabb901cc361b1b74cda3d7449ccc45d4b142c822c5e78b47246b0d8bbf7bee"
}

rule MalwareBazaar_unknown_032_a8ee26aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ee26aaa41e04b86cdeebd2c3748171bec0f8e4fab02f9a48cd5bbedd5db544"
    family = "unknown"
    file_name = "macho_a8ee26aaa41e.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:35:48"
  condition:
    hash.sha256(0, filesize) == "a8ee26aaa41e04b86cdeebd2c3748171bec0f8e4fab02f9a48cd5bbedd5db544"
}

rule MalwareBazaar_unknown_033_bb4568b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb4568b5a0a179f5391be75ac164900363133b29c24b225438f66c17a741d2dd"
    family = "unknown"
    file_name = "macho_bb4568b5a0a1.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:30:42"
  condition:
    hash.sha256(0, filesize) == "bb4568b5a0a179f5391be75ac164900363133b29c24b225438f66c17a741d2dd"
}

rule MalwareBazaar_SalatStealer_034_d86551d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d86551d45a34c7941768dd04e8cbb96f8ab4344bed2ad13f9a993cb2d3731812"
    family = "SalatStealer"
    file_name = "2d4caec37be793fa.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:26:41"
  condition:
    hash.sha256(0, filesize) == "d86551d45a34c7941768dd04e8cbb96f8ab4344bed2ad13f9a993cb2d3731812"
}

rule MalwareBazaar_unknown_035_f9713062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9713062c7f48d9689b2f921def5c3ebcb35e036b2ab694d625102dbadce8b52"
    family = "unknown"
    file_name = "macho_f9713062c7f4.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:26:05"
  condition:
    hash.sha256(0, filesize) == "f9713062c7f48d9689b2f921def5c3ebcb35e036b2ab694d625102dbadce8b52"
}

rule MalwareBazaar_SalatStealer_036_40b3daa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40b3daa9cf994704313ee59bc8cfbd6807d5a174173fa07b2056e2693999ae59"
    family = "SalatStealer"
    file_name = "92854c890d6fe100.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:59"
  condition:
    hash.sha256(0, filesize) == "40b3daa9cf994704313ee59bc8cfbd6807d5a174173fa07b2056e2693999ae59"
}

rule MalwareBazaar_SalatStealer_037_a9588db7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9588db7e895e28cd1cd7fb2e46ea08a626800fedd549fae9845c35db8b00691"
    family = "SalatStealer"
    file_name = "a41edbb52c94d58c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:53"
  condition:
    hash.sha256(0, filesize) == "a9588db7e895e28cd1cd7fb2e46ea08a626800fedd549fae9845c35db8b00691"
}

rule MalwareBazaar_SalatStealer_038_fa1c4e3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa1c4e3c842df81fae1772046eb456d67ef95afd9dca58dbae9dd33b8d907af1"
    family = "SalatStealer"
    file_name = "95424c6f72424f3b.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:48"
  condition:
    hash.sha256(0, filesize) == "fa1c4e3c842df81fae1772046eb456d67ef95afd9dca58dbae9dd33b8d907af1"
}

rule MalwareBazaar_SalatStealer_039_2613303e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2613303e7488c44063180a9d7d958efe8c72652f187ea2bbcd2e67984a6cb642"
    family = "SalatStealer"
    file_name = "d74572351d353e4e.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:40"
  condition:
    hash.sha256(0, filesize) == "2613303e7488c44063180a9d7d958efe8c72652f187ea2bbcd2e67984a6cb642"
}

rule MalwareBazaar_SalatStealer_040_1912921e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1912921e15be201b33e39053ff27945c22e7719713eca66589c8c8da65133a81"
    family = "SalatStealer"
    file_name = "cb41fdc089dd9303.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:34"
  condition:
    hash.sha256(0, filesize) == "1912921e15be201b33e39053ff27945c22e7719713eca66589c8c8da65133a81"
}

rule MalwareBazaar_SalatStealer_041_2d4caec3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d4caec37be793fa0cea5f370c7a06ab62f8325f3154e20be6f544d94bb3ad19"
    family = "SalatStealer"
    file_name = "2d4caec37be793fa.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:24"
  condition:
    hash.sha256(0, filesize) == "2d4caec37be793fa0cea5f370c7a06ab62f8325f3154e20be6f544d94bb3ad19"
}

rule MalwareBazaar_SalatStealer_042_92854c89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92854c890d6fe100858ffae5f213eb89ece3cdd4f72984adca1eb3439f240458"
    family = "SalatStealer"
    file_name = "92854c890d6fe100.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:14"
  condition:
    hash.sha256(0, filesize) == "92854c890d6fe100858ffae5f213eb89ece3cdd4f72984adca1eb3439f240458"
}

rule MalwareBazaar_SalatStealer_043_a41edbb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a41edbb52c94d58ca11aa599b0e168336537444fa55bc0597ccc25ce18ee2ad8"
    family = "SalatStealer"
    file_name = "a41edbb52c94d58c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:25:03"
  condition:
    hash.sha256(0, filesize) == "a41edbb52c94d58ca11aa599b0e168336537444fa55bc0597ccc25ce18ee2ad8"
}

rule MalwareBazaar_SalatStealer_044_95424c6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95424c6f72424f3b1f0ec1b3d3a3f89b9623b41a9ad828c8c9a97386c4d6d76f"
    family = "SalatStealer"
    file_name = "95424c6f72424f3b.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:24:54"
  condition:
    hash.sha256(0, filesize) == "95424c6f72424f3b1f0ec1b3d3a3f89b9623b41a9ad828c8c9a97386c4d6d76f"
}

rule MalwareBazaar_SalatStealer_045_d7457235
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d74572351d353e4e3df810c99361baddce5b966ce0c5e8c833f31612140f9024"
    family = "SalatStealer"
    file_name = "d74572351d353e4e.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:24:44"
  condition:
    hash.sha256(0, filesize) == "d74572351d353e4e3df810c99361baddce5b966ce0c5e8c833f31612140f9024"
}

rule MalwareBazaar_SalatStealer_046_cb41fdc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb41fdc089dd930349d1ab001d506a62153473621c8555b77a59dd5943a07874"
    family = "SalatStealer"
    file_name = "cb41fdc089dd9303.bin"
    file_type = "exe"
    first_seen = "2026-10-30 04:24:34"
  condition:
    hash.sha256(0, filesize) == "cb41fdc089dd930349d1ab001d506a62153473621c8555b77a59dd5943a07874"
}

rule MalwareBazaar_unknown_047_23746b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23746b451646aeaec0e56f813c7654fd75cb3c5a6d7c0e75fcda66c6287e5df2"
    family = "unknown"
    file_name = "macho_23746b451646.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:21:13"
  condition:
    hash.sha256(0, filesize) == "23746b451646aeaec0e56f813c7654fd75cb3c5a6d7c0e75fcda66c6287e5df2"
}

rule MalwareBazaar_unknown_048_54c7ebe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54c7ebe70c5981d14bda4f2ed99adbac28fcf390e4ddd0e0f272dd893f6caa1b"
    family = "unknown"
    file_name = "macho_54c7ebe70c59.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:16:26"
  condition:
    hash.sha256(0, filesize) == "54c7ebe70c5981d14bda4f2ed99adbac28fcf390e4ddd0e0f272dd893f6caa1b"
}

rule MalwareBazaar_WannaCry_049_f5524521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822"
    family = "WannaCry"
    file_name = "f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822"
    file_type = "exe"
    first_seen = "2026-10-30 04:15:24"
  condition:
    hash.sha256(0, filesize) == "f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822"
}

rule MalwareBazaar_unknown_050_85279394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85279394e95efea3d2678c9561021cb4a9f7a4d88dbafc74668ee918fff0fd0a"
    family = "unknown"
    file_name = "macho_85279394e95e.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:11:47"
  condition:
    hash.sha256(0, filesize) == "85279394e95efea3d2678c9561021cb4a9f7a4d88dbafc74668ee918fff0fd0a"
}

rule MalwareBazaar_unknown_051_69092c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69092c70e390ba31429d4bbd08ca01eef3415e665551d3d3a66b673f36ed48d3"
    family = "unknown"
    file_name = "macho_69092c70e390.bin"
    file_type = "macho"
    first_seen = "2026-10-30 04:07:17"
  condition:
    hash.sha256(0, filesize) == "69092c70e390ba31429d4bbd08ca01eef3415e665551d3d3a66b673f36ed48d3"
}

rule MalwareBazaar_unknown_052_fca13846
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419"
    family = "unknown"
    file_name = "fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419"
    file_type = "elf"
    first_seen = "2026-10-30 03:50:06"
  condition:
    hash.sha256(0, filesize) == "fca13846d30c12351274e78df6895aca5912930f44f211fb69f0e0cbbf1ae419"
}

rule MalwareBazaar_OverlordRAT_053_2c496e41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6"
    family = "OverlordRAT"
    file_name = "2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6.exe"
    file_type = "exe"
    first_seen = "2026-10-30 03:45:45"
  condition:
    hash.sha256(0, filesize) == "2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6"
}

rule MalwareBazaar_OverlordRAT_054_782cdb17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8"
    family = "OverlordRAT"
    file_name = "782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8.exe"
    file_type = "exe"
    first_seen = "2026-10-30 03:45:37"
  condition:
    hash.sha256(0, filesize) == "782cdb174d91a2c9116c077cdb4f23c3280c617ad352f169f97f221dd8a5fbd8"
}

rule MalwareBazaar_unknown_055_058a59ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5"
    family = "unknown"
    file_name = "058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5.exe"
    file_type = "exe"
    first_seen = "2026-10-30 03:38:32"
  condition:
    hash.sha256(0, filesize) == "058a59adc40cfa2ef440ef16901dd84a2087e56f0df820916054a11525c25cd5"
}

rule MalwareBazaar_unknown_056_a8c8c65f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c8c65f81460cc3a93f8c1e4d366c2299119e5c570054a9c9d5658df9319530"
    family = "unknown"
    file_name = "FACEITInstaller_64.exe"
    file_type = "exe"
    first_seen = "2026-10-30 03:27:50"
  condition:
    hash.sha256(0, filesize) == "a8c8c65f81460cc3a93f8c1e4d366c2299119e5c570054a9c9d5658df9319530"
}

rule MalwareBazaar_SalatStealer_057_58a6d068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58a6d06873b5773ae10d442cd8fda21b5dc79fb7ca340dc3062f48ec2d280a8c"
    family = "SalatStealer"
    file_name = "a12e5c2fac9e0204.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:27:41"
  condition:
    hash.sha256(0, filesize) == "58a6d06873b5773ae10d442cd8fda21b5dc79fb7ca340dc3062f48ec2d280a8c"
}

rule MalwareBazaar_SalatStealer_058_b8b1c140
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8b1c14015de8e04efa1fcfcd95a71b79c89cdc788aacfb2e91cff5b6604772c"
    family = "SalatStealer"
    file_name = "47fd48ccfadd4246.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:58"
  condition:
    hash.sha256(0, filesize) == "b8b1c14015de8e04efa1fcfcd95a71b79c89cdc788aacfb2e91cff5b6604772c"
}

rule MalwareBazaar_SalatStealer_059_318a0399
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "318a039986594d58b3b669c716d8f7a13a261699f10ed82f8b5ef14234bbb4da"
    family = "SalatStealer"
    file_name = "b83bb0bedf80fdc7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:52"
  condition:
    hash.sha256(0, filesize) == "318a039986594d58b3b669c716d8f7a13a261699f10ed82f8b5ef14234bbb4da"
}

rule MalwareBazaar_SalatStealer_060_bb32aad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb32aad3a82e3f608aabb57e1b2744f97e18373872b8fee7749abd5500bf4ff5"
    family = "SalatStealer"
    file_name = "20ca642dc72d3b2e.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:46"
  condition:
    hash.sha256(0, filesize) == "bb32aad3a82e3f608aabb57e1b2744f97e18373872b8fee7749abd5500bf4ff5"
}

rule MalwareBazaar_SalatStealer_061_d13b1625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d13b1625624298fa966c3f63bc29db048111c03219d6f9a732b63b951f14e385"
    family = "SalatStealer"
    file_name = "78a9600e16431eb0.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:39"
  condition:
    hash.sha256(0, filesize) == "d13b1625624298fa966c3f63bc29db048111c03219d6f9a732b63b951f14e385"
}

rule MalwareBazaar_SalatStealer_062_7b1e6a0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b1e6a0f78057136d95643a801652649afb64b25798d6b296ee2b58025093eef"
    family = "SalatStealer"
    file_name = "219fe381157b3a2c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:31"
  condition:
    hash.sha256(0, filesize) == "7b1e6a0f78057136d95643a801652649afb64b25798d6b296ee2b58025093eef"
}

rule MalwareBazaar_SalatStealer_063_9bd124b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd124b714e997c744465e74d644ac7df44fe2a348c6b06cfd903dbe06a5c735"
    family = "SalatStealer"
    file_name = "d83a81b346d53f24.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:25"
  condition:
    hash.sha256(0, filesize) == "9bd124b714e997c744465e74d644ac7df44fe2a348c6b06cfd903dbe06a5c735"
}

rule MalwareBazaar_SalatStealer_064_a12e5c2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a12e5c2fac9e020414e8e2fe54ade89a0ced1aedb47999869f587cdde687e50c"
    family = "SalatStealer"
    file_name = "a12e5c2fac9e0204.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:17"
  condition:
    hash.sha256(0, filesize) == "a12e5c2fac9e020414e8e2fe54ade89a0ced1aedb47999869f587cdde687e50c"
}

rule MalwareBazaar_SalatStealer_065_47fd48cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47fd48ccfadd4246158e201272f754d2ed530bbcd06a8d60005aca8504b5c1e6"
    family = "SalatStealer"
    file_name = "47fd48ccfadd4246.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:26:07"
  condition:
    hash.sha256(0, filesize) == "47fd48ccfadd4246158e201272f754d2ed530bbcd06a8d60005aca8504b5c1e6"
}

rule MalwareBazaar_SalatStealer_066_b83bb0be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b83bb0bedf80fdc7a85314c50ca2f438075eb24bd737988d4fdeb37b2ba32e04"
    family = "SalatStealer"
    file_name = "b83bb0bedf80fdc7.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:57"
  condition:
    hash.sha256(0, filesize) == "b83bb0bedf80fdc7a85314c50ca2f438075eb24bd737988d4fdeb37b2ba32e04"
}

rule MalwareBazaar_SalatStealer_067_20ca642d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20ca642dc72d3b2e260eedae8be9e63afcbe43844140fd0148d91fb328dfb18c"
    family = "SalatStealer"
    file_name = "20ca642dc72d3b2e.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:47"
  condition:
    hash.sha256(0, filesize) == "20ca642dc72d3b2e260eedae8be9e63afcbe43844140fd0148d91fb328dfb18c"
}

rule MalwareBazaar_SalatStealer_068_78a9600e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a9600e16431eb0e2469b8c7eed2540c351a92e1204d0f4016307e0ec8da1e6"
    family = "SalatStealer"
    file_name = "78a9600e16431eb0.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:38"
  condition:
    hash.sha256(0, filesize) == "78a9600e16431eb0e2469b8c7eed2540c351a92e1204d0f4016307e0ec8da1e6"
}

rule MalwareBazaar_SalatStealer_069_63223cfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63223cfe6e860c5945971bf36e6782bb5e5c801638dc980062302c25337398f7"
    family = "SalatStealer"
    file_name = "a3021d32d573bb4a.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:28"
  condition:
    hash.sha256(0, filesize) == "63223cfe6e860c5945971bf36e6782bb5e5c801638dc980062302c25337398f7"
}

rule MalwareBazaar_SalatStealer_070_219fe381
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "219fe381157b3a2c9149a96dc7ebdf1ed088bb444a2244e9c5b3bebdf6308522"
    family = "SalatStealer"
    file_name = "219fe381157b3a2c.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:28"
  condition:
    hash.sha256(0, filesize) == "219fe381157b3a2c9149a96dc7ebdf1ed088bb444a2244e9c5b3bebdf6308522"
}

rule MalwareBazaar_SalatStealer_071_d83a81b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d83a81b346d53f24152535604b0087fa88eb7f9214dc996141b5778820bcb91b"
    family = "SalatStealer"
    file_name = "d83a81b346d53f24.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:18"
  condition:
    hash.sha256(0, filesize) == "d83a81b346d53f24152535604b0087fa88eb7f9214dc996141b5778820bcb91b"
}

rule MalwareBazaar_SalatStealer_072_a3021d32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3021d32d573bb4a64c3804fcc6bf95d756784e80c88dc0fe6223aada7ab2cb8"
    family = "SalatStealer"
    file_name = "a3021d32d573bb4a.bin"
    file_type = "exe"
    first_seen = "2026-10-30 03:25:08"
  condition:
    hash.sha256(0, filesize) == "a3021d32d573bb4a64c3804fcc6bf95d756784e80c88dc0fe6223aada7ab2cb8"
}

rule MalwareBazaar_Mirai_073_027ee201
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-30 03:18:16"
  condition:
    hash.sha256(0, filesize) == "027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f"
}

rule MalwareBazaar_WannaCry_074_ac29dd46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1"
    family = "WannaCry"
    file_name = "ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1"
    file_type = "exe"
    first_seen = "2026-10-30 03:15:15"
  condition:
    hash.sha256(0, filesize) == "ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1"
}

rule MalwareBazaar_unknown_075_fd3bf009
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d"
    family = "unknown"
    file_name = "fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d.bin"
    file_type = "sh"
    first_seen = "2026-10-30 02:59:16"
  condition:
    hash.sha256(0, filesize) == "fd3bf0098efb117fef62fcc2dd486d9aefac4f25116129324c4472dbb31b551d"
}

rule MalwareBazaar_Mirai_076_50467b69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50467b69921dd34c67ddcbbdb529f81159844c6e80effe4b4ccb06725b14f26e"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-30 02:53:19"
  condition:
    hash.sha256(0, filesize) == "50467b69921dd34c67ddcbbdb529f81159844c6e80effe4b4ccb06725b14f26e"
}

rule MalwareBazaar_Mirai_077_278bd6ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "278bd6ea4a998a126fc59102a339d2f2ad879de6c99addcc532465a11cce67bf"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-30 02:52:59"
  condition:
    hash.sha256(0, filesize) == "278bd6ea4a998a126fc59102a339d2f2ad879de6c99addcc532465a11cce67bf"
}

rule MalwareBazaar_Formbook_078_db5a90a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db5a90a147265bf5f253ce1e8f7a40a8cf5197f5d90f0a6c4cbe4c2328f18f14"
    family = "Formbook"
    file_name = "Permintan Penawaran Harga CV. ANUGRAH M.js"
    file_type = "js"
    first_seen = "2026-10-30 02:48:02"
  condition:
    hash.sha256(0, filesize) == "db5a90a147265bf5f253ce1e8f7a40a8cf5197f5d90f0a6c4cbe4c2328f18f14"
}

rule MalwareBazaar_GuLoader_079_2ec5493b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec5493be911c869dc4729f77e6b0daa8c775aa972bcfb18a427074270fe587f"
    family = "GuLoader"
    file_name = "Argante.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 02:40:20"
  condition:
    hash.sha256(0, filesize) == "2ec5493be911c869dc4729f77e6b0daa8c775aa972bcfb18a427074270fe587f"
}

rule MalwareBazaar_SalatStealer_080_fc5eeaca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc5eeacaf8c5453827a864a4895628118c9f08df780f3f961a592152b3ca0137"
    family = "SalatStealer"
    file_name = "a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:39:20"
  condition:
    hash.sha256(0, filesize) == "fc5eeacaf8c5453827a864a4895628118c9f08df780f3f961a592152b3ca0137"
}

rule MalwareBazaar_SalatStealer_081_a0150547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d"
    family = "SalatStealer"
    file_name = "a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:38:33"
  condition:
    hash.sha256(0, filesize) == "a0150547114a3b5d48728afe684c983aa4fe4cb950f791cb120b2256ba39847d"
}

rule MalwareBazaar_Mirai_082_ea04ba91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea04ba910ce5fd987031377d8e17faaae855f8c9743f550a045f800820ecace4"
    family = "Mirai"
    file_name = "e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:24:21"
  condition:
    hash.sha256(0, filesize) == "ea04ba910ce5fd987031377d8e17faaae855f8c9743f550a045f800820ecace4"
}

rule MalwareBazaar_Mirai_083_e0805ad4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48"
    family = "Mirai"
    file_name = "e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:23:32"
  condition:
    hash.sha256(0, filesize) == "e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48"
}

rule MalwareBazaar_Mirai_084_6e20b185
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e20b1859bf3072a5e6fbdd81d3e03279becbf1dee8503207b4ea1d86e569d3a"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-30 02:15:29"
  condition:
    hash.sha256(0, filesize) == "6e20b1859bf3072a5e6fbdd81d3e03279becbf1dee8503207b4ea1d86e569d3a"
}

rule MalwareBazaar_unknown_085_db6edde2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014"
    family = "unknown"
    file_name = "db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014.exe"
    file_type = "exe"
    first_seen = "2026-10-30 02:13:36"
  condition:
    hash.sha256(0, filesize) == "db6edde280746449f017cce7fa43bf383f1cd6a3606a39cd14c78b1e24b4f014"
}

rule MalwareBazaar_GuLoader_086_230675c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "230675c608fc6f82517f6c1733dc24d643007f206d2f2bd26ee1123ab9d4ff2b"
    family = "GuLoader"
    file_name = "likeways.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 02:10:36"
  condition:
    hash.sha256(0, filesize) == "230675c608fc6f82517f6c1733dc24d643007f206d2f2bd26ee1123ab9d4ff2b"
}

rule MalwareBazaar_Mirai_087_7c005720
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c00572008134d39687755c03cf38a6dc57ae970922ea4aab6b7ec8c15fac9df"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-30 01:56:17"
  condition:
    hash.sha256(0, filesize) == "7c00572008134d39687755c03cf38a6dc57ae970922ea4aab6b7ec8c15fac9df"
}

rule MalwareBazaar_unknown_088_31592658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31592658015dacf038dffbf98b41d0eca512a310f60094ac676179c5aaa0f57e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win32.MalwareX-gen.1259.29265"
    file_type = "exe"
    first_seen = "2026-10-30 01:30:19"
  condition:
    hash.sha256(0, filesize) == "31592658015dacf038dffbf98b41d0eca512a310f60094ac676179c5aaa0f57e"
}

rule MalwareBazaar_Mirai_089_376549b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "376549b7dea66fb5aed231cb1e3637147f21278593886ef7292351e05f39a412"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-10-30 01:27:18"
  condition:
    hash.sha256(0, filesize) == "376549b7dea66fb5aed231cb1e3637147f21278593886ef7292351e05f39a412"
}

rule MalwareBazaar_Mirai_090_763a76c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "763a76c9d818a6706ebda12b09d57f5596a564debaa7bcade80d4db409b89473"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-10-30 01:26:32"
  condition:
    hash.sha256(0, filesize) == "763a76c9d818a6706ebda12b09d57f5596a564debaa7bcade80d4db409b89473"
}

rule MalwareBazaar_unknown_091_c0f61b3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e"
    family = "unknown"
    file_name = "c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e.exe"
    file_type = "exe"
    first_seen = "2026-10-30 01:25:22"
  condition:
    hash.sha256(0, filesize) == "c0f61b3eef8b8100c900427cb4313e7ed25465b6c695aec3dc3ace5e7031b78e"
}

rule MalwareBazaar_Mirai_092_5db3f505
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5db3f505afe99561ab98e028186867f578eac2186467150887865c93565850a4"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-30 01:10:20"
  condition:
    hash.sha256(0, filesize) == "5db3f505afe99561ab98e028186867f578eac2186467150887865c93565850a4"
}

rule MalwareBazaar_Mirai_093_414e138f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "414e138f6d5ee5b863029e29ad0405bd2fa10a4f5f4401b9a06ac134873158c7"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-30 01:09:14"
  condition:
    hash.sha256(0, filesize) == "414e138f6d5ee5b863029e29ad0405bd2fa10a4f5f4401b9a06ac134873158c7"
}

rule MalwareBazaar_Mirai_094_98bd848f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98bd848f7e6f37ffe9108bd5410f8f95250f928bc27d3cf65a79d22bfd208e81"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-10-30 00:46:11"
  condition:
    hash.sha256(0, filesize) == "98bd848f7e6f37ffe9108bd5410f8f95250f928bc27d3cf65a79d22bfd208e81"
}

rule MalwareBazaar_unknown_095_038fb6a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "038fb6a3b1cbb208f05b372e085a1588a8d6701ff247b1700eae01008b7b9752"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-10-30 00:45:39"
  condition:
    hash.sha256(0, filesize) == "038fb6a3b1cbb208f05b372e085a1588a8d6701ff247b1700eae01008b7b9752"
}

rule MalwareBazaar_GuLoader_096_7ecb1e48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ecb1e48abd985233e3b70fee0fc648e05ae5e1df2685c30903a30262de3dac8"
    family = "GuLoader"
    file_name = "Paatrykkes.vbs"
    file_type = "vbs"
    first_seen = "2026-10-30 00:43:01"
  condition:
    hash.sha256(0, filesize) == "7ecb1e48abd985233e3b70fee0fc648e05ae5e1df2685c30903a30262de3dac8"
}

rule MalwareBazaar_Mirai_097_03df0e48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03df0e485f3e3e8388810b650459a92268da897f226c2c5af3331e22498eba99"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-30 00:40:28"
  condition:
    hash.sha256(0, filesize) == "03df0e485f3e3e8388810b650459a92268da897f226c2c5af3331e22498eba99"
}

rule MalwareBazaar_ConnectWise_098_c064f815
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c"
    family = "ConnectWise"
    file_name = "c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c.msi"
    file_type = "msi"
    first_seen = "2026-10-30 00:39:50"
  condition:
    hash.sha256(0, filesize) == "c064f815d1d28b34a06032ae614ecc4743101573b47ac14dcacf90e1dc61ca8c"
}

rule MalwareBazaar_Mirai_099_8296537d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8296537d43829b79e0eef4236768a20a5d2c28a3f4436af6fbeab7688ae04045"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-30 00:39:24"
  condition:
    hash.sha256(0, filesize) == "8296537d43829b79e0eef4236768a20a5d2c28a3f4436af6fbeab7688ae04045"
}

rule MalwareBazaar_unknown_100_28550f9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece"
    family = "unknown"
    file_name = "28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece.exe"
    file_type = "exe"
    first_seen = "2026-10-30 00:35:46"
  condition:
    hash.sha256(0, filesize) == "28550f9ba7f4791bb5be2ce17d67ed81d9ebfa6d15895aeee52cc23905bd6ece"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

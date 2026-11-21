# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-21

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
| Unique family labels | 3 |
| Unique file types | 3 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 69 |
| Mirai | 30 |
| Gafgyt | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 95 |
| macho | 4 |
| sh | 1 |

## Per-Sample Analysis

### Sample 1: `c767ea74ed7921a8`

| Field | Value |
|---|---|
| SHA-256 | `c767ea74ed7921a8c8e68ac66a143c4fd67b54884b4a0b10898a76fca418c36a` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `sh` |
| First seen | `2026-11-21 07:11:28` |
| Reporter | `pickledrick` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d71282e01dd6c0957a0ef55d42c65485` |
| SHA-1 | `ab0251a73003fe83589aaedfba32466e4a2bd62c` |
| SHA-256 | `c767ea74ed7921a8c8e68ac66a143c4fd67b54884b4a0b10898a76fca418c36a` |
| SHA3-384 | `2ec908983e10b6fb1255ec84e465ed160c9641b6521fedeeec1568e17ba2067f50fc52090cc8be53d8cfd5a264491474` |
| TLSH | `T15451BAE1FC76ED31768D153CAD4D569A2AC38D3B052938127083BD24376C51EA1A9B34` |
| SSDEEP | `48:G+B0O5TTerTcGAcQDef7zBDJ1vtrwxUIqzvX1OzvXVo:G+BxcjRJVtrBI4mi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_c767ea74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c767ea74ed7921a8c8e68ac66a143c4fd67b54884b4a0b10898a76fca418c36a"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-21 07:11:28"
  condition:
    hash.sha256(0, filesize) == "c767ea74ed7921a8c8e68ac66a143c4fd67b54884b4a0b10898a76fca418c36a"
}
```

### Sample 2: `832ad50276a88526`

| Field | Value |
|---|---|
| SHA-256 | `832ad50276a88526977ebf7a4d74333fb2dfd1cd875def573aa7dce8828399c1` |
| Family label | `unknown` |
| File name | `easyshell-l64-832ad50276a88526.bin` |
| File type | `elf` |
| First seen | `2026-11-21 07:06:43` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed91dd09d3c838be829daa4f887749d4` |
| SHA-1 | `2cc5bb4376f559aaf6230f22e2d4c4bda457fb1c` |
| SHA-256 | `832ad50276a88526977ebf7a4d74333fb2dfd1cd875def573aa7dce8828399c1` |
| SHA3-384 | `2a718390c415bf908dfe089b4446798a3f754ccc7d9d6e58b6d693ad64f65066b385e6e0608b2495364e8b02601734b7` |
| TLSH | `T178267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiWH8hIU6iKHh:OYjiiKgib9qRGcEulWcW+gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_832ad502
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "832ad50276a88526977ebf7a4d74333fb2dfd1cd875def573aa7dce8828399c1"
    family = "unknown"
    file_name = "easyshell-l64-832ad50276a88526.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:06:43"
  condition:
    hash.sha256(0, filesize) == "832ad50276a88526977ebf7a4d74333fb2dfd1cd875def573aa7dce8828399c1"
}
```

### Sample 3: `ea2a034979d02174`

| Field | Value |
|---|---|
| SHA-256 | `ea2a034979d021746346218c75a41f5ac5cd5dea93ed756698a6edfe5a04d66f` |
| Family label | `unknown` |
| File name | `easyshell-l32-ea2a034979d02174.bin` |
| File type | `elf` |
| First seen | `2026-11-21 07:06:34` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `419aba700edd3bc316ccba37c3f8b845` |
| SHA-1 | `6cc7c53d16e796d9692cb8d4943e589e4179fe6d` |
| SHA-256 | `ea2a034979d021746346218c75a41f5ac5cd5dea93ed756698a6edfe5a04d66f` |
| SHA3-384 | `b73cc66c1d1c651626dafa848ead394e599ddaee42e351c37747399ce49df352278473b7e10a8eaa0336db4963e33ee6` |
| TLSH | `T114068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1WF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Wdb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_ea2a0349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea2a034979d021746346218c75a41f5ac5cd5dea93ed756698a6edfe5a04d66f"
    family = "unknown"
    file_name = "easyshell-l32-ea2a034979d02174.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:06:34"
  condition:
    hash.sha256(0, filesize) == "ea2a034979d021746346218c75a41f5ac5cd5dea93ed756698a6edfe5a04d66f"
}
```

### Sample 4: `d4c8ec37ca836f0f`

| Field | Value |
|---|---|
| SHA-256 | `d4c8ec37ca836f0f01d1c1e1f34f549a37a09a251538f6e56a99cadc37e496fc` |
| Family label | `unknown` |
| File name | `easyshell-l128-d4c8ec37ca836f0f.bin` |
| File type | `elf` |
| First seen | `2026-11-21 07:06:25` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ee9fb3012b0e354f3fefd6a13c4224b` |
| SHA-1 | `6aec0b8a0719f48b7efda1054db35f7b2561fa00` |
| SHA-256 | `d4c8ec37ca836f0f01d1c1e1f34f549a37a09a251538f6e56a99cadc37e496fc` |
| SHA3-384 | `d8e64173a355ffd5291dfcc3bdc6b9b3efcb40b4c4f6341d94916e613fdd199741b311b37916745b76975832194af624` |
| TLSH | `T13B067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1Ck:FUkCxwUGnaPdX8P1AS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_d4c8ec37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4c8ec37ca836f0f01d1c1e1f34f549a37a09a251538f6e56a99cadc37e496fc"
    family = "unknown"
    file_name = "easyshell-l128-d4c8ec37ca836f0f.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:06:25"
  condition:
    hash.sha256(0, filesize) == "d4c8ec37ca836f0f01d1c1e1f34f549a37a09a251538f6e56a99cadc37e496fc"
}
```

### Sample 5: `1467a95824a3ea48`

| Field | Value |
|---|---|
| SHA-256 | `1467a95824a3ea48eadc43ca152218af2f6d2ef9880f391a1f7add91450bff1e` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-1467a95824a3ea48.bin` |
| File type | `macho` |
| First seen | `2026-11-21 07:06:17` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ed2d37c35fd9e3401829a5db18ab0ee` |
| SHA-1 | `9abc91014451533abc5645c68ac0e12129d1ea02` |
| SHA-256 | `1467a95824a3ea48eadc43ca152218af2f6d2ef9880f391a1f7add91450bff1e` |
| SHA3-384 | `09893ed20208d070f8455a60983d6b4cf4548cd98242f488e8f32f863792eabe868170496409654995537451d273acb1` |
| TLSH | `T177F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1TgTsj5g5FIU6icBV8GQU5NZm+lzg:8SeI1gkkvTgTt5C+OGU5NZm+lzg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_1467a958
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1467a95824a3ea48eadc43ca152218af2f6d2ef9880f391a1f7add91450bff1e"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-1467a95824a3ea48.bin"
    file_type = "macho"
    first_seen = "2026-11-21 07:06:17"
  condition:
    hash.sha256(0, filesize) == "1467a95824a3ea48eadc43ca152218af2f6d2ef9880f391a1f7add91450bff1e"
}
```

### Sample 6: `e6c4954796b5efee`

| Field | Value |
|---|---|
| SHA-256 | `e6c4954796b5efee464583ac52fad6b03e19d2d9792e960ecbcf1bfcc7635f59` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-e6c4954796b5efee.bin` |
| File type | `macho` |
| First seen | `2026-11-21 07:06:09` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6201b2b2ea8fb9ba9f7640c36ec265e4` |
| SHA-1 | `eafef7644a65ca5b731c5e34737da603c2d5e02d` |
| SHA-256 | `e6c4954796b5efee464583ac52fad6b03e19d2d9792e960ecbcf1bfcc7635f59` |
| SHA3-384 | `9587be50473020b7e9db1abfb693ca9578a027ce881f8a3ed1bb0bdc9da737b77e293d7594a03d734da2e44fa1367cb6` |
| TLSH | `T119168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO62Khx+wgbZmBlz3X:kyLbLNomEr62Kjb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_e6c49547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6c4954796b5efee464583ac52fad6b03e19d2d9792e960ecbcf1bfcc7635f59"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-e6c4954796b5efee.bin"
    file_type = "macho"
    first_seen = "2026-11-21 07:06:09"
  condition:
    hash.sha256(0, filesize) == "e6c4954796b5efee464583ac52fad6b03e19d2d9792e960ecbcf1bfcc7635f59"
}
```

### Sample 7: `d4ec31ed44698baa`

| Field | Value |
|---|---|
| SHA-256 | `d4ec31ed44698baae338d55ba1ed0f45ba959b1d84a1ff17ca1dbdc5ba439f3a` |
| Family label | `unknown` |
| File name | `easyshell-a64-d4ec31ed44698baa.bin` |
| File type | `elf` |
| First seen | `2026-11-21 07:06:00` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48ddc347506377126acdc5997b515988` |
| SHA-1 | `16211039d9bdad60cb7220ebab84f682173726b6` |
| SHA-256 | `d4ec31ed44698baae338d55ba1ed0f45ba959b1d84a1ff17ca1dbdc5ba439f3a` |
| SHA3-384 | `1518dab27f5ffeaec965f0c46a710b572df8978402629b22bad0feacaa5aa76399a65861ed8c7ae80f1eb39530ce7207` |
| TLSH | `T1B506B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WSGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WSLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_d4ec31ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4ec31ed44698baae338d55ba1ed0f45ba959b1d84a1ff17ca1dbdc5ba439f3a"
    family = "unknown"
    file_name = "easyshell-a64-d4ec31ed44698baa.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:06:00"
  condition:
    hash.sha256(0, filesize) == "d4ec31ed44698baae338d55ba1ed0f45ba959b1d84a1ff17ca1dbdc5ba439f3a"
}
```

### Sample 8: `93607de77b347997`

| Field | Value |
|---|---|
| SHA-256 | `93607de77b347997b832aac3f8bffd33e71846981eb293d29d6c03b352b99677` |
| Family label | `unknown` |
| File name | `easyshell-a32-93607de77b347997.bin` |
| File type | `elf` |
| First seen | `2026-11-21 07:05:52` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adc2a4e0bc80eac8173893be83a9d4dc` |
| SHA-1 | `b2119e9026392f17fe5c63340cf646346e235201` |
| SHA-256 | `93607de77b347997b832aac3f8bffd33e71846981eb293d29d6c03b352b99677` |
| SHA3-384 | `bb9eeb7b1186f06312f7e413b9edb2907f1ee696d7f8c5e80d8b63c711bb1abdeee7c07fdae6583b3e4251d9a1eb5a59` |
| TLSH | `T1C3F53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBj:FhvZpiEGUx+pVdq22laB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_93607de7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93607de77b347997b832aac3f8bffd33e71846981eb293d29d6c03b352b99677"
    family = "unknown"
    file_name = "easyshell-a32-93607de77b347997.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:05:52"
  condition:
    hash.sha256(0, filesize) == "93607de77b347997b832aac3f8bffd33e71846981eb293d29d6c03b352b99677"
}
```

### Sample 9: `462bf4dcddd8e8d8`

| Field | Value |
|---|---|
| SHA-256 | `462bf4dcddd8e8d8c3d6393d3ed95dbf99617cec2cc7db25c80b87c789fb27f3` |
| Family label | `Mirai` |
| File name | `main_arm64` |
| File type | `elf` |
| First seen | `2026-11-21 07:03:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16eef712ad2f079959a2eee71b6600a8` |
| SHA-1 | `32a4d69ac53b1690a37b6751de8601ca98f526b5` |
| SHA-256 | `462bf4dcddd8e8d8c3d6393d3ed95dbf99617cec2cc7db25c80b87c789fb27f3` |
| SHA3-384 | `f9df46f4580a191ae4618819c6f35f95b48c8b03db629ebc3aa5405f6b9277967fed1d06c5b0dabd5afdfc6f606fbe45` |
| TLSH | `T122A35A404D1EA825C7CAE4BC8C4E0A54B62F78781A35C3752D1292ECDB51AA85FF5FB3` |
| SSDEEP | `1536:PrNvyhcP8aVhdZ7xh+R9v+8MptHYdxKYM7pwhr01QtxL9RcBX4mSyV0rP7oM+:DbcR4pjHYiwkIp9Rcyr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_462bf4dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "462bf4dcddd8e8d8c3d6393d3ed95dbf99617cec2cc7db25c80b87c789fb27f3"
    family = "Mirai"
    file_name = "main_arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:03:09"
  condition:
    hash.sha256(0, filesize) == "462bf4dcddd8e8d8c3d6393d3ed95dbf99617cec2cc7db25c80b87c789fb27f3"
}
```

### Sample 10: `07bddf244fd8068f`

| Field | Value |
|---|---|
| SHA-256 | `07bddf244fd8068f2918c47a269b9ffcc9c696c0b838456c5c6ef370c3882a09` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-armv7` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:58` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d602b0db0bc8b9aaba657dd9652cd47c` |
| SHA-1 | `e40e93c5a82cadbdcf4e43bd92e0fdc0207d0f86` |
| SHA-256 | `07bddf244fd8068f2918c47a269b9ffcc9c696c0b838456c5c6ef370c3882a09` |
| SHA3-384 | `16de8101fde9f15943782a6afe15d91a5d6ebe0c6d3430cd191ba5de5640926e009f23ef0edafbd6b86699d7dfd51e08` |
| TLSH | `T1EFC63A97B9924982C4E43A37B8BE81C433631EB98B8756565D05FE3C3AFE5D90E38314` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:mjxP1B3f/k2EUMTA84Pi2M6haa5XP3IiNj/ZeO1+cqW93gfScwGBnf8xUwJwoeLE:u51BPc2hMTAK6lYoqcqoWcOED` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_07bddf24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07bddf244fd8068f2918c47a269b9ffcc9c696c0b838456c5c6ef370c3882a09"
    family = "unknown"
    file_name = "myc2-agent-linux-armv7"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:58"
  condition:
    hash.sha256(0, filesize) == "07bddf244fd8068f2918c47a269b9ffcc9c696c0b838456c5c6ef370c3882a09"
}
```

### Sample 11: `795245a2ceaa0d59`

| Field | Value |
|---|---|
| SHA-256 | `795245a2ceaa0d59a9a78e8672c97447a9cb14bf82a31872b85b00fb8a07ed47` |
| Family label | `Mirai` |
| File name | `hn101.b` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe9059dcd5461a6e19c276a4ee522e63` |
| SHA-1 | `2be7cf0292dcf83b27c633c6127d33cd1bcd96fd` |
| SHA-256 | `795245a2ceaa0d59a9a78e8672c97447a9cb14bf82a31872b85b00fb8a07ed47` |
| SHA3-384 | `32e708b9550025032588146d0714b71a383e2ac8625e2614bf1dec59864c43e6b7c5d99425208e7ba99e7e32eed11093` |
| TLSH | `T1A4466C4BF5A354ECC1AFC830475BDA53BA71746842317E3B3694AA302E63F605B69F21` |
| TELFHASH | `t146221fb48be534f1a1c7ca56e732f4b89ab304b626fd35b146277d81df94e410cba812` |
| SSDEEP | `98304:WblISCwlkwuds9b2BDTYA4LakE56gllyGLtPE8y66UB1hzc3FoT6ey6nZFqIToC5:BwllVtUf5aCy6jTZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_795245a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "795245a2ceaa0d59a9a78e8672c97447a9cb14bf82a31872b85b00fb8a07ed47"
    family = "Mirai"
    file_name = "hn101.b"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:55"
  condition:
    hash.sha256(0, filesize) == "795245a2ceaa0d59a9a78e8672c97447a9cb14bf82a31872b85b00fb8a07ed47"
}
```

### Sample 12: `bfb5f607f970408e`

| Field | Value |
|---|---|
| SHA-256 | `bfb5f607f970408e564af51c976a31889c6ec278abf53852b26d1f02733d0f03` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-amd64` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f4d46f058c2cdd367b1f306fa84a7b5` |
| SHA-1 | `9be0f7af472fce913dbc2551fd6c64aad0bbbe6b` |
| SHA-256 | `bfb5f607f970408e564af51c976a31889c6ec278abf53852b26d1f02733d0f03` |
| SHA3-384 | `4b3a99c5e18d2e50bbf3f6b91583145bb2d5f959f8de319f125cd983c73526c3dca400f80f631e8f0a06f2f421abb157` |
| TLSH | `T16A522357E3918E7EDEFC53B840D7063062B9F824667303135710B6386E937A47B1A5DA` |
| SSDEEP | `48:RkEZRxBWB0cH0U626drQFl1FIObiC8ZdsGuuZ+i0e8DAyagJr3Gh1:RkEdBWB0od626WbiCGupK+iAV3Gh1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_bfb5f607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfb5f607f970408e564af51c976a31889c6ec278abf53852b26d1f02733d0f03"
    family = "unknown"
    file_name = "myc2-preload-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:52"
  condition:
    hash.sha256(0, filesize) == "bfb5f607f970408e564af51c976a31889c6ec278abf53852b26d1f02733d0f03"
}
```

### Sample 13: `687a3594d494be74`

| Field | Value |
|---|---|
| SHA-256 | `687a3594d494be74a730d14772d1939577f90ba4267423128bdf7fb5cbb857f3` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-riscv64` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddbeaa8f7d2d8abfd24378b3ff86cd32` |
| SHA-1 | `7335a8a5078b99d608bb0cf9fd83f8644cd3097d` |
| SHA-256 | `687a3594d494be74a730d14772d1939577f90ba4267423128bdf7fb5cbb857f3` |
| SHA3-384 | `40ce451b5d6a904953320e70278542a6436ae1eeb45eee4e59b6a3a98989bd5a0d6eecabe95721469969d8b44c3781f1` |
| TLSH | `T1FCB69C07FA50AFA6CA3D41B6889613E46731FC145F938B971B14F23CAC7E6A45E853C2` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:D7m0WRj5US6IRCTUuz3ua7aQhgx45LgfScwGBnf8yzd5og9ftiYPdU75E9:Dc1USYu/d9ftidE9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_687a3594
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "687a3594d494be74a730d14772d1939577f90ba4267423128bdf7fb5cbb857f3"
    family = "unknown"
    file_name = "myc2-agent-linux-riscv64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:49"
  condition:
    hash.sha256(0, filesize) == "687a3594d494be74a730d14772d1939577f90ba4267423128bdf7fb5cbb857f3"
}
```

### Sample 14: `17d704b734a57f82`

| Field | Value |
|---|---|
| SHA-256 | `17d704b734a57f82150ad0ee9fb9d394026acd9bb7d2851b102e6b24721ea3d7` |
| Family label | `unknown` |
| File name | `cnc-linux-arm64` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed6718b257eaf0c42acf161217f4bc28` |
| SHA-1 | `c2d6154db688e67ccce659f4f24c999bfb10b3e6` |
| SHA-256 | `17d704b734a57f82150ad0ee9fb9d394026acd9bb7d2851b102e6b24721ea3d7` |
| SHA3-384 | `e724f15ea0accf37bc743257025f7953c603553193f871d4f7d4066c3215157ccbe3fbbd65e9012ed1e05e2c835bda6c` |
| TLSH | `T124B69D99F82C6952E6C971752F264294323DBC488F82C7276B14BB3DADF2B54CF13162` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:N0lkTblrrpCd1w/KzhaHAtTdKMoFQM1APtWi27nEG:N0W5rU1w/chagtTdK5QMqPoBEG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_17d704b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17d704b734a57f82150ad0ee9fb9d394026acd9bb7d2851b102e6b24721ea3d7"
    family = "unknown"
    file_name = "cnc-linux-arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:45"
  condition:
    hash.sha256(0, filesize) == "17d704b734a57f82150ad0ee9fb9d394026acd9bb7d2851b102e6b24721ea3d7"
}
```

### Sample 15: `7d365030af1e49f7`

| Field | Value |
|---|---|
| SHA-256 | `7d365030af1e49f7de82f9e6ab9629efd0fc38b69b8ef85abe24901f7dddac9e` |
| Family label | `unknown` |
| File name | `myc2-killer-linux-m68k` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f2969e532d47fa576b58a481b962606` |
| SHA-1 | `2e0e9225185a3477b3142ee12484de7dfd9b95c8` |
| SHA-256 | `7d365030af1e49f7de82f9e6ab9629efd0fc38b69b8ef85abe24901f7dddac9e` |
| SHA3-384 | `4ecf1805f9e774bdaa10446eee00621a47ec9c7a04238366286e72f3c97f0b5a5900fcbd70698265034553a4d375fd0d` |
| TLSH | `T1E4737C81930D3EAFD2C3FA3E855155126E20EF14F9030D2361B9B64B6AF766A2F3D505` |
| SSDEEP | `1536:FnrsAonlqranlhU19bJ9H0XVPypBidr9aFD52vcRIV69EdJHA9Qr33pnJ:xponkWny5J9UXVP42sD0vM9Erg9o35nJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_7d365030
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d365030af1e49f7de82f9e6ab9629efd0fc38b69b8ef85abe24901f7dddac9e"
    family = "unknown"
    file_name = "myc2-killer-linux-m68k"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:42"
  condition:
    hash.sha256(0, filesize) == "7d365030af1e49f7de82f9e6ab9629efd0fc38b69b8ef85abe24901f7dddac9e"
}
```

### Sample 16: `9652f77e939c9c93`

| Field | Value |
|---|---|
| SHA-256 | `9652f77e939c9c932ba3fb8b1ba71c58e82933d5264d36b8f03e74e648ce1ee9` |
| Family label | `Mirai` |
| File name | `bot.arm` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21d2743cedc277223209d7b7da21f007` |
| SHA-1 | `90991a62da7ac15217e833c956ac0f30be4d3eac` |
| SHA-256 | `9652f77e939c9c932ba3fb8b1ba71c58e82933d5264d36b8f03e74e648ce1ee9` |
| SHA3-384 | `369422d74f4d5aee71a32d9d5f8915632f7b103ec9ae2ba66ef924e5f9be5f9fa3c1a4ea0547d7be65d9c5f699395ea1` |
| TLSH | `T16AD43A56F8808F62C5D12676FA5F8268331347B9C3DB720699189B383BD786B0F3B645` |
| TELFHASH | `t17c0126354b2066225a51de8898eea763612c865a9b0cfc77d431440c21050fee63bc8f` |
| SSDEEP | `12288:Tyq9fiZSjQIzjOTGWj5VM24jR6Ie5kaUgpjrg26JI8AMAHS:TyqV9zSTRj5V7SY4bJLAMAH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_9652f77e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9652f77e939c9c932ba3fb8b1ba71c58e82933d5264d36b8f03e74e648ce1ee9"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:40"
  condition:
    hash.sha256(0, filesize) == "9652f77e939c9c932ba3fb8b1ba71c58e82933d5264d36b8f03e74e648ce1ee9"
}
```

### Sample 17: `6fbe726366d26259`

| Field | Value |
|---|---|
| SHA-256 | `6fbe726366d26259527bf29dcce9f1c0476151928bef609cff2b992e82635009` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fb3a235f33b0b90f210d26739f98ebe` |
| SHA-1 | `ac793b90f685ac246a6b3a730819ed92bb831024` |
| SHA-256 | `6fbe726366d26259527bf29dcce9f1c0476151928bef609cff2b992e82635009` |
| SHA3-384 | `f9c084217fc7b31a182e2df32b1a9054123fcc019bbfe057fedf5c884fff96b51d5fb2af736baad38516c0488b1b7a5a` |
| TLSH | `T125E47C6273318F64E361D27505E3C7A59AA521A20BE390C3937CC7207A6176C6D6FFE8` |
| TELFHASH | `t17c0126354b2066225a51de8898eea763612c865a9b0cfc77d431440c21050fee63bc8f` |
| SSDEEP | `12288:ATMbGSW5shmXEHqLzntCXaXAM4sZG3b8QHZNggpjyisAR+uOIsuHe:A4bZ+sKV8s4sZG3bPHZN/sfIsu+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_6fbe7263
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fbe726366d26259527bf29dcce9f1c0476151928bef609cff2b992e82635009"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:37"
  condition:
    hash.sha256(0, filesize) == "6fbe726366d26259527bf29dcce9f1c0476151928bef609cff2b992e82635009"
}
```

### Sample 18: `cc82557d7b782b4f`

| Field | Value |
|---|---|
| SHA-256 | `cc82557d7b782b4f49e2548b9d23922a0427640a3e21ffb52c84fa1679a8ba3f` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-arm64` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db7ee6fe189721030a101b5567d4964c` |
| SHA-1 | `469a43ed63b5702ff5042a02cb565d313551c93f` |
| SHA-256 | `cc82557d7b782b4f49e2548b9d23922a0427640a3e21ffb52c84fa1679a8ba3f` |
| SHA3-384 | `39aafc45f82fbefd2d3932ce73d5feb4165dd4599823d4429f810bc7e480782b09b8407bebd7ec27b7f4c3f9c91d0055` |
| TLSH | `T16BD52915BD1D6822D5CD76756FB612983339BD084F81D3276618FA3CAAF23988F132B1` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:VzAcCEFRDdfUvo2IH67yhoY3OXzLtKqLFFo6tcsTDlpnZj3pgHepzRurgBzH8/Ev:VbF7fUuhpOxzg0cc2sE+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_cc82557d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc82557d7b782b4f49e2548b9d23922a0427640a3e21ffb52c84fa1679a8ba3f"
    family = "unknown"
    file_name = "myc2-shell-linux-arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:35"
  condition:
    hash.sha256(0, filesize) == "cc82557d7b782b4f49e2548b9d23922a0427640a3e21ffb52c84fa1679a8ba3f"
}
```

### Sample 19: `50c399cf00a83be3`

| Field | Value |
|---|---|
| SHA-256 | `50c399cf00a83be3614b6f111669c0d1f041b9ae0e28fba42d029258a481ead4` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-amd64` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fae24d062cc07c8c2946c9a3f75e31b` |
| SHA-1 | `6b19a93fd6b9932a0edaa3cdc961d9161909f3d6` |
| SHA-256 | `50c399cf00a83be3614b6f111669c0d1f041b9ae0e28fba42d029258a481ead4` |
| SHA3-384 | `a0fcaa48a63a04a0742c0b19c8e47a0ff854d016d6d93ad6074387dcfd7d3b1fe618ef6a4b27b83841c6c5566f29abb7` |
| TLSH | `T1CCC66B47FCA514E4C1AED574C9669623BB727C494B3123D72B90F6282F33BE06AB9710` |
| TELFHASH | `t1715258714abc35b5a3a6d911b362b4f856372ca576f834f05063a985ffc1e801cea837` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:ovkOiLAithM+wQCXTE6RamhqXeBo6jqDEa:oNzithMoePhqXeK6eQa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_50c399cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50c399cf00a83be3614b6f111669c0d1f041b9ae0e28fba42d029258a481ead4"
    family = "unknown"
    file_name = "myc2-agent-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:32"
  condition:
    hash.sha256(0, filesize) == "50c399cf00a83be3614b6f111669c0d1f041b9ae0e28fba42d029258a481ead4"
}
```

### Sample 20: `40bdd8b2870b81d6`

| Field | Value |
|---|---|
| SHA-256 | `40bdd8b2870b81d6585ddc83e83073f9b4e7b10f7bc0b2d77c29f429bf7791f9` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-ppc64le` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cca51b96ba2d1fc229eed1cd67059b2` |
| SHA-1 | `b71d110be7da2ed9a0cc6c8737686e63ce3f23d5` |
| SHA-256 | `40bdd8b2870b81d6585ddc83e83073f9b4e7b10f7bc0b2d77c29f429bf7791f9` |
| SHA3-384 | `6652b6ec9af33ba16923bfc9b567815a228e73e6bccdba08fd8d8beb0ac7a4e87d67b49d5b93950acadffa5c0e549499` |
| TLSH | `T136D52902FA485EA1C924593789F70E9437A26D586F21A787D704F2BF79B33060F16F98` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:UEqmVD2kQ8K7FEpGcbJyDZfDxaKAsRhRCLh4jNVhuVUVGqGhWmfZHH1p+a+g1AFq:UEJRjKNqh4jNsqEBX+CAFRtifd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_40bdd8b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40bdd8b2870b81d6585ddc83e83073f9b4e7b10f7bc0b2d77c29f429bf7791f9"
    family = "unknown"
    file_name = "myc2-shell-linux-ppc64le"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:29"
  condition:
    hash.sha256(0, filesize) == "40bdd8b2870b81d6585ddc83e83073f9b4e7b10f7bc0b2d77c29f429bf7791f9"
}
```

### Sample 21: `7fec1535a6530617`

| Field | Value |
|---|---|
| SHA-256 | `7fec1535a6530617d8b5976a5aec59469d90a25b21481f027187d7ed1c732a39` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-mips64` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:26` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5184ef1bc80ff694fbb65478efafb1bd` |
| SHA-1 | `61d710159ccfc689f37e151d28ee5233687747e8` |
| SHA-256 | `7fec1535a6530617d8b5976a5aec59469d90a25b21481f027187d7ed1c732a39` |
| SHA3-384 | `6b1e6c4b154a05e43f93ef6bcdb24922f57421c9a39e4ecf90f7a9878811ed6dafb9b2ee15e453aeb6985822fbbe7642` |
| TLSH | `T157F51912BF54DE1FE19432359AAAC33873D53E0481A0A0379616F71D1EBB2B9C91BDD8` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `12288:I3TFydlVibYnalWHSLRqOX31SDhGbKSP34eZMN6YL6YU6YU6YUdjvqMDaStCIfid:78y63TM0YJdIMMOjGkG5K8X/3xhc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_7fec1535
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fec1535a6530617d8b5976a5aec59469d90a25b21481f027187d7ed1c732a39"
    family = "unknown"
    file_name = "myc2-shell-linux-mips64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:26"
  condition:
    hash.sha256(0, filesize) == "7fec1535a6530617d8b5976a5aec59469d90a25b21481f027187d7ed1c732a39"
}
```

### Sample 22: `e47984f2543c3ea2`

| Field | Value |
|---|---|
| SHA-256 | `e47984f2543c3ea22ce0072c503f9c624bc217cb2828f0552b60f9cf28997f99` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-386` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18dae81d1309e51d46d76075ea32fe3a` |
| SHA-1 | `7c5e96a70dc1ba997919ad44d35b0d8d17935461` |
| SHA-256 | `e47984f2543c3ea22ce0072c503f9c624bc217cb2828f0552b60f9cf28997f99` |
| SHA3-384 | `765151ff346ce4f0497b370471f914a494929ab8ce7d6f8a6be58301b0225cbea4a75914d3445cc69a9f06f11cf284d4` |
| TLSH | `T133D51810FD8B04F7E6432E3118ABA26F27315D094F34EBD3EA447B69FA776954832219` |
| TELFHASH | `t15992ddb316ad94ec63e08415565fb110cef2e42726e0387249f778c1ab72e136f768b9` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:pGNKKc0wAAIrKzP/i6mBeBtUEiDdmUNmyAvqgSQGHzISSuCrtxqr4MEYbRJQ3KeI:pGNKCHE/HJUBUqrhRQmS0HAi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_e47984f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e47984f2543c3ea22ce0072c503f9c624bc217cb2828f0552b60f9cf28997f99"
    family = "unknown"
    file_name = "myc2-shell-linux-386"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:23"
  condition:
    hash.sha256(0, filesize) == "e47984f2543c3ea22ce0072c503f9c624bc217cb2828f0552b60f9cf28997f99"
}
```

### Sample 23: `827ddff9799015e4`

| Field | Value |
|---|---|
| SHA-256 | `827ddff9799015e49d09c0244aab4551826b1195c00e43231197d0213ddb5053` |
| Family label | `unknown` |
| File name | `myc2-killer-linux-ppc` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:20` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3c0a1f970681f3392fc9df8f8042599` |
| SHA-1 | `bf95cb66f39b13a6a911b628b46894f62b1fad68` |
| SHA-256 | `827ddff9799015e49d09c0244aab4551826b1195c00e43231197d0213ddb5053` |
| SHA3-384 | `9b0e32d05a591573ca40a9e5242c9109a0e3886bd682dccc5e9f833129066c5aac66c57e74e52192f2abcf52b2424e00` |
| TLSH | `T1A5D35B01FB194763C1824DB45F7B07A6D3215C9200B9E12EA60EBF6A2633D7B91C7BD9` |
| SSDEEP | `3072:a5+uQhMlb7ypyK9i8OkxJzpM5sf3gZoY7:ao3W17uNPOkxJzpM5sfwuY7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_827ddff9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "827ddff9799015e49d09c0244aab4551826b1195c00e43231197d0213ddb5053"
    family = "unknown"
    file_name = "myc2-killer-linux-ppc"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:20"
  condition:
    hash.sha256(0, filesize) == "827ddff9799015e49d09c0244aab4551826b1195c00e43231197d0213ddb5053"
}
```

### Sample 24: `1e04b4833c10e94c`

| Field | Value |
|---|---|
| SHA-256 | `1e04b4833c10e94cbf6dbb005b7748511f0b9d3abbfa0d595bd341cbfa9d6397` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-m68k` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:18` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `153847114c8e2637e0f5bdb796a5d28c` |
| SHA-1 | `4a5269039fb969b6aa229a83599ba81c2add0fc6` |
| SHA-256 | `1e04b4833c10e94cbf6dbb005b7748511f0b9d3abbfa0d595bd341cbfa9d6397` |
| SHA3-384 | `1e3b0e2857ce8ffebee2117074fc68da0247ebb4ba1365d4cb3e5e94ebc3134917197110832d9a9ff076b7c7eb3681eb` |
| TLSH | `T1F112300BB32D7EDBDD786B38E5D70311377DA9909E6252BB8268640818E21680F747EC` |
| SSDEEP | `96:ZoxBWBSh0gI0ORQqohr65Ok3z+4NRA/lPt:88ch0wOU65Okj+4rA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_1e04b483
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e04b4833c10e94cbf6dbb005b7748511f0b9d3abbfa0d595bd341cbfa9d6397"
    family = "unknown"
    file_name = "myc2-preload-linux-m68k"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:18"
  condition:
    hash.sha256(0, filesize) == "1e04b4833c10e94cbf6dbb005b7748511f0b9d3abbfa0d595bd341cbfa9d6397"
}
```

### Sample 25: `c89b971c7ba9962a`

| Field | Value |
|---|---|
| SHA-256 | `c89b971c7ba9962a3ed1e1011746caeab2fbeb52671dc8139045a68760b3c6a5` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-ppc64` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5485c8ec11780c6c0b4b42d061bef6fe` |
| SHA-1 | `e9b08588e2c7ccd82e12ecc309320afd1ee3d9db` |
| SHA-256 | `c89b971c7ba9962a3ed1e1011746caeab2fbeb52671dc8139045a68760b3c6a5` |
| SHA3-384 | `5a1673b95260aed491c51fcbde2dfd06a48d89cbddc45faa9e3e51f8deb15a84c40a2899da893a9d5dfd6b7d460cfa3a` |
| TLSH | `T1F3C67D80F748A22ADD4A0E3284A30B74B3615D45C2F5C96F4705F76B45B2BFA6A4EFD0` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `196608:06UMc+CYstGzFX+Zv+JTIHrZ1cBPlanp9RnLhFwlCkpdSgiMM65p+U8gIZy4LQ5i:QfnxZ3onWRwuiDfCwERK/I` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_c89b971c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c89b971c7ba9962a3ed1e1011746caeab2fbeb52671dc8139045a68760b3c6a5"
    family = "unknown"
    file_name = "myc2-agent-linux-ppc64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:15"
  condition:
    hash.sha256(0, filesize) == "c89b971c7ba9962a3ed1e1011746caeab2fbeb52671dc8139045a68760b3c6a5"
}
```

### Sample 26: `82cc862a4633f65c`

| Field | Value |
|---|---|
| SHA-256 | `82cc862a4633f65c707fe09c311111d80fa9072a39e82db8d34b97f68f7b8ab1` |
| Family label | `Mirai` |
| File name | `bot.arm64` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69616458fa6dc1fcb406598a388db0a1` |
| SHA-1 | `860aa970658536cd5c4f1922e78797725f54e1c9` |
| SHA-256 | `82cc862a4633f65c707fe09c311111d80fa9072a39e82db8d34b97f68f7b8ab1` |
| SHA3-384 | `ebe0e0fe8797121c8bccc5fed3ff4f7eaf9b5a93ea135ac5bff06fbe7ee9df87082f3f1cad91951e7b165917c2d26d4f` |
| TLSH | `T180D46C5DFE5E3C42E3DBE2789F8E83E1A22BB290D32351A33981534C94C65E9CBB0555` |
| SSDEEP | `12288:oovRG5eyliLhNxUtwWtG98dxfLw5WAkle:o/XUhyBtGGn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_82cc862a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82cc862a4633f65c707fe09c311111d80fa9072a39e82db8d34b97f68f7b8ab1"
    family = "Mirai"
    file_name = "bot.arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:12"
  condition:
    hash.sha256(0, filesize) == "82cc862a4633f65c707fe09c311111d80fa9072a39e82db8d34b97f68f7b8ab1"
}
```

### Sample 27: `9689934f15901d3b`

| Field | Value |
|---|---|
| SHA-256 | `9689934f15901d3bd2d9139cde12dd46a74e13e7b3aafd4ba37fea66e6589462` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-ppc64le` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88de35b9d1489e12e875de5f18428030` |
| SHA-1 | `e3f7b6231b71080360d3587fbc9fa8af31c0ad33` |
| SHA-256 | `9689934f15901d3bd2d9139cde12dd46a74e13e7b3aafd4ba37fea66e6589462` |
| SHA3-384 | `417000915833785dacb22643f41b4288304854e8208fdbf91d29801ad0ebff51e294e33cd13bc541e29b5385b7e963f1` |
| TLSH | `T104C66C42E6086FD5C914893385A30EA127A62D546B318B93DB44F2BFBDF33424F56F98` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:/hobj6jHJewl5wjQneWm7Fa5nNnYhbxyDUx7HhkGG8l3gfScwGBnf82v9R2NClA8:5objAHJeAGjQUxajYpxCP2NBiYgE2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_9689934f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9689934f15901d3bd2d9139cde12dd46a74e13e7b3aafd4ba37fea66e6589462"
    family = "unknown"
    file_name = "myc2-agent-linux-ppc64le"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:09"
  condition:
    hash.sha256(0, filesize) == "9689934f15901d3bd2d9139cde12dd46a74e13e7b3aafd4ba37fea66e6589462"
}
```

### Sample 28: `7a9070da36b51c61`

| Field | Value |
|---|---|
| SHA-256 | `7a9070da36b51c610b5232c661bbebc6f7d5a0b3b2f7fae5f975894cdf1a7f83` |
| Family label | `Mirai` |
| File name | `myc2-agent-linux-mips` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba34cdc563358270c45c6dc3db4020d9` |
| SHA-1 | `bb327e36de692fed12782839e4d457987a02057b` |
| SHA-256 | `7a9070da36b51c610b5232c661bbebc6f7d5a0b3b2f7fae5f975894cdf1a7f83` |
| SHA3-384 | `ad4080c91297f0063847bb850d2c657481d26b0d47757010c0d9de79eff325243f64a6d140c7b02f0fc0b03aa394e1e8` |
| TLSH | `T151444A9377224FD1E325E3710EB34B5A5AEB11920EF244D1936DD6203A206AD6C9FFE4` |
| TELFHASH | `t105e0bf2c68781774d181dd5e84edef14d8a195cba9231c2bc944c9688b75e868d01c68` |
| SSDEEP | `6144:FnnDBhRsUsKd/9WSpkUZyEuOQOwq5952art:1SUPdFxlZeMh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_7a9070da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a9070da36b51c610b5232c661bbebc6f7d5a0b3b2f7fae5f975894cdf1a7f83"
    family = "Mirai"
    file_name = "myc2-agent-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:05"
  condition:
    hash.sha256(0, filesize) == "7a9070da36b51c610b5232c661bbebc6f7d5a0b3b2f7fae5f975894cdf1a7f83"
}
```

### Sample 29: `4f816a214c466eb5`

| Field | Value |
|---|---|
| SHA-256 | `4f816a214c466eb5cef1e53c0904a9b703d2eedd82b8958c8f424118b28f675e` |
| Family label | `Mirai` |
| File name | `main_mips` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25e92e4118bf46e38c0af8e15681ef33` |
| SHA-1 | `b3cc1a81032f6db1b6548c469b9e9c0c82c5a6de` |
| SHA-256 | `4f816a214c466eb5cef1e53c0904a9b703d2eedd82b8958c8f424118b28f675e` |
| SHA3-384 | `6d9a996a77329f397d1d8c7c2021e4c996cd20d2a084387be9442be37fd2851afd24c34c7f9933244f91f26626eb1bd0` |
| TLSH | `T1AFE3E866BA14EF7FC00D9130A972CB5006D13DB22E914A3E7365D7AC2F3119B5E1BAE4` |
| SSDEEP | `1536:Yhrqp/M4udTRv4Ye2IlX2wDRjaYM4KTvVL4oGB6iYAQb/4WrI2bvo5XF0k:iq1MBFq2C5DPOL/Vb/4v2bggk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_4f816a21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f816a214c466eb5cef1e53c0904a9b703d2eedd82b8958c8f424118b28f675e"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:03"
  condition:
    hash.sha256(0, filesize) == "4f816a214c466eb5cef1e53c0904a9b703d2eedd82b8958c8f424118b28f675e"
}
```

### Sample 30: `841bdbfe6611bd8b`

| Field | Value |
|---|---|
| SHA-256 | `841bdbfe6611bd8b42d60f9ff73b9d849ed1dce96d19517d2ec4376842d4621d` |
| Family label | `Gafgyt` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-11-21 07:02:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fba6e5c4b14914d1fb8473c159e58833` |
| SHA-1 | `81848a9a2243f330447b181096e02b6230a70ea0` |
| SHA-256 | `841bdbfe6611bd8b42d60f9ff73b9d849ed1dce96d19517d2ec4376842d4621d` |
| SHA3-384 | `3218466076c39c4cf12aa6f44e68fa52d604871e52d2875c93c1cc61e4f684dc27e0722466a9c2987539f47a1d6599ba` |
| TLSH | `T1469307A6FD919852C5C425FBFA1E81CC334753BCD2EA3105EE15CA2075CF99E4A3BA81` |
| TELFHASH | `t1e941c055fe682599bbd642e4cea5513acaf531cc630865168a1cfa5f2c83dc6703ec13` |
| SSDEEP | `1536:P34+rNGwTvtMGIbjBbaS1HysG5Wbif6Haiw9dWEY/k+y000DiQmm0Plg++:P34WFTF/IbjhaEXGF6HajrWo0` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_030_841bdbfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "841bdbfe6611bd8b42d60f9ff73b9d849ed1dce96d19517d2ec4376842d4621d"
    family = "Gafgyt"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:00"
  condition:
    hash.sha256(0, filesize) == "841bdbfe6611bd8b42d60f9ff73b9d849ed1dce96d19517d2ec4376842d4621d"
}
```

### Sample 31: `910b7f870e7a54de`

| Field | Value |
|---|---|
| SHA-256 | `910b7f870e7a54de9be8881e42be1619655c7275ec5cf0503254777e9ce2b4a3` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-mipsle` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:58` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a50579830570bb26bce06ee26ad6fec1` |
| SHA-1 | `0252bbbc00941c01994079f6ce7a39081014a04f` |
| SHA-256 | `910b7f870e7a54de9be8881e42be1619655c7275ec5cf0503254777e9ce2b4a3` |
| SHA3-384 | `6439ff1aa01efcfba07d56dce31da46faf4eaf0e005fa135954c65038efc704bd7186ceb5acf4afba6edcf11d5081d87` |
| TLSH | `T1FE63521BFFE84E13C8B9CA30051F079537BBE80EA2A2532B9138C9493E5695C4F6745E` |
| SSDEEP | `96:s5QcBWBShQwquqEl3NtIIF4pAevV+pshKd0tgsek:sn8chQeDaIF2A++Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_910b7f87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "910b7f870e7a54de9be8881e42be1619655c7275ec5cf0503254777e9ce2b4a3"
    family = "unknown"
    file_name = "myc2-preload-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:58"
  condition:
    hash.sha256(0, filesize) == "910b7f870e7a54de9be8881e42be1619655c7275ec5cf0503254777e9ce2b4a3"
}
```

### Sample 32: `238775f192864991`

| Field | Value |
|---|---|
| SHA-256 | `238775f192864991a92f964b1d7bcd7a5384d9cc874fdf19e7b31d547606df41` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-mips` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a7fd5da2b6d26724af6b304d4f3e9d0` |
| SHA-1 | `8321aef0056ab2c37df080e9b5767f8b000bfe89` |
| SHA-256 | `238775f192864991a92f964b1d7bcd7a5384d9cc874fdf19e7b31d547606df41` |
| SHA3-384 | `b897589fb36a685a6e2d66b66e7eb3093225ed203854c20762d43893a8c3aaaead7f5be252e3c6f9d98fab37319ea2a7` |
| TLSH | `T185639457E753AD2AE566C378A47B877537B8BBD01EA20343B364E1442E0131C0A2BADC` |
| SSDEEP | `96:dB7BWBShUBSTGyMtFUmuB7OcYCp9ixYmvb2syJfVoKqV6s/ydrQ02G:dR8chUUylmixrvtKuc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_238775f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "238775f192864991a92f964b1d7bcd7a5384d9cc874fdf19e7b31d547606df41"
    family = "unknown"
    file_name = "myc2-preload-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:55"
  condition:
    hash.sha256(0, filesize) == "238775f192864991a92f964b1d7bcd7a5384d9cc874fdf19e7b31d547606df41"
}
```

### Sample 33: `2d6af5fc7d81127b`

| Field | Value |
|---|---|
| SHA-256 | `2d6af5fc7d81127ba730d45795e131846217fb536bf1c06b207627c996d96267` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11f52eaf028ff51e7af1c514f3471503` |
| SHA-1 | `60958c0490fb245987a5041cb2868f7c187556c8` |
| SHA-256 | `2d6af5fc7d81127ba730d45795e131846217fb536bf1c06b207627c996d96267` |
| SHA3-384 | `51734385a0817bd38ed5f2ac3ccbf4bde7f7fa25b6f5d2b310a77084267dbca9d50ced068ce098581cbbb37761222f8b` |
| TLSH | `T1B2F48D2BB2B2B17CD01BC0300BDBCAB15532F47526222D7B26C5DA353D6ADE1276DB61` |
| TELFHASH | `t192919b7048fa28b0b6dfc611f353f0b59d7a14a656ed35b0273669c4ef85f806c92823` |
| SSDEEP | `12288:+88HoZZFdlYHRPTNgRbmeuRgkxvPCiGaycv6rSHX:hE8PCTNgZhILxvPCgY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_2d6af5fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d6af5fc7d81127ba730d45795e131846217fb536bf1c06b207627c996d96267"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:53"
  condition:
    hash.sha256(0, filesize) == "2d6af5fc7d81127ba730d45795e131846217fb536bf1c06b207627c996d96267"
}
```

### Sample 34: `4609a5993fd2b8e6`

| Field | Value |
|---|---|
| SHA-256 | `4609a5993fd2b8e61ced40d4321ef058c289db91232ad317639a016523fd409c` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-arm64` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f81807214d34962ba18d07045060033f` |
| SHA-1 | `53730cd1e58692f6ae42d572a993b88021c37a3d` |
| SHA-256 | `4609a5993fd2b8e61ced40d4321ef058c289db91232ad317639a016523fd409c` |
| SHA3-384 | `787e5e2d49f27b83005eac7f71b05788cd5f845e783478bf0e4fd174f80f52f7b4b9124df1efb08c4f5f703123dc6820` |
| TLSH | `T1B1B67B51BC1D65A2CAC9B9302F7653A43339BC088B92C7576618BB3CF9F27948F17261` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:q9oXXH4+QjDWEDEt5+/FHZg8XvXFywTww09SHSSPEnHN2QVREMq3gfScwGBnf8EW:q9onH4++WEY0HZDwwTwwBAV0x/+TEh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_4609a599
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4609a5993fd2b8e61ced40d4321ef058c289db91232ad317639a016523fd409c"
    family = "unknown"
    file_name = "myc2-agent-linux-arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:50"
  condition:
    hash.sha256(0, filesize) == "4609a5993fd2b8e61ced40d4321ef058c289db91232ad317639a016523fd409c"
}
```

### Sample 35: `abb17282e3234a14`

| Field | Value |
|---|---|
| SHA-256 | `abb17282e3234a14bde204a4587c58477a88434c1157ee857b425223a65cca85` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-armv6` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `217b0154683a70a42f2414280855c65a` |
| SHA-1 | `0bec838b16c920e0b67d7b034d214326f9163d4f` |
| SHA-256 | `abb17282e3234a14bde204a4587c58477a88434c1157ee857b425223a65cca85` |
| SHA3-384 | `aeb898f55a44eb0304f7aa80bce6f111329e2d11ba28de36e3656adbbbf29fdc076b268825e2bb7307e369e71e93b331` |
| TLSH | `T14DC63B97B9D24983C4E83A37B8BE80C433631EB98B8756565D05FD3C3ABE5D90A39314` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:2CqATX1UwECtAnex4WTxLiEKxsTh8H2i/IgsF5/Zo493gfScwGBnf8tfCrLu9Cu6:LTXbEUSexjRCxR2DgsSnuQGgtEu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_abb17282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb17282e3234a14bde204a4587c58477a88434c1157ee857b425223a65cca85"
    family = "unknown"
    file_name = "myc2-agent-linux-armv6"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:46"
  condition:
    hash.sha256(0, filesize) == "abb17282e3234a14bde204a4587c58477a88434c1157ee857b425223a65cca85"
}
```

### Sample 36: `ecfd5818eba98cf3`

| Field | Value |
|---|---|
| SHA-256 | `ecfd5818eba98cf3ccc5a22ba5b9744961d9de9a3fa22648aef90a353232728e` |
| Family label | `Mirai` |
| File name | `myc2-killer-linux-mipsle` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf49f6c44fd7163961de93a9c641a4a5` |
| SHA-1 | `45b65ffbe307465e4fb8c3474db03fcc56c4e988` |
| SHA-256 | `ecfd5818eba98cf3ccc5a22ba5b9744961d9de9a3fa22648aef90a353232728e` |
| SHA3-384 | `fd228ae79600f2ed7ad9db3f18af8dff1cf1d04bb136d4095d08c994a590afc1772922ee9fbb767a72a85200f1db8ea9` |
| TLSH | `T1FD146C87EF880ECBCC5BCEB046AF03AB19F7459A4DC2A1E5547C8C58759E3854AD36C8` |
| SSDEEP | `3072:S37VYEX/ovyBPFe05icyfxjCKRwsa0vXNYEltSBMqx:+RRnVZytRwmjlgBMqx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_ecfd5818
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecfd5818eba98cf3ccc5a22ba5b9744961d9de9a3fa22648aef90a353232728e"
    family = "Mirai"
    file_name = "myc2-killer-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:43"
  condition:
    hash.sha256(0, filesize) == "ecfd5818eba98cf3ccc5a22ba5b9744961d9de9a3fa22648aef90a353232728e"
}
```

### Sample 37: `dfd84f1540ff5b34`

| Field | Value |
|---|---|
| SHA-256 | `dfd84f1540ff5b349de6cd358c5ff5d8ce1f2e747527945b65ddfbf5956fa324` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-armv5` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ced587b6d10db2b38b0267f3ea42f21` |
| SHA-1 | `4ef02b12be542723605c846b9df2455ebc9c4758` |
| SHA-256 | `dfd84f1540ff5b349de6cd358c5ff5d8ce1f2e747527945b65ddfbf5956fa324` |
| SHA3-384 | `5f71168e1ef965ae2074d8121a4e5d14ba04f945fa3d925f2fa88720794670bb09d1769e09757e101a7ffd33f5c87c6e` |
| TLSH | `T185D50857B9914942C4E43A3BACBE81C833665EBD9B8A53165D05FE3C3EBE1C90E35318` |
| TELFHASH | `t166d05e191e4d2a9c6ae642d10828011f9be530f845687ba48fad72af4f019a954c5095` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:/vyfLBKEAsqomYN0a5yVg/dWE6vKoGRrMt2/EcyH6SSgOi0pi3O6vgSBPeHkdswF:3HfjBpx9Rrqb04LZAJlkhfmf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_dfd84f15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfd84f1540ff5b349de6cd358c5ff5d8ce1f2e747527945b65ddfbf5956fa324"
    family = "unknown"
    file_name = "myc2-shell-linux-armv5"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:41"
  condition:
    hash.sha256(0, filesize) == "dfd84f1540ff5b349de6cd358c5ff5d8ce1f2e747527945b65ddfbf5956fa324"
}
```

### Sample 38: `8cfa1ceb515c01f8`

| Field | Value |
|---|---|
| SHA-256 | `8cfa1ceb515c01f8a0f7310d4697e9544903fdbe6bf077b503fd366fa5603887` |
| Family label | `Mirai` |
| File name | `bot.arm7` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1db3c3a19fd57aeea2c60f80cdaad81c` |
| SHA-1 | `8b2074560eea0ad46440abff9cb0f6dce37274bd` |
| SHA-256 | `8cfa1ceb515c01f8a0f7310d4697e9544903fdbe6bf077b503fd366fa5603887` |
| SHA3-384 | `a7ae9ecbbf9f767f12881e2bb82b220de7f3444eb47375e02c1312c28d6002d95e35d8700019b8b4ff4c164d8e9136c0` |
| TLSH | `T15694BF67F6621C43C8F78A3E15978268536BD2421792D306A30AF57D3ED637E8F192C8` |
| SSDEEP | `12288:s81Enq4659JdnGd2gpeFbknqoyy1+rjMv:71En1Qx4SS+rjM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_8cfa1ceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cfa1ceb515c01f8a0f7310d4697e9544903fdbe6bf077b503fd366fa5603887"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:38"
  condition:
    hash.sha256(0, filesize) == "8cfa1ceb515c01f8a0f7310d4697e9544903fdbe6bf077b503fd366fa5603887"
}
```

### Sample 39: `7781a462ab51c7d6`

| Field | Value |
|---|---|
| SHA-256 | `7781a462ab51c7d6dcc6b35aba066f1551271f656e6e9e6c3b057dd58d11a7eb` |
| Family label | `Mirai` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd0de92fdde3a0bc266c63490604ee63` |
| SHA-1 | `3e8045e0d47fa768368bdfc176cafc6626f0e93e` |
| SHA-256 | `7781a462ab51c7d6dcc6b35aba066f1551271f656e6e9e6c3b057dd58d11a7eb` |
| SHA3-384 | `5107a09e8ded7e086e76101ceb68a50e67c3b61a42972f11a63d7be83a62fdd8c817385aba19685d2645652871690b43` |
| TLSH | `T19DB32944E36ADAF4F56644F04158D3B56E344938A362CBDBCF87B7B1A8001E05F7A26E` |
| TELFHASH | `t1aa21d0209ba350f9a243e4d2ccb1f965c6f513ee97c06f3053a4f9705d87e51ac19803` |
| SSDEEP | `3072:rLQUOZ/gEJGGmDD068bIGyFUfEpsdCFPF6L:rLQU+hJGDD0JIGyB9F6L` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_7781a462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7781a462ab51c7d6dcc6b35aba066f1551271f656e6e9e6c3b057dd58d11a7eb"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:35"
  condition:
    hash.sha256(0, filesize) == "7781a462ab51c7d6dcc6b35aba066f1551271f656e6e9e6c3b057dd58d11a7eb"
}
```

### Sample 40: `268332911cbfc970`

| Field | Value |
|---|---|
| SHA-256 | `268332911cbfc970c5ded5dc5f085b1e4a1f5bc151e4427bd2261f4d90d7aa2d` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-ppc` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddeeeacca58542ab04004e32a20b9db4` |
| SHA-1 | `6d28d60d56c3877456a523031e4ebc1ed4ab1575` |
| SHA-256 | `268332911cbfc970c5ded5dc5f085b1e4a1f5bc151e4427bd2261f4d90d7aa2d` |
| SHA3-384 | `d53b132afe337859ba500b5a2bcf34eedb282a7d0b9a613ae7b7d1d573a9305408c47655549c7769db300c5d2220246d` |
| TLSH | `T161D34B01FB094663C6431EB05E7B07B7D361589200B9E21DAA09BF5A1B33D3BA5C7BD9` |
| SSDEEP | `3072:OZygslvWQJoyNyCvzRiBYiR+2ffYMzmJikKNS+7366VYjoMVWcP:OZ8WwoqVbMBYs+2fAMzmJikKNS+7KMY9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_26833291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "268332911cbfc970c5ded5dc5f085b1e4a1f5bc151e4427bd2261f4d90d7aa2d"
    family = "unknown"
    file_name = "myc2-agent-linux-ppc"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:33"
  condition:
    hash.sha256(0, filesize) == "268332911cbfc970c5ded5dc5f085b1e4a1f5bc151e4427bd2261f4d90d7aa2d"
}
```

### Sample 41: `87576b2e25086edf`

| Field | Value |
|---|---|
| SHA-256 | `87576b2e25086edfc60edc3e0e843ec11e708fb029d70ca6d9cfb351c997f9e4` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-mips-softfloat` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:30` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df822e38cd6a05fcfb8613df62187243` |
| SHA-1 | `5dbb2dcbd49affa4b323af80eece6edbe208027b` |
| SHA-256 | `87576b2e25086edfc60edc3e0e843ec11e708fb029d70ca6d9cfb351c997f9e4` |
| SHA3-384 | `02fb8d492c1e7ff6bf5d05f0629821c8b094a663553109768aa27a76470db6fa01da2d71f83b7315d9cc870039c93d4d` |
| TLSH | `T1DDD629136B1CE71EDA2A213459B1CA946B7A1C9642E6D817A385F30CE5F30BC4D6ECF4` |
| TELFHASH | `t1f5c09b454b55165c75419d961dcdf26155f5f7170d25546c7b3c05c30d3c2d1503c508` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:v1sBUhIkrevQDS8lokGgJTM+joZnF4SiPd0Rjmms+Xz8Jy8Xf9Yi0kCANiMKg9dH:XnosNiREuTShKkjEO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_87576b2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87576b2e25086edfc60edc3e0e843ec11e708fb029d70ca6d9cfb351c997f9e4"
    family = "unknown"
    file_name = "myc2-agent-linux-mips-softfloat"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:30"
  condition:
    hash.sha256(0, filesize) == "87576b2e25086edfc60edc3e0e843ec11e708fb029d70ca6d9cfb351c997f9e4"
}
```

### Sample 42: `d74aed92c29d88a4`

| Field | Value |
|---|---|
| SHA-256 | `d74aed92c29d88a45c2909631ccf3b8a1fb415be1514a53bc17d8d9b34eaab28` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a47710506f8136638ed92dea25a15a4` |
| SHA-1 | `471936a064a98692f869209557b8791eee60df5f` |
| SHA-256 | `d74aed92c29d88a45c2909631ccf3b8a1fb415be1514a53bc17d8d9b34eaab28` |
| SHA3-384 | `091fe81fd3346f900f15e322743393959cb0994f646ef524d516bab81e8ce214fe69919ca1cc82bc3b5aaff70b0cb94d` |
| TLSH | `T1DDE3D64B7904FFA7C02D4E70997DD71241D1A0C6B696A13FB2A48BCE6E763230E179D8` |
| SSDEEP | `1536:Nor5JPR2Q3ac95gR1M9miuQKjI/EGTyYJtzonMdpssgjDIlZeA6pw4:K/R2QV5gR1MsJjIxyY7iMvtOU7i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_d74aed92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d74aed92c29d88a45c2909631ccf3b8a1fb415be1514a53bc17d8d9b34eaab28"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:27"
  condition:
    hash.sha256(0, filesize) == "d74aed92c29d88a45c2909631ccf3b8a1fb415be1514a53bc17d8d9b34eaab28"
}
```

### Sample 43: `47d114f176a5b738`

| Field | Value |
|---|---|
| SHA-256 | `47d114f176a5b7387880473e5449b0868b27d5e5c0dee2042710990428302ecf` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-armv6` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:24` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6d35a7b509946e4b3e5a54252f35535` |
| SHA-1 | `eeb877eb4f2519d8248ef389954ef8b7c5e2ddbf` |
| SHA-256 | `47d114f176a5b7387880473e5449b0868b27d5e5c0dee2042710990428302ecf` |
| SHA3-384 | `10b03983b3e5e8a5dcb29792622e5282f471ecfd98d2b5a36e6106853b359d2818deec5f782a6d6ac0ee5c4b9242a576` |
| TLSH | `T1F9D50857B9920942C4E83A7BACBE80C833665EB98B8A53575D05FD3C3EBE1D90E35314` |
| TELFHASH | `t1b8d05e564e6c25682ad642910460026f8be534fc36643ba48fee72df4b0546a61d8056` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:V7Fhf+TY1n4Nt2cpiQGzPSo+wiRAePYUFDJ4rhQWLsBgRZ1TYF7UgrP8uBd23shG:Vs/WwlEvxDY508alFl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_47d114f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47d114f176a5b7387880473e5449b0868b27d5e5c0dee2042710990428302ecf"
    family = "unknown"
    file_name = "myc2-shell-linux-armv6"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:24"
  condition:
    hash.sha256(0, filesize) == "47d114f176a5b7387880473e5449b0868b27d5e5c0dee2042710990428302ecf"
}
```

### Sample 44: `6ba62337402b6ab1`

| Field | Value |
|---|---|
| SHA-256 | `6ba62337402b6ab19ab5e6b1334a4e429c629e800f008cde4a33f345e54ae7bc` |
| Family label | `unknown` |
| File name | `myc2-dlr-linux-mipsle` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:21` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59edd372c5be3e8e9fb5f5bee7a3d395` |
| SHA-1 | `a193c039f4654f269b24de43a81efb56453ae257` |
| SHA-256 | `6ba62337402b6ab19ab5e6b1334a4e429c629e800f008cde4a33f345e54ae7bc` |
| SHA3-384 | `bf17df3043e3a52e29e025f06bb68ba4089bd1d4a91589cdb7e8cf76c5db302cde4021d41c2ade935b7afd27ab0a42be` |
| TLSH | `T14A314FD3DE296DC2D629C5348F6D936A43A2A48B4CE24A7AE35C9C042E295C81DE3C09` |
| SSDEEP | `48:4vyK/5p3aZfCgSubroglpYQEqJHOnspF1upR:mrBpSfRSIosY1cHOnspjuz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_6ba62337
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ba62337402b6ab19ab5e6b1334a4e429c629e800f008cde4a33f345e54ae7bc"
    family = "unknown"
    file_name = "myc2-dlr-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:21"
  condition:
    hash.sha256(0, filesize) == "6ba62337402b6ab19ab5e6b1334a4e429c629e800f008cde4a33f345e54ae7bc"
}
```

### Sample 45: `1ca85b500dcf8c3c`

| Field | Value |
|---|---|
| SHA-256 | `1ca85b500dcf8c3ca194d848ad4091489a06a6234c487ec7f278b98dbcfef0b0` |
| Family label | `Mirai` |
| File name | `main_riscv` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `847339dbc7c8965faa0e258ac2258cb1` |
| SHA-1 | `43fcfcc82c5b39fe4003b8ec5db59bc810bcb661` |
| SHA-256 | `1ca85b500dcf8c3ca194d848ad4091489a06a6234c487ec7f278b98dbcfef0b0` |
| SHA3-384 | `e07d1549a6c158667dc49b02b2ec0c2c2a5c496c753c08243881f5357207bf2494b2dbd4ad639a90b80067dfa55e6082` |
| TLSH | `T175937C051120049ECCA99AB54AEF4325BFD9FCB30B8713445F179AA43AE696C3B9DBD0` |
| SSDEEP | `1536:1rNCxPybv74uR/CUpaGRlVU6S4IzR8EUGDT8REWPZNmJknC2gSFjb:JMyb75R/pJS4IzVUMgRfaf2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_1ca85b50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ca85b500dcf8c3ca194d848ad4091489a06a6234c487ec7f278b98dbcfef0b0"
    family = "Mirai"
    file_name = "main_riscv"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:19"
  condition:
    hash.sha256(0, filesize) == "1ca85b500dcf8c3ca194d848ad4091489a06a6234c487ec7f278b98dbcfef0b0"
}
```

### Sample 46: `eaa7d55098d15040`

| Field | Value |
|---|---|
| SHA-256 | `eaa7d55098d150404770936ccd83b351542936f029c994122c27f82099d033ac` |
| Family label | `Mirai` |
| File name | `myc2-killer-linux-mips` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c289312d4a30e59bc6e4a568179e52d7` |
| SHA-1 | `ab75b4298ef2fb67bacc1d0a6e361e36d47db122` |
| SHA-256 | `eaa7d55098d150404770936ccd83b351542936f029c994122c27f82099d033ac` |
| SHA3-384 | `d00889a386dac8371486be77c2880fda3eed991ba7eba2c8daa9221637b483bad5ea3e048c1f94cd381a3e1e08bd76eb` |
| TLSH | `T1EA142B5377224F92D25697710FB34F1A5AE722D21EE284D0532CC6143A20AA96C9FFF4` |
| TELFHASH | `t12f21981c483813f0e3659d9d5becff31e4a171db96661e37ce40d5a96a29d814d00c2c` |
| SSDEEP | `3072:yLua0gfz2o7lLDsvZZZSi6SBr1l4e7ZAwaAUOEE5l5dF8F95SRRpZm:suar5lLgpB1l4e6LOT5l5dF8F9MRk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_eaa7d550
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaa7d55098d150404770936ccd83b351542936f029c994122c27f82099d033ac"
    family = "Mirai"
    file_name = "myc2-killer-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:16"
  condition:
    hash.sha256(0, filesize) == "eaa7d55098d150404770936ccd83b351542936f029c994122c27f82099d033ac"
}
```

### Sample 47: `21530b2038e60e57`

| Field | Value |
|---|---|
| SHA-256 | `21530b2038e60e57fd9a07a1c80bccee7319823912895377a44302be135fd218` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-ppc64` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c62630348daeb46ab1dab776c416d95c` |
| SHA-1 | `d04fb6588ea5891b615dad93d7c0438cee3d7126` |
| SHA-256 | `21530b2038e60e57fd9a07a1c80bccee7319823912895377a44302be135fd218` |
| SHA3-384 | `f6a7b7e280504dc065df731f129edcb6da770bf26ecf16dee45b1645ef99b9a763ed42401d9fc42361dc119153190a6d` |
| TLSH | `T1DAD54AC0F748962ADA4B0F3A48A30B7573546D49CAE4892B0309F77F16B16F75A4FE90` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:CKi4j4dHKqg/CKraiBpU6fQdTrJ8tMdMgWo/7NA1W6PUDXwxRHZf:r4vg/CKhLU6oKy/xAUIUCZf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_21530b20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21530b2038e60e57fd9a07a1c80bccee7319823912895377a44302be135fd218"
    family = "unknown"
    file_name = "myc2-shell-linux-ppc64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:14"
  condition:
    hash.sha256(0, filesize) == "21530b2038e60e57fd9a07a1c80bccee7319823912895377a44302be135fd218"
}
```

### Sample 48: `0a6eb94b51584ac4`

| Field | Value |
|---|---|
| SHA-256 | `0a6eb94b51584ac484bc4f01fdbf70a32e684ce62655707eb8babc31ae33ec32` |
| Family label | `Mirai` |
| File name | `myc2-killer-linux-sparc` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf2d14ddb469cd39f3a81f443e4d6717` |
| SHA-1 | `1b32e1ca5fa9b9bb9fd5818638729750551db687` |
| SHA-256 | `0a6eb94b51584ac484bc4f01fdbf70a32e684ce62655707eb8babc31ae33ec32` |
| SHA3-384 | `24515670be9d9ffc783d3e825fce733ff70d22f7ef3a56692ddf7fb3450edeed2d8e81fe0cc2832bc4271c8be2c2f66a` |
| TLSH | `T1EE043C13B9BA4D2AC4D1513292F74326F2F7834A2C6897C7BE644D8D6E287E471933B4` |
| SSDEEP | `3072:Th/4qgr5Gf31H+rRisbRRLVphM3Gw3Z4yiXpAgA:TN4qqGf3U8urLzhaGwJ9i6H` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_0a6eb94b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a6eb94b51584ac484bc4f01fdbf70a32e684ce62655707eb8babc31ae33ec32"
    family = "Mirai"
    file_name = "myc2-killer-linux-sparc"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:11"
  condition:
    hash.sha256(0, filesize) == "0a6eb94b51584ac484bc4f01fdbf70a32e684ce62655707eb8babc31ae33ec32"
}
```

### Sample 49: `c44cf5a3c37399ee`

| Field | Value |
|---|---|
| SHA-256 | `c44cf5a3c37399ee6bddeb20541b7b3ead578e4c6f14baa531b076649c2e544c` |
| Family label | `unknown` |
| File name | `scanner-linux-arm64` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b152b1cb22ca6fb49fa77eacbd8a7cfd` |
| SHA-1 | `0451cd0a5f1d7bd4e3dd583c73fe3ad341808938` |
| SHA-256 | `c44cf5a3c37399ee6bddeb20541b7b3ead578e4c6f14baa531b076649c2e544c` |
| SHA3-384 | `00e93d3dcde31da1488d85bb6382c4c9d63b60f8207d2e95b86be41c80d955ab4fe48056bfd7737df94459e75ecaeb00` |
| TLSH | `T116B54A16BC9D6862D5CE67716E7202983339BC495F81C3276A14BB3CAEF37588F13621` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:uFLmgrXmRcqu9gxhOxu92htIQzbsEqDNKVvnMUsXJJC2vTrNTk13Ffws8:6rct3vS6FNjCwlUFfG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_c44cf5a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c44cf5a3c37399ee6bddeb20541b7b3ead578e4c6f14baa531b076649c2e544c"
    family = "unknown"
    file_name = "scanner-linux-arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:09"
  condition:
    hash.sha256(0, filesize) == "c44cf5a3c37399ee6bddeb20541b7b3ead578e4c6f14baa531b076649c2e544c"
}
```

### Sample 50: `86faf2c79eac2d2a`

| Field | Value |
|---|---|
| SHA-256 | `86faf2c79eac2d2aa4a432089e79f41704431232e22ef94ec43586fe6fed90ba` |
| Family label | `Mirai` |
| File name | `myc2-agent-linux-sparc` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66e170f0321bf8ed1611740fc52f596e` |
| SHA-1 | `55cbe744fdb20712ee22bedb51ecaa014bccdaeb` |
| SHA-256 | `86faf2c79eac2d2aa4a432089e79f41704431232e22ef94ec43586fe6fed90ba` |
| SHA3-384 | `af441c1753fc81d082b21d024c369f1d7f2a4bb17441b9cde537ee2694d426f5b8c19d9f0f50df5d111deb4ded49e9ef` |
| TLSH | `T12F245D13B9BA4D2BC4C1913192F74336F3F78389286867CABE654D496F286E431533B5` |
| SSDEEP | `3072:/0tgFUyh3fUE4n3Cs6j6+JEelXFzHLvtxbzxxUvqTupzv:stiUyVUJ3Csc9yehdjXbzxSvqTMv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_86faf2c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86faf2c79eac2d2aa4a432089e79f41704431232e22ef94ec43586fe6fed90ba"
    family = "Mirai"
    file_name = "myc2-agent-linux-sparc"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:06"
  condition:
    hash.sha256(0, filesize) == "86faf2c79eac2d2aa4a432089e79f41704431232e22ef94ec43586fe6fed90ba"
}
```

### Sample 51: `6beeeac76a58ffc0`

| Field | Value |
|---|---|
| SHA-256 | `6beeeac76a58ffc01df26aba423eccb66a9bb3cdc2c8c370c2b3d42daf97ccad` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `495362a04e08acdd357a13e5f64979ad` |
| SHA-1 | `d34b69a16a92fe7a34fc1fdd5240ff7a887dcc4d` |
| SHA-256 | `6beeeac76a58ffc01df26aba423eccb66a9bb3cdc2c8c370c2b3d42daf97ccad` |
| SHA3-384 | `27f58bac0af0c20f289cb89686770df3ab202bda33fc9e2a902c4af0215c577880c7db612e3ac5a8f735100450f10829` |
| TLSH | `T1EC9318A5FC829992C5D425FEFE1E85CC335713ACC2E93106EE11CB2175DF9990A3AA42` |
| TELFHASH | `t118e0cd61bbc411b473c19bd05f51013a95e935ce464421d94f590b5f45019c2b07684e` |
| SSDEEP | `1536:FbHMJrNcdBqtoUHrXTy04VTaoUG3gYFc7H7KPbKeo7CGEXuyFfPn:NHMtiBOoQX94VTlUsgtKjZGLyZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_6beeeac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6beeeac76a58ffc01df26aba423eccb66a9bb3cdc2c8c370c2b3d42daf97ccad"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:03"
  condition:
    hash.sha256(0, filesize) == "6beeeac76a58ffc01df26aba423eccb66a9bb3cdc2c8c370c2b3d42daf97ccad"
}
```

### Sample 52: `800a41b40b8d4620`

| Field | Value |
|---|---|
| SHA-256 | `800a41b40b8d462071e333652dcc452b8b248a2c3cea28f7cc68ddb7e3f8a165` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-riscv64` |
| File type | `elf` |
| First seen | `2026-11-21 07:01:01` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `829d8168bd406bec930706dcd63aa964` |
| SHA-1 | `60b783c47306f5e3759247909bd703e265edf355` |
| SHA-256 | `800a41b40b8d462071e333652dcc452b8b248a2c3cea28f7cc68ddb7e3f8a165` |
| SHA3-384 | `7d38865cc3e41876b42f01385774fddc4c7c276a8e0187c91fa49a9fcfe47abd2da83862d6b42d47190e2e2123863064` |
| TLSH | `T1B8C57D06F9A49F16C96D52B388A516CC2738FC449FC7A7531A28FA3C7CBB6846D413C6` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:28xPjyEXLlduLuRp4Y0dx7gUkxY+3Mtz9fbvb2lP7TNWt:d5KmnAJa1S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_800a41b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "800a41b40b8d462071e333652dcc452b8b248a2c3cea28f7cc68ddb7e3f8a165"
    family = "unknown"
    file_name = "myc2-shell-linux-riscv64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:01"
  condition:
    hash.sha256(0, filesize) == "800a41b40b8d462071e333652dcc452b8b248a2c3cea28f7cc68ddb7e3f8a165"
}
```

### Sample 53: `436c31e78af95e7a`

| Field | Value |
|---|---|
| SHA-256 | `436c31e78af95e7a582aa7813fb54d798cf9fae9d8a5f07bafa46993ff0bf0cd` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-mips64` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:58` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10d2432f5a052cc88bf0547aa3ec7eb8` |
| SHA-1 | `820b9ac5936bdd109040ea4aa5e07feddc79f9ab` |
| SHA-256 | `436c31e78af95e7a582aa7813fb54d798cf9fae9d8a5f07bafa46993ff0bf0cd` |
| SHA3-384 | `3df6972b2bae3bba1dbd19e533a546b9990dc00bd3b9dbcb7a45fe3de5a1bff737ed6aeda8a9539922c7af2342985682` |
| TLSH | `T1AFD619527F88DE4FE6A4213589AAC23473D53D0082E06436C756F3192E7F3B59A1BED8` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:IZgMd06KCWPN+bLgfScwGBnf8cbrDr2giCBUR5WG1dOuY5Q7+92Hqkt5Es:IXKfdDTD01dwGa0KkjEs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_436c31e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "436c31e78af95e7a582aa7813fb54d798cf9fae9d8a5f07bafa46993ff0bf0cd"
    family = "unknown"
    file_name = "myc2-agent-linux-mips64"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:58"
  condition:
    hash.sha256(0, filesize) == "436c31e78af95e7a582aa7813fb54d798cf9fae9d8a5f07bafa46993ff0bf0cd"
}
```

### Sample 54: `5174bf924761e7c6`

| Field | Value |
|---|---|
| SHA-256 | `5174bf924761e7c62c61d1dcbfe398a1c8315ac924778a7f1aa529caa28ae8cc` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-m68k` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52e18d36ae35aa4d4a8d30883696f406` |
| SHA-1 | `1cc654fd0bf7ffd636d5af6e2c8c18b39f1ed53a` |
| SHA-256 | `5174bf924761e7c62c61d1dcbfe398a1c8315ac924778a7f1aa529caa28ae8cc` |
| SHA3-384 | `f9548aee39abc3268fe1b2334dc24f76cf4b813861524433af40f41747486ef56a1c4acac0f1408ba9e29a31e08b7115` |
| TLSH | `T1F2B37CD2264DBEAED3C37A3DC11185126D24EE10F4830A1360FABA4B6BF79653F36945` |
| SSDEEP | `3072:TZ3wr9N/whKYPtMAZQIR+8lqfvhJ5jZoevuG:t3wqKoMAWIRGvhJ5jum` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_5174bf92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5174bf924761e7c62c61d1dcbfe398a1c8315ac924778a7f1aa529caa28ae8cc"
    family = "unknown"
    file_name = "myc2-agent-linux-m68k"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:54"
  condition:
    hash.sha256(0, filesize) == "5174bf924761e7c62c61d1dcbfe398a1c8315ac924778a7f1aa529caa28ae8cc"
}
```

### Sample 55: `0883c4ecf76185e7`

| Field | Value |
|---|---|
| SHA-256 | `0883c4ecf76185e79619d7d9a16ffc39212f963c33b14e43e63d278399cd7501` |
| Family label | `Mirai` |
| File name | `loader.x86_64` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f10a37316f96adf3a085763a4e78aa1` |
| SHA-1 | `1277046141acb9c28ded7fc8a517cbd4959e4616` |
| SHA-256 | `0883c4ecf76185e79619d7d9a16ffc39212f963c33b14e43e63d278399cd7501` |
| SHA3-384 | `ce6d2b62c2383c7445ddb8fce6b4445e719da37b2b837dbe611d011063ad98e5914447f70125d849c9118622cba1990f` |
| TLSH | `T16FA33B477251D4ACD54981BC0A8F86B1C7ACBC611B0936B73B8AF6FC7E31CD22A19724` |
| TELFHASH | `t170312b40d7cc2974976a96a32e453c2b15fb10d757d33d8587a8b7421838fe22b9dd32` |
| SSDEEP | `1536:qg/lvM/rdWgrNBaeg2JVTVYyGp6+vIWU+TWbXp4ctY+WHkk+39F0SLKXKcQfcI8:qg9KpvJZSM+QWUoWlrthWHLsESO2fcI8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_0883c4ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0883c4ecf76185e79619d7d9a16ffc39212f963c33b14e43e63d278399cd7501"
    family = "Mirai"
    file_name = "loader.x86_64"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:51"
  condition:
    hash.sha256(0, filesize) == "0883c4ecf76185e79619d7d9a16ffc39212f963c33b14e43e63d278399cd7501"
}
```

### Sample 56: `bbff751f3ab13eb4`

| Field | Value |
|---|---|
| SHA-256 | `bbff751f3ab13eb48a95f9be771e747a4e9e81b3ec17b1c3d93538b1ea02b869` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-armv7` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8b957711bcce7fe59e8099183834ae7` |
| SHA-1 | `cee1969531cf518185b93bf5846e4e85b7be241b` |
| SHA-256 | `bbff751f3ab13eb48a95f9be771e747a4e9e81b3ec17b1c3d93538b1ea02b869` |
| SHA3-384 | `ef500a6240b7ed06e10881f68e30027939bb095bdc65deca51bdf62a2788205cd71f19eb675c2879e522d2f23634aa10` |
| TLSH | `T108D50757B9914942C4E83637BCBE81C833665EB99B8A13666D05FD3C3EBE2D80D39314` |
| TELFHASH | `t19bd05e998f5d7ac8abd190a14830122f9ee470f927146bd68f6a758e1a0242f80ed49a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:7mk+/9Hbo4/fpkmbYNS+964UnTk6iDNjkh2e/5xDZEN+adAdMC4syh2g9iJ+edQk:7YK9UxM7MXXtSEJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_bbff751f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbff751f3ab13eb48a95f9be771e747a4e9e81b3ec17b1c3d93538b1ea02b869"
    family = "unknown"
    file_name = "myc2-shell-linux-armv7"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:48"
  condition:
    hash.sha256(0, filesize) == "bbff751f3ab13eb48a95f9be771e747a4e9e81b3ec17b1c3d93538b1ea02b869"
}
```

### Sample 57: `ab87f24e09e8b142`

| Field | Value |
|---|---|
| SHA-256 | `ab87f24e09e8b1428f3d4a6b995387b4d4f994d1de3c93a095782b00e8c109e3` |
| Family label | `unknown` |
| File name | `llcp-linux-amd64` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9569c723ddea33fff3df082215b287fb` |
| SHA-1 | `1ab7cc2d049afce4edfc65f93aa1c88825658d47` |
| SHA-256 | `ab87f24e09e8b1428f3d4a6b995387b4d4f994d1de3c93a095782b00e8c109e3` |
| SHA3-384 | `864f9558746b536ec6170a362d755ded7c7489961213701224f8c090a77b1499b779ff13ced5e710f5b335943cbb774c` |
| TLSH | `T1C1468C43FCA141E9C4AE913589A291A27B717C498F2063D73AA4B7783F73BD49D7A340` |
| TELFHASH | `t16fe384965db249859f864b7aeca820c143b5c04ecd9efcdd8d7547b0abcb08a067f364` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:VggD38iN7sS/2F01VDXpsvPv+dfu3/im7o7BTpP3K5CVjAYcBst334qECUV5yCWG:VB38iNwYH+CUbNi4Wc0fLuSCKq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_ab87f24e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab87f24e09e8b1428f3d4a6b995387b4d4f994d1de3c93a095782b00e8c109e3"
    family = "unknown"
    file_name = "llcp-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:45"
  condition:
    hash.sha256(0, filesize) == "ab87f24e09e8b1428f3d4a6b995387b4d4f994d1de3c93a095782b00e8c109e3"
}
```

### Sample 58: `98ac0ba82d659646`

| Field | Value |
|---|---|
| SHA-256 | `98ac0ba82d65964691097fe7d0f4a96175425f44fcdd5c6d211377ca88ce4e0b` |
| Family label | `unknown` |
| File name | `zk_bridge_mips_9004` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdbcd781fb714b4d8d95e00ce6ccdec6` |
| SHA-1 | `c38aec3486b20fdac30db5c456fd4a2e18f9fbbb` |
| SHA-256 | `98ac0ba82d65964691097fe7d0f4a96175425f44fcdd5c6d211377ca88ce4e0b` |
| SHA3-384 | `53d4d71012cd75cb74a293240ead987c00af478867e58d0dfb2669c17919e3264cfde8ea5ccf00be28fe419104bd9adb` |
| TLSH | `T184518617EF241E9FC81D193105BF821B6397D86056D3451F725C9A8E4E63A906CC35DC` |
| SSDEEP | `48:xpSlR0OBYbv1RhcVHBrDf8TdiM3O8Ecck1GURYjyB/0ysiYfexwdjL5p:ecaYbv3hcDEdiM3X9cqGURYjE0ysivx4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_98ac0ba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98ac0ba82d65964691097fe7d0f4a96175425f44fcdd5c6d211377ca88ce4e0b"
    family = "unknown"
    file_name = "zk_bridge_mips_9004"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:42"
  condition:
    hash.sha256(0, filesize) == "98ac0ba82d65964691097fe7d0f4a96175425f44fcdd5c6d211377ca88ce4e0b"
}
```

### Sample 59: `21f209415c23ae83`

| Field | Value |
|---|---|
| SHA-256 | `21f209415c23ae83ce7e74b8d711f7b7f9f01b7fc0a7c3c24f94c93ab51c958d` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-mipsle-softfloat` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a6fc939c2c58493a4868859be7259b2` |
| SHA-1 | `6be4bacd6021509066f3bee9a211a21d5cdec242` |
| SHA-256 | `21f209415c23ae83ce7e74b8d711f7b7f9f01b7fc0a7c3c24f94c93ab51c958d` |
| SHA3-384 | `d0de145948d046e85134e08573526ddce4d99af2a8c6774f647bf55093508c36c99b710b5ed0cbee13ad501711f09700` |
| TLSH | `T1EED62C55AD842BF6CC2D4E3490EACA9613705D144AF2463A62A0FF9DBD772787F0788C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:syZAO3BU79NN22WIFFe8ZA2IyYlSO8tlbQov3gfScwGBnf84gd2+F000J/dNwbgg:xE922ntdIflkGhLIEot` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_21f20941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21f209415c23ae83ce7e74b8d711f7b7f9f01b7fc0a7c3c24f94c93ab51c958d"
    family = "unknown"
    file_name = "myc2-agent-linux-mipsle-softfloat"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:40"
  condition:
    hash.sha256(0, filesize) == "21f209415c23ae83ce7e74b8d711f7b7f9f01b7fc0a7c3c24f94c93ab51c958d"
}
```

### Sample 60: `2153ccb713bd5df0`

| Field | Value |
|---|---|
| SHA-256 | `2153ccb713bd5df077c8ff530eafe2f473a0470b5c98c0301da7a3c41b8478e9` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-riscv32` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `051ab252efab6e638363a713bbdc2ba3` |
| SHA-1 | `c106add0eae6431f90d22ba7913e2eacc18dbb4f` |
| SHA-256 | `2153ccb713bd5df077c8ff530eafe2f473a0470b5c98c0301da7a3c41b8478e9` |
| SHA3-384 | `24305fa25ab69f5a7f76faf9f0095cb8e9678bee750c61336c0a04419c8f99939e64ebdb326eef014383bee3013f7ac2` |
| TLSH | `T1E1B1210BD7D5BE63D468633DBC930B047670AC411BF593E34B1885643A072A82551B6A` |
| SSDEEP | `96:WUhcBWBShSQr0RqpIcBRfSlN/mNJw67lAl:pc8ch6sqcfSlN/m3P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_2153ccb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2153ccb713bd5df077c8ff530eafe2f473a0470b5c98c0301da7a3c41b8478e9"
    family = "unknown"
    file_name = "myc2-preload-linux-riscv32"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:36"
  condition:
    hash.sha256(0, filesize) == "2153ccb713bd5df077c8ff530eafe2f473a0470b5c98c0301da7a3c41b8478e9"
}
```

### Sample 61: `d64b93bb6917326e`

| Field | Value |
|---|---|
| SHA-256 | `d64b93bb6917326ec993b3cc398ed1259d64dcbf65e5dc23f53f2ae8b8350fd9` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-armv5` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c94cb7d46fa090537c28c9c0a9db6a2` |
| SHA-1 | `6dbb1ea733380555179e995f8a75bbca175c691a` |
| SHA-256 | `d64b93bb6917326ec993b3cc398ed1259d64dcbf65e5dc23f53f2ae8b8350fd9` |
| SHA3-384 | `893181e321dbecb9c9cd88c242f4d76a21ae470ac9a83749982f24f83d6035eb8d851a1054813f52743c486edf075e1e` |
| TLSH | `T1ECC63B97B9D24983C8E83A37B8BD80C433631EB99B9756565D05FD383ABE1D90E38314` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:mOGnqoGUr54k4NqsPbU+fN01RAo9H/ZN0c93gfScwGBnf8LNIA2b68qCiWWWIvKX:sqoGaKk4gsDFeco9yfbThUvKxXLHEM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_d64b93bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d64b93bb6917326ec993b3cc398ed1259d64dcbf65e5dc23f53f2ae8b8350fd9"
    family = "unknown"
    file_name = "myc2-agent-linux-armv5"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:33"
  condition:
    hash.sha256(0, filesize) == "d64b93bb6917326ec993b3cc398ed1259d64dcbf65e5dc23f53f2ae8b8350fd9"
}
```

### Sample 62: `8a825a6bddfe0a69`

| Field | Value |
|---|---|
| SHA-256 | `8a825a6bddfe0a699000cd2bb9d62fd9cf13e62eb385e0d58d1feb64ee37b491` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-mips64le` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c788bad110e9c73744d934f3ecb83218` |
| SHA-1 | `6d69362ca1e207b1105cf13f793893eaab946178` |
| SHA-256 | `8a825a6bddfe0a699000cd2bb9d62fd9cf13e62eb385e0d58d1feb64ee37b491` |
| SHA3-384 | `13af425ba81e8e3cfddab3b619258606dbc6335a9c044897e6717c2377e0c07034e2aa54f8155a0189755f42b3c2fabb` |
| TLSH | `T1CEF5E715BEC22B66C98D033545ED229A23603F451B95072713B8FBAC3A7773DAF5688C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:0M8Msb1OHZX4bSeRV12iql+mJI7hQTwWiu9sTIlq7zRJ1hGkGB2L1XF0HWQ:08sxO5IR12iql+mJI7hQTwT/f1OQF0Hb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_8a825a6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a825a6bddfe0a699000cd2bb9d62fd9cf13e62eb385e0d58d1feb64ee37b491"
    family = "unknown"
    file_name = "myc2-shell-linux-mips64le"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:29"
  condition:
    hash.sha256(0, filesize) == "8a825a6bddfe0a699000cd2bb9d62fd9cf13e62eb385e0d58d1feb64ee37b491"
}
```

### Sample 63: `c026c274bf6b34e8`

| Field | Value |
|---|---|
| SHA-256 | `c026c274bf6b34e86aa6fec4926343daf74cbecd61a0282ee7f374eb8a40abd3` |
| Family label | `Mirai` |
| File name | `myc2-killer-linux-arc` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecada364a0ffad0e97d1138b826f6b57` |
| SHA-1 | `809781c0fca4e8bf8e672ee2acd5d564add46eab` |
| SHA-256 | `c026c274bf6b34e86aa6fec4926343daf74cbecd61a0282ee7f374eb8a40abd3` |
| SHA3-384 | `2f127e12d864d92c63b882316e76d90fa272a44cc4ccc6e42fbe9e90d643ff29040bbc32242cc7a3f1545994581b617a` |
| TLSH | `T14CD37B4BB30A76C4C5610AF0A7D79F5C2E27B0242F5752EB6D2A93E6A0F31DB441DB60` |
| SSDEEP | `1536:Z6XRBVkUPwcYrLjHACEk9YkGacPL8HV5MJ7z+JAg00HSr/Y9BWgJXi9s/LW7JG:IBqUPEvHACEPkGa2WTo7zsAgxBS9sq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_c026c274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c026c274bf6b34e86aa6fec4926343daf74cbecd61a0282ee7f374eb8a40abd3"
    family = "Mirai"
    file_name = "myc2-killer-linux-arc"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:26"
  condition:
    hash.sha256(0, filesize) == "c026c274bf6b34e86aa6fec4926343daf74cbecd61a0282ee7f374eb8a40abd3"
}
```

### Sample 64: `07f67717e4a1edaf`

| Field | Value |
|---|---|
| SHA-256 | `07f67717e4a1edaf37a20893597dd26e4dc1d84b4de814736c2c4365081649e5` |
| Family label | `Mirai` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4786e68f0e1db0fcdf283251e7720bda` |
| SHA-1 | `40fd37e533a6832ac92d812dc55627f58bd0d848` |
| SHA-256 | `07f67717e4a1edaf37a20893597dd26e4dc1d84b4de814736c2c4365081649e5` |
| SHA3-384 | `e98e8f1fba8ae6059bfaf7d1cb8a2a520c839932f15ebcf77ce83f9c3185ce5c7dca5fc37a883b99898215ed1ccf4a37` |
| TLSH | `T1CDE46C06EF901FEBC4AFCF35896E831705EDD88742C2A23961BCC96CBA496594FD3458` |
| TELFHASH | `t17c0126354b2066225a51de8898eea763612c865a9b0cfc77d431440c21050fee63bc8f` |
| SSDEEP | `12288:YNA0vLG0uwJxYZi9BbqNWsilWN1Lmqh6Ie0UjSRmBX/NM/fGGUPEHQbObS9JAsOf:w7LG0uErefX8Qno/PZIsu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_07f67717
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f67717e4a1edaf37a20893597dd26e4dc1d84b4de814736c2c4365081649e5"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:24"
  condition:
    hash.sha256(0, filesize) == "07f67717e4a1edaf37a20893597dd26e4dc1d84b4de814736c2c4365081649e5"
}
```

### Sample 65: `2d69394f8b2cf830`

| Field | Value |
|---|---|
| SHA-256 | `2d69394f8b2cf8304b98bc7f1b38e6f413195c80a6c680097b4cbfad521935e5` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-mips64le` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:21` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `763cbfac977e7e1e9a74a9e529c2ec81` |
| SHA-1 | `42eb31f17e0436de76d37d2790d18a2beeabe587` |
| SHA-256 | `2d69394f8b2cf8304b98bc7f1b38e6f413195c80a6c680097b4cbfad521935e5` |
| SHA3-384 | `b352319a26803722690325a9bf2dae53be9aa5c0c4832a045277d3cb60c7652423da09ca76de1c060c3fb6f2ca2445cb` |
| TLSH | `T101D609A1AE822BA7C9DD033445ED62E652603E444695073313F4FBB83E77B3D9F5A848` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `196608:UU63WJKtb9v9cVxZv3C/nzk1/mos61QmqsYh2vr6lB/ZLeE:563WJKtb9v9cVxZv3iZhD/EE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_2d69394f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d69394f8b2cf8304b98bc7f1b38e6f413195c80a6c680097b4cbfad521935e5"
    family = "unknown"
    file_name = "myc2-agent-linux-mips64le"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:21"
  condition:
    hash.sha256(0, filesize) == "2d69394f8b2cf8304b98bc7f1b38e6f413195c80a6c680097b4cbfad521935e5"
}
```

### Sample 66: `3357e4bfb3c8b408`

| Field | Value |
|---|---|
| SHA-256 | `3357e4bfb3c8b408b2b4f6eaaf66b917b437f070e27b4c0ae444ca6b1f70dcb9` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-386` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:17` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32cf2b48bb0e3cd4dc9668ad884324f4` |
| SHA-1 | `24219884e69d5bd01f5643669b8626d01054ae07` |
| SHA-256 | `3357e4bfb3c8b408b2b4f6eaaf66b917b437f070e27b4c0ae444ca6b1f70dcb9` |
| SHA3-384 | `3609e98d25358f63fac79095a0c4a20c8feca19d9662bd62cfb0edf91bf160d945708461dad335c5debf8b735a171353` |
| TLSH | `T1B8C64950FACB04F2E9430E3054ABB23F67311D098B24DBD7DB447B29F93B692593A259` |
| TELFHASH | `t13c23beb3049ca4e967e0451783ab7124cff2e0f726e028f165e6bcd1dab2c435636979` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:3eYO48cSvcWDCjdb66cOmMMN9Wy2dcyuu7EBoZf+1H8Eh:3E48PdCjdJcOmZ9WyHwa1h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_3357e4bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3357e4bfb3c8b408b2b4f6eaaf66b917b437f070e27b4c0ae444ca6b1f70dcb9"
    family = "unknown"
    file_name = "myc2-agent-linux-386"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:17"
  condition:
    hash.sha256(0, filesize) == "3357e4bfb3c8b408b2b4f6eaaf66b917b437f070e27b4c0ae444ca6b1f70dcb9"
}
```

### Sample 67: `79267be4e49498c3`

| Field | Value |
|---|---|
| SHA-256 | `79267be4e49498c346d039e8e873b53e585df61eb9ab13a7a06873d2582daf4d` |
| Family label | `Mirai` |
| File name | `myc2-agent-linux-arc` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bf244b9755227b21039849bb4e975d4` |
| SHA-1 | `962da94937a37c014f4d1b22050c67c3d0a94253` |
| SHA-256 | `79267be4e49498c346d039e8e873b53e585df61eb9ab13a7a06873d2582daf4d` |
| SHA3-384 | `f03364a7a9033a0830c7a87dce9a21f7678280c9ef05197ef9a424a4fb0d541524c6b021d66f4711b55f94159ed9dd4f` |
| TLSH | `T130046C4BB70A76C9C1300EB1A7D7AF5C2937B0241F0B66EFAD1A52E664F31DA441D7A0` |
| SSDEEP | `3072:x77vzGVvzmrg/mS0rXkWbnUatxib1BbcaYcwajpnCP/eq:x3CVvzMh4WbnT/ib1Jca1Pjpa/eq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_79267be4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79267be4e49498c346d039e8e873b53e585df61eb9ab13a7a06873d2582daf4d"
    family = "Mirai"
    file_name = "myc2-agent-linux-arc"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:13"
  condition:
    hash.sha256(0, filesize) == "79267be4e49498c346d039e8e873b53e585df61eb9ab13a7a06873d2582daf4d"
}
```

### Sample 68: `1bf4972256900769`

| Field | Value |
|---|---|
| SHA-256 | `1bf49722569007690957f4110d0046441e44c36975719f269b6806c115b9d488` |
| Family label | `unknown` |
| File name | `scanner-linux-amd64` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:10` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4b64da2997b3e6c3803087ef0cd3066` |
| SHA-1 | `7d7ad21509a14879872661537f32192860ae3ce4` |
| SHA-256 | `1bf49722569007690957f4110d0046441e44c36975719f269b6806c115b9d488` |
| SHA3-384 | `ad76d111425938c704ffb1086b2da6558431c17e028d4365a18811388e3ba3393c21d10dfda6ac29a73bdd4070f4be70` |
| TLSH | `T1F4B54B57BCA104A5C4AEA23289B255937B71BC481F3123DB2F50FA782FB7BD0597A344` |
| TELFHASH | `t1204247714abd74b5b6a9da10b393b4f895372c6572f838f11023ad95efc1e801ca2877` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:rycb0YvbxOTw/GwpZCpHYfQIa+R90mfuw0Cjaco79fThkTwXZB2ajt/bxEk:rycwYvbxOTw+wpZpfXHuw0aaco7BAw5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_1bf49722
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bf49722569007690957f4110d0046441e44c36975719f269b6806c115b9d488"
    family = "unknown"
    file_name = "scanner-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:10"
  condition:
    hash.sha256(0, filesize) == "1bf49722569007690957f4110d0046441e44c36975719f269b6806c115b9d488"
}
```

### Sample 69: `d854d418353d351f`

| Field | Value |
|---|---|
| SHA-256 | `d854d418353d351fb1027fe141396faa33a83be13b44185928cb22df3f82f8a4` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-mipsle` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:07` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07b62dfd893c43532cb7d7d273aabe1c` |
| SHA-1 | `4e17f842ee45f977565b4d00b7ebbca498bb9336` |
| SHA-256 | `d854d418353d351fb1027fe141396faa33a83be13b44185928cb22df3f82f8a4` |
| SHA3-384 | `554cd8630656d624cea65246586bd0c00bcbbcb27fc9418c1966af64c325fc047b8af9acb4b09eafeb65f53b7af8a129` |
| TLSH | `T184E5D804AD802EA7C42E5B3498EA8A9613B45D140FF1566B22A8FE6D7C773347F43D9C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:ck6p2h8ib/OeQbZNplLeSFRoEAuyyI1WMTZxli3HG8myxix0dQxLRRy1K7JFwgVy:al3F+oGliW8QEYrwuOb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_d854d418
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d854d418353d351fb1027fe141396faa33a83be13b44185928cb22df3f82f8a4"
    family = "unknown"
    file_name = "myc2-shell-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:07"
  condition:
    hash.sha256(0, filesize) == "d854d418353d351fb1027fe141396faa33a83be13b44185928cb22df3f82f8a4"
}
```

### Sample 70: `fdd57a728d9f6dc1`

| Field | Value |
|---|---|
| SHA-256 | `fdd57a728d9f6dc1e27451cb8a18c25a2f143195a1ae18aa904039cbdc25c6bb` |
| Family label | `unknown` |
| File name | `myc2-killer-linux-riscv32` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b86ec6509ebbd822cf708c5eb3379368` |
| SHA-1 | `55540f45f6ef9f2a6c5b329ac73539b6a69a3ae9` |
| SHA-256 | `fdd57a728d9f6dc1e27451cb8a18c25a2f143195a1ae18aa904039cbdc25c6bb` |
| SHA3-384 | `a16d3847e2c64bd9a99a7e3e317105d825f861c8f9a691b410f73d1deb97dedbc8c8a063efba64babdd899c99462643c` |
| TLSH | `T11583CFC4B21A74D1C79382B524E046478375EDB74B6BB71A19DCB9E82A388AC0EC4DF5` |
| SSDEEP | `1536:jpbKj5vWDLkYslcZ66lxLUzSZ2YUtefl53GkpApOP/DGzE/YXXidIr:qWDVsaZvxLqpYUtYl52kpAe/6E/YXSG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_fdd57a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd57a728d9f6dc1e27451cb8a18c25a2f143195a1ae18aa904039cbdc25c6bb"
    family = "unknown"
    file_name = "myc2-killer-linux-riscv32"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:04"
  condition:
    hash.sha256(0, filesize) == "fdd57a728d9f6dc1e27451cb8a18c25a2f143195a1ae18aa904039cbdc25c6bb"
}
```

### Sample 71: `a50a751252223942`

| Field | Value |
|---|---|
| SHA-256 | `a50a751252223942429abb005e78fb4fed4ad63cbd9a300b06ba5500d2fe3a06` |
| Family label | `Mirai` |
| File name | `bot_local` |
| File type | `elf` |
| First seen | `2026-11-21 07:00:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a196c9b77856dba337b79b2d40319f9c` |
| SHA-1 | `ff64e67a2062e22006d5bec65af2ab13116e7dba` |
| SHA-256 | `a50a751252223942429abb005e78fb4fed4ad63cbd9a300b06ba5500d2fe3a06` |
| SHA3-384 | `0b0b94b2c47871fe5530c66eb61cabe87094d1197651a92f0892c8d48517f6d6c3e6ac6246a49e519b2c76c3c1672eb2` |
| TLSH | `T18A54F93AE3A1EA79D442E9782FDFC2E16534B0F06732784F33521A327836AC44F65656` |
| TELFHASH | `t1e5f0ac81fc719b394dd359b09c6c43e88225c6167172e334ef14c9d0993e014b729f4a` |
| SSDEEP | `6144:0GAUfxVc0V1AdEeGDIYkXBPg57ujS/rBP6X5A:0GAUfDc0/ttkXBPvQlPu5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_a50a7512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a50a751252223942429abb005e78fb4fed4ad63cbd9a300b06ba5500d2fe3a06"
    family = "Mirai"
    file_name = "bot_local"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:00"
  condition:
    hash.sha256(0, filesize) == "a50a751252223942429abb005e78fb4fed4ad63cbd9a300b06ba5500d2fe3a06"
}
```

### Sample 72: `004ecde33410d2c7`

| Field | Value |
|---|---|
| SHA-256 | `004ecde33410d2c73b54a33ea3a7b1f5269c4b712e8224a2c4b62ef5ec2a29bc` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-sh4` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:58` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50d6c65cec3ccc1583d128c351f4aa21` |
| SHA-1 | `19a172ee7d7d8f0ddac8effb8604eb70f2fdc4d2` |
| SHA-256 | `004ecde33410d2c73b54a33ea3a7b1f5269c4b712e8224a2c4b62ef5ec2a29bc` |
| SHA3-384 | `b5e45b39743bedad3a7908aa17ab527866eda455440f298f29fda044f461fc61875b6c6c65d01809121fc33739dd6573` |
| TLSH | `T1D8B15242D3E49E2AC8241A78C4E362702374FE4036291727DBE4AAB53D43ABD2F1135A` |
| SSDEEP | `48:DBRaBWBSouo3yyzMeT3YHEQMOY2MzhRhWBg8+bfs8ZPduvpd1:DB4BWBShBeTUy7d1Ryg8evZPduvpd1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_004ecde3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "004ecde33410d2c73b54a33ea3a7b1f5269c4b712e8224a2c4b62ef5ec2a29bc"
    family = "unknown"
    file_name = "myc2-preload-linux-sh4"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:58"
  condition:
    hash.sha256(0, filesize) == "004ecde33410d2c73b54a33ea3a7b1f5269c4b712e8224a2c4b62ef5ec2a29bc"
}
```

### Sample 73: `467214c576ea4dc1`

| Field | Value |
|---|---|
| SHA-256 | `467214c576ea4dc1d1bf4ff2b87e094d64f026103f71e3d6471196b325f4db67` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-mipsle-softfloat` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b23c97b85fca1567eca4506eaf5222a2` |
| SHA-1 | `3fa53fa1ba14a2a0da1e73b1be604330dbe99756` |
| SHA-256 | `467214c576ea4dc1d1bf4ff2b87e094d64f026103f71e3d6471196b325f4db67` |
| SHA3-384 | `281369079fb728ce29cc91f7f38472e7e7dfa09ac73e6ea15681dd38ee39370ed15156317524e48b83c3cf8579847c23` |
| TLSH | `T1EBF5E704AD852AA7C81E4F3494EA8A9703705E140BF1573A25A8FEAD7C773397F4789C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:WmL6+VdSfYCx4Is8dTMkb2436aAtxeZadR+LaRv1KOQgWGNAxW5:Nz+QCylWgFYs8s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_467214c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "467214c576ea4dc1d1bf4ff2b87e094d64f026103f71e3d6471196b325f4db67"
    family = "unknown"
    file_name = "myc2-shell-linux-mipsle-softfloat"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:55"
  condition:
    hash.sha256(0, filesize) == "467214c576ea4dc1d1bf4ff2b87e094d64f026103f71e3d6471196b325f4db67"
}
```

### Sample 74: `7c2479254ab633b3`

| Field | Value |
|---|---|
| SHA-256 | `7c2479254ab633b3d552d9db092cbfd64bcecf161efa4979b64586963d78043e` |
| Family label | `Mirai` |
| File name | `main_ppc64` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7dbf022aaba6a1df2e2d546d868f315` |
| SHA-1 | `a05312fc3d7954bc89897b20bae6f80551d6dce1` |
| SHA-256 | `7c2479254ab633b3d552d9db092cbfd64bcecf161efa4979b64586963d78043e` |
| SHA3-384 | `3700751176e2ba9e031267481a1cb1728279d16f8a91c222af3e096e41841567bc8b3b8fbc02cc8bb77fb6250f79bf8a` |
| TLSH | `T151C318033600EE26CB83A937821EFD16F716769516A29B15BB00827FDE75316DF2E5C8` |
| SSDEEP | `1536:v0r1iwKN0oAfUZ9oCzovBMH9YPAa7fW8Q0lvp0enqDWi4N1oraHYkpemLval5:E1LKN0Xfmj849SE0N2jKi4TQ2v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_7c247925
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c2479254ab633b3d552d9db092cbfd64bcecf161efa4979b64586963d78043e"
    family = "Mirai"
    file_name = "main_ppc64"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:52"
  condition:
    hash.sha256(0, filesize) == "7c2479254ab633b3d552d9db092cbfd64bcecf161efa4979b64586963d78043e"
}
```

### Sample 75: `ccd8cdbaf11aa9cb`

| Field | Value |
|---|---|
| SHA-256 | `ccd8cdbaf11aa9cbac84e73cbf634b686052a4caf317f44a88b77c00009832b6` |
| Family label | `Mirai` |
| File name | `loader.aarch64` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88085de98c40b7ff05df1ca205d91103` |
| SHA-1 | `59721eed1eba50b79dd61bd9c25992aa9576209b` |
| SHA-256 | `ccd8cdbaf11aa9cbac84e73cbf634b686052a4caf317f44a88b77c00009832b6` |
| SHA3-384 | `3a65c42959efed32d2c9df9bbb119661ce1e02752a0b0e03c6b1335cff9ed65c1d52a88414f24ffc96647371356c67d8` |
| TLSH | `T191A35B40B58DF81DD6C5E0BC494E4AA0A32BFD601F12833A7C1277DEE9716E44FA97A1` |
| SSDEEP | `1536:tflvMJrdWYrN+RZKoNDU1xvMzba8DcD/VaUx2znRMyi99jNcXSrFBb6qsfR4GxXS:tdmXQRZKoRoFW6aFiXx6qspPXF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_ccd8cdba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccd8cdbaf11aa9cbac84e73cbf634b686052a4caf317f44a88b77c00009832b6"
    family = "Mirai"
    file_name = "loader.aarch64"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:50"
  condition:
    hash.sha256(0, filesize) == "ccd8cdbaf11aa9cbac84e73cbf634b686052a4caf317f44a88b77c00009832b6"
}
```

### Sample 76: `78fc34cfcb438a76`

| Field | Value |
|---|---|
| SHA-256 | `78fc34cfcb438a76e7859e76853d699f6b19faca7e378bd379c6e72f33222a49` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-mips` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c998b7ab4026e62ba0959e56bf21414` |
| SHA-1 | `e2c98edaa293d41bae4195f43f4ace15f59311dc` |
| SHA-256 | `78fc34cfcb438a76e7859e76853d699f6b19faca7e378bd379c6e72f33222a49` |
| SHA3-384 | `f090bfb05f18319ce4a346c6677791662d28ec9f34026f3135f078bc123dc3358600106ab573f6e03011b0d51926adf8` |
| TLSH | `T178E528127F68DB0EE518223459F1CB886B6A1C8502D2A51BB355F319E9F30BC4E6ECF5` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:kLUnn7x6slXzDRetfAgrTkgTaj5MXZ4S3EmkfPA0K60HUWSxh3j7gQyvLu+M1K7t:kLUAsXeHkfPXZgSYYoSGt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_78fc34cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78fc34cfcb438a76e7859e76853d699f6b19faca7e378bd379c6e72f33222a49"
    family = "unknown"
    file_name = "myc2-shell-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:47"
  condition:
    hash.sha256(0, filesize) == "78fc34cfcb438a76e7859e76853d699f6b19faca7e378bd379c6e72f33222a49"
}
```

### Sample 77: `34fe8478bd83c8c2`

| Field | Value |
|---|---|
| SHA-256 | `34fe8478bd83c8c20316969dff761f0603a9c085321521b67e0208e2ef42af90` |
| Family label | `unknown` |
| File name | `myc2-killer-linux-sh4` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fa9d8f91cfc7f75526d72f96c44525b` |
| SHA-1 | `3f8582389972c5adbc7529fb49cdf165ae409d0e` |
| SHA-256 | `34fe8478bd83c8c20316969dff761f0603a9c085321521b67e0208e2ef42af90` |
| SHA3-384 | `5f746aefb13b4f3b0097625a1d97a9c5a469445c968429adbbfcb1e7d94f52c484c7c754256caee1b9d3a593ff0f1ea9` |
| TLSH | `T12D739C30F091DCA7C90486F61034D4710651ADB01BE3A6D4B46EF3AD9BA3F90BE9E7A1` |
| SSDEEP | `1536:17XObUCmDxOkHOk+T6NNItuWYbCip7doyrZgtSQO0XijIrU:1SbDmXb+2WYbCi5rZgtSQO0SU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_34fe8478
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34fe8478bd83c8c20316969dff761f0603a9c085321521b67e0208e2ef42af90"
    family = "unknown"
    file_name = "myc2-killer-linux-sh4"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:45"
  condition:
    hash.sha256(0, filesize) == "34fe8478bd83c8c20316969dff761f0603a9c085321521b67e0208e2ef42af90"
}
```

### Sample 78: `781df860d104130d`

| Field | Value |
|---|---|
| SHA-256 | `781df860d104130d6890f515430ac004d8c16ec34f443f91e2a8b9444a614546` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-arc` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82d52dbe0f5e0b63ab8e2de24fefa226` |
| SHA-1 | `a89fd804f7f0f0dd024e9b25b26fedef9c35437e` |
| SHA-256 | `781df860d104130d6890f515430ac004d8c16ec34f443f91e2a8b9444a614546` |
| SHA3-384 | `058bc8a52e2b8e256ac75ab1efae2d0751e731ee37b519922ff47795e414fe04e243a7ae580489d6f5f50f228f80ac70` |
| TLSH | `T199129382EBC1E839D2D4163D10EB073063B2985909A9B787663FA55D7BD326B30C531E` |
| SSDEEP | `96:E5tBWBSh7z1Vn7dJniQrtjVTvgTGtMWvZ9Mr:E/8ch7xV7dJniYtpTEGti` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_781df860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "781df860d104130d6890f515430ac004d8c16ec34f443f91e2a8b9444a614546"
    family = "unknown"
    file_name = "myc2-preload-linux-arc"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:42"
  condition:
    hash.sha256(0, filesize) == "781df860d104130d6890f515430ac004d8c16ec34f443f91e2a8b9444a614546"
}
```

### Sample 79: `4b0b7a916b29ab63`

| Field | Value |
|---|---|
| SHA-256 | `4b0b7a916b29ab63061cde59b018cc669a835fd09d9d2d4b8fa618b1bd638261` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-ppc` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a36157324cd56d37a89d883be2290b6` |
| SHA-1 | `92fcccd62ab7bb73e124c80225b0b56c5c867172` |
| SHA-256 | `4b0b7a916b29ab63061cde59b018cc669a835fd09d9d2d4b8fa618b1bd638261` |
| SHA3-384 | `c967ffcc9df9fd7c53fc996bbc51e95125599a671641b86210bf12878877e0d328b7c093b987e871455b9a000e45e42a` |
| TLSH | `T1BF635241F34A582BD4142F3C67FF63086379FC028B5B831B130DA64A2D6227EAD5276D` |
| SSDEEP | `96:aABWBShV+Jo/GlI1WnPdCaCvDLIM3U5M6QU:t8chV+JoHWnPIFvX5g` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_4b0b7a91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b0b7a916b29ab63061cde59b018cc669a835fd09d9d2d4b8fa618b1bd638261"
    family = "unknown"
    file_name = "myc2-preload-linux-ppc"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:40"
  condition:
    hash.sha256(0, filesize) == "4b0b7a916b29ab63061cde59b018cc669a835fd09d9d2d4b8fa618b1bd638261"
}
```

### Sample 80: `3fd5f54a31541641`

| Field | Value |
|---|---|
| SHA-256 | `3fd5f54a31541641d8d5525e791e528d76c2845d7d5c630d4726d527196474dd` |
| Family label | `unknown` |
| File name | `myc2-dlr-linux-mips` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3798b4b1817ff82e431bb3fe6f0219d0` |
| SHA-1 | `3a74af2e92744f6a10b85c91d60cbb0417f2a21d` |
| SHA-256 | `3fd5f54a31541641d8d5525e791e528d76c2845d7d5c630d4726d527196474dd` |
| SHA3-384 | `050019fabda6b3fd4caaf54494ce4cbd6eb7afa5513b491766358bba49afe5bff44ef8d6e87f427b5a234f0441524011` |
| TLSH | `T1BC31114EAE44ABC0F5A487B595BE0258764571C509B28E8FF2A4A6065F187903CF65A0` |
| SSDEEP | `48:xhKPqgWSG7sISmX0DA1KnvO2HPUbKsJsUHtUUt:zOX/e3Sm9Km1eO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_3fd5f54a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fd5f54a31541641d8d5525e791e528d76c2845d7d5c630d4726d527196474dd"
    family = "unknown"
    file_name = "myc2-dlr-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:38"
  condition:
    hash.sha256(0, filesize) == "3fd5f54a31541641d8d5525e791e528d76c2845d7d5c630d4726d527196474dd"
}
```

### Sample 81: `9edceade969da12e`

| Field | Value |
|---|---|
| SHA-256 | `9edceade969da12e0c700f13488552e77168ff88d811202a4a02f4bb67cd0315` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbaef0e75aff37f1a5854043422b8d64` |
| SHA-1 | `5e51ff2e46dc1b0336b4383b329de3bc911cc119` |
| SHA-256 | `9edceade969da12e0c700f13488552e77168ff88d811202a4a02f4bb67cd0315` |
| SHA3-384 | `c71d709c2bb240cb07ce795e38a7963dfc07d1931867b505ff77a36fabea37d3db5494cbe135b10c18b7957655fbc34a` |
| TLSH | `T14D934B02B95224B9C95BCD74C25E9122E738741653A26BFF27C0AF213F16DD0AF3EA51` |
| TELFHASH | `t17131f9c8a7c91939c3d942109e04793b54e320f766561cc8479e8fda2d17fd4129ac31` |
| SSDEEP | `1536:CrNAZ+KecZowjO2XRUgKWbBUKdlFx4122F/LGfqZ6Y8UTxda54oNIlAosBC:6WnZo1gPdlfC2eTGNY8UFda59NwAosB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_9edceade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9edceade969da12e0c700f13488552e77168ff88d811202a4a02f4bb67cd0315"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:35"
  condition:
    hash.sha256(0, filesize) == "9edceade969da12e0c700f13488552e77168ff88d811202a4a02f4bb67cd0315"
}
```

### Sample 82: `70d60ff8199d8645`

| Field | Value |
|---|---|
| SHA-256 | `70d60ff8199d864543b08c09c7bcf01a91ee1fdf3b5160dda29f56e745fb6d6a` |
| Family label | `unknown` |
| File name | `zk_bridge_mips_9001` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `533c9dd4e6d4a6a97b05041f54110532` |
| SHA-1 | `574af2c3031dc5df5c560437994447344c04649d` |
| SHA-256 | `70d60ff8199d864543b08c09c7bcf01a91ee1fdf3b5160dda29f56e745fb6d6a` |
| SHA3-384 | `d245fe4398fcd325bad0ea97cbd3dd2c36e92d17d98d89563e469dba63e07a68ffa62c8f96dc00f1a2a0bfaaa4f46514` |
| TLSH | `T1D751A427AF241E9FC81D193105BF821B73A7D86052C3452F721C9A8E4E63A906DC35EC` |
| SSDEEP | `48:xflR0OBYbv1RhcVHBrDfbdOdiM3O8Ecck1GURYjyB/xysiYfexwdjL5p:RcaYbv3hcDzodiM3X9cqGURYjExysivi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_70d60ff8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70d60ff8199d864543b08c09c7bcf01a91ee1fdf3b5160dda29f56e745fb6d6a"
    family = "unknown"
    file_name = "zk_bridge_mips_9001"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:33"
  condition:
    hash.sha256(0, filesize) == "70d60ff8199d864543b08c09c7bcf01a91ee1fdf3b5160dda29f56e745fb6d6a"
}
```

### Sample 83: `5dd5d3033aa1b730`

| Field | Value |
|---|---|
| SHA-256 | `5dd5d3033aa1b730cd6059f5cdc4d01a8b63a1bc3d362cc7fa990c46ce96e055` |
| Family label | `Mirai` |
| File name | `bot.x86` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f057d5c437f783a8879597a0b7f3d56` |
| SHA-1 | `53617a383369700c8f6713d4c34f8487d88778df` |
| SHA-256 | `5dd5d3033aa1b730cd6059f5cdc4d01a8b63a1bc3d362cc7fa990c46ce96e055` |
| SHA3-384 | `6bafea3cb8335398cd722d8a361b0373b799836598b37c85b89a707d98faeb2598e32b9bd3fb9158c1ed1afeadb74880` |
| TLSH | `T188F46D8AE793D8F2F16341B60A8FC7F2053492165027B6F3EB8D6A7678327521E4631D` |
| TELFHASH | `t1590147350b206a225a51de94aceea367652cc65b9b1dfd77d431444c31080feea3bc8f` |
| SSDEEP | `24576:/tvaZuhLfhpZ6HT0zqOUbRemJm5JBy54UuQ:VhLfhpiI2rbETl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_5dd5d303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dd5d3033aa1b730cd6059f5cdc4d01a8b63a1bc3d362cc7fa990c46ce96e055"
    family = "Mirai"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:30"
  condition:
    hash.sha256(0, filesize) == "5dd5d3033aa1b730cd6059f5cdc4d01a8b63a1bc3d362cc7fa990c46ce96e055"
}
```

### Sample 84: `a45cadbc4020de09`

| Field | Value |
|---|---|
| SHA-256 | `a45cadbc4020de09ef964a4f7604037f5aa0a81d1fde73b4eda6488154a73ba2` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-amd64` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9a973e9e53f608403950d3b669b8dfc` |
| SHA-1 | `37bed1e1b1496d0a8bd1bd7b19835e12def88871` |
| SHA-256 | `a45cadbc4020de09ef964a4f7604037f5aa0a81d1fde73b4eda6488154a73ba2` |
| SHA3-384 | `a15453c48a163f4861a78aa2aff1e38e7391a0dac5da47e64d3c135a52881c5c1a5cf2fa2db6a4d54fbe3dd4bce2fca0` |
| TLSH | `T15CD54A17FCA518AAC0AEA232897656567F71BC490B3023C72B60BA3D2F77BD06D75344` |
| TELFHASH | `t1556298754a7c74b5b2a6d921f3a3b5f495331cb562f438b05063ac81efc1e8068e687b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:9f9VjxEuNi5IlUkWjHkXT3AXkAGSyttaV0I0jl:9fPCuEVdyl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_a45cadbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a45cadbc4020de09ef964a4f7604037f5aa0a81d1fde73b4eda6488154a73ba2"
    family = "unknown"
    file_name = "myc2-shell-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:28"
  condition:
    hash.sha256(0, filesize) == "a45cadbc4020de09ef964a4f7604037f5aa0a81d1fde73b4eda6488154a73ba2"
}
```

### Sample 85: `3d0a4c17bff6b295`

| Field | Value |
|---|---|
| SHA-256 | `3d0a4c17bff6b295f2d7ce5c3e404bb6362978429872089320b5003f7e9b8dbd` |
| Family label | `unknown` |
| File name | `myc2-shell-linux-mips-softfloat` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:25` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c73dfe871394020079abb71b4eea69b` |
| SHA-1 | `e2a05876534850873f5780a05d22db8382021af9` |
| SHA-256 | `3d0a4c17bff6b295f2d7ce5c3e404bb6362978429872089320b5003f7e9b8dbd` |
| SHA3-384 | `069183a0fee87f309f71393ae31312a5da2c5ea1970b29cf5a5ea7bd09bb4a06703de83210553aa5523eac9b69ea9d9f` |
| TLSH | `T173F518137F28DB1EE12831345CB1CB986B6A1C8502D6A557B396F30DB9B30AC496EDF4` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:hK1CkqbRFzL5jY7cptK2TJrl8W9zfnllvgDK6CUOyoluinInl6jMAQVC45+r1KOL:41CNStCUTqnGrKYU4H2T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_3d0a4c17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d0a4c17bff6b295f2d7ce5c3e404bb6362978429872089320b5003f7e9b8dbd"
    family = "unknown"
    file_name = "myc2-shell-linux-mips-softfloat"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:25"
  condition:
    hash.sha256(0, filesize) == "3d0a4c17bff6b295f2d7ce5c3e404bb6362978429872089320b5003f7e9b8dbd"
}
```

### Sample 86: `f848d48b672649b5`

| Field | Value |
|---|---|
| SHA-256 | `f848d48b672649b5abfeb8479c364eea84c9314f9d2b6df5bfb323358a770eeb` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60f93ee4fe225b4eb785641c247f1656` |
| SHA-1 | `7a4d91ff10d12520ebe2596c75f8e6e10899e8ae` |
| SHA-256 | `f848d48b672649b5abfeb8479c364eea84c9314f9d2b6df5bfb323358a770eeb` |
| SHA3-384 | `def40112580d68e881341b47d6ab452b0f2cf02c0c7bc297b0a231b40f9decc0598ccd931273a879762cf4c231b19ae8` |
| TLSH | `T1E7E36C00B7080E33C0B76FB0153F1739A7EB558652B49506191EEB8E46B1E7267CADEE` |
| SSDEEP | `3072:yUSn4iH+XXw8xpHgiKN5YpC7G69zn5G0g12IZR6eq98VHYQbVJewWmoys/3fO3fy:vSnnH+XgKgiYYpC7GIn5IR45` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_f848d48b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f848d48b672649b5abfeb8479c364eea84c9314f9d2b6df5bfb323358a770eeb"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:22"
  condition:
    hash.sha256(0, filesize) == "f848d48b672649b5abfeb8479c364eea84c9314f9d2b6df5bfb323358a770eeb"
}
```

### Sample 87: `9d1191963bbb0196`

| Field | Value |
|---|---|
| SHA-256 | `9d1191963bbb019636e11380b258e815d1e3384a1d642ec1e22d7d87c3c4e3f0` |
| Family label | `unknown` |
| File name | `zk_bridge_mips_9002` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:20` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6121a7d59ce99db5e881d6ac720d6563` |
| SHA-1 | `2416d72133d91d25264b4eebe71da7bda77780bf` |
| SHA-256 | `9d1191963bbb019636e11380b258e815d1e3384a1d642ec1e22d7d87c3c4e3f0` |
| SHA3-384 | `2ad5cc65145f87d3cbafb5012341e4c7d539275fe4e6fe201585c1b66cf0eb0de310631b264c46bc2dd05221190069e5` |
| TLSH | `T12F515117FF404FAAC82E06B000EB474B179AC1D21242074BA76C93C7389A5E55DA2D99` |
| SSDEEP | `48:N1d9Q/BtkqmVnY27oKeztpcqFOBS/+NsipwdkMXx:Nu/BtkqmVY27o6/E+NsiphI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_9d119196
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d1191963bbb019636e11380b258e815d1e3384a1d642ec1e22d7d87c3c4e3f0"
    family = "unknown"
    file_name = "zk_bridge_mips_9002"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:20"
  condition:
    hash.sha256(0, filesize) == "9d1191963bbb019636e11380b258e815d1e3384a1d642ec1e22d7d87c3c4e3f0"
}
```

### Sample 88: `1b59e5e6b79e2fda`

| Field | Value |
|---|---|
| SHA-256 | `1b59e5e6b79e2fda9c2d7d8f112b4b600c2077d6929e29a419eb6edab11d3d3a` |
| Family label | `Mirai` |
| File name | `myc2-agent-linux-mipsle` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `010317c640ff599f5dcfecaa52bd9001` |
| SHA-1 | `78c5bae8e1d97337b0ee910fc182f0006f2f9b5a` |
| SHA-256 | `1b59e5e6b79e2fda9c2d7d8f112b4b600c2077d6929e29a419eb6edab11d3d3a` |
| SHA3-384 | `faf09b977ef23b584213165ed6fbc5eac8a4b7b54feceb3646a31970e18f79e71ab6faf784d09111d70c591c93fc11f1` |
| TLSH | `T1CD443A47EF880FCFCC6BCEB0476F435B1EE3959A49D1A1A9507C8C4C769D28A49D3688` |
| SSDEEP | `6144:7py7KPwDbcRMXZw9FmS2SI83nq+mRnH/Beeq:7pZB2jYq+yfQe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_1b59e5e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b59e5e6b79e2fda9c2d7d8f112b4b600c2077d6929e29a419eb6edab11d3d3a"
    family = "Mirai"
    file_name = "myc2-agent-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:17"
  condition:
    hash.sha256(0, filesize) == "1b59e5e6b79e2fda9c2d7d8f112b4b600c2077d6929e29a419eb6edab11d3d3a"
}
```

### Sample 89: `c075fc89daaa63bd`

| Field | Value |
|---|---|
| SHA-256 | `c075fc89daaa63bd0747993537fe26a766686f461cf5e05c90f437251a9209e3` |
| Family label | `unknown` |
| File name | `myc2-agent-linux-riscv32` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be7909059d515878b5a0edb79cc45c88` |
| SHA-1 | `b6e6e2fead53bff38607c2ad4c542677d6d7c1f2` |
| SHA-256 | `c075fc89daaa63bd0747993537fe26a766686f461cf5e05c90f437251a9209e3` |
| SHA3-384 | `81514b7f89d45b9214aaa17b5c7ab926c62eea3c7dea8caef077c4e1522eba5283f23fc4c8200cbb85450590389e759f` |
| TLSH | `T174B3E1F0B698795AC26343F164E00E424379BC278762B70D65EC7DB41E398BC5E89CE9` |
| SSDEEP | `3072:umO8ICxBTz0OAitREUlQ/UVyvtWCNVpemQNxYdJ:GLCzzAYBC/UMvtWCNVsmQNidJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_c075fc89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c075fc89daaa63bd0747993537fe26a766686f461cf5e05c90f437251a9209e3"
    family = "unknown"
    file_name = "myc2-agent-linux-riscv32"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:15"
  condition:
    hash.sha256(0, filesize) == "c075fc89daaa63bd0747993537fe26a766686f461cf5e05c90f437251a9209e3"
}
```

### Sample 90: `a798aae56cc763b5`

| Field | Value |
|---|---|
| SHA-256 | `a798aae56cc763b51af3504b0f51114fe6090127c7e75e7938251e7adf52966a` |
| Family label | `unknown` |
| File name | `myc2-preload-linux-sparc` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:12` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54817ec31c7edd2ebce49fa7c35267ab` |
| SHA-1 | `f4d18e1b87cbf82b2802981fad10eb4b06032865` |
| SHA-256 | `a798aae56cc763b51af3504b0f51114fe6090127c7e75e7938251e7adf52966a` |
| SHA3-384 | `320d2df96dea2c5dfb18f18f627b61a2b23f749a6b6d3274a5797b323f1f7d171d80cfdce7fd40d6bf416f933e1e527b` |
| TLSH | `T1C8127322E7967E67C8D41738E4EF0722333AAE54487893837758555B2E823107E3679A` |
| SSDEEP | `96:jUfBWBShu0oH1cP2FeInYHgOljB4ZVioU1IwQnZd4i:Q8chu9H1cP2FhnQBgiouU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_a798aae5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a798aae56cc763b51af3504b0f51114fe6090127c7e75e7938251e7adf52966a"
    family = "unknown"
    file_name = "myc2-preload-linux-sparc"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:12"
  condition:
    hash.sha256(0, filesize) == "a798aae56cc763b51af3504b0f51114fe6090127c7e75e7938251e7adf52966a"
}
```

### Sample 91: `c8583732602aec89`

| Field | Value |
|---|---|
| SHA-256 | `c8583732602aec896bcd8ee032e2fbc30a6419f4221581e20a400d3c723d24c7` |
| Family label | `Mirai` |
| File name | `Heyiwei-csky-gx3201` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efd95b52188716f5bc1d5eff9882f8b3` |
| SHA-1 | `f13794b14cbb0dc7a1451051279248cf3a10ddc7` |
| SHA-256 | `c8583732602aec896bcd8ee032e2fbc30a6419f4221581e20a400d3c723d24c7` |
| SHA3-384 | `ba84d8b81a3ddfd13bb610fa1c99fd7da95dc71b11762739789917ecd9bf4d5a92fbac660567c800a2619984473d6c8a` |
| TLSH | `T129C37CADB5A8538DE45293F78F407A14AE5F9EB03BB093ADBF0267029C10BB14F4565C` |
| SSDEEP | `3072:BZxrBHfb8SEOk+PyPFm0wyXaqcyeY06RfWG4XSNPnuA+m:BZ1B/bppDyPFmdyS6aCNnuE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_c8583732
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8583732602aec896bcd8ee032e2fbc30a6419f4221581e20a400d3c723d24c7"
    family = "Mirai"
    file_name = "Heyiwei-csky-gx3201"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:10"
  condition:
    hash.sha256(0, filesize) == "c8583732602aec896bcd8ee032e2fbc30a6419f4221581e20a400d3c723d24c7"
}
```

### Sample 92: `be6c883cdae60204`

| Field | Value |
|---|---|
| SHA-256 | `be6c883cdae6020464df420c34addb4eb1d3b02238457e7934eb4e695076663d` |
| Family label | `Mirai` |
| File name | `Heyiwei-csky-abiv1` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a5b8cff95f6c741d219e5d986b060cc` |
| SHA-1 | `408c411f0259aec2a9dc942ab79fc1649a6c60f3` |
| SHA-256 | `be6c883cdae6020464df420c34addb4eb1d3b02238457e7934eb4e695076663d` |
| SHA3-384 | `4d0e4222b35cb4f8b83f03986d47d0808114d1ae29a754122330d3715e37b06828e58d5b53019ff7c0c17a2177c0ce22` |
| TLSH | `T1D0E39DBCB88452DCD02E42FB5D5114152D59AFBC07705ABDEB8A7F218C842718FE9EAC` |
| SSDEEP | `3072:SID/QkIbj09Nkpe4faZqdkV4zmYUTGxNf7iIPjEKYI7q://QjAIg4faZq6VvYUYNf7iIPjEKDq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_be6c883c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be6c883cdae6020464df420c34addb4eb1d3b02238457e7934eb4e695076663d"
    family = "Mirai"
    file_name = "Heyiwei-csky-abiv1"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:07"
  condition:
    hash.sha256(0, filesize) == "be6c883cdae6020464df420c34addb4eb1d3b02238457e7934eb4e695076663d"
}
```

### Sample 93: `6ee6e28f2c5c4298`

| Field | Value |
|---|---|
| SHA-256 | `6ee6e28f2c5c42988fb33d7389ba5f94c9eb295f3c813506227d39f1eea1203d` |
| Family label | `unknown` |
| File name | `zk_bridge_mips_tcp_9003` |
| File type | `elf` |
| First seen | `2026-11-21 06:59:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7042c52c37bcaa87407924fc75193d98` |
| SHA-1 | `8e07f9944896fad289c4523cf70a261217fc975f` |
| SHA-256 | `6ee6e28f2c5c42988fb33d7389ba5f94c9eb295f3c813506227d39f1eea1203d` |
| SHA3-384 | `68a5924536e6ebf115a08630f36b1860a003eccd95223803cd6026dc553339ced35497964091add851468ff91742419f` |
| TLSH | `T16351863F7B20AE5FCC4D45304A7F82672767D45412D7412FA12C99890EA3AD598938EC` |
| SSDEEP | `48:uRoPbal0Ybv1RhXr/H7u+k7w7RgzapQyTk9mYpw/NZysiCmwdDrD:uyaiYbv3hbzu/w7RgzIwYhNZysiCmWf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_6ee6e28f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee6e28f2c5c42988fb33d7389ba5f94c9eb295f3c813506227d39f1eea1203d"
    family = "unknown"
    file_name = "zk_bridge_mips_tcp_9003"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:04"
  condition:
    hash.sha256(0, filesize) == "6ee6e28f2c5c42988fb33d7389ba5f94c9eb295f3c813506227d39f1eea1203d"
}
```

### Sample 94: `3f5080473eb31a2d`

| Field | Value |
|---|---|
| SHA-256 | `3f5080473eb31a2d6b9e01722ad4e81e345266c2164153d2e4149e5162c2120e` |
| Family label | `unknown` |
| File name | `easyshell-l64-3f5080473eb31a2d.bin` |
| File type | `elf` |
| First seen | `2026-11-21 06:07:20` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6c2345235e7a0d41bbdd7c27c3239e5` |
| SHA-1 | `3fb2e06edef92f9424bc46930fa0b790cd494291` |
| SHA-256 | `3f5080473eb31a2d6b9e01722ad4e81e345266c2164153d2e4149e5162c2120e` |
| SHA3-384 | `f2aa28328c3fd9710e9fd16dca93e9b7949aca41f6d308d83f5af05094e591aeb21975b0d4917ff21831adc5eae71a28` |
| TLSH | `T161267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiyH8hIU6iKHh:OYjiiKgib9qRGcEulycW+gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_3f508047
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f5080473eb31a2d6b9e01722ad4e81e345266c2164153d2e4149e5162c2120e"
    family = "unknown"
    file_name = "easyshell-l64-3f5080473eb31a2d.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:07:20"
  condition:
    hash.sha256(0, filesize) == "3f5080473eb31a2d6b9e01722ad4e81e345266c2164153d2e4149e5162c2120e"
}
```

### Sample 95: `3fa0f8c7618ee2f2`

| Field | Value |
|---|---|
| SHA-256 | `3fa0f8c7618ee2f2445fe1dc065cdc3c035240205f6ca62d2017e0894f756b5f` |
| Family label | `unknown` |
| File name | `easyshell-l32-3fa0f8c7618ee2f2.bin` |
| File type | `elf` |
| First seen | `2026-11-21 06:07:09` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dec43354357f09140163dc984b19974c` |
| SHA-1 | `40534a9d6b42e2c398d5e1530cefcbad001aad93` |
| SHA-256 | `3fa0f8c7618ee2f2445fe1dc065cdc3c035240205f6ca62d2017e0894f756b5f` |
| SHA3-384 | `14816020dc5c6632210413e7a1d216f277a8b8bf42b1b30001a58264b1f63f09b05720300ce6c58c80736c717955e75d` |
| TLSH | `T1BB068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1vF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1vdb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_3fa0f8c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa0f8c7618ee2f2445fe1dc065cdc3c035240205f6ca62d2017e0894f756b5f"
    family = "unknown"
    file_name = "easyshell-l32-3fa0f8c7618ee2f2.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:07:09"
  condition:
    hash.sha256(0, filesize) == "3fa0f8c7618ee2f2445fe1dc065cdc3c035240205f6ca62d2017e0894f756b5f"
}
```

### Sample 96: `9c0c05ccc57cc2d3`

| Field | Value |
|---|---|
| SHA-256 | `9c0c05ccc57cc2d3b5b4a03ee436f3ee035262a860527637532fcd655abdb697` |
| Family label | `unknown` |
| File name | `easyshell-l128-9c0c05ccc57cc2d3.bin` |
| File type | `elf` |
| First seen | `2026-11-21 06:07:00` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bd0f105e3e1b9b2cab94e3c7307c579` |
| SHA-1 | `0e806d07eb2697aa9ebe57109d67bbb327a3a242` |
| SHA-256 | `9c0c05ccc57cc2d3b5b4a03ee436f3ee035262a860527637532fcd655abdb697` |
| SHA3-384 | `9a134910ca3b84388befc1bcae3f4b15ba0d02507a42ba61e4dd19ea8e030dacf50e4d98ef95db61f19563000cf9c3bd` |
| TLSH | `T1AE067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1Ci:FUkCxwUGnaPdX8P3AS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_9c0c05cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c0c05ccc57cc2d3b5b4a03ee436f3ee035262a860527637532fcd655abdb697"
    family = "unknown"
    file_name = "easyshell-l128-9c0c05ccc57cc2d3.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:07:00"
  condition:
    hash.sha256(0, filesize) == "9c0c05ccc57cc2d3b5b4a03ee436f3ee035262a860527637532fcd655abdb697"
}
```

### Sample 97: `daf52a4e4b498469`

| Field | Value |
|---|---|
| SHA-256 | `daf52a4e4b498469c2181ca1868248964b0a4e1054dd603a4625155335ed2bf9` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-daf52a4e4b498469.bin` |
| File type | `macho` |
| First seen | `2026-11-21 06:06:49` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a4025b2014f50202f8418c5fd1e2a3c` |
| SHA-1 | `10857ec188976e1066bb1340473deb6ce59b2350` |
| SHA-256 | `daf52a4e4b498469c2181ca1868248964b0a4e1054dd603a4625155335ed2bf9` |
| SHA3-384 | `70db13f4eb3e8ed07a34c3a5e64d7b9b63f294caea8effb7b2ddfc038720718c9fb0c562170c2582092d7e9ccb0139df` |
| TLSH | `T11DF5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tg/sj5g5FIU6icBV8GQU5NZm+lzF:8SeI1gkkvTg/t5C+OGU5NZm+lzF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_daf52a4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daf52a4e4b498469c2181ca1868248964b0a4e1054dd603a4625155335ed2bf9"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-daf52a4e4b498469.bin"
    file_type = "macho"
    first_seen = "2026-11-21 06:06:49"
  condition:
    hash.sha256(0, filesize) == "daf52a4e4b498469c2181ca1868248964b0a4e1054dd603a4625155335ed2bf9"
}
```

### Sample 98: `b23a97f6969cce8b`

| Field | Value |
|---|---|
| SHA-256 | `b23a97f6969cce8bf4c5faeb1cd386ee22525bd99af1d6a62365121aa45f154b` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-b23a97f6969cce8b.bin` |
| File type | `macho` |
| First seen | `2026-11-21 06:06:41` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7c3e910e4b0bff22cdc04a05e18cc16` |
| SHA-1 | `4398bf547f2f8ab33e11aed1e5760672e169d07d` |
| SHA-256 | `b23a97f6969cce8bf4c5faeb1cd386ee22525bd99af1d6a62365121aa45f154b` |
| SHA3-384 | `db9fb3e7017fb64f86ca7f51fc8be0fedf86473ae42a06f009604ef791d98cbb12c132c4094c01b92dfbfdb096dca9ad` |
| TLSH | `T132168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6jKhx+wgbZmBlzvX:kyLbLNomEr6jKj7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_b23a97f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b23a97f6969cce8bf4c5faeb1cd386ee22525bd99af1d6a62365121aa45f154b"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-b23a97f6969cce8b.bin"
    file_type = "macho"
    first_seen = "2026-11-21 06:06:41"
  condition:
    hash.sha256(0, filesize) == "b23a97f6969cce8bf4c5faeb1cd386ee22525bd99af1d6a62365121aa45f154b"
}
```

### Sample 99: `6730470ecc68b21c`

| Field | Value |
|---|---|
| SHA-256 | `6730470ecc68b21cd5aea84398e369100e5f93d51c4d431ddca655dcd4abe3bc` |
| Family label | `unknown` |
| File name | `easyshell-a64-6730470ecc68b21c.bin` |
| File type | `elf` |
| First seen | `2026-11-21 06:06:30` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `939857e9c462d042027ba992e6852727` |
| SHA-1 | `d627f5ef6f748908d58cd36ef1b4d127d4693560` |
| SHA-256 | `6730470ecc68b21cd5aea84398e369100e5f93d51c4d431ddca655dcd4abe3bc` |
| SHA3-384 | `c3ec8f6b570a0400ba65be69c3cdc32014a2c51de8d064e6d1dbdb477b1727898b0bd7c0e9c0eb79bb498cc91f5edfc4` |
| TLSH | `T1D706B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WTGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WTLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_6730470e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6730470ecc68b21cd5aea84398e369100e5f93d51c4d431ddca655dcd4abe3bc"
    family = "unknown"
    file_name = "easyshell-a64-6730470ecc68b21c.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:06:30"
  condition:
    hash.sha256(0, filesize) == "6730470ecc68b21cd5aea84398e369100e5f93d51c4d431ddca655dcd4abe3bc"
}
```

### Sample 100: `11f92911072b19b1`

| Field | Value |
|---|---|
| SHA-256 | `11f92911072b19b1687414f6846191d97370ad52172dcc0bef063e79a783d6ed` |
| Family label | `unknown` |
| File name | `easyshell-a32-11f92911072b19b1.bin` |
| File type | `elf` |
| First seen | `2026-11-21 06:06:22` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaec03a265f34138367a1984c8a1ece5` |
| SHA-1 | `4c1d798b6acc3869896dfec0290318b56d64563a` |
| SHA-256 | `11f92911072b19b1687414f6846191d97370ad52172dcc0bef063e79a783d6ed` |
| SHA3-384 | `768e576387e4473cda6d3f89a5f0ecf66b028fed93b90573a18f8993022cc8376928b5ba755ecdf83ba5d28a19f64955` |
| TLSH | `T180F53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBZ:FhvZpiEGUx+pVdq42laB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_11f92911
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f92911072b19b1687414f6846191d97370ad52172dcc0bef063e79a783d6ed"
    family = "unknown"
    file_name = "easyshell-a32-11f92911072b19b1.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:06:22"
  condition:
    hash.sha256(0, filesize) == "11f92911072b19b1687414f6846191d97370ad52172dcc0bef063e79a783d6ed"
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
 * Generated: 2026-11-21T07:23:11.383660+00:00
 */

rule MalwareBazaar_unknown_001_c767ea74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c767ea74ed7921a8c8e68ac66a143c4fd67b54884b4a0b10898a76fca418c36a"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-21 07:11:28"
  condition:
    hash.sha256(0, filesize) == "c767ea74ed7921a8c8e68ac66a143c4fd67b54884b4a0b10898a76fca418c36a"
}

rule MalwareBazaar_unknown_002_832ad502
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "832ad50276a88526977ebf7a4d74333fb2dfd1cd875def573aa7dce8828399c1"
    family = "unknown"
    file_name = "easyshell-l64-832ad50276a88526.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:06:43"
  condition:
    hash.sha256(0, filesize) == "832ad50276a88526977ebf7a4d74333fb2dfd1cd875def573aa7dce8828399c1"
}

rule MalwareBazaar_unknown_003_ea2a0349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea2a034979d021746346218c75a41f5ac5cd5dea93ed756698a6edfe5a04d66f"
    family = "unknown"
    file_name = "easyshell-l32-ea2a034979d02174.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:06:34"
  condition:
    hash.sha256(0, filesize) == "ea2a034979d021746346218c75a41f5ac5cd5dea93ed756698a6edfe5a04d66f"
}

rule MalwareBazaar_unknown_004_d4c8ec37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4c8ec37ca836f0f01d1c1e1f34f549a37a09a251538f6e56a99cadc37e496fc"
    family = "unknown"
    file_name = "easyshell-l128-d4c8ec37ca836f0f.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:06:25"
  condition:
    hash.sha256(0, filesize) == "d4c8ec37ca836f0f01d1c1e1f34f549a37a09a251538f6e56a99cadc37e496fc"
}

rule MalwareBazaar_unknown_005_1467a958
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1467a95824a3ea48eadc43ca152218af2f6d2ef9880f391a1f7add91450bff1e"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-1467a95824a3ea48.bin"
    file_type = "macho"
    first_seen = "2026-11-21 07:06:17"
  condition:
    hash.sha256(0, filesize) == "1467a95824a3ea48eadc43ca152218af2f6d2ef9880f391a1f7add91450bff1e"
}

rule MalwareBazaar_unknown_006_e6c49547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6c4954796b5efee464583ac52fad6b03e19d2d9792e960ecbcf1bfcc7635f59"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-e6c4954796b5efee.bin"
    file_type = "macho"
    first_seen = "2026-11-21 07:06:09"
  condition:
    hash.sha256(0, filesize) == "e6c4954796b5efee464583ac52fad6b03e19d2d9792e960ecbcf1bfcc7635f59"
}

rule MalwareBazaar_unknown_007_d4ec31ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4ec31ed44698baae338d55ba1ed0f45ba959b1d84a1ff17ca1dbdc5ba439f3a"
    family = "unknown"
    file_name = "easyshell-a64-d4ec31ed44698baa.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:06:00"
  condition:
    hash.sha256(0, filesize) == "d4ec31ed44698baae338d55ba1ed0f45ba959b1d84a1ff17ca1dbdc5ba439f3a"
}

rule MalwareBazaar_unknown_008_93607de7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93607de77b347997b832aac3f8bffd33e71846981eb293d29d6c03b352b99677"
    family = "unknown"
    file_name = "easyshell-a32-93607de77b347997.bin"
    file_type = "elf"
    first_seen = "2026-11-21 07:05:52"
  condition:
    hash.sha256(0, filesize) == "93607de77b347997b832aac3f8bffd33e71846981eb293d29d6c03b352b99677"
}

rule MalwareBazaar_Mirai_009_462bf4dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "462bf4dcddd8e8d8c3d6393d3ed95dbf99617cec2cc7db25c80b87c789fb27f3"
    family = "Mirai"
    file_name = "main_arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:03:09"
  condition:
    hash.sha256(0, filesize) == "462bf4dcddd8e8d8c3d6393d3ed95dbf99617cec2cc7db25c80b87c789fb27f3"
}

rule MalwareBazaar_unknown_010_07bddf24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07bddf244fd8068f2918c47a269b9ffcc9c696c0b838456c5c6ef370c3882a09"
    family = "unknown"
    file_name = "myc2-agent-linux-armv7"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:58"
  condition:
    hash.sha256(0, filesize) == "07bddf244fd8068f2918c47a269b9ffcc9c696c0b838456c5c6ef370c3882a09"
}

rule MalwareBazaar_Mirai_011_795245a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "795245a2ceaa0d59a9a78e8672c97447a9cb14bf82a31872b85b00fb8a07ed47"
    family = "Mirai"
    file_name = "hn101.b"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:55"
  condition:
    hash.sha256(0, filesize) == "795245a2ceaa0d59a9a78e8672c97447a9cb14bf82a31872b85b00fb8a07ed47"
}

rule MalwareBazaar_unknown_012_bfb5f607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfb5f607f970408e564af51c976a31889c6ec278abf53852b26d1f02733d0f03"
    family = "unknown"
    file_name = "myc2-preload-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:52"
  condition:
    hash.sha256(0, filesize) == "bfb5f607f970408e564af51c976a31889c6ec278abf53852b26d1f02733d0f03"
}

rule MalwareBazaar_unknown_013_687a3594
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "687a3594d494be74a730d14772d1939577f90ba4267423128bdf7fb5cbb857f3"
    family = "unknown"
    file_name = "myc2-agent-linux-riscv64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:49"
  condition:
    hash.sha256(0, filesize) == "687a3594d494be74a730d14772d1939577f90ba4267423128bdf7fb5cbb857f3"
}

rule MalwareBazaar_unknown_014_17d704b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17d704b734a57f82150ad0ee9fb9d394026acd9bb7d2851b102e6b24721ea3d7"
    family = "unknown"
    file_name = "cnc-linux-arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:45"
  condition:
    hash.sha256(0, filesize) == "17d704b734a57f82150ad0ee9fb9d394026acd9bb7d2851b102e6b24721ea3d7"
}

rule MalwareBazaar_unknown_015_7d365030
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d365030af1e49f7de82f9e6ab9629efd0fc38b69b8ef85abe24901f7dddac9e"
    family = "unknown"
    file_name = "myc2-killer-linux-m68k"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:42"
  condition:
    hash.sha256(0, filesize) == "7d365030af1e49f7de82f9e6ab9629efd0fc38b69b8ef85abe24901f7dddac9e"
}

rule MalwareBazaar_Mirai_016_9652f77e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9652f77e939c9c932ba3fb8b1ba71c58e82933d5264d36b8f03e74e648ce1ee9"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:40"
  condition:
    hash.sha256(0, filesize) == "9652f77e939c9c932ba3fb8b1ba71c58e82933d5264d36b8f03e74e648ce1ee9"
}

rule MalwareBazaar_Mirai_017_6fbe7263
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fbe726366d26259527bf29dcce9f1c0476151928bef609cff2b992e82635009"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:37"
  condition:
    hash.sha256(0, filesize) == "6fbe726366d26259527bf29dcce9f1c0476151928bef609cff2b992e82635009"
}

rule MalwareBazaar_unknown_018_cc82557d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc82557d7b782b4f49e2548b9d23922a0427640a3e21ffb52c84fa1679a8ba3f"
    family = "unknown"
    file_name = "myc2-shell-linux-arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:35"
  condition:
    hash.sha256(0, filesize) == "cc82557d7b782b4f49e2548b9d23922a0427640a3e21ffb52c84fa1679a8ba3f"
}

rule MalwareBazaar_unknown_019_50c399cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50c399cf00a83be3614b6f111669c0d1f041b9ae0e28fba42d029258a481ead4"
    family = "unknown"
    file_name = "myc2-agent-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:32"
  condition:
    hash.sha256(0, filesize) == "50c399cf00a83be3614b6f111669c0d1f041b9ae0e28fba42d029258a481ead4"
}

rule MalwareBazaar_unknown_020_40bdd8b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40bdd8b2870b81d6585ddc83e83073f9b4e7b10f7bc0b2d77c29f429bf7791f9"
    family = "unknown"
    file_name = "myc2-shell-linux-ppc64le"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:29"
  condition:
    hash.sha256(0, filesize) == "40bdd8b2870b81d6585ddc83e83073f9b4e7b10f7bc0b2d77c29f429bf7791f9"
}

rule MalwareBazaar_unknown_021_7fec1535
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fec1535a6530617d8b5976a5aec59469d90a25b21481f027187d7ed1c732a39"
    family = "unknown"
    file_name = "myc2-shell-linux-mips64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:26"
  condition:
    hash.sha256(0, filesize) == "7fec1535a6530617d8b5976a5aec59469d90a25b21481f027187d7ed1c732a39"
}

rule MalwareBazaar_unknown_022_e47984f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e47984f2543c3ea22ce0072c503f9c624bc217cb2828f0552b60f9cf28997f99"
    family = "unknown"
    file_name = "myc2-shell-linux-386"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:23"
  condition:
    hash.sha256(0, filesize) == "e47984f2543c3ea22ce0072c503f9c624bc217cb2828f0552b60f9cf28997f99"
}

rule MalwareBazaar_unknown_023_827ddff9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "827ddff9799015e49d09c0244aab4551826b1195c00e43231197d0213ddb5053"
    family = "unknown"
    file_name = "myc2-killer-linux-ppc"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:20"
  condition:
    hash.sha256(0, filesize) == "827ddff9799015e49d09c0244aab4551826b1195c00e43231197d0213ddb5053"
}

rule MalwareBazaar_unknown_024_1e04b483
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e04b4833c10e94cbf6dbb005b7748511f0b9d3abbfa0d595bd341cbfa9d6397"
    family = "unknown"
    file_name = "myc2-preload-linux-m68k"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:18"
  condition:
    hash.sha256(0, filesize) == "1e04b4833c10e94cbf6dbb005b7748511f0b9d3abbfa0d595bd341cbfa9d6397"
}

rule MalwareBazaar_unknown_025_c89b971c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c89b971c7ba9962a3ed1e1011746caeab2fbeb52671dc8139045a68760b3c6a5"
    family = "unknown"
    file_name = "myc2-agent-linux-ppc64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:15"
  condition:
    hash.sha256(0, filesize) == "c89b971c7ba9962a3ed1e1011746caeab2fbeb52671dc8139045a68760b3c6a5"
}

rule MalwareBazaar_Mirai_026_82cc862a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82cc862a4633f65c707fe09c311111d80fa9072a39e82db8d34b97f68f7b8ab1"
    family = "Mirai"
    file_name = "bot.arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:12"
  condition:
    hash.sha256(0, filesize) == "82cc862a4633f65c707fe09c311111d80fa9072a39e82db8d34b97f68f7b8ab1"
}

rule MalwareBazaar_unknown_027_9689934f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9689934f15901d3bd2d9139cde12dd46a74e13e7b3aafd4ba37fea66e6589462"
    family = "unknown"
    file_name = "myc2-agent-linux-ppc64le"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:09"
  condition:
    hash.sha256(0, filesize) == "9689934f15901d3bd2d9139cde12dd46a74e13e7b3aafd4ba37fea66e6589462"
}

rule MalwareBazaar_Mirai_028_7a9070da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a9070da36b51c610b5232c661bbebc6f7d5a0b3b2f7fae5f975894cdf1a7f83"
    family = "Mirai"
    file_name = "myc2-agent-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:05"
  condition:
    hash.sha256(0, filesize) == "7a9070da36b51c610b5232c661bbebc6f7d5a0b3b2f7fae5f975894cdf1a7f83"
}

rule MalwareBazaar_Mirai_029_4f816a21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f816a214c466eb5cef1e53c0904a9b703d2eedd82b8958c8f424118b28f675e"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:03"
  condition:
    hash.sha256(0, filesize) == "4f816a214c466eb5cef1e53c0904a9b703d2eedd82b8958c8f424118b28f675e"
}

rule MalwareBazaar_Gafgyt_030_841bdbfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "841bdbfe6611bd8b42d60f9ff73b9d849ed1dce96d19517d2ec4376842d4621d"
    family = "Gafgyt"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-11-21 07:02:00"
  condition:
    hash.sha256(0, filesize) == "841bdbfe6611bd8b42d60f9ff73b9d849ed1dce96d19517d2ec4376842d4621d"
}

rule MalwareBazaar_unknown_031_910b7f87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "910b7f870e7a54de9be8881e42be1619655c7275ec5cf0503254777e9ce2b4a3"
    family = "unknown"
    file_name = "myc2-preload-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:58"
  condition:
    hash.sha256(0, filesize) == "910b7f870e7a54de9be8881e42be1619655c7275ec5cf0503254777e9ce2b4a3"
}

rule MalwareBazaar_unknown_032_238775f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "238775f192864991a92f964b1d7bcd7a5384d9cc874fdf19e7b31d547606df41"
    family = "unknown"
    file_name = "myc2-preload-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:55"
  condition:
    hash.sha256(0, filesize) == "238775f192864991a92f964b1d7bcd7a5384d9cc874fdf19e7b31d547606df41"
}

rule MalwareBazaar_Mirai_033_2d6af5fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d6af5fc7d81127ba730d45795e131846217fb536bf1c06b207627c996d96267"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:53"
  condition:
    hash.sha256(0, filesize) == "2d6af5fc7d81127ba730d45795e131846217fb536bf1c06b207627c996d96267"
}

rule MalwareBazaar_unknown_034_4609a599
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4609a5993fd2b8e61ced40d4321ef058c289db91232ad317639a016523fd409c"
    family = "unknown"
    file_name = "myc2-agent-linux-arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:50"
  condition:
    hash.sha256(0, filesize) == "4609a5993fd2b8e61ced40d4321ef058c289db91232ad317639a016523fd409c"
}

rule MalwareBazaar_unknown_035_abb17282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb17282e3234a14bde204a4587c58477a88434c1157ee857b425223a65cca85"
    family = "unknown"
    file_name = "myc2-agent-linux-armv6"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:46"
  condition:
    hash.sha256(0, filesize) == "abb17282e3234a14bde204a4587c58477a88434c1157ee857b425223a65cca85"
}

rule MalwareBazaar_Mirai_036_ecfd5818
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecfd5818eba98cf3ccc5a22ba5b9744961d9de9a3fa22648aef90a353232728e"
    family = "Mirai"
    file_name = "myc2-killer-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:43"
  condition:
    hash.sha256(0, filesize) == "ecfd5818eba98cf3ccc5a22ba5b9744961d9de9a3fa22648aef90a353232728e"
}

rule MalwareBazaar_unknown_037_dfd84f15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfd84f1540ff5b349de6cd358c5ff5d8ce1f2e747527945b65ddfbf5956fa324"
    family = "unknown"
    file_name = "myc2-shell-linux-armv5"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:41"
  condition:
    hash.sha256(0, filesize) == "dfd84f1540ff5b349de6cd358c5ff5d8ce1f2e747527945b65ddfbf5956fa324"
}

rule MalwareBazaar_Mirai_038_8cfa1ceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cfa1ceb515c01f8a0f7310d4697e9544903fdbe6bf077b503fd366fa5603887"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:38"
  condition:
    hash.sha256(0, filesize) == "8cfa1ceb515c01f8a0f7310d4697e9544903fdbe6bf077b503fd366fa5603887"
}

rule MalwareBazaar_Mirai_039_7781a462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7781a462ab51c7d6dcc6b35aba066f1551271f656e6e9e6c3b057dd58d11a7eb"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:35"
  condition:
    hash.sha256(0, filesize) == "7781a462ab51c7d6dcc6b35aba066f1551271f656e6e9e6c3b057dd58d11a7eb"
}

rule MalwareBazaar_unknown_040_26833291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "268332911cbfc970c5ded5dc5f085b1e4a1f5bc151e4427bd2261f4d90d7aa2d"
    family = "unknown"
    file_name = "myc2-agent-linux-ppc"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:33"
  condition:
    hash.sha256(0, filesize) == "268332911cbfc970c5ded5dc5f085b1e4a1f5bc151e4427bd2261f4d90d7aa2d"
}

rule MalwareBazaar_unknown_041_87576b2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87576b2e25086edfc60edc3e0e843ec11e708fb029d70ca6d9cfb351c997f9e4"
    family = "unknown"
    file_name = "myc2-agent-linux-mips-softfloat"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:30"
  condition:
    hash.sha256(0, filesize) == "87576b2e25086edfc60edc3e0e843ec11e708fb029d70ca6d9cfb351c997f9e4"
}

rule MalwareBazaar_Mirai_042_d74aed92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d74aed92c29d88a45c2909631ccf3b8a1fb415be1514a53bc17d8d9b34eaab28"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:27"
  condition:
    hash.sha256(0, filesize) == "d74aed92c29d88a45c2909631ccf3b8a1fb415be1514a53bc17d8d9b34eaab28"
}

rule MalwareBazaar_unknown_043_47d114f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47d114f176a5b7387880473e5449b0868b27d5e5c0dee2042710990428302ecf"
    family = "unknown"
    file_name = "myc2-shell-linux-armv6"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:24"
  condition:
    hash.sha256(0, filesize) == "47d114f176a5b7387880473e5449b0868b27d5e5c0dee2042710990428302ecf"
}

rule MalwareBazaar_unknown_044_6ba62337
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ba62337402b6ab19ab5e6b1334a4e429c629e800f008cde4a33f345e54ae7bc"
    family = "unknown"
    file_name = "myc2-dlr-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:21"
  condition:
    hash.sha256(0, filesize) == "6ba62337402b6ab19ab5e6b1334a4e429c629e800f008cde4a33f345e54ae7bc"
}

rule MalwareBazaar_Mirai_045_1ca85b50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ca85b500dcf8c3ca194d848ad4091489a06a6234c487ec7f278b98dbcfef0b0"
    family = "Mirai"
    file_name = "main_riscv"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:19"
  condition:
    hash.sha256(0, filesize) == "1ca85b500dcf8c3ca194d848ad4091489a06a6234c487ec7f278b98dbcfef0b0"
}

rule MalwareBazaar_Mirai_046_eaa7d550
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaa7d55098d150404770936ccd83b351542936f029c994122c27f82099d033ac"
    family = "Mirai"
    file_name = "myc2-killer-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:16"
  condition:
    hash.sha256(0, filesize) == "eaa7d55098d150404770936ccd83b351542936f029c994122c27f82099d033ac"
}

rule MalwareBazaar_unknown_047_21530b20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21530b2038e60e57fd9a07a1c80bccee7319823912895377a44302be135fd218"
    family = "unknown"
    file_name = "myc2-shell-linux-ppc64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:14"
  condition:
    hash.sha256(0, filesize) == "21530b2038e60e57fd9a07a1c80bccee7319823912895377a44302be135fd218"
}

rule MalwareBazaar_Mirai_048_0a6eb94b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a6eb94b51584ac484bc4f01fdbf70a32e684ce62655707eb8babc31ae33ec32"
    family = "Mirai"
    file_name = "myc2-killer-linux-sparc"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:11"
  condition:
    hash.sha256(0, filesize) == "0a6eb94b51584ac484bc4f01fdbf70a32e684ce62655707eb8babc31ae33ec32"
}

rule MalwareBazaar_unknown_049_c44cf5a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c44cf5a3c37399ee6bddeb20541b7b3ead578e4c6f14baa531b076649c2e544c"
    family = "unknown"
    file_name = "scanner-linux-arm64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:09"
  condition:
    hash.sha256(0, filesize) == "c44cf5a3c37399ee6bddeb20541b7b3ead578e4c6f14baa531b076649c2e544c"
}

rule MalwareBazaar_Mirai_050_86faf2c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86faf2c79eac2d2aa4a432089e79f41704431232e22ef94ec43586fe6fed90ba"
    family = "Mirai"
    file_name = "myc2-agent-linux-sparc"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:06"
  condition:
    hash.sha256(0, filesize) == "86faf2c79eac2d2aa4a432089e79f41704431232e22ef94ec43586fe6fed90ba"
}

rule MalwareBazaar_Mirai_051_6beeeac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6beeeac76a58ffc01df26aba423eccb66a9bb3cdc2c8c370c2b3d42daf97ccad"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:03"
  condition:
    hash.sha256(0, filesize) == "6beeeac76a58ffc01df26aba423eccb66a9bb3cdc2c8c370c2b3d42daf97ccad"
}

rule MalwareBazaar_unknown_052_800a41b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "800a41b40b8d462071e333652dcc452b8b248a2c3cea28f7cc68ddb7e3f8a165"
    family = "unknown"
    file_name = "myc2-shell-linux-riscv64"
    file_type = "elf"
    first_seen = "2026-11-21 07:01:01"
  condition:
    hash.sha256(0, filesize) == "800a41b40b8d462071e333652dcc452b8b248a2c3cea28f7cc68ddb7e3f8a165"
}

rule MalwareBazaar_unknown_053_436c31e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "436c31e78af95e7a582aa7813fb54d798cf9fae9d8a5f07bafa46993ff0bf0cd"
    family = "unknown"
    file_name = "myc2-agent-linux-mips64"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:58"
  condition:
    hash.sha256(0, filesize) == "436c31e78af95e7a582aa7813fb54d798cf9fae9d8a5f07bafa46993ff0bf0cd"
}

rule MalwareBazaar_unknown_054_5174bf92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5174bf924761e7c62c61d1dcbfe398a1c8315ac924778a7f1aa529caa28ae8cc"
    family = "unknown"
    file_name = "myc2-agent-linux-m68k"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:54"
  condition:
    hash.sha256(0, filesize) == "5174bf924761e7c62c61d1dcbfe398a1c8315ac924778a7f1aa529caa28ae8cc"
}

rule MalwareBazaar_Mirai_055_0883c4ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0883c4ecf76185e79619d7d9a16ffc39212f963c33b14e43e63d278399cd7501"
    family = "Mirai"
    file_name = "loader.x86_64"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:51"
  condition:
    hash.sha256(0, filesize) == "0883c4ecf76185e79619d7d9a16ffc39212f963c33b14e43e63d278399cd7501"
}

rule MalwareBazaar_unknown_056_bbff751f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbff751f3ab13eb48a95f9be771e747a4e9e81b3ec17b1c3d93538b1ea02b869"
    family = "unknown"
    file_name = "myc2-shell-linux-armv7"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:48"
  condition:
    hash.sha256(0, filesize) == "bbff751f3ab13eb48a95f9be771e747a4e9e81b3ec17b1c3d93538b1ea02b869"
}

rule MalwareBazaar_unknown_057_ab87f24e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab87f24e09e8b1428f3d4a6b995387b4d4f994d1de3c93a095782b00e8c109e3"
    family = "unknown"
    file_name = "llcp-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:45"
  condition:
    hash.sha256(0, filesize) == "ab87f24e09e8b1428f3d4a6b995387b4d4f994d1de3c93a095782b00e8c109e3"
}

rule MalwareBazaar_unknown_058_98ac0ba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98ac0ba82d65964691097fe7d0f4a96175425f44fcdd5c6d211377ca88ce4e0b"
    family = "unknown"
    file_name = "zk_bridge_mips_9004"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:42"
  condition:
    hash.sha256(0, filesize) == "98ac0ba82d65964691097fe7d0f4a96175425f44fcdd5c6d211377ca88ce4e0b"
}

rule MalwareBazaar_unknown_059_21f20941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21f209415c23ae83ce7e74b8d711f7b7f9f01b7fc0a7c3c24f94c93ab51c958d"
    family = "unknown"
    file_name = "myc2-agent-linux-mipsle-softfloat"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:40"
  condition:
    hash.sha256(0, filesize) == "21f209415c23ae83ce7e74b8d711f7b7f9f01b7fc0a7c3c24f94c93ab51c958d"
}

rule MalwareBazaar_unknown_060_2153ccb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2153ccb713bd5df077c8ff530eafe2f473a0470b5c98c0301da7a3c41b8478e9"
    family = "unknown"
    file_name = "myc2-preload-linux-riscv32"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:36"
  condition:
    hash.sha256(0, filesize) == "2153ccb713bd5df077c8ff530eafe2f473a0470b5c98c0301da7a3c41b8478e9"
}

rule MalwareBazaar_unknown_061_d64b93bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d64b93bb6917326ec993b3cc398ed1259d64dcbf65e5dc23f53f2ae8b8350fd9"
    family = "unknown"
    file_name = "myc2-agent-linux-armv5"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:33"
  condition:
    hash.sha256(0, filesize) == "d64b93bb6917326ec993b3cc398ed1259d64dcbf65e5dc23f53f2ae8b8350fd9"
}

rule MalwareBazaar_unknown_062_8a825a6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a825a6bddfe0a699000cd2bb9d62fd9cf13e62eb385e0d58d1feb64ee37b491"
    family = "unknown"
    file_name = "myc2-shell-linux-mips64le"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:29"
  condition:
    hash.sha256(0, filesize) == "8a825a6bddfe0a699000cd2bb9d62fd9cf13e62eb385e0d58d1feb64ee37b491"
}

rule MalwareBazaar_Mirai_063_c026c274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c026c274bf6b34e86aa6fec4926343daf74cbecd61a0282ee7f374eb8a40abd3"
    family = "Mirai"
    file_name = "myc2-killer-linux-arc"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:26"
  condition:
    hash.sha256(0, filesize) == "c026c274bf6b34e86aa6fec4926343daf74cbecd61a0282ee7f374eb8a40abd3"
}

rule MalwareBazaar_Mirai_064_07f67717
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f67717e4a1edaf37a20893597dd26e4dc1d84b4de814736c2c4365081649e5"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:24"
  condition:
    hash.sha256(0, filesize) == "07f67717e4a1edaf37a20893597dd26e4dc1d84b4de814736c2c4365081649e5"
}

rule MalwareBazaar_unknown_065_2d69394f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d69394f8b2cf8304b98bc7f1b38e6f413195c80a6c680097b4cbfad521935e5"
    family = "unknown"
    file_name = "myc2-agent-linux-mips64le"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:21"
  condition:
    hash.sha256(0, filesize) == "2d69394f8b2cf8304b98bc7f1b38e6f413195c80a6c680097b4cbfad521935e5"
}

rule MalwareBazaar_unknown_066_3357e4bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3357e4bfb3c8b408b2b4f6eaaf66b917b437f070e27b4c0ae444ca6b1f70dcb9"
    family = "unknown"
    file_name = "myc2-agent-linux-386"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:17"
  condition:
    hash.sha256(0, filesize) == "3357e4bfb3c8b408b2b4f6eaaf66b917b437f070e27b4c0ae444ca6b1f70dcb9"
}

rule MalwareBazaar_Mirai_067_79267be4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79267be4e49498c346d039e8e873b53e585df61eb9ab13a7a06873d2582daf4d"
    family = "Mirai"
    file_name = "myc2-agent-linux-arc"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:13"
  condition:
    hash.sha256(0, filesize) == "79267be4e49498c346d039e8e873b53e585df61eb9ab13a7a06873d2582daf4d"
}

rule MalwareBazaar_unknown_068_1bf49722
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bf49722569007690957f4110d0046441e44c36975719f269b6806c115b9d488"
    family = "unknown"
    file_name = "scanner-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:10"
  condition:
    hash.sha256(0, filesize) == "1bf49722569007690957f4110d0046441e44c36975719f269b6806c115b9d488"
}

rule MalwareBazaar_unknown_069_d854d418
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d854d418353d351fb1027fe141396faa33a83be13b44185928cb22df3f82f8a4"
    family = "unknown"
    file_name = "myc2-shell-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:07"
  condition:
    hash.sha256(0, filesize) == "d854d418353d351fb1027fe141396faa33a83be13b44185928cb22df3f82f8a4"
}

rule MalwareBazaar_unknown_070_fdd57a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd57a728d9f6dc1e27451cb8a18c25a2f143195a1ae18aa904039cbdc25c6bb"
    family = "unknown"
    file_name = "myc2-killer-linux-riscv32"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:04"
  condition:
    hash.sha256(0, filesize) == "fdd57a728d9f6dc1e27451cb8a18c25a2f143195a1ae18aa904039cbdc25c6bb"
}

rule MalwareBazaar_Mirai_071_a50a7512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a50a751252223942429abb005e78fb4fed4ad63cbd9a300b06ba5500d2fe3a06"
    family = "Mirai"
    file_name = "bot_local"
    file_type = "elf"
    first_seen = "2026-11-21 07:00:00"
  condition:
    hash.sha256(0, filesize) == "a50a751252223942429abb005e78fb4fed4ad63cbd9a300b06ba5500d2fe3a06"
}

rule MalwareBazaar_unknown_072_004ecde3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "004ecde33410d2c73b54a33ea3a7b1f5269c4b712e8224a2c4b62ef5ec2a29bc"
    family = "unknown"
    file_name = "myc2-preload-linux-sh4"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:58"
  condition:
    hash.sha256(0, filesize) == "004ecde33410d2c73b54a33ea3a7b1f5269c4b712e8224a2c4b62ef5ec2a29bc"
}

rule MalwareBazaar_unknown_073_467214c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "467214c576ea4dc1d1bf4ff2b87e094d64f026103f71e3d6471196b325f4db67"
    family = "unknown"
    file_name = "myc2-shell-linux-mipsle-softfloat"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:55"
  condition:
    hash.sha256(0, filesize) == "467214c576ea4dc1d1bf4ff2b87e094d64f026103f71e3d6471196b325f4db67"
}

rule MalwareBazaar_Mirai_074_7c247925
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c2479254ab633b3d552d9db092cbfd64bcecf161efa4979b64586963d78043e"
    family = "Mirai"
    file_name = "main_ppc64"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:52"
  condition:
    hash.sha256(0, filesize) == "7c2479254ab633b3d552d9db092cbfd64bcecf161efa4979b64586963d78043e"
}

rule MalwareBazaar_Mirai_075_ccd8cdba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccd8cdbaf11aa9cbac84e73cbf634b686052a4caf317f44a88b77c00009832b6"
    family = "Mirai"
    file_name = "loader.aarch64"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:50"
  condition:
    hash.sha256(0, filesize) == "ccd8cdbaf11aa9cbac84e73cbf634b686052a4caf317f44a88b77c00009832b6"
}

rule MalwareBazaar_unknown_076_78fc34cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78fc34cfcb438a76e7859e76853d699f6b19faca7e378bd379c6e72f33222a49"
    family = "unknown"
    file_name = "myc2-shell-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:47"
  condition:
    hash.sha256(0, filesize) == "78fc34cfcb438a76e7859e76853d699f6b19faca7e378bd379c6e72f33222a49"
}

rule MalwareBazaar_unknown_077_34fe8478
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34fe8478bd83c8c20316969dff761f0603a9c085321521b67e0208e2ef42af90"
    family = "unknown"
    file_name = "myc2-killer-linux-sh4"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:45"
  condition:
    hash.sha256(0, filesize) == "34fe8478bd83c8c20316969dff761f0603a9c085321521b67e0208e2ef42af90"
}

rule MalwareBazaar_unknown_078_781df860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "781df860d104130d6890f515430ac004d8c16ec34f443f91e2a8b9444a614546"
    family = "unknown"
    file_name = "myc2-preload-linux-arc"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:42"
  condition:
    hash.sha256(0, filesize) == "781df860d104130d6890f515430ac004d8c16ec34f443f91e2a8b9444a614546"
}

rule MalwareBazaar_unknown_079_4b0b7a91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b0b7a916b29ab63061cde59b018cc669a835fd09d9d2d4b8fa618b1bd638261"
    family = "unknown"
    file_name = "myc2-preload-linux-ppc"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:40"
  condition:
    hash.sha256(0, filesize) == "4b0b7a916b29ab63061cde59b018cc669a835fd09d9d2d4b8fa618b1bd638261"
}

rule MalwareBazaar_unknown_080_3fd5f54a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fd5f54a31541641d8d5525e791e528d76c2845d7d5c630d4726d527196474dd"
    family = "unknown"
    file_name = "myc2-dlr-linux-mips"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:38"
  condition:
    hash.sha256(0, filesize) == "3fd5f54a31541641d8d5525e791e528d76c2845d7d5c630d4726d527196474dd"
}

rule MalwareBazaar_Mirai_081_9edceade
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9edceade969da12e0c700f13488552e77168ff88d811202a4a02f4bb67cd0315"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:35"
  condition:
    hash.sha256(0, filesize) == "9edceade969da12e0c700f13488552e77168ff88d811202a4a02f4bb67cd0315"
}

rule MalwareBazaar_unknown_082_70d60ff8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70d60ff8199d864543b08c09c7bcf01a91ee1fdf3b5160dda29f56e745fb6d6a"
    family = "unknown"
    file_name = "zk_bridge_mips_9001"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:33"
  condition:
    hash.sha256(0, filesize) == "70d60ff8199d864543b08c09c7bcf01a91ee1fdf3b5160dda29f56e745fb6d6a"
}

rule MalwareBazaar_Mirai_083_5dd5d303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dd5d3033aa1b730cd6059f5cdc4d01a8b63a1bc3d362cc7fa990c46ce96e055"
    family = "Mirai"
    file_name = "bot.x86"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:30"
  condition:
    hash.sha256(0, filesize) == "5dd5d3033aa1b730cd6059f5cdc4d01a8b63a1bc3d362cc7fa990c46ce96e055"
}

rule MalwareBazaar_unknown_084_a45cadbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a45cadbc4020de09ef964a4f7604037f5aa0a81d1fde73b4eda6488154a73ba2"
    family = "unknown"
    file_name = "myc2-shell-linux-amd64"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:28"
  condition:
    hash.sha256(0, filesize) == "a45cadbc4020de09ef964a4f7604037f5aa0a81d1fde73b4eda6488154a73ba2"
}

rule MalwareBazaar_unknown_085_3d0a4c17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d0a4c17bff6b295f2d7ce5c3e404bb6362978429872089320b5003f7e9b8dbd"
    family = "unknown"
    file_name = "myc2-shell-linux-mips-softfloat"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:25"
  condition:
    hash.sha256(0, filesize) == "3d0a4c17bff6b295f2d7ce5c3e404bb6362978429872089320b5003f7e9b8dbd"
}

rule MalwareBazaar_Mirai_086_f848d48b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f848d48b672649b5abfeb8479c364eea84c9314f9d2b6df5bfb323358a770eeb"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:22"
  condition:
    hash.sha256(0, filesize) == "f848d48b672649b5abfeb8479c364eea84c9314f9d2b6df5bfb323358a770eeb"
}

rule MalwareBazaar_unknown_087_9d119196
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d1191963bbb019636e11380b258e815d1e3384a1d642ec1e22d7d87c3c4e3f0"
    family = "unknown"
    file_name = "zk_bridge_mips_9002"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:20"
  condition:
    hash.sha256(0, filesize) == "9d1191963bbb019636e11380b258e815d1e3384a1d642ec1e22d7d87c3c4e3f0"
}

rule MalwareBazaar_Mirai_088_1b59e5e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b59e5e6b79e2fda9c2d7d8f112b4b600c2077d6929e29a419eb6edab11d3d3a"
    family = "Mirai"
    file_name = "myc2-agent-linux-mipsle"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:17"
  condition:
    hash.sha256(0, filesize) == "1b59e5e6b79e2fda9c2d7d8f112b4b600c2077d6929e29a419eb6edab11d3d3a"
}

rule MalwareBazaar_unknown_089_c075fc89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c075fc89daaa63bd0747993537fe26a766686f461cf5e05c90f437251a9209e3"
    family = "unknown"
    file_name = "myc2-agent-linux-riscv32"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:15"
  condition:
    hash.sha256(0, filesize) == "c075fc89daaa63bd0747993537fe26a766686f461cf5e05c90f437251a9209e3"
}

rule MalwareBazaar_unknown_090_a798aae5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a798aae56cc763b51af3504b0f51114fe6090127c7e75e7938251e7adf52966a"
    family = "unknown"
    file_name = "myc2-preload-linux-sparc"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:12"
  condition:
    hash.sha256(0, filesize) == "a798aae56cc763b51af3504b0f51114fe6090127c7e75e7938251e7adf52966a"
}

rule MalwareBazaar_Mirai_091_c8583732
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8583732602aec896bcd8ee032e2fbc30a6419f4221581e20a400d3c723d24c7"
    family = "Mirai"
    file_name = "Heyiwei-csky-gx3201"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:10"
  condition:
    hash.sha256(0, filesize) == "c8583732602aec896bcd8ee032e2fbc30a6419f4221581e20a400d3c723d24c7"
}

rule MalwareBazaar_Mirai_092_be6c883c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be6c883cdae6020464df420c34addb4eb1d3b02238457e7934eb4e695076663d"
    family = "Mirai"
    file_name = "Heyiwei-csky-abiv1"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:07"
  condition:
    hash.sha256(0, filesize) == "be6c883cdae6020464df420c34addb4eb1d3b02238457e7934eb4e695076663d"
}

rule MalwareBazaar_unknown_093_6ee6e28f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee6e28f2c5c42988fb33d7389ba5f94c9eb295f3c813506227d39f1eea1203d"
    family = "unknown"
    file_name = "zk_bridge_mips_tcp_9003"
    file_type = "elf"
    first_seen = "2026-11-21 06:59:04"
  condition:
    hash.sha256(0, filesize) == "6ee6e28f2c5c42988fb33d7389ba5f94c9eb295f3c813506227d39f1eea1203d"
}

rule MalwareBazaar_unknown_094_3f508047
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f5080473eb31a2d6b9e01722ad4e81e345266c2164153d2e4149e5162c2120e"
    family = "unknown"
    file_name = "easyshell-l64-3f5080473eb31a2d.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:07:20"
  condition:
    hash.sha256(0, filesize) == "3f5080473eb31a2d6b9e01722ad4e81e345266c2164153d2e4149e5162c2120e"
}

rule MalwareBazaar_unknown_095_3fa0f8c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa0f8c7618ee2f2445fe1dc065cdc3c035240205f6ca62d2017e0894f756b5f"
    family = "unknown"
    file_name = "easyshell-l32-3fa0f8c7618ee2f2.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:07:09"
  condition:
    hash.sha256(0, filesize) == "3fa0f8c7618ee2f2445fe1dc065cdc3c035240205f6ca62d2017e0894f756b5f"
}

rule MalwareBazaar_unknown_096_9c0c05cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c0c05ccc57cc2d3b5b4a03ee436f3ee035262a860527637532fcd655abdb697"
    family = "unknown"
    file_name = "easyshell-l128-9c0c05ccc57cc2d3.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:07:00"
  condition:
    hash.sha256(0, filesize) == "9c0c05ccc57cc2d3b5b4a03ee436f3ee035262a860527637532fcd655abdb697"
}

rule MalwareBazaar_unknown_097_daf52a4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daf52a4e4b498469c2181ca1868248964b0a4e1054dd603a4625155335ed2bf9"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-daf52a4e4b498469.bin"
    file_type = "macho"
    first_seen = "2026-11-21 06:06:49"
  condition:
    hash.sha256(0, filesize) == "daf52a4e4b498469c2181ca1868248964b0a4e1054dd603a4625155335ed2bf9"
}

rule MalwareBazaar_unknown_098_b23a97f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b23a97f6969cce8bf4c5faeb1cd386ee22525bd99af1d6a62365121aa45f154b"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-b23a97f6969cce8b.bin"
    file_type = "macho"
    first_seen = "2026-11-21 06:06:41"
  condition:
    hash.sha256(0, filesize) == "b23a97f6969cce8bf4c5faeb1cd386ee22525bd99af1d6a62365121aa45f154b"
}

rule MalwareBazaar_unknown_099_6730470e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6730470ecc68b21cd5aea84398e369100e5f93d51c4d431ddca655dcd4abe3bc"
    family = "unknown"
    file_name = "easyshell-a64-6730470ecc68b21c.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:06:30"
  condition:
    hash.sha256(0, filesize) == "6730470ecc68b21cd5aea84398e369100e5f93d51c4d431ddca655dcd4abe3bc"
}

rule MalwareBazaar_unknown_100_11f92911
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f92911072b19b1687414f6846191d97370ad52172dcc0bef063e79a783d6ed"
    family = "unknown"
    file_name = "easyshell-a32-11f92911072b19b1.bin"
    file_type = "elf"
    first_seen = "2026-11-21 06:06:22"
  condition:
    hash.sha256(0, filesize) == "11f92911072b19b1687414f6846191d97370ad52172dcc0bef063e79a783d6ed"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

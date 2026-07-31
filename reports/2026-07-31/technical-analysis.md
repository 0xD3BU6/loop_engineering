# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-31

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 660 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 660 |
| Unique family labels | 10 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 44 |
| Mirai | 42 |
| WannaCry | 4 |
| AsyncRAT | 3 |
| RemcosRAT | 2 |
| NanoCore | 1 |
| ValleyRAT | 1 |
| CoinMiner | 1 |
| Vjw0rm | 1 |
| STRRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 53 |
| exe | 29 |
| sh | 10 |
| vbs | 5 |
| hta | 1 |
| zip | 1 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `a4b32f5f53a64195`

| Field | Value |
|---|---|
| SHA-256 | `a4b32f5f53a64195ee0cea0ea67a51799d90b25e761f0fec8d38b81e75b8a3c1` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 03:52:38` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15e99852c1be5de518692e7fed8b5966` |
| SHA-1 | `3a1c29c57c88ccfa5ad88b68511ae6e80cacb9c3` |
| SHA-256 | `a4b32f5f53a64195ee0cea0ea67a51799d90b25e761f0fec8d38b81e75b8a3c1` |
| SHA3-384 | `3de19dfc4e9de6b7b1ceb2f4b72fe523b959c17e13bc4eaf63022f49377cab1738b6fa75eeba18612906de104c99506c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T15CE63388AED015EDEA73913CDA729896FAA874A703B2CFDF0B6893615C531E10C3D651` |
| SSDEEP | `393216:m8XwBgN7KYZFbros/HxvYh94tXMCHWUjXOcuI3/PGTAI:m8gBgN7KQ6wxYhKXMb8XjH/O7` |
| ICON-DHASH | `f0d89ea292c6e4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_a4b32f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4b32f5f53a64195ee0cea0ea67a51799d90b25e761f0fec8d38b81e75b8a3c1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 03:52:38"
  condition:
    hash.sha256(0, filesize) == "a4b32f5f53a64195ee0cea0ea67a51799d90b25e761f0fec8d38b81e75b8a3c1"
}
```

### Sample 2: `dcc4899e3c3a30ba`

| Field | Value |
|---|---|
| SHA-256 | `dcc4899e3c3a30ba66cb03b92ff74755338f422f4ba47f1060a9503dde31fdfd` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 02:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41ac69b68fdbd435885f881abfe1587c` |
| SHA-1 | `6114ee757fe2e97974fbdb08bd852d6645eaa096` |
| SHA-256 | `dcc4899e3c3a30ba66cb03b92ff74755338f422f4ba47f1060a9503dde31fdfd` |
| SHA3-384 | `7fbd25bfa0688f045c1d84a40e06f223db8898f26f68431220b72e9925a5c711fe2c723795ac1630f1cf34c6c7023e0c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C7E6335CDAD101EEFAB3413CE9E216E5D509B8A613F2C58F1B18C3A4ADA76804D3D763` |
| SSDEEP | `393216:xTX20JRunLNwGVRgn7EXMCHWUjXCcuI3/PGTAI:xTeLNDAQXMb8X/H/O7` |
| ICON-DHASH | `71f0d4d8c8e4f170` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_dcc4899e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcc4899e3c3a30ba66cb03b92ff74755338f422f4ba47f1060a9503dde31fdfd"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 02:52:31"
  condition:
    hash.sha256(0, filesize) == "dcc4899e3c3a30ba66cb03b92ff74755338f422f4ba47f1060a9503dde31fdfd"
}
```

### Sample 3: `06f809fa0703109f`

| Field | Value |
|---|---|
| SHA-256 | `06f809fa0703109f2e34862b5614aa607ed8e654498fc31058dc9e4737785f34` |
| Family label | `unknown` |
| File name | `컴퓨터 완전 종료하기.exe` |
| File type | `exe` |
| First seen | `2026-07-31 02:05:48` |
| Reporter | `anonymous` |
| Tags | `custom_av, exe, suspicious` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25ce8f243b117430fb6379e22d2b6dac` |
| SHA-256 | `06f809fa0703109f2e34862b5614aa607ed8e654498fc31058dc9e4737785f34` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_06f809fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06f809fa0703109f2e34862b5614aa607ed8e654498fc31058dc9e4737785f34"
    family = "unknown"
    file_name = "컴퓨터 완전 종료하기.exe"
    file_type = "exe"
    first_seen = "2026-07-31 02:05:48"
  condition:
    hash.sha256(0, filesize) == "06f809fa0703109f2e34862b5614aa607ed8e654498fc31058dc9e4737785f34"
}
```

### Sample 4: `b521edd2233b62e6`

| Field | Value |
|---|---|
| SHA-256 | `b521edd2233b62e69e3c3e8ae27414e7e19f566675479884479139b7c576363d` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-31 02:01:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4f406e09bbbf4058e26c9a2b1b058f2` |
| SHA-1 | `901d920368e6d6848daf79eb48171fa2af38b692` |
| SHA-256 | `b521edd2233b62e69e3c3e8ae27414e7e19f566675479884479139b7c576363d` |
| SHA3-384 | `8e5946572680c240b975f21605339908aaaa929f5d7bf7cdf3fe185fceacc7832797b044708b731db93644aaad1dbd6e` |
| TLSH | `T17DC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B2A` |
| SSDEEP | `768:18vCB+25j6es8RJ9FYpMSUpi+20qUpi+20YQX:18l25Jvd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_b521edd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b521edd2233b62e69e3c3e8ae27414e7e19f566675479884479139b7c576363d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-31 02:01:34"
  condition:
    hash.sha256(0, filesize) == "b521edd2233b62e69e3c3e8ae27414e7e19f566675479884479139b7c576363d"
}
```

### Sample 5: `d14b8fd63a8933d8`

| Field | Value |
|---|---|
| SHA-256 | `d14b8fd63a8933d814039d0c157abe3032fccb34143d8fd94532419dc8f993a5` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-31 01:54:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e58340ba7997992f3273e691645b3d8` |
| SHA-1 | `914a8087c722571ddf0ac240179f33f714f7b2be` |
| SHA-256 | `d14b8fd63a8933d814039d0c157abe3032fccb34143d8fd94532419dc8f993a5` |
| SHA3-384 | `91d6586103c475b367da8549ffe7054547e1b697cea780dd915b8c3ec6c3fc5388bd9b15f7b445d0a6dfcebefeab3077` |
| TLSH | `T1BB01EFC6E210490080DED85C26A72455F431C3C7314B4F79FF6C943A9B94D14B0AAFA8` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha5C8WQ8GXF4tXuGX:e9Qp+Msc8WQ3F4huGX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_d14b8fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d14b8fd63a8933d814039d0c157abe3032fccb34143d8fd94532419dc8f993a5"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-31 01:54:42"
  condition:
    hash.sha256(0, filesize) == "d14b8fd63a8933d814039d0c157abe3032fccb34143d8fd94532419dc8f993a5"
}
```

### Sample 6: `2670c97b169e7752`

| Field | Value |
|---|---|
| SHA-256 | `2670c97b169e77527f6db4726e58db1c95926c35b56e292c0a3a975dd6656cb8` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 01:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e35810ed86789ee1d511550578dc81ec` |
| SHA-1 | `751e2692d1b8c18efba5b12c2e4076d57620e4eb` |
| SHA-256 | `2670c97b169e77527f6db4726e58db1c95926c35b56e292c0a3a975dd6656cb8` |
| SHA3-384 | `2a99cbd24ebe775ef457e73a4698257e598158b728d0acbe42d9c25caddc27d011cc19fb2bdf52e54ae4d7617b866503` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T187E6330872D01AFDEDA30278FEB15665D5A9B4320B71C8DF4E5497A36E0B1E08D3E267` |
| SSDEEP | `393216:igmkLdZLxHeuFJYzPUXMCHWUjXvcuI3/PGTAI:ig5HPYDUXMb8XkH/O7` |
| ICON-DHASH | `71f0e4d6e6e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_2670c97b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2670c97b169e77527f6db4726e58db1c95926c35b56e292c0a3a975dd6656cb8"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 01:52:31"
  condition:
    hash.sha256(0, filesize) == "2670c97b169e77527f6db4726e58db1c95926c35b56e292c0a3a975dd6656cb8"
}
```

### Sample 7: `b6c1a882ea04ab43`

| Field | Value |
|---|---|
| SHA-256 | `b6c1a882ea04ab43ef08120d0505c9e764c7cd41b7cb1151039a78c72828485f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-31 01:45:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `becb6654f16cee0e0b77969306f07e49` |
| SHA-1 | `474f97bf37f63de0ac733bf6d7f8962285e80a73` |
| SHA-256 | `b6c1a882ea04ab43ef08120d0505c9e764c7cd41b7cb1151039a78c72828485f` |
| SHA3-384 | `ef8aa0e749639a64d60bce667090c67cbdf7a664cc8ecda722edf587d0e855765996dea8e1ceb16111bcda48154cf6d0` |
| TLSH | `T13E235B651A857C14AA98C4361D7F2F0CB9AD43E6320452EE7FCF3CF28C5A6ADA10572D` |
| SSDEEP | `768:46Utd8/v9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Scr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_b6c1a882
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6c1a882ea04ab43ef08120d0505c9e764c7cd41b7cb1151039a78c72828485f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-31 01:45:34"
  condition:
    hash.sha256(0, filesize) == "b6c1a882ea04ab43ef08120d0505c9e764c7cd41b7cb1151039a78c72828485f"
}
```

### Sample 8: `fe1f6a9fa4f17f52`

| Field | Value |
|---|---|
| SHA-256 | `fe1f6a9fa4f17f52f6dc426da7fd08547bf533c8a65a4de0ab1dda879a77dae6` |
| Family label | `unknown` |
| File name | `a.sh` |
| File type | `sh` |
| First seen | `2026-07-31 01:45:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b94939373a9171000f7bba72876c2633` |
| SHA-1 | `acaf64907b86bfe282e611809e9bd910c01edec8` |
| SHA-256 | `fe1f6a9fa4f17f52f6dc426da7fd08547bf533c8a65a4de0ab1dda879a77dae6` |
| SHA3-384 | `5e8c47764dc59e251b757c2b5f52c4213d8f1e65d4bd8d7921adc7d34500b629f95e43bc225f72dbbf370f09f1c382aa` |
| TLSH | `T12911ADAF4454290ED6039D03F174D32FB26BBFED2EB62B04D68A2563E08D55030326DD` |
| SSDEEP | `24:5wEREwgaTaT4aqgA8T3TXhqbME/EE2tEE8EKL5kPDEKEqxBw:1aFuu4LgA8DXAbDcDtbzsLNqHw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_fe1f6a9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe1f6a9fa4f17f52f6dc426da7fd08547bf533c8a65a4de0ab1dda879a77dae6"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-07-31 01:45:32"
  condition:
    hash.sha256(0, filesize) == "fe1f6a9fa4f17f52f6dc426da7fd08547bf533c8a65a4de0ab1dda879a77dae6"
}
```

### Sample 9: `8809a03eaf8431f2`

| Field | Value |
|---|---|
| SHA-256 | `8809a03eaf8431f2d4252a2d23b1f0888b7fd8722281586fa7bf3154cec38a6d` |
| Family label | `Mirai` |
| File name | `zero.aarch64` |
| File type | `elf` |
| First seen | `2026-07-31 01:40:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11ac44040a66654731a06b19dee8ff57` |
| SHA-1 | `b332d06a3615b536e6486b9af45c1b767ceffbfb` |
| SHA-256 | `8809a03eaf8431f2d4252a2d23b1f0888b7fd8722281586fa7bf3154cec38a6d` |
| SHA3-384 | `817f46fcb15bd13888a90d441bad5e2f67e03fa17264203e3e369fc583d02148916a44340a9a8f9b27c4ec09fc3da1d7` |
| TLSH | `T103043A99FA0F5D42F1C7D3FCDA4D8BD13E2730E397368AB56D0202EDDAA39965940902` |
| SSDEEP | `3072:xqkmqYLlrPqIalNwXuB7+1anpor0y4hH/+7N3YvojYdCjsMZiwLq:beAo91Spo4y4A7hYgRjsbwLq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_8809a03e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8809a03eaf8431f2d4252a2d23b1f0888b7fd8722281586fa7bf3154cec38a6d"
    family = "Mirai"
    file_name = "zero.aarch64"
    file_type = "elf"
    first_seen = "2026-07-31 01:40:51"
  condition:
    hash.sha256(0, filesize) == "8809a03eaf8431f2d4252a2d23b1f0888b7fd8722281586fa7bf3154cec38a6d"
}
```

### Sample 10: `48e8aad529f74997`

| Field | Value |
|---|---|
| SHA-256 | `48e8aad529f74997fc1682ddd48d40201d4223e9cca45d988a86a7060e3b2be4` |
| Family label | `Mirai` |
| File name | `zero.aarch64` |
| File type | `elf` |
| First seen | `2026-07-31 01:40:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0f1498e3a85bd5361cb8c23abd335ee` |
| SHA-1 | `8fbc83e3d558f80d189863ae77e7c72f5a5e51a8` |
| SHA-256 | `48e8aad529f74997fc1682ddd48d40201d4223e9cca45d988a86a7060e3b2be4` |
| SHA3-384 | `6f405de9f100e8d0c264bd5fd016e0b2e0a3ff6821a3b44dce89b5c9b87d798c4c61a926efa42c673656084c748f41a6` |
| TLSH | `T1F86302C03DAFDD97E1045E3B9924C691F318E26F1B6B92E07D0CE1CA817858F69B605B` |
| SSDEEP | `1536:hIs+rxz6IZtdUL5osUMq0rtsOe+spjNQO55RjbiDSQrJ:z+tz68dc5osLrBnm+ssV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_48e8aad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48e8aad529f74997fc1682ddd48d40201d4223e9cca45d988a86a7060e3b2be4"
    family = "Mirai"
    file_name = "zero.aarch64"
    file_type = "elf"
    first_seen = "2026-07-31 01:40:23"
  condition:
    hash.sha256(0, filesize) == "48e8aad529f74997fc1682ddd48d40201d4223e9cca45d988a86a7060e3b2be4"
}
```

### Sample 11: `dd0d940f462679c1`

| Field | Value |
|---|---|
| SHA-256 | `dd0d940f462679c191187e004a9c66a811d50678eefe964e47d6d7efc1dd65ba` |
| Family label | `unknown` |
| File name | `x` |
| File type | `sh` |
| First seen | `2026-07-31 01:39:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d3763dc1ef5597d5a2184cc1f8712ad` |
| SHA-1 | `e49929ed7eed7e7dc9c7fefe18cc0980d1d1f0d9` |
| SHA-256 | `dd0d940f462679c191187e004a9c66a811d50678eefe964e47d6d7efc1dd65ba` |
| SHA3-384 | `fda45c48981065e2f84fa2ca60e54337f861430f91097dc4670af04950f80bf6d07a2f6e4cb926decde5d3df2ea67162` |
| TLSH | `T1E8D213F1F8ECA831369D453A779DA805A9DF7C2F0DA77D2014275A38421CB1EA119B3E` |
| SSDEEP | `384:jV4QiRUud3s153iDu7isrGcA4UADAZdhQuW5a:1iRUQs53iDlYUAkz/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_dd0d940f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd0d940f462679c191187e004a9c66a811d50678eefe964e47d6d7efc1dd65ba"
    family = "unknown"
    file_name = "x"
    file_type = "sh"
    first_seen = "2026-07-31 01:39:12"
  condition:
    hash.sha256(0, filesize) == "dd0d940f462679c191187e004a9c66a811d50678eefe964e47d6d7efc1dd65ba"
}
```

### Sample 12: `58ed7e2e13fbf102`

| Field | Value |
|---|---|
| SHA-256 | `58ed7e2e13fbf102e0732cc5b5e78c5f2dc6ee90ec849e2afb5d1a87ba4ffa4a` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-31 01:31:15` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbd29e268479c8ed497fcbae3798af66` |
| SHA-1 | `c2137cb10272a592698dc9e6b1f6fb634eda41d3` |
| SHA-256 | `58ed7e2e13fbf102e0732cc5b5e78c5f2dc6ee90ec849e2afb5d1a87ba4ffa4a` |
| SHA3-384 | `24d2ad464e24c29cc91c6f8857aaba99cba9936a13f334f1684604a708a4ba75bd2c4daa3b0d29502952523e2e0c2119` |
| TLSH | `T144236C651A857C24AA98C4371D7E2F0CBDAD43E6324492DE7FCA3CF28C5A69DD10872D` |
| SSDEEP | `768:iXRWNGxVg9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:OlxDcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_58ed7e2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58ed7e2e13fbf102e0732cc5b5e78c5f2dc6ee90ec849e2afb5d1a87ba4ffa4a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-31 01:31:15"
  condition:
    hash.sha256(0, filesize) == "58ed7e2e13fbf102e0732cc5b5e78c5f2dc6ee90ec849e2afb5d1a87ba4ffa4a"
}
```

### Sample 13: `eaa51075a1f46596`

| Field | Value |
|---|---|
| SHA-256 | `eaa51075a1f46596fe60d9f2b6ae226ce99ba8d8d6419ca6f8d5a4843971f642` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-07-31 01:30:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3c94b3bfb82d0e04aa1e67cf01853e3` |
| SHA-1 | `42e91c7e1272feaa338b643ffac013cee805924e` |
| SHA-256 | `eaa51075a1f46596fe60d9f2b6ae226ce99ba8d8d6419ca6f8d5a4843971f642` |
| SHA3-384 | `ada04d61b2e29b70b89972156ca519b6964e8e933197a4e2a29598ecc579997ec9f445e883397102390e8a1b9eabde67` |
| TLSH | `T137A32956FD818B61D6C116BAFA0E118E3313177CE2EE73129D146F2077CA96B0E7B846` |
| TELFHASH | `t170f09eba8514a4e9b3eb8299622d003807d471eb263432818feb7fdb245b0d9b61443f` |
| SSDEEP | `1536:d8nqNGSaII5sG0+JodMmkorsGKycWC5dmfaFeB9oV/UnBiPkshx5dyL769YVgA:ZGSaIjGJzouyfCXmfaFIEksL5dyLG9M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_eaa51075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaa51075a1f46596fe60d9f2b6ae226ce99ba8d8d6419ca6f8d5a4843971f642"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-31 01:30:53"
  condition:
    hash.sha256(0, filesize) == "eaa51075a1f46596fe60d9f2b6ae226ce99ba8d8d6419ca6f8d5a4843971f642"
}
```

### Sample 14: `68e383c37e939f48`

| Field | Value |
|---|---|
| SHA-256 | `68e383c37e939f4867cfe9a68ef58b636c0f722ca6e5aeb0ff6e46f3b5c0fcd6` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-07-31 01:29:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ff7ad305948eb05a5fa342df7763be6` |
| SHA-1 | `6c46381f5eec962b0b45976df6c91638d6cde567` |
| SHA-256 | `68e383c37e939f4867cfe9a68ef58b636c0f722ca6e5aeb0ff6e46f3b5c0fcd6` |
| SHA3-384 | `c6e268069a9109b3f9a6767293d006f37e736486aeca12dcb644cfb56afb9c06e85777889123934764c7525c0054e310` |
| TLSH | `T1A913F1B132A7AC71D9306D37D154F387AE1F1F35DD4B3233A21B20AE42D29A72B24116` |
| SSDEEP | `768:Eganv+60ZMMxOUXGYbrK2dbPANg3yJIutnpgsx9MLJv19q3UEL5x:xav+6xMYU2mW2dbPA23yJZvEvILH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_68e383c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68e383c37e939f4867cfe9a68ef58b636c0f722ca6e5aeb0ff6e46f3b5c0fcd6"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-31 01:29:36"
  condition:
    hash.sha256(0, filesize) == "68e383c37e939f4867cfe9a68ef58b636c0f722ca6e5aeb0ff6e46f3b5c0fcd6"
}
```

### Sample 15: `c42bc3059c891020`

| Field | Value |
|---|---|
| SHA-256 | `c42bc3059c891020a57e738e03039b269bd61358b33789de8a30532b7abe39ab` |
| Family label | `Mirai` |
| File name | `zero.arc` |
| File type | `elf` |
| First seen | `2026-07-31 01:25:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `930fa2760d24eb4c23cd3de0f1995f0f` |
| SHA-1 | `2a1499bb47ca32094085994711beae05e9380d95` |
| SHA-256 | `c42bc3059c891020a57e738e03039b269bd61358b33789de8a30532b7abe39ab` |
| SHA3-384 | `3c449e304fa55739c85e048e696249bd5fb141474c60d663902581071f969b42f2c06739a288e9523b64b1a3e8407aa1` |
| TLSH | `T186E3AE3B724B0460C85505F45AEB9B6E3B2326804F6F4AEF7CAD663E9B724CE15417E0` |
| SSDEEP | `3072:8k2ZZOYJ+It80IV12VTPeM2VcEdHxVLq5eYM1kgJCOSFXguxq:/2ZZOYJ+It80IVSP2VcoHeULvCOSFVxq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_c42bc305
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c42bc3059c891020a57e738e03039b269bd61358b33789de8a30532b7abe39ab"
    family = "Mirai"
    file_name = "zero.arc"
    file_type = "elf"
    first_seen = "2026-07-31 01:25:16"
  condition:
    hash.sha256(0, filesize) == "c42bc3059c891020a57e738e03039b269bd61358b33789de8a30532b7abe39ab"
}
```

### Sample 16: `b7f40db7b2110281`

| Field | Value |
|---|---|
| SHA-256 | `b7f40db7b2110281b3606c24e44d97751fc58b7a504641a4bd3525b053047836` |
| Family label | `Mirai` |
| File name | `nz.m68k` |
| File type | `elf` |
| First seen | `2026-07-31 01:21:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67710de95c8dc037b2447f1e6eb51cf1` |
| SHA-1 | `3f50d4cecc5c205b2b20531aacd3512372f350b5` |
| SHA-256 | `b7f40db7b2110281b3606c24e44d97751fc58b7a504641a4bd3525b053047836` |
| SHA3-384 | `dda4bb42d6b604c8e68cf5eb35139be9374b15724072397f1c26772af0b95b335867905d6fc3ee9ca193ceb0c7e08bd7` |
| TLSH | `T150A349D7B401CDBDF84AD77B4453490AB131E3A20A831F3663ABB967EC751981927F82` |
| SSDEEP | `3072:r7/l9ynsJp7+j8So6FkLV33AP2ZDok5IzgK:r7/2sJpS98333ZDUzgK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_b7f40db7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f40db7b2110281b3606c24e44d97751fc58b7a504641a4bd3525b053047836"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-31 01:21:14"
  condition:
    hash.sha256(0, filesize) == "b7f40db7b2110281b3606c24e44d97751fc58b7a504641a4bd3525b053047836"
}
```

### Sample 17: `05be5a8131993a50`

| Field | Value |
|---|---|
| SHA-256 | `05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e` |
| Family label | `WannaCry` |
| File name | `05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e` |
| File type | `exe` |
| First seen | `2026-07-31 01:15:05` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7955f6409c9e6669fcd5e3a0a293bc21` |
| SHA-1 | `d2e9e164a0ea103a6efedf290665e0e40dcc66fe` |
| SHA-256 | `05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e` |
| SHA3-384 | `75ecca04fcfb0c4da4a2bdbac9625d82cb28e0c91340bcdbba5d9a21edc4518a40879b0d929a81f0b9dd542880e6ccea` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1C636125A32AC90BCC11A5274A4B34E25E7B37C9622BD870F8B5487670E13790BF78B57` |
| SSDEEP | `24576:jbLg8bLguVQhfdmMSirYbcMNgef0QeQjGZ:jnRnFQqMSPbcBVQejZ` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_017_05be5a81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e"
    family = "WannaCry"
    file_name = "05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e"
    file_type = "exe"
    first_seen = "2026-07-31 01:15:05"
  condition:
    hash.sha256(0, filesize) == "05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e"
}
```

### Sample 18: `8a4636e894d4d7a9`

| Field | Value |
|---|---|
| SHA-256 | `8a4636e894d4d7a9ac0880a1210d70e0cf2c05e14924bcfbf39cffcef27c1e41` |
| Family label | `Mirai` |
| File name | `nz.arc` |
| File type | `elf` |
| First seen | `2026-07-31 01:05:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5af2dcb2788bb7a9d70c7fbf9da6273e` |
| SHA-1 | `cb6cdbb8df88e37fd3ead37be7d815a6674f63ac` |
| SHA-256 | `8a4636e894d4d7a9ac0880a1210d70e0cf2c05e14924bcfbf39cffcef27c1e41` |
| SHA3-384 | `be8ae406a70bbae322c29818029332fd0b9d25d60eb576417cf60040d6731ace1157e688b37b595f199e23a73f331cbc` |
| TLSH | `T11CC3AEC3FA8714A1C46206F007C71FAD2F93A121CE5FE4E7AC1DB63B5A7A4DA1616781` |
| SSDEEP | `1536:ErMjtT/2h9gduHjVLraXQHlWuoPpMS4sTlt0y1csxs5tZgRCET/LW5:ErWT/i9LGXQFn+z4sT4y1chgJq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_8a4636e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a4636e894d4d7a9ac0880a1210d70e0cf2c05e14924bcfbf39cffcef27c1e41"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-31 01:05:30"
  condition:
    hash.sha256(0, filesize) == "8a4636e894d4d7a9ac0880a1210d70e0cf2c05e14924bcfbf39cffcef27c1e41"
}
```

### Sample 19: `33d3debdce6373af`

| Field | Value |
|---|---|
| SHA-256 | `33d3debdce6373af8112ee1bd1649bf12b8c2944265108dafa2e7432a014d870` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-31 01:03:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `115f11b1f494e406ca839caffdecd888` |
| SHA-1 | `530de2891a7899fb8419aba6af5b0f7aac3542b9` |
| SHA-256 | `33d3debdce6373af8112ee1bd1649bf12b8c2944265108dafa2e7432a014d870` |
| SHA3-384 | `d57781cee43d66ebbba9a5be41ce11844ebf7c757a1e5de8597459fa4bd7fe4535cf6b58dbd615ceee35803a31e615eb` |
| TLSH | `T155935D02B70C0E43D1675DF02A3F27D1D3EEA6E121F4F688691F9A8591B2D335586EC9` |
| SSDEEP | `1536:GFsCCOHrTgbrkU4V4SKUgZ5VvHfNa0Y0uM1y1pAzKYH2FOtMuXyCg7cA/kx3BFW:LROHrTZU4qk8iAzxJMVCEOW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_33d3debd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33d3debdce6373af8112ee1bd1649bf12b8c2944265108dafa2e7432a014d870"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-31 01:03:54"
  condition:
    hash.sha256(0, filesize) == "33d3debdce6373af8112ee1bd1649bf12b8c2944265108dafa2e7432a014d870"
}
```

### Sample 20: `103467ebe5fc36e8`

| Field | Value |
|---|---|
| SHA-256 | `103467ebe5fc36e88c3eac3af0cd1fe42bb1b6dbcb5e0abbf80410c58667d0c8` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-31 01:02:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f0de96ada700ba75915dc9e2e1454a8` |
| SHA-1 | `e0673d622f9a07cb26af37d923f2b4c898c2ea18` |
| SHA-256 | `103467ebe5fc36e88c3eac3af0cd1fe42bb1b6dbcb5e0abbf80410c58667d0c8` |
| SHA3-384 | `56994ddaf41f0bfaae07934c4ad36211a4f07d21542958e963dda1a86cdb3fba347a3ba1f32d3a4898c70e1583dff19d` |
| TLSH | `T10A03F1B0B8688D41CFDFF8B44EA5E151B3D38E5557B8D6C085C59AE10A53C32EE88EC8` |
| SSDEEP | `768:lzmIAsqqVUYvRGgwvq0bQGPlCLIziey3gzUNX24uVcqgw0Ih:9mIJqqVNRGgwvXbQGwUz/UNX24u+qgw3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_103467eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "103467ebe5fc36e88c3eac3af0cd1fe42bb1b6dbcb5e0abbf80410c58667d0c8"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-31 01:02:37"
  condition:
    hash.sha256(0, filesize) == "103467ebe5fc36e88c3eac3af0cd1fe42bb1b6dbcb5e0abbf80410c58667d0c8"
}
```

### Sample 21: `675e7bbd6ff60ebf`

| Field | Value |
|---|---|
| SHA-256 | `675e7bbd6ff60ebf352b1d9a788caaee58cb1a4688d74ecc7752ebe8970b81c4` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-31 01:01:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eae3492f34f9e71dde1e010d8aef8875` |
| SHA-1 | `97da543f3edf1087bc4821471967abbcdcc20276` |
| SHA-256 | `675e7bbd6ff60ebf352b1d9a788caaee58cb1a4688d74ecc7752ebe8970b81c4` |
| SHA3-384 | `ecdc04fa6e6fd59d86b98e750d3f8d25c170ffe701c60e1e65f07b2933bca24843c7eb5de80a3a4564c4d11a24d57165` |
| TLSH | `T10F932992FD818622C6C116B7FB6E428E376713A8E2EE32039D155F2137CB95B0E7B541` |
| TELFHASH | `t175510efbeb950adc5bd7d284828f51094aec31fd1f083495d608bb4f8582682f62c837` |
| SSDEEP | `1536:cvz5t3kgmzvOv3JISR0UTktQAvQ193So2TfL+HGjQlZlo2vqaJQ:Iz5t3kgoOv3JlxAv85B2TfI24FHQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_675e7bbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "675e7bbd6ff60ebf352b1d9a788caaee58cb1a4688d74ecc7752ebe8970b81c4"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-31 01:01:50"
  condition:
    hash.sha256(0, filesize) == "675e7bbd6ff60ebf352b1d9a788caaee58cb1a4688d74ecc7752ebe8970b81c4"
}
```

### Sample 22: `b9fa1dc749428b51`

| Field | Value |
|---|---|
| SHA-256 | `b9fa1dc749428b51ef1855db00fdcff798c4ec865f1ed823b6f5e0eed49363c7` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-31 00:59:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9ed9036d693a360ad7f7db9347b2385` |
| SHA-1 | `553f737c53edcdd5516fa95d34099c112aaa6c84` |
| SHA-256 | `b9fa1dc749428b51ef1855db00fdcff798c4ec865f1ed823b6f5e0eed49363c7` |
| SHA3-384 | `64da7ba0595865062bc104d1c2420268d9073fbd9f743fed4f685449fa2910335036deded57b4b5b185526b647bcf3bd` |
| TLSH | `T19613F1B073515276D5BC7131DEE88729230851ADB0BAF45E7E209BC8764329762BDFC2` |
| SSDEEP | `768:P786Hwlf95Xo2qsL7x0oFpCtvHBjeJUn4LOHHhP5BSq3Pmjs3Uozt:PQ6Hwlf95Xo0LGFxeJy4LQBffvzt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_b9fa1dc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9fa1dc749428b51ef1855db00fdcff798c4ec865f1ed823b6f5e0eed49363c7"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-31 00:59:32"
  condition:
    hash.sha256(0, filesize) == "b9fa1dc749428b51ef1855db00fdcff798c4ec865f1ed823b6f5e0eed49363c7"
}
```

### Sample 23: `c3db3111e5636ec2`

| Field | Value |
|---|---|
| SHA-256 | `c3db3111e5636ec2615f58d66e2a90b5c2d36556a29b584ae3344e3d7dee6b5c` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-31 00:57:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fd6645acb40539b1108923301834f83` |
| SHA-1 | `b996359b19f06c36e976a198db79f1f87a27d1ae` |
| SHA-256 | `c3db3111e5636ec2615f58d66e2a90b5c2d36556a29b584ae3344e3d7dee6b5c` |
| SHA3-384 | `28e6b1b843de833939ce98bd3c686b06c04ba73a30846c635d20a492ed634220caa26f396b089e05e38e4736d802fac3` |
| TLSH | `T127043B46EA404B13C4D32B79BA9B424633239B64D3EB730699187FF43F8679E4E67501` |
| TELFHASH | `t1c2314e75673994046fa1c864dcfc57b2551b87130784ae32cf3bc8cc181a08ee62ac0f` |
| SSDEEP | `3072:J2PZAZVxrj3LaFbPUaqA98I9iNFpqZPvYCrZQAM/9RDW9gS:JOZAZ/zLaFbPUaq9I9ApYPgCrZnM/9RQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_c3db3111
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3db3111e5636ec2615f58d66e2a90b5c2d36556a29b584ae3344e3d7dee6b5c"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 00:57:43"
  condition:
    hash.sha256(0, filesize) == "c3db3111e5636ec2615f58d66e2a90b5c2d36556a29b584ae3344e3d7dee6b5c"
}
```

### Sample 24: `2c748313a5a75f19`

| Field | Value |
|---|---|
| SHA-256 | `2c748313a5a75f19574f44dd6db9c1c064ddc494132a91a46ff71be7b6f60d61` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-31 00:57:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `628f4fcdbbfafdd3104b399ac74f9c80` |
| SHA-1 | `ed1a896e81e0d265a0cb33a422459cccbd344a45` |
| SHA-256 | `2c748313a5a75f19574f44dd6db9c1c064ddc494132a91a46ff71be7b6f60d61` |
| SHA3-384 | `9f067b7963a19fc58c9b5ad838cd82ec4c659267bfb30fe03c2c3c1dd9e9486e2c6750d5ac329d008aad08a91dbd2bea` |
| TLSH | `T13363F170912916E3DBE04EB5F4DA8EC445BC5AFCD33E30A70531A82C7C5A58256EB9CB` |
| SSDEEP | `1536:71dpHYEXFuUWeJJMIdxYqyCL0MNrKr6z8mqCs:77CEXFuUWergqTL0MpR4p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_2c748313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c748313a5a75f19574f44dd6db9c1c064ddc494132a91a46ff71be7b6f60d61"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 00:57:18"
  condition:
    hash.sha256(0, filesize) == "2c748313a5a75f19574f44dd6db9c1c064ddc494132a91a46ff71be7b6f60d61"
}
```

### Sample 25: `f3a34d567b2dcf24`

| Field | Value |
|---|---|
| SHA-256 | `f3a34d567b2dcf24fd994959ddf22daaa11c679e9f570f4fa9227ba53a53dff5` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-31 00:53:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7658330069eb3a1d341756df91429eab` |
| SHA-1 | `0295a29772b542430fce37bb62a76a99522479cb` |
| SHA-256 | `f3a34d567b2dcf24fd994959ddf22daaa11c679e9f570f4fa9227ba53a53dff5` |
| SHA3-384 | `ba2f5b37c87256db854cb6b2faca3f873b9d906d318f3099b6c89cd5baa7bffe9532fe097e9b245d046b9e3b5b7be5e5` |
| TLSH | `T1B2837DC6E743C4F4E8528973217BE7328A73E53D102DEE83D769A932ED12501D66A39C` |
| TELFHASH | `t13f31a8f71eba5df8b7d06400d31e5b522969d67b186036625673c82022beed290bac39` |
| SSDEEP | `1536:bAxTtfhenc5SWHpoClHNVVk/13HWCsBjJe7s4TtAQV:bALIuS0poClHN4/13HlsBdar1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_f3a34d56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3a34d567b2dcf24fd994959ddf22daaa11c679e9f570f4fa9227ba53a53dff5"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-31 00:53:49"
  condition:
    hash.sha256(0, filesize) == "f3a34d567b2dcf24fd994959ddf22daaa11c679e9f570f4fa9227ba53a53dff5"
}
```

### Sample 26: `6a73772fd7b33b4f`

| Field | Value |
|---|---|
| SHA-256 | `6a73772fd7b33b4f84b67053356c0cffe6e19a7b18b098ad1df5ea572aafbc3b` |
| Family label | `unknown` |
| File name | `weneedsuchakingdomofnicepersonentirelinkingforebst.hta` |
| File type | `hta` |
| First seen | `2026-07-31 00:53:27` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d55cbb307ce9e58ade8a2146e5aa9ed7` |
| SHA-1 | `d289296434dee98e19781da245050b263840fbce` |
| SHA-256 | `6a73772fd7b33b4f84b67053356c0cffe6e19a7b18b098ad1df5ea572aafbc3b` |
| SHA3-384 | `caedab1362b8f2da6b583e23b98846437d5b56f3b62020588348ff0de98d2ac2355e5fadb9f23b3a732b1d59231897dc` |
| TLSH | `T17731815248F01847332082699FD5B51ADD46BE1B8F495C5570DF614A0FF1F9389A347E` |
| SSDEEP | `24:hYdRA20yev1jG56VGM6p6dZ6rq6hFG96/3BHgA7+QhkHtW/OO1o:gRAOg7E861gA9h0nr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_6a73772f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a73772fd7b33b4f84b67053356c0cffe6e19a7b18b098ad1df5ea572aafbc3b"
    family = "unknown"
    file_name = "weneedsuchakingdomofnicepersonentirelinkingforebst.hta"
    file_type = "hta"
    first_seen = "2026-07-31 00:53:27"
  condition:
    hash.sha256(0, filesize) == "6a73772fd7b33b4f84b67053356c0cffe6e19a7b18b098ad1df5ea572aafbc3b"
}
```

### Sample 27: `1741729211a76777`

| Field | Value |
|---|---|
| SHA-256 | `1741729211a767777d024691477bc83333d59e0f9f222571600487bdd4f9b011` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-31 00:53:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90b1395f968280d5d57239a008632788` |
| SHA-1 | `4eb254547404ed7d20f9202bd04941b33e18f120` |
| SHA-256 | `1741729211a767777d024691477bc83333d59e0f9f222571600487bdd4f9b011` |
| SHA3-384 | `a28583739f30bf23149d4cd7e2d3d3198c075aadfb58b4f7eb9af9f1ebe4f2326ee347206dc3198be03c1b2a358a08fd` |
| TLSH | `T10003F163F89967DAC05E103C68BDE3460D20D7414C64D970AAE4A4D3BD86F2A4BBC5E9` |
| SSDEEP | `768:j5UcnRyjFbZGbR6AhF60uqmsHW24TQIp9bEQP4di7ZVO/eSQawK+EA4nnbcuyD7+:j5UoyjFbZGlh40Kt2A9p9t4dASntnnoo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_17417292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1741729211a767777d024691477bc83333d59e0f9f222571600487bdd4f9b011"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-31 00:53:26"
  condition:
    hash.sha256(0, filesize) == "1741729211a767777d024691477bc83333d59e0f9f222571600487bdd4f9b011"
}
```

### Sample 28: `4bb4b92b54c8ecd1`

| Field | Value |
|---|---|
| SHA-256 | `4bb4b92b54c8ecd1db145f986e9725e9d327713cd9262dbe010318afd6af8137` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 00:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d310c9820dcc8e5badcba6b05c5b16f1` |
| SHA-1 | `48edf7fee4bb273650d3624f9829c9ee075eee49` |
| SHA-256 | `4bb4b92b54c8ecd1db145f986e9725e9d327713cd9262dbe010318afd6af8137` |
| SHA3-384 | `cddd3eecc5fd7cbc3e07715b04e132af3e2231e8d9b88d6065674a522e9f7ea785c64ab20a3f08b9616a237e7dcd2101` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1B3E6330426F152EEDAA3003CEDB25455E86978720336C6EF4BF89715BE573F4483E26A` |
| SSDEEP | `393216:nv3FXcgxeRlkNp2vsS8pj/svXMCHWUjXscuI3/PGTAI:nv1k6L2U/8XMb8X5H/O7` |
| ICON-DHASH | `b270e8cccce8f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_4bb4b92b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bb4b92b54c8ecd1db145f986e9725e9d327713cd9262dbe010318afd6af8137"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 00:52:31"
  condition:
    hash.sha256(0, filesize) == "4bb4b92b54c8ecd1db145f986e9725e9d327713cd9262dbe010318afd6af8137"
}
```

### Sample 29: `95f92b2e46e524ee`

| Field | Value |
|---|---|
| SHA-256 | `95f92b2e46e524ee532a486516189c8b33ba1fbbcc37cfb3a043c97f4af8a327` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-31 00:51:13` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f958e33cf6ebd0e282131708d5720d2e` |
| SHA-1 | `d21ee8e78de317d4e4f675c3caf66be6cab9617c` |
| SHA-256 | `95f92b2e46e524ee532a486516189c8b33ba1fbbcc37cfb3a043c97f4af8a327` |
| SHA3-384 | `29f463c93a3afd7c138b4935f01707af28602c66738a8c03cfc2c030ebd7d29ffd0c012ef10411ae6a06ab64ea5e347e` |
| TLSH | `T118C28C966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:L8vCB+25j6es8RG9FYpMSUpi+20qUpi+20YQX:L8l25Jwd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_95f92b2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95f92b2e46e524ee532a486516189c8b33ba1fbbcc37cfb3a043c97f4af8a327"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-31 00:51:13"
  condition:
    hash.sha256(0, filesize) == "95f92b2e46e524ee532a486516189c8b33ba1fbbcc37cfb3a043c97f4af8a327"
}
```

### Sample 30: `c7866aec77c1fa71`

| Field | Value |
|---|---|
| SHA-256 | `c7866aec77c1fa71cd9a678de4ba00abf6ccd862a47258cba319f21eb42da76e` |
| Family label | `Mirai` |
| File name | `bot.arm7` |
| File type | `elf` |
| First seen | `2026-07-31 00:51:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ad8a84dfb545c5ced66729358017b9e` |
| SHA-1 | `3fc5b7dd8878f215acd5b1abc561b60c9abfed0d` |
| SHA-256 | `c7866aec77c1fa71cd9a678de4ba00abf6ccd862a47258cba319f21eb42da76e` |
| SHA3-384 | `51a8c39d3041fa311b2e17483c2305c8040dfa3bc17aa29884140a4bff8782b8e35ce2535a2e90f1bb1766426f814be7` |
| TLSH | `T10B93088AFC819B11D4D522BAFE5E228C335317BCE3EE72029D255B2527CA95F0E77502` |
| TELFHASH | `t18c11c254a5dc1acca3e48b06018ac737796632d99f111d5e9faa6b0f0621ee27424033` |
| SSDEEP | `1536:Jhnsxvr6caAWqm59cTCLSgKsY9fcbDRd0HA3NwmBdlBXic8cPaNFlFpmY7CTo2O:OvKTPsTK6T9fcbDRd0HA3NtR8yaNF7pv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_c7866aec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7866aec77c1fa71cd9a678de4ba00abf6ccd862a47258cba319f21eb42da76e"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 00:51:12"
  condition:
    hash.sha256(0, filesize) == "c7866aec77c1fa71cd9a678de4ba00abf6ccd862a47258cba319f21eb42da76e"
}
```

### Sample 31: `ed1d3f69fbbd5576`

| Field | Value |
|---|---|
| SHA-256 | `ed1d3f69fbbd5576c2ed8dba45ba22c4f6884eb311d4f6e389203846d512ec11` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-31 00:50:14` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2cfaefe80e05fe0f093cf5c382d7c77f` |
| SHA-1 | `c2ad2a5b5cd45e6f574d86b6e5b1079ed3063933` |
| SHA-256 | `ed1d3f69fbbd5576c2ed8dba45ba22c4f6884eb311d4f6e389203846d512ec11` |
| SHA3-384 | `2b6822be6a3b02ae09825e90471b0ba49be1898766febcd1cc8a323ff8b1bb35e0f487c3bb31647add09c25bd0c97560` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T131968D07EC9155A9C0AAE6358A729253BA717C485B3123D73F90F7382F73BD06AB8750` |
| SSDEEP | `98304:aoM7vbdbj6O/qZLw5tfjf8Bwm1sDjNXX5Ikr3aX5svhUE:aoMLbdbWO/eLafjUBD1+jNnSMq+t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_ed1d3f69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed1d3f69fbbd5576c2ed8dba45ba22c4f6884eb311d4f6e389203846d512ec11"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 00:50:14"
  condition:
    hash.sha256(0, filesize) == "ed1d3f69fbbd5576c2ed8dba45ba22c4f6884eb311d4f6e389203846d512ec11"
}
```

### Sample 32: `4d91f77e3e4a056b`

| Field | Value |
|---|---|
| SHA-256 | `4d91f77e3e4a056b4c2f494ac6bade22d6ed083f757a75735698c2a08a5c37fe` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-07-31 00:50:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6609f3e27d41af516bca56484cb153b` |
| SHA-1 | `3e644aa26b7cf55ca24e56e71cb4309a777181bc` |
| SHA-256 | `4d91f77e3e4a056b4c2f494ac6bade22d6ed083f757a75735698c2a08a5c37fe` |
| SHA3-384 | `cf7eb36c9b809dcdb12ca99abf3d151c1d03ae0d3cb332fb4971ded06a4b389934e5cbb8c2162f288f27d2d9ea9064d7` |
| TLSH | `T19383AD33C92A0E68D84845B4B0B18FB65763E515C0972EF7499AC67AD083EDCF58A3F4` |
| SSDEEP | `1536:Fgynxf8zTGNxM4aiuRAKxPrSZCeRCaBqn3HyH:Fxnx3NUpRHx2CeR/+8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_4d91f77e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d91f77e3e4a056b4c2f494ac6bade22d6ed083f757a75735698c2a08a5c37fe"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-31 00:50:06"
  condition:
    hash.sha256(0, filesize) == "4d91f77e3e4a056b4c2f494ac6bade22d6ed083f757a75735698c2a08a5c37fe"
}
```

### Sample 33: `ddf666a2eb309680`

| Field | Value |
|---|---|
| SHA-256 | `ddf666a2eb3096803696ddf5fee4eb56922a67b89242370a0796289feb124357` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-31 00:49:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c70e7e65c8142527c78945213756f80` |
| SHA-1 | `3c76916cde7bf3ed931eb4d7ab470bc4b90da49d` |
| SHA-256 | `ddf666a2eb3096803696ddf5fee4eb56922a67b89242370a0796289feb124357` |
| SHA3-384 | `306e58bbcb0ac87c8bfeffeacb8aec59d178ca1501546fee51e67d0dcb475a239c833ff579efff3b4c329b7f218bc99b` |
| TLSH | `T1C1430893FD92469BC5C027B6B76F568933A267A5C2DE3313C8140B113BCAA4F4E67A41` |
| TELFHASH | `t1a1f0c084fe764f1589e1a574dcbc0360e9436126a5625b20df52cad0883e149d30cd1d` |
| SSDEEP | `1536:LVXyO/FNXnttb+E1Cv8HVepmZL6t9CWW:LVXyoFNXuXtpmZLmd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_ddf666a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddf666a2eb3096803696ddf5fee4eb56922a67b89242370a0796289feb124357"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-31 00:49:38"
  condition:
    hash.sha256(0, filesize) == "ddf666a2eb3096803696ddf5fee4eb56922a67b89242370a0796289feb124357"
}
```

### Sample 34: `a8ff9266caf4a5c7`

| Field | Value |
|---|---|
| SHA-256 | `a8ff9266caf4a5c7871f67e6dd1efdec84998ebc5a18970273350407b7a02dbf` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-31 00:48:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `180e1dc72e0cb6b907568535c9b60774` |
| SHA-1 | `d7cc84f90916bdad0982795ece4c3a959269da01` |
| SHA-256 | `a8ff9266caf4a5c7871f67e6dd1efdec84998ebc5a18970273350407b7a02dbf` |
| SHA3-384 | `39c86918423a6e96496eae559224630f13a4b62c66dd9cbbe56b9e555e5a6b4a2bc8a129f7bb93970b99e9d70627cc57` |
| TLSH | `T180B2D02124ABFD61CAF5483EADFC4043367247BD9AFE715523401179A9C974F28F92CA` |
| SSDEEP | `768:sU2CkpevxM63iw/6IFEvWe+9tvbOjJfBv/s3UozNW:4xpiWzw/6IuPf5yzNW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_a8ff9266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ff9266caf4a5c7871f67e6dd1efdec84998ebc5a18970273350407b7a02dbf"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-31 00:48:35"
  condition:
    hash.sha256(0, filesize) == "a8ff9266caf4a5c7871f67e6dd1efdec84998ebc5a18970273350407b7a02dbf"
}
```

### Sample 35: `7d56228e11bcf1fe`

| Field | Value |
|---|---|
| SHA-256 | `7d56228e11bcf1feafa30c07418322cbd223b2d95b8092fc34e7e3a346f19361` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-31 00:46:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1906ab8f794fb185a82254714b7075f0` |
| SHA-1 | `df0cdfd21fbaa6cf8d1ed4ce542f2404a76f09da` |
| SHA-256 | `7d56228e11bcf1feafa30c07418322cbd223b2d95b8092fc34e7e3a346f19361` |
| SHA3-384 | `761cd05856f3866b5aa88c1a09493cb966e57411fca363260555afcb473d427c91e7e867a6fa9ba9e1a665caab428607` |
| TLSH | `T19D13F2FDD140025EDE938037A6624B723D6DCF68D1C09903D4D85E8B0D52CA66BE3ED6` |
| SSDEEP | `768:sLUFxa5EgKxb2jpAANVULUYVCxX3PB4GNvOXrj47w9juLdqJ+po2JiwRa3cFJgGf:Xva5EnxbVAMLNinpxE47wM42o286as/f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_7d56228e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d56228e11bcf1feafa30c07418322cbd223b2d95b8092fc34e7e3a346f19361"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-31 00:46:19"
  condition:
    hash.sha256(0, filesize) == "7d56228e11bcf1feafa30c07418322cbd223b2d95b8092fc34e7e3a346f19361"
}
```

### Sample 36: `fd0dfe41d5290fc1`

| Field | Value |
|---|---|
| SHA-256 | `fd0dfe41d5290fc192b1af69eb866c40387a59848f8c99946a30be1e70bf639d` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-31 00:44:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b56b46c6b9fe63a83af33a2636bd7b8` |
| SHA-1 | `773dc6a021ae9115bb7be7607bbd65ba87215c3a` |
| SHA-256 | `fd0dfe41d5290fc192b1af69eb866c40387a59848f8c99946a30be1e70bf639d` |
| SHA3-384 | `eab77999edc84cb34b1cd5f34b241171e0b98b7164759e4132a603c18b624a5bfdb4189173d4eadf0e32a6a8e36247e7` |
| TLSH | `T19DC3F909EB614FFBE86FCD3746E90B0525CC551722A83B7A3574D828F64B64B4AE3870` |
| SSDEEP | `1536:FtJ6cGVoxBFf+g6z3jLH514RXvsneY0+YdW0OKhp6XposGZ5uhrKnr1Fm41CUhQH:XJ6cGVoJ6TneH6X7GCJO91fFa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_fd0dfe41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0dfe41d5290fc192b1af69eb866c40387a59848f8c99946a30be1e70bf639d"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-31 00:44:38"
  condition:
    hash.sha256(0, filesize) == "fd0dfe41d5290fc192b1af69eb866c40387a59848f8c99946a30be1e70bf639d"
}
```

### Sample 37: `2873519dc02a5080`

| Field | Value |
|---|---|
| SHA-256 | `2873519dc02a5080e24cf664641d4ba6f4ca92d7b2c5861d420efa3cab7807fd` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-31 00:44:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `439e22c0e9fd6292196f9d0500f3aada` |
| SHA-1 | `5c03f6ea25a06a6430a2f70a902d3212afd2e2ea` |
| SHA-256 | `2873519dc02a5080e24cf664641d4ba6f4ca92d7b2c5861d420efa3cab7807fd` |
| SHA3-384 | `a6ba8ae9573bf798b87890b73975c5579bce6dc4707246ddb3147dc0594e46e1ccc240cf4566f474edce016701ef8c1a` |
| TLSH | `T12E13F12CB8B1A8C6C7EC6D72B06927D0AA0DF0C17147CF9B23525805AA3B68FB5470B5` |
| SSDEEP | `768:uGeKZKIg8ShZ/9QL8C0mRsK9mQO8+GxoxnqB8BFhFGfvbYZqNtRWP:uqsIg8ShZlQL3jRHPXnuekFP8AqNW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_2873519d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2873519dc02a5080e24cf664641d4ba6f4ca92d7b2c5861d420efa3cab7807fd"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-31 00:44:10"
  condition:
    hash.sha256(0, filesize) == "2873519dc02a5080e24cf664641d4ba6f4ca92d7b2c5861d420efa3cab7807fd"
}
```

### Sample 38: `770296c374081051`

| Field | Value |
|---|---|
| SHA-256 | `770296c3740810517ffe272adbb0c45160e2f309b206f14695cb125e6d240217` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-31 00:42:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0654313e88f06d8651e8c91643c5423` |
| SHA-1 | `569d24a1ca5017f6c2fb53910697cd3fce6891e9` |
| SHA-256 | `770296c3740810517ffe272adbb0c45160e2f309b206f14695cb125e6d240217` |
| SHA3-384 | `e361dea255eb66b04646a449e72aeb07ac5abc24eab9f9b238b813b47882c0eec2c0542c9273313b1fe883135c09a385` |
| TLSH | `T1298318C1BA4BC0F5D90748304067F33FCB32D6394061D66EEFAADE65EA73642522629D` |
| TELFHASH | `t19d312cfa297e0cfca7d45940935e1e623d29e77f29a076b046735834336be8150bac39` |
| SSDEEP | `1536:8l8IhK59kLMSbgWbzKWAc6HWiay3Tx9gorF6ShJIl9:8/hU9ktbfKWnpwTx9dryl9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_770296c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "770296c3740810517ffe272adbb0c45160e2f309b206f14695cb125e6d240217"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-31 00:42:36"
  condition:
    hash.sha256(0, filesize) == "770296c3740810517ffe272adbb0c45160e2f309b206f14695cb125e6d240217"
}
```

### Sample 39: `0b54fb4e5cab6274`

| Field | Value |
|---|---|
| SHA-256 | `0b54fb4e5cab6274b4604abe2ef2514f11e5c61ccd0eb5006075b1770665f0d4` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-31 00:41:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `826b8a2cc94c8fcae9cf0b061d710307` |
| SHA-1 | `29fa79ec2e696af5f87a8435548480d7f7dd5df4` |
| SHA-256 | `0b54fb4e5cab6274b4604abe2ef2514f11e5c61ccd0eb5006075b1770665f0d4` |
| SHA3-384 | `734a99200ca3cb3ec925db779c5724c85ea1f6ea2e03e4cad0a4e40cd0a869bd96bdf34d0f4047d05491884822f8e08b` |
| TLSH | `T1FC13F11AD9D8EF22C29E637402FF0E991CD4D1378B44C7A3A9DD46250A07FE92634776` |
| SSDEEP | `768:t6sry8pGtT5Srlssa6ynogyr6oBqTdj/5lp4bTvXHQTijnbcuyD7UHQRju:t6srMxglAfoPrGR78ljnouy8Hyi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_0b54fb4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b54fb4e5cab6274b4604abe2ef2514f11e5c61ccd0eb5006075b1770665f0d4"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-31 00:41:31"
  condition:
    hash.sha256(0, filesize) == "0b54fb4e5cab6274b4604abe2ef2514f11e5c61ccd0eb5006075b1770665f0d4"
}
```

### Sample 40: `5343115d212ba599`

| Field | Value |
|---|---|
| SHA-256 | `5343115d212ba59929bc32e42f33689f683982a0c660297029e6892316a1226e` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-31 00:40:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e4554da401092edf1682934740ea322` |
| SHA-1 | `522d769abe2d117c10b389018d5626ea0c447533` |
| SHA-256 | `5343115d212ba59929bc32e42f33689f683982a0c660297029e6892316a1226e` |
| SHA3-384 | `da54ee37756d0a873876dd2873b5a5f18593830d85077b28b5a32e85cd2839f7276406f88502a567ac3c25aa6f1fc79b` |
| TLSH | `T11C836AC2B747D0F0F8260635217BE7364677E13E0069DA42D769DC32ED12641EB6A3AD` |
| TELFHASH | `t1f0312afb1f7e0cf8f3d0a850c31e5fd15a19e67b495136b54572982822abdc194bac38` |
| SSDEEP | `1536:dIEpuaRPFkawuF1DMjxj3jRBbE3kcE4+LDVyfDlyOiB5:dwaFkawy1DMh3jbE3tEnfwAOiB5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_5343115d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5343115d212ba59929bc32e42f33689f683982a0c660297029e6892316a1226e"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-31 00:40:49"
  condition:
    hash.sha256(0, filesize) == "5343115d212ba59929bc32e42f33689f683982a0c660297029e6892316a1226e"
}
```

### Sample 41: `5fc0a59adeec5452`

| Field | Value |
|---|---|
| SHA-256 | `5fc0a59adeec5452af90ecd17f5d909309e86c6ae632fde01748a1e7814d823d` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-31 00:40:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59ecb08f97c9626c6a4784fd01481108` |
| SHA-1 | `b26b65e44f9faa35028b03a04f1ed8b6c420300a` |
| SHA-256 | `5fc0a59adeec5452af90ecd17f5d909309e86c6ae632fde01748a1e7814d823d` |
| SHA3-384 | `ab1c9b49d1c9965161447f621bc1939a578b354c53bdccfbe118d1e51f0eaa8d1cd1fa5d7527dff4157c67c9d1b901e4` |
| TLSH | `T1A30302B7998E156EC82D50BC0175B26B0050C03EF298E2C5C6F5A0B731FAB79B95D1F9` |
| SSDEEP | `768:3AOfJjljkAJyWrtBF5ptrHbfF/EBQXpkZfinZ5wElnbcuyD7UHQRjO:QOzQAsyt7JXpKfVElnouy8Hyi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_5fc0a59a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc0a59adeec5452af90ecd17f5d909309e86c6ae632fde01748a1e7814d823d"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-31 00:40:26"
  condition:
    hash.sha256(0, filesize) == "5fc0a59adeec5452af90ecd17f5d909309e86c6ae632fde01748a1e7814d823d"
}
```

### Sample 42: `0a75f316cdc7e7cd`

| Field | Value |
|---|---|
| SHA-256 | `0a75f316cdc7e7cd61881368081f801ee7b63a98174de6cea80f9da85cddc945` |
| Family label | `Mirai` |
| File name | `nz.spc` |
| File type | `elf` |
| First seen | `2026-07-31 00:39:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b69b8eb6e841c0e6172f54d9778f2494` |
| SHA-1 | `f64af890b9989e925cd4ea74da8c0a142b053de3` |
| SHA-256 | `0a75f316cdc7e7cd61881368081f801ee7b63a98174de6cea80f9da85cddc945` |
| SHA3-384 | `49a0c013664f4e735db581e6ab355a998346b7f1862d0ff06e1524b2f723a3c3b03c483eef4cc45b0cb0e314eb52ad0c` |
| TLSH | `T12D934922FD75293BC4C4A57722F34335F2F6478A25A88A1F7D610E8DAF2564032A76F4` |
| SSDEEP | `1536:vh6LzKznKgsovsJEcrDygx9FRHuFWYCsuut9Go957QRQXWot7OR+fa:Ziq3gxXuHGoP78b7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_0a75f316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a75f316cdc7e7cd61881368081f801ee7b63a98174de6cea80f9da85cddc945"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-07-31 00:39:21"
  condition:
    hash.sha256(0, filesize) == "0a75f316cdc7e7cd61881368081f801ee7b63a98174de6cea80f9da85cddc945"
}
```

### Sample 43: `60bc107df8681a70`

| Field | Value |
|---|---|
| SHA-256 | `60bc107df8681a7088dbba0e7198044cd2c4bc8a97ab80ed4e17389ce8cc3d75` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-31 00:38:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60480490681a9957bf9e0a1b6248c6a7` |
| SHA-1 | `3300412561a3f97b0e309a2fa833fb3eba41cc85` |
| SHA-256 | `60bc107df8681a7088dbba0e7198044cd2c4bc8a97ab80ed4e17389ce8cc3d75` |
| SHA3-384 | `2dc00b6d97527efe8161d9568be485d9e124b6dfa778dbd653a04fdc048224679da97bd1b5b2ed6fe5a561c4e0c6c93d` |
| TLSH | `T1D6935B13B9C480FCC849C13087AFB536D963F17E1279B29B73D4EA167E8DE511E6A680` |
| TELFHASH | `t1ab3104b279aa1c90e0ebe9a6b307f1e918350d2005e136f5e9b294f3ef053d54d72856` |
| SSDEEP | `1536:Ac50J45j1WS60TTxMuQQ8vilyxAwuV1h1ss6fuf55nulEJHWIt:Rf5j1W0TTxR8yyx4V1h1ss6fS5ncEIK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_60bc107d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60bc107df8681a7088dbba0e7198044cd2c4bc8a97ab80ed4e17389ce8cc3d75"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-31 00:38:31"
  condition:
    hash.sha256(0, filesize) == "60bc107df8681a7088dbba0e7198044cd2c4bc8a97ab80ed4e17389ce8cc3d75"
}
```

### Sample 44: `b277ac8ece6cb1a4`

| Field | Value |
|---|---|
| SHA-256 | `b277ac8ece6cb1a417fbad35fac655fc28036b7529bfbaa34bc36b293388a67c` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-31 00:38:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49ee9a4e871b2cbebb6a0f8690d3c656` |
| SHA-1 | `48c864d22edcabc30fe5c6c2bc06dd9f4ab6e2e9` |
| SHA-256 | `b277ac8ece6cb1a417fbad35fac655fc28036b7529bfbaa34bc36b293388a67c` |
| SHA3-384 | `a659023d919a452a8e7e9cb10c7453f4efaa233dc606b746847325541653f0031208bb3b2ea42689a384a13eabd35ed1` |
| TLSH | `T12713F297917BE932C5FA2CBA870FC2C1DF321DEBD969AE1F04995BAC585B240E0107C0` |
| SSDEEP | `768:GcA1khiEVA0wZmSuoVgswtYOvROxi4QuoY56Ti6ev4PKYx0Qy:LOEVgoLf+i4Qc6TrDTy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_b277ac8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b277ac8ece6cb1a417fbad35fac655fc28036b7529bfbaa34bc36b293388a67c"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-31 00:38:17"
  condition:
    hash.sha256(0, filesize) == "b277ac8ece6cb1a417fbad35fac655fc28036b7529bfbaa34bc36b293388a67c"
}
```

### Sample 45: `93f1112efb938ede`

| Field | Value |
|---|---|
| SHA-256 | `93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647` |
| Family label | `WannaCry` |
| File name | `93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647` |
| File type | `exe` |
| First seen | `2026-07-31 00:15:37` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3ebd1db429e9ec95e75b8daaf43e2b3` |
| SHA-1 | `b3344fd24a3b750d6c90baac3316af342a41b298` |
| SHA-256 | `93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647` |
| SHA3-384 | `8cd55aa728369840b706a6ff299923ddf02adf619d59a6dabaee4bf7be7803a4396d4560fb51d3afd8092bde86613e5a` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T141363344A2A862BCE0A10AF444B38F25A7777C5597BA960F5380426F1D73F4AEFE0F15` |
| SSDEEP | `98304:DyDqPoBez1nGxcSUDk36SAEdhvxWa9P593RkAVp2a:DyDqP51Gxcxk3ZAEUadzRkc4a` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_045_93f1112e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647"
    family = "WannaCry"
    file_name = "93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647"
    file_type = "exe"
    first_seen = "2026-07-31 00:15:37"
  condition:
    hash.sha256(0, filesize) == "93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647"
}
```

### Sample 46: `589e46d07f1239dd`

| Field | Value |
|---|---|
| SHA-256 | `589e46d07f1239dd6b8b07a00d5739279648863d9cc78ced1a05fb034fc16122` |
| Family label | `NanoCore` |
| File name | `DA3635D346D58158CB0E09ADDD12F5B2.exe` |
| File type | `exe` |
| First seen | `2026-07-31 00:15:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da3635d346d58158cb0e09addd12f5b2` |
| SHA-1 | `ffa21433f4d9994417951617ce8b089fe632ecc5` |
| SHA-256 | `589e46d07f1239dd6b8b07a00d5739279648863d9cc78ced1a05fb034fc16122` |
| SHA3-384 | `edc9b9aba6d78ef42eac7d34ca8de3c68f1503f89918b70d2fbbb379c2a25b501f53e0310def01a7502a959a876bd709` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A114CF563BA84A2FE2DE82B9611201139379C2E798C3F7DE68D454B79F277E10A071D3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM55Yi2H5fni/MuQfKK:MLV6Btpmk+YHtniY1` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_046_589e46d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "589e46d07f1239dd6b8b07a00d5739279648863d9cc78ced1a05fb034fc16122"
    family = "NanoCore"
    file_name = "DA3635D346D58158CB0E09ADDD12F5B2.exe"
    file_type = "exe"
    first_seen = "2026-07-31 00:15:04"
  condition:
    hash.sha256(0, filesize) == "589e46d07f1239dd6b8b07a00d5739279648863d9cc78ced1a05fb034fc16122"
}
```

### Sample 47: `b2388fb3fedb1d62`

| Field | Value |
|---|---|
| SHA-256 | `b2388fb3fedb1d62f7a6cd1719613b5f298c56e677de981f339550a6b7a3daf3` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-31 00:14:53` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, telegram, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdd4f264cbeaf1e092a6f6b4932d56da` |
| SHA-1 | `2a4326bbaa5ab0544d78bce237722c65ff35ccd9` |
| SHA-256 | `b2388fb3fedb1d62f7a6cd1719613b5f298c56e677de981f339550a6b7a3daf3` |
| SHA3-384 | `581b7692a5916bb9029b22ea55725ebea778a8e2353e9faa0988d1435d9a29c02496ab03271758a434b2dde6fef5ad73` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11FF59D07BC9119F5C0AAA23289B326857B747C494F3223D72EA0B6B82F337D15D76B54` |
| SSDEEP | `49152:ObXFqLv0JYztBcje05jdujdxfH5fJXSMrCbmI8TcSKvqP7/xjlotoQhrbTFPNtSQ:Ob88uczNL7tT18G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_b2388fb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2388fb3fedb1d62f7a6cd1719613b5f298c56e677de981f339550a6b7a3daf3"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-31 00:14:53"
  condition:
    hash.sha256(0, filesize) == "b2388fb3fedb1d62f7a6cd1719613b5f298c56e677de981f339550a6b7a3daf3"
}
```

### Sample 48: `c076437d6a30f394`

| Field | Value |
|---|---|
| SHA-256 | `c076437d6a30f394ea3f97331987884228703b350026da16337e7c1b4d740b66` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-31 00:13:13` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, telegram, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33949eaabd8ab52d2bc39a1b21ea3dc2` |
| SHA-1 | `8714303539a5d6401b37d729c801dfa8020bd6cf` |
| SHA-256 | `c076437d6a30f394ea3f97331987884228703b350026da16337e7c1b4d740b66` |
| SHA3-384 | `000d82cef2ce928dfcb157e85eaaeed64d9b51a639c63003160369b7b09012c7a2ac68948e93343fcef7a4fc10a91c35` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17FE59D077CD059EAC4A9973199B75291BB74BC480F3223DB2E40B6782FB2BD09D72B54` |
| SSDEEP | `49152:6x6qIlPFgVnsZfso0QnjtBM6UNnI8wP4BfZzT98jbN:6CipvQYIS9K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_c076437d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c076437d6a30f394ea3f97331987884228703b350026da16337e7c1b4d740b66"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-31 00:13:13"
  condition:
    hash.sha256(0, filesize) == "c076437d6a30f394ea3f97331987884228703b350026da16337e7c1b4d740b66"
}
```

### Sample 49: `c50a08b67bbe92e4`

| Field | Value |
|---|---|
| SHA-256 | `c50a08b67bbe92e4afae7bb28b33af820001aa384ee82ad1a88e16d623c14e6d` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-31 00:11:00` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, telegram, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25ce92092fefdcff7acde8689c4cfd8c` |
| SHA-1 | `dd36453cdc9becd6b6366bcc0f9eeb706925b3c4` |
| SHA-256 | `c50a08b67bbe92e4afae7bb28b33af820001aa384ee82ad1a88e16d623c14e6d` |
| SHA3-384 | `bd42df97507e3d5d997e76628564552ac1bde2f11b96ab7d6a23448e9cb7de63483472447d6958c33c37b4f24b2d9ed8` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T190F5AE47BCA156E9C4AA923188B712527B34BC194F3133DB2EA0B7382F727D09D76B54` |
| SSDEEP | `49152:3dFQq8Lmm4sw90dYiPP9G1dnzwyqUOr4oAvvjJ3odD5MB8zb:3n7HWYtq8vlDB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_c50a08b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c50a08b67bbe92e4afae7bb28b33af820001aa384ee82ad1a88e16d623c14e6d"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-31 00:11:00"
  condition:
    hash.sha256(0, filesize) == "c50a08b67bbe92e4afae7bb28b33af820001aa384ee82ad1a88e16d623c14e6d"
}
```

### Sample 50: `847daefabc7cf5e4`

| Field | Value |
|---|---|
| SHA-256 | `847daefabc7cf5e466c8540fc331a2ee340fe286aaa7127b20527beaf8b8fce2` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-31 00:05:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b400fc3cc711fbaa53ad10cbbbac1c48` |
| SHA-1 | `2ce8972f8bee8e93d3ce16ff42dd6c92f8591f7c` |
| SHA-256 | `847daefabc7cf5e466c8540fc331a2ee340fe286aaa7127b20527beaf8b8fce2` |
| SHA3-384 | `8f98d6bf31ad979225fb0d6760861ae78e0db187d24a259a9cfa1b0a358396b4a9d1f1036f4a26b7650894858e8ce783` |
| TLSH | `T138C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:N8vCB+25j6es8Rql9FYpMSUpi+20qUpi+20YQX:N8l25JSd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_847daefa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847daefabc7cf5e466c8540fc331a2ee340fe286aaa7127b20527beaf8b8fce2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-31 00:05:37"
  condition:
    hash.sha256(0, filesize) == "847daefabc7cf5e466c8540fc331a2ee340fe286aaa7127b20527beaf8b8fce2"
}
```

### Sample 51: `223f03fcc04e7c0f`

| Field | Value |
|---|---|
| SHA-256 | `223f03fcc04e7c0f0fdc1b5ffaa30ce817269ad1903d25036887bea299cdf187` |
| Family label | `unknown` |
| File name | `Setup64x.exe` |
| File type | `exe` |
| First seen | `2026-07-30 23:55:48` |
| Reporter | `Kejult` |
| Tags | `exe, signed, trojan, VMProtect` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49001016110fad151822a3554125c4d0` |
| SHA-1 | `1d12f264ae667eb587a7a28434afabfc23a0f664` |
| SHA-256 | `223f03fcc04e7c0f0fdc1b5ffaa30ce817269ad1903d25036887bea299cdf187` |
| SHA3-384 | `79a982ce08bd4826fe89c107fa14e3c31d98b0d87e7c7b684035bf4cf0628f566611c058ccffd6af00aa7a33dd6413ff` |
| IMPHASH | `c50b742aefae4e604003304a53593dc6` |
| TLSH | `T1981723C77FDAD3A8C0824E30559283DB22C0F89985EE865F35CE6C07B850DD64E8B676` |
| SSDEEP | `393216:26A3RAQt9NO7qRWq4ZUwdz2xMkMW/YOpU:26whWqWfgxMkr/YOpU` |
| ICON-DHASH | `70c88c92968ec070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_223f03fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "223f03fcc04e7c0f0fdc1b5ffaa30ce817269ad1903d25036887bea299cdf187"
    family = "unknown"
    file_name = "Setup64x.exe"
    file_type = "exe"
    first_seen = "2026-07-30 23:55:48"
  condition:
    hash.sha256(0, filesize) == "223f03fcc04e7c0f0fdc1b5ffaa30ce817269ad1903d25036887bea299cdf187"
}
```

### Sample 52: `8cd988e1f749a5e0`

| Field | Value |
|---|---|
| SHA-256 | `8cd988e1f749a5e008128df6f2b7da55c2760fbcdf414f26260331db723e6a15` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-30 23:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `326177e27aef5d34b2ae4d5c9935be62` |
| SHA-1 | `0187cf883e634bb9c8069c1ccbe1323a055c4e65` |
| SHA-256 | `8cd988e1f749a5e008128df6f2b7da55c2760fbcdf414f26260331db723e6a15` |
| SHA3-384 | `45f70aa763d4b2b86ccdec5fb91be9cfed0384381ebacb1ba302be9d3843e4ed21a746ea890497e799cae19be0fa322a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D3E63308B6D502EDEDB3413DDDB088A5E63934A54BB2CACF1F4897A59C632E04D3E257` |
| SSDEEP | `393216:jDWmx9Of0xB1PXMCHWUjXkcuI3/PGTAI:jD1OfCvPXMb8XxH/O7` |
| ICON-DHASH | `e8e864e0d8e8e848` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_8cd988e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cd988e1f749a5e008128df6f2b7da55c2760fbcdf414f26260331db723e6a15"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 23:52:32"
  condition:
    hash.sha256(0, filesize) == "8cd988e1f749a5e008128df6f2b7da55c2760fbcdf414f26260331db723e6a15"
}
```

### Sample 53: `8489605870dd2735`

| Field | Value |
|---|---|
| SHA-256 | `8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead` |
| Family label | `WannaCry` |
| File name | `8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead` |
| File type | `exe` |
| First seen | `2026-07-30 23:15:37` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2743ee280188d4250ab5aa6528a20448` |
| SHA-1 | `749de482e4b125876ba05f88958e4f4c279abfc1` |
| SHA-256 | `8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead` |
| SHA3-384 | `f19e6263386fbebec2a55a314dd79025414f2e5353ebf571a88732f7de516cb92253552a297c62d514ac1fddf3d0962b` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1F236238932AC81FCD1061674D4B78E26F3B37C6A22BE570F9B40853A1D53B86BB64753` |
| SSDEEP | `49152:jn2nRMSPbcBVQej/1INx+TSqTdXeRdhnv:DyRPoBhz1axcSU4dhv` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_053_84896058
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead"
    family = "WannaCry"
    file_name = "8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead"
    file_type = "exe"
    first_seen = "2026-07-30 23:15:37"
  condition:
    hash.sha256(0, filesize) == "8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead"
}
```

### Sample 54: `3f9f8dd458b0a1f8`

| Field | Value |
|---|---|
| SHA-256 | `3f9f8dd458b0a1f82c47dfdde874f609ae5f451644fb96c85c95403d2f4816a4` |
| Family label | `unknown` |
| File name | `Zeta_Launcher_v2.4.3.zip` |
| File type | `zip` |
| First seen | `2026-07-30 23:15:09` |
| Reporter | `Kejult` |
| Tags | `exe, stealc, stealer, telegram, vidar, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27a41dad272c5f71c6224d324a534f6b` |
| SHA-1 | `82b8a27234600f464bc58abe6a8b96bd10d031f1` |
| SHA-256 | `3f9f8dd458b0a1f82c47dfdde874f609ae5f451644fb96c85c95403d2f4816a4` |
| SHA3-384 | `2b4324493d4c6a9a99e51d85fbe60970102435274aee51257813b9050709fcb293b7476fd85f5327b20c10a6751ec01f` |
| TLSH | `T18DC55269D78AE5FAC09C5170625F8BAF36B185CD47A1820AC7228C6E2CD7FC47F60D46` |
| SSDEEP | `49152:hiYuqqGi6ddJds5HJXjwnxDEQEUzlYKUeT2sZ3ywndI:uGZddJm5HJknxBEYOKUadI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_3f9f8dd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f9f8dd458b0a1f82c47dfdde874f609ae5f451644fb96c85c95403d2f4816a4"
    family = "unknown"
    file_name = "Zeta_Launcher_v2.4.3.zip"
    file_type = "zip"
    first_seen = "2026-07-30 23:15:09"
  condition:
    hash.sha256(0, filesize) == "3f9f8dd458b0a1f82c47dfdde874f609ae5f451644fb96c85c95403d2f4816a4"
}
```

### Sample 55: `c2ae41bff71b9d5d`

| Field | Value |
|---|---|
| SHA-256 | `c2ae41bff71b9d5dd6d5845f1cda894729f406db9501c3afca402420b91515c0` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-30 22:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f8fc068a9464e9b3d7f052ef53ea5ec` |
| SHA-1 | `d2e7c31d09fd9fc6908b1c005756bbf10eafcda7` |
| SHA-256 | `c2ae41bff71b9d5dd6d5845f1cda894729f406db9501c3afca402420b91515c0` |
| SHA3-384 | `232fb761c7d9db469b54e15a1058dd09b9ac9a1d45ba75caa86a17f24611e08bdab424954c8be9fb2bee348277e78bf5` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T170E6332865D011FEEAB7413DFBA1126195B6B8715BB3CAEB536483507E231E08C3E727` |
| SSDEEP | `393216:srmzzRVqd6ugXkmp89IT14/XMCHWUjXdcuI3/PGTAI:Gm/RVqd6uaPNZ4/XMb8XqH/O7` |
| ICON-DHASH | `51f0d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_c2ae41bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2ae41bff71b9d5dd6d5845f1cda894729f406db9501c3afca402420b91515c0"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 22:52:31"
  condition:
    hash.sha256(0, filesize) == "c2ae41bff71b9d5dd6d5845f1cda894729f406db9501c3afca402420b91515c0"
}
```

### Sample 56: `58b16700b8a3b8f0`

| Field | Value |
|---|---|
| SHA-256 | `58b16700b8a3b8f0db2fb2e14b8c3e835270111518e67239b373a81ffd265b9a` |
| Family label | `ValleyRAT` |
| File name | `8F93AA8AA04CA6C13477542655CDB74B.exe` |
| File type | `exe` |
| First seen | `2026-07-30 22:45:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f93aa8aa04ca6c13477542655cdb74b` |
| SHA-1 | `8a68d580a0bb9f62923bf112a467cb723e9f1b5d` |
| SHA-256 | `58b16700b8a3b8f0db2fb2e14b8c3e835270111518e67239b373a81ffd265b9a` |
| SHA3-384 | `e42a7d654dbe85e6b811a6726cdc86246edd6721a61590f77e2be08f8eeeb8593202e73b3c968efd3511dc259f813f8d` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T11416023FF28B653EE02A1A357A72E110943B7A6164168C1696ECF88CCF355711E3F687` |
| SSDEEP | `98304:R5OazgrwE36ts/7/kB1Wjpe7nYOX/gL7kBO5WIw0XDR6Pkta:LAwdtsD/mW1GrXI3kG9t6Pkta` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_056_58b16700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58b16700b8a3b8f0db2fb2e14b8c3e835270111518e67239b373a81ffd265b9a"
    family = "ValleyRAT"
    file_name = "8F93AA8AA04CA6C13477542655CDB74B.exe"
    file_type = "exe"
    first_seen = "2026-07-30 22:45:09"
  condition:
    hash.sha256(0, filesize) == "58b16700b8a3b8f0db2fb2e14b8c3e835270111518e67239b373a81ffd265b9a"
}
```

### Sample 57: `9117cbbaf4a200b5`

| Field | Value |
|---|---|
| SHA-256 | `9117cbbaf4a200b534763f9c129d0f1a7bfca9d73d9a1fbfe97564790405e902` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-30 22:43:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d03e3df578be46ce6fe5a4b0406eb54` |
| SHA-1 | `3d579edd9de3109c44ac49cc9c87a3943075100d` |
| SHA-256 | `9117cbbaf4a200b534763f9c129d0f1a7bfca9d73d9a1fbfe97564790405e902` |
| SHA3-384 | `bdd4f7648309fcf511d73f1d786373720c65c9f7fa61fe07f26b3f2dccfd0f29544d7d272ff651f8976ed211b9405f6c` |
| TLSH | `T1B80186C74510B910405D9E5E66D766E0B410D3CE459A0B68BFDC5E7DF78C814B137F98` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaSL5uGz06X0zlf7:e9Qp+MsSLnga0zlf7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_9117cbba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9117cbbaf4a200b534763f9c129d0f1a7bfca9d73d9a1fbfe97564790405e902"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-30 22:43:14"
  condition:
    hash.sha256(0, filesize) == "9117cbbaf4a200b534763f9c129d0f1a7bfca9d73d9a1fbfe97564790405e902"
}
```

### Sample 58: `ca116b3d7caea85d`

| Field | Value |
|---|---|
| SHA-256 | `ca116b3d7caea85d448cc674087381d06902d80f2d2842e8dc22cd4b266379b5` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-30 22:31:00` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d24420d2f8ffbb8cec06376b9548ca1b` |
| SHA-1 | `05b21b6fcf2b60f7e617ab76e62150b3dd7047b3` |
| SHA-256 | `ca116b3d7caea85d448cc674087381d06902d80f2d2842e8dc22cd4b266379b5` |
| SHA3-384 | `cc45cb68d396ef38fb7eb070f995a97aedd190f611c29c63840906e860207a01c2be654dbca643142d9fa61d610dc83b` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T15722282E6E890072E79049F416B54A4D657E45732BC6B3EBF373C5990EEA2448042AEF` |
| SSDEEP | `192:z0oVW0BJBqcx+ep/AX5PFJxTEZmFhSKcq:z0oLBecwCAX5PFwZ2` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_058_ca116b3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca116b3d7caea85d448cc674087381d06902d80f2d2842e8dc22cd4b266379b5"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 22:31:00"
  condition:
    hash.sha256(0, filesize) == "ca116b3d7caea85d448cc674087381d06902d80f2d2842e8dc22cd4b266379b5"
}
```

### Sample 59: `79cab94e4ca816ac`

| Field | Value |
|---|---|
| SHA-256 | `79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee` |
| Family label | `WannaCry` |
| File name | `79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee` |
| File type | `exe` |
| First seen | `2026-07-30 22:16:31` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edc0d904974de3d03e654e98d24bfe9e` |
| SHA-1 | `1fe32ef5a3ca6ad3f31a71b280421efec3cd255f` |
| SHA-256 | `79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee` |
| SHA3-384 | `c8f5947b761c7071178b1f4e123e52714bdd79ed708e8b1c4671dc55cfe102e3633aeb9c186faf54cf69bab128709233` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1C336125932AC80FCD11B6274A4B34E26E7B37C96227D930F8B5487660E13790BF78B56` |
| SSDEEP | `24576:jbLgWbLgddQhfdmMSirYbcMNgef0QeQjG:jnXnAQqMSPbcBVQej` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_059_79cab94e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee"
    family = "WannaCry"
    file_name = "79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee"
    file_type = "exe"
    first_seen = "2026-07-30 22:16:31"
  condition:
    hash.sha256(0, filesize) == "79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee"
}
```

### Sample 60: `2aab00defb69f62e`

| Field | Value |
|---|---|
| SHA-256 | `2aab00defb69f62ea24fcf2d2afc85750e1e24bc67a6e2fed6166438dfc1172d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-30 21:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3e025e96594d5b774b54e8859f9dc04` |
| SHA-1 | `c207405903d482df122e6ceec35c61b0e61ce6cc` |
| SHA-256 | `2aab00defb69f62ea24fcf2d2afc85750e1e24bc67a6e2fed6166438dfc1172d` |
| SHA3-384 | `d8f45b19b300665d3c431ffa7f6b8de614f22450371085ee7050f4abe611995e438267c047da397ac1c0e2429f3c2c09` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T171E6332969F412EEEBB3023CE9E0ABC5C099742B0771C8DB57A407497E472F54D3926B` |
| SSDEEP | `393216:V2j+2SyspO+NQDPWRwSFpzOPKS3QvkTOXMCHWUjX3cuI3/PGTAI:V2g11NQqK+zOPgv4OXMb8XMH/O7` |
| ICON-DHASH | `5479d0f0e0e971b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_2aab00de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2aab00defb69f62ea24fcf2d2afc85750e1e24bc67a6e2fed6166438dfc1172d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 21:52:31"
  condition:
    hash.sha256(0, filesize) == "2aab00defb69f62ea24fcf2d2afc85750e1e24bc67a6e2fed6166438dfc1172d"
}
```

### Sample 61: `0262c43ca22a7fb7`

| Field | Value |
|---|---|
| SHA-256 | `0262c43ca22a7fb751f38117641a206220b0ab116cd79864c7336207dffa7358` |
| Family label | `unknown` |
| File name | `Purchase Order-AUG.js` |
| File type | `js` |
| First seen | `2026-07-30 21:29:29` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd6100eb5cb1493d6f9c071fe2836810` |
| SHA-1 | `18b8f98f8c2108a428a2ba7df53fcaa7eeeea619` |
| SHA-256 | `0262c43ca22a7fb751f38117641a206220b0ab116cd79864c7336207dffa7358` |
| SHA3-384 | `c16d30585d5953793776899d3e3cefc9de0987f1bfdf206d425de53ce886ca27f4a8c7997f6aaeec740910475277601e` |
| TLSH | `T19E958E354B1E3999A2BB3A586EEF9FCDF2D7EC994539469D131FC2006DC580229C8B34` |
| SSDEEP | `12288:RsvH0m3uUXpkgGxEyDF2gvB9t/d8Nk2yQxc6vSPSJDdcHhlRg90BreF/4IFukH+f:xz6alOOj4Gv5PHR3qP4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_0262c43c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0262c43ca22a7fb751f38117641a206220b0ab116cd79864c7336207dffa7358"
    family = "unknown"
    file_name = "Purchase Order-AUG.js"
    file_type = "js"
    first_seen = "2026-07-30 21:29:29"
  condition:
    hash.sha256(0, filesize) == "0262c43ca22a7fb751f38117641a206220b0ab116cd79864c7336207dffa7358"
}
```

### Sample 62: `a0f85de525c9f112`

| Field | Value |
|---|---|
| SHA-256 | `a0f85de525c9f1126dd701b4b9a50237ef6dd1605836da64e983e49a2c50d268` |
| Family label | `unknown` |
| File name | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9c56c8942f9468ce8480d954cc377a5` |
| SHA-1 | `1f5c8fdef37bf62da21929d4cfb609d8142671f1` |
| SHA-256 | `a0f85de525c9f1126dd701b4b9a50237ef6dd1605836da64e983e49a2c50d268` |
| SHA3-384 | `49c4b370592bb9d15878e96696df471efeff45ecd93c9a51f3ab1f03d636b0420d2b4f43124234e7f1aa89df2664e20c` |
| TLSH | `T127365C4BF1A324FCC19BD434875B99A2B935785901207EBB66C4EA302B33F605B59F72` |
| TELFHASH | `t10f7242f452d538e1a5928a59dbb6f974da3318fa13d0b5b08837bc53cfa0f490d6a812` |
| SSDEEP | `98304:rMuNn060dCJVDTXnMiepG1mnBLBtaYJ9uKLKxI/2AQzOi+EgY:xxX0dBpG1mnBbGi2bG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_a0f85de5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0f85de525c9f1126dd701b4b9a50237ef6dd1605836da64e983e49a2c50d268"
    family = "unknown"
    file_name = "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:55"
  condition:
    hash.sha256(0, filesize) == "a0f85de525c9f1126dd701b4b9a50237ef6dd1605836da64e983e49a2c50d268"
}
```

### Sample 63: `e98f72882d520f1a`

| Field | Value |
|---|---|
| SHA-256 | `e98f72882d520f1a1d17036847154b84db0b44a463f75d2d12af1bb9c48fff95` |
| Family label | `unknown` |
| File name | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7efed36b9ca6a61ed7505aeeec20706` |
| SHA-1 | `553b4850d6c015412a2cdd169ef7a30caec1f8c8` |
| SHA-256 | `e98f72882d520f1a1d17036847154b84db0b44a463f75d2d12af1bb9c48fff95` |
| SHA3-384 | `a3c5572df1dcd6b35f44d1611924c5f344a78d52ebc387f65549006419ff9cffa50a54ba230ad82e15698c4e2fbd8d10` |
| TLSH | `T16E368C88E793E0F4E26308F0559BD7F661201A355057F6F2EB8A6F65B4337806F0936A` |
| TELFHASH | `t19282ad73048864e977f08407c3af7234cba6e0e7679169f125f66ce056f3cc2a626d68` |
| SSDEEP | `98304:nfAcKI9cEJb9KG/lfvUeQTZlvy8JSsFc1EYksKS/Dee8oSkmb+Q2H:nfAcx9cEJb9KyfMeQpNFYvA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_e98f7288
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e98f72882d520f1a1d17036847154b84db0b44a463f75d2d12af1bb9c48fff95"
    family = "unknown"
    file_name = "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:49"
  condition:
    hash.sha256(0, filesize) == "e98f72882d520f1a1d17036847154b84db0b44a463f75d2d12af1bb9c48fff95"
}
```

### Sample 64: `b9679a478bea2fb3`

| Field | Value |
|---|---|
| SHA-256 | `b9679a478bea2fb3eb238e75139e20fff5652b1b2495e6cc66e9f7110e3f4339` |
| Family label | `unknown` |
| File name | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b85409306e67fc3be24ab3b4c5e8cffa` |
| SHA-1 | `329f5ca23327d931a8f6b4503282e3b71c2e10b3` |
| SHA-256 | `b9679a478bea2fb3eb238e75139e20fff5652b1b2495e6cc66e9f7110e3f4339` |
| SHA3-384 | `8486292072443edb4629add864cb2b5c7f5c207b7850033c296e5cb4551ebba9c944cb9151932733bb7523237e0963d1` |
| TLSH | `T1A4168C94ED0F3912F3C7E23CCF4A97E1761735A4E32390B279D2524DC59E9E4CAA2A11` |
| SSDEEP | `98304:1ykIx9+FV4Ytc+TLqvdqJmiBwQQxax4+gFTg:IkIx9CGYdTmvMS7nc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_b9679a47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9679a478bea2fb3eb238e75139e20fff5652b1b2495e6cc66e9f7110e3f4339"
    family = "unknown"
    file_name = "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:44"
  condition:
    hash.sha256(0, filesize) == "b9679a478bea2fb3eb238e75139e20fff5652b1b2495e6cc66e9f7110e3f4339"
}
```

### Sample 65: `431f2f7b389128c8`

| Field | Value |
|---|---|
| SHA-256 | `431f2f7b389128c829dcd139f4f1c3bf95411ea14b87e271c0b04ad6469ba896` |
| Family label | `unknown` |
| File name | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5616d901f351402fc9e98376ecf0671b` |
| SHA-1 | `fc32882e6dd78c8c248e7d4d22cc61aea355e4da` |
| SHA-256 | `431f2f7b389128c829dcd139f4f1c3bf95411ea14b87e271c0b04ad6469ba896` |
| SHA3-384 | `14bcc70f309cde1775d927c6773f868c91cf4428ccbef3f43d4a145d3ad6376535474b95f69bb58461a98da1c734c70a` |
| TLSH | `T180065B81FC418F52C9D03A7BF76E828833530779D2EA70069D255B7467DF99A0F3AA42` |
| TELFHASH | `t14531008c4dc539b4f3e897d011b925a594bf38be8f2244e74a5a76bb9d03dc13150407` |
| SSDEEP | `49152:RO39oEk7AnNAcJBpALQk/Zn39HM9jnmguplA:R/Ekm6cJBpARns9jnmrplA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_431f2f7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "431f2f7b389128c829dcd139f4f1c3bf95411ea14b87e271c0b04ad6469ba896"
    family = "unknown"
    file_name = "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:36"
  condition:
    hash.sha256(0, filesize) == "431f2f7b389128c829dcd139f4f1c3bf95411ea14b87e271c0b04ad6469ba896"
}
```

### Sample 66: `f0aa83bbbd2c75e2`

| Field | Value |
|---|---|
| SHA-256 | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` |
| Family label | `unknown` |
| File name | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:08` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f47ecc10bc008ad26e504897b940f22` |
| SHA-1 | `94e6098bab3b1d1d2930ab87e0f82f5fe3ac1d7b` |
| SHA-256 | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` |
| SHA3-384 | `45e2b1cc8a7ffde348598f4c87a2294d7b512c8c9c90dc2f2a0f77b3e7ebfa225ccf8ea8fe87ce25fe60d426b644b0b2` |
| TLSH | `T198953328DE2CEAED8237AB645A90C2CFCFC41E453A2FE551297C91BC53DD4E69C43848` |
| SSDEEP | `49152:YrtUegEsxwWb+vck/XialwAyaIkY5JN1DByF1IzjrojaQeS7sf:YrnsTw9/vy0mN1Hnasf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_f0aa83bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
    family = "unknown"
    file_name = "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:08"
  condition:
    hash.sha256(0, filesize) == "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
}
```

### Sample 67: `3f3bf218089d1488`

| Field | Value |
|---|---|
| SHA-256 | `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39` |
| Family label | `unknown` |
| File name | `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:06` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `117dd0c3e5b37e2db85305cc57d34730` |
| SHA-1 | `aa389c5fabc812bea68056224e3c58c6c5e43775` |
| SHA-256 | `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39` |
| SHA3-384 | `192e9cb731340e10cdb963385cdc4e109152449acfc1d3488b50b310e5adf1efa3c0c3ee32b01af024abdba7e9c63d51` |
| TLSH | `T185853341E259D8BCDD07ABC8A52D5D4B672594A367EEFEEE0C8397D821303EE507068C` |
| SSDEEP | `24576:25j9xYk56Ulw+g3kDqEMX8dKQVT2ZfZolXqr8OmF+AzM/qe8NFb8+GDGeMH:Gh/wFkDqEMM7KZo0ECqe8NHQ1K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_3f3bf218
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39"
    family = "unknown"
    file_name = "3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:06"
  condition:
    hash.sha256(0, filesize) == "3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39"
}
```

### Sample 68: `8e1a67a5c03b3cd8`

| Field | Value |
|---|---|
| SHA-256 | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` |
| Family label | `unknown` |
| File name | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:05` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e7e88377aae5459d5acaceae91a80ee` |
| SHA-1 | `c51d1e88476f88e2e0256e272913f419f4694134` |
| SHA-256 | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` |
| SHA3-384 | `620d908c4d6cd5471024c56f55440e77ea4b733e9d726bb9e114c5547396f335c0874588b25bf90db27a891fe156e144` |
| TLSH | `T18D85334A719B318FDC255138B399B67305B327143096BCA29A2EC258F805677DF25CBF` |
| TELFHASH | `t19ab011c800000ec0238b800808eaa80002b0380803f0f0beb300c0aec23800b283a3a0` |
| SSDEEP | `49152:CZLKHlog/V9KHRwKtby2pqJtbxeRXWKMb4TW:ClK6KViwKVyWm9elWrUq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_8e1a67a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70"
    family = "unknown"
    file_name = "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:05"
  condition:
    hash.sha256(0, filesize) == "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70"
}
```

### Sample 69: `d1cac82f44b54b0f`

| Field | Value |
|---|---|
| SHA-256 | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` |
| Family label | `unknown` |
| File name | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:03` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e0328dc8084e6203c09a3e5ea1539f8` |
| SHA-1 | `99be01382e567d68cb9f317fb3c039c17e4315eb` |
| SHA-256 | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` |
| SHA3-384 | `3484a1427de103f3612bac512cd9441968d1107bce419ca222fed86254bdabecb2077e03076cf988b4ad2fcb0388e96e` |
| TLSH | `T11E753371740D0AA9F9F3A91F66575101E5ACED8C041358CE2F3CE6CE669E0DCF6029BA` |
| SSDEEP | `24576:sc6qWRqqRfVMP7Cft/U1QNlMKDZB3EIq5WrSCv55LhFdmQ5Rp6bpgit1ggrcDmU2:4dFkP7ov3DZeoWCvnLDdJHik/DVLwz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_d1cac82f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e"
    family = "unknown"
    file_name = "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:03"
  condition:
    hash.sha256(0, filesize) == "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e"
}
```

### Sample 70: `d70f917e35813a7a`

| Field | Value |
|---|---|
| SHA-256 | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` |
| Family label | `unknown` |
| File name | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` |
| File type | `elf` |
| First seen | `2026-07-30 21:18:02` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ed17cd8d521a329e62321797547a03c` |
| SHA-1 | `379d971c686dfd0d10ed8c1b6bd5fe1ae3dd4f7e` |
| SHA-256 | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` |
| SHA3-384 | `a139a776cf3427b638217af12c434b563a2ff7df47f6ee5c31cad7b8303885570a518d282bf7c777f847fab875d474bb` |
| TLSH | `T1A96533D7D26BE5DADE8128CD50CDE2733AE691F8C3EEA927AC1205908F4BC134257949` |
| SSDEEP | `24576:5MVf5G045SzJ+M0xyHyZ+5OSSuBuAXrECblkU/es5QxxcbF/rVKBygNvdjraYUJr:5KMnaFBHh5O61Lblf2siyprfgFdU0ED/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_d70f917e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141"
    family = "unknown"
    file_name = "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:02"
  condition:
    hash.sha256(0, filesize) == "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141"
}
```

### Sample 71: `c7ba7ec8cb6953a2`

| Field | Value |
|---|---|
| SHA-256 | `c7ba7ec8cb6953a25ab30fd3d9ec6c9422da9a9c9db8dad664667c5d4baa9a55` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-07-30 20:52:39` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `795f84b1d494e91bc85911bc90e48bec` |
| SHA-1 | `b88ff84817045513f9189691b4af6dd5ac7cbc97` |
| SHA-256 | `c7ba7ec8cb6953a25ab30fd3d9ec6c9422da9a9c9db8dad664667c5d4baa9a55` |
| SHA3-384 | `75b175d834573c1dc7df4bc7eda97c2cd183ef39d82d4bbd77cec8e65288143046a7b8652c1a00a57d9b34c7f0eff0c7` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16AA67B07BCD049EAC4AA933189B751927B31BC084F3663D72E90BA782F727D19D76B50` |
| SSDEEP | `49152:cyNuLi3pXeYqJRltK7Ej1RFyLBCkJR3tUwC68Og5:c7QUM7E5RFyLBz/UP6q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_c7ba7ec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7ba7ec8cb6953a25ab30fd3d9ec6c9422da9a9c9db8dad664667c5d4baa9a55"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-30 20:52:39"
  condition:
    hash.sha256(0, filesize) == "c7ba7ec8cb6953a25ab30fd3d9ec6c9422da9a9c9db8dad664667c5d4baa9a55"
}
```

### Sample 72: `76b2713b63e443c8`

| Field | Value |
|---|---|
| SHA-256 | `76b2713b63e443c83a23794087f2cad4b7588e78b0afa9a0fc276dd5de65a226` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-30 20:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3752c08eb40761569cc7c4a90485320` |
| SHA-1 | `dae4a62d13b6f7f6d91151e5d6ec2a3803dcad42` |
| SHA-256 | `76b2713b63e443c83a23794087f2cad4b7588e78b0afa9a0fc276dd5de65a226` |
| SHA3-384 | `82614cb7c78b9343ed996dff83b124d9ad9d3ddfbd9376758ab5c02f9c13bbf1968017bceff31e61c685c48f5b22a0e3` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T16EE6331476E052FEDA73413DE9F1A2A6D06174720B72CBCF478887A1BEA72D0893D647` |
| SSDEEP | `393216:s97ZSvWf/1DA1Obgb+2rtmXMCHWUjXGcuI3/PGTAI:sLSvWf/aJrtmXMb8X7H/O7` |
| ICON-DHASH | `d4f8d1f0e0e971b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_76b2713b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76b2713b63e443c83a23794087f2cad4b7588e78b0afa9a0fc276dd5de65a226"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 20:52:30"
  condition:
    hash.sha256(0, filesize) == "76b2713b63e443c83a23794087f2cad4b7588e78b0afa9a0fc276dd5de65a226"
}
```

### Sample 73: `e71b7fd8a38ace53`

| Field | Value |
|---|---|
| SHA-256 | `e71b7fd8a38ace53045a576a8498f11a81c2d8f66b93086317c250dff5430429` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.MalwareX-gen.27393152` |
| File type | `exe` |
| First seen | `2026-07-30 20:50:45` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e2d4b36f015abe75e8a3be0ff4257e3` |
| SHA-1 | `53f852158655029bf42c478c08c0fd61024fbc0e` |
| SHA-256 | `e71b7fd8a38ace53045a576a8498f11a81c2d8f66b93086317c250dff5430429` |
| SHA3-384 | `f92aa0f838f0f99588fc99de36c372964b43362f74ac1b1305ed6bde68eb4455346311fdd98d841cb5a1bbedb8946ff4` |
| IMPHASH | `8341f477b472c677846eb3e45a02bddf` |
| TLSH | `T195820A87E26104E6C973D53CE652AA1AB5B3B8566B321BDF4B210A1B4F317D4B23CF14` |
| SSDEEP | `384:s3vOEFN8n1zt1o2nWXEd2j9v8bLTBHFBlj8F4a8GCGItwjm:s/oK2WUd2J0bLBFTN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_e71b7fd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e71b7fd8a38ace53045a576a8498f11a81c2d8f66b93086317c250dff5430429"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.MalwareX-gen.27393152"
    file_type = "exe"
    first_seen = "2026-07-30 20:50:45"
  condition:
    hash.sha256(0, filesize) == "e71b7fd8a38ace53045a576a8498f11a81c2d8f66b93086317c250dff5430429"
}
```

### Sample 74: `ae0c7cf73a057246`

| Field | Value |
|---|---|
| SHA-256 | `ae0c7cf73a0572469bd43b4f44bbe38b67ca35a45728c3f2a3cbb37662b44a8f` |
| Family label | `Vjw0rm` |
| File name | `ORDER-0260730-006752.XLS.vbs` |
| File type | `vbs` |
| First seen | `2026-07-30 20:35:08` |
| Reporter | `abuse_ch` |
| Tags | `vbs, Vjw0rm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f86763c1b7866f8bb08e261051eed44` |
| SHA-1 | `33919d9e56093496799ce3ca78e396eb3a58f1de` |
| SHA-256 | `ae0c7cf73a0572469bd43b4f44bbe38b67ca35a45728c3f2a3cbb37662b44a8f` |
| SHA3-384 | `90f103ff726c0c9afba691dafdfb04634298e6dc9205796ea0916c8ae664720ccf5000bc7ce83aa7ea5eb8da88f13e30` |
| TLSH | `T1F9D421684CF8342C2BB750DBD761887FC2BE0FD2815D515E63B4E89663CE6264E6B01E` |
| SSDEEP | `1536:2M6Cyeq57cy04+ceZOFSvTONu8gBeh+Fus++ZeDjP5ijvKejyXLNlmVq8ZB:dgcy0fzZOUv6Nvh+Fc+ZU5ijAp8v` |

#### Technical Assessment

- The sample is tracked as `Vjw0rm` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vjw0rm_074_ae0c7cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0c7cf73a0572469bd43b4f44bbe38b67ca35a45728c3f2a3cbb37662b44a8f"
    family = "Vjw0rm"
    file_name = "ORDER-0260730-006752.XLS.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:35:08"
  condition:
    hash.sha256(0, filesize) == "ae0c7cf73a0572469bd43b4f44bbe38b67ca35a45728c3f2a3cbb37662b44a8f"
}
```

### Sample 75: `1362adc3a121da86`

| Field | Value |
|---|---|
| SHA-256 | `1362adc3a121da862b252c1e9d7beb81fc9d19aa18335555a6771a3685d46cca` |
| Family label | `Mirai` |
| File name | `zero.i486` |
| File type | `elf` |
| First seen | `2026-07-30 20:22:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c7b290060669f6962a7067d401b657c` |
| SHA-1 | `77fe4c2e84864ff63dbe85205f15ac6647e0d5d1` |
| SHA-256 | `1362adc3a121da862b252c1e9d7beb81fc9d19aa18335555a6771a3685d46cca` |
| SHA3-384 | `f5dfc025ab13c6dadfa531c57cbd667abbe58e603c32446baf1ec7a36409eff003d8ebd084d913c0c47da9a3de86b18a` |
| TLSH | `T17753F81DD783EAF0C54206F0504FFB7BA972D8D122A09CF7D7E4BAD699626C1A042E1C` |
| TELFHASH | `t1d9218efa06fe58d8aad49100c19e6f91285df23f769476d046239230371ff82607ac3e` |
| SSDEEP | `1536:+95gYrzdpZgJE9MLYsrlrXYp8sLGOKUpn7Stffj:I5gYrzdpZfYYsrlrXYnGlsneRj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_1362adc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1362adc3a121da862b252c1e9d7beb81fc9d19aa18335555a6771a3685d46cca"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-07-30 20:22:42"
  condition:
    hash.sha256(0, filesize) == "1362adc3a121da862b252c1e9d7beb81fc9d19aa18335555a6771a3685d46cca"
}
```

### Sample 76: `4178cf0bd11cd997`

| Field | Value |
|---|---|
| SHA-256 | `4178cf0bd11cd9977008647ebb6bb12a7ad34c384faab31da66c8dfbf64f72a4` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-30 20:21:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9eb89fdb0346355072616e1f94c9e362` |
| SHA-1 | `c25bc797914ae48de8b9359b6bfa6ac74cef5e12` |
| SHA-256 | `4178cf0bd11cd9977008647ebb6bb12a7ad34c384faab31da66c8dfbf64f72a4` |
| SHA3-384 | `1125450eb4b79a7a6ef852cb71e9f05e05eb6c64d2ae591bf5d280b76b6a485a7527a403596b29a55c1462b9bcdda1e6` |
| TLSH | `T19801C2D6E3109900405ED85E66E766A0B431C3C7254B0F78BF9D443EAB98A14F06BFA8` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha5C8WW8GjF47luS7:e9Qp+Msc8WWDF47AS7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_4178cf0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4178cf0bd11cd9977008647ebb6bb12a7ad34c384faab31da66c8dfbf64f72a4"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-30 20:21:31"
  condition:
    hash.sha256(0, filesize) == "4178cf0bd11cd9977008647ebb6bb12a7ad34c384faab31da66c8dfbf64f72a4"
}
```

### Sample 77: `33adb2cf048181b5`

| Field | Value |
|---|---|
| SHA-256 | `33adb2cf048181b5de75d5dd5c837565a738ebd1350b7953e0dc47a3fb7040fe` |
| Family label | `Mirai` |
| File name | `zero.i486` |
| File type | `elf` |
| First seen | `2026-07-30 20:21:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6961fdf43103cd834f28ecf301a117c` |
| SHA-1 | `a4d51254e08afdf61bfe51d234b05f4a6fd89685` |
| SHA-256 | `33adb2cf048181b5de75d5dd5c837565a738ebd1350b7953e0dc47a3fb7040fe` |
| SHA3-384 | `67dc6f2115806b1df91ba4bdf32495dae82685f0ddbfa8f5a13c6c94dbe2101ecd8abda7030c08e8e236e7b7a0d5242b` |
| TLSH | `T118C2E0F5E1EA1340C2B3307A21CAB6262A41D61DF78C80AE99DC949B8D32F516D1C3CD` |
| SSDEEP | `768:n4V7Z1gi/FN2Wr57S+mHuLGSEnbcuyD7ULWykkA/F:nI91gi/usnmHEGSEnouy8Lzkk4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_33adb2cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33adb2cf048181b5de75d5dd5c837565a738ebd1350b7953e0dc47a3fb7040fe"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-07-30 20:21:29"
  condition:
    hash.sha256(0, filesize) == "33adb2cf048181b5de75d5dd5c837565a738ebd1350b7953e0dc47a3fb7040fe"
}
```

### Sample 78: `38027ca6afc21bd7`

| Field | Value |
|---|---|
| SHA-256 | `38027ca6afc21bd734d86e96b8d3c6016e5afff6d8139b777cb55825a92f8f15` |
| Family label | `RemcosRAT` |
| File name | `1314f9049217e0871f8979cf33b1ac63.exe` |
| File type | `exe` |
| First seen | `2026-07-30 20:15:20` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1314f9049217e0871f8979cf33b1ac63` |
| SHA-1 | `7e70a6772d83ea168b5c4b15e6067ae51a7d0e05` |
| SHA-256 | `38027ca6afc21bd734d86e96b8d3c6016e5afff6d8139b777cb55825a92f8f15` |
| SHA3-384 | `bff6af74d6ecd2da9ce3c237c304ca9b7a300eff787b582cb394afe78b6887eb044544680439bc2f896b6e9ef5c4d1ed` |
| IMPHASH | `7d5125df1b721f19e7f94988d3e3ee5a` |
| TLSH | `T10BB4AF02B6F2C072DA7664300936E735DEBC7C31183699AB63D61D5BBD30151DB39AB2` |
| SSDEEP | `12288:llQAiR49ckiK7JV8AuE4lKC/kPHM9/IsPZSkj/:ll0GcNUJV8i4mHM9/DZB` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_078_38027ca6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38027ca6afc21bd734d86e96b8d3c6016e5afff6d8139b777cb55825a92f8f15"
    family = "RemcosRAT"
    file_name = "1314f9049217e0871f8979cf33b1ac63.exe"
    file_type = "exe"
    first_seen = "2026-07-30 20:15:20"
  condition:
    hash.sha256(0, filesize) == "38027ca6afc21bd734d86e96b8d3c6016e5afff6d8139b777cb55825a92f8f15"
}
```

### Sample 79: `a477f89d63408f5a`

| Field | Value |
|---|---|
| SHA-256 | `a477f89d63408f5ada9698388e4348c65611c81efe19681772e7354d64c2d3ed` |
| Family label | `RemcosRAT` |
| File name | `1C1F469D72D082FB956CA88133D8D8DB.exe` |
| File type | `exe` |
| First seen | `2026-07-30 20:15:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c1f469d72d082fb956ca88133d8d8db` |
| SHA-1 | `8e2e193083339d842f176642387a0b3b2b858540` |
| SHA-256 | `a477f89d63408f5ada9698388e4348c65611c81efe19681772e7354d64c2d3ed` |
| SHA3-384 | `a872869ca8f522d725b3ce457999d86aeab7bd421dbba98f2c2a243699253da629c37703e76168445f1c1958f80cd1a7` |
| IMPHASH | `cd443d07fb22cc071cc33eee6cd16e2e` |
| TLSH | `T129B4BE02F6C3C1B2E57224300825EB79CEBCBC215839996B63DE3DA7FD74151D62A762` |
| SSDEEP | `12288:I3hHcqmchoYIaLCaVZmne9qQR5Ww91e3tccv0sPZ2Bd/svs:IR8qmmIaWaVZ99de3tlXZUd/` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_079_a477f89d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a477f89d63408f5ada9698388e4348c65611c81efe19681772e7354d64c2d3ed"
    family = "RemcosRAT"
    file_name = "1C1F469D72D082FB956CA88133D8D8DB.exe"
    file_type = "exe"
    first_seen = "2026-07-30 20:15:17"
  condition:
    hash.sha256(0, filesize) == "a477f89d63408f5ada9698388e4348c65611c81efe19681772e7354d64c2d3ed"
}
```

### Sample 80: `c65f05b9f92b5d1c`

| Field | Value |
|---|---|
| SHA-256 | `c65f05b9f92b5d1cc2d19cf9f8d12fad263403d54952be88f93cd65a54239a5b` |
| Family label | `AsyncRAT` |
| File name | `IntimationRefund2024-2025.vbs` |
| File type | `vbs` |
| First seen | `2026-07-30 20:15:14` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, RAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c65ccef988e27a2efc27cb11f31eafc` |
| SHA-1 | `9e95e95127a0ddd1257976eda1dfb1582f9fd952` |
| SHA-256 | `c65f05b9f92b5d1cc2d19cf9f8d12fad263403d54952be88f93cd65a54239a5b` |
| SHA3-384 | `fa75243807f39fd3b4cee8f9d2131517d5bebf4af9e225cd61eb7cdce81d26bb8a79c940e20380e64056de7a61c80b18` |
| TLSH | `T107269F606E5859F5EF8C6A0E90AE6F1D87F042176A33706BFB41DF04BD9A341864B21F` |
| SSDEEP | `24576:KrSVzHwm9MNo2bsO4sKps6CT28TSo3pLCym7hpxZU9xfARdKVKm32XsEdfQAxDKM:mB+` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_080_c65f05b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c65f05b9f92b5d1cc2d19cf9f8d12fad263403d54952be88f93cd65a54239a5b"
    family = "AsyncRAT"
    file_name = "IntimationRefund2024-2025.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:15:14"
  condition:
    hash.sha256(0, filesize) == "c65f05b9f92b5d1cc2d19cf9f8d12fad263403d54952be88f93cd65a54239a5b"
}
```

### Sample 81: `b7330cf42457ba3a`

| Field | Value |
|---|---|
| SHA-256 | `b7330cf42457ba3a1cb515d260f2fb3f4dd90e4de9cf26fd6b070cf53109df6d` |
| Family label | `AsyncRAT` |
| File name | `ITRIntimation24-25.vbs` |
| File type | `vbs` |
| First seen | `2026-07-30 20:15:11` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, RAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc8f595456e314aff3efceb55f72f74f` |
| SHA-1 | `e02d982f78d80925324a2c72dde90a365dad8371` |
| SHA-256 | `b7330cf42457ba3a1cb515d260f2fb3f4dd90e4de9cf26fd6b070cf53109df6d` |
| SHA3-384 | `0e3142b25b8390210d485de727cc3bf3ccb0bfb862d5a8dfef5a8ce7f46bbef4777b66e035678fc52212848e8ac30246` |
| TLSH | `T161269F606E5859F5EF8C6A0E90AE6F1D87F042176A33706BFB41DF04BD9A341864B21F` |
| SSDEEP | `24576:t/sffqbNv51KUiAsO4sKps6CT28TSo3pLCym7hpxZU9xfARdKVKm32XsEdfQAxD7:drBI` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_081_b7330cf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7330cf42457ba3a1cb515d260f2fb3f4dd90e4de9cf26fd6b070cf53109df6d"
    family = "AsyncRAT"
    file_name = "ITRIntimation24-25.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:15:11"
  condition:
    hash.sha256(0, filesize) == "b7330cf42457ba3a1cb515d260f2fb3f4dd90e4de9cf26fd6b070cf53109df6d"
}
```

### Sample 82: `93a180ec5678568b`

| Field | Value |
|---|---|
| SHA-256 | `93a180ec5678568b9d071861338cc3572ac8c95cba3f7887ab597565c722602f` |
| Family label | `AsyncRAT` |
| File name | `IntimationReturn.vbs` |
| File type | `vbs` |
| First seen | `2026-07-30 20:15:08` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, RAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ebf0e1a54cdf15a4bcfcbfbdc12958f` |
| SHA-1 | `3b750cb6c9f401ec5780ae615552be53f879d373` |
| SHA-256 | `93a180ec5678568b9d071861338cc3572ac8c95cba3f7887ab597565c722602f` |
| SHA3-384 | `ac00d5584c53f58ea0f85500ee6b826b82f31a156a0a2de8d80d93af0e25acf5f6e02782b79fe2f43d64d25544b19231` |
| TLSH | `T17B269F606E5859F5EF8C6A0E90AE6F1D87F042176A33706BFB41DF04BD9A341864B21F` |
| SSDEEP | `24576:UzyEQIEATJ9N2sO4sKps6CT28TSo3pLCym7hpxZU9xfARdKVKm32XsEdfQAxDKvV:TBn` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_082_93a180ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93a180ec5678568b9d071861338cc3572ac8c95cba3f7887ab597565c722602f"
    family = "AsyncRAT"
    file_name = "IntimationReturn.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:15:08"
  condition:
    hash.sha256(0, filesize) == "93a180ec5678568b9d071861338cc3572ac8c95cba3f7887ab597565c722602f"
}
```

### Sample 83: `de6f4352d29b3063`

| Field | Value |
|---|---|
| SHA-256 | `de6f4352d29b306317a03c96a39d8d9df21c70435676311573f70b7e73acf567` |
| Family label | `STRRAT` |
| File name | `ORDER-260730-0956436.XLS.vbs` |
| File type | `vbs` |
| First seen | `2026-07-30 20:15:05` |
| Reporter | `abuse_ch` |
| Tags | `STRRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a01dab0dfbb977e357e3022e1a680946` |
| SHA-1 | `5b8031afecdc5edf91e8bfbf9aa0e19dcd5a1bcc` |
| SHA-256 | `de6f4352d29b306317a03c96a39d8d9df21c70435676311573f70b7e73acf567` |
| SHA3-384 | `0ff67e64b124c3cb5930a244dbfca5ae29ca6e776a06504987d0925d8d655aa9065a5cfac7434b7fecfaf3db841b4fcc` |
| TLSH | `T122655E0227787871DDB8172890EB182E0AE4F95C99F5751CBE05166F6D7E9CA080F2EF` |
| SSDEEP | `12288:rk+11z4lIF/woiYYcofyBi5P3sT9xbf2+h:rk+11fF1ixcNBE3S9/` |

#### Technical Assessment

- The sample is tracked as `STRRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_STRRAT_083_de6f4352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de6f4352d29b306317a03c96a39d8d9df21c70435676311573f70b7e73acf567"
    family = "STRRAT"
    file_name = "ORDER-260730-0956436.XLS.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:15:05"
  condition:
    hash.sha256(0, filesize) == "de6f4352d29b306317a03c96a39d8d9df21c70435676311573f70b7e73acf567"
}
```

### Sample 84: `5d19c6cd2687c252`

| Field | Value |
|---|---|
| SHA-256 | `5d19c6cd2687c25287f30d6de13a2e0ec95f909576f5d29b018be095062d3437` |
| Family label | `unknown` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-30 20:07:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07b54090888884cb2b74f058b5a041af` |
| SHA-1 | `57d94d6cb4fa974521f0ec3211a64b73c1c84ef1` |
| SHA-256 | `5d19c6cd2687c25287f30d6de13a2e0ec95f909576f5d29b018be095062d3437` |
| SHA3-384 | `28cf42a95cc99698c0eca53cf108f914b471a04b578ebe6ef328a952bfc1247aee1269398725c8b8b68255b7d346e99f` |
| TLSH | `T1C3F319C7F900D9B6F80EE7374853080AB130BBA144925A777257357FED3A199097BE8A` |
| SSDEEP | `3072:GhliYIgfonZCi88Dya4Az+Fw/yFIDl2ufh4oTvRVKjbirLffe9WN+O:GhIX9AEDyaBz+y/yGD1PTv3Lfw2+O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_5d19c6cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d19c6cd2687c25287f30d6de13a2e0ec95f909576f5d29b018be095062d3437"
    family = "unknown"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-30 20:07:47"
  condition:
    hash.sha256(0, filesize) == "5d19c6cd2687c25287f30d6de13a2e0ec95f909576f5d29b018be095062d3437"
}
```

### Sample 85: `468e406f1b699984`

| Field | Value |
|---|---|
| SHA-256 | `468e406f1b699984ba66833482de4f1e4586e8f80bfbb8fd46056260ed19b0e4` |
| Family label | `Mirai` |
| File name | `zero.m68k` |
| File type | `elf` |
| First seen | `2026-07-30 20:07:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2f3973f47f41a6d7c01b6cf7c9fa5e8` |
| SHA-1 | `7e01a2ea600bdcc008fcc16f2bd2f2668a8c0335` |
| SHA-256 | `468e406f1b699984ba66833482de4f1e4586e8f80bfbb8fd46056260ed19b0e4` |
| SHA3-384 | `687246f90a5464a9d63e392b179944fcea846991ba3fdb854190252c596a72af5b47f36ec3efdcbc24441eaf8a820b19` |
| TLSH | `T1E4F329D7F800CDBEF41BE37684570A05B130B7E145826B376257786BED7E1A92823E86` |
| SSDEEP | `3072:xZz2+2FoN9CqWxXvpTM0DjJs+P0VUjbi/LTg8MqEuGCFkw9y/lshE:7EjpTM0De+PSLTdYuby/uhE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_468e406f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "468e406f1b699984ba66833482de4f1e4586e8f80bfbb8fd46056260ed19b0e4"
    family = "Mirai"
    file_name = "zero.m68k"
    file_type = "elf"
    first_seen = "2026-07-30 20:07:45"
  condition:
    hash.sha256(0, filesize) == "468e406f1b699984ba66833482de4f1e4586e8f80bfbb8fd46056260ed19b0e4"
}
```

### Sample 86: `b253c73d2cac9ee2`

| Field | Value |
|---|---|
| SHA-256 | `b253c73d2cac9ee27a3ebe89896b08bd455ed9f552ff7af20154d925822379ed` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-30 20:07:30` |
| Reporter | `Bitsight` |
| Tags | `BB3.file, dropped-by-GCleaner, exe, F, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c801495c98610e60a0d31b3a15aa888f` |
| SHA-1 | `559489ad8d698e36028a007d9df33d74494b1cdd` |
| SHA-256 | `b253c73d2cac9ee27a3ebe89896b08bd455ed9f552ff7af20154d925822379ed` |
| SHA3-384 | `31cab536672cd9b54c160c18601c11aaf772ba97f833a2b40d8d7725fc8efe55ec7041cb154dd58dc799b7ed96fb892b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10EA68D077CE049E9C46AA33199B651527B34BC084F3563DB2E90BB782F727D09E76B81` |
| SSDEEP | `49152:079SU8P6amJldBZuHAAX9jJXnPxfCT+JSn8qbQ:0R7ApNtJCTiSng` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_b253c73d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b253c73d2cac9ee27a3ebe89896b08bd455ed9f552ff7af20154d925822379ed"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 20:07:30"
  condition:
    hash.sha256(0, filesize) == "b253c73d2cac9ee27a3ebe89896b08bd455ed9f552ff7af20154d925822379ed"
}
```

### Sample 87: `eaebbaf4e6affb72`

| Field | Value |
|---|---|
| SHA-256 | `eaebbaf4e6affb72d0979fb50e61538cfb2f24f61b9c8157862f124f761465d9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-30 20:07:04` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX1.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d5e0258501cbce5abc822c762a4906a` |
| SHA-1 | `a7fe3adbedd77c50af192b7bf5e37ca9556349bf` |
| SHA-256 | `eaebbaf4e6affb72d0979fb50e61538cfb2f24f61b9c8157862f124f761465d9` |
| SHA3-384 | `a05d6eaad7084f4f6a61743afeceb230771dcac5356f91c0ff8f1d9d8ed7437ee8e325add219e778eb1a57b0aa954b8c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D2B56B07BCE049E9C4A9933189BA51527B35BC084F3263DB2E90BB782F727D09D76B54` |
| SSDEEP | `24576:JJsll+jpaoQv03VhxxsoW2NEU/UXpOc0uO2lVsu7dpijIX7ldzBeletrKDX7jiNt:JJsL+1ae3zDsoL//ElVsnI98Ab` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_eaebbaf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaebbaf4e6affb72d0979fb50e61538cfb2f24f61b9c8157862f124f761465d9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 20:07:04"
  condition:
    hash.sha256(0, filesize) == "eaebbaf4e6affb72d0979fb50e61538cfb2f24f61b9c8157862f124f761465d9"
}
```

### Sample 88: `6e6513b872fcd852`

| Field | Value |
|---|---|
| SHA-256 | `6e6513b872fcd852b76ac8927cc6126c63bd4b31badb2cb451d383c058f7fcb1` |
| Family label | `unknown` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-07-30 20:05:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22452f1e8c4d8575115fe5171953a51c` |
| SHA-1 | `d0038908e56ad086bb51ff7950c17ca9ea65dc7a` |
| SHA-256 | `6e6513b872fcd852b76ac8927cc6126c63bd4b31badb2cb451d383c058f7fcb1` |
| SHA3-384 | `0e16675409e50df13989800dd12a3a8b4b9a4c3bf6e8ac84ddb520f494690881aac37e81661e7051c4ce8e8f7deb7e8c` |
| TLSH | `T1CF233B22C6B95D02CBE07A7A03F303E3D1DA9B148394DA4FEDD55EA69F477108C9668C` |
| TELFHASH | `t154f05944ed3d8e0e46e25d30cc7d5b51e1a3456352a08775df45d9c0493e514f219e1e` |
| SSDEEP | `768:DkDr9HH4nnnoWV1VAkr9HH4nnngoI9RE2ERaq8Pd6wlREJjtBE+E221zhUK1TNB:D6r9n4noWt3r9n4n69K2aaZd6eEJjtBU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_6e6513b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e6513b872fcd852b76ac8927cc6126c63bd4b31badb2cb451d383c058f7fcb1"
    family = "unknown"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-07-30 20:05:15"
  condition:
    hash.sha256(0, filesize) == "6e6513b872fcd852b76ac8927cc6126c63bd4b31badb2cb451d383c058f7fcb1"
}
```

### Sample 89: `a90c1e26e58a9744`

| Field | Value |
|---|---|
| SHA-256 | `a90c1e26e58a9744f4b647fbb6707e18df24b38a4769982a50a004ab909f9c66` |
| Family label | `Mirai` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-07-30 20:03:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84b0664e111a15774082e40f5d99e8ba` |
| SHA-1 | `1d8edbf494ef6226066fa70260fe155b949eab59` |
| SHA-256 | `a90c1e26e58a9744f4b647fbb6707e18df24b38a4769982a50a004ab909f9c66` |
| SHA3-384 | `f44ff52f1aabf06b40db9be899f8409776253727a1745ce8aad3a3f74c8e6bf0b5581207f6dea078531c4bcd2e6dd3f2` |
| TLSH | `T167631B82BD80E62AC7C057B6EE6F509E3311A7D8C1D93642DD181BB47B8E90F0E17796` |
| TELFHASH | `t17ae06840bc76862888d6aab4ad9d07b19601a21250178b20cf20d5e0d83f448e308e6a` |
| SSDEEP | `1536:DFIer4K3LRCnmd+gG9XMSEHljjl8t4VGqBnBSMZ:6erlaYll84oenUu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_a90c1e26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a90c1e26e58a9744f4b647fbb6707e18df24b38a4769982a50a004ab909f9c66"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-07-30 20:03:32"
  condition:
    hash.sha256(0, filesize) == "a90c1e26e58a9744f4b647fbb6707e18df24b38a4769982a50a004ab909f9c66"
}
```

### Sample 90: `928ea1b44130b207`

| Field | Value |
|---|---|
| SHA-256 | `928ea1b44130b207af4151cc988bb6beab1b94f29abcd6d58d469f6876f4f7ee` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-07-30 20:00:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77d8a7a32a72664787de58b4fd2f6188` |
| SHA-1 | `d03b200732e858b16869babe39e4badfc1395c72` |
| SHA-256 | `928ea1b44130b207af4151cc988bb6beab1b94f29abcd6d58d469f6876f4f7ee` |
| SHA3-384 | `ff914d6cf1bee2ccaeb049288d174cd6309b0d781204541f35c183eb65da5eb448a350450b74a3f0655863e1b4ca2d15` |
| TLSH | `T1A3F48D1BB2B2B1BCD01BC03007DBCAB25672F47526212D7B26C4DA353E96DE1176EB61` |
| TELFHASH | `t1d691287409f675b1a6dbda01b322f0be6a7614a562ec35b02627ddd5dfc4f810c92823` |
| SSDEEP | `12288:EU9ij7tPlPwa9awPNgcCRdpd1HRvonq8eOY/vCiTayU7WHX:EYij7ka9awPNgcaq0OY3CH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_928ea1b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "928ea1b44130b207af4151cc988bb6beab1b94f29abcd6d58d469f6876f4f7ee"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-07-30 20:00:38"
  condition:
    hash.sha256(0, filesize) == "928ea1b44130b207af4151cc988bb6beab1b94f29abcd6d58d469f6876f4f7ee"
}
```

### Sample 91: `9a81a09982169309`

| Field | Value |
|---|---|
| SHA-256 | `9a81a09982169309d5d1c81b4563ba7d37ffe4cae58d3de3c2f5935f4809dc42` |
| Family label | `Mirai` |
| File name | `cXiP` |
| File type | `elf` |
| First seen | `2026-07-30 19:55:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27eb8c169675b08ec6b4b1964bdd8c24` |
| SHA-1 | `2e06e83021fd57e152ca30bf67709a939d6176a9` |
| SHA-256 | `9a81a09982169309d5d1c81b4563ba7d37ffe4cae58d3de3c2f5935f4809dc42` |
| SHA3-384 | `e82148a65cf30eea7c0ee8d7a3f650265e5a45b2c7b732156157f8c6af06b32758ec465aa33b30d01ea7de6d4ea6537d` |
| TLSH | `T11FA3E94AAF611DBBD81BDD3705AD0B4235CCA60771683B763534C928BA4B54F8AE3CB4` |
| SSDEEP | `1536:Td7e6rpPLrmXnB9TtC/UwXouw6A01dYSJX4mMU4py00D5sPXv5:5C2LCXB9TEouCQgy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_9a81a099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a81a09982169309d5d1c81b4563ba7d37ffe4cae58d3de3c2f5935f4809dc42"
    family = "Mirai"
    file_name = "cXiP"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:23"
  condition:
    hash.sha256(0, filesize) == "9a81a09982169309d5d1c81b4563ba7d37ffe4cae58d3de3c2f5935f4809dc42"
}
```

### Sample 92: `cec9d22bdac62119`

| Field | Value |
|---|---|
| SHA-256 | `cec9d22bdac621193a5ca25471be565cc88141bb163777b4f9b9c19b25bff42f` |
| Family label | `Mirai` |
| File name | `kiA` |
| File type | `elf` |
| First seen | `2026-07-30 19:55:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f3cf912ded88a17c4da2d10525ceca3` |
| SHA-1 | `0f3f5620cb540a6d09a60ffefa8ffa0ae6c23d14` |
| SHA-256 | `cec9d22bdac621193a5ca25471be565cc88141bb163777b4f9b9c19b25bff42f` |
| SHA3-384 | `3d6219e920f12ebd125928eabaec0756c617e3105bc340d41645e3ee3d874993583cc5c33cfe60594b409e7dea91cf3d` |
| TLSH | `T15FA3C71B2F219FACF3A98334D7B74B309A5C23D126E2C684D5ACD5012E7434E591F7AA` |
| TELFHASH | `t1cf31d419497413f4d3610d9d6eeefb32e0a170df29251e378f22e95a9a1d9428d10c1d` |
| SSDEEP | `1536:DqzBciaGF/2cdorwE0IK8F75mlcBy18HgDgh6B7dXaW09Tp353J1:DdGF/jdorwx+mcBy1rs0Bcr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_cec9d22b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cec9d22bdac621193a5ca25471be565cc88141bb163777b4f9b9c19b25bff42f"
    family = "Mirai"
    file_name = "kiA"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:21"
  condition:
    hash.sha256(0, filesize) == "cec9d22bdac621193a5ca25471be565cc88141bb163777b4f9b9c19b25bff42f"
}
```

### Sample 93: `7dcf4a36579a8f73`

| Field | Value |
|---|---|
| SHA-256 | `7dcf4a36579a8f730a0a624eae103f3726f7a6230e92fa16010cee45a494bb9d` |
| Family label | `Mirai` |
| File name | `tAGc` |
| File type | `elf` |
| First seen | `2026-07-30 19:55:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c2225c6a4477eb9e589afb7324ec2d0` |
| SHA-1 | `d806fb511af6ff3d184071de5ebba97b995a025b` |
| SHA-256 | `7dcf4a36579a8f730a0a624eae103f3726f7a6230e92fa16010cee45a494bb9d` |
| SHA3-384 | `3ae3cdff3d4a8da1505bc9eab4d2862193b18b8c6ada462cef879991ad11e4b2c32981e12a9736fad156e87d7bf56000` |
| TLSH | `T16683182AF9419F15D5D526BAFF5E534933132BB8E3EE7102DE142B2527CA91B0F3A801` |
| TELFHASH | `t1a0e061e61d0a6fcc86f04445d1c5751609b5f57b1a1056977cdc2d5b44e3582725e006` |
| SSDEEP | `1536:w5nMlDw4i5YfaDTLkSIaErKcoMSJmTVSimaBp0GadlNhiaWVRd7E:T+4uYi7BWKtMSJmTVSimaBx+lWVRd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_7dcf4a36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dcf4a36579a8f730a0a624eae103f3726f7a6230e92fa16010cee45a494bb9d"
    family = "Mirai"
    file_name = "tAGc"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:20"
  condition:
    hash.sha256(0, filesize) == "7dcf4a36579a8f730a0a624eae103f3726f7a6230e92fa16010cee45a494bb9d"
}
```

### Sample 94: `0a072ac7e5af0b6a`

| Field | Value |
|---|---|
| SHA-256 | `0a072ac7e5af0b6af24550a46755dddfc6582e575112a9794ff6ada7e283ac6c` |
| Family label | `Mirai` |
| File name | `fR9v` |
| File type | `elf` |
| First seen | `2026-07-30 19:55:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95dceecbcc64ccb29b1cbe583db3abc1` |
| SHA-1 | `1eee9a068cfe53526e0e715e5d6fc11c433db190` |
| SHA-256 | `0a072ac7e5af0b6af24550a46755dddfc6582e575112a9794ff6ada7e283ac6c` |
| SHA3-384 | `7d0a7593b36632b5bb403b60e39aac39028112a59c13f8dd30ce5b5eb7e4f53e0b7946a2e8a24ae3ac04dc1626a69d50` |
| TLSH | `T18D631A26B8519F1AC2C21677FF1EC388372663F8E3DA7202DA152F5937CB41A0E3A555` |
| TELFHASH | `t1d1e02238678716eca2f4c08180ef0a654bacb0790355222c6aed8f9e02235d3a906c0d` |
| SSDEEP | `1536:EWiWusxI9BLG3wWClyILPd8ofAflIGdR8YwgZcYMRFXEoX1tmz:Et3EI90boLmoIflIGdRgyvCFXEA1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_0a072ac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a072ac7e5af0b6af24550a46755dddfc6582e575112a9794ff6ada7e283ac6c"
    family = "Mirai"
    file_name = "fR9v"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:19"
  condition:
    hash.sha256(0, filesize) == "0a072ac7e5af0b6af24550a46755dddfc6582e575112a9794ff6ada7e283ac6c"
}
```

### Sample 95: `a5450557a47e6bf7`

| Field | Value |
|---|---|
| SHA-256 | `a5450557a47e6bf770bcfa02c8731baf3600725eba203926631c0202a926798f` |
| Family label | `Mirai` |
| File name | `CCJt` |
| File type | `elf` |
| First seen | `2026-07-30 19:55:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f21c2c8ee97fc1cbc1685fcff2807611` |
| SHA-1 | `500304592366303e0caf03839181371ffdc0a82b` |
| SHA-256 | `a5450557a47e6bf770bcfa02c8731baf3600725eba203926631c0202a926798f` |
| SHA3-384 | `d439f25eb641035d25fd75ed1a2b98dfcb305e31119614a22403374176a7a5174c81c17c81f87b26cad1a1a607132f87` |
| TLSH | `T1F463096AB9818F15C5C1167AFE1D534E731327B8E3DE7213DE142B642B8B96B0F3A805` |
| TELFHASH | `t1dfe06137ee0419ecf7d08145c89ba73214d4b1b52b15270d5fde4e0e0123543b29b015` |
| SSDEEP | `1536:lNnnereRNqHJKHLkU9QjJ+GvaFpWASApYiGYIBJv4E2KC:cePwSId+NFpWo8YIBJva` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_a5450557
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5450557a47e6bf770bcfa02c8731baf3600725eba203926631c0202a926798f"
    family = "Mirai"
    file_name = "CCJt"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:18"
  condition:
    hash.sha256(0, filesize) == "a5450557a47e6bf770bcfa02c8731baf3600725eba203926631c0202a926798f"
}
```

### Sample 96: `cdc3b1b449c8196d`

| Field | Value |
|---|---|
| SHA-256 | `cdc3b1b449c8196d3025cf953f12c3eba5c6e3371b402e5ddd945170f831b546` |
| Family label | `Mirai` |
| File name | `zero.mipsrouter` |
| File type | `elf` |
| First seen | `2026-07-30 19:54:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1aed145a2c604c1426f292de320eea6` |
| SHA-1 | `b5bd3e3acd751e4961a3302617587e8045c65aba` |
| SHA-256 | `cdc3b1b449c8196d3025cf953f12c3eba5c6e3371b402e5ddd945170f831b546` |
| SHA3-384 | `76ad8b1fe8e4384cb46b6f386f9832fa166a0f90f60a6b1b3f5750d93415ece67551117272c709dc1a0a76ce130c5dde` |
| TLSH | `T1AC14B74E6E138F7DF67C87304BB78E25676923D523E0D684E1ACC2505E2029E546FFA8` |
| TELFHASH | `t12a417c180a7417f4a3795c9e09adff7a96a730db3f122d278e11e55aa7699838d20c0c` |
| SSDEEP | `1536:4F2L0TU2DkPxz8fWAC6n5BmOEVXJjTa5umF3fGIT+mpAn0RzKke9zvK7q8iw:j0uy8VXJjTa5umAMpAnkzKB7K7q8iw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_cdc3b1b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdc3b1b449c8196d3025cf953f12c3eba5c6e3371b402e5ddd945170f831b546"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-07-30 19:54:45"
  condition:
    hash.sha256(0, filesize) == "cdc3b1b449c8196d3025cf953f12c3eba5c6e3371b402e5ddd945170f831b546"
}
```

### Sample 97: `e202969e703aa1cf`

| Field | Value |
|---|---|
| SHA-256 | `e202969e703aa1cffa4932c7dfba8b667e99f8c9cc556497223f5bc08e0756ea` |
| Family label | `Mirai` |
| File name | `zero.mipsrouter` |
| File type | `elf` |
| First seen | `2026-07-30 19:54:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e4a20ec7b29d7d8cb7052e03076626b` |
| SHA-1 | `bf5537237a550709c4faf43034f3f3b2066daed4` |
| SHA-256 | `e202969e703aa1cffa4932c7dfba8b667e99f8c9cc556497223f5bc08e0756ea` |
| SHA3-384 | `119d173e6d2531eaf2e283ff4773f7e9f2b520acf70f0e73ff0d5a302039945e6fab09d894f0c7c1198093b3c6d77515` |
| TLSH | `T1FC43025D053245D3E56A18F50BC84F223B110E72A603AB16259BE7B76CCC4EEB6B32C6` |
| SSDEEP | `1536:Kl6sZ/AAX4Ko3SamkxzMsgoZrC3q5PIbMSKzSxVJuy:Kl5RJoKo3SwVMsfZrUMAoKVQy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_e202969e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e202969e703aa1cffa4932c7dfba8b667e99f8c9cc556497223f5bc08e0756ea"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-07-30 19:54:10"
  condition:
    hash.sha256(0, filesize) == "e202969e703aa1cffa4932c7dfba8b667e99f8c9cc556497223f5bc08e0756ea"
}
```

### Sample 98: `ad21776ed177bd75`

| Field | Value |
|---|---|
| SHA-256 | `ad21776ed177bd75e1771cf39efbf97f0d1c4d809f7bf5c93e2d14f6317b0999` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-30 19:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74e56d0afa0ab0b7cc138edfaee2c792` |
| SHA-1 | `7f306eb9a0fe2f8523a4048194bb97dc0553d465` |
| SHA-256 | `ad21776ed177bd75e1771cf39efbf97f0d1c4d809f7bf5c93e2d14f6317b0999` |
| SHA3-384 | `a50307df2562fef37eb274c51190507df9ce15afe07cdad7d6b9f6609e90f535a62e9df5692ee52e05a1f40aec85bdbd` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A7E6335CA7E042F9EDF34039D9E246A1DA6534724BB3C9AB4BECC6B1AD470944C3A707` |
| SSDEEP | `393216:r+gQ2EroRmKDwp1k8B8a79IXMCHWUjXIcuI3/PGTAI:rVRamVDCnB3JIXMb8X9H/O7` |
| ICON-DHASH | `30f8fc9ccce4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_ad21776e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad21776ed177bd75e1771cf39efbf97f0d1c4d809f7bf5c93e2d14f6317b0999"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 19:52:31"
  condition:
    hash.sha256(0, filesize) == "ad21776ed177bd75e1771cf39efbf97f0d1c4d809f7bf5c93e2d14f6317b0999"
}
```

### Sample 99: `bea4c166b9ad9a93`

| Field | Value |
|---|---|
| SHA-256 | `bea4c166b9ad9a936911b052601f480ca4f2de0d3f7494fe35562805bf491491` |
| Family label | `unknown` |
| File name | `e8feab72279dab768ac7bd1adcfe034a.exe` |
| File type | `exe` |
| First seen | `2026-07-30 19:51:34` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8feab72279dab768ac7bd1adcfe034a` |
| SHA-1 | `ca7b1d99b193ad5ffd735df9b114f73d66ceb88d` |
| SHA-256 | `bea4c166b9ad9a936911b052601f480ca4f2de0d3f7494fe35562805bf491491` |
| SHA3-384 | `51d99a81eda158af6acc274e8765871105863cdf315030728d48755755bb854b29f7d54a6b64c4a1bda36c0a64474424` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1BF968D03ECA555E9C1A9A23089B29253BB71BC484F3263D36B90F7386F72BD06E75354` |
| SSDEEP | `98304:WRtKWjvVsgoHOb3sC201UWEThjQa00xlKXDBm3TO2xJr/7+rMA+3kh:WnvVsNHOb8ui1jQsxlKXDBm3XJD7Zk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_bea4c166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bea4c166b9ad9a936911b052601f480ca4f2de0d3f7494fe35562805bf491491"
    family = "unknown"
    file_name = "e8feab72279dab768ac7bd1adcfe034a.exe"
    file_type = "exe"
    first_seen = "2026-07-30 19:51:34"
  condition:
    hash.sha256(0, filesize) == "bea4c166b9ad9a936911b052601f480ca4f2de0d3f7494fe35562805bf491491"
}
```

### Sample 100: `a685603be47c7c22`

| Field | Value |
|---|---|
| SHA-256 | `a685603be47c7c2290ed7682ec863cfbf363db84ca1f6a7f46a1e1cf5ac98d19` |
| Family label | `Mirai` |
| File name | `zero.armv7l` |
| File type | `elf` |
| First seen | `2026-07-30 19:48:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf49ce3287ae063d2ed3d4a3a1666f3f` |
| SHA-1 | `9b5703771c79c76d17c45d4ae8eba2a6e0c486c3` |
| SHA-256 | `a685603be47c7c2290ed7682ec863cfbf363db84ca1f6a7f46a1e1cf5ac98d19` |
| SHA3-384 | `2a779c040b03fd431dddcfa47e4b27e5b7cebbd88ccfb31f70c087d59bf85bb59e6c51e18cea8a8fdaae255fd458c84a` |
| TLSH | `T172C3F889BC814B00D5D636BAFE0E124933534BBCE3F9B1039E145B2E278AD5B0B77A55` |
| TELFHASH | `t15721dd74df6806ec33e587585287a12596f831dc63215ab4de3b17cb1542cc0753e12b` |
| SSDEEP | `3072:ZIBhkG44j54cKlDcLkOu+rt6Ooy1KaKGSTP9:/GmxDcg2rt6OoEKauP9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_a685603b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a685603be47c7c2290ed7682ec863cfbf363db84ca1f6a7f46a1e1cf5ac98d19"
    family = "Mirai"
    file_name = "zero.armv7l"
    file_type = "elf"
    first_seen = "2026-07-30 19:48:38"
  condition:
    hash.sha256(0, filesize) == "a685603be47c7c2290ed7682ec863cfbf363db84ca1f6a7f46a1e1cf5ac98d19"
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
 * Generated: 2026-07-31T03:55:07.423636+00:00
 */

rule MalwareBazaar_unknown_001_a4b32f5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4b32f5f53a64195ee0cea0ea67a51799d90b25e761f0fec8d38b81e75b8a3c1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 03:52:38"
  condition:
    hash.sha256(0, filesize) == "a4b32f5f53a64195ee0cea0ea67a51799d90b25e761f0fec8d38b81e75b8a3c1"
}

rule MalwareBazaar_unknown_002_dcc4899e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcc4899e3c3a30ba66cb03b92ff74755338f422f4ba47f1060a9503dde31fdfd"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 02:52:31"
  condition:
    hash.sha256(0, filesize) == "dcc4899e3c3a30ba66cb03b92ff74755338f422f4ba47f1060a9503dde31fdfd"
}

rule MalwareBazaar_unknown_003_06f809fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06f809fa0703109f2e34862b5614aa607ed8e654498fc31058dc9e4737785f34"
    family = "unknown"
    file_name = "컴퓨터 완전 종료하기.exe"
    file_type = "exe"
    first_seen = "2026-07-31 02:05:48"
  condition:
    hash.sha256(0, filesize) == "06f809fa0703109f2e34862b5614aa607ed8e654498fc31058dc9e4737785f34"
}

rule MalwareBazaar_unknown_004_b521edd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b521edd2233b62e69e3c3e8ae27414e7e19f566675479884479139b7c576363d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-31 02:01:34"
  condition:
    hash.sha256(0, filesize) == "b521edd2233b62e69e3c3e8ae27414e7e19f566675479884479139b7c576363d"
}

rule MalwareBazaar_unknown_005_d14b8fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d14b8fd63a8933d814039d0c157abe3032fccb34143d8fd94532419dc8f993a5"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-31 01:54:42"
  condition:
    hash.sha256(0, filesize) == "d14b8fd63a8933d814039d0c157abe3032fccb34143d8fd94532419dc8f993a5"
}

rule MalwareBazaar_unknown_006_2670c97b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2670c97b169e77527f6db4726e58db1c95926c35b56e292c0a3a975dd6656cb8"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 01:52:31"
  condition:
    hash.sha256(0, filesize) == "2670c97b169e77527f6db4726e58db1c95926c35b56e292c0a3a975dd6656cb8"
}

rule MalwareBazaar_unknown_007_b6c1a882
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6c1a882ea04ab43ef08120d0505c9e764c7cd41b7cb1151039a78c72828485f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-31 01:45:34"
  condition:
    hash.sha256(0, filesize) == "b6c1a882ea04ab43ef08120d0505c9e764c7cd41b7cb1151039a78c72828485f"
}

rule MalwareBazaar_unknown_008_fe1f6a9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe1f6a9fa4f17f52f6dc426da7fd08547bf533c8a65a4de0ab1dda879a77dae6"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-07-31 01:45:32"
  condition:
    hash.sha256(0, filesize) == "fe1f6a9fa4f17f52f6dc426da7fd08547bf533c8a65a4de0ab1dda879a77dae6"
}

rule MalwareBazaar_Mirai_009_8809a03e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8809a03eaf8431f2d4252a2d23b1f0888b7fd8722281586fa7bf3154cec38a6d"
    family = "Mirai"
    file_name = "zero.aarch64"
    file_type = "elf"
    first_seen = "2026-07-31 01:40:51"
  condition:
    hash.sha256(0, filesize) == "8809a03eaf8431f2d4252a2d23b1f0888b7fd8722281586fa7bf3154cec38a6d"
}

rule MalwareBazaar_Mirai_010_48e8aad5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48e8aad529f74997fc1682ddd48d40201d4223e9cca45d988a86a7060e3b2be4"
    family = "Mirai"
    file_name = "zero.aarch64"
    file_type = "elf"
    first_seen = "2026-07-31 01:40:23"
  condition:
    hash.sha256(0, filesize) == "48e8aad529f74997fc1682ddd48d40201d4223e9cca45d988a86a7060e3b2be4"
}

rule MalwareBazaar_unknown_011_dd0d940f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd0d940f462679c191187e004a9c66a811d50678eefe964e47d6d7efc1dd65ba"
    family = "unknown"
    file_name = "x"
    file_type = "sh"
    first_seen = "2026-07-31 01:39:12"
  condition:
    hash.sha256(0, filesize) == "dd0d940f462679c191187e004a9c66a811d50678eefe964e47d6d7efc1dd65ba"
}

rule MalwareBazaar_unknown_012_58ed7e2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58ed7e2e13fbf102e0732cc5b5e78c5f2dc6ee90ec849e2afb5d1a87ba4ffa4a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-31 01:31:15"
  condition:
    hash.sha256(0, filesize) == "58ed7e2e13fbf102e0732cc5b5e78c5f2dc6ee90ec849e2afb5d1a87ba4ffa4a"
}

rule MalwareBazaar_Mirai_013_eaa51075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaa51075a1f46596fe60d9f2b6ae226ce99ba8d8d6419ca6f8d5a4843971f642"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-31 01:30:53"
  condition:
    hash.sha256(0, filesize) == "eaa51075a1f46596fe60d9f2b6ae226ce99ba8d8d6419ca6f8d5a4843971f642"
}

rule MalwareBazaar_Mirai_014_68e383c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68e383c37e939f4867cfe9a68ef58b636c0f722ca6e5aeb0ff6e46f3b5c0fcd6"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-31 01:29:36"
  condition:
    hash.sha256(0, filesize) == "68e383c37e939f4867cfe9a68ef58b636c0f722ca6e5aeb0ff6e46f3b5c0fcd6"
}

rule MalwareBazaar_Mirai_015_c42bc305
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c42bc3059c891020a57e738e03039b269bd61358b33789de8a30532b7abe39ab"
    family = "Mirai"
    file_name = "zero.arc"
    file_type = "elf"
    first_seen = "2026-07-31 01:25:16"
  condition:
    hash.sha256(0, filesize) == "c42bc3059c891020a57e738e03039b269bd61358b33789de8a30532b7abe39ab"
}

rule MalwareBazaar_Mirai_016_b7f40db7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f40db7b2110281b3606c24e44d97751fc58b7a504641a4bd3525b053047836"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-31 01:21:14"
  condition:
    hash.sha256(0, filesize) == "b7f40db7b2110281b3606c24e44d97751fc58b7a504641a4bd3525b053047836"
}

rule MalwareBazaar_WannaCry_017_05be5a81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e"
    family = "WannaCry"
    file_name = "05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e"
    file_type = "exe"
    first_seen = "2026-07-31 01:15:05"
  condition:
    hash.sha256(0, filesize) == "05be5a8131993a5034bc4a57963f0c8860aeb3188dd906ed78d95439d15d813e"
}

rule MalwareBazaar_Mirai_018_8a4636e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a4636e894d4d7a9ac0880a1210d70e0cf2c05e14924bcfbf39cffcef27c1e41"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-07-31 01:05:30"
  condition:
    hash.sha256(0, filesize) == "8a4636e894d4d7a9ac0880a1210d70e0cf2c05e14924bcfbf39cffcef27c1e41"
}

rule MalwareBazaar_Mirai_019_33d3debd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33d3debdce6373af8112ee1bd1649bf12b8c2944265108dafa2e7432a014d870"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-31 01:03:54"
  condition:
    hash.sha256(0, filesize) == "33d3debdce6373af8112ee1bd1649bf12b8c2944265108dafa2e7432a014d870"
}

rule MalwareBazaar_Mirai_020_103467eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "103467ebe5fc36e88c3eac3af0cd1fe42bb1b6dbcb5e0abbf80410c58667d0c8"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-31 01:02:37"
  condition:
    hash.sha256(0, filesize) == "103467ebe5fc36e88c3eac3af0cd1fe42bb1b6dbcb5e0abbf80410c58667d0c8"
}

rule MalwareBazaar_Mirai_021_675e7bbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "675e7bbd6ff60ebf352b1d9a788caaee58cb1a4688d74ecc7752ebe8970b81c4"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-31 01:01:50"
  condition:
    hash.sha256(0, filesize) == "675e7bbd6ff60ebf352b1d9a788caaee58cb1a4688d74ecc7752ebe8970b81c4"
}

rule MalwareBazaar_Mirai_022_b9fa1dc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9fa1dc749428b51ef1855db00fdcff798c4ec865f1ed823b6f5e0eed49363c7"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-31 00:59:32"
  condition:
    hash.sha256(0, filesize) == "b9fa1dc749428b51ef1855db00fdcff798c4ec865f1ed823b6f5e0eed49363c7"
}

rule MalwareBazaar_Mirai_023_c3db3111
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3db3111e5636ec2615f58d66e2a90b5c2d36556a29b584ae3344e3d7dee6b5c"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 00:57:43"
  condition:
    hash.sha256(0, filesize) == "c3db3111e5636ec2615f58d66e2a90b5c2d36556a29b584ae3344e3d7dee6b5c"
}

rule MalwareBazaar_Mirai_024_2c748313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c748313a5a75f19574f44dd6db9c1c064ddc494132a91a46ff71be7b6f60d61"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 00:57:18"
  condition:
    hash.sha256(0, filesize) == "2c748313a5a75f19574f44dd6db9c1c064ddc494132a91a46ff71be7b6f60d61"
}

rule MalwareBazaar_Mirai_025_f3a34d56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3a34d567b2dcf24fd994959ddf22daaa11c679e9f570f4fa9227ba53a53dff5"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-31 00:53:49"
  condition:
    hash.sha256(0, filesize) == "f3a34d567b2dcf24fd994959ddf22daaa11c679e9f570f4fa9227ba53a53dff5"
}

rule MalwareBazaar_unknown_026_6a73772f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a73772fd7b33b4f84b67053356c0cffe6e19a7b18b098ad1df5ea572aafbc3b"
    family = "unknown"
    file_name = "weneedsuchakingdomofnicepersonentirelinkingforebst.hta"
    file_type = "hta"
    first_seen = "2026-07-31 00:53:27"
  condition:
    hash.sha256(0, filesize) == "6a73772fd7b33b4f84b67053356c0cffe6e19a7b18b098ad1df5ea572aafbc3b"
}

rule MalwareBazaar_Mirai_027_17417292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1741729211a767777d024691477bc83333d59e0f9f222571600487bdd4f9b011"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-31 00:53:26"
  condition:
    hash.sha256(0, filesize) == "1741729211a767777d024691477bc83333d59e0f9f222571600487bdd4f9b011"
}

rule MalwareBazaar_unknown_028_4bb4b92b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bb4b92b54c8ecd1db145f986e9725e9d327713cd9262dbe010318afd6af8137"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 00:52:31"
  condition:
    hash.sha256(0, filesize) == "4bb4b92b54c8ecd1db145f986e9725e9d327713cd9262dbe010318afd6af8137"
}

rule MalwareBazaar_unknown_029_95f92b2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95f92b2e46e524ee532a486516189c8b33ba1fbbcc37cfb3a043c97f4af8a327"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-31 00:51:13"
  condition:
    hash.sha256(0, filesize) == "95f92b2e46e524ee532a486516189c8b33ba1fbbcc37cfb3a043c97f4af8a327"
}

rule MalwareBazaar_Mirai_030_c7866aec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7866aec77c1fa71cd9a678de4ba00abf6ccd862a47258cba319f21eb42da76e"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 00:51:12"
  condition:
    hash.sha256(0, filesize) == "c7866aec77c1fa71cd9a678de4ba00abf6ccd862a47258cba319f21eb42da76e"
}

rule MalwareBazaar_unknown_031_ed1d3f69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed1d3f69fbbd5576c2ed8dba45ba22c4f6884eb311d4f6e389203846d512ec11"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 00:50:14"
  condition:
    hash.sha256(0, filesize) == "ed1d3f69fbbd5576c2ed8dba45ba22c4f6884eb311d4f6e389203846d512ec11"
}

rule MalwareBazaar_Mirai_032_4d91f77e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d91f77e3e4a056b4c2f494ac6bade22d6ed083f757a75735698c2a08a5c37fe"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-31 00:50:06"
  condition:
    hash.sha256(0, filesize) == "4d91f77e3e4a056b4c2f494ac6bade22d6ed083f757a75735698c2a08a5c37fe"
}

rule MalwareBazaar_Mirai_033_ddf666a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddf666a2eb3096803696ddf5fee4eb56922a67b89242370a0796289feb124357"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-31 00:49:38"
  condition:
    hash.sha256(0, filesize) == "ddf666a2eb3096803696ddf5fee4eb56922a67b89242370a0796289feb124357"
}

rule MalwareBazaar_Mirai_034_a8ff9266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ff9266caf4a5c7871f67e6dd1efdec84998ebc5a18970273350407b7a02dbf"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-31 00:48:35"
  condition:
    hash.sha256(0, filesize) == "a8ff9266caf4a5c7871f67e6dd1efdec84998ebc5a18970273350407b7a02dbf"
}

rule MalwareBazaar_Mirai_035_7d56228e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d56228e11bcf1feafa30c07418322cbd223b2d95b8092fc34e7e3a346f19361"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-31 00:46:19"
  condition:
    hash.sha256(0, filesize) == "7d56228e11bcf1feafa30c07418322cbd223b2d95b8092fc34e7e3a346f19361"
}

rule MalwareBazaar_Mirai_036_fd0dfe41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd0dfe41d5290fc192b1af69eb866c40387a59848f8c99946a30be1e70bf639d"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-31 00:44:38"
  condition:
    hash.sha256(0, filesize) == "fd0dfe41d5290fc192b1af69eb866c40387a59848f8c99946a30be1e70bf639d"
}

rule MalwareBazaar_Mirai_037_2873519d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2873519dc02a5080e24cf664641d4ba6f4ca92d7b2c5861d420efa3cab7807fd"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-31 00:44:10"
  condition:
    hash.sha256(0, filesize) == "2873519dc02a5080e24cf664641d4ba6f4ca92d7b2c5861d420efa3cab7807fd"
}

rule MalwareBazaar_Mirai_038_770296c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "770296c3740810517ffe272adbb0c45160e2f309b206f14695cb125e6d240217"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-31 00:42:36"
  condition:
    hash.sha256(0, filesize) == "770296c3740810517ffe272adbb0c45160e2f309b206f14695cb125e6d240217"
}

rule MalwareBazaar_Mirai_039_0b54fb4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b54fb4e5cab6274b4604abe2ef2514f11e5c61ccd0eb5006075b1770665f0d4"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-31 00:41:31"
  condition:
    hash.sha256(0, filesize) == "0b54fb4e5cab6274b4604abe2ef2514f11e5c61ccd0eb5006075b1770665f0d4"
}

rule MalwareBazaar_Mirai_040_5343115d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5343115d212ba59929bc32e42f33689f683982a0c660297029e6892316a1226e"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-31 00:40:49"
  condition:
    hash.sha256(0, filesize) == "5343115d212ba59929bc32e42f33689f683982a0c660297029e6892316a1226e"
}

rule MalwareBazaar_Mirai_041_5fc0a59a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc0a59adeec5452af90ecd17f5d909309e86c6ae632fde01748a1e7814d823d"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-31 00:40:26"
  condition:
    hash.sha256(0, filesize) == "5fc0a59adeec5452af90ecd17f5d909309e86c6ae632fde01748a1e7814d823d"
}

rule MalwareBazaar_Mirai_042_0a75f316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a75f316cdc7e7cd61881368081f801ee7b63a98174de6cea80f9da85cddc945"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-07-31 00:39:21"
  condition:
    hash.sha256(0, filesize) == "0a75f316cdc7e7cd61881368081f801ee7b63a98174de6cea80f9da85cddc945"
}

rule MalwareBazaar_Mirai_043_60bc107d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60bc107df8681a7088dbba0e7198044cd2c4bc8a97ab80ed4e17389ce8cc3d75"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-31 00:38:31"
  condition:
    hash.sha256(0, filesize) == "60bc107df8681a7088dbba0e7198044cd2c4bc8a97ab80ed4e17389ce8cc3d75"
}

rule MalwareBazaar_Mirai_044_b277ac8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b277ac8ece6cb1a417fbad35fac655fc28036b7529bfbaa34bc36b293388a67c"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-31 00:38:17"
  condition:
    hash.sha256(0, filesize) == "b277ac8ece6cb1a417fbad35fac655fc28036b7529bfbaa34bc36b293388a67c"
}

rule MalwareBazaar_WannaCry_045_93f1112e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647"
    family = "WannaCry"
    file_name = "93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647"
    file_type = "exe"
    first_seen = "2026-07-31 00:15:37"
  condition:
    hash.sha256(0, filesize) == "93f1112efb938edee0b52aa69c28303d99b489ec0d785af553250478546ec647"
}

rule MalwareBazaar_NanoCore_046_589e46d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "589e46d07f1239dd6b8b07a00d5739279648863d9cc78ced1a05fb034fc16122"
    family = "NanoCore"
    file_name = "DA3635D346D58158CB0E09ADDD12F5B2.exe"
    file_type = "exe"
    first_seen = "2026-07-31 00:15:04"
  condition:
    hash.sha256(0, filesize) == "589e46d07f1239dd6b8b07a00d5739279648863d9cc78ced1a05fb034fc16122"
}

rule MalwareBazaar_unknown_047_b2388fb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2388fb3fedb1d62f7a6cd1719613b5f298c56e677de981f339550a6b7a3daf3"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-31 00:14:53"
  condition:
    hash.sha256(0, filesize) == "b2388fb3fedb1d62f7a6cd1719613b5f298c56e677de981f339550a6b7a3daf3"
}

rule MalwareBazaar_unknown_048_c076437d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c076437d6a30f394ea3f97331987884228703b350026da16337e7c1b4d740b66"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-31 00:13:13"
  condition:
    hash.sha256(0, filesize) == "c076437d6a30f394ea3f97331987884228703b350026da16337e7c1b4d740b66"
}

rule MalwareBazaar_unknown_049_c50a08b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c50a08b67bbe92e4afae7bb28b33af820001aa384ee82ad1a88e16d623c14e6d"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-31 00:11:00"
  condition:
    hash.sha256(0, filesize) == "c50a08b67bbe92e4afae7bb28b33af820001aa384ee82ad1a88e16d623c14e6d"
}

rule MalwareBazaar_unknown_050_847daefa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847daefabc7cf5e466c8540fc331a2ee340fe286aaa7127b20527beaf8b8fce2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-31 00:05:37"
  condition:
    hash.sha256(0, filesize) == "847daefabc7cf5e466c8540fc331a2ee340fe286aaa7127b20527beaf8b8fce2"
}

rule MalwareBazaar_unknown_051_223f03fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "223f03fcc04e7c0f0fdc1b5ffaa30ce817269ad1903d25036887bea299cdf187"
    family = "unknown"
    file_name = "Setup64x.exe"
    file_type = "exe"
    first_seen = "2026-07-30 23:55:48"
  condition:
    hash.sha256(0, filesize) == "223f03fcc04e7c0f0fdc1b5ffaa30ce817269ad1903d25036887bea299cdf187"
}

rule MalwareBazaar_unknown_052_8cd988e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cd988e1f749a5e008128df6f2b7da55c2760fbcdf414f26260331db723e6a15"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 23:52:32"
  condition:
    hash.sha256(0, filesize) == "8cd988e1f749a5e008128df6f2b7da55c2760fbcdf414f26260331db723e6a15"
}

rule MalwareBazaar_WannaCry_053_84896058
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead"
    family = "WannaCry"
    file_name = "8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead"
    file_type = "exe"
    first_seen = "2026-07-30 23:15:37"
  condition:
    hash.sha256(0, filesize) == "8489605870dd2735a8298cbb05db98cc6dc1d49e30caf3aa7d3260cc8fecdead"
}

rule MalwareBazaar_unknown_054_3f9f8dd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f9f8dd458b0a1f82c47dfdde874f609ae5f451644fb96c85c95403d2f4816a4"
    family = "unknown"
    file_name = "Zeta_Launcher_v2.4.3.zip"
    file_type = "zip"
    first_seen = "2026-07-30 23:15:09"
  condition:
    hash.sha256(0, filesize) == "3f9f8dd458b0a1f82c47dfdde874f609ae5f451644fb96c85c95403d2f4816a4"
}

rule MalwareBazaar_unknown_055_c2ae41bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2ae41bff71b9d5dd6d5845f1cda894729f406db9501c3afca402420b91515c0"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 22:52:31"
  condition:
    hash.sha256(0, filesize) == "c2ae41bff71b9d5dd6d5845f1cda894729f406db9501c3afca402420b91515c0"
}

rule MalwareBazaar_ValleyRAT_056_58b16700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58b16700b8a3b8f0db2fb2e14b8c3e835270111518e67239b373a81ffd265b9a"
    family = "ValleyRAT"
    file_name = "8F93AA8AA04CA6C13477542655CDB74B.exe"
    file_type = "exe"
    first_seen = "2026-07-30 22:45:09"
  condition:
    hash.sha256(0, filesize) == "58b16700b8a3b8f0db2fb2e14b8c3e835270111518e67239b373a81ffd265b9a"
}

rule MalwareBazaar_unknown_057_9117cbba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9117cbbaf4a200b534763f9c129d0f1a7bfca9d73d9a1fbfe97564790405e902"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-30 22:43:14"
  condition:
    hash.sha256(0, filesize) == "9117cbbaf4a200b534763f9c129d0f1a7bfca9d73d9a1fbfe97564790405e902"
}

rule MalwareBazaar_CoinMiner_058_ca116b3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca116b3d7caea85d448cc674087381d06902d80f2d2842e8dc22cd4b266379b5"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 22:31:00"
  condition:
    hash.sha256(0, filesize) == "ca116b3d7caea85d448cc674087381d06902d80f2d2842e8dc22cd4b266379b5"
}

rule MalwareBazaar_WannaCry_059_79cab94e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee"
    family = "WannaCry"
    file_name = "79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee"
    file_type = "exe"
    first_seen = "2026-07-30 22:16:31"
  condition:
    hash.sha256(0, filesize) == "79cab94e4ca816acbb4068254adaac761f16f8a6e4796408c77840235e5890ee"
}

rule MalwareBazaar_unknown_060_2aab00de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2aab00defb69f62ea24fcf2d2afc85750e1e24bc67a6e2fed6166438dfc1172d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 21:52:31"
  condition:
    hash.sha256(0, filesize) == "2aab00defb69f62ea24fcf2d2afc85750e1e24bc67a6e2fed6166438dfc1172d"
}

rule MalwareBazaar_unknown_061_0262c43c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0262c43ca22a7fb751f38117641a206220b0ab116cd79864c7336207dffa7358"
    family = "unknown"
    file_name = "Purchase Order-AUG.js"
    file_type = "js"
    first_seen = "2026-07-30 21:29:29"
  condition:
    hash.sha256(0, filesize) == "0262c43ca22a7fb751f38117641a206220b0ab116cd79864c7336207dffa7358"
}

rule MalwareBazaar_unknown_062_a0f85de5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0f85de525c9f1126dd701b4b9a50237ef6dd1605836da64e983e49a2c50d268"
    family = "unknown"
    file_name = "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:55"
  condition:
    hash.sha256(0, filesize) == "a0f85de525c9f1126dd701b4b9a50237ef6dd1605836da64e983e49a2c50d268"
}

rule MalwareBazaar_unknown_063_e98f7288
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e98f72882d520f1a1d17036847154b84db0b44a463f75d2d12af1bb9c48fff95"
    family = "unknown"
    file_name = "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:49"
  condition:
    hash.sha256(0, filesize) == "e98f72882d520f1a1d17036847154b84db0b44a463f75d2d12af1bb9c48fff95"
}

rule MalwareBazaar_unknown_064_b9679a47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9679a478bea2fb3eb238e75139e20fff5652b1b2495e6cc66e9f7110e3f4339"
    family = "unknown"
    file_name = "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:44"
  condition:
    hash.sha256(0, filesize) == "b9679a478bea2fb3eb238e75139e20fff5652b1b2495e6cc66e9f7110e3f4339"
}

rule MalwareBazaar_unknown_065_431f2f7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "431f2f7b389128c829dcd139f4f1c3bf95411ea14b87e271c0b04ad6469ba896"
    family = "unknown"
    file_name = "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:36"
  condition:
    hash.sha256(0, filesize) == "431f2f7b389128c829dcd139f4f1c3bf95411ea14b87e271c0b04ad6469ba896"
}

rule MalwareBazaar_unknown_066_f0aa83bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
    family = "unknown"
    file_name = "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:08"
  condition:
    hash.sha256(0, filesize) == "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
}

rule MalwareBazaar_unknown_067_3f3bf218
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39"
    family = "unknown"
    file_name = "3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:06"
  condition:
    hash.sha256(0, filesize) == "3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39"
}

rule MalwareBazaar_unknown_068_8e1a67a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70"
    family = "unknown"
    file_name = "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:05"
  condition:
    hash.sha256(0, filesize) == "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70"
}

rule MalwareBazaar_unknown_069_d1cac82f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e"
    family = "unknown"
    file_name = "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:03"
  condition:
    hash.sha256(0, filesize) == "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e"
}

rule MalwareBazaar_unknown_070_d70f917e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141"
    family = "unknown"
    file_name = "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141"
    file_type = "elf"
    first_seen = "2026-07-30 21:18:02"
  condition:
    hash.sha256(0, filesize) == "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141"
}

rule MalwareBazaar_unknown_071_c7ba7ec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7ba7ec8cb6953a25ab30fd3d9ec6c9422da9a9c9db8dad664667c5d4baa9a55"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-30 20:52:39"
  condition:
    hash.sha256(0, filesize) == "c7ba7ec8cb6953a25ab30fd3d9ec6c9422da9a9c9db8dad664667c5d4baa9a55"
}

rule MalwareBazaar_unknown_072_76b2713b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76b2713b63e443c83a23794087f2cad4b7588e78b0afa9a0fc276dd5de65a226"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 20:52:30"
  condition:
    hash.sha256(0, filesize) == "76b2713b63e443c83a23794087f2cad4b7588e78b0afa9a0fc276dd5de65a226"
}

rule MalwareBazaar_unknown_073_e71b7fd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e71b7fd8a38ace53045a576a8498f11a81c2d8f66b93086317c250dff5430429"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.MalwareX-gen.27393152"
    file_type = "exe"
    first_seen = "2026-07-30 20:50:45"
  condition:
    hash.sha256(0, filesize) == "e71b7fd8a38ace53045a576a8498f11a81c2d8f66b93086317c250dff5430429"
}

rule MalwareBazaar_Vjw0rm_074_ae0c7cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0c7cf73a0572469bd43b4f44bbe38b67ca35a45728c3f2a3cbb37662b44a8f"
    family = "Vjw0rm"
    file_name = "ORDER-0260730-006752.XLS.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:35:08"
  condition:
    hash.sha256(0, filesize) == "ae0c7cf73a0572469bd43b4f44bbe38b67ca35a45728c3f2a3cbb37662b44a8f"
}

rule MalwareBazaar_Mirai_075_1362adc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1362adc3a121da862b252c1e9d7beb81fc9d19aa18335555a6771a3685d46cca"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-07-30 20:22:42"
  condition:
    hash.sha256(0, filesize) == "1362adc3a121da862b252c1e9d7beb81fc9d19aa18335555a6771a3685d46cca"
}

rule MalwareBazaar_unknown_076_4178cf0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4178cf0bd11cd9977008647ebb6bb12a7ad34c384faab31da66c8dfbf64f72a4"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-30 20:21:31"
  condition:
    hash.sha256(0, filesize) == "4178cf0bd11cd9977008647ebb6bb12a7ad34c384faab31da66c8dfbf64f72a4"
}

rule MalwareBazaar_Mirai_077_33adb2cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33adb2cf048181b5de75d5dd5c837565a738ebd1350b7953e0dc47a3fb7040fe"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-07-30 20:21:29"
  condition:
    hash.sha256(0, filesize) == "33adb2cf048181b5de75d5dd5c837565a738ebd1350b7953e0dc47a3fb7040fe"
}

rule MalwareBazaar_RemcosRAT_078_38027ca6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38027ca6afc21bd734d86e96b8d3c6016e5afff6d8139b777cb55825a92f8f15"
    family = "RemcosRAT"
    file_name = "1314f9049217e0871f8979cf33b1ac63.exe"
    file_type = "exe"
    first_seen = "2026-07-30 20:15:20"
  condition:
    hash.sha256(0, filesize) == "38027ca6afc21bd734d86e96b8d3c6016e5afff6d8139b777cb55825a92f8f15"
}

rule MalwareBazaar_RemcosRAT_079_a477f89d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a477f89d63408f5ada9698388e4348c65611c81efe19681772e7354d64c2d3ed"
    family = "RemcosRAT"
    file_name = "1C1F469D72D082FB956CA88133D8D8DB.exe"
    file_type = "exe"
    first_seen = "2026-07-30 20:15:17"
  condition:
    hash.sha256(0, filesize) == "a477f89d63408f5ada9698388e4348c65611c81efe19681772e7354d64c2d3ed"
}

rule MalwareBazaar_AsyncRAT_080_c65f05b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c65f05b9f92b5d1cc2d19cf9f8d12fad263403d54952be88f93cd65a54239a5b"
    family = "AsyncRAT"
    file_name = "IntimationRefund2024-2025.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:15:14"
  condition:
    hash.sha256(0, filesize) == "c65f05b9f92b5d1cc2d19cf9f8d12fad263403d54952be88f93cd65a54239a5b"
}

rule MalwareBazaar_AsyncRAT_081_b7330cf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7330cf42457ba3a1cb515d260f2fb3f4dd90e4de9cf26fd6b070cf53109df6d"
    family = "AsyncRAT"
    file_name = "ITRIntimation24-25.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:15:11"
  condition:
    hash.sha256(0, filesize) == "b7330cf42457ba3a1cb515d260f2fb3f4dd90e4de9cf26fd6b070cf53109df6d"
}

rule MalwareBazaar_AsyncRAT_082_93a180ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93a180ec5678568b9d071861338cc3572ac8c95cba3f7887ab597565c722602f"
    family = "AsyncRAT"
    file_name = "IntimationReturn.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:15:08"
  condition:
    hash.sha256(0, filesize) == "93a180ec5678568b9d071861338cc3572ac8c95cba3f7887ab597565c722602f"
}

rule MalwareBazaar_STRRAT_083_de6f4352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de6f4352d29b306317a03c96a39d8d9df21c70435676311573f70b7e73acf567"
    family = "STRRAT"
    file_name = "ORDER-260730-0956436.XLS.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 20:15:05"
  condition:
    hash.sha256(0, filesize) == "de6f4352d29b306317a03c96a39d8d9df21c70435676311573f70b7e73acf567"
}

rule MalwareBazaar_unknown_084_5d19c6cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d19c6cd2687c25287f30d6de13a2e0ec95f909576f5d29b018be095062d3437"
    family = "unknown"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-30 20:07:47"
  condition:
    hash.sha256(0, filesize) == "5d19c6cd2687c25287f30d6de13a2e0ec95f909576f5d29b018be095062d3437"
}

rule MalwareBazaar_Mirai_085_468e406f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "468e406f1b699984ba66833482de4f1e4586e8f80bfbb8fd46056260ed19b0e4"
    family = "Mirai"
    file_name = "zero.m68k"
    file_type = "elf"
    first_seen = "2026-07-30 20:07:45"
  condition:
    hash.sha256(0, filesize) == "468e406f1b699984ba66833482de4f1e4586e8f80bfbb8fd46056260ed19b0e4"
}

rule MalwareBazaar_unknown_086_b253c73d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b253c73d2cac9ee27a3ebe89896b08bd455ed9f552ff7af20154d925822379ed"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 20:07:30"
  condition:
    hash.sha256(0, filesize) == "b253c73d2cac9ee27a3ebe89896b08bd455ed9f552ff7af20154d925822379ed"
}

rule MalwareBazaar_unknown_087_eaebbaf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaebbaf4e6affb72d0979fb50e61538cfb2f24f61b9c8157862f124f761465d9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 20:07:04"
  condition:
    hash.sha256(0, filesize) == "eaebbaf4e6affb72d0979fb50e61538cfb2f24f61b9c8157862f124f761465d9"
}

rule MalwareBazaar_unknown_088_6e6513b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e6513b872fcd852b76ac8927cc6126c63bd4b31badb2cb451d383c058f7fcb1"
    family = "unknown"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-07-30 20:05:15"
  condition:
    hash.sha256(0, filesize) == "6e6513b872fcd852b76ac8927cc6126c63bd4b31badb2cb451d383c058f7fcb1"
}

rule MalwareBazaar_Mirai_089_a90c1e26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a90c1e26e58a9744f4b647fbb6707e18df24b38a4769982a50a004ab909f9c66"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-07-30 20:03:32"
  condition:
    hash.sha256(0, filesize) == "a90c1e26e58a9744f4b647fbb6707e18df24b38a4769982a50a004ab909f9c66"
}

rule MalwareBazaar_Mirai_090_928ea1b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "928ea1b44130b207af4151cc988bb6beab1b94f29abcd6d58d469f6876f4f7ee"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-07-30 20:00:38"
  condition:
    hash.sha256(0, filesize) == "928ea1b44130b207af4151cc988bb6beab1b94f29abcd6d58d469f6876f4f7ee"
}

rule MalwareBazaar_Mirai_091_9a81a099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a81a09982169309d5d1c81b4563ba7d37ffe4cae58d3de3c2f5935f4809dc42"
    family = "Mirai"
    file_name = "cXiP"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:23"
  condition:
    hash.sha256(0, filesize) == "9a81a09982169309d5d1c81b4563ba7d37ffe4cae58d3de3c2f5935f4809dc42"
}

rule MalwareBazaar_Mirai_092_cec9d22b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cec9d22bdac621193a5ca25471be565cc88141bb163777b4f9b9c19b25bff42f"
    family = "Mirai"
    file_name = "kiA"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:21"
  condition:
    hash.sha256(0, filesize) == "cec9d22bdac621193a5ca25471be565cc88141bb163777b4f9b9c19b25bff42f"
}

rule MalwareBazaar_Mirai_093_7dcf4a36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dcf4a36579a8f730a0a624eae103f3726f7a6230e92fa16010cee45a494bb9d"
    family = "Mirai"
    file_name = "tAGc"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:20"
  condition:
    hash.sha256(0, filesize) == "7dcf4a36579a8f730a0a624eae103f3726f7a6230e92fa16010cee45a494bb9d"
}

rule MalwareBazaar_Mirai_094_0a072ac7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a072ac7e5af0b6af24550a46755dddfc6582e575112a9794ff6ada7e283ac6c"
    family = "Mirai"
    file_name = "fR9v"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:19"
  condition:
    hash.sha256(0, filesize) == "0a072ac7e5af0b6af24550a46755dddfc6582e575112a9794ff6ada7e283ac6c"
}

rule MalwareBazaar_Mirai_095_a5450557
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5450557a47e6bf770bcfa02c8731baf3600725eba203926631c0202a926798f"
    family = "Mirai"
    file_name = "CCJt"
    file_type = "elf"
    first_seen = "2026-07-30 19:55:18"
  condition:
    hash.sha256(0, filesize) == "a5450557a47e6bf770bcfa02c8731baf3600725eba203926631c0202a926798f"
}

rule MalwareBazaar_Mirai_096_cdc3b1b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdc3b1b449c8196d3025cf953f12c3eba5c6e3371b402e5ddd945170f831b546"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-07-30 19:54:45"
  condition:
    hash.sha256(0, filesize) == "cdc3b1b449c8196d3025cf953f12c3eba5c6e3371b402e5ddd945170f831b546"
}

rule MalwareBazaar_Mirai_097_e202969e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e202969e703aa1cffa4932c7dfba8b667e99f8c9cc556497223f5bc08e0756ea"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-07-30 19:54:10"
  condition:
    hash.sha256(0, filesize) == "e202969e703aa1cffa4932c7dfba8b667e99f8c9cc556497223f5bc08e0756ea"
}

rule MalwareBazaar_unknown_098_ad21776e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad21776ed177bd75e1771cf39efbf97f0d1c4d809f7bf5c93e2d14f6317b0999"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 19:52:31"
  condition:
    hash.sha256(0, filesize) == "ad21776ed177bd75e1771cf39efbf97f0d1c4d809f7bf5c93e2d14f6317b0999"
}

rule MalwareBazaar_unknown_099_bea4c166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bea4c166b9ad9a936911b052601f480ca4f2de0d3f7494fe35562805bf491491"
    family = "unknown"
    file_name = "e8feab72279dab768ac7bd1adcfe034a.exe"
    file_type = "exe"
    first_seen = "2026-07-30 19:51:34"
  condition:
    hash.sha256(0, filesize) == "bea4c166b9ad9a936911b052601f480ca4f2de0d3f7494fe35562805bf491491"
}

rule MalwareBazaar_Mirai_100_a685603b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a685603be47c7c2290ed7682ec863cfbf363db84ca1f6a7f46a1e1cf5ac98d19"
    family = "Mirai"
    file_name = "zero.armv7l"
    file_type = "elf"
    first_seen = "2026-07-30 19:48:38"
  condition:
    hash.sha256(0, filesize) == "a685603be47c7c2290ed7682ec863cfbf363db84ca1f6a7f46a1e1cf5ac98d19"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

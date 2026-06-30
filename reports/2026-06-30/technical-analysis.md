# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-06-30

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 627 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 627 |
| Unique family labels | 7 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 67 |
| unknown | 25 |
| ValleyRAT | 3 |
| Gafgyt | 2 |
| AgentTesla | 1 |
| MaskGramStealer | 1 |
| AveMariaRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 71 |
| exe | 15 |
| sh | 6 |
| unknown | 5 |
| js | 2 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `ea37cf74d52ae3a8`

| Field | Value |
|---|---|
| SHA-256 | `ea37cf74d52ae3a829b32b3c91f940132a649ec854b2d2377ef82c523fff7fe4` |
| Family label | `ValleyRAT` |
| File name | `4F46075552500DA5B19B711285A5152D.dll` |
| File type | `dll` |
| First seen | `2026-06-30 04:30:12` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f46075552500da5b19b711285a5152d` |
| SHA-1 | `0fda1bfcc63a8198882a0bbfcfdc1e40bc001df8` |
| SHA-256 | `ea37cf74d52ae3a829b32b3c91f940132a649ec854b2d2377ef82c523fff7fe4` |
| SHA3-384 | `9b37d6e2704dd2333c334f92ac360c5083fd7ea90d4d0204a5683306e664690031907425969306681c665464f23c5ee8` |
| IMPHASH | `2cf88258b418fcd7a89902f001ed24cf` |
| TLSH | `T1C3246B217680C13BC19B1A3196BF9FB618BCAA35176581CBB7904EB91E707D1FE3470A` |
| SSDEEP | `6144:n3WOArZU5HEl9YKmfeHvkZWNEbgN4YYYYE:3fA1U5HEl8eHvkZWNEHYYYY` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_001_ea37cf74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea37cf74d52ae3a829b32b3c91f940132a649ec854b2d2377ef82c523fff7fe4"
    family = "ValleyRAT"
    file_name = "4F46075552500DA5B19B711285A5152D.dll"
    file_type = "dll"
    first_seen = "2026-06-30 04:30:12"
  condition:
    hash.sha256(0, filesize) == "ea37cf74d52ae3a829b32b3c91f940132a649ec854b2d2377ef82c523fff7fe4"
}
```

### Sample 2: `f55acb3e7fde7e6f`

| Field | Value |
|---|---|
| SHA-256 | `f55acb3e7fde7e6f9800bc6b705cc4067a552bf480ba9c730d1f325d8ef1a15a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 03:42:18` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08e9531670974fdfa5a92dfc61fb70dd` |
| SHA-1 | `c5e8e846df06c92f52e3c1ce1df3812d3efcde83` |
| SHA-256 | `f55acb3e7fde7e6f9800bc6b705cc4067a552bf480ba9c730d1f325d8ef1a15a` |
| SHA3-384 | `868b26a6a07a944cfa46571ca7172fa930debab1668559bd2b41211dbe81e9f09dc6d84fa95390e7ea55aa94bff5fb63` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T12B22381F6E490131E7A18AF016B64B5E917D5673278BB3EBF333D5880BE95848011BAF` |
| SSDEEP | `96:k/dfsoGYz/9PYz/qYhwGgB3dSpqDrVx+ZQxrdcNGiPFJxGE9mZ2FFhxC7tCEmcfR:kqo1W4JBxx+exSLPFJxTEZmFhSmcUsh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_f55acb3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f55acb3e7fde7e6f9800bc6b705cc4067a552bf480ba9c730d1f325d8ef1a15a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 03:42:18"
  condition:
    hash.sha256(0, filesize) == "f55acb3e7fde7e6f9800bc6b705cc4067a552bf480ba9c730d1f325d8ef1a15a"
}
```

### Sample 3: `31a3bb40761aed25`

| Field | Value |
|---|---|
| SHA-256 | `31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a` |
| Family label | `unknown` |
| File name | `31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a` |
| File type | `elf` |
| First seen | `2026-06-30 03:10:37` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8fb2ee405c5638daf19e4d6f04e6264` |
| SHA-1 | `bae52dae900db1ae97acf83494350db852dbb64b` |
| SHA-256 | `31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a` |
| SHA3-384 | `d5eac2b8c565a173f8e997d3b9513ba84faed10e54b7eebc503cc3e01cb622b8b64811632d345ad3fd29a49777e268ff` |
| TLSH | `T1FEA2D040DF9082D6CEC0BDBA1E8C5331E2BB9780BDA6D83143E5C6ADDB76D51D972114` |
| SSDEEP | `384:GaiAgXHo4zkejSudOylMns6PmUipfaES8TR057HUkOeZHoc4wt:GfI4zlmuIruFUZ+47HU49ocp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_31a3bb40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a"
    family = "unknown"
    file_name = "31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a"
    file_type = "elf"
    first_seen = "2026-06-30 03:10:37"
  condition:
    hash.sha256(0, filesize) == "31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a"
}
```

### Sample 4: `7d06b7a9bd21800b`

| Field | Value |
|---|---|
| SHA-256 | `7d06b7a9bd21800b8f8151f42c9ccce3903479d8bb4ef0f7869cc69f08043abd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 03:09:25` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54b85f0168a06ee4c8a55b77f84f33f5` |
| SHA-1 | `5e714ebd805f2acef2812cf8d7bc277d91ffca96` |
| SHA-256 | `7d06b7a9bd21800b8f8151f42c9ccce3903479d8bb4ef0f7869cc69f08043abd` |
| SHA3-384 | `818882aeab7498fa3f2b965a332ec5cac14de4c9a8a9f44d02f69a63253792da159b9e39dc4ac47ce0d83669985ffe9d` |
| IMPHASH | `1f4aa02608e7148e89185346464290fd` |
| TLSH | `T12E75E05FFAA503E5C879D17984519212FAF1B8128B20AFDF62802E531E27EE85F3D314` |
| SSDEEP | `24576:gFtUNQKgVmhcjRrMvWR3IZ4uMGLqGKA91ltABKk+5ZqyBDYIZpqjQ:gyWlrgEAhMRXA9nkCZXBci` |
| ICON-DHASH | `f0f89a9a9adcf830` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_7d06b7a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d06b7a9bd21800b8f8151f42c9ccce3903479d8bb4ef0f7869cc69f08043abd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 03:09:25"
  condition:
    hash.sha256(0, filesize) == "7d06b7a9bd21800b8f8151f42c9ccce3903479d8bb4ef0f7869cc69f08043abd"
}
```

### Sample 5: `fe6c204be4172804`

| Field | Value |
|---|---|
| SHA-256 | `fe6c204be417280411d878672cf522d466732199b75261c533655621bcf8f284` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-06-30 02:35:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44d83d519035f0466130385eba151d41` |
| SHA-1 | `5fd0aa48c67c806ac36866f55b07e94e478409b3` |
| SHA-256 | `fe6c204be417280411d878672cf522d466732199b75261c533655621bcf8f284` |
| SHA3-384 | `626321e76b155d3619239f51a0d8650291075b7043eedea0180ccc30278f6adebc2b37d7ef4ab088c5886e09e261d190` |
| TLSH | `T1B0143A06B1C05CFEC8C5C3788BDFB536A83AF08D5225B65B6BC5BB212D4DD607A6D680` |
| TELFHASH | `t1ce51bf201daa7d6c62cb8716330ee669f97305500ef2b1eaaf2775d6cd067c81d970e2` |
| SSDEEP | `3072:wNhiKC7pQ3s3kS9XfivQokPlU/c9y/lqV61afTNL4K09FvSu2pegp1468m43PBs6:wNhiKC7pQ83kS9XfivQl96k4L3vdJ4Yh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_fe6c204b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe6c204be417280411d878672cf522d466732199b75261c533655621bcf8f284"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-06-30 02:35:13"
  condition:
    hash.sha256(0, filesize) == "fe6c204be417280411d878672cf522d466732199b75261c533655621bcf8f284"
}
```

### Sample 6: `6b0b063e20f67cf5`

| Field | Value |
|---|---|
| SHA-256 | `6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5` |
| Family label | `unknown` |
| File name | `6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5` |
| File type | `elf` |
| First seen | `2026-06-30 02:31:58` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2de584895188ae7b984e4bf35b624672` |
| SHA-1 | `1b5c00e3db26aa26ce4df1deb30f2b57a61ac061` |
| SHA-256 | `6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5` |
| SHA3-384 | `b488559369c20d85e4750f60641f646647f62b0d169f835fe6ad2cad05e37042d2e7fa949c53ab722189f8ec23f03816` |
| TLSH | `T19517BE77814338E9E5A98CB4D51025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQW:cqYUQuVDt0TZEV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_6b0b063e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5"
    family = "unknown"
    file_name = "6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5"
    file_type = "elf"
    first_seen = "2026-06-30 02:31:58"
  condition:
    hash.sha256(0, filesize) == "6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5"
}
```

### Sample 7: `90d8358588b9ded6`

| Field | Value |
|---|---|
| SHA-256 | `90d8358588b9ded64882a5385fc8c5f42f0ab963bad27951fda848e6926ac9c5` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-06-30 02:28:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `666c9726d029ed9c6798f099a1cb765f` |
| SHA-1 | `b965a981ffe4dc233c167e734af08f0a456c8302` |
| SHA-256 | `90d8358588b9ded64882a5385fc8c5f42f0ab963bad27951fda848e6926ac9c5` |
| SHA3-384 | `266f0a0edfc8bec24987a44be94890e31ddb5018b30c361495ccf9d5b66aa17ca5f904beb0a350e3d14ce448c8fe6981` |
| TLSH | `T182442B41AA404F23C4D727BAF69F4345333397E4D7E77305DA25ABB03A8779A2E26601` |
| TELFHASH | `t1b43121769774512669a0ec14d8e997b21a1fc7131341fe33df26c4cc681a44ef52ac4f` |
| SSDEEP | `6144:cKGK49WtEy8TM+3Faerc+FUaeSIC2rUls6jaMjSxsgKDM/Rrtmnqr:/t4o1+3Faerc+FUIxPXXWsgKY/53` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_90d83585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90d8358588b9ded64882a5385fc8c5f42f0ab963bad27951fda848e6926ac9c5"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-06-30 02:28:17"
  condition:
    hash.sha256(0, filesize) == "90d8358588b9ded64882a5385fc8c5f42f0ab963bad27951fda848e6926ac9c5"
}
```

### Sample 8: `2d477985d0347878`

| Field | Value |
|---|---|
| SHA-256 | `2d477985d03478784f158a4ab363d24ec2b4b43eb1bdd2f0db74c30c942375d1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 02:23:46` |
| Reporter | `Bitsight` |
| Tags | `54e64e, 9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `767c6a62cead5f8ed2b034a504348fa7` |
| SHA-1 | `58f2c09f93f85be3ce305afbfbcdafe45d8791b9` |
| SHA-256 | `2d477985d03478784f158a4ab363d24ec2b4b43eb1bdd2f0db74c30c942375d1` |
| SHA3-384 | `30f5425411d7dccbcb8e43717b402e7a09efceca9345ba258533fdbcf06dcac6031cab8bdeec94c7b118f99af80b7351` |
| IMPHASH | `98dd3d814a5021f0ae25288f1a64c7b4` |
| TLSH | `T12066F103A1E7CEF4D12BE67D46625373A924B0895E33B11C29A4F36A5FE0D34A15EB70` |
| SSDEEP | `98304:Ucq2gb+/ZOtFHNxZemybhjcnjHJuuoUZYV6jPQ9+A5VRg7h4guEiAcmt+jInErz3:UsO/demyMjpu6a67buEjcmUInErzvF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_2d477985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d477985d03478784f158a4ab363d24ec2b4b43eb1bdd2f0db74c30c942375d1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 02:23:46"
  condition:
    hash.sha256(0, filesize) == "2d477985d03478784f158a4ab363d24ec2b4b43eb1bdd2f0db74c30c942375d1"
}
```

### Sample 9: `df6191370cf98b3c`

| Field | Value |
|---|---|
| SHA-256 | `df6191370cf98b3c054aa3d686088b84ce4bfa862515c2abeff79c30eb7077d3` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-06-30 02:23:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20d8582d44cf469d9585e41d71cabdee` |
| SHA-1 | `15ad0ec6d4887a37b716ea517cc0ca2d864c1007` |
| SHA-256 | `df6191370cf98b3c054aa3d686088b84ce4bfa862515c2abeff79c30eb7077d3` |
| SHA3-384 | `aade723c32008cfa519f0815740bc75ff48939d927d511539af3bcd88dba1f5755d6231db002668b179ff773dfde6773` |
| TLSH | `T1DD14F915BD505F26C9C352BBFB5E438D372A17E8D3EB7202CE166B203A874972D3A641` |
| TELFHASH | `t1b8f0c9115b81146d3fa890cc82efc417b26971e4733e1851b2bf289c0fa68da7038a4c` |
| SSDEEP | `3072:7XxWtIB9MMfzW42NTQX3493cdytiBUbEjkT1+ckMqys4lIsF:7XRxzT2RM349MdeiBUnT1+Uls4lLF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_df619137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df6191370cf98b3c054aa3d686088b84ce4bfa862515c2abeff79c30eb7077d3"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-06-30 02:23:14"
  condition:
    hash.sha256(0, filesize) == "df6191370cf98b3c054aa3d686088b84ce4bfa862515c2abeff79c30eb7077d3"
}
```

### Sample 10: `24df5181c0875b59`

| Field | Value |
|---|---|
| SHA-256 | `24df5181c0875b598fbb04b6845be8bd5ab4cde3e5eb39233cefd3daf9083b36` |
| Family label | `AgentTesla` |
| File name | `Mv_Meritius_Requisition_Form.js` |
| File type | `js` |
| First seen | `2026-06-30 02:22:16` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcf466cb7c66468249f8221c47e0f5e3` |
| SHA-1 | `f09e1d4c69486215ebad48a30da633da7d48f558` |
| SHA-256 | `24df5181c0875b598fbb04b6845be8bd5ab4cde3e5eb39233cefd3daf9083b36` |
| SHA3-384 | `ff584df8e8a516355ef9375b95ab5e371322161897aa68c6a809d8541812278a57cd867a7237a88ca277dda8c8d555f5` |
| TLSH | `T1E0A56D258F26B0553C335AB26E542B93902FA36353EB68086F754ECC1F51B9B19B432F` |
| SSDEEP | `12288:sOTeVCucajXMfYFqeakMCKDDYdBi6i1ld2ohnmJq:JH7` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_010_24df5181
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24df5181c0875b598fbb04b6845be8bd5ab4cde3e5eb39233cefd3daf9083b36"
    family = "AgentTesla"
    file_name = "Mv_Meritius_Requisition_Form.js"
    file_type = "js"
    first_seen = "2026-06-30 02:22:16"
  condition:
    hash.sha256(0, filesize) == "24df5181c0875b598fbb04b6845be8bd5ab4cde3e5eb39233cefd3daf9083b36"
}
```

### Sample 11: `268c712de3d96bd3`

| Field | Value |
|---|---|
| SHA-256 | `268c712de3d96bd394632e67d86f4626ae15b0ac76d57c0a3e23b1fa2f41f0ad` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 02:21:51` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce3fa4f128226b18b56640699df75730` |
| SHA-1 | `f8a81ef2599e3617b1009f352a6220a0cb26a826` |
| SHA-256 | `268c712de3d96bd394632e67d86f4626ae15b0ac76d57c0a3e23b1fa2f41f0ad` |
| SHA3-384 | `4577939ea193e7ced88dc63b43d2b45c1ef7b69d39df3d5f0deffa048fe54958170358476b1a9844ca5598093dd46e1d` |
| IMPHASH | `332b41c0ffa734bb9c9d5b037af977ac` |
| TLSH | `T140C31292D3E84590D3B69537E8EB4269D4EC36288D89F64D0F9A0CEF3531BCE9FA1111` |
| SSDEEP | `3072:kdHsJbzB6/ci5bbCMcfBE8i4/yIUQbYdjbNpTxNcN:lE1b+MkBE8V/yI4d9pI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_268c712d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "268c712de3d96bd394632e67d86f4626ae15b0ac76d57c0a3e23b1fa2f41f0ad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 02:21:51"
  condition:
    hash.sha256(0, filesize) == "268c712de3d96bd394632e67d86f4626ae15b0ac76d57c0a3e23b1fa2f41f0ad"
}
```

### Sample 12: `164ac73154aafebc`

| Field | Value |
|---|---|
| SHA-256 | `164ac73154aafebcace00b726f8285cbe8bdf6bf937d70d2e4060eebae2062a8` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-06-30 02:13:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f20e6a9164085dca47f8c094af22bd5d` |
| SHA-1 | `a1ecf76af2b43f917f3099d81618a54fbfaeb918` |
| SHA-256 | `164ac73154aafebcace00b726f8285cbe8bdf6bf937d70d2e4060eebae2062a8` |
| SHA3-384 | `e1b784743647881a31c680b42ffc47412f3b90d044d08d8b975d287fac5d3b253ad503a51f95c144bd7a35a24079e3d0` |
| TLSH | `T1DF3407166F710FFBD8ABCE3742EA0B0538DC509B22A52B3536B4D524F50A54B69E3CB4` |
| SSDEEP | `3072:lm2zGN3BTljSIwExLAXWRlmTqJc5dt6EpRKckMqysvgIf:k4GJBRSIzxrvgqJsXfKUlsvgY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_164ac731
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "164ac73154aafebcace00b726f8285cbe8bdf6bf937d70d2e4060eebae2062a8"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-06-30 02:13:32"
  condition:
    hash.sha256(0, filesize) == "164ac73154aafebcace00b726f8285cbe8bdf6bf937d70d2e4060eebae2062a8"
}
```

### Sample 13: `0d87a0985a608c6e`

| Field | Value |
|---|---|
| SHA-256 | `0d87a0985a608c6e0dd1c43d37eabcb525f23e65630a9bc5dcd46a0c898bf502` |
| Family label | `Mirai` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-06-30 01:55:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6c5d9ece6137d1fcb8ba253cb1e3c08` |
| SHA-1 | `4c011cf13656c217ec3e6b406335d567560d5fe1` |
| SHA-256 | `0d87a0985a608c6e0dd1c43d37eabcb525f23e65630a9bc5dcd46a0c898bf502` |
| SHA3-384 | `ca8f7cadb47558c8d83bf93c9574001eb673541bcddb1e6d8634b8a22e5499682f665a566a4249fb3965f46960d17b9f` |
| TLSH | `T1DBE37C80F343D6F1DD924372502BAB335632A06A553BDB42DBEE6B31AC45540FA2B39D` |
| TELFHASH | `t1d051d2f9667a0cd8a7d09802f24d6b60bd5eab7b341437f749b329743227941027bc39` |
| SSDEEP | `3072:/5MNWznwjBYDIstv5gWKyAKgphVXNwMY468m43eCQ4:/5MNWjwlYEYB47V9r/OCx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_0d87a098
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d87a0985a608c6e0dd1c43d37eabcb525f23e65630a9bc5dcd46a0c898bf502"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-06-30 01:55:11"
  condition:
    hash.sha256(0, filesize) == "0d87a0985a608c6e0dd1c43d37eabcb525f23e65630a9bc5dcd46a0c898bf502"
}
```

### Sample 14: `44b6b758145eaa63`

| Field | Value |
|---|---|
| SHA-256 | `44b6b758145eaa63171cbb5cc2a28002abb30f94d8076ae727f5d876ffddcc13` |
| Family label | `Mirai` |
| File name | `main_mips` |
| File type | `elf` |
| First seen | `2026-06-30 01:48:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5bf2816d500f6313187ce6f3cf215a6` |
| SHA-1 | `71badfc1cc0deb60e66979bd7784433106ff7842` |
| SHA-256 | `44b6b758145eaa63171cbb5cc2a28002abb30f94d8076ae727f5d876ffddcc13` |
| SHA3-384 | `876268c158af7f88fee4f5d4fce46d04970cd992430f5d4d3a0ae2dd3bfb52778ea19bd7ad4b79b5527676322b551ae5` |
| TLSH | `T11F34D91E2E218F7DF6A9C7B547F74A219B6923D613D2D6C4D2ACD1005E2028E741FFA8` |
| TELFHASH | `t1fd41a1180d7813f4a2256c9d449dfb2be6a331eb7e162c238e11e85eeb69f435d14c1c` |
| SSDEEP | `3072:PCk5jbb7CPjNwa9vuWLv+jdBJHXrdN6C4xi9SvdxckMqysqGwqD00:akNbb7/yvzEHHXT//9SVxUlsq5Oh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_44b6b758
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44b6b758145eaa63171cbb5cc2a28002abb30f94d8076ae727f5d876ffddcc13"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-06-30 01:48:19"
  condition:
    hash.sha256(0, filesize) == "44b6b758145eaa63171cbb5cc2a28002abb30f94d8076ae727f5d876ffddcc13"
}
```

### Sample 15: `80df8251504352d1`

| Field | Value |
|---|---|
| SHA-256 | `80df8251504352d10f11985f7dbd73d1c2429692b2d87e81422982ed50382180` |
| Family label | `unknown` |
| File name | `2026-7C-004219-1.js` |
| File type | `js` |
| First seen | `2026-06-30 01:41:47` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91b1ba3239eaebe4eb78cd9ba15c9719` |
| SHA-1 | `6039302de8042a82ce5a8766a66eb2368b5db6e2` |
| SHA-256 | `80df8251504352d10f11985f7dbd73d1c2429692b2d87e81422982ed50382180` |
| SHA3-384 | `f5ae27c62de1ed4345546146ab52ec13b472d766cbf906552ce3902525abf3d41186b9b6d88d768ba7967d2a11bdf2c5` |
| TLSH | `T11BA502018AC43FBC8B9A5F2951BE6549E3E10D8FA4A4194AE733FD46FFF76018216178` |
| SSDEEP | `24576:uuldcrJJYxoCPgkKLff5n2j+6CWkkvEJ903rvlCNJy+n1YuGqeoZkB6qxp4CQtIS:tdFm+MTWzl3+fNeoZk98R1Hxph` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_80df8251
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80df8251504352d10f11985f7dbd73d1c2429692b2d87e81422982ed50382180"
    family = "unknown"
    file_name = "2026-7C-004219-1.js"
    file_type = "js"
    first_seen = "2026-06-30 01:41:47"
  condition:
    hash.sha256(0, filesize) == "80df8251504352d10f11985f7dbd73d1c2429692b2d87e81422982ed50382180"
}
```

### Sample 16: `fb98ed4d9a5ff701`

| Field | Value |
|---|---|
| SHA-256 | `fb98ed4d9a5ff70157e5652602a92a7edf0ac11af3a9981996dc00dcffd8cc2f` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-06-30 01:39:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac64a7e74c43ed32618e1d8e17ba8cb2` |
| SHA-1 | `579edf5d8869da76fcc492712d9a8ea9cca964bf` |
| SHA-256 | `fb98ed4d9a5ff70157e5652602a92a7edf0ac11af3a9981996dc00dcffd8cc2f` |
| SHA3-384 | `cb9c9e087511ee2dafc50ead2a1f1696b29c3981d1029f83495a620fa80b3f5ea2cdff42165a9de6b899cae4bb22b590` |
| TLSH | `T161142911B8419F21C9D212BEFA1E538D372717F8D3DF7212CE156B603A868AB1E3E645` |
| TELFHASH | `t14bf0ac70099408b837e05194c6fec13a596532f9393634619f3ff01e6a87ce0503840e` |
| SSDEEP | `3072:7QmrXBTDzMta/4VCRq2YlTHSl/7wnttUcUvWrR10XSt3l5/aFaG3d4uYdsuwDTBI:niHSN7IdIc0Xm3lRavKuYLwDNbUlsT+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_fb98ed4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb98ed4d9a5ff70157e5652602a92a7edf0ac11af3a9981996dc00dcffd8cc2f"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-06-30 01:39:10"
  condition:
    hash.sha256(0, filesize) == "fb98ed4d9a5ff70157e5652602a92a7edf0ac11af3a9981996dc00dcffd8cc2f"
}
```

### Sample 17: `22d7f840c2172050`

| Field | Value |
|---|---|
| SHA-256 | `22d7f840c2172050085316795c270b8f75da45108d087a132556ffbf8dd3e158` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-06-30 01:32:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87c43fd86c42b21e21239de021caac9b` |
| SHA-1 | `0a55c47b1ff795de246435b6d3072fd2f37ccf66` |
| SHA-256 | `22d7f840c2172050085316795c270b8f75da45108d087a132556ffbf8dd3e158` |
| SHA3-384 | `feb5226115639a0c4242003aff34cbf31398978010ae0574c7d360a7f1607f1de8aea0a79d65e77d5861f67ecf5ba9d9` |
| TLSH | `T10A047D32DC346F78CAA1C279A0E69F352B5355D182976FBA4B9BC3601443CD8B909BF4` |
| SSDEEP | `3072:NBM1TKCEuK1WlZwdFf0tGvoBRBzydMX/WPDhemckMqysLgIX:NW2CEP2Zo0tGvoxtuPsmUlsLgc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_22d7f840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22d7f840c2172050085316795c270b8f75da45108d087a132556ffbf8dd3e158"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-06-30 01:32:14"
  condition:
    hash.sha256(0, filesize) == "22d7f840c2172050085316795c270b8f75da45108d087a132556ffbf8dd3e158"
}
```

### Sample 18: `724666cc3e87297c`

| Field | Value |
|---|---|
| SHA-256 | `724666cc3e87297c4deafd3ab65b81b1493cd223b48baf2b588ad14894482eb9` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-06-30 01:22:28` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c80ed1b08701100c1195c625d210690` |
| SHA-1 | `fa3e3793d19c1e5d4eb63ba0175edbbf44dcfbbc` |
| SHA-256 | `724666cc3e87297c4deafd3ab65b81b1493cd223b48baf2b588ad14894482eb9` |
| SHA3-384 | `2ccedf365e71c0e1f89081705d04f11bcdbd2a1facdb2c050c2eb53d4eae52c44a72ec7d790aac2009a17ec269dc6c10` |
| TLSH | `T1C50188D98604AC1040A99A5D2297A454F82183CF259B8BA4BF7C6E2AEB98804B027F84` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha9SX9NcLFYFv8RH1lX:e9Qp+MsM7cxYFKVlX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_724666cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "724666cc3e87297c4deafd3ab65b81b1493cd223b48baf2b588ad14894482eb9"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-06-30 01:22:28"
  condition:
    hash.sha256(0, filesize) == "724666cc3e87297c4deafd3ab65b81b1493cd223b48baf2b588ad14894482eb9"
}
```

### Sample 19: `6da6fe83c1a948bb`

| Field | Value |
|---|---|
| SHA-256 | `6da6fe83c1a948bba950f53254b5130e0f17cc6a5af67ba4b3aa7f6c4e3801e4` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-06-30 01:10:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7d8d28d3fed2f1a743d3d9933cd58b1` |
| SHA-1 | `15c99984309f7c947ce4a5c3c44b30fe2dcb318e` |
| SHA-256 | `6da6fe83c1a948bba950f53254b5130e0f17cc6a5af67ba4b3aa7f6c4e3801e4` |
| SHA3-384 | `2058db5c35ec588320d014957b2a02417c07e6cdd3f3235f067d0d92158cd6165d9fa694165371de4effc5bb8b2b259f` |
| TLSH | `T12101AFD58600AD10403D9A5E7297A5A0B421C3CF059B0BB47FBC5E2DFB98804B027F44` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha9SX9ZcnFOzFv8RL1v7:e9Qp+MsMXcFOzFKhv7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_6da6fe83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6da6fe83c1a948bba950f53254b5130e0f17cc6a5af67ba4b3aa7f6c4e3801e4"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-30 01:10:27"
  condition:
    hash.sha256(0, filesize) == "6da6fe83c1a948bba950f53254b5130e0f17cc6a5af67ba4b3aa7f6c4e3801e4"
}
```

### Sample 20: `7290cbb1028c1b54`

| Field | Value |
|---|---|
| SHA-256 | `7290cbb1028c1b544a0d38509321df1c391c4cf7f4dd9e5b751c6132738b1bc3` |
| Family label | `Mirai` |
| File name | `main_aarch64` |
| File type | `elf` |
| First seen | `2026-06-30 01:08:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d137da0ee97cf99d00ac528efb86660` |
| SHA-1 | `baae0995dfa7b90441e21775f86c776048c401f4` |
| SHA-256 | `7290cbb1028c1b544a0d38509321df1c391c4cf7f4dd9e5b751c6132738b1bc3` |
| SHA3-384 | `78602e60cc564555f5d2e94cd171a881adfad080d0463249cdb01a9dfae8393dd4d55a9fac36238bd87dc6d24478f2c6` |
| TLSH | `T1FD045B2EEE0ADE55CEC6C37E9D9A0FA3703234A49752C1B34F42907CB68B6D574B8095` |
| SSDEEP | `3072:XFol/IEvRXZGt3CeDWVWmLCfkjyYJlMBwucDleBU+KhR1ctaysd+kB:NE0LSgxYJ5leBDKxEVsd+k` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_7290cbb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7290cbb1028c1b544a0d38509321df1c391c4cf7f4dd9e5b751c6132738b1bc3"
    family = "Mirai"
    file_name = "main_aarch64"
    file_type = "elf"
    first_seen = "2026-06-30 01:08:15"
  condition:
    hash.sha256(0, filesize) == "7290cbb1028c1b544a0d38509321df1c391c4cf7f4dd9e5b751c6132738b1bc3"
}
```

### Sample 21: `22ea2b5030dfa05a`

| Field | Value |
|---|---|
| SHA-256 | `22ea2b5030dfa05adbd50d714c170fd0a0c4ff4d0a245a46a8a7a23f995e6d3b` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-06-30 01:05:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52db389b981279765c0e97991f2b4d26` |
| SHA-1 | `1b87fe003190c174cdae2847347c91618775aefd` |
| SHA-256 | `22ea2b5030dfa05adbd50d714c170fd0a0c4ff4d0a245a46a8a7a23f995e6d3b` |
| SHA3-384 | `3d0c8d6d72000b902a803fda656f34db9f7913624c9125f80018c1a1a02a83c85eb477f49f1f66ded83c55d04b1494af` |
| TLSH | `T1DB145A02771C0A17D2932FF42A3F2BE093AF95D121E2F640AB4F9A855176D723459ECB` |
| SSDEEP | `3072:kQSvZN7J6yXskxh7B2G7x59mWUHckMqysltjgd:WvnN62skxdB2G7L4WmUlslxgd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_22ea2b50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22ea2b5030dfa05adbd50d714c170fd0a0c4ff4d0a245a46a8a7a23f995e6d3b"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-06-30 01:05:31"
  condition:
    hash.sha256(0, filesize) == "22ea2b5030dfa05adbd50d714c170fd0a0c4ff4d0a245a46a8a7a23f995e6d3b"
}
```

### Sample 22: `a79102b1943a98ec`

| Field | Value |
|---|---|
| SHA-256 | `a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1` |
| Family label | `unknown` |
| File name | `a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1` |
| File type | `exe` |
| First seen | `2026-06-30 01:00:43` |
| Reporter | `johnk3r` |
| Tags | `banker, exe, skywalker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1317ad649bdf2b62c5bdae50444fd09` |
| SHA-1 | `3b5170aead120abe59cac82a4f10c1ad9694b73d` |
| SHA-256 | `a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1` |
| SHA3-384 | `b3ef20dcc4e125d64417e15fa0c2a5418c13a5ebf596b381ec751c628291156ad5fccf71da8ce6df3e0673563b654e86` |
| TLSH | `T1FCC51A9D765076DFCC5BC972CAA81C74EA5074BB930BE207942316ED9A0D99BCF180F2` |
| SSDEEP | `49152:yP+NwzOmIjinorWWQPJivWLUdSD/212pGA7C:yP+NC3MWWQQv8UdSD/2E8A` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_a79102b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1"
    family = "unknown"
    file_name = "a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1"
    file_type = "exe"
    first_seen = "2026-06-30 01:00:43"
  condition:
    hash.sha256(0, filesize) == "a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1"
}
```

### Sample 23: `31ea1252fc6866e3`

| Field | Value |
|---|---|
| SHA-256 | `31ea1252fc6866e35ed394c00647a3f811c6b3a4edfdcfc42b2609fa1411af4b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 00:59:42` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8346e093a9b5a5722c482877e2f5eb08` |
| SHA-1 | `6d2af3960f4c159fd721cd7a695bb6c2b2beef59` |
| SHA-256 | `31ea1252fc6866e35ed394c00647a3f811c6b3a4edfdcfc42b2609fa1411af4b` |
| SHA3-384 | `01d6b3f8dd5f6bcf5cf3ad3dba11d91bddd46d1110ceab13f83f19f8937ba56a468f824d82bed25c43a813bbed2fe9ac` |
| IMPHASH | `47e1b6c93da00245a33e9a81299262d5` |
| TLSH | `T1A4F512427F54D902D55A2E7189B4C7B42320FC589A29C38B34E67E5FFED9AD35E222C0` |
| SSDEEP | `49152:PzG/JmqYV045IikPAUOgujOGgxfmB85CnRoHgWTn7NZmwrphp:PzKmp7ZNUOlSf+O5qSZz/` |
| ICON-DHASH | `9271e8c0c0c0e000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_31ea1252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31ea1252fc6866e35ed394c00647a3f811c6b3a4edfdcfc42b2609fa1411af4b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 00:59:42"
  condition:
    hash.sha256(0, filesize) == "31ea1252fc6866e35ed394c00647a3f811c6b3a4edfdcfc42b2609fa1411af4b"
}
```

### Sample 24: `9723ffa8e979dabd`

| Field | Value |
|---|---|
| SHA-256 | `9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8` |
| Family label | `unknown` |
| File name | `9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8` |
| File type | `exe` |
| First seen | `2026-06-30 00:58:57` |
| Reporter | `johnk3r` |
| Tags | `banker, exe, skywalker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f52a7e4256ff562be6a7bf4b1dec922` |
| SHA-1 | `c0a48e07c80595d53e730b2afc76980f634abad7` |
| SHA-256 | `9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8` |
| SHA3-384 | `7618e0bc77bacf859efaa547a5e441945f8ddfbc09ff46f00d7ed7bb22a8808e5e25b636f264b20928432cb288cb8a09` |
| TLSH | `T147C5199D765075DFCC5BC972CAA81C64EA5074BB630BE207A42316EC9E0D99BCF184F2` |
| SSDEEP | `24576:LSAUem+a1pO4pd66u3jzSqSz0eAZa63HUaR1FeUpRy2tcoKXs/yV36/51XUiAR6Q:LSAf0zR76Jz1eUXXR1V1cTriHxF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_9723ffa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8"
    family = "unknown"
    file_name = "9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8"
    file_type = "exe"
    first_seen = "2026-06-30 00:58:57"
  condition:
    hash.sha256(0, filesize) == "9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8"
}
```

### Sample 25: `072b708c1658e274`

| Field | Value |
|---|---|
| SHA-256 | `072b708c1658e2744b77af796f5f12b9edd0bcfed6aa338fafab2891de868205` |
| Family label | `unknown` |
| File name | `rev.sh` |
| File type | `sh` |
| First seen | `2026-06-30 00:56:09` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28da33ca44dfcddd729a6099343a6dff` |
| SHA-1 | `f53e5df6c6f7142403affa6b78439792facabe2e` |
| SHA-256 | `072b708c1658e2744b77af796f5f12b9edd0bcfed6aa338fafab2891de868205` |
| SHA3-384 | `9e0f7fabb6615749efabd17129e700a2a8c9ebf7b1d9d235393b73f11d3c3e8c1fa0fa1e7aa7fd8753598604dd841751` |
| TLSH | `T173219DB1A7F12DB93F7484586147E120B6DA7F874B8C9CE24C3D5AE13623548F0B0B24` |
| SSDEEP | `24:w1NLHte/uDupr+SrNvNSL5lOKT0TGz5lOKT0TGP:wT5o6SuOKT0TGGKT0TGP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_072b708c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "072b708c1658e2744b77af796f5f12b9edd0bcfed6aa338fafab2891de868205"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-06-30 00:56:09"
  condition:
    hash.sha256(0, filesize) == "072b708c1658e2744b77af796f5f12b9edd0bcfed6aa338fafab2891de868205"
}
```

### Sample 26: `f96575db91db3fc3`

| Field | Value |
|---|---|
| SHA-256 | `f96575db91db3fc3f49101dbc1d31ff9a596d8d2aa51c5d0951db941623f9ba0` |
| Family label | `ValleyRAT` |
| File name | `3004dc9fd6900a26cf5efb6e757f3e13.exe` |
| File type | `exe` |
| First seen | `2026-06-30 00:45:14` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3004dc9fd6900a26cf5efb6e757f3e13` |
| SHA-1 | `333c4e6400c4b75297dbd088bfe7763be9ed875d` |
| SHA-256 | `f96575db91db3fc3f49101dbc1d31ff9a596d8d2aa51c5d0951db941623f9ba0` |
| SHA3-384 | `7143436adf36a8a537c066822b325342e07fdb2da2876c137e5ac5954e4e35ee03aea7e05682ed27d7f9c6847b5f7596` |
| IMPHASH | `9d16429ea3f188ffcf2e3096ce40da3c` |
| TLSH | `T1D9A42B6BF711CFBCC08BC77444A297E29630FE280A71978A52C1B71F1DB1DA06E6964D` |
| SSDEEP | `6144:hW4BCyi3j/63SxXGYA7KgjdPXHkpFrPTf03WBHYD3fmat:Ej/6ixWYLg5PXEpVTf03WBHYzfmat` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_026_f96575db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f96575db91db3fc3f49101dbc1d31ff9a596d8d2aa51c5d0951db941623f9ba0"
    family = "ValleyRAT"
    file_name = "3004dc9fd6900a26cf5efb6e757f3e13.exe"
    file_type = "exe"
    first_seen = "2026-06-30 00:45:14"
  condition:
    hash.sha256(0, filesize) == "f96575db91db3fc3f49101dbc1d31ff9a596d8d2aa51c5d0951db941623f9ba0"
}
```

### Sample 27: `149e6ee81e88ce9a`

| Field | Value |
|---|---|
| SHA-256 | `149e6ee81e88ce9a42851961d11bd8ed7654f553b160e125dbecc6ef963a14d5` |
| Family label | `unknown` |
| File name | `.bash_history` |
| File type | `unknown` |
| First seen | `2026-06-30 00:44:29` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5db062e849287d6580e2344dc97986ce` |
| SHA-256 | `149e6ee81e88ce9a42851961d11bd8ed7654f553b160e125dbecc6ef963a14d5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_149e6ee8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "149e6ee81e88ce9a42851961d11bd8ed7654f553b160e125dbecc6ef963a14d5"
    family = "unknown"
    file_name = ".bash_history"
    file_type = "unknown"
    first_seen = "2026-06-30 00:44:29"
  condition:
    hash.sha256(0, filesize) == "149e6ee81e88ce9a42851961d11bd8ed7654f553b160e125dbecc6ef963a14d5"
}
```

### Sample 28: `51634b90405a6af4`

| Field | Value |
|---|---|
| SHA-256 | `51634b90405a6af4e01b530eaabee0b2a23f446855693bad966dbb8374ec6a1b` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-06-30 00:42:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae24f40f640515d623050e1f681b50ef` |
| SHA-1 | `4987178eefb9efb6d9cda5e1d76a923bf8f36875` |
| SHA-256 | `51634b90405a6af4e01b530eaabee0b2a23f446855693bad966dbb8374ec6a1b` |
| SHA3-384 | `8245f27d4a80438f1c5fe47f73549dd983ee4b8b81219f8257031a3dbc9aa0fcd589893952cac6f3f1a045b94c241e82` |
| TLSH | `T1EE245B97B500EEBDFC0AF33B44175935713077E274934B37A35B79A6AC69084283AE86` |
| SSDEEP | `3072:NgeMeZS93wIHwRHf3vTBnBG1koKDifEQTpRF4VojbivL27PoyHhH468m43SLr:Nghl3wsQhBG1HKDItRFmL20yH2iLr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_51634b90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51634b90405a6af4e01b530eaabee0b2a23f446855693bad966dbb8374ec6a1b"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-06-30 00:42:19"
  condition:
    hash.sha256(0, filesize) == "51634b90405a6af4e01b530eaabee0b2a23f446855693bad966dbb8374ec6a1b"
}
```

### Sample 29: `ac4066497f065e66`

| Field | Value |
|---|---|
| SHA-256 | `ac4066497f065e66e6552267c6c359b6739b3203de70dd066a292e3e9541aebc` |
| Family label | `Mirai` |
| File name | `main_arm5` |
| File type | `elf` |
| First seen | `2026-06-30 00:35:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa2ee750aa8c3db29048859cacde786c` |
| SHA-1 | `8f76736e71e666845bbcbf328c30e3a953699b8a` |
| SHA-256 | `ac4066497f065e66e6552267c6c359b6739b3203de70dd066a292e3e9541aebc` |
| SHA3-384 | `fb6345253ae11c011890eec49af441d46b9321780bab0101b118150b098db55eeb9f13c91f0413a17db8b0d49e27372d` |
| TLSH | `T1E5141A11BD505B26C9D352BBFB5E438D372A17E8D3EB7202CE266F2036874972D3A641` |
| TELFHASH | `t183110e06db501b9c7fc454c482ed5217fab630f0b6652840febe279f8f824c67025829` |
| SSDEEP | `3072:aP3KFA/Zvq3zVQAEuCbM9X4N+beyHX0LCKIoJbsckMqysqIm:aPzijVRyQ4NMeyHX0lIoJbsUlsql` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_ac406649
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac4066497f065e66e6552267c6c359b6739b3203de70dd066a292e3e9541aebc"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-06-30 00:35:29"
  condition:
    hash.sha256(0, filesize) == "ac4066497f065e66e6552267c6c359b6739b3203de70dd066a292e3e9541aebc"
}
```

### Sample 30: `ce779eea029e7597`

| Field | Value |
|---|---|
| SHA-256 | `ce779eea029e759719fae9e424c52954c1f7e5373099b5d45426ca01bec50d04` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-30 00:31:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ecbff7dfed196a028c0e371a30494b3` |
| SHA-1 | `1c63498ee193f6ac1b241a7406dce3ba85288138` |
| SHA-256 | `ce779eea029e759719fae9e424c52954c1f7e5373099b5d45426ca01bec50d04` |
| SHA3-384 | `88b003c58e3dbef34c72404b1dca158b0c90c87bbc791ec02553de500edd7f6aa7c20f49a4e34ead6ff24cc5816a3334` |
| TLSH | `T128236C6556857C24AE99C8361C7E2F0CB9AD83E5320451EDBFCB3CF28C4AA9CE11971D` |
| SSDEEP | `768:i+F9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:i+WcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_ce779eea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce779eea029e759719fae9e424c52954c1f7e5373099b5d45426ca01bec50d04"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-30 00:31:10"
  condition:
    hash.sha256(0, filesize) == "ce779eea029e759719fae9e424c52954c1f7e5373099b5d45426ca01bec50d04"
}
```

### Sample 31: `a17eda1169e4bf8d`

| Field | Value |
|---|---|
| SHA-256 | `a17eda1169e4bf8d16020ba917b13708f8abeb0bffafee5c1da99ec5cfd49a00` |
| Family label | `unknown` |
| File name | `o.xml` |
| File type | `unknown` |
| First seen | `2026-06-30 00:24:11` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbea7ffbb515a1d20478b78d047c81c9` |
| SHA-256 | `a17eda1169e4bf8d16020ba917b13708f8abeb0bffafee5c1da99ec5cfd49a00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_a17eda11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a17eda1169e4bf8d16020ba917b13708f8abeb0bffafee5c1da99ec5cfd49a00"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-06-30 00:24:11"
  condition:
    hash.sha256(0, filesize) == "a17eda1169e4bf8d16020ba917b13708f8abeb0bffafee5c1da99ec5cfd49a00"
}
```

### Sample 32: `ffb5e04b4403df4f`

| Field | Value |
|---|---|
| SHA-256 | `ffb5e04b4403df4fc22d04c1a46a2fd27edd6696a4eae6a435afa105a4d1a364` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 00:08:36` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71bb3b483fe054be4b097a021230231b` |
| SHA-1 | `3afe7dcd1e381ce3919133f0ff4740f809bc10c0` |
| SHA-256 | `ffb5e04b4403df4fc22d04c1a46a2fd27edd6696a4eae6a435afa105a4d1a364` |
| SHA3-384 | `1b5558ab1c41d758830eb406564853a3824e22a7001612c31caa7ab9f506da119b16b3d1f2883894518b0e0cae9a1c56` |
| IMPHASH | `e89b199319545459542fa1f28caeb6ba` |
| TLSH | `T123345A3BD9A90AF9D8B2E274CA1A52339674B4A81129F5073751EC217E34B60F73CF61` |
| SSDEEP | `3072:Z6iiUmK2K8DX1UVof5+ZUgUl1d2Nii5B8RxBUgXujf1/7hTjQoZftoa:UlUmK2J6UtN2XQ3Tejf1/lsO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_ffb5e04b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb5e04b4403df4fc22d04c1a46a2fd27edd6696a4eae6a435afa105a4d1a364"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 00:08:36"
  condition:
    hash.sha256(0, filesize) == "ffb5e04b4403df4fc22d04c1a46a2fd27edd6696a4eae6a435afa105a4d1a364"
}
```

### Sample 33: `98d86be099dd339a`

| Field | Value |
|---|---|
| SHA-256 | `98d86be099dd339adebf2d9d761635652f5e8a854a9640e8114c3ae1ffbd7c85` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-30 00:07:23` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX7.file, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56c136163da3df7317cf1c8e8acb5c23` |
| SHA-1 | `08003e1ee88b45aef5463e9f58f1246f14d8f69b` |
| SHA-256 | `98d86be099dd339adebf2d9d761635652f5e8a854a9640e8114c3ae1ffbd7c85` |
| SHA3-384 | `21349f5004c89bb3e779e0255bd302f4d6a50e9eb6f999e46e87fbcb1b5ec0350426bb331e53283283054ffe430e02f6` |
| IMPHASH | `332b41c0ffa734bb9c9d5b037af977ac` |
| TLSH | `T11EC312B283A40A40C2719637F8DF836EC4E8BE1D4954EE9D8B9B9CDD2130E9E5794162` |
| SSDEEP | `3072:fdHsJbzB6/ci5bL249GDanMF+OBveIvvQKAeqZ20iyJzcN:UE1b6qGOMoOBm4YKAP20XK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_98d86be0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98d86be099dd339adebf2d9d761635652f5e8a854a9640e8114c3ae1ffbd7c85"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 00:07:23"
  condition:
    hash.sha256(0, filesize) == "98d86be099dd339adebf2d9d761635652f5e8a854a9640e8114c3ae1ffbd7c85"
}
```

### Sample 34: `2d113a07c025bfdf`

| Field | Value |
|---|---|
| SHA-256 | `2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0` |
| Family label | `unknown` |
| File name | `2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0` |
| File type | `elf` |
| First seen | `2026-06-29 23:54:32` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0774ab75edc85b9b564e333b9789dddc` |
| SHA-1 | `d9a19167abf0768895f5c761e231b20f097f80c2` |
| SHA-256 | `2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0` |
| SHA3-384 | `336db70d995d752f1e29cf34e82a1ef427bafb94d0ba5179944a1b87ac46253979ddd315ba35ab026376458aa0a54d46` |
| TLSH | `TNULL` |
| SSDEEP | `3:Bnks//xlEldlkl1llS/pllltml:BnX//InsE/ptk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_2d113a07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0"
    family = "unknown"
    file_name = "2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0"
    file_type = "elf"
    first_seen = "2026-06-29 23:54:32"
  condition:
    hash.sha256(0, filesize) == "2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0"
}
```

### Sample 35: `248319980ae1b866`

| Field | Value |
|---|---|
| SHA-256 | `248319980ae1b866a7ea30da121f43923a6aeee0f2bbb6576fa6dd368e5ddf4a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-29 23:33:47` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb492fc991e6829f39691c708e98b193` |
| SHA-1 | `8b19cf95487cadc52826d3d7959d2a5f6e9e7681` |
| SHA-256 | `248319980ae1b866a7ea30da121f43923a6aeee0f2bbb6576fa6dd368e5ddf4a` |
| SHA3-384 | `35035925979505bad8a454e0ade0bf0f584781bc5e2bcf585a28237ee8d782ac7f5a6fee155fd179db2541c1c6fcf2a7` |
| IMPHASH | `a7a48e6a1ac574443f1b812e09daef71` |
| TLSH | `T14693CF2BAC0335F7EC90D5BF42004224EFA2EA36235617F75A9711299E94FE0BD356E0` |
| SSDEEP | `1536:L9j0hUF2ueHJYMi4XkiMtPkzbEmNH27sxJk+1tsfFC4ctQXtQV:Rjfwd27p9kz/asX1nk8JtktA` |
| ICON-DHASH | `e2f4fcececece462` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_24831998
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "248319980ae1b866a7ea30da121f43923a6aeee0f2bbb6576fa6dd368e5ddf4a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-29 23:33:47"
  condition:
    hash.sha256(0, filesize) == "248319980ae1b866a7ea30da121f43923a6aeee0f2bbb6576fa6dd368e5ddf4a"
}
```

### Sample 36: `8dcf47bc0bb07232`

| Field | Value |
|---|---|
| SHA-256 | `8dcf47bc0bb0723203972ea05c1f05df6d38f61d3fe0460d6b727d9ed2bafcaf` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-29 23:33:40` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddf0b410d672f6bccb66b95808757ac5` |
| SHA-1 | `70c219a9551a2c5e196818da69bc7a431583b354` |
| SHA-256 | `8dcf47bc0bb0723203972ea05c1f05df6d38f61d3fe0460d6b727d9ed2bafcaf` |
| SHA3-384 | `a689d534cb461c76fadad2c62dd207f11ae168a76c113b3d9c48e62ed43cf513a4a52b8dc0b4114dca8a5016f07e6239` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10AE58C0BBCE049F9D4A9A33184AA5186BB75BC050F3223C36E50B7792F72BD19D79784` |
| SSDEEP | `49152:oXO2PWyKBM4XAXhh4sD3MRTXi5bj2Wq/ajTFPlWbkUrnn6E:oX15hLAWQyMh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_8dcf47bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dcf47bc0bb0723203972ea05c1f05df6d38f61d3fe0460d6b727d9ed2bafcaf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-29 23:33:40"
  condition:
    hash.sha256(0, filesize) == "8dcf47bc0bb0723203972ea05c1f05df6d38f61d3fe0460d6b727d9ed2bafcaf"
}
```

### Sample 37: `32f9896f5207858a`

| Field | Value |
|---|---|
| SHA-256 | `32f9896f5207858ae63d718e89562e9dea9780513873da26aebe6666d3d495fb` |
| Family label | `Mirai` |
| File name | `morte.arm7` |
| File type | `elf` |
| First seen | `2026-06-29 23:22:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d08811df5ba288d0694d34251696179` |
| SHA-1 | `2b0df069022548d13ca01636a0b9ed2f60515a83` |
| SHA-256 | `32f9896f5207858ae63d718e89562e9dea9780513873da26aebe6666d3d495fb` |
| SHA3-384 | `c268c8ad17dd3806524b9ee2afe2806ec47ac22b04800e2c13c9f1f3bfb37783e20271b952ec2b849e3ec1971634f34d` |
| TLSH | `T170144C46EA414E13C4D717BABAAF414A333297A4E3DB730699286FB43F8275F0D63905` |
| TELFHASH | `t1be313072933052266a61d914ddec97b2162dc7071288fe33df36849c141a49ee53bc1f` |
| SSDEEP | `6144:gvJu2A6YwfxZqgva7XBKBK6/bzQgCKPHNQLHAM/9NEC:gRu2AhwfPqgva7XBKBK6zzHn1i5/LZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_32f9896f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f9896f5207858ae63d718e89562e9dea9780513873da26aebe6666d3d495fb"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:58"
  condition:
    hash.sha256(0, filesize) == "32f9896f5207858ae63d718e89562e9dea9780513873da26aebe6666d3d495fb"
}
```

### Sample 38: `0967707c5308593c`

| Field | Value |
|---|---|
| SHA-256 | `0967707c5308593cb114117b5489c6f004f656810ab0616680d9c7c1277c661c` |
| Family label | `Mirai` |
| File name | `morte.mips` |
| File type | `elf` |
| First seen | `2026-06-29 23:22:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6310c4425cc824212c955d100c8da450` |
| SHA-1 | `40b79180daacd73c32fdce349717ebc02d1b4902` |
| SHA-256 | `0967707c5308593cb114117b5489c6f004f656810ab0616680d9c7c1277c661c` |
| SHA3-384 | `f86e9b8437830ef285d456a72d565b3e7c18b4e22896805b3d1a072935f2a72dcb06a71dbe5e8e191841adc8fc1178ca` |
| TLSH | `T1D4E3C50EAE259F3DFB99C33447B78E26965833C727E1C585D2ACE6011E6024E641FFA4` |
| TELFHASH | `t1eb11901c897822f087724c992bedff73e59030df1a262e378e10e86caa2dd425d01c2c` |
| SSDEEP | `3072:3DVu6G8ZtEwUGbZipObqR2q88JQXU4B3jHfWwLAH5yUtHSppNpKwdEc35XZWAypR:TVu6G8ZtEwUGbZipObqR2q88JQXU4B34` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_0967707c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0967707c5308593cb114117b5489c6f004f656810ab0616680d9c7c1277c661c"
    family = "Mirai"
    file_name = "morte.mips"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:51"
  condition:
    hash.sha256(0, filesize) == "0967707c5308593cb114117b5489c6f004f656810ab0616680d9c7c1277c661c"
}
```

### Sample 39: `00a5bb1a22bb63d4`

| Field | Value |
|---|---|
| SHA-256 | `00a5bb1a22bb63d4f94c09a5dc748260b0710129874ad38cd38bed68120c2cff` |
| Family label | `Mirai` |
| File name | `morte.arm6` |
| File type | `elf` |
| First seen | `2026-06-29 23:22:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3fa1f394201832fcd88c141378d1422` |
| SHA-1 | `ad4bd25c3534c0912e774ca0c6aa68027d8fe3e3` |
| SHA-256 | `00a5bb1a22bb63d4f94c09a5dc748260b0710129874ad38cd38bed68120c2cff` |
| SHA3-384 | `ffb2a5b541cac4d614e802ed432f5706a1abfec6e8935717f235558b9106ffca793c667b4fcb363b7c99689d861d2316` |
| TLSH | `T12EC30886F8824A22C5D712BEF92D118E331217F8E3DE72239E245F25778661F0E7B945` |
| TELFHASH | `t16ce0d837ff74069d2bc5525882ae9a15176d79c81751416287bd1ac60b134c2316900a` |
| SSDEEP | `3072:uqCLzmTWBda4qhYolgvLQaVlQbdQxABt+Ys:uqC2TUda40YSgvEa8SxAyYs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_00a5bb1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00a5bb1a22bb63d4f94c09a5dc748260b0710129874ad38cd38bed68120c2cff"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:46"
  condition:
    hash.sha256(0, filesize) == "00a5bb1a22bb63d4f94c09a5dc748260b0710129874ad38cd38bed68120c2cff"
}
```

### Sample 40: `acaa4f20c6d7ee00`

| Field | Value |
|---|---|
| SHA-256 | `acaa4f20c6d7ee0094f62a38d6f0706ed42acaad600f58741a48648cefaab5c2` |
| Family label | `Mirai` |
| File name | `morte.x86` |
| File type | `elf` |
| First seen | `2026-06-29 23:22:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52e249d9745e9ba0e11ebc2c9395d22a` |
| SHA-1 | `7459c9ed3a53cdebebf8c9d2116b62ddc276df1a` |
| SHA-256 | `acaa4f20c6d7ee0094f62a38d6f0706ed42acaad600f58741a48648cefaab5c2` |
| SHA3-384 | `6cee5b3043a6718898e502eb955c6580481dbcfa79d2af070f258a29321c5a968aad236f50408ae2b9da6767691ef725` |
| TLSH | `T113A35BC4F243D4F5FC92053421B6FB37DA72E6B92129DEC3D7A89A72EC16542C406A9C` |
| TELFHASH | `t17d31dfb9b1ba0ce8ebe05903e28e5b31bd0e6b7b603436f206f718352257251907bc34` |
| SSDEEP | `3072:/Iw5rh8wEz6mpWqxo5gGDOxP3DyyA503J:t5rh8wEzRpZZMb03J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_acaa4f20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acaa4f20c6d7ee0094f62a38d6f0706ed42acaad600f58741a48648cefaab5c2"
    family = "Mirai"
    file_name = "morte.x86"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:43"
  condition:
    hash.sha256(0, filesize) == "acaa4f20c6d7ee0094f62a38d6f0706ed42acaad600f58741a48648cefaab5c2"
}
```

### Sample 41: `f897580a09ebb3dd`

| Field | Value |
|---|---|
| SHA-256 | `f897580a09ebb3dd3cdeb3df81b4627a0e1ae4adf72982e1005d291c4096d14b` |
| Family label | `Mirai` |
| File name | `morte.ppc` |
| File type | `elf` |
| First seen | `2026-06-29 23:22:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e02ffbe81751903828746b2c6b4b533` |
| SHA-1 | `348fa0846a633238d8ed21225bbf700d9c2ad8b9` |
| SHA-256 | `f897580a09ebb3dd3cdeb3df81b4627a0e1ae4adf72982e1005d291c4096d14b` |
| SHA3-384 | `c16b578e4724bbad353b52c25b8070667bfaed484299cf4376ea76ca862592c70e44d4ea233fec9ba63e712c9261fd4a` |
| TLSH | `T150B34B1273180B57C5934AB02E3F1BE587FEE5D021F8BA89260FDB5A4675E371489EC8` |
| SSDEEP | `1536:XLSoHAS7nGBqLNqyFrn+MB4K4SNiVx2+P96+puSdw+B7dmge:XL9nGkyR/Sgr95umege` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_f897580a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f897580a09ebb3dd3cdeb3df81b4627a0e1ae4adf72982e1005d291c4096d14b"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:40"
  condition:
    hash.sha256(0, filesize) == "f897580a09ebb3dd3cdeb3df81b4627a0e1ae4adf72982e1005d291c4096d14b"
}
```

### Sample 42: `dd4630f1e9597ec3`

| Field | Value |
|---|---|
| SHA-256 | `dd4630f1e9597ec3de130d5abae83d28d01b4447edfdcf25b64bda9a288181e4` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-06-29 23:22:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `592689309b3e8c3d75a588e0b16481f4` |
| SHA-1 | `c3e38ec0a6004fa81695fde384c6992b9dd6ae4d` |
| SHA-256 | `dd4630f1e9597ec3de130d5abae83d28d01b4447edfdcf25b64bda9a288181e4` |
| SHA3-384 | `113db5d4e15c4b1f2663ede5b0a83233d574c8ae6e42a890bcb0cc89c79b8cfe827fcb590af89f60e99117036ed765b2` |
| TLSH | `T19BB34CC5E283D4F9FC5605312176FB376D72E1BA2328D983D3F89A32AC61A41D416B9C` |
| TELFHASH | `t12a31f7f9673608e58bd08d03b1ce8b21dd1e77bb256039b715b65914762b45283bbc38` |
| SSDEEP | `3072:vu6b5m1QwvQc+HKOcVQa7McC2h9c69CzB/:vnNm1QwvQnHxNUA69CzB/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_dd4630f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd4630f1e9597ec3de130d5abae83d28d01b4447edfdcf25b64bda9a288181e4"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:37"
  condition:
    hash.sha256(0, filesize) == "dd4630f1e9597ec3de130d5abae83d28d01b4447edfdcf25b64bda9a288181e4"
}
```

### Sample 43: `b854094b3d704b2d`

| Field | Value |
|---|---|
| SHA-256 | `b854094b3d704b2d70bd0d1458a648dfce74e2a3c16cb1d88967ae12f22d383a` |
| Family label | `Mirai` |
| File name | `morte.x86_64` |
| File type | `elf` |
| First seen | `2026-06-29 23:22:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e944b998d487449991a53f343c49e56` |
| SHA-1 | `0d1d2e7e200a6286a552694349081ae94aa8300b` |
| SHA-256 | `b854094b3d704b2d70bd0d1458a648dfce74e2a3c16cb1d88967ae12f22d383a` |
| SHA3-384 | `fa5185277dd55dfa612b9224d2bf0c4eea069ba4542c186ac0698712bc5ee8809c25d26d887a8145387c0c0090fa8778` |
| TLSH | `T15AB31906B8D48DFDC086C23447BE7537DC21F0ED0278B2AB67D4AE262D0DE625B1DA59` |
| TELFHASH | `t10f219cb42d9a36a800e39b45b34ed7e8f6b205224fd0b1d95f677ae28e05b8c0cc50d1` |
| SSDEEP | `3072:asW5+8ePGmIMXUej+qgveJkr7NYl8l7jwe9CnWTOYb9z:asb8eemdXUej+qgveJCNjyWTOYb9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_b854094b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b854094b3d704b2d70bd0d1458a648dfce74e2a3c16cb1d88967ae12f22d383a"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:34"
  condition:
    hash.sha256(0, filesize) == "b854094b3d704b2d70bd0d1458a648dfce74e2a3c16cb1d88967ae12f22d383a"
}
```

### Sample 44: `b0b9bb6785cf9e02`

| Field | Value |
|---|---|
| SHA-256 | `b0b9bb6785cf9e0216c365a9e231eac747c3d5236b1f29677b3444acc1a918ae` |
| Family label | `Mirai` |
| File name | `morte.i686` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44b904f37625e2c455231d3d1e40ba02` |
| SHA-1 | `e0e05d2141b79e7e3d02589dd9a1530e2f29dbf1` |
| SHA-256 | `b0b9bb6785cf9e0216c365a9e231eac747c3d5236b1f29677b3444acc1a918ae` |
| SHA3-384 | `c7e3dae48a6ca9fe2c51d8c08170d00575999679567fe96e75f8d65fedf099bb82b7c4ea4c88222279219686292a9b30` |
| TLSH | `T1ACB33980F98B80FAC5078C3461A6F63FDE32D5A94173CA9DEF959F32DA3B541911228D` |
| TELFHASH | `t1b73125b9b5725c98abd08c03f6ce7700ed0eb6bf742472b44aa310a1366655183bac3d` |
| SSDEEP | `3072:fAriZAVY5/QJPxHSHNeNyIVxEUfLfZk17r6Q+mTRWyh8:AiZAVY5IJZHSteNb/LjhoMQ8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_b0b9bb67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0b9bb6785cf9e0216c365a9e231eac747c3d5236b1f29677b3444acc1a918ae"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:32"
  condition:
    hash.sha256(0, filesize) == "b0b9bb6785cf9e0216c365a9e231eac747c3d5236b1f29677b3444acc1a918ae"
}
```

### Sample 45: `ce2684992b42f245`

| Field | Value |
|---|---|
| SHA-256 | `ce2684992b42f2454cfe637cbadf547545240366b9b0b79de036502d80ae996d` |
| Family label | `Mirai` |
| File name | `morte.arm` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `956154e8d60fb34912c0c32d22328b53` |
| SHA-1 | `795c0f1132278ce32ec475242333607cfc5c49cb` |
| SHA-256 | `ce2684992b42f2454cfe637cbadf547545240366b9b0b79de036502d80ae996d` |
| SHA3-384 | `c568720c4e5b704715b813eeeff0707650a5382c3b55825731ecb3bd0ab671a19a13295530f62bbaae997bcd22c47e43` |
| TLSH | `T180C33945F8815623C6D7237AFAAE118E332263E8D3DF3217CE255F21378651B0D6BA91` |
| TELFHASH | `t152e0c091ff0803a49dd8003480ff16372fceb84ca9042b10256dae9f40d28d4f82d10e` |
| SSDEEP | `1536:hUyw8WqZQzBCEfB5aYh2RMQWykWhT3ksjDOEWXjP2MNrivnDM:hUyw8LQgtDWOTxjDaT8nDM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_ce268499
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce2684992b42f2454cfe637cbadf547545240366b9b0b79de036502d80ae996d"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:29"
  condition:
    hash.sha256(0, filesize) == "ce2684992b42f2454cfe637cbadf547545240366b9b0b79de036502d80ae996d"
}
```

### Sample 46: `c76de2972ac27799`

| Field | Value |
|---|---|
| SHA-256 | `c76de2972ac27799404163a44547a789ba25aeb42570ff21d0efb92128e5cf1a` |
| Family label | `Mirai` |
| File name | `1.sh` |
| File type | `sh` |
| First seen | `2026-06-29 23:21:27` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3979994dc971fb87738440246a701584` |
| SHA-1 | `10cfbaaca32297b97fcffccd51de3bd9d6d369e0` |
| SHA-256 | `c76de2972ac27799404163a44547a789ba25aeb42570ff21d0efb92128e5cf1a` |
| SHA3-384 | `2e4bd8685ffe297ca05cea48c94923e1ba7ae8e3206bf14975cf0f5af84cbbc5c746142f353fb10b32ca2759636e7269` |
| TLSH | `T1A56183FB134906335CB389D732BA4444719082AB54CFAF76EBDC28A50EADECD7C42652` |
| SSDEEP | `24:ItS8xZsS32bhSCXkSTqlfSZQmsSlUTSCnCGgJS0Z6SdcnLSsnsNIpKksSnGMEShP:iS5wpnj/C1GXLoJJh0dYBgJsxk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_c76de297
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c76de2972ac27799404163a44547a789ba25aeb42570ff21d0efb92128e5cf1a"
    family = "Mirai"
    file_name = "1.sh"
    file_type = "sh"
    first_seen = "2026-06-29 23:21:27"
  condition:
    hash.sha256(0, filesize) == "c76de2972ac27799404163a44547a789ba25aeb42570ff21d0efb92128e5cf1a"
}
```

### Sample 47: `350549faf559177c`

| Field | Value |
|---|---|
| SHA-256 | `350549faf559177c364f192f013dfa537fb33a5ff1e6ca3674abba5daf2cce4d` |
| Family label | `Mirai` |
| File name | `morte.arm7` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6af4be64ec1e0246ecca535ce1cbcc73` |
| SHA-1 | `a921813b7adf7398465f33b1f6d33d15f31142d1` |
| SHA-256 | `350549faf559177c364f192f013dfa537fb33a5ff1e6ca3674abba5daf2cce4d` |
| SHA3-384 | `f66843d71556be31cca1a95240720067cb1511d99386f5074d927e467b5e532698d04213a0ad6cd32c735640b75024d1` |
| TLSH | `T10073F1A2273D2BFE61300AB6395DC9853E91CFFCC96E5923420D8724B925A442BFC54E` |
| SSDEEP | `1536:hWUcXivqfnuon+Mm8vC1+zb5+LVuidny6vWPkrP:kU6ivom8vC6+LTdnNOPGP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_350549fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "350549faf559177c364f192f013dfa537fb33a5ff1e6ca3674abba5daf2cce4d"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:26"
  condition:
    hash.sha256(0, filesize) == "350549faf559177c364f192f013dfa537fb33a5ff1e6ca3674abba5daf2cce4d"
}
```

### Sample 48: `935af0fa9a178296`

| Field | Value |
|---|---|
| SHA-256 | `935af0fa9a1782969009255431376cb3cc4fe5579ceef16542130abf0656c780` |
| Family label | `Mirai` |
| File name | `morte.mpsl` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c217aed4c753b575c8ca1c804ba28487` |
| SHA-1 | `b187dfe57ab2df36e49712e731d5a1d4110f7059` |
| SHA-256 | `935af0fa9a1782969009255431376cb3cc4fe5579ceef16542130abf0656c780` |
| SHA3-384 | `6764699c279dee552260448b51cddfeb35de36012e6e27253593af0268aadd495b9d90fa2b732f451956195f2f6c3bbb` |
| TLSH | `T1F9E3E809BF610EFBE89BCC3705F9170628CD555722E97B3AB530D918B64B24F26E3864` |
| SSDEEP | `3072:iim0VCGdFX27iLZzvHzCzkBgBu4xIHtWJj4J03:iimJGdFX27iLZbzekMu4xIHtW13` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_935af0fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "935af0fa9a1782969009255431376cb3cc4fe5579ceef16542130abf0656c780"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:25"
  condition:
    hash.sha256(0, filesize) == "935af0fa9a1782969009255431376cb3cc4fe5579ceef16542130abf0656c780"
}
```

### Sample 49: `b5c7ac1345074e9a`

| Field | Value |
|---|---|
| SHA-256 | `b5c7ac1345074e9aea48617010e887d570a53868e1802566f3f6e63bb21bfd4d` |
| Family label | `Mirai` |
| File name | `morte.arc` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a881c38e9259d30a8b4524fc26d09ad2` |
| SHA-1 | `64d98c9696c2e707360d5529bd84d890cb99d07e` |
| SHA-256 | `b5c7ac1345074e9aea48617010e887d570a53868e1802566f3f6e63bb21bfd4d` |
| SHA3-384 | `ce353f99c063cbc059fbde669e4de073998217dde131ee8386380ca20b46587886f5f119ac6548b9776bad0434a9ca52` |
| TLSH | `T18DD3AD97B64721A1C86302F40BCB5BDD2E9362826F5BD8E77C2F757B583A0DB4402B91` |
| SSDEEP | `3072:TCIRz+2jCWyXfhIEh9oGQVPn2ObFguvaq:T/qdRdQkyvaq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_b5c7ac13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5c7ac1345074e9aea48617010e887d570a53868e1802566f3f6e63bb21bfd4d"
    family = "Mirai"
    file_name = "morte.arc"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:25"
  condition:
    hash.sha256(0, filesize) == "b5c7ac1345074e9aea48617010e887d570a53868e1802566f3f6e63bb21bfd4d"
}
```

### Sample 50: `93635303f7c28602`

| Field | Value |
|---|---|
| SHA-256 | `93635303f7c28602ea37b8ba0a420acffd527c2eea76e4791c79239d4fa4e481` |
| Family label | `Mirai` |
| File name | `morte.mips` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2008bd0286b1a870bed86b50ae667b7e` |
| SHA-1 | `60db9d6f898bbaf8590895052c395431fcbc4e79` |
| SHA-256 | `93635303f7c28602ea37b8ba0a420acffd527c2eea76e4791c79239d4fa4e481` |
| SHA3-384 | `fa2fc3a8d2d804eb428f4cb0f83e7547e453913f60059d222ae2a116e46c6b7a4a5a34a12d8ee3b682e845c493094bdf` |
| TLSH | `T15823F14D10505EB8DDA790BCC7844B332B6482E79462F9A599CCF9917B0DEA83C077E9` |
| SSDEEP | `1536:QIbRcl2ehlpmgVm1PcOHdyrETMIY4VJud:nev0gnlrnIbVQd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_93635303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93635303f7c28602ea37b8ba0a420acffd527c2eea76e4791c79239d4fa4e481"
    family = "Mirai"
    file_name = "morte.mips"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:24"
  condition:
    hash.sha256(0, filesize) == "93635303f7c28602ea37b8ba0a420acffd527c2eea76e4791c79239d4fa4e481"
}
```

### Sample 51: `6f639155215ecc4b`

| Field | Value |
|---|---|
| SHA-256 | `6f639155215ecc4b9590e0f768cdf3201df52dbd581275d58ec1723bbafe3afd` |
| Family label | `Mirai` |
| File name | `morte.sh4` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e6fcac04b9df059679acfa9e2304689` |
| SHA-1 | `2b5051ee90d4ffdc8ea364fcb7ad90780d0c662d` |
| SHA-256 | `6f639155215ecc4b9590e0f768cdf3201df52dbd581275d58ec1723bbafe3afd` |
| SHA3-384 | `19acc3ba778b89d606cc38a1eb7449f043700a1e2a00c0df137c7931f33e6a69d7ac0161539d79d914b758af30c4ea3d` |
| TLSH | `T128A3AE36D4199CE8C5550238A4F89E361F63B1805357AEF726E9C3B7609BE58F809FB0` |
| SSDEEP | `1536:6/CpYUyOokMYq50m175HKZxOAdKERLD7HxBzxCEOQ1g107wm:6KmU/Rxm1EZxOAEEJ9Bzx/+q7w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_6f639155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f639155215ecc4b9590e0f768cdf3201df52dbd581275d58ec1723bbafe3afd"
    family = "Mirai"
    file_name = "morte.sh4"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:22"
  condition:
    hash.sha256(0, filesize) == "6f639155215ecc4b9590e0f768cdf3201df52dbd581275d58ec1723bbafe3afd"
}
```

### Sample 52: `f49c3c78218ea5a3`

| Field | Value |
|---|---|
| SHA-256 | `f49c3c78218ea5a3a0fb99f8dcb42251d4781e2f21ed3b9f3b7f9fd4e58e3ec1` |
| Family label | `Mirai` |
| File name | `morte.arm6` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `388b4572e749fc4a4477ff659641067f` |
| SHA-1 | `5231f58da2ed74c9d693e59ee8ee175e0df4eee5` |
| SHA-256 | `f49c3c78218ea5a3a0fb99f8dcb42251d4781e2f21ed3b9f3b7f9fd4e58e3ec1` |
| SHA3-384 | `4774505e4cfecf814755053ff1e9f623b366db418b41693c350b3906ffd67b08bb039fe0aaab65839bd9445cd2ddf9fa` |
| TLSH | `T15D33F2D2451690D3C76095B5EE39ABC70C991EECE478ED7342A00AAE6CCD649BED3083` |
| SSDEEP | `768:ohBrFO+Syh+ykozizz6yFQWhNIv2hZO+SuDrITOeGReHTJ0MvAK9oZuXUFG8AtMk:ohxFOyhZP+PhKuhGu3Ii/RezJlocPXLf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_f49c3c78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f49c3c78218ea5a3a0fb99f8dcb42251d4781e2f21ed3b9f3b7f9fd4e58e3ec1"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:21"
  condition:
    hash.sha256(0, filesize) == "f49c3c78218ea5a3a0fb99f8dcb42251d4781e2f21ed3b9f3b7f9fd4e58e3ec1"
}
```

### Sample 53: `a45370fa1f96c2bd`

| Field | Value |
|---|---|
| SHA-256 | `a45370fa1f96c2bdfa34cb7909d15ed30c459a58a0e35a77295c2982e0500dfa` |
| Family label | `Mirai` |
| File name | `morte.arm5` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4584c99a9f3653aac1db139b30492e6b` |
| SHA-1 | `98821d590f61d0873c494d16d81f10011e5f9e7e` |
| SHA-256 | `a45370fa1f96c2bdfa34cb7909d15ed30c459a58a0e35a77295c2982e0500dfa` |
| SHA3-384 | `604a36f8ff3f6f08d676b78910311031a10d9bc5962406f8ffec1fd2e9f3a65b9245939d4f87fdf673e1605e683ca318` |
| TLSH | `T15B831846B9C28A2AC2D0237EE67E628D33A167E4D2DFB157CC215B11378520F1E67F91` |
| TELFHASH | `t10fe06140fe764b1884e75a34ecdd47b495116217a1664710cf54daf0883f15ca71cd5e` |
| SSDEEP | `1536:yhb0qwwSd9Pf0HQOCmm4NKpnCAHcxynQAPQZD73F:y10qwwSbeMQRF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_a45370fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a45370fa1f96c2bdfa34cb7909d15ed30c459a58a0e35a77295c2982e0500dfa"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:20"
  condition:
    hash.sha256(0, filesize) == "a45370fa1f96c2bdfa34cb7909d15ed30c459a58a0e35a77295c2982e0500dfa"
}
```

### Sample 54: `dc38fd9545732814`

| Field | Value |
|---|---|
| SHA-256 | `dc38fd9545732814bee53e08b3cee550cca12e0222a233912a8a91b2a178077f` |
| Family label | `Mirai` |
| File name | `morte.x86` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8046bc5957720ba1be1c3d86b43f120f` |
| SHA-1 | `de5ed98ffd6d1261bec9d28bdae9d4521a4c0d1c` |
| SHA-256 | `dc38fd9545732814bee53e08b3cee550cca12e0222a233912a8a91b2a178077f` |
| SHA3-384 | `58da6d51ad9e6deefa01a31da290597cb34a09d8bfb2cebdfae14e81a488237b0ae7f9196ee02c0d5c54fa920534ee88` |
| TLSH | `T11F23F151B4EF0F5FC47F7831143DB68FE628C1AA83D44E78EBE0247A2865D36156CA82` |
| SSDEEP | `768:Ev5dETgniheMkMkSWT5lUhQ//gFVn77kGjTHSgfVHjeY4U0VWaRH8WSMEHqUVnbi:Evwrz5wHUhQ/Yb77ZPHSgtjzn0VjRcde` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_dc38fd95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc38fd9545732814bee53e08b3cee550cca12e0222a233912a8a91b2a178077f"
    family = "Mirai"
    file_name = "morte.x86"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:20"
  condition:
    hash.sha256(0, filesize) == "dc38fd9545732814bee53e08b3cee550cca12e0222a233912a8a91b2a178077f"
}
```

### Sample 55: `e4c51e8e44c4ad43`

| Field | Value |
|---|---|
| SHA-256 | `e4c51e8e44c4ad43b8007f5b39be914d658e653bbfa8ea2363e18041278306fa` |
| Family label | `Mirai` |
| File name | `morte.ppc` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ced65a3f16fa51214a52ae7e48241f7e` |
| SHA-1 | `66db3ea83f31ecd1647a109e9c1cd9b19c1fba10` |
| SHA-256 | `e4c51e8e44c4ad43b8007f5b39be914d658e653bbfa8ea2363e18041278306fa` |
| SHA3-384 | `27377d52a644ad45ed8aaec5907c5a6adf70616d7a5975b1aaa68d6f8ad13363b2d0a8cb706ec478cf9a402747300b35` |
| TLSH | `T1A023F164EC8BD28ED6EB24725C60E7CE27645AD4D271C0B25E13BF8517843ADB2398D0` |
| SSDEEP | `768:kDU1O7KPZL21LYyNeskXca6kKhvDFuoxygNJUaL+/lEzP4O5zVyIBXK1qh4uVcq+:+KPZ4HIvKhJuOJul85z8a4u+qgw09n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_e4c51e8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4c51e8e44c4ad43b8007f5b39be914d658e653bbfa8ea2363e18041278306fa"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:19"
  condition:
    hash.sha256(0, filesize) == "e4c51e8e44c4ad43b8007f5b39be914d658e653bbfa8ea2363e18041278306fa"
}
```

### Sample 56: `e0052270db2b15ba`

| Field | Value |
|---|---|
| SHA-256 | `e0052270db2b15bacb79524bf4b6943404ab566ddeed5e9a56b3aac87c987fe6` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71f81c81b6ec62e50f0e53e259f3d0db` |
| SHA-1 | `4c8f68af62521eb21671aa057d00ca8cc93bcdb6` |
| SHA-256 | `e0052270db2b15bacb79524bf4b6943404ab566ddeed5e9a56b3aac87c987fe6` |
| SHA3-384 | `4eb8717dbd4a8a61a6f741c8f43cc017e945d1f493fed5e2dd1e6a8738b4fa35739375f203817aef68c492b690dc3351` |
| TLSH | `T1FC230219F2AFC254DACD47BA2EFB55501610D5891A2DE96FEF06300BB628FA4CD320C7` |
| SSDEEP | `768:PXM6+V5GhFGNYewdV9ZvwSHppYzd/G1xkq9QMRZpOES8MsqUF1pLeVnbcuyD7UHT:0R5GhF3ewjvpWd/G1FaGztFkqXeVnouJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_e0052270
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0052270db2b15bacb79524bf4b6943404ab566ddeed5e9a56b3aac87c987fe6"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:18"
  condition:
    hash.sha256(0, filesize) == "e0052270db2b15bacb79524bf4b6943404ab566ddeed5e9a56b3aac87c987fe6"
}
```

### Sample 57: `0c2d1a47fbc1c6b8`

| Field | Value |
|---|---|
| SHA-256 | `0c2d1a47fbc1c6b887afa8dcd96e2becc7b52154295ded81d3d1ea259fd29910` |
| Family label | `Mirai` |
| File name | `morte.x86_64` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7a6d425e99629401dfb4df121c701b1` |
| SHA-1 | `edc6fdd2fbdf73a9f345cf4d0491a2ea24f3ab35` |
| SHA-256 | `0c2d1a47fbc1c6b887afa8dcd96e2becc7b52154295ded81d3d1ea259fd29910` |
| SHA3-384 | `7e5a0ee1a3fcd6a1b7ad4e14fe9766fabc0d16480fee48baff1c709cc911f100695dd37ee809802d16535545b2b5e10c` |
| TLSH | `T18C23F1B761DBC93CE031F5B2117AAEC5D1B5642972CA27EE084EA23B1DFED503550790` |
| SSDEEP | `768:QEkTK0B51hHgK6PW8aaCTqs60mgLDlW856fc4b79+nKjJXJFmJHiwMsKMJ+9AhA7:XeBRHgKManTqsXtlfH4FiKjhm5lMsp+x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_0c2d1a47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c2d1a47fbc1c6b887afa8dcd96e2becc7b52154295ded81d3d1ea259fd29910"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:16"
  condition:
    hash.sha256(0, filesize) == "0c2d1a47fbc1c6b887afa8dcd96e2becc7b52154295ded81d3d1ea259fd29910"
}
```

### Sample 58: `4c9ba8e26c1f993f`

| Field | Value |
|---|---|
| SHA-256 | `4c9ba8e26c1f993fc5f6b8e4ba46cb4ca956d21ca0beba6b5326c3e8bd389751` |
| Family label | `Mirai` |
| File name | `morte.spc` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88cba93506d25e93bbaae0035ad48d1e` |
| SHA-1 | `515569b4512e680c3c9164ae3b76e71cb0fd9d7f` |
| SHA-256 | `4c9ba8e26c1f993fc5f6b8e4ba46cb4ca956d21ca0beba6b5326c3e8bd389751` |
| SHA3-384 | `bbb53586d278702b954ef9203d73478068f1d1aec8a85d594fcdc48fde2f3aad87322ec35ba0793c7edb9c2985bd1ade` |
| TLSH | `T140C38E22B4391A27C4E0947B12F74721F5F653CA11A8D60F7E720E8FFF216502A17AB9` |
| SSDEEP | `1536:hagP+QJILwim69EFieLp2s9M2enEbHgaRlbPZMSPa1C3jeF3YuA63mtN1qd09vMM:hb2oBa31YwVfKpRETEL1KFrY2FYOBF6r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_4c9ba8e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c9ba8e26c1f993fc5f6b8e4ba46cb4ca956d21ca0beba6b5326c3e8bd389751"
    family = "Mirai"
    file_name = "morte.spc"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:15"
  condition:
    hash.sha256(0, filesize) == "4c9ba8e26c1f993fc5f6b8e4ba46cb4ca956d21ca0beba6b5326c3e8bd389751"
}
```

### Sample 59: `d651fbf908c4f5a2`

| Field | Value |
|---|---|
| SHA-256 | `d651fbf908c4f5a25cd048b993b5bc8b99ca011c070749bcaf5e4b1b7bc14f5c` |
| Family label | `unknown` |
| File name | `o.xml` |
| File type | `unknown` |
| First seen | `2026-06-29 23:21:14` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `836950a7bbd14e21625d9eb7976a1247` |
| SHA-256 | `d651fbf908c4f5a25cd048b993b5bc8b99ca011c070749bcaf5e4b1b7bc14f5c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_d651fbf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d651fbf908c4f5a25cd048b993b5bc8b99ca011c070749bcaf5e4b1b7bc14f5c"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-06-29 23:21:14"
  condition:
    hash.sha256(0, filesize) == "d651fbf908c4f5a25cd048b993b5bc8b99ca011c070749bcaf5e4b1b7bc14f5c"
}
```

### Sample 60: `355643ac8395f5a0`

| Field | Value |
|---|---|
| SHA-256 | `355643ac8395f5a0778ab43b9e02a2271693bc1397ea0d6aa6b2d56ba3be8406` |
| Family label | `Mirai` |
| File name | `morte.i686` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9d58c732ddb190df6003cf67b6b458a` |
| SHA-1 | `7aa1937a9ac2fbb6c16e58c700b1aa0f2755400a` |
| SHA-256 | `355643ac8395f5a0778ab43b9e02a2271693bc1397ea0d6aa6b2d56ba3be8406` |
| SHA3-384 | `1d6b9d2f766bdb1c59d20c9162f75e447b05c670b71332236a7661678a3b5e50b5c1ad291306cb993bcb3737569b2638` |
| TLSH | `T17923F18381EADBDBC0A814311EEFBA491914E91DB92742F378B0E4F89045EF921694C7` |
| SSDEEP | `768:XMVFZ8PdT3TzXvlULWd4OTkMJdK8Z+FGJZeoCtn1Hp47QAu0ALZTCh9nbcuyD7Ux:YunXvlU84OTkxAypMQAush9nouy8HyW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_355643ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "355643ac8395f5a0778ab43b9e02a2271693bc1397ea0d6aa6b2d56ba3be8406"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:13"
  condition:
    hash.sha256(0, filesize) == "355643ac8395f5a0778ab43b9e02a2271693bc1397ea0d6aa6b2d56ba3be8406"
}
```

### Sample 61: `a2711c76b11bc5ea`

| Field | Value |
|---|---|
| SHA-256 | `a2711c76b11bc5ead48ada4bd1052a4bdbca06c1a7b7e88c2f4d4e5b44a9a3c0` |
| Family label | `Mirai` |
| File name | `morte.arm` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e18868a2d227452a06c2cf6bf20e7668` |
| SHA-1 | `ae3197f9866b509f94af45e2b5f48c4171c915f4` |
| SHA-256 | `a2711c76b11bc5ead48ada4bd1052a4bdbca06c1a7b7e88c2f4d4e5b44a9a3c0` |
| SHA3-384 | `51ff4a97204bb8e25d9dbd4e041fc5fe1772cc6b925056015dd17e273ae98accf0139e74e5b7379e7713822329630ac7` |
| TLSH | `T1C023F11441AE8C22D7784C77CEA6D3C0571BEEBBF1F661E9399413B09F1688709B86C2` |
| SSDEEP | `768:MNb/RVtBHCL68j28fLz6H5TwTdRDLOpUpBj9vtk7LXu37caUYt0ayfrwzcQh8ZVy:MnX5CL66fLz6ZQdLH3j9vtkfu3Jf0aI8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_a2711c76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2711c76b11bc5ead48ada4bd1052a4bdbca06c1a7b7e88c2f4d4e5b44a9a3c0"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:12"
  condition:
    hash.sha256(0, filesize) == "a2711c76b11bc5ead48ada4bd1052a4bdbca06c1a7b7e88c2f4d4e5b44a9a3c0"
}
```

### Sample 62: `a8bc5383b157d561`

| Field | Value |
|---|---|
| SHA-256 | `a8bc5383b157d561fe771cd5f9446940cd13bd2cf0ad4dba25216c836fe3191c` |
| Family label | `Mirai` |
| File name | `morte.mpsl` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4d974f962a6d43ecc58fcdbc7b3e97e` |
| SHA-1 | `86fda6d0ca0db21ed620528d8659d7e6b3c9ddcc` |
| SHA-256 | `a8bc5383b157d561fe771cd5f9446940cd13bd2cf0ad4dba25216c836fe3191c` |
| SHA3-384 | `c4f3ce146a3b3993e7fef372b084b8e0c437c6e3099144581d6f4e59874996e26f7fa48a5cb370b80b45ac6ebb2dfe20` |
| TLSH | `T1AA33F19F77D6A123CA4E7DFBF14D2BB0C60B31C5A7468645474095DCB7E2246308A4F6` |
| SSDEEP | `1536:9nSRr1nRi61QCvKZ+CasTKVPZf9iIz7WFAnCfC:9knRikKNOxf9iI/4AnCfC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_a8bc5383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8bc5383b157d561fe771cd5f9446940cd13bd2cf0ad4dba25216c836fe3191c"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:11"
  condition:
    hash.sha256(0, filesize) == "a8bc5383b157d561fe771cd5f9446940cd13bd2cf0ad4dba25216c836fe3191c"
}
```

### Sample 63: `237e4d5bba9ec28e`

| Field | Value |
|---|---|
| SHA-256 | `237e4d5bba9ec28ea100c5f6fc2d8dda23392af28b333c4d8d2cebcbfa81d577` |
| Family label | `Mirai` |
| File name | `morte.arm5` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4b5dfa1ce72d2a1db6fdf9ef0b2acc1` |
| SHA-1 | `d1b050dcd08583b41876e0c9f3605bbc09edf05c` |
| SHA-256 | `237e4d5bba9ec28ea100c5f6fc2d8dda23392af28b333c4d8d2cebcbfa81d577` |
| SHA3-384 | `1b9da19d0f6b380b6d2f537e3424f84ea6ca7ad89f49b90ab333e30f1a13d537a9a94d651be8b9a406644d17f50b235a` |
| TLSH | `T159E2E17DDF90A999C2A42431EBACCDC7B5CB5258E3E8371B322801A1804961DD7BD28F` |
| SSDEEP | `768:67xetyYfWrC/l/+w/3GY1ja4SXD3A2yBQAn4ts3Uoz9BJ:6t8yYurMtxOX02yBV/zF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_237e4d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "237e4d5bba9ec28ea100c5f6fc2d8dda23392af28b333c4d8d2cebcbfa81d577"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:09"
  condition:
    hash.sha256(0, filesize) == "237e4d5bba9ec28ea100c5f6fc2d8dda23392af28b333c4d8d2cebcbfa81d577"
}
```

### Sample 64: `03fdc64c672dfa7a`

| Field | Value |
|---|---|
| SHA-256 | `03fdc64c672dfa7a9a5e40ec87643037db26c9c52f7236655560a8a9678d6d24` |
| Family label | `Mirai` |
| File name | `morte.m68k` |
| File type | `elf` |
| First seen | `2026-06-29 23:21:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21f5d9921921ccc076b4fc46f09d5df1` |
| SHA-1 | `39f3535ba0ce5b2d3263b57db9564908a4192310` |
| SHA-256 | `03fdc64c672dfa7a9a5e40ec87643037db26c9c52f7236655560a8a9678d6d24` |
| SHA3-384 | `46783ae1699854d47fea519fb420b56f67293a105d65b26218e184e6748266d983b4d14126893afd87037b66076f6bcf` |
| TLSH | `T15AC33B8AB402DE7CF90FD9BB45674D0EBE30939156931B26639BFD93AC321A47D02D81` |
| SSDEEP | `3072:CkEjP+TNSqyagYFpqHUzNzaKx6tit6txu:2jP+TN6mgHENh6ti4Pu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_03fdc64c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03fdc64c672dfa7a9a5e40ec87643037db26c9c52f7236655560a8a9678d6d24"
    family = "Mirai"
    file_name = "morte.m68k"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:08"
  condition:
    hash.sha256(0, filesize) == "03fdc64c672dfa7a9a5e40ec87643037db26c9c52f7236655560a8a9678d6d24"
}
```

### Sample 65: `b66c3e12ac9cc816`

| Field | Value |
|---|---|
| SHA-256 | `b66c3e12ac9cc8161c2d313a0cc7ed02ae4ee7b785dc2b091b2be4ec679ec76f` |
| Family label | `unknown` |
| File name | `.bash_history` |
| File type | `unknown` |
| First seen | `2026-06-29 23:16:30` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bc6b19f811367f6835e68d969fe8517` |
| SHA-256 | `b66c3e12ac9cc8161c2d313a0cc7ed02ae4ee7b785dc2b091b2be4ec679ec76f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_b66c3e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b66c3e12ac9cc8161c2d313a0cc7ed02ae4ee7b785dc2b091b2be4ec679ec76f"
    family = "unknown"
    file_name = ".bash_history"
    file_type = "unknown"
    first_seen = "2026-06-29 23:16:30"
  condition:
    hash.sha256(0, filesize) == "b66c3e12ac9cc8161c2d313a0cc7ed02ae4ee7b785dc2b091b2be4ec679ec76f"
}
```

### Sample 66: `a81dd7a5c94f3f82`

| Field | Value |
|---|---|
| SHA-256 | `a81dd7a5c94f3f82fe489a5e9ccb5e8618f22d3846d1d74388e88e399a8de2e7` |
| Family label | `ValleyRAT` |
| File name | `2f3e3c0134aee76ac9876b3212116261.exe` |
| File type | `exe` |
| First seen | `2026-06-29 23:00:11` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f3e3c0134aee76ac9876b3212116261` |
| SHA-1 | `f3110e6cdfb86d0f09ff61e45aa42c555ca073df` |
| SHA-256 | `a81dd7a5c94f3f82fe489a5e9ccb5e8618f22d3846d1d74388e88e399a8de2e7` |
| SHA3-384 | `8ab9c545b9a0257489d7bd1130ab2d2de404e54c69dbe504d22810ba2fa34c2d1d851ca8f71cafb3a630fd1036503a22` |
| IMPHASH | `40ab50289f7ef5fae60801f88d4541fc` |
| TLSH | `T17095D023B2CBE13EE05E4B3B45B2A15494FB6B216523BD579AE4849CCF360601E3E747` |
| SSDEEP | `49152:F+MRvHLywv67MZ2Z9ftchfudg87dqn7iMj:FrGwv+MYchXqdnMj` |
| ICON-DHASH | `c0e2d89e9ec67c99` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_066_a81dd7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a81dd7a5c94f3f82fe489a5e9ccb5e8618f22d3846d1d74388e88e399a8de2e7"
    family = "ValleyRAT"
    file_name = "2f3e3c0134aee76ac9876b3212116261.exe"
    file_type = "exe"
    first_seen = "2026-06-29 23:00:11"
  condition:
    hash.sha256(0, filesize) == "a81dd7a5c94f3f82fe489a5e9ccb5e8618f22d3846d1d74388e88e399a8de2e7"
}
```

### Sample 67: `0e3e1d057c4a8553`

| Field | Value |
|---|---|
| SHA-256 | `0e3e1d057c4a85536e64c991f239b51961da39fe677bf72014bc96ffa0d21bbe` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-06-29 22:50:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6c2690b8736aec358e41b9d30d05ca1` |
| SHA-1 | `89d1df638589ae628e3d13ba77f0f4a68e66ea7a` |
| SHA-256 | `0e3e1d057c4a85536e64c991f239b51961da39fe677bf72014bc96ffa0d21bbe` |
| SHA3-384 | `4a864de9ea5a33cb9e2cac03f791ab02b494b9cc6becbe28c1bb2ecbf50ca778fb32e3d1de05feb917ee17bc8e8c75ee` |
| TLSH | `T16FE32C46E6814B13C0D2177ABADF42453323A764D3EB73059928BFB43F8679E0E63606` |
| TELFHASH | `t1f031fd325721411aae52cc60dcee57f1251d86272744ee33ef3ac8cc651a49ae62bc8f` |
| SSDEEP | `3072:U+UgVWIx0UEaK0U4560zSlzhXRzM9hO3+keLUM/9g2JCVF:U+UzIxLEaK0U456xl9RI9c3+ZgM/9d8T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_0e3e1d05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3e1d057c4a85536e64c991f239b51961da39fe677bf72014bc96ffa0d21bbe"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-06-29 22:50:59"
  condition:
    hash.sha256(0, filesize) == "0e3e1d057c4a85536e64c991f239b51961da39fe677bf72014bc96ffa0d21bbe"
}
```

### Sample 68: `26c13660580b570b`

| Field | Value |
|---|---|
| SHA-256 | `26c13660580b570bc0d7e8ad91bd337047edfd7f0e1311d8b6be8364ad525b8f` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-06-29 22:49:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d2e761438c5a9d2c0d6d001ab02b636` |
| SHA-1 | `5c32a270ef271fbb446155b4a59bb1bc7ca09079` |
| SHA-256 | `26c13660580b570bc0d7e8ad91bd337047edfd7f0e1311d8b6be8364ad525b8f` |
| SHA3-384 | `9de1f36f356c9b15aa3e820480f7a34feb45a62ec6b7acd87d2bb2f24e08211f57b39a3e884df837e4592be0625c4366` |
| TLSH | `T189539C73C8296E54D19582B4B871CB781B63B48482471FFA5BD9C2BA9087DFCF6093B4` |
| SSDEEP | `1536:JaDwtqKcomlIFZCXaZMYfPkYPmgpK2mP5A/iabC0c/v38Bs/n8a:JwacomlITCXaZMYXkYegQ2mgiabgXMla` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_26c13660
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26c13660580b570bc0d7e8ad91bd337047edfd7f0e1311d8b6be8364ad525b8f"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-06-29 22:49:40"
  condition:
    hash.sha256(0, filesize) == "26c13660580b570bc0d7e8ad91bd337047edfd7f0e1311d8b6be8364ad525b8f"
}
```

### Sample 69: `b3a346cecace10c6`

| Field | Value |
|---|---|
| SHA-256 | `b3a346cecace10c6212e65fe8f24fb25057f1efd72b3cefd69736ed2f1f1f5e4` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-06-29 22:49:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b450c2c166f1103fea060eb4afdd40a` |
| SHA-1 | `2e1f1c53625376adea047f39baae16fd9ff46935` |
| SHA-256 | `b3a346cecace10c6212e65fe8f24fb25057f1efd72b3cefd69736ed2f1f1f5e4` |
| SHA3-384 | `18603943df306b0bab526078243052c7bc4edd0e6711ad88d6cba1f4258f919ef12c2cfb103a277332e7b60a31de338f` |
| TLSH | `T1D9832A97F400EDBDF80AD77B4453090AB270A3A105830F36A39BB963FD721A45967EC6` |
| SSDEEP | `1536:quKG91p4sgWxYRyRqwwrzPQtav8FjWtFUo/V6OXZJ7/aNSOFmA7ExtX1dT:q5GTDxYRyRqwazPQta6Q9VXXz4FmA7ux` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_b3a346ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3a346cecace10c6212e65fe8f24fb25057f1efd72b3cefd69736ed2f1f1f5e4"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-06-29 22:49:39"
  condition:
    hash.sha256(0, filesize) == "b3a346cecace10c6212e65fe8f24fb25057f1efd72b3cefd69736ed2f1f1f5e4"
}
```

### Sample 70: `21d0c42ad9cd1258`

| Field | Value |
|---|---|
| SHA-256 | `21d0c42ad9cd1258b7c353537940cf23f536630b246af1184549931be1722c00` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-06-29 22:49:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f52da6a52371f62e7242a692aeea3126` |
| SHA-1 | `8bad37d9a78ebd7c847210d900f15f8f9afb0e13` |
| SHA-256 | `21d0c42ad9cd1258b7c353537940cf23f536630b246af1184549931be1722c00` |
| SHA3-384 | `fb376f6abe2e6b96b3554e42518d4ff2e7afce1ac761980502fac283b5804f4f7a2eff37317f7cfac305fbec893caead` |
| TLSH | `T18643023A92476FF8DB220971A0B625517B836BFE70FC66166B6EC728478EC160351783` |
| SSDEEP | `1536:FbokSFoBueUWdIACx8AL8xlYykDkSR6Luy6tlV1nLJ:uk0ge98lokS4Ld6tlH1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_21d0c42a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d0c42ad9cd1258b7c353537940cf23f536630b246af1184549931be1722c00"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-06-29 22:49:38"
  condition:
    hash.sha256(0, filesize) == "21d0c42ad9cd1258b7c353537940cf23f536630b246af1184549931be1722c00"
}
```

### Sample 71: `ae90b42ef3990549`

| Field | Value |
|---|---|
| SHA-256 | `ae90b42ef39905492d1950705c95a45466dbddb952fe7076c72d4a7a322e80ff` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35f1ffdd700a1de90138413f8aea7a78` |
| SHA-1 | `d33ad475106b58cdae8af9f581b61d9b6558c954` |
| SHA-256 | `ae90b42ef39905492d1950705c95a45466dbddb952fe7076c72d4a7a322e80ff` |
| SHA3-384 | `a56839b7a8c1b3e40e0ea92fc956d61565ba2f295e59d8ce131c27a589787d3679dbfbd942fcd89d47e496b3a76aaa88` |
| TLSH | `T170535BC5AA47D8F6FD5602711173E7378632F13A1129DA87C7A9ED32BC52900EA1739C` |
| TELFHASH | `t11f31b0fa6dee09fcb3d4a808c75a6fd31a7ae177156139b044b5585027f388081b5c3a` |
| SSDEEP | `1536:ahZerRy3lVDKvfb9IZG4R9bdx6uQWP++CMq32UFSTGhk15uJnaroXf:ahqo3lVDKbd4bnP+zf2UMT2M5O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_ae90b42e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae90b42ef39905492d1950705c95a45466dbddb952fe7076c72d4a7a322e80ff"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:51"
  condition:
    hash.sha256(0, filesize) == "ae90b42ef39905492d1950705c95a45466dbddb952fe7076c72d4a7a322e80ff"
}
```

### Sample 72: `972d2430ad555fa1`

| Field | Value |
|---|---|
| SHA-256 | `972d2430ad555fa14785036dfb3e9c9b36704ad9a4e7dc1a8713d03b88f24f66` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b0091ac4b40b3dd644fcc71b60e2d8b` |
| SHA-1 | `2d0758d5bb5f2e2c225711f8b1cbe3937de8f5dd` |
| SHA-256 | `972d2430ad555fa14785036dfb3e9c9b36704ad9a4e7dc1a8713d03b88f24f66` |
| SHA3-384 | `5ed44894fbff4849c7328bd47e1a24108c7f73b80006cea288ed4859a5f1b4831df27b881e2204c2c199810ad4b83ae6` |
| TLSH | `T1D8831895B8814B12D5D512BAFE1E118E3313177CE3DE73129D206F20778B96B0E7BA16` |
| TELFHASH | `t12311bd143ec84fcd92f08e18c3dea12679453a72da67393e8a97a61f43135d2201541e` |
| SSDEEP | `1536:ijna/CzPC7fG7rnmhsUrrar1FtQtMEig+wG3if7z7ueY52Y0s/hG:rwP0km+Urrar8+wG3if7zKeYw1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_972d2430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "972d2430ad555fa14785036dfb3e9c9b36704ad9a4e7dc1a8713d03b88f24f66"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:47"
  condition:
    hash.sha256(0, filesize) == "972d2430ad555fa14785036dfb3e9c9b36704ad9a4e7dc1a8713d03b88f24f66"
}
```

### Sample 73: `88a4b640bff61b58`

| Field | Value |
|---|---|
| SHA-256 | `88a4b640bff61b58aef117e03723e9e426afa9b0257fda7d1b91a4f799ad844f` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28095402913bbdef97f62714a279297b` |
| SHA-1 | `308bce0e56b5f17d770eb7a7a235b55b78c825b3` |
| SHA-256 | `88a4b640bff61b58aef117e03723e9e426afa9b0257fda7d1b91a4f799ad844f` |
| SHA3-384 | `2d025a4da889381962d9bcf98e28ade29d47c1a48c17bea8b940df5298aa54bc383239fa8c32cab4f420bd8c2cc0a898` |
| TLSH | `T1BEA3E506BB650FF7DC6FCD3706A9070225CCA51B22B83B367674D928B50B65B4AE3874` |
| SSDEEP | `1536:LvGefaZSdtuQ4/xl4ExO29zyN0ZNhdZp54crFCZeLs/h5J:LOefaZSdg59zm0Hr6eoJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_88a4b640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88a4b640bff61b58aef117e03723e9e426afa9b0257fda7d1b91a4f799ad844f"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:44"
  condition:
    hash.sha256(0, filesize) == "88a4b640bff61b58aef117e03723e9e426afa9b0257fda7d1b91a4f799ad844f"
}
```

### Sample 74: `0e421c747565b1a1`

| Field | Value |
|---|---|
| SHA-256 | `0e421c747565b1a178ac468d65a55d4e998589ae91181ff134a9473c9b653de7` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d206f2fdb9aa531b3bb7c0bba5dd94ad` |
| SHA-1 | `6587877cd2d7920a206d7937d1d2bc124954f2d3` |
| SHA-256 | `0e421c747565b1a178ac468d65a55d4e998589ae91181ff134a9473c9b653de7` |
| SHA3-384 | `9d95844890c5f7f41da9ee2a056df22a5ce2476de99690ec08452ea7663b31211ff4032efc41f9c297b3d9285dfd3942` |
| TLSH | `T197A3C91E6E218FBDF369C33047B78E21A79837D626E1D685E26CD6011E6034E641FFA4` |
| TELFHASH | `t173217f5c4d7412e48b321d9e2baeff76e19030de0b326d378e11aaadba6d9425d00c1c` |
| SSDEEP | `1536:yk8NZJjWAavP4cve4meOeuCyTPHvwIp/read7Q1Qs/Rd/uP:WZJjBavgzhHvlp/o1F/c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_0e421c74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e421c747565b1a178ac468d65a55d4e998589ae91181ff134a9473c9b653de7"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:40"
  condition:
    hash.sha256(0, filesize) == "0e421c747565b1a178ac468d65a55d4e998589ae91181ff134a9473c9b653de7"
}
```

### Sample 75: `bb5826a75467c0c2`

| Field | Value |
|---|---|
| SHA-256 | `bb5826a75467c0c2d1100f5c2ffbf690d93131084a999c9908f34849cc811e4d` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0413bbce2c2c98b5a5e22e360b311d4a` |
| SHA-1 | `dc8cd7b1f8a5c6d3e611e5bdbc8a66ded7ef31d3` |
| SHA-256 | `bb5826a75467c0c2d1100f5c2ffbf690d93131084a999c9908f34849cc811e4d` |
| SHA3-384 | `2b66814adcdfc89799b075c9621c8418d0529896223e8701d405f3bc9d20a4084ad5a1995a0fee561344f8965bb10414` |
| TLSH | `T11A631A91BD819B13C6D0227BFB5E428E372653A8D2EE72079D226F21378785F0E77641` |
| TELFHASH | `t1fb411fa55b940bdd5fd4c755928f613aa89e38f9af10399a8d2ebb0f81435c2b118433` |
| SSDEEP | `1536:XGBQnw68oqNi5Ivzu/GIw+D3ohyaRdWViEs/hX:XGBBa5Mg1w+8kayA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_bb5826a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb5826a75467c0c2d1100f5c2ffbf690d93131084a999c9908f34849cc811e4d"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:37"
  condition:
    hash.sha256(0, filesize) == "bb5826a75467c0c2d1100f5c2ffbf690d93131084a999c9908f34849cc811e4d"
}
```

### Sample 76: `ddd082b95397d7d2`

| Field | Value |
|---|---|
| SHA-256 | `ddd082b95397d7d25d7ee84bfdc42edd7a6dd0b9d3d5cc284869ad7fcd059088` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eddd6e41b95444ed3fb9af91adf2253f` |
| SHA-1 | `3cfa4834a035dbc99faf491b6be2051e15a61899` |
| SHA-256 | `ddd082b95397d7d25d7ee84bfdc42edd7a6dd0b9d3d5cc284869ad7fcd059088` |
| SHA3-384 | `55c47ec19cbd1856cf4646cde89e027e2af0f838ffb44bf7513811a541dffb896df883b87e7c407c248b41e55675859e` |
| TLSH | `T167732A91BD815713C6D012BBFB5E028E372A53A8D2EE72179D226F2137C786B0E77641` |
| TELFHASH | `t1d45112b9cba50aec1be0c74482c9a13cabea34ac5b00555acb5c7f2b8547981b01a437` |
| SSDEEP | `1536:86dz9MTC0XU66Ee5pk5brAMjztPz+Sbjt+UvAs/hY:86dS6EUgrAMNb+AA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_ddd082b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddd082b95397d7d25d7ee84bfdc42edd7a6dd0b9d3d5cc284869ad7fcd059088"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:33"
  condition:
    hash.sha256(0, filesize) == "ddd082b95397d7d25d7ee84bfdc42edd7a6dd0b9d3d5cc284869ad7fcd059088"
}
```

### Sample 77: `60a68bdb7838f8f9`

| Field | Value |
|---|---|
| SHA-256 | `60a68bdb7838f8f9c1bcceae008a115606c9d4c268882635e5d9d4b6fa595e17` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `965179c60aaa14f4c81abde3f2bdfa0c` |
| SHA-1 | `2a7aecdb6bdbc074e5ccbf562f1900bf035399d8` |
| SHA-256 | `60a68bdb7838f8f9c1bcceae008a115606c9d4c268882635e5d9d4b6fa595e17` |
| SHA3-384 | `e3c8818ad412327a25235d463c4e3f3ec101b502fbb626fc172c9c6d40db065291e270e0b3c10949b3f3cd09a416c067` |
| TLSH | `T1C7E2F26A51ECB12CE44E903BC32FA98E31E65D11FE17C69424C4B6DADF611F910B6833` |
| SSDEEP | `768:g32bRAqg2NQzSPMjFY8AFOEPB6ZSq7xnwNQBUW:DbRAp2N4ECF+FvB6ZSonwN2d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_60a68bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60a68bdb7838f8f9c1bcceae008a115606c9d4c268882635e5d9d4b6fa595e17"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:23"
  condition:
    hash.sha256(0, filesize) == "60a68bdb7838f8f9c1bcceae008a115606c9d4c268882635e5d9d4b6fa595e17"
}
```

### Sample 78: `e8ba36a1a044991c`

| Field | Value |
|---|---|
| SHA-256 | `e8ba36a1a044991c46b6396917dc9e9667e2d12e9365ced95fafc20dc72a1aa9` |
| Family label | `Mirai` |
| File name | `pspc` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `796fa4761ce88bae51e8d455fe03bb93` |
| SHA-1 | `48994e6ce55e3043e36be88af7c1df1a90cad603` |
| SHA-256 | `e8ba36a1a044991c46b6396917dc9e9667e2d12e9365ced95fafc20dc72a1aa9` |
| SHA3-384 | `40934120a165742da9762c6ce335fed13ff1637d1b16c74fd62b69bf1cc2332ec0ed3434c3d127f8c07a42d0c3021ef9` |
| TLSH | `T1D6735C32B9751D2BC4D0A87A61F30325F2F2478A25ACCA1A7D720D8EBF6565032477F9` |
| SSDEEP | `1536:jP+SbCGR18pspTH1qDQ2tXXUN95s0xwlWptCMR8/pW:zf4yV0pENP1x6MoW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_e8ba36a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8ba36a1a044991c46b6396917dc9e9667e2d12e9365ced95fafc20dc72a1aa9"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:22"
  condition:
    hash.sha256(0, filesize) == "e8ba36a1a044991c46b6396917dc9e9667e2d12e9365ced95fafc20dc72a1aa9"
}
```

### Sample 79: `68857051c25bbf96`

| Field | Value |
|---|---|
| SHA-256 | `68857051c25bbf96357594e0d70c0678eba91b3ee67ff189ba20859dbfa359a1` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec294f33271a4ca914ece4e2fd5400b4` |
| SHA-1 | `0ec8208b11115911b8a5331025e3dcec8b718f6d` |
| SHA-256 | `68857051c25bbf96357594e0d70c0678eba91b3ee67ff189ba20859dbfa359a1` |
| SHA3-384 | `6e5602ddc57729f8c70b746001df9a2bcf67e725d67ce42ebb1ddf72b5d36151b5f3d5bb4cad740b9034708caf776abc` |
| TLSH | `T12A03E02510105EF0DEBA1872E8F844C629034BFC55FB7B9139F448AC45CA5AE2EEE5D5` |
| SSDEEP | `768:YhbUpgfK/AwDBKK3fgYg17cLkilEBwWEG+gXFubkavou8Lv9q3UEL+u:YxUpgy4iBHfgY+7UlEBvZdGkhkLD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_68857051
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68857051c25bbf96357594e0d70c0678eba91b3ee67ff189ba20859dbfa359a1"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:18"
  condition:
    hash.sha256(0, filesize) == "68857051c25bbf96357594e0d70c0678eba91b3ee67ff189ba20859dbfa359a1"
}
```

### Sample 80: `f46ee46298b90eb0`

| Field | Value |
|---|---|
| SHA-256 | `f46ee46298b90eb04b1c15e4e4cecc8a4e5a7730c654d58261c9c846084249ca` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec5d20c474c57178927808f21b857bae` |
| SHA-1 | `916539d6363dadf5d4af44e16b403eba1b954fc1` |
| SHA-256 | `f46ee46298b90eb04b1c15e4e4cecc8a4e5a7730c654d58261c9c846084249ca` |
| SHA3-384 | `769fbd578e5985d12a3b44d3951254042728d3956c30f342a407cad7e1183e6a73d6865e66a833ee913de97acae65ab7` |
| TLSH | `T16303F1DD9FE9ECCECC6D89B7175D27C7AD242240339B46846644CCCD37271A618468BD` |
| SSDEEP | `768:MVyIwYjG0JFLyEJCVsffisu6A15pPV25F0hZjUCa1Bzz+hbpzxlkK5/WV:MVyYjXJ07Vsfq7FHJ8QjUF1BzKZ5h5Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_f46ee462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f46ee46298b90eb04b1c15e4e4cecc8a4e5a7730c654d58261c9c846084249ca"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:17"
  condition:
    hash.sha256(0, filesize) == "f46ee46298b90eb04b1c15e4e4cecc8a4e5a7730c654d58261c9c846084249ca"
}
```

### Sample 81: `916c30b5ea0d508e`

| Field | Value |
|---|---|
| SHA-256 | `916c30b5ea0d508e5bc4cfb91a51e0dc2da256a309eb6f0d9555790852077159` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f36831b2969245308a83b19da70e7964` |
| SHA-1 | `a4693daa615853780e4b4d8a3e8b0efb4d1bf493` |
| SHA-256 | `916c30b5ea0d508e5bc4cfb91a51e0dc2da256a309eb6f0d9555790852077159` |
| SHA3-384 | `84a4e190f5131c0d48c94838b864f0fa13a8a5acfc8ecbaa17c99cfccab4311f1f2416be18a81ba0237c48d58ae92664` |
| TLSH | `T178F2D07E27508BCDCD2DC6BA90FD47E0B3540B96D1434C9FB18B3763686A8563253BA0` |
| SSDEEP | `768:NNYKyukZoTMKeIGb+xTJLiEUDiq/zR46zamw5t4Tj52JgGlzDpbuR1J5:HYdWleLylLXUH/vM5tm5iVJuv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_916c30b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "916c30b5ea0d508e5bc4cfb91a51e0dc2da256a309eb6f0d9555790852077159"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:16"
  condition:
    hash.sha256(0, filesize) == "916c30b5ea0d508e5bc4cfb91a51e0dc2da256a309eb6f0d9555790852077159"
}
```

### Sample 82: `5cf36b618810a999`

| Field | Value |
|---|---|
| SHA-256 | `5cf36b618810a9991e792956ccccb82fea10a6713793adb9a0c80bee8a945b4e` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `874286e093d600b4c79d4638b9721153` |
| SHA-1 | `64a9f6516952ed0e298eef52ec161a1a99aebf86` |
| SHA-256 | `5cf36b618810a9991e792956ccccb82fea10a6713793adb9a0c80bee8a945b4e` |
| SHA3-384 | `28020d665b2f36a5485f4f7005b6e1dded59384bef7fc34fe5b1a67cbceb44cd5766249bb65c55066096ea475a90a1fc` |
| TLSH | `T1B0E2E1912927AC30E320647B1E6CD34719BAB6B0C2AE31DA3D3506BD37878DC5A79747` |
| SSDEEP | `768:XeBsVPxhgNjq3NXJlX0y+CVidmYfhkXS8qwjKVhIs3UozJ:XeGVPxGpq9viCViTMqwjKVh9zJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_5cf36b61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cf36b618810a9991e792956ccccb82fea10a6713793adb9a0c80bee8a945b4e"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:15"
  condition:
    hash.sha256(0, filesize) == "5cf36b618810a9991e792956ccccb82fea10a6713793adb9a0c80bee8a945b4e"
}
```

### Sample 83: `47f4697de6e24f50`

| Field | Value |
|---|---|
| SHA-256 | `47f4697de6e24f50bc84f1325aae1436d0e19788f350bdcc90a3f3943a9728a7` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-06-29 22:47:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3c3a2bc354092052327ef14aab5b4f4` |
| SHA-1 | `29688c18726d8c190bb2d0a8f2ee8604ab354cec` |
| SHA-256 | `47f4697de6e24f50bc84f1325aae1436d0e19788f350bdcc90a3f3943a9728a7` |
| SHA3-384 | `df6d010c8a5f777aa542b705e8bc6cf7a1af64de22774ab0e6824d5beeb902097d5d63b60bc166e1ba50ad7f0a65c62e` |
| TLSH | `T1AAF2E1315E1A3DE0E6B0AC7C517641C5E4A35BB1E17296FD674C8398B38C82612BE62B` |
| SSDEEP | `768:+ZAb2jdTWDPtuRl//9ysfu/Gig+7pBWLX5F1ms3UozX:+ZAKjBWDPtuT/9ysfZpcWLX53zX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_47f4697d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47f4697de6e24f50bc84f1325aae1436d0e19788f350bdcc90a3f3943a9728a7"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:13"
  condition:
    hash.sha256(0, filesize) == "47f4697de6e24f50bc84f1325aae1436d0e19788f350bdcc90a3f3943a9728a7"
}
```

### Sample 84: `d928467888cd402a`

| Field | Value |
|---|---|
| SHA-256 | `d928467888cd402afbdd062a04e903d639086f614e7a0424dbc098aa8e8d31ef` |
| Family label | `MaskGramStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-29 22:41:16` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, MaskGramStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `798dc85674894812f6a5102126a3295c` |
| SHA-1 | `938f4bbd1a6f036e58ceab6484cd71a765eaa87b` |
| SHA-256 | `d928467888cd402afbdd062a04e903d639086f614e7a0424dbc098aa8e8d31ef` |
| SHA3-384 | `2b870cce8b0022476ff9a5bfe22f67b6e10dcc858ac364216e2890f7153535c043a7ab0c83e5be857ee3330e704e0059` |
| IMPHASH | `e8f58099adbf7104a18801c577843dc7` |
| TLSH | `T163043B1BD5D540F9EC2AC678865AE232A4B3BC591936BA4F6BA0DF052F50B30B71DF04` |
| SSDEEP | `3072:sXp/pamDY4MAHDMihyHmJY7b1iDXBe2AVNAONl3k7Fsq1Y4him+:m/bHDMigHmK7+RlAVuONVQRhim` |

#### Technical Assessment

- The sample is tracked as `MaskGramStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MaskGramStealer_084_d9284678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d928467888cd402afbdd062a04e903d639086f614e7a0424dbc098aa8e8d31ef"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-29 22:41:16"
  condition:
    hash.sha256(0, filesize) == "d928467888cd402afbdd062a04e903d639086f614e7a0424dbc098aa8e8d31ef"
}
```

### Sample 85: `0f451ed1c1a487f6`

| Field | Value |
|---|---|
| SHA-256 | `0f451ed1c1a487f63d83620e0e3fd650e8d982098864c7c96013f3213204a2bb` |
| Family label | `Mirai` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-06-29 22:32:22` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81065487899b565f1d8cd282b8d80782` |
| SHA-1 | `268c98b0d984ed402fbfd53f403229323613e16d` |
| SHA-256 | `0f451ed1c1a487f63d83620e0e3fd650e8d982098864c7c96013f3213204a2bb` |
| SHA3-384 | `e523e97cc605f4e0fff435a52412761408f7eadb6a8de869c9057a9c83fcfcd453b241be32d3b1acaaf2baac63f81449` |
| TLSH | `T1BC415CDD80766A926DEDDC11707BD96160A3DD926CA84B0AADDC7DB1CC89E00701AF2C` |
| SSDEEP | `48:9XJ2pXJ/XJhXJ8XJfpXJ2XJKXJPXJYXJ1XJuQwXJ0XJtXJDBXJ6i8XJ4XJw:9XUXZXfXOXXXUXoXFXaXnXMQwX2XjXTK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_0f451ed1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f451ed1c1a487f63d83620e0e3fd650e8d982098864c7c96013f3213204a2bb"
    family = "Mirai"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-06-29 22:32:22"
  condition:
    hash.sha256(0, filesize) == "0f451ed1c1a487f63d83620e0e3fd650e8d982098864c7c96013f3213204a2bb"
}
```

### Sample 86: `014f3accbf588566`

| Field | Value |
|---|---|
| SHA-256 | `014f3accbf588566489bb34bd21402c1ab70f70448f818ba817b7db2d6e21122` |
| Family label | `AveMariaRAT` |
| File name | `2DF7867DD2AF4783E4881D38E5901F5F.exe` |
| File type | `exe` |
| First seen | `2026-06-29 22:25:08` |
| Reporter | `abuse_ch` |
| Tags | `AveMariaRAT, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2df7867dd2af4783e4881d38e5901f5f` |
| SHA-1 | `4d7d1e9a64f5f4262fa269d5df819411aa31bfaf` |
| SHA-256 | `014f3accbf588566489bb34bd21402c1ab70f70448f818ba817b7db2d6e21122` |
| SHA3-384 | `d0012a941f7c5e6543a4b7f20715852fedb5e23cb161d983dc18b27c7c2ca3c16d0ed49166912321eaa9cc8a6167d116` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T140845A88728039AEC857CD3145641D7896136E6A7F1AF203AC277DB77B3F9C79E110A2` |
| SSDEEP | `6144:yvsIu8/bUtPXsNPEjsIad+Zj/Thoeem0Lr0ftEdRsIaTmSHCX3YhOI:ya8/bUC7lufmr0ftEdRsIaTmSHCi` |
| ICON-DHASH | `70c0db4eea7ab0fc` |

#### Technical Assessment

- The sample is tracked as `AveMariaRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AveMariaRAT_086_014f3acc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "014f3accbf588566489bb34bd21402c1ab70f70448f818ba817b7db2d6e21122"
    family = "AveMariaRAT"
    file_name = "2DF7867DD2AF4783E4881D38E5901F5F.exe"
    file_type = "exe"
    first_seen = "2026-06-29 22:25:08"
  condition:
    hash.sha256(0, filesize) == "014f3accbf588566489bb34bd21402c1ab70f70448f818ba817b7db2d6e21122"
}
```

### Sample 87: `76ef465db71f0b8b`

| Field | Value |
|---|---|
| SHA-256 | `76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83` |
| Family label | `unknown` |
| File name | `76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83` |
| File type | `elf` |
| First seen | `2026-06-29 22:08:52` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8d1f95ba964fc0ba510ecbc0473e22c` |
| SHA-1 | `c8be6d97aff857de4551cc5711167e87631c29cf` |
| SHA-256 | `76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83` |
| SHA3-384 | `625cbdb81bfd24151fd8a86f940b1614681b3d5e90e66505fce9a016c376e46d2380c99d9a5eded47321756ad20d5826` |
| TLSH | `T13957DF77814238E9E9B98DB4D01025416DAC788B5778A3C7BAC871E667EB7E08D3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ0:cqYUQuVDt0TZEL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_76ef465d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83"
    family = "unknown"
    file_name = "76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83"
    file_type = "elf"
    first_seen = "2026-06-29 22:08:52"
  condition:
    hash.sha256(0, filesize) == "76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83"
}
```

### Sample 88: `483ddab777936fca`

| Field | Value |
|---|---|
| SHA-256 | `483ddab777936fca2b3fe7896c84987deb519e236ae41796eb35767f46bb38f5` |
| Family label | `Mirai` |
| File name | `nerv.sh4` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39a8d266f551599ad3550dc7edd24347` |
| SHA-1 | `e8e604bfaad7ec3e27a1938398f223a36570df61` |
| SHA-256 | `483ddab777936fca2b3fe7896c84987deb519e236ae41796eb35767f46bb38f5` |
| SHA3-384 | `90c6b7b05222c44e1d85a591c35cc232faf2020b2f6194ed1da32756930966e44dc6d121f160f6dcd65a2d2d2ad5afc2` |
| TLSH | `T10893AD33C52A6DD4E6519674E0F48AF81B63E10082671FBB59D8C5E95087EBCF20A3F8` |
| SSDEEP | `1536:CGKSorFc8wtA6zh8qjeCckbJcNcnMakQ7mTFiFfJGKGUFeo7UzEmUvCxuJo99C8j:CG7orFc8969xjeCcEeWnbq0J5GOmEmUc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_483ddab7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "483ddab777936fca2b3fe7896c84987deb519e236ae41796eb35767f46bb38f5"
    family = "Mirai"
    file_name = "nerv.sh4"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:38"
  condition:
    hash.sha256(0, filesize) == "483ddab777936fca2b3fe7896c84987deb519e236ae41796eb35767f46bb38f5"
}
```

### Sample 89: `482698293d879600`

| Field | Value |
|---|---|
| SHA-256 | `482698293d879600cb9b1b93c45075f77750102661fe8dd8cd97680e25ec8681` |
| Family label | `Mirai` |
| File name | `nerv.arm4` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c272174b3d0141a6c45969125324e27a` |
| SHA-1 | `88a76684a2de53f261a54cfd3baefe447b22b0f2` |
| SHA-256 | `482698293d879600cb9b1b93c45075f77750102661fe8dd8cd97680e25ec8681` |
| SHA3-384 | `283be81630145c5b99b3b91189f3ab23b3108fa08a1f12dc1b24bb3cb11312f8b70919c4bd5ed5467e7c4797d02db97a` |
| TLSH | `T173B31851BC825612C6D612BBFA6E418E375623A8D3EF3213CD255F203BC791B0E77652` |
| SSDEEP | `1536:bjcun8lzTm/RWSimQAf3GVNUsdnS3qF4Z7Fo5YWRavLKjA/t5tt61rO4nl6DoRa4:bjcmam0SwNUsdnS3qWJjW+LEA/t5zD+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_48269829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "482698293d879600cb9b1b93c45075f77750102661fe8dd8cd97680e25ec8681"
    family = "Mirai"
    file_name = "nerv.arm4"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:37"
  condition:
    hash.sha256(0, filesize) == "482698293d879600cb9b1b93c45075f77750102661fe8dd8cd97680e25ec8681"
}
```

### Sample 90: `c15510299e739d04`

| Field | Value |
|---|---|
| SHA-256 | `c15510299e739d04f78a611d2cee455ac3e49004ff19ca5707a7728a54213772` |
| Family label | `Mirai` |
| File name | `nerv.x86_32` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fcb7b1c465156e8b0a627157cdb11ba` |
| SHA-1 | `985c0626a83fac8a6ae0388cf166382f5a3ce207` |
| SHA-256 | `c15510299e739d04f78a611d2cee455ac3e49004ff19ca5707a7728a54213772` |
| SHA3-384 | `717c35110c1a4f8e5bde33e1b136c9c7ad175e62475c8bbd951db23d0adc8677c90aeddba5363cee6b239002ded3b72c` |
| TLSH | `T1E1A329C1F68B84F9D54B48704066F33FCE32E5268071C9AEDF99AF36DA37641921629C` |
| TELFHASH | `t1db411afa56760cd8a7d0ac03a64e5730ad0d27bb546076a309f72924331fd8645bbc3d` |
| SSDEEP | `3072:ZTdeqPbQ0yhOEckEUI6An128egcTz3s6yNCoUKcnsEW+QuY09RO:ZTFPbQ0yhOEckEUI6A12ZHTz1qmn0jWy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_c1551029
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c15510299e739d04f78a611d2cee455ac3e49004ff19ca5707a7728a54213772"
    family = "Mirai"
    file_name = "nerv.x86_32"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:36"
  condition:
    hash.sha256(0, filesize) == "c15510299e739d04f78a611d2cee455ac3e49004ff19ca5707a7728a54213772"
}
```

### Sample 91: `d99cfe550c1e0731`

| Field | Value |
|---|---|
| SHA-256 | `d99cfe550c1e0731cc26677db68de552a55b90b8696dbc21a8d01ee5960f710d` |
| Family label | `Mirai` |
| File name | `nerv.x86` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb032ea13698949165948aab8ac657d6` |
| SHA-1 | `d2cb2671563dbc04f0ed68135927592921c353d3` |
| SHA-256 | `d99cfe550c1e0731cc26677db68de552a55b90b8696dbc21a8d01ee5960f710d` |
| SHA3-384 | `251c1b127da08ed1bfa1268cc52299abdb3583edb03c4b7db0bc1f2b94d569d941223fefd0b93fab6440a7d322cb3ce4` |
| TLSH | `T1D4936BC1E653E8F5ED1705751137E33B4B37F139102DDA97DBA8AA32BCA2600D5262AC` |
| TELFHASH | `t196410cfa197f0cd897d4a802d20e2f31798eab3b656073e206f3b5753067501517ac39` |
| SSDEEP | `1536:Lh+jn2+ifI/EIzRBIepUGzX+VCW+XpElUx02V78OKTiI3nPKxCdg71G+dkChCq:9+jn2tA/EIzPIepUG6VCPulo7JAiI3P2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_d99cfe55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d99cfe550c1e0731cc26677db68de552a55b90b8696dbc21a8d01ee5960f710d"
    family = "Mirai"
    file_name = "nerv.x86"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:34"
  condition:
    hash.sha256(0, filesize) == "d99cfe550c1e0731cc26677db68de552a55b90b8696dbc21a8d01ee5960f710d"
}
```

### Sample 92: `e4e6ea8ea27556af`

| Field | Value |
|---|---|
| SHA-256 | `e4e6ea8ea27556af7985e46eea728b71c69bf997a458dbbad629b78a5595b98d` |
| Family label | `Mirai` |
| File name | `nerv.arm5` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e898b537f1992c3d03d036050032c10` |
| SHA-1 | `dd8a37ea41303c03ffd171c2b67388c0f17de52b` |
| SHA-256 | `e4e6ea8ea27556af7985e46eea728b71c69bf997a458dbbad629b78a5595b98d` |
| SHA3-384 | `de718356721e681906ce0288431b372fbdeab7dd9949aaae953e29a620a478e4556be542bd312dd4625246847def1173` |
| TLSH | `T181B32986BD826622C5D423BBFA6E418E771623A8D3EF32138D215F2037C792B0D77651` |
| TELFHASH | `t1afb012a1222077f6f7ce248200fb33110a84900f25ad15e162e86c4e01c7413b27bd12` |
| SSDEEP | `1536:vOlviIlGPod87HK7CnvLNUsdnYkqlGxPR+UK7as+fr0V5EYFYlTWzLxuIeJq:vOlazoiNUsdnYkqQ5+T+fr/DW/8q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_e4e6ea8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4e6ea8ea27556af7985e46eea728b71c69bf997a458dbbad629b78a5595b98d"
    family = "Mirai"
    file_name = "nerv.arm5"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:33"
  condition:
    hash.sha256(0, filesize) == "e4e6ea8ea27556af7985e46eea728b71c69bf997a458dbbad629b78a5595b98d"
}
```

### Sample 93: `99a5a14183cbc57a`

| Field | Value |
|---|---|
| SHA-256 | `99a5a14183cbc57a8d72fd7f3470aa874e046488482c8b75a5cef228ffb24314` |
| Family label | `Mirai` |
| File name | `nerv.sparc` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53f6e757c51162ef64abbf6771f17306` |
| SHA-1 | `8b4b20f72d3e92fdf412b8a35a8b340193187430` |
| SHA-256 | `99a5a14183cbc57a8d72fd7f3470aa874e046488482c8b75a5cef228ffb24314` |
| SHA3-384 | `e87bcac1d277ce8125dfb11dde8774932b19fbd59631d0413ab4b75195ff9646246102a128bff7b33a5b7fedee6424f8` |
| TLSH | `T1EDB35D22B9751E2BC4D4A8BA61F74365F1F2578A21ECC51E3D710E8EEF242503257BB8` |
| SSDEEP | `1536:X1/ik8A0iX/SSqcYI88KrNUv4oOaOHykDfZAXQChShIy6LIzifWL2Y9t9fDNWq5H:XhjoNUAo8JHR3OU9PfDNlCDg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_99a5a141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99a5a14183cbc57a8d72fd7f3470aa874e046488482c8b75a5cef228ffb24314"
    family = "Mirai"
    file_name = "nerv.sparc"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:32"
  condition:
    hash.sha256(0, filesize) == "99a5a14183cbc57a8d72fd7f3470aa874e046488482c8b75a5cef228ffb24314"
}
```

### Sample 94: `63c2176ac941063c`

| Field | Value |
|---|---|
| SHA-256 | `63c2176ac941063c3c0dfaf8d3f6d798bed2cb976e0a622dff1ea5caa4d9d3ff` |
| Family label | `Mirai` |
| File name | `nerv.mpsl` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `771dfb7d8a43c5c757f9bb762199dccb` |
| SHA-1 | `b2799b723b324f2fb63f4e6a5f214e89be956cb2` |
| SHA-256 | `63c2176ac941063c3c0dfaf8d3f6d798bed2cb976e0a622dff1ea5caa4d9d3ff` |
| SHA3-384 | `dd7c715d8728a9e883b9845fb3c50bac17bf2b6ea657c298e53c0720f04c35d3a5723c701d9df96ccaa3875e0f8d734c` |
| TLSH | `T107D3F806FB210EFBEC9BCD374AE91705258C651A22AE7F367934D928F44B15B16E3C60` |
| SSDEEP | `3072:NnjFbpospIvGVSy/QrajBcNiD0qwwgr7P:Nn1bJfUYSS0qKfP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_63c2176a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c2176ac941063c3c0dfaf8d3f6d798bed2cb976e0a622dff1ea5caa4d9d3ff"
    family = "Mirai"
    file_name = "nerv.mpsl"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:31"
  condition:
    hash.sha256(0, filesize) == "63c2176ac941063c3c0dfaf8d3f6d798bed2cb976e0a622dff1ea5caa4d9d3ff"
}
```

### Sample 95: `da94ba7c1a962a0d`

| Field | Value |
|---|---|
| SHA-256 | `da94ba7c1a962a0d6c7508118c82bc8bd7f0f47771515779594298edbe8790a3` |
| Family label | `Gafgyt` |
| File name | `nerv.m68k` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30650fc73f5e3d3190fe23baca7f260c` |
| SHA-1 | `0d996b9aadc930493606589a784b0bfcd6d9da20` |
| SHA-256 | `da94ba7c1a962a0d6c7508118c82bc8bd7f0f47771515779594298edbe8790a3` |
| SHA3-384 | `d26f7b4b3b99657fc9c0130bf6ed5cd3cec4acff584256999a9b40d5228a9dbf44ba312e6ea93ae5df55c5845097154c` |
| TLSH | `T171B34AD6F801DD7DFC0EDB7F4457050AB621A36216935F3A6357BE63BC310A46922E82` |
| SSDEEP | `1536:w/Fd8MNhs3SVr7fVnYMF7ZzBso1K8FJBGxtjovb5c/nLa17AuQJCPvA:KFd/GC/Vnr7Zlso1/BQolKRuQJuvA` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_095_da94ba7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da94ba7c1a962a0d6c7508118c82bc8bd7f0f47771515779594298edbe8790a3"
    family = "Gafgyt"
    file_name = "nerv.m68k"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:29"
  condition:
    hash.sha256(0, filesize) == "da94ba7c1a962a0d6c7508118c82bc8bd7f0f47771515779594298edbe8790a3"
}
```

### Sample 96: `31c737dc339d77f6`

| Field | Value |
|---|---|
| SHA-256 | `31c737dc339d77f66a8eb33f5e514c7294b77978d084d60b0f6730c46ac6cf1d` |
| Family label | `Gafgyt` |
| File name | `nerv.arm7` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7bb5b3a770497ae1389f9c0ba02ddd1` |
| SHA-1 | `6609fbc18d14bb8afb97b5c85f6ac93c92f76e37` |
| SHA-256 | `31c737dc339d77f66a8eb33f5e514c7294b77978d084d60b0f6730c46ac6cf1d` |
| SHA3-384 | `ab64104ccc70eddc76f0ccec703f3d4db126002581f7d230846c1eb4a0f8dd223918a435b0b5b576ff265ac5eadaba1a` |
| TLSH | `T1A7D32A46AD425A12D5D732FAFAAE408933137F79E3FA7102DD205F5023C9A9B0E77612` |
| TELFHASH | `t1d0b0120fa520205d076180bac0c7d869807034df15002940c5541609a0a0a12380b267` |
| SSDEEP | `3072:UY+3OS15mqV5O4nnPfGxKCEk7bUBbaVYScU0UlElEfMKV0KebzoC:TS1tLnPexKCEOb+baVYScUrElEr0XvoC` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_096_31c737dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31c737dc339d77f66a8eb33f5e514c7294b77978d084d60b0f6730c46ac6cf1d"
    family = "Gafgyt"
    file_name = "nerv.arm7"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:28"
  condition:
    hash.sha256(0, filesize) == "31c737dc339d77f66a8eb33f5e514c7294b77978d084d60b0f6730c46ac6cf1d"
}
```

### Sample 97: `b5331c5a2934b2ff`

| Field | Value |
|---|---|
| SHA-256 | `b5331c5a2934b2ff4863bc94d14b1ba89cb1070b34814470dce5d0e4750aca3a` |
| Family label | `Mirai` |
| File name | `nerv.mips` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `053aed9d14db57e4b0e5894b5dee7d31` |
| SHA-1 | `7bb9852340576399d1041d833a4441d8df80998c` |
| SHA-256 | `b5331c5a2934b2ff4863bc94d14b1ba89cb1070b34814470dce5d0e4750aca3a` |
| SHA3-384 | `5bd194fb4e76035bab55b7cf2365e710ed273f73edb866b6e80491d60454ad8464a83cd3b09f7472a9f0d15e8668b370` |
| TLSH | `T158D3D81E6E218FBDF769C33447B78E25A39873C622E1C641E17CD6115E6028E641FFA8` |
| TELFHASH | `t1022151584e7827e477365c89559dfb7bd2a130ef3b125c378e11a8aab76cc819e20c0c` |
| SSDEEP | `3072:WEyxpsn1wPuuvIJnNKBkKNQYRKMpw+grwDAg48+:Ap41wPyJnNK2Bnw+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_b5331c5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5331c5a2934b2ff4863bc94d14b1ba89cb1070b34814470dce5d0e4750aca3a"
    family = "Mirai"
    file_name = "nerv.mips"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:27"
  condition:
    hash.sha256(0, filesize) == "b5331c5a2934b2ff4863bc94d14b1ba89cb1070b34814470dce5d0e4750aca3a"
}
```

### Sample 98: `3c90550ad4e64b93`

| Field | Value |
|---|---|
| SHA-256 | `3c90550ad4e64b9395add010732315f4fcb3dcd6bbea98d79432dbf5327401b8` |
| Family label | `Mirai` |
| File name | `nerv.ppc` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0428bdbdfb83870c2dc8504aa98cbfe3` |
| SHA-1 | `43b26dd9e5a7b8436bc7801e36e5c607fae291fb` |
| SHA-256 | `3c90550ad4e64b9395add010732315f4fcb3dcd6bbea98d79432dbf5327401b8` |
| SHA3-384 | `fb3d167858a3ffbb7955041e969505f51ca4d95cb32e61a33fb8efb21cae7c5bb00e0bf94bf0cf56a2a8d1f0eab4e992` |
| TLSH | `T18DB34C02B31C0F47C5675AB02D3F57E1A3FF999021F4BA89251EAB5692B1E361182FCD` |
| SSDEEP | `1536:bL4aGHx7PtazxJWsvNW/yHoslGEMzdbCLLOpHqDXzSbJ6ecKwgmkyRwPIe+hZ:buiNvHogMQe/b9BjsZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_3c90550a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c90550ad4e64b9395add010732315f4fcb3dcd6bbea98d79432dbf5327401b8"
    family = "Mirai"
    file_name = "nerv.ppc"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:25"
  condition:
    hash.sha256(0, filesize) == "3c90550ad4e64b9395add010732315f4fcb3dcd6bbea98d79432dbf5327401b8"
}
```

### Sample 99: `5a021367a916abe1`

| Field | Value |
|---|---|
| SHA-256 | `5a021367a916abe1d8b054fff01ca0b7fde072eb96452dee4cf1a7b644c03ff9` |
| Family label | `Mirai` |
| File name | `nerv.arm6` |
| File type | `elf` |
| First seen | `2026-06-29 22:04:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd8588cd932547329088b8fc456652b3` |
| SHA-1 | `7ed220ae4bd70c0d5ad8012c3327a4b7bae3bbf3` |
| SHA-256 | `5a021367a916abe1d8b054fff01ca0b7fde072eb96452dee4cf1a7b644c03ff9` |
| SHA3-384 | `135793349c1df55c9473e7a65ded5750de4d931fc2ba4535ff28511a20f0ec8bca1b4c8c2d6772b714298ebd6b77ed0e` |
| TLSH | `T120B32A86AC814A11C5D613BFFA2E118D3313277CE3DE72129D205F2477CA96B0E7BA56` |
| TELFHASH | `t1bdf08bd4a085318cabd51a95d5adb69114e638f83f4a1cc2ab8e5a4e13484f1b834c3f` |
| SSDEEP | `3072:Vfx2IfERqVXKO4bnOfGZKuawHQonVLao6qXmfeaMFM6xut:uIfjlQDOeZKuaWQonpaPYmgMmU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_5a021367
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a021367a916abe1d8b054fff01ca0b7fde072eb96452dee4cf1a7b644c03ff9"
    family = "Mirai"
    file_name = "nerv.arm6"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:24"
  condition:
    hash.sha256(0, filesize) == "5a021367a916abe1d8b054fff01ca0b7fde072eb96452dee4cf1a7b644c03ff9"
}
```

### Sample 100: `3133d611ad668557`

| Field | Value |
|---|---|
| SHA-256 | `3133d611ad668557d92759f99f104bb6d41da16b9819f0566e6943fd7931c132` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-06-29 22:00:45` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f725826dd7029e6ef97666bac93ca082` |
| SHA-256 | `3133d611ad668557d92759f99f104bb6d41da16b9819f0566e6943fd7931c132` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_3133d611
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3133d611ad668557d92759f99f104bb6d41da16b9819f0566e6943fd7931c132"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-06-29 22:00:45"
  condition:
    hash.sha256(0, filesize) == "3133d611ad668557d92759f99f104bb6d41da16b9819f0566e6943fd7931c132"
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
 * Generated: 2026-06-30T04:37:43.729813+00:00
 */

rule MalwareBazaar_ValleyRAT_001_ea37cf74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea37cf74d52ae3a829b32b3c91f940132a649ec854b2d2377ef82c523fff7fe4"
    family = "ValleyRAT"
    file_name = "4F46075552500DA5B19B711285A5152D.dll"
    file_type = "dll"
    first_seen = "2026-06-30 04:30:12"
  condition:
    hash.sha256(0, filesize) == "ea37cf74d52ae3a829b32b3c91f940132a649ec854b2d2377ef82c523fff7fe4"
}

rule MalwareBazaar_unknown_002_f55acb3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f55acb3e7fde7e6f9800bc6b705cc4067a552bf480ba9c730d1f325d8ef1a15a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 03:42:18"
  condition:
    hash.sha256(0, filesize) == "f55acb3e7fde7e6f9800bc6b705cc4067a552bf480ba9c730d1f325d8ef1a15a"
}

rule MalwareBazaar_unknown_003_31a3bb40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a"
    family = "unknown"
    file_name = "31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a"
    file_type = "elf"
    first_seen = "2026-06-30 03:10:37"
  condition:
    hash.sha256(0, filesize) == "31a3bb40761aed253ce166adb8db78ea1c11ad4ce4c7ede75115b6c2d7de0a7a"
}

rule MalwareBazaar_unknown_004_7d06b7a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d06b7a9bd21800b8f8151f42c9ccce3903479d8bb4ef0f7869cc69f08043abd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 03:09:25"
  condition:
    hash.sha256(0, filesize) == "7d06b7a9bd21800b8f8151f42c9ccce3903479d8bb4ef0f7869cc69f08043abd"
}

rule MalwareBazaar_Mirai_005_fe6c204b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe6c204be417280411d878672cf522d466732199b75261c533655621bcf8f284"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-06-30 02:35:13"
  condition:
    hash.sha256(0, filesize) == "fe6c204be417280411d878672cf522d466732199b75261c533655621bcf8f284"
}

rule MalwareBazaar_unknown_006_6b0b063e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5"
    family = "unknown"
    file_name = "6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5"
    file_type = "elf"
    first_seen = "2026-06-30 02:31:58"
  condition:
    hash.sha256(0, filesize) == "6b0b063e20f67cf5acafda5e1a68d0abce59fcc129100349388e0f616995b3a5"
}

rule MalwareBazaar_Mirai_007_90d83585
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90d8358588b9ded64882a5385fc8c5f42f0ab963bad27951fda848e6926ac9c5"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-06-30 02:28:17"
  condition:
    hash.sha256(0, filesize) == "90d8358588b9ded64882a5385fc8c5f42f0ab963bad27951fda848e6926ac9c5"
}

rule MalwareBazaar_unknown_008_2d477985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d477985d03478784f158a4ab363d24ec2b4b43eb1bdd2f0db74c30c942375d1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 02:23:46"
  condition:
    hash.sha256(0, filesize) == "2d477985d03478784f158a4ab363d24ec2b4b43eb1bdd2f0db74c30c942375d1"
}

rule MalwareBazaar_Mirai_009_df619137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df6191370cf98b3c054aa3d686088b84ce4bfa862515c2abeff79c30eb7077d3"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-06-30 02:23:14"
  condition:
    hash.sha256(0, filesize) == "df6191370cf98b3c054aa3d686088b84ce4bfa862515c2abeff79c30eb7077d3"
}

rule MalwareBazaar_AgentTesla_010_24df5181
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24df5181c0875b598fbb04b6845be8bd5ab4cde3e5eb39233cefd3daf9083b36"
    family = "AgentTesla"
    file_name = "Mv_Meritius_Requisition_Form.js"
    file_type = "js"
    first_seen = "2026-06-30 02:22:16"
  condition:
    hash.sha256(0, filesize) == "24df5181c0875b598fbb04b6845be8bd5ab4cde3e5eb39233cefd3daf9083b36"
}

rule MalwareBazaar_unknown_011_268c712d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "268c712de3d96bd394632e67d86f4626ae15b0ac76d57c0a3e23b1fa2f41f0ad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 02:21:51"
  condition:
    hash.sha256(0, filesize) == "268c712de3d96bd394632e67d86f4626ae15b0ac76d57c0a3e23b1fa2f41f0ad"
}

rule MalwareBazaar_Mirai_012_164ac731
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "164ac73154aafebcace00b726f8285cbe8bdf6bf937d70d2e4060eebae2062a8"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-06-30 02:13:32"
  condition:
    hash.sha256(0, filesize) == "164ac73154aafebcace00b726f8285cbe8bdf6bf937d70d2e4060eebae2062a8"
}

rule MalwareBazaar_Mirai_013_0d87a098
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d87a0985a608c6e0dd1c43d37eabcb525f23e65630a9bc5dcd46a0c898bf502"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-06-30 01:55:11"
  condition:
    hash.sha256(0, filesize) == "0d87a0985a608c6e0dd1c43d37eabcb525f23e65630a9bc5dcd46a0c898bf502"
}

rule MalwareBazaar_Mirai_014_44b6b758
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44b6b758145eaa63171cbb5cc2a28002abb30f94d8076ae727f5d876ffddcc13"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-06-30 01:48:19"
  condition:
    hash.sha256(0, filesize) == "44b6b758145eaa63171cbb5cc2a28002abb30f94d8076ae727f5d876ffddcc13"
}

rule MalwareBazaar_unknown_015_80df8251
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80df8251504352d10f11985f7dbd73d1c2429692b2d87e81422982ed50382180"
    family = "unknown"
    file_name = "2026-7C-004219-1.js"
    file_type = "js"
    first_seen = "2026-06-30 01:41:47"
  condition:
    hash.sha256(0, filesize) == "80df8251504352d10f11985f7dbd73d1c2429692b2d87e81422982ed50382180"
}

rule MalwareBazaar_Mirai_016_fb98ed4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb98ed4d9a5ff70157e5652602a92a7edf0ac11af3a9981996dc00dcffd8cc2f"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-06-30 01:39:10"
  condition:
    hash.sha256(0, filesize) == "fb98ed4d9a5ff70157e5652602a92a7edf0ac11af3a9981996dc00dcffd8cc2f"
}

rule MalwareBazaar_Mirai_017_22d7f840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22d7f840c2172050085316795c270b8f75da45108d087a132556ffbf8dd3e158"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-06-30 01:32:14"
  condition:
    hash.sha256(0, filesize) == "22d7f840c2172050085316795c270b8f75da45108d087a132556ffbf8dd3e158"
}

rule MalwareBazaar_unknown_018_724666cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "724666cc3e87297c4deafd3ab65b81b1493cd223b48baf2b588ad14894482eb9"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-06-30 01:22:28"
  condition:
    hash.sha256(0, filesize) == "724666cc3e87297c4deafd3ab65b81b1493cd223b48baf2b588ad14894482eb9"
}

rule MalwareBazaar_unknown_019_6da6fe83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6da6fe83c1a948bba950f53254b5130e0f17cc6a5af67ba4b3aa7f6c4e3801e4"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-30 01:10:27"
  condition:
    hash.sha256(0, filesize) == "6da6fe83c1a948bba950f53254b5130e0f17cc6a5af67ba4b3aa7f6c4e3801e4"
}

rule MalwareBazaar_Mirai_020_7290cbb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7290cbb1028c1b544a0d38509321df1c391c4cf7f4dd9e5b751c6132738b1bc3"
    family = "Mirai"
    file_name = "main_aarch64"
    file_type = "elf"
    first_seen = "2026-06-30 01:08:15"
  condition:
    hash.sha256(0, filesize) == "7290cbb1028c1b544a0d38509321df1c391c4cf7f4dd9e5b751c6132738b1bc3"
}

rule MalwareBazaar_Mirai_021_22ea2b50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22ea2b5030dfa05adbd50d714c170fd0a0c4ff4d0a245a46a8a7a23f995e6d3b"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-06-30 01:05:31"
  condition:
    hash.sha256(0, filesize) == "22ea2b5030dfa05adbd50d714c170fd0a0c4ff4d0a245a46a8a7a23f995e6d3b"
}

rule MalwareBazaar_unknown_022_a79102b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1"
    family = "unknown"
    file_name = "a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1"
    file_type = "exe"
    first_seen = "2026-06-30 01:00:43"
  condition:
    hash.sha256(0, filesize) == "a79102b1943a98ec07d45fe7b85432f6d8bb534e4fd90d2e18213b9d59bea6a1"
}

rule MalwareBazaar_unknown_023_31ea1252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31ea1252fc6866e35ed394c00647a3f811c6b3a4edfdcfc42b2609fa1411af4b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 00:59:42"
  condition:
    hash.sha256(0, filesize) == "31ea1252fc6866e35ed394c00647a3f811c6b3a4edfdcfc42b2609fa1411af4b"
}

rule MalwareBazaar_unknown_024_9723ffa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8"
    family = "unknown"
    file_name = "9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8"
    file_type = "exe"
    first_seen = "2026-06-30 00:58:57"
  condition:
    hash.sha256(0, filesize) == "9723ffa8e979dabd945619498666655daf695a805057f552e53b1f9a0b9c34e8"
}

rule MalwareBazaar_unknown_025_072b708c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "072b708c1658e2744b77af796f5f12b9edd0bcfed6aa338fafab2891de868205"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-06-30 00:56:09"
  condition:
    hash.sha256(0, filesize) == "072b708c1658e2744b77af796f5f12b9edd0bcfed6aa338fafab2891de868205"
}

rule MalwareBazaar_ValleyRAT_026_f96575db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f96575db91db3fc3f49101dbc1d31ff9a596d8d2aa51c5d0951db941623f9ba0"
    family = "ValleyRAT"
    file_name = "3004dc9fd6900a26cf5efb6e757f3e13.exe"
    file_type = "exe"
    first_seen = "2026-06-30 00:45:14"
  condition:
    hash.sha256(0, filesize) == "f96575db91db3fc3f49101dbc1d31ff9a596d8d2aa51c5d0951db941623f9ba0"
}

rule MalwareBazaar_unknown_027_149e6ee8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "149e6ee81e88ce9a42851961d11bd8ed7654f553b160e125dbecc6ef963a14d5"
    family = "unknown"
    file_name = ".bash_history"
    file_type = "unknown"
    first_seen = "2026-06-30 00:44:29"
  condition:
    hash.sha256(0, filesize) == "149e6ee81e88ce9a42851961d11bd8ed7654f553b160e125dbecc6ef963a14d5"
}

rule MalwareBazaar_Mirai_028_51634b90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51634b90405a6af4e01b530eaabee0b2a23f446855693bad966dbb8374ec6a1b"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-06-30 00:42:19"
  condition:
    hash.sha256(0, filesize) == "51634b90405a6af4e01b530eaabee0b2a23f446855693bad966dbb8374ec6a1b"
}

rule MalwareBazaar_Mirai_029_ac406649
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac4066497f065e66e6552267c6c359b6739b3203de70dd066a292e3e9541aebc"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-06-30 00:35:29"
  condition:
    hash.sha256(0, filesize) == "ac4066497f065e66e6552267c6c359b6739b3203de70dd066a292e3e9541aebc"
}

rule MalwareBazaar_unknown_030_ce779eea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce779eea029e759719fae9e424c52954c1f7e5373099b5d45426ca01bec50d04"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-30 00:31:10"
  condition:
    hash.sha256(0, filesize) == "ce779eea029e759719fae9e424c52954c1f7e5373099b5d45426ca01bec50d04"
}

rule MalwareBazaar_unknown_031_a17eda11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a17eda1169e4bf8d16020ba917b13708f8abeb0bffafee5c1da99ec5cfd49a00"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-06-30 00:24:11"
  condition:
    hash.sha256(0, filesize) == "a17eda1169e4bf8d16020ba917b13708f8abeb0bffafee5c1da99ec5cfd49a00"
}

rule MalwareBazaar_unknown_032_ffb5e04b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb5e04b4403df4fc22d04c1a46a2fd27edd6696a4eae6a435afa105a4d1a364"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 00:08:36"
  condition:
    hash.sha256(0, filesize) == "ffb5e04b4403df4fc22d04c1a46a2fd27edd6696a4eae6a435afa105a4d1a364"
}

rule MalwareBazaar_unknown_033_98d86be0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98d86be099dd339adebf2d9d761635652f5e8a854a9640e8114c3ae1ffbd7c85"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-30 00:07:23"
  condition:
    hash.sha256(0, filesize) == "98d86be099dd339adebf2d9d761635652f5e8a854a9640e8114c3ae1ffbd7c85"
}

rule MalwareBazaar_unknown_034_2d113a07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0"
    family = "unknown"
    file_name = "2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0"
    file_type = "elf"
    first_seen = "2026-06-29 23:54:32"
  condition:
    hash.sha256(0, filesize) == "2d113a07c025bfdf7f0ad82cdaa6ccfd217ffd5c224694bd1ee0fd69f34e04f0"
}

rule MalwareBazaar_unknown_035_24831998
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "248319980ae1b866a7ea30da121f43923a6aeee0f2bbb6576fa6dd368e5ddf4a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-29 23:33:47"
  condition:
    hash.sha256(0, filesize) == "248319980ae1b866a7ea30da121f43923a6aeee0f2bbb6576fa6dd368e5ddf4a"
}

rule MalwareBazaar_unknown_036_8dcf47bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dcf47bc0bb0723203972ea05c1f05df6d38f61d3fe0460d6b727d9ed2bafcaf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-29 23:33:40"
  condition:
    hash.sha256(0, filesize) == "8dcf47bc0bb0723203972ea05c1f05df6d38f61d3fe0460d6b727d9ed2bafcaf"
}

rule MalwareBazaar_Mirai_037_32f9896f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32f9896f5207858ae63d718e89562e9dea9780513873da26aebe6666d3d495fb"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:58"
  condition:
    hash.sha256(0, filesize) == "32f9896f5207858ae63d718e89562e9dea9780513873da26aebe6666d3d495fb"
}

rule MalwareBazaar_Mirai_038_0967707c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0967707c5308593cb114117b5489c6f004f656810ab0616680d9c7c1277c661c"
    family = "Mirai"
    file_name = "morte.mips"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:51"
  condition:
    hash.sha256(0, filesize) == "0967707c5308593cb114117b5489c6f004f656810ab0616680d9c7c1277c661c"
}

rule MalwareBazaar_Mirai_039_00a5bb1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00a5bb1a22bb63d4f94c09a5dc748260b0710129874ad38cd38bed68120c2cff"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:46"
  condition:
    hash.sha256(0, filesize) == "00a5bb1a22bb63d4f94c09a5dc748260b0710129874ad38cd38bed68120c2cff"
}

rule MalwareBazaar_Mirai_040_acaa4f20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acaa4f20c6d7ee0094f62a38d6f0706ed42acaad600f58741a48648cefaab5c2"
    family = "Mirai"
    file_name = "morte.x86"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:43"
  condition:
    hash.sha256(0, filesize) == "acaa4f20c6d7ee0094f62a38d6f0706ed42acaad600f58741a48648cefaab5c2"
}

rule MalwareBazaar_Mirai_041_f897580a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f897580a09ebb3dd3cdeb3df81b4627a0e1ae4adf72982e1005d291c4096d14b"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:40"
  condition:
    hash.sha256(0, filesize) == "f897580a09ebb3dd3cdeb3df81b4627a0e1ae4adf72982e1005d291c4096d14b"
}

rule MalwareBazaar_Mirai_042_dd4630f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd4630f1e9597ec3de130d5abae83d28d01b4447edfdcf25b64bda9a288181e4"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:37"
  condition:
    hash.sha256(0, filesize) == "dd4630f1e9597ec3de130d5abae83d28d01b4447edfdcf25b64bda9a288181e4"
}

rule MalwareBazaar_Mirai_043_b854094b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b854094b3d704b2d70bd0d1458a648dfce74e2a3c16cb1d88967ae12f22d383a"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-06-29 23:22:34"
  condition:
    hash.sha256(0, filesize) == "b854094b3d704b2d70bd0d1458a648dfce74e2a3c16cb1d88967ae12f22d383a"
}

rule MalwareBazaar_Mirai_044_b0b9bb67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0b9bb6785cf9e0216c365a9e231eac747c3d5236b1f29677b3444acc1a918ae"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:32"
  condition:
    hash.sha256(0, filesize) == "b0b9bb6785cf9e0216c365a9e231eac747c3d5236b1f29677b3444acc1a918ae"
}

rule MalwareBazaar_Mirai_045_ce268499
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce2684992b42f2454cfe637cbadf547545240366b9b0b79de036502d80ae996d"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:29"
  condition:
    hash.sha256(0, filesize) == "ce2684992b42f2454cfe637cbadf547545240366b9b0b79de036502d80ae996d"
}

rule MalwareBazaar_Mirai_046_c76de297
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c76de2972ac27799404163a44547a789ba25aeb42570ff21d0efb92128e5cf1a"
    family = "Mirai"
    file_name = "1.sh"
    file_type = "sh"
    first_seen = "2026-06-29 23:21:27"
  condition:
    hash.sha256(0, filesize) == "c76de2972ac27799404163a44547a789ba25aeb42570ff21d0efb92128e5cf1a"
}

rule MalwareBazaar_Mirai_047_350549fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "350549faf559177c364f192f013dfa537fb33a5ff1e6ca3674abba5daf2cce4d"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:26"
  condition:
    hash.sha256(0, filesize) == "350549faf559177c364f192f013dfa537fb33a5ff1e6ca3674abba5daf2cce4d"
}

rule MalwareBazaar_Mirai_048_935af0fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "935af0fa9a1782969009255431376cb3cc4fe5579ceef16542130abf0656c780"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:25"
  condition:
    hash.sha256(0, filesize) == "935af0fa9a1782969009255431376cb3cc4fe5579ceef16542130abf0656c780"
}

rule MalwareBazaar_Mirai_049_b5c7ac13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5c7ac1345074e9aea48617010e887d570a53868e1802566f3f6e63bb21bfd4d"
    family = "Mirai"
    file_name = "morte.arc"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:25"
  condition:
    hash.sha256(0, filesize) == "b5c7ac1345074e9aea48617010e887d570a53868e1802566f3f6e63bb21bfd4d"
}

rule MalwareBazaar_Mirai_050_93635303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93635303f7c28602ea37b8ba0a420acffd527c2eea76e4791c79239d4fa4e481"
    family = "Mirai"
    file_name = "morte.mips"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:24"
  condition:
    hash.sha256(0, filesize) == "93635303f7c28602ea37b8ba0a420acffd527c2eea76e4791c79239d4fa4e481"
}

rule MalwareBazaar_Mirai_051_6f639155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f639155215ecc4b9590e0f768cdf3201df52dbd581275d58ec1723bbafe3afd"
    family = "Mirai"
    file_name = "morte.sh4"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:22"
  condition:
    hash.sha256(0, filesize) == "6f639155215ecc4b9590e0f768cdf3201df52dbd581275d58ec1723bbafe3afd"
}

rule MalwareBazaar_Mirai_052_f49c3c78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f49c3c78218ea5a3a0fb99f8dcb42251d4781e2f21ed3b9f3b7f9fd4e58e3ec1"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:21"
  condition:
    hash.sha256(0, filesize) == "f49c3c78218ea5a3a0fb99f8dcb42251d4781e2f21ed3b9f3b7f9fd4e58e3ec1"
}

rule MalwareBazaar_Mirai_053_a45370fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a45370fa1f96c2bdfa34cb7909d15ed30c459a58a0e35a77295c2982e0500dfa"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:20"
  condition:
    hash.sha256(0, filesize) == "a45370fa1f96c2bdfa34cb7909d15ed30c459a58a0e35a77295c2982e0500dfa"
}

rule MalwareBazaar_Mirai_054_dc38fd95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc38fd9545732814bee53e08b3cee550cca12e0222a233912a8a91b2a178077f"
    family = "Mirai"
    file_name = "morte.x86"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:20"
  condition:
    hash.sha256(0, filesize) == "dc38fd9545732814bee53e08b3cee550cca12e0222a233912a8a91b2a178077f"
}

rule MalwareBazaar_Mirai_055_e4c51e8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4c51e8e44c4ad43b8007f5b39be914d658e653bbfa8ea2363e18041278306fa"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:19"
  condition:
    hash.sha256(0, filesize) == "e4c51e8e44c4ad43b8007f5b39be914d658e653bbfa8ea2363e18041278306fa"
}

rule MalwareBazaar_Mirai_056_e0052270
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0052270db2b15bacb79524bf4b6943404ab566ddeed5e9a56b3aac87c987fe6"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:18"
  condition:
    hash.sha256(0, filesize) == "e0052270db2b15bacb79524bf4b6943404ab566ddeed5e9a56b3aac87c987fe6"
}

rule MalwareBazaar_Mirai_057_0c2d1a47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c2d1a47fbc1c6b887afa8dcd96e2becc7b52154295ded81d3d1ea259fd29910"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:16"
  condition:
    hash.sha256(0, filesize) == "0c2d1a47fbc1c6b887afa8dcd96e2becc7b52154295ded81d3d1ea259fd29910"
}

rule MalwareBazaar_Mirai_058_4c9ba8e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c9ba8e26c1f993fc5f6b8e4ba46cb4ca956d21ca0beba6b5326c3e8bd389751"
    family = "Mirai"
    file_name = "morte.spc"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:15"
  condition:
    hash.sha256(0, filesize) == "4c9ba8e26c1f993fc5f6b8e4ba46cb4ca956d21ca0beba6b5326c3e8bd389751"
}

rule MalwareBazaar_unknown_059_d651fbf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d651fbf908c4f5a25cd048b993b5bc8b99ca011c070749bcaf5e4b1b7bc14f5c"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-06-29 23:21:14"
  condition:
    hash.sha256(0, filesize) == "d651fbf908c4f5a25cd048b993b5bc8b99ca011c070749bcaf5e4b1b7bc14f5c"
}

rule MalwareBazaar_Mirai_060_355643ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "355643ac8395f5a0778ab43b9e02a2271693bc1397ea0d6aa6b2d56ba3be8406"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:13"
  condition:
    hash.sha256(0, filesize) == "355643ac8395f5a0778ab43b9e02a2271693bc1397ea0d6aa6b2d56ba3be8406"
}

rule MalwareBazaar_Mirai_061_a2711c76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2711c76b11bc5ead48ada4bd1052a4bdbca06c1a7b7e88c2f4d4e5b44a9a3c0"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:12"
  condition:
    hash.sha256(0, filesize) == "a2711c76b11bc5ead48ada4bd1052a4bdbca06c1a7b7e88c2f4d4e5b44a9a3c0"
}

rule MalwareBazaar_Mirai_062_a8bc5383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8bc5383b157d561fe771cd5f9446940cd13bd2cf0ad4dba25216c836fe3191c"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:11"
  condition:
    hash.sha256(0, filesize) == "a8bc5383b157d561fe771cd5f9446940cd13bd2cf0ad4dba25216c836fe3191c"
}

rule MalwareBazaar_Mirai_063_237e4d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "237e4d5bba9ec28ea100c5f6fc2d8dda23392af28b333c4d8d2cebcbfa81d577"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:09"
  condition:
    hash.sha256(0, filesize) == "237e4d5bba9ec28ea100c5f6fc2d8dda23392af28b333c4d8d2cebcbfa81d577"
}

rule MalwareBazaar_Mirai_064_03fdc64c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03fdc64c672dfa7a9a5e40ec87643037db26c9c52f7236655560a8a9678d6d24"
    family = "Mirai"
    file_name = "morte.m68k"
    file_type = "elf"
    first_seen = "2026-06-29 23:21:08"
  condition:
    hash.sha256(0, filesize) == "03fdc64c672dfa7a9a5e40ec87643037db26c9c52f7236655560a8a9678d6d24"
}

rule MalwareBazaar_unknown_065_b66c3e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b66c3e12ac9cc8161c2d313a0cc7ed02ae4ee7b785dc2b091b2be4ec679ec76f"
    family = "unknown"
    file_name = ".bash_history"
    file_type = "unknown"
    first_seen = "2026-06-29 23:16:30"
  condition:
    hash.sha256(0, filesize) == "b66c3e12ac9cc8161c2d313a0cc7ed02ae4ee7b785dc2b091b2be4ec679ec76f"
}

rule MalwareBazaar_ValleyRAT_066_a81dd7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a81dd7a5c94f3f82fe489a5e9ccb5e8618f22d3846d1d74388e88e399a8de2e7"
    family = "ValleyRAT"
    file_name = "2f3e3c0134aee76ac9876b3212116261.exe"
    file_type = "exe"
    first_seen = "2026-06-29 23:00:11"
  condition:
    hash.sha256(0, filesize) == "a81dd7a5c94f3f82fe489a5e9ccb5e8618f22d3846d1d74388e88e399a8de2e7"
}

rule MalwareBazaar_Mirai_067_0e3e1d05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3e1d057c4a85536e64c991f239b51961da39fe677bf72014bc96ffa0d21bbe"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-06-29 22:50:59"
  condition:
    hash.sha256(0, filesize) == "0e3e1d057c4a85536e64c991f239b51961da39fe677bf72014bc96ffa0d21bbe"
}

rule MalwareBazaar_Mirai_068_26c13660
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26c13660580b570bc0d7e8ad91bd337047edfd7f0e1311d8b6be8364ad525b8f"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-06-29 22:49:40"
  condition:
    hash.sha256(0, filesize) == "26c13660580b570bc0d7e8ad91bd337047edfd7f0e1311d8b6be8364ad525b8f"
}

rule MalwareBazaar_Mirai_069_b3a346ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3a346cecace10c6212e65fe8f24fb25057f1efd72b3cefd69736ed2f1f1f5e4"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-06-29 22:49:39"
  condition:
    hash.sha256(0, filesize) == "b3a346cecace10c6212e65fe8f24fb25057f1efd72b3cefd69736ed2f1f1f5e4"
}

rule MalwareBazaar_Mirai_070_21d0c42a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d0c42ad9cd1258b7c353537940cf23f536630b246af1184549931be1722c00"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-06-29 22:49:38"
  condition:
    hash.sha256(0, filesize) == "21d0c42ad9cd1258b7c353537940cf23f536630b246af1184549931be1722c00"
}

rule MalwareBazaar_Mirai_071_ae90b42e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae90b42ef39905492d1950705c95a45466dbddb952fe7076c72d4a7a322e80ff"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:51"
  condition:
    hash.sha256(0, filesize) == "ae90b42ef39905492d1950705c95a45466dbddb952fe7076c72d4a7a322e80ff"
}

rule MalwareBazaar_Mirai_072_972d2430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "972d2430ad555fa14785036dfb3e9c9b36704ad9a4e7dc1a8713d03b88f24f66"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:47"
  condition:
    hash.sha256(0, filesize) == "972d2430ad555fa14785036dfb3e9c9b36704ad9a4e7dc1a8713d03b88f24f66"
}

rule MalwareBazaar_Mirai_073_88a4b640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88a4b640bff61b58aef117e03723e9e426afa9b0257fda7d1b91a4f799ad844f"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:44"
  condition:
    hash.sha256(0, filesize) == "88a4b640bff61b58aef117e03723e9e426afa9b0257fda7d1b91a4f799ad844f"
}

rule MalwareBazaar_Mirai_074_0e421c74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e421c747565b1a178ac468d65a55d4e998589ae91181ff134a9473c9b653de7"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:40"
  condition:
    hash.sha256(0, filesize) == "0e421c747565b1a178ac468d65a55d4e998589ae91181ff134a9473c9b653de7"
}

rule MalwareBazaar_Mirai_075_bb5826a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb5826a75467c0c2d1100f5c2ffbf690d93131084a999c9908f34849cc811e4d"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:37"
  condition:
    hash.sha256(0, filesize) == "bb5826a75467c0c2d1100f5c2ffbf690d93131084a999c9908f34849cc811e4d"
}

rule MalwareBazaar_Mirai_076_ddd082b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddd082b95397d7d25d7ee84bfdc42edd7a6dd0b9d3d5cc284869ad7fcd059088"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:33"
  condition:
    hash.sha256(0, filesize) == "ddd082b95397d7d25d7ee84bfdc42edd7a6dd0b9d3d5cc284869ad7fcd059088"
}

rule MalwareBazaar_Mirai_077_60a68bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60a68bdb7838f8f9c1bcceae008a115606c9d4c268882635e5d9d4b6fa595e17"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:23"
  condition:
    hash.sha256(0, filesize) == "60a68bdb7838f8f9c1bcceae008a115606c9d4c268882635e5d9d4b6fa595e17"
}

rule MalwareBazaar_Mirai_078_e8ba36a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8ba36a1a044991c46b6396917dc9e9667e2d12e9365ced95fafc20dc72a1aa9"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:22"
  condition:
    hash.sha256(0, filesize) == "e8ba36a1a044991c46b6396917dc9e9667e2d12e9365ced95fafc20dc72a1aa9"
}

rule MalwareBazaar_Mirai_079_68857051
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68857051c25bbf96357594e0d70c0678eba91b3ee67ff189ba20859dbfa359a1"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:18"
  condition:
    hash.sha256(0, filesize) == "68857051c25bbf96357594e0d70c0678eba91b3ee67ff189ba20859dbfa359a1"
}

rule MalwareBazaar_Mirai_080_f46ee462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f46ee46298b90eb04b1c15e4e4cecc8a4e5a7730c654d58261c9c846084249ca"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:17"
  condition:
    hash.sha256(0, filesize) == "f46ee46298b90eb04b1c15e4e4cecc8a4e5a7730c654d58261c9c846084249ca"
}

rule MalwareBazaar_Mirai_081_916c30b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "916c30b5ea0d508e5bc4cfb91a51e0dc2da256a309eb6f0d9555790852077159"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:16"
  condition:
    hash.sha256(0, filesize) == "916c30b5ea0d508e5bc4cfb91a51e0dc2da256a309eb6f0d9555790852077159"
}

rule MalwareBazaar_Mirai_082_5cf36b61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cf36b618810a9991e792956ccccb82fea10a6713793adb9a0c80bee8a945b4e"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:15"
  condition:
    hash.sha256(0, filesize) == "5cf36b618810a9991e792956ccccb82fea10a6713793adb9a0c80bee8a945b4e"
}

rule MalwareBazaar_Mirai_083_47f4697d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47f4697de6e24f50bc84f1325aae1436d0e19788f350bdcc90a3f3943a9728a7"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-06-29 22:47:13"
  condition:
    hash.sha256(0, filesize) == "47f4697de6e24f50bc84f1325aae1436d0e19788f350bdcc90a3f3943a9728a7"
}

rule MalwareBazaar_MaskGramStealer_084_d9284678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d928467888cd402afbdd062a04e903d639086f614e7a0424dbc098aa8e8d31ef"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-29 22:41:16"
  condition:
    hash.sha256(0, filesize) == "d928467888cd402afbdd062a04e903d639086f614e7a0424dbc098aa8e8d31ef"
}

rule MalwareBazaar_Mirai_085_0f451ed1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f451ed1c1a487f63d83620e0e3fd650e8d982098864c7c96013f3213204a2bb"
    family = "Mirai"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-06-29 22:32:22"
  condition:
    hash.sha256(0, filesize) == "0f451ed1c1a487f63d83620e0e3fd650e8d982098864c7c96013f3213204a2bb"
}

rule MalwareBazaar_AveMariaRAT_086_014f3acc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "014f3accbf588566489bb34bd21402c1ab70f70448f818ba817b7db2d6e21122"
    family = "AveMariaRAT"
    file_name = "2DF7867DD2AF4783E4881D38E5901F5F.exe"
    file_type = "exe"
    first_seen = "2026-06-29 22:25:08"
  condition:
    hash.sha256(0, filesize) == "014f3accbf588566489bb34bd21402c1ab70f70448f818ba817b7db2d6e21122"
}

rule MalwareBazaar_unknown_087_76ef465d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83"
    family = "unknown"
    file_name = "76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83"
    file_type = "elf"
    first_seen = "2026-06-29 22:08:52"
  condition:
    hash.sha256(0, filesize) == "76ef465db71f0b8b94b5a8a6b5ba1e6dbc7f11a72e3759bf2896aafe3b82fc83"
}

rule MalwareBazaar_Mirai_088_483ddab7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "483ddab777936fca2b3fe7896c84987deb519e236ae41796eb35767f46bb38f5"
    family = "Mirai"
    file_name = "nerv.sh4"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:38"
  condition:
    hash.sha256(0, filesize) == "483ddab777936fca2b3fe7896c84987deb519e236ae41796eb35767f46bb38f5"
}

rule MalwareBazaar_Mirai_089_48269829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "482698293d879600cb9b1b93c45075f77750102661fe8dd8cd97680e25ec8681"
    family = "Mirai"
    file_name = "nerv.arm4"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:37"
  condition:
    hash.sha256(0, filesize) == "482698293d879600cb9b1b93c45075f77750102661fe8dd8cd97680e25ec8681"
}

rule MalwareBazaar_Mirai_090_c1551029
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c15510299e739d04f78a611d2cee455ac3e49004ff19ca5707a7728a54213772"
    family = "Mirai"
    file_name = "nerv.x86_32"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:36"
  condition:
    hash.sha256(0, filesize) == "c15510299e739d04f78a611d2cee455ac3e49004ff19ca5707a7728a54213772"
}

rule MalwareBazaar_Mirai_091_d99cfe55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d99cfe550c1e0731cc26677db68de552a55b90b8696dbc21a8d01ee5960f710d"
    family = "Mirai"
    file_name = "nerv.x86"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:34"
  condition:
    hash.sha256(0, filesize) == "d99cfe550c1e0731cc26677db68de552a55b90b8696dbc21a8d01ee5960f710d"
}

rule MalwareBazaar_Mirai_092_e4e6ea8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4e6ea8ea27556af7985e46eea728b71c69bf997a458dbbad629b78a5595b98d"
    family = "Mirai"
    file_name = "nerv.arm5"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:33"
  condition:
    hash.sha256(0, filesize) == "e4e6ea8ea27556af7985e46eea728b71c69bf997a458dbbad629b78a5595b98d"
}

rule MalwareBazaar_Mirai_093_99a5a141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99a5a14183cbc57a8d72fd7f3470aa874e046488482c8b75a5cef228ffb24314"
    family = "Mirai"
    file_name = "nerv.sparc"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:32"
  condition:
    hash.sha256(0, filesize) == "99a5a14183cbc57a8d72fd7f3470aa874e046488482c8b75a5cef228ffb24314"
}

rule MalwareBazaar_Mirai_094_63c2176a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c2176ac941063c3c0dfaf8d3f6d798bed2cb976e0a622dff1ea5caa4d9d3ff"
    family = "Mirai"
    file_name = "nerv.mpsl"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:31"
  condition:
    hash.sha256(0, filesize) == "63c2176ac941063c3c0dfaf8d3f6d798bed2cb976e0a622dff1ea5caa4d9d3ff"
}

rule MalwareBazaar_Gafgyt_095_da94ba7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da94ba7c1a962a0d6c7508118c82bc8bd7f0f47771515779594298edbe8790a3"
    family = "Gafgyt"
    file_name = "nerv.m68k"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:29"
  condition:
    hash.sha256(0, filesize) == "da94ba7c1a962a0d6c7508118c82bc8bd7f0f47771515779594298edbe8790a3"
}

rule MalwareBazaar_Gafgyt_096_31c737dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31c737dc339d77f66a8eb33f5e514c7294b77978d084d60b0f6730c46ac6cf1d"
    family = "Gafgyt"
    file_name = "nerv.arm7"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:28"
  condition:
    hash.sha256(0, filesize) == "31c737dc339d77f66a8eb33f5e514c7294b77978d084d60b0f6730c46ac6cf1d"
}

rule MalwareBazaar_Mirai_097_b5331c5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5331c5a2934b2ff4863bc94d14b1ba89cb1070b34814470dce5d0e4750aca3a"
    family = "Mirai"
    file_name = "nerv.mips"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:27"
  condition:
    hash.sha256(0, filesize) == "b5331c5a2934b2ff4863bc94d14b1ba89cb1070b34814470dce5d0e4750aca3a"
}

rule MalwareBazaar_Mirai_098_3c90550a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c90550ad4e64b9395add010732315f4fcb3dcd6bbea98d79432dbf5327401b8"
    family = "Mirai"
    file_name = "nerv.ppc"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:25"
  condition:
    hash.sha256(0, filesize) == "3c90550ad4e64b9395add010732315f4fcb3dcd6bbea98d79432dbf5327401b8"
}

rule MalwareBazaar_Mirai_099_5a021367
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a021367a916abe1d8b054fff01ca0b7fde072eb96452dee4cf1a7b644c03ff9"
    family = "Mirai"
    file_name = "nerv.arm6"
    file_type = "elf"
    first_seen = "2026-06-29 22:04:24"
  condition:
    hash.sha256(0, filesize) == "5a021367a916abe1d8b054fff01ca0b7fde072eb96452dee4cf1a7b644c03ff9"
}

rule MalwareBazaar_unknown_100_3133d611
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3133d611ad668557d92759f99f104bb6d41da16b9819f0566e6943fd7931c132"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-06-29 22:00:45"
  condition:
    hash.sha256(0, filesize) == "3133d611ad668557d92759f99f104bb6d41da16b9819f0566e6943fd7931c132"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.
